"""Tests for the activation lifecycle: serialization, failure safety, token rules.

``activate()`` and ``deactivate()`` change four things that must always
describe the same policy: the ``_config`` reference, the C guardian's state,
whether the audit hook is installed, and the ``_TETHERED_CHILD_POLICY``
environment variable read by child processes.
"""

from __future__ import annotations

import _thread
import contextlib
import ctypes
import inspect
import json
import os
import random
import signal
import socket
import subprocess
import sys
import threading
import types

import pytest

import tethered
import tethered._core as _core

POLICY_VAR = _core._CHILD_POLICY_ENV
guardian = _core._c_guardian

pytestmark = pytest.mark.skipif(guardian is None, reason="C guardian extension not available")


# ── Failure injection ──────────────────────────────────────────────
# An audit hook can veto the operation that raised the event, which makes
# it a way to let an environment write fail without replacing any tethered
# function.  Audit hooks cannot be removed, so this one is installed once
# and does nothing unless a test arms it.


class _Veto:
    event: str | None = None
    error: BaseException | None = None


def _vetoing_hook(event: str, args: tuple) -> None:
    if event != _Veto.event or not args:
        return
    key = args[0]
    if isinstance(key, bytes):
        key = os.fsdecode(key)
    if isinstance(key, str) and key.upper() == POLICY_VAR:
        error, _Veto.event, _Veto.error = _Veto.error, None, None  # one shot
        assert error is not None
        raise error


sys.addaudithook(_vetoing_hook)


@pytest.fixture
def veto():
    """Make the next write of the policy variable fail: ``veto("os.putenv", error)``.

    One shot: the write that follows (tethered putting the old value back,
    for instance) goes through.
    """

    def arm(event: str, error: BaseException) -> None:
        _Veto.event, _Veto.error = event, error

    yield arm
    _Veto.event, _Veto.error = None, None


# ── Helpers ────────────────────────────────────────────────────────


@pytest.fixture
def loopback_port():
    """A listening TCP port on 127.0.0.1 that accepts and closes every connection.

    The accept-and-close daemon is load-bearing.  A listener that only calls
    ``listen()`` and never ``accept()`` stops completing handshakes once the
    backlog fills — 64 pending connections here — after which the next
    connect is refused (Windows) or blocks to its timeout (Linux).
    ``test_many_threads`` probes with an unbounded connect loop whose
    ``_try_connect`` catches only :class:`~tethered.EgressBlocked`, so such an
    ``OSError`` would escape and fail the test intermittently, the more so
    under load.  Draining keeps every allowed connect genuinely connectable,
    which is what these tests mean to assert.

    The daemon ends with the test.  Closing the socket does not wake an
    ``accept()`` that another thread is blocked in on Linux, and a thread left
    behind would make every later ``fork()`` in the session a fork of a
    multi-threaded process.  So ``accept()`` waits with a timeout and the
    thread is joined before the socket is closed.
    """
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(64)
    server.settimeout(0.05)
    done = threading.Event()

    def drain() -> None:
        while not done.is_set():
            try:
                conn, _ = server.accept()
            except OSError:  # nothing to accept within the timeout
                continue
            conn.close()

    drainer = threading.Thread(target=drain, daemon=True)
    drainer.start()
    yield server.getsockname()[1]
    done.set()
    drainer.join()
    server.close()


def _try_connect(port: int) -> str:
    with socket.socket() as client:
        client.settimeout(5)
        try:
            client.connect(("127.0.0.1", port))
        except tethered.EgressBlocked:
            return "blocked"
        return "connected"


def _observe(token: object = None) -> tuple:
    """Everything a lifecycle call may change, for before/after comparison."""
    return (
        _core._config,
        guardian.is_active(),
        guardian.check_token(token),
        guardian.verify(),
        os.environ.get(POLICY_VAR),
    )


def _assert_coherent(token: object = None) -> None:
    """Config, guardian and environment describe the same policy."""
    cfg = _core._config
    published = os.environ.get(POLICY_VAR)
    if cfg is None:
        assert published is None, "no policy is active but one is published to children"
        assert guardian.is_active() is False
        return
    assert published == cfg._serialized_payload, "children would get a different policy"
    assert guardian.is_active() is cfg.locked
    assert _core._hook_installed is True
    if cfg.locked:
        assert guardian.verify() is True, "config and guardian snapshot disagree"
        if token is not None:
            assert guardian.check_token(token) is True


def _source_line(func, marker: str) -> int:
    """Line number of the one line of ``func`` whose source contains ``marker``."""
    lines, first = inspect.getsourcelines(func)
    matches = [first + offset for offset, line in enumerate(lines) if marker in line]
    assert len(matches) == 1, f"expected one line containing {marker!r}, found {len(matches)}"
    return matches[0]


class _PauseAt:
    """Hold a thread just before it executes one line of a function.

    Driven by a trace function, so the implementation runs unmodified.
    """

    def __init__(self, func, marker: str) -> None:
        self._code = func.__code__
        self._lineno = _source_line(func, marker)
        self.reached = threading.Event()
        self.resume = threading.Event()

    def run(self, call) -> None:
        """Thread target: run ``call()`` with the pause point armed."""
        sys.settrace(self._trace)
        try:
            call()
        finally:
            sys.settrace(None)

    def _trace(self, frame, event, arg):
        return self._local if frame.f_code is self._code else None

    def _local(self, frame, event, arg):
        if event == "line" and frame.f_lineno == self._lineno and not self.reached.is_set():
            self.reached.set()
            assert self.resume.wait(30)
        return self._local


class _SingleStep:
    """Run a function in another thread one source line at a time."""

    def __init__(self, func) -> None:
        self._code = func.__code__
        self._paused = threading.Event()
        self._proceed = threading.Event()
        self._finished = False
        self._free_running = False
        self.errors: list[BaseException] = []

    def run(self, call) -> None:
        sys.settrace(self._trace)
        try:
            call()
        except BaseException as exc:
            self.errors.append(exc)
        finally:
            sys.settrace(None)
            self._finished = True
            self._paused.set()

    def _trace(self, frame, event, arg):
        return self._local if frame.f_code is self._code else None

    def _local(self, frame, event, arg):
        if event == "line" and not self._free_running:
            self._proceed.clear()
            self._paused.set()
            assert self._proceed.wait(30)
        return self._local

    def pauses(self):
        """Yield once per line the other thread is about to execute."""
        while True:
            assert self._paused.wait(30)
            if self._finished:
                return
            self._paused.clear()
            yield
            self._proceed.set()

    def release(self) -> None:
        """Stop pausing and let the other thread run to the end."""
        self._free_running = True
        self._proceed.set()


def _run_paused(pause: _PauseAt, first, second) -> None:
    """Start ``first`` and hold it at the pause point while ``second`` runs alongside.

    If the two calls are serialized, ``second`` cannot finish before
    ``first`` is released; either way ``first`` is released after a short
    grace period and both are joined.
    """
    errors: list[BaseException] = []

    def guarded(call):
        def target():
            try:
                call()
            except BaseException as exc:
                errors.append(exc)

        return target

    second_done = threading.Event()

    def run_second():
        second()
        second_done.set()

    thread_a = threading.Thread(target=lambda: pause.run(guarded(first)))
    thread_b = threading.Thread(target=guarded(run_second))
    thread_a.start()
    assert pause.reached.wait(30), "the pause point was never reached"
    thread_b.start()
    second_done.wait(0.3)
    pause.resume.set()
    thread_a.join(30)
    thread_b.join(30)
    assert not thread_a.is_alive()
    assert not thread_b.is_alive()
    assert errors == []


# ── R8: one serialized transition ──────────────────────────────────


class TestSerializedTransitions:
    def test_deactivate_during_activate(self, loopback_port, capfd):
        """activate() held just before it publishes the policy; deactivate() runs meanwhile.

        Unserialized, both returned with no policy active and a policy still
        published to children.
        """
        pause = _PauseAt(_core.activate, "_propagate_policy_to_env(cfg)")
        _run_paused(
            pause,
            lambda: tethered.activate(allow=[f"127.0.0.1:{loopback_port}"], allow_localhost=False),
            lambda: tethered.deactivate(),
        )
        _assert_coherent()
        assert _try_connect(loopback_port) == "connected"
        assert "TAMPER DETECTED" not in capfd.readouterr().err

    def test_two_locked_activations(self, loopback_port, capfd):
        """A locked re-activation held just before the guardian commit; another runs meanwhile.

        Unserialized, both returned, leaving the config of one and the
        guardian snapshot of the other — after which every socket operation
        was refused as tampering.
        """
        secret = object()
        rule = f"127.0.0.1:{loopback_port}"
        tethered.activate(allow=[rule], allow_localhost=False, locked=True, lock_token=secret)

        def reactivate(extra: str):
            tethered.activate(
                allow=[rule, extra], allow_localhost=False, locked=True, lock_token=secret
            )

        pause = _PauseAt(_core.activate, "_c_guardian.activate(")
        _run_paused(pause, lambda: reactivate("first.test"), lambda: reactivate("second.test"))

        _assert_coherent(secret)
        policy = _core._config.policy
        assert policy.is_allowed("first.test") != policy.is_allowed("second.test")
        assert _try_connect(loopback_port) == "connected"
        socket.socket().close()
        assert "TAMPER DETECTED" not in capfd.readouterr().err

    @pytest.mark.parametrize(
        "transition",
        ["locked -> locked", "locked -> unlocked", "locked -> off", "off -> locked"],
    )
    def test_socket_events_never_see_a_torn_state(self, transition, loopback_port, capfd):
        """Step a transition one line at a time; probe from another thread at every line.

        A connect the old and the new policy both allow must never be
        refused, and the guardian must never find its snapshot at odds with
        the config.
        """
        secret = object()
        rule = f"127.0.0.1:{loopback_port}"
        before, _, after = transition.partition(" -> ")
        if before == "locked":
            tethered.activate(allow=[rule], allow_localhost=False, locked=True, lock_token=secret)

        if after == "locked":
            func = _core.activate

            def call():
                tethered.activate(
                    allow=[rule, "new.test"], allow_localhost=False, locked=True, lock_token=secret
                )
        elif after == "unlocked":
            func = _core.activate

            def call():
                tethered.activate(allow=[rule, "new.test"], lock_token=secret)
        else:
            func = _core.deactivate

            def call():
                tethered.deactivate(lock_token=secret)

        stepper = _SingleStep(func)
        thread = threading.Thread(target=lambda: stepper.run(call))
        thread.start()
        probes = 0
        try:
            for _ in stepper.pauses():
                if _core._ip_map_lock.locked():
                    continue  # the paused thread holds the lock the connect hook needs
                assert guardian.verify() is True
                assert _try_connect(loopback_port) == "connected"
                probes += 1
        finally:
            stepper.release()
            thread.join(30)
        assert not thread.is_alive()
        assert stepper.errors == []
        assert probes > 10
        _assert_coherent(secret)
        assert "TAMPER DETECTED" not in capfd.readouterr().err

    def test_loopback_fixture_serves_past_the_backlog(self, loopback_port):
        """The loopback fixture must keep serving connects past ``listen()``'s backlog.

        ``test_many_threads`` probes with an unbounded connect loop; if the
        fixture's listener did not drain its accept queue it would refuse
        (Windows) or time out (Linux) once the backlog of 64 filled, raising
        an ``OSError`` that ``_try_connect`` does not catch and that would
        surface as a spurious failure under load.  Many sequential connects —
        well past the backlog — must all succeed.
        """
        for _ in range(200):
            assert _try_connect(loopback_port) == "connected"

    def test_many_threads(self, loopback_port, capfd):
        """Lifecycle calls from several threads while another thread keeps connecting."""
        secret = object()
        rule = f"127.0.0.1:{loopback_port}"
        errors: list[BaseException] = []
        stop = threading.Event()
        outcomes: set[str] = set()

        def churn(seed: int):
            rng = random.Random(seed)
            try:
                for i in range(30):
                    choice = rng.randrange(4)
                    if choice == 0:
                        tethered.deactivate(lock_token=secret)
                    elif choice == 1:
                        tethered.activate(allow=[rule, f"u{seed}-{i}.test"], lock_token=secret)
                    else:
                        tethered.activate(
                            allow=[rule, f"l{seed}-{i}.test"],
                            allow_localhost=False,
                            locked=True,
                            lock_token=secret,
                        )
            except BaseException as exc:
                errors.append(exc)

        def connect_loop():
            try:
                while not stop.is_set():
                    outcomes.add(_try_connect(loopback_port))
            except BaseException as exc:
                errors.append(exc)

        prober = threading.Thread(target=connect_loop)
        workers = [threading.Thread(target=churn, args=(seed,)) for seed in range(4)]
        prober.start()
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(60)
        stop.set()
        prober.join(60)

        assert errors == []
        # Every policy in play allowed this connect; none of them may have
        # been seen half-installed.
        assert outcomes == {"connected"}
        _assert_coherent(secret)
        assert _try_connect(loopback_port) == "connected"
        assert "TAMPER DETECTED" not in capfd.readouterr().err

    def test_lifecycle_lock_is_reentrant(self):
        """Environment writes inside a transition raise audit events on the same thread."""
        with _core._lifecycle_lock, _core._lifecycle_lock:
            tethered.activate(allow=["*.example.com"])
            tethered.deactivate()
        _assert_coherent()


# ── Taking turns with the other interpreters of the process ────────
# The policy variable belongs to the whole process, and a write to it is
# under way from its audit event until the environment is changed.  So
# whoever writes it for tethered first takes the C guardian's activation
# claim, and keeps it until its transition is committed or undone; nobody
# else publishes or commits meanwhile, in any interpreter.
#
# Here the claim is contended by threads of this interpreter, which is all
# that coverage can see.  ``test_subinterpreters.py`` contends for it with
# real interpreters.

claim = _core._activation_claim


class _Contender:
    """A thread that takes the claim and gives it up again at once."""

    def __init__(self) -> None:
        self.took = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        with claim:
            self.took.set()

    def is_waiting(self, seconds: float = 0.2) -> bool:
        """Has it still not got the claim after ``seconds``?"""
        return not self.took.wait(seconds)

    def finish(self) -> None:
        assert self.took.wait(30), "the claim was never given up"
        self._thread.join(30)


def _assert_claim_is_free() -> None:
    _Contender().finish()


def _in_a_thread(call) -> tuple[threading.Thread, threading.Event, list[BaseException]]:
    """Start ``call()`` in a thread; return it, the event set when it is over, and its errors."""
    done = threading.Event()
    errors: list[BaseException] = []

    def run() -> None:
        try:
            call()
        except BaseException as exc:
            errors.append(exc)
        done.set()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, done, errors


# What a child process reports when an object that is finalized while Python
# shuts down asks for a claim that a daemon thread took and never gave up.
_SHUTDOWN_WITH_THE_CLAIM_TAKEN = """
import os, sys, threading, time

import tethered._core as core

core._load_guardian()  # what activate() does first: import tethered loads no extension
claim = core._activation_claim
held = threading.Event()


def hold():
    claim.__enter__()
    held.set()
    time.sleep(3600)  # stopped by the shutdown, with the claim


threading.Thread(target=hold, daemon=True).start()
assert held.wait(30)


class AtTheEnd:
    # (It brings what it needs: module globals may be gone when this runs.)
    def __init__(self):
        self.claim, self.write = claim, os.write

    def __del__(self):
        try:
            with self.claim:
                self.write(1, b"TOOK IT")
        except RuntimeError as exc:
            self.write(1, str(exc).encode())


# Kept by the sys module, whose namespace is cleared late in the shutdown.
# (This module's own is kept alive by the frame of the stopped thread.)
sys.kept_until_the_end = AtTheEnd()
"""


class TestActivationClaim:
    def test_it_is_the_guardians_context_manager(self):
        assert claim is guardian.activation_claim
        assert type(claim).__name__ == "ActivationClaim"
        with pytest.raises(TypeError, match="cannot create"):
            type(claim)()
        with claim as entered:
            assert entered is None
        _assert_claim_is_free()

    def test_another_thread_waits_and_then_proceeds(self):
        with claim:
            contender = _Contender()
            assert contender.is_waiting()
        contender.finish()

    def test_the_holding_thread_may_take_it_again(self):
        with claim:
            with claim:
                pass
            contender = _Contender()
            assert contender.is_waiting()  # taken twice, given up once
        contender.finish()

    def test_it_is_given_up_when_the_block_raises(self):
        with pytest.raises(ZeroDivisionError), claim:
            _ = 1 / 0
        _assert_claim_is_free()

    def test_giving_up_what_is_not_held_is_refused(self):
        with pytest.raises(RuntimeError, match="does not hold the activation claim"):
            claim.__exit__(None, None, None)
        _assert_claim_is_free()

    def test_held_counts_and_restore_gives_up_what_is_held_beyond_a_count(self):
        assert claim.held() == 0
        with claim:
            assert claim.held() == 1
            with claim:
                assert claim.held() == 2
            assert claim.held() == 1
            claim.restore(1)  # held as often as before: nothing to do
            assert claim.held() == 1
            seen_elsewhere: list[int] = []
            thread = threading.Thread(target=lambda: seen_elsewhere.append(claim.held()))
            thread.start()
            thread.join(30)
            assert seen_elsewhere == [0]  # it counts for the calling thread
        assert claim.held() == 0
        claim.restore(0)  # not held: nothing to do
        _assert_claim_is_free()

        # What blocks that were never entered would leave behind.
        for _ in range(3):
            claim.__enter__()
        claim.restore(1)
        assert claim.held() == 1
        contender = _Contender()
        assert contender.is_waiting()
        claim.restore(0)
        contender.finish()
        assert claim.held() == 0
        with pytest.raises(TypeError):
            claim.restore("once")

    @pytest.mark.parametrize("call", ["activate", "deactivate", "the launch hook"])
    def test_an_exception_that_arrives_as_the_claim_is_taken_does_not_leave_it_taken(self, call):
        """Python 3.14 raises a pending exception between ``__enter__`` and the block.

        It never calls ``__exit__`` then: a ``with`` alone would leave the
        claim taken for good, for every interpreter.  The exception is set
        on the thread while it waits for the claim, so that it is pending
        at the moment the claim is taken.  Wherever a version raises it,
        the claim and the lifecycle lock are free afterwards.
        """

        class Arrived(Exception):
            pass

        tethered.activate(allow=["prior.test"], external_subprocess_policy="allow")
        cfg = _core._config
        if call == "the launch hook":
            del os.environ[POLICY_VAR]  # so that the hook has a payload to put back
        calls = {
            "activate": lambda: tethered.activate(allow=["new.test"]),
            "deactivate": tethered.deactivate,
            "the launch hook": lambda: _core._handle_subprocess(cfg, "os.system", ("echo hi",)),
        }

        with claim:
            thread, done, errors = _in_a_thread(calls[call])
            assert not done.wait(0.3)  # it waits for the claim
            set_on = ctypes.pythonapi.PyThreadState_SetAsyncExc(
                ctypes.c_ulong(thread.ident), ctypes.py_object(Arrived)
            )
            assert set_on == 1
        assert done.wait(30)
        thread.join(30)

        assert [type(error) for error in errors] == [Arrived]
        _assert_claim_is_free()
        assert _core._lifecycle_lock.acquire(timeout=30)
        _core._lifecycle_lock.release()
        # The transition did not happen: the policy is the one from before.
        assert _core._config is cfg
        if call != "the launch hook":
            _assert_coherent()

    def test_without_the_extension_a_lock_of_the_interpreters_own_stands_in(self):
        stand_in = _core._UnsharedClaim()
        took = threading.Event()

        def take() -> None:
            with stand_in:
                took.set()

        with stand_in, stand_in:  # the holding thread may take it again
            thread = threading.Thread(target=take, daemon=True)
            thread.start()
            assert not took.wait(0.2)
        assert took.wait(30)
        thread.join(30)
        # It keeps no count: nothing to report, nothing to give up.
        assert stand_in.held() == 0
        stand_in.restore(0)

    def test_one_thread_cannot_give_up_what_another_holds(self):
        holding, release = threading.Event(), threading.Event()

        def hold() -> None:
            with claim:
                holding.set()
                assert release.wait(30)

        holder = threading.Thread(target=hold, daemon=True)
        holder.start()
        assert holding.wait(30)
        contender = _Contender()
        try:
            with pytest.raises(RuntimeError, match="does not hold the activation claim"):
                claim.__exit__(None, None, None)
            assert contender.is_waiting()  # the holder's claim is as it was
        finally:
            release.set()
            holder.join(30)
        contender.finish()

    @pytest.mark.skipif(
        threading.current_thread() is not threading.main_thread(),
        reason="only the main thread handles signals",
    )
    def test_a_signal_ends_the_wait(self):
        """Ctrl-C reaches a call that waits for the claim, and leaves the claim as it was."""
        holding, release = threading.Event(), threading.Event()

        def hold() -> None:
            with claim:
                holding.set()
                assert release.wait(60)

        holder = threading.Thread(target=hold, daemon=True)
        holder.start()
        assert holding.wait(30)
        interrupt = threading.Timer(0.2, _thread.interrupt_main)
        give_up = threading.Timer(30, release.set)  # so that a failure is not a hang
        give_up.start()
        try:
            with pytest.raises(KeyboardInterrupt):
                # (Started in here: the interrupt must find this thread
                # inside the block that expects it, however slow the day.)
                interrupt.start()
                with claim:
                    pytest.fail("took a claim that another thread holds")
            assert not release.is_set()
            contender = _Contender()
            assert contender.is_waiting()  # the holder still holds it
        finally:
            give_up.cancel()
            release.set()
            holder.join(30)
            if interrupt.ident is not None:
                interrupt.join(30)
        contender.finish()

    # ── activate() and deactivate() ────────────────────────────────────

    @pytest.mark.parametrize("call", ["activate", "locked activate", "deactivate"])
    def test_a_transition_waits_for_the_claim_and_changes_nothing_meanwhile(self, call):
        secret = object()
        if call == "deactivate":
            tethered.activate(allow=["prior.test"])
            transition = tethered.deactivate
        else:

            def transition() -> None:
                tethered.activate(
                    allow=["new.test"], locked=call == "locked activate", lock_token=secret
                )

        before = _observe(secret)
        with claim:
            thread, done, errors = _in_a_thread(transition)
            assert not done.wait(0.3)
            assert _observe(secret) == before
        assert done.wait(30)
        thread.join(30)
        assert errors == []
        assert _observe(secret) != before
        _assert_coherent(secret)
        _assert_claim_is_free()

    @pytest.mark.parametrize("call", ["activate", "deactivate"])
    def test_it_is_held_while_the_variable_is_written(self, call, monkeypatch):
        """From before the write until the transition is over, and by nobody afterwards."""
        writer = "_propagate_policy_to_env" if call == "activate" else "_clear_policy_from_env"
        genuine = getattr(_core, writer)
        waited: list[bool] = []
        contenders: list[_Contender] = []

        def write(*args: object) -> None:
            contenders.append(_Contender())
            waited.append(contenders[-1].is_waiting())
            genuine(*args)
            waited.append(contenders[-1].is_waiting(0.05))

        tethered.activate(allow=["prior.test"])
        monkeypatch.setattr(_core, writer, write)
        if call == "activate":
            tethered.activate(allow=["new.test"])
        else:
            tethered.deactivate()

        assert waited == [True, True]
        contenders[0].finish()
        _assert_coherent()

    @pytest.mark.parametrize(
        "ending",
        [
            "committed",
            "publishing refused by an audit hook",
            "clearing refused by an audit hook",
            "commit failed",
            "refused at the door",
            "identical policy: nothing to do",
        ],
    )
    def test_it_is_given_up_however_a_transition_ends(self, ending, veto, monkeypatch):
        secret = object()
        if ending == "committed":
            tethered.activate(allow=["a.test"], locked=True, lock_token=secret)
            _assert_claim_is_free()
            tethered.activate(allow=["b.test"], lock_token=secret)
            _assert_claim_is_free()
            tethered.deactivate()
        elif ending == "publishing refused by an audit hook":
            veto("os.putenv", OSError("environment is read-only"))
            with pytest.raises(OSError, match="read-only"):
                tethered.activate(allow=["a.test"])
        elif ending == "clearing refused by an audit hook":
            tethered.activate(allow=["a.test"])
            veto("os.unsetenv", OSError("environment is read-only"))
            with pytest.raises(OSError, match="read-only"):
                tethered.deactivate()
        elif ending == "commit failed":
            monkeypatch.setattr(_core, "_build_integrity_snapshot", lambda cfg: [("not", "a pin")])
            with pytest.raises(TypeError):
                tethered.activate(allow=["a.test"], locked=True, lock_token=secret)
        else:
            tethered.activate(allow=["a.test"], locked=True, lock_token=secret)
            if ending == "refused at the door":
                with pytest.raises(tethered.TetheredLocked):
                    tethered.activate(allow=["b.test"])
                _assert_claim_is_free()
                with pytest.raises(tethered.TetheredLocked):
                    tethered.deactivate()
            else:
                tethered.activate(allow=["a.test"], locked=True, lock_token=object())
        _assert_claim_is_free()
        _assert_coherent(secret)

    # ── The launch hook, where it puts the payload back ────────────────

    @pytest.mark.parametrize("taken", ["the lifecycle lock", "the claim"])
    def test_the_launch_hook_takes_its_turn_before_it_puts_the_payload_back(self, taken):
        """It takes the lifecycle lock and then the claim, in the order a transition does."""
        tethered.activate(allow=["a.test"], external_subprocess_policy="allow")
        cfg = _core._config
        payload = os.environ.pop(POLICY_VAR)  # an ordinary cleanup of the environment

        with _core._lifecycle_lock if taken == "the lifecycle lock" else claim:
            thread, done, errors = _in_a_thread(
                lambda: _core._handle_subprocess(cfg, "os.system", ("echo hi",))
            )
            assert not done.wait(0.3)
            assert POLICY_VAR not in os.environ
            if taken == "the lifecycle lock":
                # It is not sitting on the claim while it waits for the lock.
                _assert_claim_is_free()
        assert done.wait(30)
        thread.join(30)
        assert errors == []
        assert os.environ[POLICY_VAR] == payload
        _assert_coherent()
        _assert_claim_is_free()

    @pytest.mark.parametrize("meanwhile", ["replaced", "deactivated"])
    def test_a_policy_that_went_while_the_hook_waited_is_not_published(self, meanwhile):
        """The variable says what the transition left there, not what the hook set out with."""
        tethered.activate(allow=["old.test"], external_subprocess_policy="allow")
        stale = _core._config
        del os.environ[POLICY_VAR]

        # (Both, in their order, as a transition holds them.)
        with _core._lifecycle_lock, claim:
            thread, done, errors = _in_a_thread(
                lambda: _core._handle_subprocess(stale, "os.system", ("echo hi",))
            )
            assert not done.wait(0.3)
            # The transition the hook waits for.  (This thread holds the
            # locks and takes them again.)
            if meanwhile == "replaced":
                tethered.activate(allow=["new.test"])
            else:
                tethered.deactivate()
        assert done.wait(30)
        thread.join(30)
        assert errors == []
        assert _core._config is not stale
        _assert_coherent()
        _assert_claim_is_free()

    # ── When nobody is left to give it up ──────────────────────────────

    def test_a_wait_does_not_outlast_the_shutdown_of_python(self):
        """A daemon thread stopped with the claim would keep the exiting process waiting for it."""
        env = {k: v for k, v in os.environ.items() if k != POLICY_VAR}
        child = subprocess.run(  # nosec B603
            [sys.executable, "-c", _SHUTDOWN_WITH_THE_CLAIM_TAKEN],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert child.returncode == 0, child.stderr
        assert child.stdout == (
            "tethered: another thread is in the middle of an activate() or deactivate() "
            "and Python is shutting down, so this call cannot wait for it"
        )

    @pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork()")
    # (Forking while another thread runs is the case under test.)
    @pytest.mark.filterwarnings("ignore:.*multi-threaded, use of fork:DeprecationWarning")
    @pytest.mark.parametrize("holder", ["another thread", "the forking thread"])
    def test_a_forked_child_has_the_claim_only_if_its_one_thread_took_it(self, holder):
        """A claim held by a thread the child does not have would never be given up there."""

        def child_takes_and_gives_up() -> int:
            pid = os.fork()
            if pid == 0:
                status = 1
                try:
                    signal.alarm(30)  # a wait that never ends is a failure, not a hang
                    with claim:
                        status = 0
                finally:
                    os._exit(status)
            return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])

        if holder == "the forking thread":
            with claim:
                assert child_takes_and_gives_up() == 0
        else:
            holding, release = threading.Event(), threading.Event()

            def hold() -> None:
                with claim:
                    holding.set()
                    assert release.wait(60)

            thread = threading.Thread(target=hold, daemon=True)
            thread.start()
            assert holding.wait(30)
            try:
                assert child_takes_and_gives_up() == 0
                contender = _Contender()
                assert contender.is_waiting()  # in the parent it is still held
            finally:
                release.set()
                thread.join(30)
            contender.finish()
        _assert_claim_is_free()


# ── R19: failure before commit leaves everything as it was ─────────


def _network_rule(i: int) -> str:
    """Distinct rules of one fixed width, so each costs the same to publish."""
    return f"10.{100 + i // 100}.{100 + i % 100}.0/24:443"


def _hostname_of_length(n: int) -> str:
    """An ordinary-looking host name exactly ``n`` characters long."""
    assert 20 <= n <= 250
    remaining = n - len(".test")
    labels = []
    while remaining > 60:
        labels.append("x" * 59)
        remaining -= 60  # the label and its dot
    labels.append("x" * remaining)
    name = ".".join(labels) + ".test"
    assert len(name) == n
    return name


def _allow_list_publishing(length: int, *, locked: bool = False) -> list[str]:
    """An allow list whose published payload is exactly ``length`` characters.

    Found by activating shorter lists and reading what was published, so it
    does not depend on how the payload is encoded — only on every
    fixed-width rule costing the same and one more character of host name
    costing one more character.  Leaves nothing active.
    """

    def published(allow: list[str]) -> int:
        secret = object()
        tethered.activate(allow=allow, locked=locked, lock_token=secret)
        size = len(os.environ[POLICY_VAR])
        tethered.deactivate(lock_token=secret)
        return size

    rules = [_network_rule(i) for i in range(1000)]
    filler = _hostname_of_length(100)
    base = published([*rules, filler])
    per_rule = published([*rules, _network_rule(1000), filler]) - base
    extra, rest = divmod(length - base, per_rule)
    assert extra >= 0
    rules += [_network_rule(1000 + i) for i in range(extra)]
    allow = [*rules, _hostname_of_length(100 + rest)]
    return allow


# Windows limits "NAME=value" to 32,767 characters.
WINDOWS_VALUE_LIMIT = 32767 - len(POLICY_VAR) - 1
on_windows = sys.platform == "win32"

PRIOR_STATES = ["nothing active", "unlocked policy", "locked policy"]


def _establish(prior: str, secret: object) -> None:
    if prior == "unlocked policy":
        tethered.activate(allow=["prior.test"])
    elif prior == "locked policy":
        tethered.activate(allow=["prior.test"], locked=True, lock_token=secret)


class TestOversizedPolicy:
    @pytest.mark.parametrize("locked", [False, True], ids=["unlocked", "locked"])
    def test_payload_at_the_windows_limit_activates(self, locked):
        secret = object()
        allow = _allow_list_publishing(WINDOWS_VALUE_LIMIT, locked=locked)
        tethered.activate(allow=allow, locked=locked, lock_token=secret)
        assert len(os.environ[POLICY_VAR]) == WINDOWS_VALUE_LIMIT
        _assert_coherent(secret)

    @pytest.mark.skipif(not on_windows, reason="only Windows limits the size of a variable")
    @pytest.mark.parametrize("prior", PRIOR_STATES)
    @pytest.mark.parametrize("locked", [False, True], ids=["unlocked", "locked"])
    def test_payload_over_the_windows_limit_changes_nothing(self, prior, locked, capfd):
        secret = object()
        allow = _allow_list_publishing(WINDOWS_VALUE_LIMIT + 1, locked=locked)
        _establish(prior, secret)
        before = _observe(secret)

        with pytest.raises(ValueError, match="Nothing was changed") as excinfo:
            tethered.activate(allow=allow, locked=locked, lock_token=secret)

        assert "32767" in str(excinfo.value.__cause__)
        assert _observe(secret) == before
        _assert_coherent(secret)
        assert "TAMPER DETECTED" not in capfd.readouterr().err

    @pytest.mark.skipif(on_windows, reason="covered by the real limit on Windows")
    def test_payload_over_the_windows_limit_is_fine_elsewhere(self):
        tethered.activate(allow=_allow_list_publishing(WINDOWS_VALUE_LIMIT + 1))
        assert len(os.environ[POLICY_VAR]) == WINDOWS_VALUE_LIMIT + 1
        _assert_coherent()

    @pytest.mark.parametrize("prior", PRIOR_STATES)
    @pytest.mark.parametrize("locked", [False, True], ids=["unlocked", "locked"])
    def test_failed_environment_write_changes_nothing(self, prior, locked, veto, capfd):
        """The same failure on any platform, injected at the ``os.putenv`` event."""
        secret = object()
        _establish(prior, secret)
        before = _observe(secret)
        veto("os.putenv", ValueError("the environment variable is longer than 32767 characters"))

        with pytest.raises(ValueError, match="Nothing was changed"):
            tethered.activate(allow=["new.test"], locked=locked, lock_token=secret)

        assert _observe(secret) == before
        _assert_coherent(secret)
        # The surviving policy still enforces, and still accepts its token.
        if prior != "nothing active":
            with pytest.raises(tethered.EgressBlocked):
                socket.getaddrinfo("new.test", 80)
        tethered.deactivate(lock_token=secret)
        assert "TAMPER DETECTED" not in capfd.readouterr().err

    def test_other_environment_failures_propagate_unwrapped(self, veto):
        veto("os.putenv", OSError("environment is read-only"))
        with pytest.raises(OSError, match="read-only"):
            tethered.activate(allow=["new.test"])
        assert _observe() == (None, False, True, True, None)

    def test_a_variable_tethered_did_not_write_survives_a_failed_activation(self, veto):
        """No policy active, but the variable is set (an inherited scope-only payload)."""
        inherited = '{"global": null, "scopes": []}'
        os.environ[POLICY_VAR] = inherited
        veto("os.putenv", ValueError("too long"))
        with pytest.raises(ValueError, match="Nothing was changed"):
            tethered.activate(allow=["new.test"])
        assert os.environ.get(POLICY_VAR) == inherited
        assert _core._config is None

    def test_failed_guardian_commit_restores_the_environment(self, monkeypatch):
        """A later step fails after the environment was written."""
        tethered.activate(allow=["prior.test"])
        before = _observe()
        with monkeypatch.context() as patch:
            patch.setattr(_core, "_build_integrity_snapshot", lambda cfg: [("not", "a pin")])
            with pytest.raises(TypeError):
                tethered.activate(allow=["new.test"], locked=True, lock_token=object())
        assert _observe() == before
        _assert_coherent()

    @pytest.mark.parametrize("prior", PRIOR_STATES)
    def test_failed_deactivation_changes_nothing(self, prior, veto):
        secret = object()
        _establish(prior, secret)
        if prior == "nothing active":
            os.environ[POLICY_VAR] = "{}"  # something for deactivate() to clear
        before = _observe(secret)
        veto("os.unsetenv", OSError("environment is read-only"))

        with pytest.raises(OSError, match="read-only"):
            tethered.deactivate(lock_token=secret)

        assert _observe(secret) == before
        tethered.deactivate(lock_token=secret)
        _assert_coherent()


# ── The guardian's part of the commit ──────────────────────────────


def _private_namespace() -> dict[str, object]:
    """A stand-in for ``_core``'s namespace holding just what the guardian reads.

    Lets a test drive the guardian's commit without touching the real
    module: the guardian binds and checks ``_config`` in whatever
    namespace it is handed.
    """
    names = ("EgressBlocked", "SubprocessBlocked", "_in_hook")
    names += ("_handle_getaddrinfo", "_fallback_resolve")
    namespace = {name: vars(_core)[name] for name in names}
    namespace["_config"] = None
    return namespace


class TestGuardianCommit:
    """The guardian rebinds ``_config`` itself, in the same step as its own state."""

    def test_activate_binds_the_config(self):
        namespace = _private_namespace()
        first, second, secret = object(), object(), object()
        try:
            guardian.activate(namespace, first, secret, [])
            assert namespace["_config"] is first
            assert guardian.verify() is True
            guardian.activate(namespace, second, secret, [])
            assert namespace["_config"] is second
            assert guardian.verify() is True
        finally:
            assert guardian.deactivate(secret) is True
        assert namespace["_config"] is None
        assert guardian.is_active() is False

    def test_deactivate_installs_the_replacement(self):
        namespace = _private_namespace()
        secret, replacement = object(), object()
        guardian.activate(namespace, object(), secret, [])
        assert guardian.deactivate(secret, replacement) is True
        assert namespace["_config"] is replacement
        assert guardian.is_active() is False

    def test_deactivate_does_nothing_when_nothing_is_locked(self):
        assert guardian.deactivate(object(), object()) is False
        assert _core._config is None

    def test_verify(self):
        namespace = _private_namespace()
        config, secret = object(), object()
        assert guardian.verify() is True  # inactive: nothing to verify
        guardian.activate(namespace, config, secret, [])
        try:
            assert guardian.verify() is True
            namespace["_config"] = object()
            assert guardian.verify() is False
            namespace["_config"] = config
            assert guardian.verify() is True
            del namespace["_config"]
            assert guardian.verify() is False
        finally:
            assert guardian.deactivate(secret) is True
        # Deactivation bound the name again.
        assert namespace["_config"] is None

    def test_activation_binds_a_name_that_was_missing(self):
        namespace = _private_namespace()
        del namespace["_config"]
        config, secret = object(), object()
        guardian.activate(namespace, config, secret, [])
        try:
            assert namespace["_config"] is config
        finally:
            guardian.deactivate(secret)

    def test_wrong_token_leaves_the_config_alone(self):
        namespace = _private_namespace()
        config, secret = object(), object()
        guardian.activate(namespace, config, secret, [])
        try:
            with pytest.raises(RuntimeError, match="lock_token"):
                guardian.activate(namespace, object(), object(), [])
            with pytest.raises(RuntimeError, match="lock_token"):
                guardian.deactivate(object(), object())
            assert namespace["_config"] is config
            assert guardian.verify() is True
        finally:
            guardian.deactivate(secret)

    def test_failed_activation_leaves_the_config_alone(self):
        namespace = _private_namespace()
        config, secret = object(), object()
        guardian.activate(namespace, config, secret, [])
        try:
            with pytest.raises(KeyError):
                guardian.activate(namespace, object(), secret, [(namespace, "nope", 1)])
            assert namespace["_config"] is config
            assert guardian.verify() is True
        finally:
            guardian.deactivate(secret)

    @pytest.mark.parametrize(
        "missing", ["EgressBlocked", "SubprocessBlocked", "_in_hook", "_fallback_resolve"]
    )
    def test_activation_needs_what_it_reads_from_the_namespace(self, missing):
        namespace = _private_namespace()
        del namespace[missing]
        with pytest.raises(KeyError, match=missing):
            guardian.activate(namespace, object(), object(), [])
        assert guardian.is_active() is False
        assert namespace["_config"] is None

    def test_resolver_callers_must_be_functions(self):
        namespace = _private_namespace()
        namespace["_handle_getaddrinfo"] = len
        with pytest.raises(TypeError, match="_handle_getaddrinfo"):
            guardian.activate(namespace, object(), object(), [])
        assert guardian.is_active() is False

    def test_namespace_must_be_a_dict(self):
        with pytest.raises(TypeError):
            guardian.activate(_core, object(), object(), [])
        assert guardian.is_active() is False


# ── Token rules across transitions ─────────────────────────────────


class TestTokenRules:
    def test_unlocked_to_locked_and_back(self):
        secret = object()
        tethered.activate(allow=["a.test"])
        _assert_coherent()
        tethered.activate(allow=["b.test"], locked=True, lock_token=secret)
        _assert_coherent(secret)
        tethered.activate(allow=["c.test"], lock_token=secret)
        _assert_coherent()
        assert guardian.is_active() is False
        assert _core._config.locked is False
        tethered.deactivate()
        _assert_coherent()

    @pytest.mark.parametrize("wrong", [None, object()], ids=["no token", "another object"])
    def test_wrong_token_changes_nothing(self, wrong):
        secret = object()
        tethered.activate(allow=["a.test"], locked=True, lock_token=secret)
        before = _observe(secret)
        with pytest.raises(tethered.TetheredLocked):
            tethered.deactivate(lock_token=wrong)
        with pytest.raises(tethered.TetheredLocked):
            tethered.activate(allow=["b.test"], lock_token=wrong)
        if wrong is not None:
            with pytest.raises(tethered.TetheredLocked):
                tethered.activate(allow=["b.test"], locked=True, lock_token=wrong)
        assert _observe(secret) == before
        _assert_coherent(secret)

    def test_identical_reactivation_changes_nothing(self):
        secret = object()
        tethered.activate(allow=["a.test"], locked=True, lock_token=secret)
        before = _observe(secret)
        tethered.activate(allow=["a.test"], locked=True, lock_token=object())
        assert _observe(secret) == before

    def test_rejected_arguments_change_nothing(self):
        tethered.activate(allow=["a.test"])
        before = _observe()
        for kwargs in (
            {"allow": "a.test"},
            {"allow": ["https://a.test"]},
            {"allow": [], "locked": True},
            {"allow": [], "locked": True, "lock_token": "text"},
            {"allow": [], "external_subprocess_policy": "sometimes"},
        ):
            with pytest.raises((TypeError, ValueError)):
                tethered.activate(**kwargs)
        assert _observe() == before
        _assert_coherent()

    def test_replacing_the_token_holder_needs_the_token_only_once(self):
        """After an authorized switch to an unlocked policy, no token is needed any more."""
        secret = object()
        tethered.activate(allow=["a.test"], locked=True, lock_token=secret)
        tethered.activate(allow=["b.test"], lock_token=secret)
        tethered.activate(allow=["c.test"])
        tethered.deactivate()
        _assert_coherent()

    def test_tampered_policy_can_be_neither_replaced_nor_deactivated(self, monkeypatch, capfd):
        """Re-activating would take a fresh snapshot of whatever is installed now."""
        secret = object()
        tethered.activate(allow=["a.test"], locked=True, lock_token=secret)
        with monkeypatch.context() as patch:
            patch.setattr(_core, "_handle_connect", lambda *args: None)
            before = _observe(secret)
            assert before[3] is False  # the guardian's own verdict
            with pytest.raises(tethered.TetheredLocked, match="integrity"):
                tethered.activate(allow=["a.test", "b.test"], locked=True, lock_token=secret)
            with pytest.raises(tethered.TetheredLocked, match="integrity"):
                tethered.activate(allow=["b.test"], lock_token=secret)
            with pytest.raises(tethered.TetheredLocked, match="integrity"):
                tethered.deactivate(lock_token=secret)
            # Without the token the answer is the ordinary one.
            with pytest.raises(tethered.TetheredLocked, match="policy is locked"):
                tethered.deactivate()
            assert _observe(secret) == before
        # The original objects are back: the policy is whole again.
        _assert_coherent(secret)
        tethered.deactivate(lock_token=secret)
        _assert_coherent()

    def test_unlocked_mode_works_without_the_extension(self, monkeypatch):
        monkeypatch.setattr(_core, "_c_guardian", None)
        tethered.activate(allow=["a.test"])
        assert os.environ[POLICY_VAR] == _core._config._serialized_payload
        tethered.activate(allow=["b.test"], lock_token=object())
        assert os.environ[POLICY_VAR] == _core._config._serialized_payload
        tethered.deactivate()
        assert _core._config is None
        assert POLICY_VAR not in os.environ


# ── The audit hook is really installed ─────────────────────────────
# sys.addaudithook() raises a "sys.addaudithook" event first.  A hook that is
# already installed can answer it with a RuntimeError, and the new hook is
# then dropped while the call returns normally.

REFUSED = "another audit hook in this process refused it, so nothing would be enforced"


class _HookList:
    """Stands in for the interpreter's list of audit hooks, as ``_install_hook()`` sees it.

    The real list cannot be used: a hook can never be removed, so one that
    refuses new hooks would stay for the rest of the session, and tethered's
    own hook is usually in it already.  Only the probe event is diverted to
    the stand-in; every other event still reaches the real hooks.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, refuse: bool = False) -> None:
        self.refuse = refuse
        self.hooks: list = []
        self.attempts = 0
        self._real_audit = sys.audit
        monkeypatch.setattr(sys, "addaudithook", self.add)
        monkeypatch.setattr(sys, "audit", self.audit)
        monkeypatch.setattr(_core, "_hook_installed", False)

    def add(self, hook) -> None:
        self.attempts += 1
        if not self.refuse:  # a refused hook is dropped without an error
            self.hooks.append(hook)

    def audit(self, event: str, *args: object) -> None:
        if event != _core._HOOK_PROBE_EVENT:
            self._real_audit(event, *args)
            return
        for hook in self.hooks:
            hook(event, args)


def _probe() -> list[bool]:
    """One entry for every copy of tethered's hook the interpreter really holds."""
    answers: list[bool] = []
    sys.audit(_core._HOOK_PROBE_EVENT, answers)
    return answers


# What a child process reports after trying to put a deny-all policy in place
# under a hook that refuses new hooks.  Such a hook is only ever installed in
# a child: here it would break every later test that adds a hook.
_REFUSING_PROCESS = """
import json, os, socket, sys


def refuse_new_hooks(event, args):
    if event == "sys.addaudithook":
        raise RuntimeError("no more audit hooks")


sys.addaudithook(refuse_new_hooks)

import tethered
import tethered._core as _core

server = socket.socket()
server.bind(("127.0.0.1", 0))
server.listen(1)

deny_all = {"allow": [], "allow_localhost": False}
report = {"raised": None, "body_ran": False}
try:
    if sys.argv[1] == "activate":
        tethered.activate(**deny_all)
    elif sys.argv[1] == "locked activate":
        tethered.activate(**deny_all, locked=True, lock_token=object())
    else:
        with tethered.scope(**deny_all):
            report["body_ran"] = True
except RuntimeError as exc:
    report["raised"] = str(exc)

with socket.socket() as client:
    try:
        client.connect(server.getsockname())
        report["connect"] = "connected"
    except tethered.EgressBlocked:
        report["connect"] = "blocked"

guardian = _core._c_guardian
report.update(
    hook_installed=_core._hook_installed,
    config=_core._config is not None,
    published=_core._CHILD_POLICY_ENV in os.environ,
    locked=guardian is not None and guardian.is_active(),
    scopes=len(_core._scopes.get()),
    active_scope_count=_core._active_scope_count,
)
print(json.dumps(report))
"""


class TestHookInstallation:
    """``_install_hook()`` confirms that the hook is live, and its callers fail if it is not."""

    def test_the_installed_hook_answers_the_probe_once(self):
        _core._install_hook()
        assert _core._hook_installed is True
        assert _probe() == [True]

    def test_a_lost_flag_does_not_add_the_hook_again(self, monkeypatch):
        """The hook is live but the flag says otherwise: nothing is added."""
        _core._install_hook()
        added: list = []
        monkeypatch.setattr(sys, "addaudithook", added.append)
        monkeypatch.setattr(_core, "_hook_installed", False)

        _core._install_hook()

        assert added == []
        assert _core._hook_installed is True
        assert _probe() == [True]

    def test_first_installation(self, monkeypatch):
        hooks = _HookList(monkeypatch)
        _core._install_hook()
        _core._install_hook()
        assert hooks.hooks == [_core._audit_hook]
        assert hooks.attempts == 1
        assert _core._hook_installed is True

    def test_refused_installation_raises(self, monkeypatch):
        hooks = _HookList(monkeypatch, refuse=True)
        with pytest.raises(RuntimeError, match=REFUSED):
            _core._install_hook()
        assert hooks.attempts == 1
        assert _core._hook_installed is False

    def test_a_later_call_tries_again(self, monkeypatch):
        hooks = _HookList(monkeypatch, refuse=True)
        for _ in range(2):
            with pytest.raises(RuntimeError, match=REFUSED):
                _core._install_hook()
        hooks.refuse = False

        _core._install_hook()
        _core._install_hook()

        assert hooks.hooks == [_core._audit_hook]
        assert hooks.attempts == 3
        assert _core._hook_installed is True

    def test_an_interrupted_installation_is_not_repeated(self, monkeypatch):
        """The hook went in, but the call ended before it could record that."""
        hooks = _HookList(monkeypatch)

        def add_then_interrupt(hook) -> None:
            hooks.add(hook)
            raise KeyboardInterrupt

        monkeypatch.setattr(sys, "addaudithook", add_then_interrupt)
        with pytest.raises(KeyboardInterrupt):
            _core._install_hook()
        assert _core._hook_installed is False
        monkeypatch.setattr(sys, "addaudithook", hooks.add)

        _core._install_hook()

        assert hooks.hooks == [_core._audit_hook]
        assert hooks.attempts == 1
        assert _core._hook_installed is True

    @pytest.mark.parametrize("locked", [False, True], ids=["unlocked", "locked"])
    def test_activate_changes_nothing(self, locked, monkeypatch, capfd):
        secret = object()
        inherited = '{"global": null, "scopes": []}'
        os.environ[POLICY_VAR] = inherited  # not written by tethered; must survive
        hooks = _HookList(monkeypatch, refuse=True)
        before = _observe(secret)

        with pytest.raises(RuntimeError, match=REFUSED):
            tethered.activate(allow=["new.test"], locked=locked, lock_token=secret)

        assert _observe(secret) == before
        assert _core._config is None
        assert guardian.is_active() is False
        assert os.environ[POLICY_VAR] == inherited
        assert _core._hook_installed is False

        # Once the hook is accepted, the same call goes through.
        hooks.refuse = False
        tethered.activate(allow=["new.test"], locked=locked, lock_token=secret)
        _assert_coherent(secret)
        assert hooks.hooks == [_core._audit_hook]
        assert "TAMPER DETECTED" not in capfd.readouterr().err

    def test_scope_entry_leaves_no_scope_behind(self, monkeypatch):
        hooks = _HookList(monkeypatch, refuse=True)
        guarded = tethered.scope(allow=[])
        ran: list[str] = []

        with pytest.raises(RuntimeError, match=REFUSED), guarded:
            ran.append("unprotected")

        assert ran == []
        assert _core._scopes.get() == ()
        assert _core._active_scope_count == 0

        # The instance was never entered, so it can be once the hook is accepted.
        hooks.refuse = False
        with guarded:
            assert _core._scopes.get() == (guarded._scope_cfg,)
            assert _core._active_scope_count == 1
        assert _core._scopes.get() == ()
        assert _core._active_scope_count == 0

    def test_decorated_function_does_not_run_unprotected(self, monkeypatch):
        _HookList(monkeypatch, refuse=True)
        ran: list[str] = []

        @tethered.scope(allow=[])
        def work() -> None:
            ran.append("unprotected")

        with pytest.raises(RuntimeError, match=REFUSED):
            work()

        assert ran == []
        assert _core._scopes.get() == ()
        assert _core._active_scope_count == 0

    @pytest.mark.asyncio
    async def test_decorated_coroutine_does_not_run_unprotected(self, monkeypatch):
        _HookList(monkeypatch, refuse=True)
        ran: list[str] = []

        @tethered.scope(allow=[])
        async def work() -> None:
            ran.append("unprotected")

        with pytest.raises(RuntimeError, match=REFUSED):
            await work()

        assert ran == []
        assert _core._scopes.get() == ()
        assert _core._active_scope_count == 0

    @pytest.mark.parametrize("how", ["activate", "locked activate", "scope"])
    def test_in_a_process_whose_hook_refuses_new_hooks(self, how):
        """The real thing: nothing can be enforced there, and the caller is told so."""
        result = subprocess.run(
            [sys.executable, "-c", _REFUSING_PROCESS, how],
            capture_output=True,
            text=True,
            timeout=60,
        )  # nosec B603 B607
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        raised = report.pop("raised")
        assert raised is not None, report
        assert REFUSED in raised
        assert report == {
            "body_ran": False,
            "connect": "connected",  # the deny-all policy is not there to refuse it
            "hook_installed": False,
            "config": False,
            "published": False,
            "locked": False,
            "scopes": 0,
            "active_scope_count": 0,
        }


_FORK_WITH_A_HELD_LOCK = """
import os, signal, socket, threading
import tethered
import tethered._core as core

tethered.activate(allow=["*.example.com"])
held = threading.Event()


def hold():
    core._ip_map_lock.acquire()
    core._lifecycle_lock.acquire()
    held.set()
    threading.Event().wait()


threading.Thread(target=hold, daemon=True).start()
assert held.wait(10)
pid = os.fork()
if pid == 0:
    signal.alarm(20)
    try:
        socket.getaddrinfo("localhost", 80)  # records the address: needs _ip_map_lock
        tethered.activate(allow=["*.example.org"])  # needs _lifecycle_lock
    except BaseException:
        os._exit(3)
    os._exit(0)
_, status = os.waitpid(pid, 0)
print("child", os.waitstatus_to_exitcode(status), flush=True)
os._exit(0)
"""

# The same in a process that has only entered a scope: the fork handler is
# registered there too, without the C extension.
_FORK_AFTER_A_SCOPE = """
import os, signal, sys, threading
import tethered
import tethered._core as core

with tethered.scope(allow=["*.example.com"]):
    pass
held = threading.Event()


def hold():
    core._state_lock.acquire()
    core._scope_count_lock.acquire()
    held.set()
    threading.Event().wait()


threading.Thread(target=hold, daemon=True).start()
assert held.wait(10)
pid = os.fork()
if pid == 0:
    signal.alarm(20)
    try:
        with tethered.scope(allow=["*.example.com"]):  # needs both locks
            pass
    except BaseException:
        os._exit(3)
    os._exit(4 if "tethered._guardian" in sys.modules else 0)
_, status = os.waitpid(pid, 0)
print("child", os.waitstatus_to_exitcode(status), flush=True)
os._exit(0)
"""


@pytest.mark.skipif(
    not hasattr(os, "register_at_fork"), reason="a process cannot fork on this platform"
)
class TestLocksAfterFork:
    """A lock that another thread held when the process forked must not hang the child.

    ``os.fork()`` copies one thread; a lock held by any other is copied
    locked, with nobody left to release it.  tethered resets its locks in
    the child, in place.
    """

    @staticmethod
    @contextlib.contextmanager
    def _held_by_another_thread(lock):
        """Run the block while another thread holds ``lock``."""
        taken, done = threading.Event(), threading.Event()

        def hold() -> None:
            lock.acquire()
            taken.set()
            done.wait(60)
            # Reset behind this thread's back if the test went well; still
            # held, and to be given back, if it did not.
            with contextlib.suppress(RuntimeError):
                lock.release()

        thread = threading.Thread(target=hold, daemon=True)
        thread.start()
        assert taken.wait(10)
        try:
            yield
        finally:
            done.set()
            thread.join(10)

    @pytest.mark.parametrize("name", ["_state_lock", "_ip_map_lock", "_scope_count_lock"])
    def test_a_lock_another_thread_held_is_free_again(self, name):
        lock = getattr(_core, name)
        with self._held_by_another_thread(lock):
            assert lock.acquire(blocking=False) is False
            _core._reinit_locks_after_fork()
            assert getattr(_core, name) is lock  # reset in place: the pinned object
            assert lock.acquire(blocking=False) is True
            lock.release()

    def test_the_lifecycle_lock_another_thread_held_is_free_again(self):
        with self._held_by_another_thread(_core._lifecycle_lock):
            assert _core._lifecycle_lock.acquire(blocking=False) is False
            _core._reinit_locks_after_fork()
            assert _core._lifecycle_lock.acquire(blocking=False) is True
            _core._lifecycle_lock.release()

    def test_a_lifecycle_lock_the_forking_thread_holds_stays_its_own(self):
        with _core._lifecycle_lock:
            _core._reinit_locks_after_fork()
            assert _core._lifecycle_lock._is_owned()
        # ... and was released by the with: taking it again from here works.
        assert _core._lifecycle_lock.acquire(blocking=False) is True
        _core._lifecycle_lock.release()

    def test_the_stand_in_claim_is_reset_too(self, monkeypatch):
        """Without the C extension the claim is a lock of this module's own."""
        claim = _core._UnsharedClaim()
        monkeypatch.setattr(_core, "_activation_claim", claim)
        with self._held_by_another_thread(claim._lock):
            _core._reinit_locks_after_fork()
            assert claim._lock.acquire(blocking=False) is True
            claim._lock.release()

    @pytest.mark.parametrize(
        "script",
        [_FORK_WITH_A_HELD_LOCK, _FORK_AFTER_A_SCOPE],
        ids=["after-activate", "after-a-scope-only"],
    )
    def test_a_forked_child_is_not_stuck_behind_a_lock_of_another_thread(self, script, tmp_path):
        """End to end: before the reset, the child waited for ever at its first lookup."""
        path = tmp_path / "fork_with_a_held_lock.py"
        path.write_text(script, encoding="utf-8")
        result = subprocess.run(  # nosec B603
            [sys.executable, str(path)], capture_output=True, text=True, timeout=60
        )
        assert result.stdout.strip() == "child 0", result.stderr


# ── The C extension and the fork handler, on first use ─────────────
# ``import tethered`` loads no C extension (on a free-threaded build, loading
# it re-enables the GIL) and registers no fork handler.  activate(),
# deactivate() and the startup bootstrap load the extension; they and the
# first scope() register the fork handler.  conftest.py loads the extension
# for the whole run, so what a process does on the way there is seen in
# fresh processes, and the loader's own steps here, with its state reset.

_FORK_HANDLER = (
    ["tethered._core._reinit_locks_after_fork"] if hasattr(os, "register_at_fork") else []
)

# A fresh process records the at-fork handlers registered from tethered's
# modules, imports tethered, takes the steps named in ``sys.argv`` and
# reports what is loaded after each.
_FIRST_USE = """
import json, os, sys

registered = []
if hasattr(os, "register_at_fork"):
    register = os.register_at_fork

    def recording(**handlers):
        for handler in handlers.values():
            name = getattr(handler, "__module__", "") + "." + getattr(handler, "__qualname__", "")
            registered.append(name)
        register(**handlers)

    os.register_at_fork = recording

gil = getattr(sys, "_is_gil_enabled", lambda: None)
report = {"gil before": gil()}


def state():
    core = sys.modules["tethered._core"]
    guardian = sys.modules.get("tethered._guardian")
    return {
        "extension": guardian is not None,
        "bound": guardian is not None
        and core._c_guardian is guardian
        and core._activation_claim is guardian.activation_claim,
        "fork handlers": [name for name in registered if name.startswith("tethered.")],
        "gil": gil(),
    }


import tethered

report["import"] = state()
report["steps"] = []
for step in sys.argv[1:]:
    if step == "scope":
        with tethered.scope(allow=["a.test"]):
            pass
        tethered.scope(allow=["a.test"])(lambda: None)()
    elif step == "activate":
        tethered.activate(allow=["a.test"])
    else:
        tethered.deactivate()
    report["steps"].append(state())
print(json.dumps(report))
"""


def _first_use(*steps: str) -> dict:
    env = {k: v for k, v in os.environ.items() if k != POLICY_VAR}
    result = subprocess.run(  # nosec B603
        [sys.executable, "-c", _FIRST_USE, *steps],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.splitlines()[-1])


class _Failing:
    """A meta path finder for which importing the C extension fails with a RuntimeError."""

    @staticmethod
    def find_spec(name, path=None, target=None):
        if name == "tethered._guardian":
            raise RuntimeError("the extension failed to load")
        return None


class TestLoadingOnFirstUse:
    def test_importing_tethered_loads_and_registers_nothing(self):
        report = _first_use()
        assert report["import"] == {
            "extension": False,
            "bound": False,
            "fork handlers": [],
            "gil": report["gil before"],  # on a free-threaded build: still off
        }

    @pytest.mark.parametrize(
        "steps",
        [
            ["scope", "scope"],
            ["activate"],
            ["deactivate"],
            ["scope", "activate", "deactivate", "scope"],
        ],
        ids=["scope", "activate", "deactivate", "scope-then-activate"],
    )
    def test_activate_and_deactivate_load_it_and_a_scope_does_not(self, steps):
        report = _first_use(*steps)
        loaded = False
        for step, found in zip(steps, report["steps"], strict=True):
            loaded = loaded or step != "scope"
            assert found["extension"] is loaded, step
            assert found["bound"] is loaded, step
            # Registered by whichever came first, and once.
            assert found["fork handlers"] == _FORK_HANDLER, step
            if not loaded:
                assert found["gil"] == report["gil before"]

    @pytest.mark.parametrize(
        ("payload", "loaded"),
        [
            (None, False),
            ({"global": {"allow": ["a.test"]}, "scopes": []}, True),
            ({"global": None, "scopes": [{"allow": ["a.test"]}]}, True),
        ],
        ids=["no-policy", "a-policy", "scopes-only"],
    )
    def test_the_bootstrap_of_a_child_loads_it(self, payload, loaded):
        """The bootstrap takes the claim and asks about a lock, whatever the payload holds."""
        env = {k: v for k, v in os.environ.items() if k != POLICY_VAR}
        if payload is not None:
            env[POLICY_VAR] = json.dumps(payload)
        result = subprocess.run(  # nosec B603
            [
                sys.executable,
                "-c",
                "import json, sys; print(json.dumps('tethered._guardian' in sys.modules))",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) is loaded

    # ── The same steps in this process, with the loader's state reset ──

    @pytest.fixture
    def unloaded(self, monkeypatch) -> list[dict]:
        """tethered as importing it leaves it; returns the fork handlers registered from now on."""
        registered: list[dict] = []
        # What the loader imports: the instance the run started with.
        monkeypatch.setitem(sys.modules, "tethered._guardian", guardian)
        monkeypatch.setattr(tethered, "_guardian", guardian)
        monkeypatch.setattr(_core, "_guardian_load_pending", True)
        monkeypatch.setattr(_core, "_c_guardian", None)
        monkeypatch.setattr(_core, "_activation_claim", _core._UnsharedClaim())
        monkeypatch.setattr(_core, "_fork_handler_pending", True)
        monkeypatch.setattr(_core, "_REGISTER_AT_FORK", lambda **kw: registered.append(kw))
        if not hasattr(_core, "_reinit_locks_after_fork"):  # where a process cannot fork
            monkeypatch.setattr(_core, "_reinit_locks_after_fork", lambda: None, raising=False)
        return registered

    @staticmethod
    def _assert_loaded() -> None:
        assert _core._c_guardian is guardian
        assert _core._activation_claim is guardian.activation_claim
        assert _core._guardian_load_pending is False

    @staticmethod
    def _assert_not_loaded(stand_in: object) -> None:
        assert _core._c_guardian is None
        assert _core._activation_claim is stand_in
        assert _core._guardian_load_pending is True

    def test_scope_here(self, unloaded):
        stand_in = _core._activation_claim
        with tethered.scope(allow=["a.test"]):
            pass
        tethered.scope(allow=["a.test"])(lambda: None)()
        self._assert_not_loaded(stand_in)
        assert unloaded == [{"after_in_child": _core._reinit_locks_after_fork}]
        assert _core._fork_handler_pending is False

    @pytest.mark.parametrize("call", ["activate", "deactivate"])
    def test_activate_and_deactivate_here(self, call, unloaded):
        if call == "activate":
            tethered.activate(allow=["a.test"])
            tethered.deactivate()
        else:
            tethered.deactivate()
        self._assert_loaded()
        assert unloaded == [{"after_in_child": _core._reinit_locks_after_fork}]
        _assert_coherent()

    def test_the_bootstrap_and_a_join_here(self, unloaded):
        from tethered import _autoactivate

        assert _autoactivate._claim_and_guardian() == (guardian.activation_claim, guardian)
        self._assert_loaded()
        _core._guardian_load_pending = True
        _core._c_guardian = None
        with pytest.raises(KeyError):
            _core._join_locked("{}")  # loaded first, then the payload is read
        self._assert_loaded()
        assert len(unloaded) == 1

    def test_a_stand_in_survives_the_loader(self, monkeypatch):
        # (The egress guard in conftest.py asks whatever is there.)
        stand_in = types.SimpleNamespace(is_active=lambda: False)
        claim_stand_in = _core._UnsharedClaim()
        monkeypatch.setattr(_core, "_guardian_load_pending", True)
        monkeypatch.setattr(_core, "_c_guardian", stand_in)
        monkeypatch.setattr(_core, "_activation_claim", claim_stand_in)
        _core._load_guardian()
        assert _core._c_guardian is stand_in
        assert _core._activation_claim is claim_stand_in
        assert _core._guardian_load_pending is False

    def test_without_the_extension(self, unloaded, monkeypatch):
        """As in a build without it: an unlocked policy works, a locked one is refused."""
        monkeypatch.setitem(sys.modules, "tethered._guardian", None)
        monkeypatch.delattr(tethered, "_guardian")
        stand_in = _core._activation_claim

        tethered.activate(allow=["a.test"])
        assert _core._c_guardian is None
        assert _core._activation_claim is stand_in
        assert _core._guardian_load_pending is False
        assert os.environ[POLICY_VAR] == _core._config._serialized_payload
        with pytest.raises(RuntimeError, match="requires the C guardian extension"):
            tethered.activate(allow=["a.test"], locked=True, lock_token=object())
        tethered.deactivate()
        assert _core._config is None
        assert POLICY_VAR not in os.environ

    def test_another_failure_is_raised_and_the_next_call_tries_again(self, unloaded, monkeypatch):
        stand_in = _core._activation_claim
        with monkeypatch.context() as patch:
            patch.delitem(sys.modules, "tethered._guardian")
            patch.delattr(tethered, "_guardian")
            patch.setattr(sys, "meta_path", [_Failing(), *sys.meta_path])
            with pytest.raises(RuntimeError, match="failed to load"):
                tethered.activate(allow=["a.test"])
            self._assert_not_loaded(stand_in)
            assert _core._config is None
        tethered.activate(allow=["a.test"])
        tethered.deactivate()
        self._assert_loaded()

    def test_its_flags_set_again_under_a_lock_change_nothing(self, unloaded, capfd):
        """They are unpinned runtime state: setting them again rebinds nothing the guardian pins."""
        token = object()
        tethered.activate(allow=["a.test"], locked=True, lock_token=token)
        _core._guardian_load_pending = True
        _core._fork_handler_pending = True
        _core._load_guardian()
        self._assert_loaded()
        assert guardian.verify() is True
        # The handler once more, which resets the locks once more in a child.
        assert unloaded == [{"after_in_child": _core._reinit_locks_after_fork}] * 2
        assert "TAMPER DETECTED" not in capfd.readouterr().err
        tethered.deactivate(lock_token=token)
        _assert_coherent()

    def test_where_a_process_cannot_fork_nothing_is_registered(self, unloaded, monkeypatch):
        monkeypatch.setattr(_core, "_REGISTER_AT_FORK", None)
        _core._install_hook()
        assert _core._fork_handler_pending is False
        _core._load_guardian()
        assert unloaded == []

    def test_an_interrupted_registration_is_made_by_the_next_call(self, unloaded, monkeypatch):
        def interrupted(**handlers):
            monkeypatch.setattr(_core, "_REGISTER_AT_FORK", lambda **kw: unloaded.append(kw))
            raise KeyboardInterrupt

        monkeypatch.setattr(_core, "_REGISTER_AT_FORK", interrupted)
        with pytest.raises(KeyboardInterrupt):
            _core._install_hook()
        assert _core._fork_handler_pending is True
        _core._install_hook()
        assert unloaded == [{"after_in_child": _core._reinit_locks_after_fork}]
        assert _core._fork_handler_pending is False
