"""Tests for the activation lifecycle: serialization, failure safety, token rules.

``activate()`` and ``deactivate()`` change four things that must always
describe the same policy: the ``_config`` reference, the C guardian's state,
whether the audit hook is installed, and the ``_TETHERED_CHILD_POLICY``
environment variable read by child processes.
"""

from __future__ import annotations

import inspect
import json
import os
import random
import socket
import subprocess
import sys
import threading

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
    """
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(64)

    def drain() -> None:
        while True:
            try:
                conn, _ = server.accept()
                conn.close()
            except OSError:
                return

    threading.Thread(target=drain, daemon=True).start()
    yield server.getsockname()[1]
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
