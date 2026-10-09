"""Tests for the tethered exception classes: pickling, copying, worker pools.

A blocked call raised inside a pool worker reaches the parent as a pickle,
so ``EgressBlocked`` and ``SubprocessBlocked`` have to survive that trip with
every attribute.  The pool tests spawn real worker processes; they are
offline — the only socket activity is a loopback connect that tethered
blocks before it leaves the audit hook.
"""

from __future__ import annotations

import copy
import multiprocessing
import os
import pickle
import socket
from concurrent.futures import ProcessPoolExecutor

import pytest

import tethered

_PROTOCOLS = range(pickle.HIGHEST_PROTOCOL + 1)

# Spawn-mode workers start slowly on Windows.  The timeout is what turns a
# regression into a failure: with an unpicklable exception a
# ``multiprocessing.Pool`` result never arrives at all.
_POOL_TIMEOUT = 30

_EGRESS_ATTRS = ("host", "port", "resolved_from", "scope_label", "scope_hint")
_SUBPROCESS_ATTRS = ("event", "description")


class _EgressBlockedWithContext(tethered.EgressBlocked):
    """A subclass whose constructor takes different arguments than its base."""

    def __init__(self, request_id: str, host: str, port: int | None) -> None:
        super().__init__(host, port, scope_label="request-scope")
        self.request_id = request_id


class _SubprocessBlockedWithContext(tethered.SubprocessBlocked):
    def __init__(self, request_id: str) -> None:
        super().__init__("subprocess.Popen", "curl https://example.test")
        self.request_id = request_id


def _full_egress_blocked() -> tethered.EgressBlocked:
    return tethered.EgressBlocked(
        "203.0.113.7",
        443,
        resolved_from="api.example.test",
        scope_label="scope(api.example.test:443)",
        scope_hint="mylib needs api.example.test:443",
    )


def _assert_same_exception(clone, original, attrs):
    assert clone is not original
    assert type(clone) is type(original)
    assert clone.args == original.args
    assert str(clone) == str(original)
    assert vars(clone) == vars(original)
    for attr in attrs:
        assert getattr(clone, attr) == getattr(original, attr)


class TestEgressBlockedRoundTrip:
    @pytest.mark.parametrize("protocol", _PROTOCOLS)
    def test_pickle_preserves_every_attribute(self, protocol):
        original = _full_egress_blocked()

        clone = pickle.loads(pickle.dumps(original, protocol))

        _assert_same_exception(clone, original, _EGRESS_ATTRS)
        assert clone.host == "203.0.113.7"
        assert clone.port == 443
        assert clone.resolved_from == "api.example.test"
        assert clone.scope_label == "scope(api.example.test:443)"
        assert clone.scope_hint == "mylib needs api.example.test:443"
        assert str(clone) == (
            "Blocked by tethered: 203.0.113.7:443 (resolved from api.example.test) "
            "is not in the allow list (blocked by scope(api.example.test:443))\n"
            "Hint: mylib needs api.example.test:443"
        )

    @pytest.mark.parametrize("protocol", _PROTOCOLS)
    def test_pickle_with_only_required_arguments(self, protocol):
        """The reviewed failure: ``__init__() missing 1 required positional argument: 'port'``."""
        original = tethered.EgressBlocked("example.test", 443)

        clone = pickle.loads(pickle.dumps(original, protocol))

        _assert_same_exception(clone, original, _EGRESS_ATTRS)
        assert (clone.resolved_from, clone.scope_label, clone.scope_hint) == (None, None, None)

    def test_pickle_without_a_port(self):
        original = tethered.EgressBlocked("example.test", None)

        clone = pickle.loads(pickle.dumps(original))

        _assert_same_exception(clone, original, _EGRESS_ATTRS)
        assert clone.port is None
        assert str(clone) == "Blocked by tethered: example.test is not in the allow list"

    def test_copy(self):
        original = _full_egress_blocked()
        _assert_same_exception(copy.copy(original), original, _EGRESS_ATTRS)

    def test_deepcopy(self):
        original = _full_egress_blocked()
        _assert_same_exception(copy.deepcopy(original), original, _EGRESS_ATTRS)

    def test_pickle_of_a_raised_exception(self):
        """A traceback, context and cause on the instance do not get in the way."""
        try:
            try:
                raise OSError("connection refused")
            except OSError as cause:
                raise _full_egress_blocked() from cause
        except tethered.EgressBlocked as exc:
            original = exc

        clone = pickle.loads(pickle.dumps(original))

        _assert_same_exception(clone, original, _EGRESS_ATTRS)

    @pytest.mark.skipif(
        not hasattr(BaseException, "add_note"), reason="exception notes need Python 3.11+"
    )
    def test_notes_survive(self):
        original = _full_egress_blocked()
        original.add_note("while fetching the weather forecast")

        for clone in (pickle.loads(pickle.dumps(original)), copy.copy(original)):
            _assert_same_exception(clone, original, _EGRESS_ATTRS)
            assert clone.__notes__ == ["while fetching the weather forecast"]

    @pytest.mark.parametrize("duplicate", [copy.copy, copy.deepcopy, pickle.loads])
    def test_subclass_with_its_own_constructor(self, duplicate):
        """Rebuilding does not call ``__init__``, so any subclass signature works."""
        original = _EgressBlockedWithContext("req-42", "example.test", 443)
        source = pickle.dumps(original) if duplicate is pickle.loads else original

        clone = duplicate(source)

        _assert_same_exception(clone, original, (*_EGRESS_ATTRS, "request_id"))
        assert clone.request_id == "req-42"
        assert clone.scope_label == "request-scope"

    def test_clone_can_be_raised_and_caught(self):
        clone = pickle.loads(pickle.dumps(_full_egress_blocked()))
        with pytest.raises(tethered.EgressBlocked, match=r"203\.0\.113\.7:443") as excinfo:
            raise clone
        assert isinstance(excinfo.value, RuntimeError)

    def test_constructor_signature_is_unchanged(self):
        """host and port are positional; the optional attributes stay keyword-only."""
        exc = tethered.EgressBlocked("example.test", 443)
        assert (exc.host, exc.port) == ("example.test", 443)
        with pytest.raises(TypeError):
            tethered.EgressBlocked("example.test")
        with pytest.raises(TypeError):
            tethered.EgressBlocked("example.test", 443, "api.example.test")


class TestSubprocessBlockedRoundTrip:
    @pytest.mark.parametrize("protocol", _PROTOCOLS)
    def test_pickle_preserves_every_attribute(self, protocol):
        original = tethered.SubprocessBlocked("subprocess.Popen", "curl https://example.test")

        clone = pickle.loads(pickle.dumps(original, protocol))

        _assert_same_exception(clone, original, _SUBPROCESS_ATTRS)
        assert clone.event == "subprocess.Popen"
        assert clone.description == "curl https://example.test"
        assert str(clone).startswith("Blocked by tethered: curl https://example.test")

    def test_copy(self):
        original = tethered.SubprocessBlocked("os.system", "curl https://example.test")
        _assert_same_exception(copy.copy(original), original, _SUBPROCESS_ATTRS)

    def test_deepcopy(self):
        original = tethered.SubprocessBlocked("os.system", "curl https://example.test")
        _assert_same_exception(copy.deepcopy(original), original, _SUBPROCESS_ATTRS)

    @pytest.mark.parametrize("duplicate", [copy.copy, copy.deepcopy, pickle.loads])
    def test_subclass_with_its_own_constructor(self, duplicate):
        original = _SubprocessBlockedWithContext("req-42")
        source = pickle.dumps(original) if duplicate is pickle.loads else original

        clone = duplicate(source)

        _assert_same_exception(clone, original, (*_SUBPROCESS_ATTRS, "request_id"))
        assert clone.request_id == "req-42"

    def test_constructor_signature_is_unchanged(self):
        exc = tethered.SubprocessBlocked("subprocess.Popen", "curl")
        assert (exc.event, exc.description) == ("subprocess.Popen", "curl")
        with pytest.raises(TypeError):
            tethered.SubprocessBlocked("subprocess.Popen")


class TestTetheredLockedRoundTrip:
    """``TetheredLocked`` always round-tripped; keep it that way."""

    @pytest.mark.parametrize("message", [None, "tethered: activate() blocked"])
    @pytest.mark.parametrize("duplicate", [copy.copy, copy.deepcopy, pickle.loads])
    def test_round_trip(self, message, duplicate):
        original = tethered.TetheredLocked(message)
        source = pickle.dumps(original) if duplicate is pickle.loads else original

        clone = duplicate(source)

        _assert_same_exception(clone, original, ())
        if message is not None:
            assert str(clone) == message


def _connect_to_loopback(port: int, hint: str | None = None) -> str:
    """Pool worker: try a loopback connect that the inherited deny-all policy blocks.

    Lives at module scope so spawn-mode workers can import it.  With ``hint``
    the connect runs inside a hinted scope; the block still comes from the
    global policy, and carries the hint as ``EgressBlocked.scope_hint``.
    """
    with socket.socket() as sock:
        sock.settimeout(5)
        if hint is None:
            sock.connect(("127.0.0.1", port))
        else:
            with tethered.scope(allow=["127.0.0.1"], hint=hint):
                sock.connect(("127.0.0.1", port))
    return "connected"


@pytest.fixture
def blocked_loopback_port():
    """A listening loopback port under a deny-all policy that pool workers inherit.

    The listener makes a missing policy visible: a worker that did not
    inherit it connects and returns instead of raising.
    """
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        tethered.activate(allow=[], allow_localhost=False)
        yield listener.getsockname()[1]


def _assert_blocked_loopback(exc, port, hint=None):
    assert type(exc) is tethered.EgressBlocked
    assert exc.host == "127.0.0.1"
    assert exc.port == port
    assert exc.scope_label is None
    assert exc.scope_hint == hint
    assert exc.args == (str(exc),)
    assert str(exc).startswith(f"Blocked by tethered: 127.0.0.1:{port}")
    assert "is not in the allow list" in str(exc)
    if hint is not None:
        assert str(exc).endswith(f"\nHint: {hint}")


class TestBlockedCallInWorkerPool:
    """A blocked call in a spawn-mode worker must raise ``EgressBlocked`` in the parent.

    Before the exceptions were picklable, ``ProcessPoolExecutor`` reported
    ``BrokenProcessPool`` and lost the pool, and ``multiprocessing.Pool``
    lost its result-handler thread, so ``get()`` never returned.
    """

    def test_process_pool_executor(self, blocked_loopback_port):
        port = blocked_loopback_port
        ctx = multiprocessing.get_context("spawn")
        with ProcessPoolExecutor(max_workers=1, mp_context=ctx) as executor:
            plain = executor.submit(_connect_to_loopback, port)
            hinted = executor.submit(_connect_to_loopback, port, "ask the platform team")
            with pytest.raises(tethered.EgressBlocked) as plain_info:
                plain.result(timeout=_POOL_TIMEOUT)
            with pytest.raises(tethered.EgressBlocked) as hinted_info:
                hinted.result(timeout=_POOL_TIMEOUT)
            # The pool is still usable after delivering the exceptions.
            worker_pid = executor.submit(os.getpid).result(timeout=_POOL_TIMEOUT)

        _assert_blocked_loopback(plain_info.value, port)
        _assert_blocked_loopback(hinted_info.value, port, hint="ask the platform team")
        assert worker_pid != os.getpid()

    def test_multiprocessing_pool(self, blocked_loopback_port):
        port = blocked_loopback_port
        pool = multiprocessing.get_context("spawn").Pool(processes=1)
        try:
            plain = pool.apply_async(_connect_to_loopback, (port,))
            hinted = pool.apply_async(_connect_to_loopback, (port, "ask the platform team"))
            with pytest.raises(tethered.EgressBlocked) as plain_info:
                plain.get(timeout=_POOL_TIMEOUT)
            with pytest.raises(tethered.EgressBlocked) as hinted_info:
                hinted.get(timeout=_POOL_TIMEOUT)
            # The pool is still usable after delivering the exceptions.
            worker_pid = pool.apply_async(os.getpid).get(timeout=_POOL_TIMEOUT)
        finally:
            pool.terminate()
            pool.join()

        _assert_blocked_loopback(plain_info.value, port)
        _assert_blocked_loopback(hinted_info.value, port, hint="ask the platform team")
        assert worker_pid != os.getpid()
