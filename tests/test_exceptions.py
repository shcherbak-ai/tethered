"""Tests for the tethered exception classes: pickling, copying, worker pools.

A blocked call raised inside a pool worker reaches the parent as a pickle,
so ``EgressBlocked`` and ``SubprocessBlocked`` have to survive that trip with
every attribute.  A transport that does not pickle (Celery's JSON result
serializer) keeps the class and ``args``, so both can also be rebuilt from
their message alone.  The pool tests spawn real worker processes; they are
offline — the only socket activity is a loopback connect that tethered
blocks before it leaves the audit hook.
"""

from __future__ import annotations

import copy
import json
import multiprocessing
import os
import pickle
import socket
import subprocess
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


# What the C guardian says to an interpreter that is outside a lock.
_OUTSIDE_THE_LOCK = (
    "a locked tethered policy is active in another interpreter of this process, so this interpreter"
)


def _rebuilt_from_args(original):
    """What a transport that keeps the class and ``args`` gives back.

    Celery's JSON result serializer does this: ``args`` goes through JSON
    and the producer calls ``cls(*args)``.
    """
    return type(original)(*json.loads(json.dumps(original.args)))


class TestEgressBlockedFromItsMessage:
    """``EgressBlocked(*exc.args)`` gives the exception back, attributes included."""

    @pytest.mark.parametrize(
        ("args", "kwargs"),
        [
            pytest.param(("example.test", 443), {}, id="name-and-port"),
            pytest.param(("example.test", None), {}, id="name"),
            pytest.param(("example.test", 0), {}, id="port-0"),
            pytest.param(("example.test", 65535), {}, id="port-65535"),
            pytest.param(("203.0.113.7", 443), {"resolved_from": "api.example.test"}, id="ipv4"),
            pytest.param(("2001:db8::8a2e:370:7334", 443), {}, id="ipv6-and-port"),
            pytest.param(("2001:db8::8a2e:370:7334", None), {}, id="ipv6"),
            pytest.param(("::1", 8080), {"resolved_from": "localhost"}, id="ipv6-resolved"),
            pytest.param(("fe80::1%eth0", 22), {}, id="ipv6-zone"),
            pytest.param(
                ("example.test", 443), {"scope_label": "scope(api.example.test:443)"}, id="label"
            ),
            pytest.param(
                ("example.test", None), {"scope_hint": "mylib needs api.example.test"}, id="hint"
            ),
            pytest.param(("<unreadable b'\\xff'>", None), {}, id="unreadable"),
        ],
    )
    def test_every_attribute_comes_back(self, args, kwargs):
        original = tethered.EgressBlocked(*args, **kwargs)

        clone = _rebuilt_from_args(original)

        _assert_same_exception(clone, original, _EGRESS_ATTRS)

    def test_with_every_attribute_set(self):
        original = _full_egress_blocked()

        clone = _rebuilt_from_args(original)

        _assert_same_exception(clone, original, _EGRESS_ATTRS)
        assert clone.host == "203.0.113.7"
        assert clone.port == 443
        assert clone.resolved_from == "api.example.test"
        assert clone.scope_label == "scope(api.example.test:443)"
        assert clone.scope_hint == "mylib needs api.example.test:443"

    def test_a_real_refusal(self, blocked_loopback_port):
        with socket.socket() as sock, pytest.raises(tethered.EgressBlocked) as excinfo:
            sock.connect(("127.0.0.1", blocked_loopback_port))

        clone = _rebuilt_from_args(excinfo.value)

        assert clone is not excinfo.value
        _assert_blocked_loopback(clone, blocked_loopback_port)

    def test_the_rebuilt_exception_can_be_raised_and_caught(self):
        clone = _rebuilt_from_args(_full_egress_blocked())
        with pytest.raises(tethered.EgressBlocked, match=r"203\.0\.113\.7:443"):
            raise clone

    def test_an_ipv6_address_with_a_port_is_written_like_an_allow_rule(self):
        """``2001:db8::1:443`` would not say where the address ends."""
        assert str(tethered.EgressBlocked("2001:db8::1", 443)) == (
            "Blocked by tethered: [2001:db8::1]:443 is not in the allow list"
        )
        assert str(tethered.EgressBlocked("2001:db8::1", None)) == (
            "Blocked by tethered: 2001:db8::1 is not in the allow list"
        )

    def test_the_message_is_kept_to_the_letter(self):
        message = "Blocked by tethered: example.test:0443 is not in the allow list (see the log)"

        clone = tethered.EgressBlocked(message)

        assert str(clone) == message
        assert clone.args == (message,)
        assert (clone.host, clone.port) == ("example.test", 443)
        assert clone.scope_label is None  # not the form a label is written in

    def test_a_resolved_from_equal_to_the_host_was_never_in_the_message(self):
        original = tethered.EgressBlocked("example.test", 443, resolved_from="example.test")

        clone = _rebuilt_from_args(original)

        assert str(clone) == str(original)
        assert (clone.host, clone.port, clone.resolved_from) == ("example.test", 443, None)

    def test_a_message_of_the_guardian_for_an_interpreter_outside_the_lock(self):
        message = (
            f"Blocked by tethered: forbidden.test ({_OUTSIDE_THE_LOCK} gets no network access)"
        )

        clone = tethered.EgressBlocked(message)

        assert str(clone) == message
        assert (clone.host, clone.port) == ("forbidden.test", None)
        assert (clone.resolved_from, clone.scope_label, clone.scope_hint) == (None, None, None)

    def test_a_message_written_before_addresses_were_bracketed(self):
        """From a worker with an older tethered: the port stays where the message has it."""
        clone = tethered.EgressBlocked(
            "Blocked by tethered: 2001:db8::1:443 is not in the allow list"
        )
        assert (clone.host, clone.port) == ("2001:db8::1:443", None)

    @pytest.mark.parametrize(
        "target",
        [
            "example.test:https",
            "example.test:",
            "example.test:123456",
            "example.test:٤٤٣",
            "[2001:db8::1]",
            "[2001:db8::1]:x",
        ],
    )
    def test_what_is_not_a_port_stays_in_the_host(self, target):
        clone = tethered.EgressBlocked(f"Blocked by tethered: {target} is not in the allow list")
        assert (clone.host, clone.port) == (target, None)

    def test_an_unfinished_resolved_from_is_none(self):
        clone = tethered.EgressBlocked(
            "Blocked by tethered: 203.0.113.7:443 (resolved from api is not in the allow list"
        )
        assert (clone.host, clone.port, clone.resolved_from) == ("203.0.113.7", 443, None)

    @pytest.mark.parametrize(
        "argument",
        ["example.test", "", "blocked by tethered: x", b"Blocked by tethered: x", None, 443],
    )
    def test_anything_but_a_message_is_still_a_type_error(self, argument):
        with pytest.raises(TypeError, match="takes a host and a port, or nothing but the message"):
            tethered.EgressBlocked(argument)

    def test_a_message_with_another_field_is_a_type_error(self):
        message = str(tethered.EgressBlocked("example.test", 443))
        with pytest.raises(TypeError, match="nothing but the message"):
            tethered.EgressBlocked(message, scope_label="scope(example.test)")

    def test_a_host_that_reads_like_a_message_stays_a_host_when_a_port_is_passed(self):
        """The hook always passes a port, ``None`` included: it never takes a host apart."""
        looks_like_a_message = str(tethered.EgressBlocked("allowed.test", 443))

        exc = tethered.EgressBlocked(looks_like_a_message, None)

        assert exc.host == looks_like_a_message
        assert str(exc) == f"Blocked by tethered: {looks_like_a_message} is not in the allow list"


class TestSubprocessBlockedFromItsMessage:
    """``SubprocessBlocked(*exc.args)`` gives the exception back."""

    @pytest.mark.parametrize(
        ("event", "description"),
        [
            ("subprocess.Popen", "subprocess.Popen(curl)"),
            ("os.system", "os.system('curl https://example.test (again)')"),
            ("os.exec", "os.exec*(/bin/sh)"),
            ("os.posix_spawn", "os.posix_spawn(/bin/sh)"),
            ("os.spawn", "os.spawn*(/bin/sh)"),
            ("os.startfile", "os.startfile(report.docx)"),
            ("_winapi.CreateProcess", "_winapi.CreateProcess(curl.exe)"),
            ("_posixsubprocess.fork_exec", "_posixsubprocess.fork_exec(/usr/bin/curl)"),
            ("subprocess.Popen", "subprocess.Popen(python) — started with -S (no site)"),
            ("os.putenv", "os.putenv refused: locked policy integrity violated"),
            ("open", "open refused: locked policy integrity violated"),
        ],
    )
    def test_event_and_description_come_back(self, event, description):
        original = tethered.SubprocessBlocked(event, description)

        clone = _rebuilt_from_args(original)

        _assert_same_exception(clone, original, _SUBPROCESS_ATTRS)
        assert (clone.event, clone.description) == (event, description)

    def test_a_real_refusal(self):
        tethered.activate(allow=[], external_subprocess_policy="block")
        with pytest.raises(tethered.SubprocessBlocked) as excinfo:
            subprocess.Popen(["tethered-test-no-such-tool"])  # refused before it is looked for

        clone = _rebuilt_from_args(excinfo.value)

        _assert_same_exception(clone, excinfo.value, _SUBPROCESS_ATTRS)
        assert clone.event == "subprocess.Popen"

    def test_a_refused_change_to_the_bootstrap_file_does_not_name_its_event(self):
        original = tethered.SubprocessBlocked(
            "os.remove", "refused deletion of /site-packages/tethered.pth in locked mode"
        )

        clone = _rebuilt_from_args(original)

        assert type(clone) is tethered.SubprocessBlocked
        assert str(clone) == str(original)
        assert clone.description == original.description
        assert clone.event == ""

    def test_a_message_of_the_guardian_for_an_interpreter_outside_the_lock(self):
        message = (
            f"Blocked by tethered: subprocess.Popen ({_OUTSIDE_THE_LOCK} cannot launch processes)"
        )

        clone = tethered.SubprocessBlocked(message)

        assert str(clone) == message
        assert clone.event == "subprocess.Popen"
        assert clone.description == message.removeprefix("Blocked by tethered: ")

    @pytest.mark.parametrize("argument", ["subprocess.Popen", "", "refused", None])
    def test_anything_but_a_message_is_still_a_type_error(self, argument):
        with pytest.raises(
            TypeError, match="takes an event and a description, or nothing but the message"
        ):
            tethered.SubprocessBlocked(argument)


def test_tethered_locked_is_rebuilt_from_its_message():
    original = tethered.TetheredLocked("tethered: activate() blocked — policy is locked.")
    _assert_same_exception(_rebuilt_from_args(original), original, ())


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
