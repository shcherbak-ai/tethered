"""Real subinterpreters next to a tethered policy.

A lock exists once per process: the C guardian holds it for the interpreter
that took it, and its audit hook sees the events of every interpreter.

An interpreter created while the policy is locked joins the lock as it
starts: it holds a locked copy of the policy, pinned like the owner's, and
reaches what the policy allows.  Every other interpreter — one that existed
before the lock, one whose startup did not join, one that joined a policy
that has since been replaced or released — is refused the operations
tethered guards (connections, lookups, process launches, changes to
``tethered.pth`` / ``tethered.start`` and to the policy variable) and keeps
working for everything else.

Tests are offline (loopback only) and destroy every interpreter they create.
Code that runs inside another interpreter is invisible to coverage; the
Python branches it takes are unit-tested in ``test_autoactivate.py``.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import textwrap
import threading
from typing import TYPE_CHECKING

import pytest

import tethered
import tethered._core as _core
from tethered._autoactivate import _in_subinterpreter
from tethered._core import _CHILD_POLICY_ENV

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

try:
    import _interpreters as _interps  # Python 3.13+
except ImportError:
    try:
        import _xxsubinterpreters as _interps  # Python 3.10 - 3.12
    except ImportError:
        _interps = None

pytestmark = [
    pytest.mark.skipif(_interps is None, reason="this Python has no subinterpreter module"),
    pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available"),
]

# From Python 3.12 an interpreter can have its own GIL, and that is the kind
# the stdlib creates by default.  Before 3.12 every interpreter shares the
# main GIL ("legacy").  The C extension loads in both kinds.
OWN_GIL = sys.version_info >= (3, 12)

# Both kinds where the version has both: (shared_gil, test id).
GIL_KINDS = [
    pytest.param(False, id="own-gil" if OWN_GIL else "default"),
    pytest.param(True, id="shared-gil"),
]

ELSEWHERE = "a locked tethered policy is active in another interpreter of this process"
NO_NETWORK = f"({ELSEWHERE}, so this interpreter gets no network access)"
NO_LAUNCHES = f"({ELSEWHERE}, so this interpreter cannot launch processes)"
NO_BOOTSTRAP_CHANGES = (
    f"({ELSEWHERE}, so this interpreter cannot change tethered.pth or tethered.start)"
)
NO_VARIABLE_CHANGES = (
    f"({ELSEWHERE}, so this interpreter cannot change the _TETHERED_CHILD_POLICY variable)"
)

# Why the guardian refuses a join (RuntimeError).
CANNOT_JOIN = "tethered: cannot join the locked policy: "
STARTUP_IS_OVER = (
    "a policy can only be joined once, while an interpreter starts, "
    "and this interpreter's startup is over"
)
CREATED_BEFORE_THE_WATCH = (
    "this interpreter was created before tethered began to watch interpreters start"
)

EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"
TETHERED_LOCKED = "tethered._core.TetheredLocked"
RUNTIME_ERROR = "builtins.RuntimeError"

# A destination no test policy allows (TEST-NET-3); only ever named in
# synthetic audit events, never connected to.
ELSEWHERE_ADDRESS = ("203.0.113.9", 443)

# Runs first in every script: ``attempt()`` records what a call did.
_PRELUDE = '''
import json, os, sys

out = {}

def attempt(name, func, *args, **kwargs):
    """Record "ok", or a description of the exception ``func`` raised."""
    try:
        func(*args, **kwargs)
    except BaseException as exc:
        out[name] = {
            "type": f"{type(exc).__module__}.{type(exc).__qualname__}",
            "is_runtime_error": isinstance(exc, RuntimeError),
            "message": str(exc),
            "host": getattr(exc, "host", None),
            "event": getattr(exc, "event", None),
            "description": getattr(exc, "description", None),
        }
    else:
        out[name] = "ok"
'''


def _create(*, shared_gil: bool) -> object:
    if sys.version_info >= (3, 13):
        return _interps.create("legacy" if shared_gil else "isolated")
    # 3.12: ``isolated`` means an own GIL.  Before that every subinterpreter
    # shares the GIL and the flag only forbids threads, fork and exec.
    return _interps.create(isolated=OWN_GIL and not shared_gil)


class _Subinterpreter:
    """One subinterpreter; ``run()`` executes a script in it and returns its ``out`` dict."""

    def __init__(self, result_file: Path, *, shared_gil: bool = False) -> None:
        self._result_file = result_file
        self._id = _create(shared_gil=shared_gil)

    def run(self, *bodies: str, **values: object) -> dict:
        """Run ``bodies`` in order, after binding each of ``values`` (JSON) to its name."""
        script = (
            _PRELUDE
            + "".join(f"{name} = json.loads({json.dumps(v)!r})\n" for name, v in values.items())
            + "".join(textwrap.dedent(body) for body in bodies)
            + f"\nwith open({str(self._result_file)!r}, 'w', encoding='utf-8') as f:\n"
            + "    json.dump(out, f)\n"
        )
        if hasattr(_interps, "exec"):
            failure = _interps.exec(self._id, script)
            assert failure is None, getattr(failure, "formatted", failure)
        else:
            _interps.run_string(self._id, script)
        return json.loads(self._result_file.read_text(encoding="utf-8"))

    def close(self) -> None:
        _interps.destroy(self._id)


@pytest.fixture
def subinterpreter(tmp_path: Path) -> Iterator[Callable[..., _Subinterpreter]]:
    """Factory for subinterpreters; each one is destroyed when the test ends."""
    created: list[_Subinterpreter] = []

    def factory(*, shared_gil: bool = False) -> _Subinterpreter:
        interp = _Subinterpreter(tmp_path / f"result-{len(created)}.json", shared_gil=shared_gil)
        created.append(interp)
        return interp

    yield factory
    for interp in created:
        interp.close()


def _lock(token: object | None = None, **policy: object) -> object:
    """Lock a policy in this interpreter, or replace the locked one given its token."""
    token = object() if token is None else token
    fields = {"allow": ["allowed.test"], "external_subprocess_policy": "allow", **policy}
    tethered.activate(**fields, locked=True, lock_token=token)
    return token


@pytest.fixture
def outsider(subinterpreter) -> _Subinterpreter:
    """A subinterpreter that exists before any policy is locked.

    Its startup was over before there was a lock to join, so under a lock
    the guardian refuses it what tethered guards.  tethered is imported in
    it, as in an interpreter whose bootstrap ran: the refusals then use
    tethered's own exception classes.

    Listed before ``locked`` by the tests that use both, so that it is
    created first.
    """
    interp = subinterpreter()
    interp.run("import tethered\n")
    return interp


def _outsider_with_a_copy(
    factory: Callable[..., _Subinterpreter], *, shared_gil: bool = False, **policy: object
) -> _Subinterpreter:
    """A subinterpreter that started under an *unlocked* policy, which is then dropped here.

    Its bootstrap gave it an unlocked copy of that policy.  For a lock
    taken afterwards it is an outsider like any interpreter that existed
    before — one that enforces (or, ``log_only``, reports through) a policy
    of its own whenever the guardian lets an event pass.
    """
    fields = {"allow": ["allowed.test"], "external_subprocess_policy": "allow", **policy}
    tethered.activate(**fields)
    interp = factory(shared_gil=shared_gil)
    tethered.deactivate()
    return interp


@pytest.fixture
def locked() -> object:
    """A locked policy held by this (the main) interpreter; returns its token."""
    return _lock()


@pytest.fixture
def listener() -> Iterator[socket.socket]:
    """A loopback TCP listener in this interpreter."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.setblocking(False)
    yield srv
    srv.close()


def _connection_arrived(srv: socket.socket) -> bool:
    try:
        conn, _ = srv.accept()
    except BlockingIOError:
        return False
    conn.close()
    return True


@pytest.fixture
def scratch_site(tmp_path: Path) -> Path:
    """A directory holding a stand-in ``tethered.pth`` (and no ``tethered.start``).

    The guardian matches these files by name, so a stand-in is refused like
    the real hook — and a failing test cannot damage the real one.
    """
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    (site_packages / "tethered.pth").write_text("# stand-in\n")
    (site_packages / "other.txt").write_text("other\n")
    return site_packages


CONNECT = """
import socket

def connect():
    with socket.socket() as s:
        s.settimeout(10)
        s.connect(("127.0.0.1", port))

attempt("connect", connect)
"""


# Collects what tethered logs at WARNING or above in that interpreter.
COLLECT_WARNINGS = """
import logging

warnings = []

class _Collect(logging.Handler):
    def emit(self, record):
        warnings.append(record.getMessage())

logging.getLogger("tethered").addHandler(_Collect(level=logging.WARNING))
"""


def _assert_refused(result: object, exc_type: str, reason: str) -> None:
    assert isinstance(result, dict), f"not refused: {result!r}"
    assert result["type"] == exc_type, result
    assert result["is_runtime_error"] is True
    assert result["message"].endswith(reason), result


# ── A policy that tells two loopback listeners apart ───────────────
# For the interpreters that join a lock: one listener is allowed and one is
# not, so both what the policy lets through and what it refuses is a real
# connection attempt, and the listener says whether it arrived.


@pytest.fixture
def ports() -> Iterator[_Ports]:
    """Two loopback listeners: one a test's policy allows, one it does not."""
    servers = []
    for _ in range(2):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(64)
        srv.setblocking(False)
        servers.append(srv)
    yield _Ports(*servers)
    for srv in servers:
        srv.close()


class _Ports:
    def __init__(self, allowed: socket.socket, forbidden: socket.socket) -> None:
        self._allowed_srv = allowed
        self._forbidden_srv = forbidden
        self.allowed = allowed.getsockname()[1]
        self.forbidden = forbidden.getsockname()[1]

    def lock(self, token: object | None = None, **policy: object) -> object:
        """Lock a policy that allows the one listener and nothing else."""
        fields = {"allow": [f"127.0.0.1:{self.allowed}"], "allow_localhost": False, **policy}
        return _lock(token, **fields)

    def reach(
        self, interp: _Subinterpreter, *bodies: str, before: str = "", **values: object
    ) -> dict:
        """Run ``before`` in ``interp``, try both listeners from it, then run ``bodies``."""
        return interp.run(
            before, REACH, *bodies, allowed=self.allowed, forbidden=self.forbidden, **values
        )

    def arrivals(self) -> tuple[bool, bool]:
        """Did a connection arrive at the allowed / at the forbidden listener?"""
        return _connection_arrived(self._allowed_srv), _connection_arrived(self._forbidden_srv)

    def not_in_the_allow_list(self) -> str:
        """The message of the policy's own refusal of the forbidden listener."""
        return f"Blocked by tethered: 127.0.0.1:{self.forbidden} is not in the allow list"


# Defines ``reach()`` and records what a connection to each listener did.
REACH = """
import socket

def reach(port):
    with socket.socket() as s:
        s.settimeout(10)
        s.connect(("127.0.0.1", port))

attempt("allowed", reach, allowed)
attempt("forbidden", reach, forbidden)
"""

# What tethered in that interpreter says about itself.
STATE = """
core = sys.modules.get("tethered._core")
out["state"] = None if core is None or core._config is None else {
    "locked": core._config.locked,
    "log_only": core._config.log_only,
    "payload": core._config._serialized_payload,
    "verify": core._c_guardian.verify(),
    "check_token": core._c_guardian.check_token(object()),
}
"""

# The refusals the guardian raises for a socket event once an interpreter's
# pinned state fails verification: its EgressBlocked(host, None), for a
# connection to loopback and for an event that names no host (making a
# socket).  The policy's own refusal names the port.
INTEGRITY_REFUSAL = "Blocked by tethered: 127.0.0.1 is not in the allow list"
SOCKET_REFUSAL = "Blocked by tethered: unknown is not in the allow list"
TAMPER_ALERT = "TAMPER DETECTED"


def _assert_enforced(result: dict, ports: _Ports) -> None:
    """The interpreter's own policy decided: the one listener yes, the other no."""
    assert result["allowed"] == "ok", result["allowed"]
    assert result["forbidden"]["type"] == EGRESS_BLOCKED, result["forbidden"]
    assert result["forbidden"]["message"] == ports.not_in_the_allow_list()
    assert ports.arrivals() == (True, False)


def _assert_outside(result: dict, ports: _Ports) -> None:
    """The guardian refused both: the interpreter is not (or no longer) joined."""
    for name in ("allowed", "forbidden"):
        _assert_refused(result[name], EGRESS_BLOCKED, NO_NETWORK)
    assert ports.arrivals() == (False, False)


class TestLockedPolicy:
    """A subinterpreter that existed before the main interpreter locked a policy.

    It did not start under the lock, so it has not joined it: the guardian
    refuses it what tethered guards, whatever the allow list says.
    """

    def test_it_keeps_computing_and_is_not_handed_the_policy(self, outsider, locked):
        result = outsider.run(
            """
            out["sum"] = sum(range(1000))
            core = sys.modules["tethered._core"]
            out["config"] = core._config
            out["is_active"] = core._c_guardian.is_active()
            from tethered._autoactivate import _in_subinterpreter
            out["in_subinterpreter"] = _in_subinterpreter()
            """
        )
        assert result["sum"] == 499500
        assert result["in_subinterpreter"] is True
        assert _in_subinterpreter() is False
        # The lock is the process's, and visible as such; the policy is not
        # this interpreter's.
        assert result["is_active"] is True
        assert result["config"] is None
        assert _core._config.locked is True
        assert os.environ[_CHILD_POLICY_ENV] == _core._config._serialized_payload

    def test_it_gets_no_network(self, outsider, locked, listener):
        """Loopback is allowed by the policy, but the guardian matches no policy."""
        port = listener.getsockname()[1]
        result = outsider.run(
            CONNECT,
            """
            def connect_ex():
                with socket.socket() as s:
                    s.settimeout(10)
                    s.connect_ex(("127.0.0.1", port))

            def sendto():
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(b"x", ("127.0.0.1", port))

            attempt("connect_ex", connect_ex)
            attempt("sendto", sendto)
            attempt("create_connection", socket.create_connection, ("127.0.0.1", port), 10)
            attempt("getaddrinfo", socket.getaddrinfo, "localhost", port)
            attempt("gethostbyname", socket.gethostbyname, "localhost")
            attempt("gethostbyname_ex", socket.gethostbyname_ex, "localhost")
            attempt("gethostbyaddr", socket.gethostbyaddr, "127.0.0.1")
            """,
            port=port,
        )
        hosts = {
            "connect": "127.0.0.1",
            "connect_ex": "127.0.0.1",
            "sendto": "127.0.0.1",
            "create_connection": "127.0.0.1",
            "getaddrinfo": "localhost",
            "gethostbyname": "localhost",
            "gethostbyname_ex": "localhost",
            "gethostbyaddr": "127.0.0.1",
        }
        assert result.keys() == hosts.keys()
        for name, host in hosts.items():
            _assert_refused(result[name], EGRESS_BLOCKED, NO_NETWORK)
            assert result[name]["host"] == host
            assert result[name]["message"] == f"Blocked by tethered: {host} {NO_NETWORK}"
        assert not _connection_arrived(listener)

    def test_it_gets_no_process_launches(self, outsider, locked, tmp_path):
        marker = tmp_path / "launched.txt"
        result = outsider.run(
            """
            def popen():
                import subprocess
                subprocess.Popen([sys.executable, "-c", "open(%r, 'w').close()" % marker])

            attempt("subprocess.Popen", popen)
            attempt("os.system", os.system, "exit 0")
            """,
            marker=str(marker),
        )
        for event in ("subprocess.Popen", "os.system"):
            _assert_refused(result[event], SUBPROCESS_BLOCKED, NO_LAUNCHES)
            assert result[event]["event"] == event
            assert result[event]["message"] == f"Blocked by tethered: {event} {NO_LAUNCHES}"
            assert result[event]["description"].startswith(f"{event} refused: {ELSEWHERE}")
        assert not marker.exists()

    def test_it_cannot_change_the_policy_variable(self, outsider, locked):
        """One variable serves the whole process: it is what child processes inherit."""
        result = outsider.run(
            """
            name = "_TETHERED_CHILD_POLICY"
            attempt("pop", os.environ.pop, name)
            attempt("set", os.environ.__setitem__, name, "{}")
            attempt("putenv", os.putenv, name, "{}")
            attempt("unsetenv", os.unsetenv, name)

            def other_variable():
                os.environ["TETHERED_TEST_OTHER_VARIABLE"] = "1"
                del os.environ["TETHERED_TEST_OTHER_VARIABLE"]

            attempt("other variable", other_variable)
            """
        )
        # os.environ is the copy this interpreter made when it started, before
        # the variable existed: popping the name fails there, in the mapping,
        # without ever reaching the process environment.
        assert result["pop"]["type"] == "builtins.KeyError"
        # What does reach it is refused.
        events = {
            "set": "os.putenv",
            "putenv": "os.putenv",
            "unsetenv": "os.unsetenv",
        }
        for name, event in events.items():
            _assert_refused(result[name], SUBPROCESS_BLOCKED, NO_VARIABLE_CHANGES)
            assert result[name]["event"] == event
        assert result["other variable"] == "ok"

        # The native variable is what a child process gets: still the locked payload.
        published = _core._config._serialized_payload
        assert _core._c_guardian.process_policy_env() == published
        child = subprocess.run(  # nosec B603
            [sys.executable, "-c", f"import os; print(os.environ[{_CHILD_POLICY_ENV!r}])"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert child.returncode == 0, child.stderr
        assert child.stdout.strip() == published

    def test_it_cannot_change_the_bootstrap_files(self, scratch_site, outsider, locked):
        result = outsider.run(
            """
            import pathlib, shutil

            site = pathlib.Path(site_packages)
            pth, start, other = site / "tethered.pth", site / "tethered.start", site / "other.txt"

            attempt("remove", os.remove, str(pth))
            attempt("remove bytes", os.remove, os.fsencode(pth))
            attempt("unlink", pth.unlink)
            attempt("open w", open, pth, "w")
            attempt("open a", open, pth, "a")
            attempt("open r+", open, pth, "r+")
            attempt("os.open", os.open, pth, os.O_WRONLY)
            attempt("write_text", pth.write_text, "gone")
            attempt("rename away", os.rename, pth, site / "moved.txt")
            attempt("replace onto", os.replace, other, pth)
            attempt("chmod", os.chmod, pth, 0o600)
            attempt("truncate", os.truncate, pth, 0)
            attempt("copy2 onto", shutil.copy2, other, pth)
            attempt("start open w", open, start, "w")
            attempt("start touch", start.touch)
            attempt("start replace onto", os.replace, other, start)
            attempt("start link", os.link, other, start)
            attempt("start symlink", os.symlink, other, start)

            def read():
                assert pth.read_text() == "# stand-in\\n"
                with open(pth, "rb") as f:
                    f.read()
                os.close(os.open(pth, os.O_RDONLY))

            attempt("read", read)
            """,
            site_packages=str(scratch_site),
        )
        assert result.pop("read") == "ok"
        assert len(result) == 18
        for name, outcome in result.items():
            _assert_refused(outcome, SUBPROCESS_BLOCKED, NO_BOOTSTRAP_CHANGES)
            assert outcome["event"] in _core._PTH_FS_EVENTS, name
        assert (scratch_site / "tethered.pth").read_text() == "# stand-in\n"
        assert (scratch_site / "other.txt").read_text() == "other\n"
        assert sorted(p.name for p in scratch_site.iterdir()) == ["other.txt", "tethered.pth"]

    def test_everything_else_keeps_working(self, scratch_site, outsider, locked):
        """Sockets that reach nobody, ordinary files, other variables, threads."""
        result = outsider.run(
            """
            import pathlib, socket, threading

            def serve():
                with socket.socket() as srv:
                    srv.bind(("127.0.0.1", 0))
                    srv.listen(1)
                    assert srv.getsockname()[1]

            def files():
                note = pathlib.Path(site_packages) / "note.txt"
                note.write_text("x")
                with open(note, "a") as f:
                    f.write("y")
                assert note.read_text() == "xy"
                os.chmod(note, 0o600)
                os.truncate(note, 1)
                moved = note.with_name("moved.txt")
                note.rename(moved)
                os.replace(moved, note)
                note.unlink()
                note.touch()
                os.remove(note)

            def thread():
                seen = []
                worker = threading.Thread(target=seen.append, args=(1,))
                worker.start()
                worker.join()
                assert seen == [1]

            attempt("serve", serve)
            attempt(
                "getnameinfo",
                socket.getnameinfo,
                ("127.0.0.1", 80),
                socket.NI_NUMERICHOST | socket.NI_NUMERICSERV,
            )
            attempt("gethostname", socket.gethostname)
            attempt("files", files)
            attempt("thread", thread)
            """,
            site_packages=str(scratch_site),
        )
        assert result == dict.fromkeys(
            ("serve", "getnameinfo", "gethostname", "files", "thread"), "ok"
        )

    def test_every_event_tethered_guards_is_refused(self, outsider, locked):
        """The C event lists stay in step with the Python hook's, seen from outside."""
        events = {
            "connect": sorted(_core._CONNECT_EVENTS),
            "lookup": sorted(_core._DNS_EVENTS | {"socket.getaddrinfo"}),
            "launch": sorted(_core._SUBPROCESS_EVENTS | {"os.startfile/2"}),
            "fs": sorted(_core._PTH_FS_EVENTS),
            "env": sorted(_core._ENV_EVENTS),
        }
        result = outsider.run(
            """
            for event in events["connect"]:
                attempt(event, sys.audit, event, None, ("203.0.113.9", 443))
            for event in events["lookup"]:
                attempt(event, sys.audit, event, "host.test", 80, 0, 0, 0)
            for event in events["launch"]:
                attempt(event, sys.audit, event, "prog", ["prog"], None, None)
            for event in events["fs"]:
                attempt(event, sys.audit, event, "site-packages/tethered.pth", "w", 0)
            for event in events["env"]:
                attempt(event, sys.audit, event, "_TETHERED_CHILD_POLICY", "x")
            """,
            events=events,
        )
        assert len(result) == sum(len(names) for names in events.values())
        for event in events["connect"]:
            _assert_refused(result[event], EGRESS_BLOCKED, NO_NETWORK)
            assert result[event]["host"] == "203.0.113.9"
        for event in events["lookup"]:
            _assert_refused(result[event], EGRESS_BLOCKED, NO_NETWORK)
            assert result[event]["host"] == "host.test"
        for event in events["launch"]:
            _assert_refused(result[event], SUBPROCESS_BLOCKED, NO_LAUNCHES)
        for event in events["fs"]:
            _assert_refused(result[event], SUBPROCESS_BLOCKED, NO_BOOTSTRAP_CHANGES)
        for event in events["env"]:
            _assert_refused(result[event], SUBPROCESS_BLOCKED, NO_VARIABLE_CHANGES)
        for kind in ("launch", "fs", "env"):
            for event in events[kind]:
                assert result[event]["event"] == event

    def test_which_filesystem_and_environment_events_are_refused(self, outsider, locked):
        """Event by event: what counts as touching the bootstrap files or the variable."""
        result = outsider.run(
            """
            import pathlib

            class Unanswering:
                def __fspath__(self):
                    raise OSError("no path")

            class Text(str):
                pass

            pth, start = "site-packages/tethered.pth", "site-packages/TETHERED.START"
            write = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            refused = {
                "open w": ("open", pth, "w", write),
                "open x": ("open", start, "x", 0),
                "open a": ("open", pth, "a", 0),
                "open rb+": ("open", pth, "rb+", 0),
                "os.open O_WRONLY": ("open", pth, None, os.O_WRONLY),
                "os.open O_RDWR": ("open", pth, None, os.O_RDWR),
                "os.open O_CREAT": ("open", start, None, os.O_CREAT),
                "os.open O_TRUNC": ("open", pth, None, os.O_TRUNC),
                "open, flags decide": ("open", pth, "rb", os.O_RDWR),
                "open, mode decides": ("open", pth, "w", 0),
                "open, odd mode": ("open", pth, 7, 0),
                "open, odd flags": ("open", pth, None, "flags"),
                "open, huge flags": ("open", pth, None, 2**70),
                "open bytes": ("open", b"site-packages/tethered.pth", "w", write),
                "open str subclass": ("open", Text(pth), "w", write),
                "open path-like": ("open", pathlib.PurePosixPath(pth), "w", write),
                "open unanswering path-like": ("open", Unanswering(), "w", write),
                "open not a path": ("open", ["tethered.pth"], "w", write),
                "remove path-like": ("os.remove", pathlib.PurePosixPath(pth), -1),
                "rename from": ("os.rename", pth, "elsewhere", -1, -1),
                "rename onto": ("os.rename", "elsewhere", pth, -1, -1),
                "link onto": ("os.link", "elsewhere", start, -1, -1),
                "symlink onto": ("os.symlink", "elsewhere", start, -1),
                "CopyFile2 onto": ("_winapi.CopyFile2", "elsewhere", pth, 0),
                "CopyFile2 path-like": (
                    "_winapi.CopyFile2", "elsewhere", pathlib.PurePosixPath(start), 0),
                "putenv": ("os.putenv", "_TETHERED_CHILD_POLICY", "x"),
                "putenv other case": ("os.putenv", "_tethered_child_policy", "x"),
                "putenv bytes": ("os.putenv", b"_TETHERED_CHILD_POLICY", b"x"),
                "unsetenv": ("os.unsetenv", "_TETHERED_CHILD_POLICY"),
                "unsetenv non-ASCII": ("os.unsetenv", "_TETHERED_CH\\u0131LD_POLICY"),
                "putenv odd key": ("os.putenv", 7, "x"),
                "putenv no key": ("os.putenv",),
            }
            passed = {
                "open r": ("open", pth, "r", 0),
                "open rb": ("open", pth, "rb", os.O_RDONLY),
                "os.open O_RDONLY": ("open", pth, None, os.O_RDONLY),
                "open, nothing known": ("open", pth),
                "open, no mode": ("open", pth, None),
                "open start r": ("open", start, "r", 0),
                "open other w": ("open", "site-packages/other.pth", "w", write),
                "open other path-like": ("open", pathlib.PurePosixPath("other.txt"), "w", write),
                "open descriptor": ("open", 7, "w", write),
                "open no arguments": ("open",),
                "remove other": ("os.remove", "site-packages/other.pth", -1),
                "remove other path-like": ("os.remove", pathlib.PurePosixPath("other.txt"), -1),
                "remove no arguments": ("os.remove",),
                "rename other": ("os.rename", "a", "b", "tethered.pth", "tethered.pth"),
                "chmod other": ("os.chmod", "other.txt", 0, -1),
                "truncate descriptor": ("os.truncate", 7, 0),
                "link other": ("os.link", "a", "b", "tethered.start", "tethered.start"),
                "symlink other": ("os.symlink", "a", "b", "tethered.start"),
                "CopyFile2 other": ("_winapi.CopyFile2", "a", "b", "tethered.pth"),
                "putenv other": ("os.putenv", "PATH", "x"),
                "putenv longer name": ("os.putenv", "_TETHERED_CHILD_POLICY_X", "x"),
                "unsetenv other": ("os.unsetenv", "HOME"),
            }
            for name, (event, *args) in {**refused, **passed}.items():
                attempt(name, sys.audit, event, *args)
            out["names"] = [sorted(refused), sorted(passed)]
            """
        )
        refused, passed = result.pop("names")
        assert sorted(result) == sorted(refused + passed)
        for name in refused:
            environment = "env" in name
            _assert_refused(
                result[name],
                SUBPROCESS_BLOCKED,
                NO_VARIABLE_CHANGES if environment else NO_BOOTSTRAP_CHANGES,
            )
        for name in passed:
            assert result[name] == "ok", name

    def test_other_events_pass(self, outsider, locked):
        result = outsider.run(
            """
            events = {
                "socket.__new__": (None, 2, 1, 0),
                "socket.bind": (None, ("127.0.0.1", 0)),
                "socket.getnameinfo": (("203.0.113.9", 443),),
                "socket.gethostname": (),
                "socket.getservbyname": ("http", "tcp"),
                "socket.tethered_test_probe": (),
                "sockets.connect": (None, ("203.0.113.9", 443)),
                "subprocess.run": ("prog", ["prog"], None, None),
                "os.listdir": ("site-packages/tethered.pth",),
                "os.mkdir": ("site-packages/tethered.start", 0o777, -1),
                "os.rmdir": ("tethered.pth", -1),
                "os.execv": ("prog",),
                "_winapi.CreateFile": ("tethered.pth",),
                "import": ("tethered.pth", None, None, None, None),
                "exec": ("_TETHERED_CHILD_POLICY",),
                "": (),
            }
            for event, args in events.items():
                attempt(event, sys.audit, event, *args)
            """
        )
        assert len(result) == 16
        assert set(result.values()) == {"ok"}

    def test_the_owning_interpreter_is_unaffected(self, outsider, locked, listener, capfd):
        port = listener.getsockname()[1]
        _assert_refused(outsider.run(CONNECT, port=port)["connect"], EGRESS_BLOCKED, NO_NETWORK)

        with socket.socket() as s:
            s.settimeout(10)
            s.connect(("127.0.0.1", port))  # allowed by the policy: loopback
        assert _connection_arrived(listener)
        with pytest.raises(tethered.EgressBlocked, match="is not in the allow list") as excinfo:
            sys.audit("socket.connect", None, ELSEWHERE_ADDRESS)
        assert ELSEWHERE not in str(excinfo.value)

        # A refusal elsewhere is not tampering here.
        assert _core._c_guardian.verify() is True
        assert _core._c_guardian.check_token(locked) is True
        assert "TAMPER DETECTED" not in capfd.readouterr().err

    def test_without_tethered_loaded_the_refusal_is_a_runtime_error(
        self, locked, listener, subinterpreter, monkeypatch
    ):
        """Removing the variable from ``os.environ`` no longer buys a free interpreter.

        Locked mode does not refuse that removal in the owning interpreter
        (it refuses the next process launch); an interpreter created
        afterwards runs no bootstrap.  The guardian never imports tethered
        into it, so the refusal is a ``RuntimeError`` — which the tethered
        exceptions derive from.
        """
        monkeypatch.delenv(_CHILD_POLICY_ENV)
        port = listener.getsockname()[1]
        interp = subinterpreter()
        result = interp.run(
            CONNECT,
            """
            attempt("getaddrinfo", socket.getaddrinfo, "localhost", port)
            attempt("launch", os.system, "exit 0")
            attempt("remove", sys.audit, "os.remove", "site-packages/tethered.pth", -1)
            attempt("putenv", os.putenv, "_TETHERED_CHILD_POLICY", "{}")
            out["sum"] = sum(range(1000))
            out["tethered loaded"] = sorted(m for m in sys.modules if m.startswith("tethered"))
            """,
            port=port,
        )
        assert result.pop("sum") == 499500
        assert result.pop("tethered loaded") == []
        reasons = {
            "connect": NO_NETWORK,
            "getaddrinfo": NO_NETWORK,
            "launch": NO_LAUNCHES,
            "remove": NO_BOOTSTRAP_CHANGES,
            "putenv": NO_VARIABLE_CHANGES,
        }
        assert result.keys() == reasons.keys()
        for name, reason in reasons.items():
            _assert_refused(result[name], RUNTIME_ERROR, reason)
        assert result["connect"]["message"] == f"Blocked by tethered: 127.0.0.1 {NO_NETWORK}"
        assert result["launch"]["message"] == f"Blocked by tethered: os.system {NO_LAUNCHES}"
        assert not _connection_arrived(listener)

        # Once tethered is imported there, its own exception classes are used.
        result = interp.run("import tethered\n", CONNECT, port=port)
        _assert_refused(result["connect"], EGRESS_BLOCKED, NO_NETWORK)

    def test_refusal_does_not_depend_on_the_exception_classes(self, outsider, locked):
        """Whatever ``tethered._core`` is in that interpreter, the operation is refused."""
        result = outsider.run(
            """
            import types
            import tethered._core as core

            def connect():
                sys.audit("socket.connect", None, ("203.0.113.9", 443))

            def launch():
                sys.audit("os.system", "prog")

            class Raises(RuntimeError):
                def __init__(self, *args):
                    raise ValueError("cannot be built")

            class Exits(RuntimeError):
                def __init__(self, *args):
                    raise SystemExit(0)

            class FixedArgs(RuntimeError):
                args = property(lambda self: ())

            real = core.EgressBlocked, core.SubprocessBlocked
            replacements = {
                "raises": Raises,
                "exits": Exits,
                "not an exception": lambda *args: "text",
                "not a class": 5,
                "message cannot be set": FixedArgs,
            }
            for name, replacement in replacements.items():
                core.EgressBlocked = core.SubprocessBlocked = replacement
                attempt(f"{name}: connect", connect)
                attempt(f"{name}: launch", launch)
            del core.EgressBlocked, core.SubprocessBlocked
            attempt("missing: connect", connect)
            attempt("missing: launch", launch)
            core.EgressBlocked, core.SubprocessBlocked = real

            for name, module in {
                "module is None": None,
                "module is an object": object(),
                "module without classes": types.ModuleType("tethered._core"),
            }.items():
                sys.modules["tethered._core"] = module
                attempt(f"{name}: connect", connect)
            sys.modules["tethered._core"] = core

            class Subclass(core.EgressBlocked):
                pass

            core.EgressBlocked = Subclass
            attempt("subclass", connect)
            core.EgressBlocked = real[0]
            attempt("restored: connect", connect)
            attempt("restored: launch", launch)
            attempt("unreadable host", sys.audit, "socket.getaddrinfo", "bad\\udc80host", 80)
            attempt("no host", sys.audit, "socket.connect")
            """
        )
        assert result.pop("subclass")["type"] == "__main__.Subclass"
        _assert_refused(result.pop("restored: connect"), EGRESS_BLOCKED, NO_NETWORK)
        _assert_refused(result.pop("restored: launch"), SUBPROCESS_BLOCKED, NO_LAUNCHES)
        for name in ("unreadable host", "no host"):
            outcome = result.pop(name)
            _assert_refused(outcome, EGRESS_BLOCKED, NO_NETWORK)
            assert outcome["host"] == "unknown"
        assert len(result) == 15
        for name, outcome in result.items():
            reason = NO_LAUNCHES if name.endswith("launch") else NO_NETWORK
            _assert_refused(outcome, RUNTIME_ERROR, reason)

    def test_unlocking_and_relocking(self, outsider, locked, listener, subinterpreter):
        """After ``deactivate(lock_token=...)`` the guardian restricts nobody."""
        port = listener.getsockname()[1]
        blocked = """
        attempt("elsewhere", sys.audit, "socket.connect", None, ("203.0.113.9", 443))
        out["config"] = getattr(sys.modules.get("tethered._core"), "_config", "not loaded")
        """
        result = outsider.run(CONNECT, blocked, port=port)
        _assert_refused(result["connect"], EGRESS_BLOCKED, NO_NETWORK)
        _assert_refused(result["elsewhere"], EGRESS_BLOCKED, NO_NETWORK)

        tethered.deactivate(lock_token=locked)
        # It never had a policy of its own, and nothing holds it back now.
        result = outsider.run(CONNECT, blocked, port=port)
        assert result == {"connect": "ok", "elsewhere": "ok", "config": None}
        assert _connection_arrived(listener)
        # One created now inherits nothing: deactivate() removed the variable.
        in_between = subinterpreter()
        result = in_between.run(CONNECT, blocked, port=port)
        assert result == {"connect": "ok", "elsewhere": "ok", "config": "not loaded"}
        assert _connection_arrived(listener)

        # A lock taken again binds both: each had finished starting before it
        # was taken, the second one with nothing locked to join.
        _lock()
        for interp in (outsider, in_between):
            result = interp.run("import tethered\n", CONNECT, blocked, port=port)
            _assert_refused(result["connect"], EGRESS_BLOCKED, NO_NETWORK)
            _assert_refused(result["elsewhere"], EGRESS_BLOCKED, NO_NETWORK)
        assert not _connection_arrived(listener)


class TestJoinedInterpreter:
    """A subinterpreter created while the main interpreter holds a locked policy.

    Its ``tethered.pth`` bootstrap joins the lock: the interpreter gets a
    locked copy of the policy, pinned by the guardian like the owner's.
    """

    @pytest.mark.parametrize("shared_gil", GIL_KINDS)
    def test_it_reaches_what_the_policy_allows_and_nothing_else(
        self, shared_gil, ports, subinterpreter, capfd
    ):
        ports.lock()
        published = _core._config._serialized_payload
        result = ports.reach(
            subinterpreter(shared_gil=shared_gil),
            STATE,
            """
            out["environment"] = os.environ.get("_TETHERED_CHILD_POLICY")
            from tethered._autoactivate import _in_subinterpreter
            out["in_subinterpreter"] = _in_subinterpreter()
            """,
        )
        _assert_enforced(result, ports)
        assert result["in_subinterpreter"] is True
        # A locked copy of the very policy the owner locked, verified there,
        # and without a token: the lock is not this interpreter's to release.
        assert result["state"] == {
            "locked": True,
            "log_only": False,
            "payload": published,
            "verify": True,
            "check_token": False,
        }
        # Nothing was published from there, and nothing was tampered with.
        assert result["environment"] == published
        assert os.environ[_CHILD_POLICY_ENV] == published
        assert TAMPER_ALERT not in capfd.readouterr().err

    @pytest.mark.parametrize("shared_gil", GIL_KINDS)
    def test_it_cannot_switch_tethered_off(self, shared_gil, ports, subinterpreter, capfd):
        ports.lock()
        interp = subinterpreter(shared_gil=shared_gil)
        result = interp.run(
            """
            import tethered
            import tethered._core as core

            guardian = core._c_guardian
            attempt("deactivate", tethered.deactivate)
            attempt("deactivate with a token", tethered.deactivate, lock_token=object())
            attempt("activate", tethered.activate, allow=["0.0.0.0/0"])
            attempt("activate locked", tethered.activate, allow=["0.0.0.0/0"], locked=True,
                    lock_token=object())
            attempt("guardian.deactivate", guardian.deactivate, object())
            attempt("guardian.activate", guardian.activate, vars(core), core._config, object(), [])
            out["still locked"] = [guardian.is_active(), core._config.locked, guardian.verify()]
            """
        )
        for name in ("deactivate", "deactivate with a token", "activate", "activate locked"):
            assert result[name]["type"] == TETHERED_LOCKED, (name, result[name])
        _assert_refused(result["guardian.deactivate"], RUNTIME_ERROR, "deactivated from there")
        _assert_refused(result["guardian.activate"], RUNTIME_ERROR, "replaced from there")
        assert result["still locked"] == [True, True, True]

        # None of it changed what the interpreter may reach ...
        _assert_enforced(ports.reach(interp), ports)
        # ... and a refused request is not tampering.
        assert TAMPER_ALERT not in capfd.readouterr().err
        assert _core._c_guardian.verify() is True

    @pytest.mark.parametrize("shared_gil", GIL_KINDS)
    @pytest.mark.parametrize(
        "tamper",
        [
            "core._config = None",
            "core._config = core._Config(policy=AllowPolicy(['0.0.0.0/0']))",
            "core._handle_connect = lambda *args: None",
            "object.__setattr__(core._config, 'policy', AllowPolicy(['0.0.0.0/0']))",
            "object.__setattr__(core._config, 'log_only', True)",
            "AllowPolicy.is_allowed = lambda self, *args, **kwargs: True",
        ],
        ids=[
            "config-removed",
            "config-replaced",
            "function-replaced",
            "policy-swapped",
            "log-only-set",
            "method-patched",
        ],
    )
    def test_tampering_there_is_detected_there(
        self, tamper, shared_gil, ports, subinterpreter, capfd
    ):
        """Its own snapshot is verified on its own events, as in the owner."""
        ports.lock()
        interp = subinterpreter(shared_gil=shared_gil)
        _assert_enforced(ports.reach(interp), ports)
        assert TAMPER_ALERT not in capfd.readouterr().err

        result = ports.reach(
            interp,
            """
            attempt("connect allowed", sys.audit, "socket.connect", None, ("127.0.0.1", allowed))
            attempt("connect forbidden", sys.audit, "socket.connect", None,
                    ("127.0.0.1", forbidden))
            attempt("lookup", sys.audit, "socket.getaddrinfo", "localhost", 80, 0, 0, 0)
            attempt("launch", sys.audit, "os.system", "prog")
            """,
            before="import tethered._core as core\n"
            "from tethered._policy import AllowPolicy\n" + tamper + "\n",
        )
        # Everything is refused there now, the allowed listener included, by
        # the guardian and not by the policy that was put in its place: not
        # even a socket can be made (the event has no host to name) ...
        for name in ("allowed", "forbidden"):
            assert result[name]["type"] == EGRESS_BLOCKED, (name, result[name])
            assert result[name]["message"] == SOCKET_REFUSAL
        # ... and a connection is refused without the policy being asked,
        # which would have named the port.
        for name in ("connect allowed", "connect forbidden"):
            assert result[name]["type"] == EGRESS_BLOCKED, (name, result[name])
            assert result[name]["message"] == INTEGRITY_REFUSAL
        assert result["lookup"]["type"] == EGRESS_BLOCKED
        assert result["lookup"]["host"] == "localhost"
        assert result["launch"]["type"] == SUBPROCESS_BLOCKED
        assert result["launch"]["description"] == (
            "os.system refused: locked policy integrity violated"
        )
        assert ports.arrivals() == (False, False)
        assert TAMPER_ALERT in capfd.readouterr().err

        # The owner's copy is its own: untouched, and still enforcing.
        assert _core._c_guardian.verify() is True
        with socket.socket() as s:
            s.settimeout(10)
            s.connect(("127.0.0.1", ports.allowed))
        with pytest.raises(tethered.EgressBlocked, match="is not in the allow list"):
            sys.audit("socket.connect", None, ("127.0.0.1", ports.forbidden))
        assert ports.arrivals() == (True, False)

    def test_it_joins_only_once(self, ports, subinterpreter):
        ports.lock()
        interp = subinterpreter()
        result = interp.run(
            """
            import tethered._core as core

            guardian = core._c_guardian
            held = core._config
            attempt("join again", core._join_locked, guardian.locked_payload())
            attempt("guardian.join", guardian.join, vars(core), held, [])
            attempt("guardian.join, another config", guardian.join, vars(core), None, [])
            out["unchanged"] = core._config is held
            """
        )
        for name in ("join again", "guardian.join", "guardian.join, another config"):
            _assert_refused(result[name], RUNTIME_ERROR, "")
            assert result[name]["message"] == CANNOT_JOIN + STARTUP_IS_OVER
        assert result["unchanged"] is True
        _assert_enforced(ports.reach(interp), ports)

    @pytest.mark.parametrize("shared_gil", GIL_KINDS)
    def test_an_interpreter_cannot_join_once_its_startup_is_over(
        self, shared_gil, ports, subinterpreter
    ):
        """Code that runs in an interpreter could offer the guardian anything.

        This one started with the guardian watching and nothing locked, so
        its bootstrap joined nothing.  Whatever it offers afterwards is not
        accepted, and it stays outside the lock.
        """
        tethered.deactivate(lock_token=ports.lock())  # the guardian's hook is in place
        late = subinterpreter(shared_gil=shared_gil)
        ports.lock()
        result = ports.reach(
            late,
            STATE,
            before="""
            import tethered._core as core

            guardian = core._c_guardian
            attempt("join", core._join_locked, guardian.locked_payload())
            attempt("guardian.join", guardian.join, vars(core), None, [])
            """,
        )
        for name in ("join", "guardian.join"):
            _assert_refused(result[name], RUNTIME_ERROR, "")
            assert result[name]["message"] == CANNOT_JOIN + STARTUP_IS_OVER
        assert result["state"] is None  # a refused join binds nothing
        _assert_outside(result, ports)

    def test_replacing_the_policy_with_the_same_one_keeps_it_joined(
        self, ports, subinterpreter, capfd
    ):
        token = ports.lock()
        interp = subinterpreter()
        _assert_enforced(ports.reach(interp), ports)

        ports.lock(token)  # the owner re-activates: the payload is the same, to the byte
        result = ports.reach(interp, STATE)
        _assert_enforced(result, ports)
        assert result["state"]["verify"] is True
        assert TAMPER_ALERT not in capfd.readouterr().err

    def test_replacing_the_policy_with_another_one_ends_the_join(
        self, ports, subinterpreter, capfd
    ):
        token = ports.lock()
        joined_first = subinterpreter()
        _assert_enforced(ports.reach(joined_first), ports)

        # The owner now allows the other listener instead.
        _lock(token, allow=[f"127.0.0.1:{ports.forbidden}"], allow_localhost=False)
        # The interpreter still holds the policy that was replaced.  That one
        # is no longer what the process enforces, and there is no joining
        # twice: it is outside the lock from here on.
        result = ports.reach(joined_first, STATE)
        _assert_outside(result, ports)
        assert result["state"]["verify"] is False
        attempt_again = joined_first.run(
            """
            import tethered._core as core
            attempt("join", core._join_locked, core._c_guardian.locked_payload())
            """
        )
        _assert_refused(attempt_again["join"], RUNTIME_ERROR, "")
        assert attempt_again["join"]["message"] == CANNOT_JOIN + STARTUP_IS_OVER

        # One created now joins the policy that is locked now.
        result = ports.reach(subinterpreter())
        assert result["forbidden"] == "ok"
        assert result["allowed"]["message"] == (
            f"Blocked by tethered: 127.0.0.1:{ports.allowed} is not in the allow list"
        )
        assert ports.arrivals() == (False, True)
        assert TAMPER_ALERT not in capfd.readouterr().err

    def test_after_the_lock_is_released_its_copy_is_its_own(self, ports, subinterpreter):
        token = ports.lock()
        interp = subinterpreter()
        _assert_enforced(ports.reach(interp), ports)

        tethered.deactivate(lock_token=token)
        # The guardian enforces nothing anywhere now.  The interpreter keeps
        # the policy it holds and enforces it from Python ...
        result = ports.reach(interp, STATE)
        _assert_enforced(result, ports)
        assert result["state"]["locked"] is True
        # ... and may drop it, like any policy nothing locks.
        result = ports.reach(
            interp,
            before="""
            import tethered
            attempt("deactivate", tethered.deactivate)
            out["config"] = sys.modules["tethered._core"]._config
            """,
        )
        assert result["deactivate"] == "ok"
        assert result["config"] is None
        assert result["allowed"] == result["forbidden"] == "ok"
        assert ports.arrivals() == (True, True)

    def test_a_lock_taken_again_does_not_take_it_back(self, ports, subinterpreter):
        """Released and locked again, even with the same policy: it joined the first."""
        token = ports.lock()
        interp = subinterpreter()
        _assert_enforced(ports.reach(interp), ports)

        tethered.deactivate(lock_token=token)
        ports.lock(token)
        _assert_outside(ports.reach(interp), ports)
        _assert_enforced(ports.reach(subinterpreter()), ports)

    @pytest.mark.parametrize("shared_gil", GIL_KINDS)
    def test_a_log_only_lock_is_joined_as_log_only(self, shared_gil, ports, subinterpreter):
        """It reports through its own copy of the policy, and blocks nothing."""
        ports.lock(log_only=True)
        result = ports.reach(
            subinterpreter(shared_gil=shared_gil),
            STATE,
            'out["warnings"] = warnings\n',
            before=COLLECT_WARNINGS,
        )
        assert result["allowed"] == result["forbidden"] == "ok"
        assert ports.arrivals() == (True, True)
        assert result["state"]["locked"] is True
        assert result["state"]["log_only"] is True
        assert result["state"]["verify"] is True
        assert result["warnings"] == [f"tethered: blocked connect to 127.0.0.1:{ports.forbidden}"]

    def test_a_process_it_launches_carries_the_locked_policy(self, ports, subinterpreter):
        """Launches are its own Python hook's to judge, and the child inherits the policy.

        In an interpreter that shares the GIL: one with its own GIL may not
        fork or exec on every platform.
        """
        ports.lock(external_subprocess_policy="block")
        published = _core._config._serialized_payload
        child_code = (
            "import os, json, tethered._core as core; "
            "print(json.dumps([os.environ['_TETHERED_CHILD_POLICY'], core._config.locked, "
            "core._c_guardian.is_active()]))"
        )
        result = subinterpreter(shared_gil=True).run(
            """
            import subprocess

            def launch():
                done = subprocess.run(
                    [sys.executable, "-c", child_code], capture_output=True, text=True, timeout=60
                )
                out["child"] = [done.returncode, done.stdout.strip(), done.stderr.strip()]

            attempt("launch", launch)
            attempt("external", subprocess.run, ["tethered-test-no-such-program"])
            """,
            child_code=child_code,
        )
        assert result["launch"] == "ok", result["launch"]
        returncode, stdout, stderr = result["child"]
        assert returncode == 0, stderr
        # The child got the locked payload and locked it for itself.
        assert json.loads(stdout) == [published, True, True]
        # What the policy says about other launches holds there too.
        assert result["external"]["type"] == SUBPROCESS_BLOCKED
        assert ELSEWHERE not in result["external"]["message"]

    def test_it_launches_nothing_once_the_owner_has_changed_the_variable(
        self, ports, subinterpreter, tmp_path
    ):
        """Its own ``os.environ`` still shows the payload; its children would not get it.

        The owner may change the variable (its own launches are then
        refused).  Only the owner's hook sees that happen: this interpreter's
        copy of the environment and its own bookkeeping are untouched, and a
        child it launched would start with whatever the process holds now.
        It asks the guardian what that is.
        """
        ports.lock()
        published = _core._config._serialized_payload
        marker = tmp_path / "launched.txt"
        launch = """
        import subprocess
        import tethered._core as core

        def launch():
            subprocess.run([sys.executable, "-c", "open(%r, 'w').close()" % marker], timeout=60)

        attempt("launch", launch)
        out["cache"] = os.environ.get("_TETHERED_CHILD_POLICY")
        out["dirty"] = core._env_dirty
        out["process"] = core._c_guardian.process_policy_env()
        """
        interp = subinterpreter(shared_gil=True)
        result = interp.run(launch, marker=str(marker))
        assert result == {"launch": "ok", "cache": published, "dirty": False, "process": published}
        assert marker.exists()
        marker.unlink()

        os.environ.pop(_CHILD_POLICY_ENV)  # in the owner
        result = interp.run(launch, marker=str(marker))
        assert result["cache"] == published
        assert result["dirty"] is False
        assert result["process"] is None
        assert result["launch"]["type"] == SUBPROCESS_BLOCKED, result["launch"]
        assert "changed from another interpreter or below Python" in result["launch"]["message"]
        assert not marker.exists()
        # (The owner's own launches are refused as well, by its own bookkeeping.)
        with pytest.raises(tethered.SubprocessBlocked, match=r"os\.environ strips"):
            subprocess.run([sys.executable, "-c", "pass"], timeout=60)  # nosec B603

        os.environ[_CHILD_POLICY_ENV] = published  # the owner puts it back
        result = interp.run(launch, marker=str(marker))
        assert result == {"launch": "ok", "cache": published, "dirty": False, "process": published}
        assert marker.exists()

    @pytest.mark.parametrize("shared_gil", GIL_KINDS)
    def test_it_cannot_change_the_policy_variable(self, shared_gil, ports, subinterpreter, capfd):
        """One variable serves the whole process, whichever interpreter launches a child."""
        ports.lock()
        published = _core._config._serialized_payload
        result = subinterpreter(shared_gil=shared_gil).run(
            """
            name = "_TETHERED_CHILD_POLICY"
            attempt("pop", os.environ.pop, name)
            attempt("set", os.environ.__setitem__, name, "{}")
            attempt("putenv", os.putenv, name, "{}")
            attempt("unsetenv", os.unsetenv, name)
            attempt("another case", sys.audit, "os.putenv", name.lower(), "{}")
            attempt("folded onto it", sys.audit, "os.unsetenv", "_TETHERED_CH\\u0131LD_POLICY")
            out["cache"] = os.environ.get(name)

            def other_variable():
                os.environ["TETHERED_TEST_OTHER_VARIABLE"] = "1"
                del os.environ["TETHERED_TEST_OTHER_VARIABLE"]

            attempt("other variable", other_variable)
            # A name with a non-ASCII character in it is not ours for that
            # alone: not at another length, and not where a letter differs.
            attempt("non-ASCII name", sys.audit, "os.putenv", "TETHERED_\\u00dcBER", "1")
            attempt("non-ASCII name, same length", sys.audit, "os.putenv",
                    "_TETHERED_CH\\u0131LD_POLICX", "1")
            out["lengths"] = [len(name), len("_TETHERED_CH\\u0131LD_POLICX")]
            """
        )
        events = {
            "pop": "os.unsetenv",
            "set": "os.putenv",
            "putenv": "os.putenv",
            "unsetenv": "os.unsetenv",
            "another case": "os.putenv",
            "folded onto it": "os.unsetenv",
        }
        for name, event in events.items():
            _assert_refused(result[name], SUBPROCESS_BLOCKED, NO_VARIABLE_CHANGES)
            assert result[name]["event"] == event
        assert result["cache"] == published
        assert result["other variable"] == "ok"
        assert result["non-ASCII name"] == "ok"
        assert result["lengths"] == [22, 22]
        assert result["non-ASCII name, same length"] == "ok"
        # Refused, not tampered with; and the process still holds the payload.
        assert TAMPER_ALERT not in capfd.readouterr().err
        assert _core._c_guardian.process_policy_env() == published

    def test_inherited_scopes_are_kept(self, locked, subinterpreter, monkeypatch):
        """The policy comes from the guardian; scopes still come from the variable."""
        payload = json.loads(os.environ[_CHILD_POLICY_ENV])
        payload["scopes"] = [{"allow": ["scoped.test"], "label": "inherited"}]
        # Written in this, the owning interpreter; the canonical global is kept.
        monkeypatch.setenv(_CHILD_POLICY_ENV, json.dumps(payload))
        result = subinterpreter().run(
            """
            import tethered._core as core
            out["scopes"] = core._active_scope_count
            out["locked"] = core._config.locked
            out["payload"] = core._config._serialized_payload
            """
        )
        # (The scope stack itself is context-local, and from Python 3.13 each
        # run in an interpreter starts with a fresh context.)
        assert result == {
            "scopes": 1,
            "locked": True,
            "payload": _core._config._serialized_payload,
        }

    def test_what_the_variable_says_does_not_change_what_is_joined(
        self, ports, subinterpreter, monkeypatch
    ):
        """The owner may rewrite the variable; a new interpreter does not read its policy there."""
        ports.lock()
        published = _core._config._serialized_payload
        permissive = json.loads(published)
        permissive["global"].update(allow=["0.0.0.0/0"], allow_localhost=True, locked=False)
        monkeypatch.setenv(_CHILD_POLICY_ENV, json.dumps(permissive))

        result = ports.reach(subinterpreter(), STATE)
        _assert_enforced(result, ports)
        assert result["state"]["locked"] is True
        assert result["state"]["payload"] == published


class TestUnlockedPolicy:
    """Nothing changes without a lock: the guardian is inactive."""

    def test_a_subinterpreter_gets_its_own_unlocked_instance(self, listener, subinterpreter):
        tethered.activate(allow=["allowed.test"], external_subprocess_policy="allow")
        port = listener.getsockname()[1]
        result = subinterpreter().run(
            CONNECT,
            """
            import tethered, tethered._core as core
            out["locked"] = core._config.locked
            out["payload"] = core._config._serialized_payload
            attempt("elsewhere", sys.audit, "socket.connect", None, ("203.0.113.9", 443))
            attempt("launch", sys.audit, "os.system", "prog")
            attempt("remove", sys.audit, "os.remove", "site-packages/tethered.pth", -1)
            attempt("putenv", sys.audit, "os.putenv", "_TETHERED_CHILD_POLICY", "x")
            attempt("deactivate", tethered.deactivate)
            out["config after deactivate"] = core._config
            attempt("elsewhere after deactivate", sys.audit, "socket.connect", None,
                    ("203.0.113.9", 443))
            """,
            port=port,
        )
        assert _core._c_guardian.is_active() is False
        assert result["locked"] is False
        assert result["payload"] == _core._config._serialized_payload
        assert result["connect"] == "ok"
        assert _connection_arrived(listener)
        assert result["elsewhere"]["message"] == (
            "Blocked by tethered: 203.0.113.9:443 is not in the allow list"
        )
        assert result["launch"] == result["remove"] == result["putenv"] == "ok"
        # Its policy is its own to deactivate; this interpreter's stays.
        assert result["deactivate"] == "ok"
        assert result["config after deactivate"] is None
        assert result["elsewhere after deactivate"] == "ok"
        assert _core._config is not None
        with pytest.raises(tethered.EgressBlocked, match="is not in the allow list"):
            sys.audit("socket.connect", None, ELSEWHERE_ADDRESS)

    def test_no_policy_no_restriction(self, listener, subinterpreter):
        port = listener.getsockname()[1]
        result = subinterpreter().run(
            CONNECT, 'out["bootstrapped"] = "tethered._core" in sys.modules\n', port=port
        )
        assert result == {"connect": "ok", "bootstrapped": False}
        assert _connection_arrived(listener)


class TestLockedLogOnlyPolicy:
    """``log_only`` monitors without blocking — in every interpreter.

    The owning interpreter is refused no connection or lookup by such a
    policy, so the guardian refuses none to the others either: not to one
    that joined the lock, which reports through its own locked copy, and
    not to one outside it.  What is not an egress decision stays refused
    outside the lock: ``log_only`` does not soften process launches, the
    bootstrap files or the policy variable for the owner.
    """

    @pytest.fixture
    def log_only_lock(self) -> object:
        return _lock(log_only=True)

    def test_socket_events_pass(self, log_only_lock, listener, subinterpreter):
        """In an interpreter created under the lock, which has joined it."""
        port = listener.getsockname()[1]
        events = {
            "connect": sorted(_core._CONNECT_EVENTS),
            "lookup": sorted(_core._DNS_EVENTS | {"socket.getaddrinfo"}),
        }
        result = subinterpreter().run(
            COLLECT_WARNINGS,
            CONNECT,
            """
            def sendto():
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(b"x", ("127.0.0.1", port))

            def create_connection():
                socket.create_connection(("127.0.0.1", port), 10).close()

            attempt("sendto", sendto)
            attempt("create_connection", create_connection)
            attempt("getaddrinfo", socket.getaddrinfo, "localhost", port)
            attempt("gethostbyname", socket.gethostbyname, "localhost")
            out["quiet so far"] = list(warnings)
            for event in events["connect"]:
                attempt(event, sys.audit, event, None, ("203.0.113.9", 443))
            for event in events["lookup"]:
                attempt(event, sys.audit, event, "host.test", 80, 0, 0, 0)
            core = sys.modules["tethered._core"]
            out["config"] = [core._config.locked, core._config.log_only]
            out["warnings"] = warnings
            """,
            port=port,
            events=events,
        )
        # Its own copy of the policy is locked and log-only too, and does the
        # reporting.
        assert result.pop("config") == [True, True]
        assert result.pop("quiet so far") == []
        warnings = result.pop("warnings")
        assert "tethered: blocked connect to 203.0.113.9:443" in warnings
        assert "tethered: blocked getaddrinfo for host.test" in warnings
        assert len(warnings) == len(events["connect"]) + len(events["lookup"])
        assert len(result) == 5 + len(warnings)
        assert set(result.values()) == {"ok"}
        assert _connection_arrived(listener)
        assert _connection_arrived(listener)

    def test_launches_the_bootstrap_and_the_variable_stay_refused(
        self, scratch_site, outsider, log_only_lock
    ):
        """Outside the lock: in an interpreter that existed before it was taken."""
        events = {
            "launch": sorted(_core._SUBPROCESS_EVENTS | {"os.startfile/2"}),
            "fs": sorted(_core._PTH_FS_EVENTS),
            "env": sorted(_core._ENV_EVENTS),
        }
        result = outsider.run(
            """
            import pathlib

            pth = pathlib.Path(site_packages) / "tethered.pth"
            attempt("system", os.system, "exit 0")
            attempt("remove", os.remove, pth)
            attempt("write", pth.write_text, "gone")
            attempt("unset", os.unsetenv, "_TETHERED_CHILD_POLICY")
            attempt("set", os.putenv, "_TETHERED_CHILD_POLICY", "{}")
            for event in events["launch"]:
                attempt(event, sys.audit, event, "prog", ["prog"], None, None)
            for event in events["fs"]:
                attempt(event, sys.audit, event, "site-packages/tethered.pth", "w", 0)
            for event in events["env"]:
                attempt(event, sys.audit, event, "_TETHERED_CHILD_POLICY", "x")
            """,
            site_packages=str(scratch_site),
            events=events,
        )
        reasons = {
            "system": NO_LAUNCHES,
            "remove": NO_BOOTSTRAP_CHANGES,
            "write": NO_BOOTSTRAP_CHANGES,
            # (os.unsetenv, not os.environ.pop: the copy of the environment
            # this interpreter made when it started never held the variable.)
            "unset": NO_VARIABLE_CHANGES,
            "set": NO_VARIABLE_CHANGES,
            **dict.fromkeys(events["launch"], NO_LAUNCHES),
            **dict.fromkeys(events["fs"], NO_BOOTSTRAP_CHANGES),
            **dict.fromkeys(events["env"], NO_VARIABLE_CHANGES),
        }
        assert result.keys() == reasons.keys()
        for name, reason in reasons.items():
            _assert_refused(result[name], SUBPROCESS_BLOCKED, reason)
        assert (scratch_site / "tethered.pth").read_text() == "# stand-in\n"
        assert os.environ[_CHILD_POLICY_ENV] == _core._config._serialized_payload
        assert _core._c_guardian.process_policy_env() == _core._config._serialized_payload

    def test_without_tethered_loaded(self, log_only_lock, listener, subinterpreter, monkeypatch):
        """No copy of the policy there: nothing reports, and still nothing is launched."""
        monkeypatch.delenv(_CHILD_POLICY_ENV)
        port = listener.getsockname()[1]
        result = subinterpreter().run(
            CONNECT,
            """
            attempt("elsewhere", sys.audit, "socket.connect", None, ("203.0.113.9", 443))
            attempt("lookup", sys.audit, "socket.getaddrinfo", "host.test", 80, 0, 0, 0)
            attempt("launch", os.system, "exit 0")
            attempt("putenv", os.putenv, "_TETHERED_CHILD_POLICY", "{}")
            out["tethered loaded"] = sorted(m for m in sys.modules if m.startswith("tethered"))
            """,
            port=port,
        )
        assert result.pop("tethered loaded") == []
        assert result.pop("connect") == result.pop("elsewhere") == result.pop("lookup") == "ok"
        assert _connection_arrived(listener)
        _assert_refused(result.pop("launch"), RUNTIME_ERROR, NO_LAUNCHES)
        _assert_refused(result.pop("putenv"), RUNTIME_ERROR, NO_VARIABLE_CHANGES)
        assert result == {}

    def test_replacing_the_locked_policy_switches_in_both_directions(
        self, listener, subinterpreter
    ):
        """What an interpreter outside the lock may do follows the policy that is locked now."""
        port = listener.getsockname()[1]
        interp = subinterpreter()  # before any lock: it joins none of the ones below
        interp.run("import tethered\n")
        token = _lock(log_only=True)

        def connect() -> object:
            return interp.run(CONNECT, port=port)["connect"]

        assert connect() == "ok"
        assert _connection_arrived(listener)

        _lock(token)  # the same lock, now enforcing
        _assert_refused(connect(), EGRESS_BLOCKED, NO_NETWORK)
        assert not _connection_arrived(listener)

        _lock(token, log_only=True)
        assert connect() == "ok"
        assert _connection_arrived(listener)

        tethered.deactivate(lock_token=token)
        assert connect() == "ok"
        assert _connection_arrived(listener)

        _lock()  # another lock, enforcing from the start
        _assert_refused(connect(), EGRESS_BLOCKED, NO_NETWORK)
        assert not _connection_arrived(listener)

    # Connects to loopback by name and by address, then somewhere the policy
    # does not allow; records which names the address was learnt under.
    _BY_NAME = """
    import socket
    import tethered._core as core

    def by_name():
        socket.getaddrinfo("localhost", port, socket.AF_INET)
        with socket.socket() as s:
            s.settimeout(10)
            s.connect(("127.0.0.1", port))

    attempt("by name", by_name)
    out["names"] = list(core._ip_to_hostname.get("127.0.0.1", ()))
    out["by name warnings"] = list(warnings)
    attempt("elsewhere", sys.audit, "socket.connect", None, ("203.0.113.9", 443))
    out["warnings"] = list(warnings)

    guardian = core._c_guardian
    out["through the guardian"] = guardian is not None and guardian.is_active()
    out["locked"] = core._config.locked
    """

    def _assert_mapped_by_name(self, result: dict, listener: socket.socket) -> None:
        assert result["by name"] == "ok"
        assert _connection_arrived(listener)
        assert result["names"] == ["localhost"]
        assert result["by name warnings"] == []
        assert result["elsewhere"] == "ok"
        assert result["warnings"] == ["tethered: blocked connect to 203.0.113.9:443"]
        # The extension loads in an interpreter of either kind, so the lookup
        # that learns the name always goes through the guardian.
        assert result["through the guardian"] is True

    @pytest.mark.parametrize("shared_gil", GIL_KINDS)
    def test_names_are_still_mapped_to_addresses(self, shared_gil, listener, subinterpreter):
        """Otherwise its log-only policy would report every connection made by hostname.

        Loopback is allowed here only by name.  In an interpreter that existed
        before the lock, with a copy of the policy of its own: the guardian
        serves a caller outside the lock from that interpreter's own resolver.
        """
        policy = {"allow": ["localhost"], "allow_localhost": False, "log_only": True}
        interp = _outsider_with_a_copy(subinterpreter, shared_gil=shared_gil, **policy)
        _lock(**policy)
        port = listener.getsockname()[1]
        result = interp.run(
            COLLECT_WARNINGS,
            self._BY_NAME,
            """
            found = guardian.resolve("localhost", port, socket.AF_INET, 0, 0, 0)
            out["resolve"] = sorted({entry[4][0] for entry in found})
            # (an address family that does not exist: fails without any lookup)
            attempt("resolve failure", guardian.resolve, "127.0.0.1", port, 12345, 0, 0, 0)
            """,
            port=port,
        )
        self._assert_mapped_by_name(result, listener)
        assert result["locked"] is False
        assert result["resolve"] == ["127.0.0.1"]
        # A failed lookup is the resolver's own error, not a refusal.
        assert result["resolve failure"]["type"] == "socket.gaierror"

    @pytest.mark.parametrize("shared_gil", GIL_KINDS)
    def test_names_are_mapped_to_addresses_in_an_interpreter_that_joined(
        self, shared_gil, listener, subinterpreter, capfd
    ):
        """Its own hook resolves inside the guardian's window, with its own resolver.

        Like the owner's — and like the owner, nothing but tethered's two
        resolving functions may call ``resolve()`` there.
        """
        _lock(allow=["localhost"], allow_localhost=False, log_only=True)
        port = listener.getsockname()[1]
        interp = subinterpreter(shared_gil=shared_gil)
        result = interp.run(COLLECT_WARNINGS, self._BY_NAME, port=port)
        self._assert_mapped_by_name(result, listener)
        assert result["locked"] is True
        assert TAMPER_ALERT not in capfd.readouterr().err

        result = interp.run(
            """
            import tethered._core as core
            attempt("resolve", core._c_guardian.resolve, "localhost", port, 0, 0, 0, 0)
            """,
            port=port,
        )
        assert result["resolve"]["type"] == EGRESS_BLOCKED
        assert result["resolve"]["host"] == "unauthorized _guardian.resolve() call"
        assert TAMPER_ALERT in capfd.readouterr().err

    def test_the_owner_is_still_refused_everything_once_tampered_with(
        self, outsider, log_only_lock, listener, subinterpreter, monkeypatch, capfd
    ):
        """A failed integrity check refuses the owner whatever ``log_only`` says.

        It is the owner's alone.  An interpreter outside the lock is judged
        by the lock, not by the state of the owner's objects; and one that
        joins — even now — is verified against its own, which are intact: its
        policy comes from the guardian's record, not from the owner's modules.
        """
        port = listener.getsockname()[1]
        sys.audit("socket.connect", None, ELSEWHERE_ADDRESS)  # reported, not refused
        with monkeypatch.context() as patch:
            patch.setattr(_core, "_handle_connect", lambda *args: None)
            with pytest.raises(tethered.EgressBlocked):
                sys.audit("socket.connect", None, ("127.0.0.1", port))
            with pytest.raises(tethered.SubprocessBlocked, match="integrity"):
                sys.audit("os.system", "prog")
            assert TAMPER_ALERT in capfd.readouterr().err
            assert _core._c_guardian.verify() is False

            # Nothing is verified on behalf of an interpreter outside the
            # lock: what it may do was settled when the lock was taken.
            assert outsider.run(CONNECT, port=port)["connect"] == "ok"

            joined = subinterpreter().run(CONNECT, STATE, port=port)
            assert joined["connect"] == "ok"
            assert joined["state"]["locked"] is True
            assert joined["state"]["log_only"] is True
            assert joined["state"]["verify"] is True
            # One alert, for the one interpreter that was tampered with.
            assert TAMPER_ALERT not in capfd.readouterr().err
        sys.audit("socket.connect", None, ELSEWHERE_ADDRESS)
        assert _core._c_guardian.verify() is True
        # Both connections arrived.  (Looked at only now: accepting one makes
        # a socket, and while its state fails verification the owner is
        # refused that as well — on POSIX, where accept() raises the event.)
        assert _connection_arrived(listener)
        assert _connection_arrived(listener)
        assert not _connection_arrived(listener)

    @pytest.mark.parametrize(
        ("config", "passes"),
        [
            ({"log_only": True}, True),
            ({"log_only": False}, False),
            ({"log_only": 1}, False),
            ({"log_only": "yes"}, False),
            ({}, False),
        ],
        ids=["True", "False", "1", "str", "missing"],
    )
    def test_only_a_plain_true_counts_as_log_only(self, config, passes, subinterpreter):
        """The guardian on its own, handed a stand-in for the config."""
        import types

        token = object()
        stand_in = types.SimpleNamespace(locked=False, **config)
        _core._c_guardian.activate(vars(_core), stand_in, token, [])
        try:
            result = subinterpreter().run(
                """
                attempt("connect", sys.audit, "socket.connect", None, ("203.0.113.9", 443))
                attempt("launch", sys.audit, "os.system", "prog")
                """
            )
        finally:
            _core._c_guardian.deactivate(token)
        if passes:
            assert result["connect"] == "ok"
        else:
            _assert_refused(result["connect"], RUNTIME_ERROR, NO_NETWORK)
        _assert_refused(result["launch"], RUNTIME_ERROR, NO_LAUNCHES)


@pytest.mark.skipif(
    sys.version_info < (3, 14), reason="InterpreterPoolExecutor arrived in Python 3.14"
)
class TestInterpreterPool:
    # Run through ``exec`` in a worker: a callable the worker can unpickle,
    # with nothing to send back but an exception.
    _CONNECT = (
        "import socket\n"
        "with socket.socket() as s:\n"
        "    s.settimeout(10)\n"
        "    s.connect(('127.0.0.1', %d))\n"
    )

    def test_a_pool_works_under_a_locked_policy(self, ports):
        """Every worker is a new interpreter, created under the lock: it joins it.

        (Before the lock could be joined a worker got no network at all, and
        before that the pool broke: ``BrokenInterpreterPool``.)
        """
        from concurrent.futures import InterpreterPoolExecutor

        ports.lock()
        with InterpreterPoolExecutor(max_workers=2) as pool:
            assert list(pool.map(pow, [2, 3, 4], [5, 5, 5])) == [32, 243, 1024]
            assert pool.submit(sum, range(1000)).result(timeout=120) == 499500

            # What the policy allows is reached ...
            assert pool.submit(exec, self._CONNECT % ports.allowed).result(timeout=120) is None
            assert ports.arrivals() == (True, False)
            # ... and what it does not is refused by the worker's own copy of
            # the policy, not by the guardian for want of one.
            refused = pool.submit(exec, self._CONNECT % ports.forbidden)
            with pytest.raises(Exception, match="is not in the allow list") as excinfo:
                refused.result(timeout=120)
            assert f"127.0.0.1:{ports.forbidden}" in str(excinfo.value)
            assert ELSEWHERE not in str(excinfo.value)
            assert ports.arrivals() == (False, False)

            # The pool survives a refused task, and a worker cannot unlock.
            assert pool.submit(len, "still working").result(timeout=120) == 13
            with pytest.raises(Exception, match="policy is locked"):
                pool.submit(exec, "import tethered\ntethered.deactivate()\n").result(timeout=120)
            assert pool.submit(exec, self._CONNECT % ports.allowed).result(timeout=120) is None
            assert ports.arrivals() == (True, False)

    def test_a_pool_that_existed_before_the_lock_gets_no_network(self, ports):
        """Its workers were not created under the lock."""
        from concurrent.futures import InterpreterPoolExecutor

        with InterpreterPoolExecutor(max_workers=1) as pool:
            assert pool.submit(pow, 2, 10).result(timeout=120) == 1024  # the worker exists
            ports.lock()
            lookup = pool.submit(exec, self._CONNECT % ports.allowed)
            with pytest.raises(Exception, match="gets no network access") as excinfo:
                lookup.result(timeout=120)
            assert ELSEWHERE in str(excinfo.value)
            assert ports.arrivals() == (False, False)
            # The pool survives a refused task.
            assert pool.submit(len, "still working").result(timeout=120) == 13

    def test_a_pool_reaches_the_network_under_a_locked_log_only_policy(self):
        from concurrent.futures import InterpreterPoolExecutor

        _lock(log_only=True)
        with InterpreterPoolExecutor(max_workers=1) as pool:
            assert pool.submit(pow, 2, 10).result(timeout=120) == 1024
            assert pool.submit(socket.getaddrinfo, "localhost", 80).result(timeout=120)

    def test_a_pool_under_an_unlocked_policy(self):
        from concurrent.futures import InterpreterPoolExecutor

        tethered.activate(allow=["allowed.test"])
        with InterpreterPoolExecutor(max_workers=1) as pool:
            assert pool.submit(pow, 2, 10).result(timeout=120) == 1024
            # localhost is allowed by the worker's own, inherited policy
            assert pool.submit(socket.getaddrinfo, "localhost", 80).result(timeout=120)


class TestInterpretersSharingTheGil:
    """Every interpreter loads the C extension and sees one lock, owned by one of them.

    (Before the guardian kept its state per interpreter, only an interpreter
    that shares the main GIL could load it — hence the name.)
    """

    @pytest.mark.parametrize("shared_gil", GIL_KINDS)
    def test_the_guardians_functions_refuse_a_caller_from_another_interpreter(
        self, shared_gil, subinterpreter, capfd
    ):
        """One outside the lock: it started under an unlocked policy, before the lock."""
        interp = _outsider_with_a_copy(subinterpreter, shared_gil=shared_gil)
        locked = _lock()
        result = interp.run(
            """
            import tethered
            import tethered._core as core

            guardian = core._c_guardian
            out["config locked"] = core._config.locked
            out["is_active"] = guardian.is_active()
            out["check_token"] = guardian.check_token(object())
            out["check_token None"] = guardian.check_token(None)
            out["verify"] = guardian.verify()
            out["locked_payload"] = guardian.locked_payload()
            attempt("guardian.activate", guardian.activate, {}, None, object(), [])
            attempt("guardian.deactivate", guardian.deactivate, object())
            attempt("guardian.join", guardian.join, vars(core), core._config, [])
            attempt("join", core._join_locked, guardian.locked_payload())
            attempt("guardian.resolve", guardian.resolve, "localhost", 80, 0, 0, 0, 0)
            attempt("tethered.activate", tethered.activate, allow=[])
            attempt("tethered.deactivate", tethered.deactivate)
            attempt("connect", sys.audit, "socket.connect", None, ("203.0.113.9", 443))
            attempt("getaddrinfo", sys.audit, "socket.getaddrinfo", "host.test", 80, 0, 0, 0)
            out["still active"] = guardian.is_active()
            out["config still unlocked"] = core._config.locked
            """
        )
        assert result["config locked"] is False
        assert result["is_active"] is True
        assert result["check_token"] is False
        assert result["check_token None"] is False
        assert result["verify"] is False
        # What is locked is no secret (the variable says as much); joining it is
        # another matter.
        assert result["locked_payload"] == _core._config._serialized_payload
        _assert_refused(result["guardian.activate"], RUNTIME_ERROR, "replaced from there")
        assert ELSEWHERE in result["guardian.activate"]["message"]
        _assert_refused(result["guardian.deactivate"], RUNTIME_ERROR, "deactivated from there")
        assert ELSEWHERE in result["guardian.deactivate"]["message"]
        for name in ("guardian.join", "join"):
            _assert_refused(result[name], RUNTIME_ERROR, "")
            # Which of the two it is depends on whether a policy had been
            # locked in this process before the interpreter was created (the
            # guardian's hook is installed by the first lock).
            assert result[name]["message"] in (
                CANNOT_JOIN + STARTUP_IS_OVER,
                CANNOT_JOIN + CREATED_BEFORE_THE_WATCH,
            )
        _assert_refused(result["guardian.resolve"], EGRESS_BLOCKED, NO_NETWORK)
        assert result["guardian.resolve"]["host"] == "localhost"
        assert result["tethered.activate"]["type"] == TETHERED_LOCKED
        assert result["tethered.deactivate"]["type"] == TETHERED_LOCKED
        _assert_refused(result["connect"], EGRESS_BLOCKED, NO_NETWORK)
        _assert_refused(result["getaddrinfo"], EGRESS_BLOCKED, NO_NETWORK)
        assert result["still active"] is True
        assert result["config still unlocked"] is False

        # Nothing of the owner's was touched: no tamper alert, still intact,
        # still unlocked by its own token only.
        assert "TAMPER DETECTED" not in capfd.readouterr().err
        assert _core._c_guardian.verify() is True
        assert _core._config.locked is True
        tethered.deactivate(lock_token=locked)
        assert _core._c_guardian.is_active() is False

    def test_the_lock_belongs_to_whichever_interpreter_took_it(self, tmp_path):
        """A subinterpreter locks: now the main interpreter is the "other" one.

        Run in a child process — the token lives in the subinterpreter, where
        the test suite's cleanup could not reach it if something went wrong.
        """
        result_file = tmp_path / "result.json"
        script = textwrap.dedent(
            f"""
            import json, sys
            try:
                import _interpreters as interps
            except ImportError:
                import _xxsubinterpreters as interps
            import tethered
            import tethered._core as core

            def create():
                if sys.version_info >= (3, 13):
                    return interps.create("legacy")
                if sys.version_info >= (3, 12):
                    return interps.create(isolated=False)
                return interps.create()

            def run(interp, code):
                if hasattr(interps, "exec"):
                    failure = interps.exec(interp, code)
                    assert failure is None, getattr(failure, "formatted", failure)
                else:
                    interps.run_string(interp, code)

            def connect():
                try:
                    sys.audit("socket.connect", None, ("127.0.0.1", 9))
                except RuntimeError as exc:
                    return [type(exc).__name__, str(exc)]
                return "ok"

            def deactivate():
                try:
                    tethered.deactivate()
                except RuntimeError as exc:
                    return type(exc).__name__
                return "ok"

            out = {{}}
            interp = create()
            run(interp, "import tethered\\n"
                        "token = object()\\n"
                        "tethered.activate(allow=[], locked=True, lock_token=token)\\n"
                        "import sys\\n"
                        "sys.audit('socket.connect', None, ('127.0.0.1', 9))\\n")
            out["while locked"] = [
                core._c_guardian.is_active(), core._c_guardian.verify(), core._config,
                connect(), deactivate(),
            ]
            run(interp, "tethered.deactivate(lock_token=token)\\n")
            out["after"] = [core._c_guardian.is_active(), connect(), deactivate()]
            interps.destroy(interp)
            with open({str(result_file)!r}, "w") as f:
                json.dump(out, f)
            """
        )
        child = subprocess.run(  # nosec B603
            [sys.executable, "-c", script], capture_output=True, text=True, timeout=120
        )
        assert child.returncode == 0, child.stderr
        assert "TAMPER DETECTED" not in child.stderr
        result = json.loads(result_file.read_text())
        assert result["while locked"] == [
            True,
            False,
            None,
            ["EgressBlocked", f"Blocked by tethered: 127.0.0.1 {NO_NETWORK}"],
            "TetheredLocked",
        ]
        assert result["after"] == [False, "ok", "ok"]

    def test_the_lock_outlives_the_interpreter_that_took_it(self, tmp_path):
        """Destroying the owner leaves the process locked, and nobody inherits the lock.

        The guardian knows the owner by its interpreter ID.  By the address
        of its state, the next interpreter created — which is likely to be
        given that memory — would pass for the owner and, with a copy of
        tethered that nothing pins, reach anything.

        The process stays locked for good.  An interpreter that had joined
        keeps its pinned copy of the policy and keeps working; one created
        afterwards still joins, from the guardian's record of the policy —
        as a joiner, never as the owner: it has no token, and dropping its
        copy gets it nothing.  The main interpreter, which existed before the
        lock, stays outside it.

        Run in a child process: this lock can never be released again.
        """
        result_file = tmp_path / "result.json"
        child = subprocess.run(  # nosec B603
            [sys.executable, "-c", _DESTROY_THE_OWNER, str(result_file), str(tmp_path / "later")],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert child.returncode == 0, child.stderr
        result = json.loads(result_file.read_text())

        allowed_then_forbidden = ["ok", "Blocked by tethered: 127.0.0.1:9 is not in the allow list"]
        enforcing = {
            "locked": True,
            "verify": True,
            "check_token": False,
            "reach": allowed_then_forbidden,
        }
        # The one that joined while the owner lived: before and after.
        assert result["joined before"] == [enforcing, enforcing]
        # Those created after the owner was destroyed, of either kind: joined,
        # and not able to release what they did not take.
        assert len(result["joined after"]) == (4 if OWN_GIL else 2)
        for later in result["joined after"]:
            assert later == {
                **enforcing,
                "deactivate": "TetheredLocked",
                "guardian.deactivate": f"RuntimeError: tethered: {ELSEWHERE} "
                "and can only be deactivated from there",
                "guardian.activate": f"RuntimeError: tethered: {ELSEWHERE} "
                "and can only be replaced from there",
            }
        # One of them drops its copy of the policy: it is not the owner under
        # another name, so nothing passes there any more.
        assert result["dropped its copy"] == [INTEGRITY_REFUSAL, INTEGRITY_REFUSAL]
        assert child.stderr.count(TAMPER_ALERT) == 1

        refused = f"Blocked by tethered: 127.0.0.1 {NO_NETWORK}"
        assert result["main"] == {
            "is_active": True,
            "verify": False,
            "reach": [refused, refused],
            "deactivate": "TetheredLocked",
            "guardian.deactivate": f"RuntimeError: tethered: {ELSEWHERE} "
            "and can only be deactivated from there",
            "join": "RuntimeError: " + CANNOT_JOIN + CREATED_BEFORE_THE_WATCH,
        }


# Child process of test_the_lock_outlives_the_interpreter_that_took_it:
# ``sys.argv`` holds the result file and the file the subinterpreters append
# their findings to, one JSON object per line.  The locked policy allows
# 127.0.0.1:1 and nothing else; connections are audit events, never made.
_DESTROY_THE_OWNER = '''
import json, sys
try:
    import _interpreters as interps
except ImportError:
    import _xxsubinterpreters as interps
import tethered
import tethered._core as core

result_file, later_file = sys.argv[1:]
OWN_GIL = sys.version_info >= (3, 12)

def create(shared_gil):
    if sys.version_info >= (3, 13):
        return interps.create("legacy" if shared_gil else "isolated")
    if sys.version_info >= (3, 12):
        return interps.create(isolated=not shared_gil)
    return interps.create()

def run(interp, code):
    if hasattr(interps, "exec"):
        failure = interps.exec(interp, code)
        assert failure is None, getattr(failure, "formatted", failure)
    else:
        interps.run_string(interp, code)

# Shared by every interpreter of this process, the main one included.
PROBES = """
import sys

def outcome(call, *args, **kwargs):
    try:
        call(*args, **kwargs)
    except RuntimeError as exc:
        return type(exc).__name__ + ": " + str(exc)
    return "ok"

def reach():
    found = []
    for port in (1, 9):
        text = outcome(sys.audit, "socket.connect", None, ("127.0.0.1", port))
        found.append(text.partition(": ")[2] if text != "ok" else text)
    return found
"""
exec(PROBES)

REPORT = PROBES + """
import json
import tethered
core = sys.modules["tethered._core"]
guardian = core._c_guardian

def report(**extra):
    found = {
        "locked": core._config.locked,
        "verify": guardian.verify(),
        "check_token": guardian.check_token(object()),
        "reach": reach(),
        **extra,
    }
    with open(%r, "a", encoding="utf-8") as f:
        f.write(json.dumps(found) + "\\\\n")
""" % later_file

owner = create(True)
run(owner, "import tethered\\n"
           "tethered.activate(allow=['127.0.0.1:1'], allow_localhost=False, locked=True,"
           " lock_token=object())\\n")
joined_before = create(True)
run(joined_before, REPORT + "report()\\n")

interps.destroy(owner)

run(joined_before, "report()\\n")
kinds = (False, True, False, True) if OWN_GIL else (True, True)
for shared_gil in kinds:
    later = create(shared_gil)
    run(later, REPORT + """
report(**{
    "deactivate": outcome(tethered.deactivate).partition(":")[0],
    "guardian.deactivate": outcome(guardian.deactivate, object()),
    "guardian.activate": outcome(guardian.activate, vars(core), core._config, object(), []),
})
""")
    interps.destroy(later)

# A later interpreter drops the policy it started with, so that only the
# guardian stands between it and the connection.
dropper = create(True)
run(dropper, REPORT + """
core._config = None
with open(%r, "a", encoding="utf-8") as f:
    f.write(json.dumps(reach()) + "\\\\n")
""" % later_file)
interps.destroy(dropper)
interps.destroy(joined_before)

with open(later_file, encoding="utf-8") as f:
    lines = [json.loads(line) for line in f.read().splitlines()]
out = {
    "joined before": lines[:2],
    "joined after": lines[2:-1],
    "dropped its copy": lines[-1],
    "main": {
        "is_active": core._c_guardian.is_active(),
        "verify": core._c_guardian.verify(),
        "reach": reach(),
        "deactivate": outcome(tethered.deactivate).partition(":")[0],
        "guardian.deactivate": outcome(core._c_guardian.deactivate, object()),
        "join": outcome(core._join_locked, core._c_guardian.locked_payload()),
    },
}
with open(result_file, "w") as f:
    json.dump(out, f)
'''


class TestOtherStartupFailures:
    """Only the lock is treated differently: every other strict failure still stops startup.

    Run in child processes: up to Python 3.12 a ``SystemExit`` raised while a
    subinterpreter starts terminates the whole process (status 1); from 3.13
    creating the interpreter fails instead.
    """

    _SCRIPT = textwrap.dedent(
        """
        import os, sys
        try:
            import _interpreters as interps
        except ImportError:
            import _xxsubinterpreters as interps

        os.environ["_TETHERED_CHILD_POLICY"] = sys.argv[1]
        try:
            interp = interps.create()
        except Exception as exc:
            print("CREATE FAILED", type(exc).__name__)
        else:
            code = (
                "import sys\\n"
                "core = sys.modules.get('tethered._core')\\n"
                "locked = core and core._config.locked\\n"
                "print('USER CODE RAN locked=%s' % locked, flush=True)\\n"
                "try:\\n"
                "    sys.audit('socket.connect', None, ('203.0.113.9', 443))\\n"
                "except RuntimeError as exc:\\n"
                "    print('ENFORCED', exc, flush=True)\\n"
            )
            if hasattr(interps, "exec"):
                interps.exec(interp, code)
            else:
                interps.run_string(interp, code)
            interps.destroy(interp)
        print("MAIN CONTINUES", os.environ["_TETHERED_CHILD_POLICY"] == sys.argv[1])
        """
    )

    def _child(self, global_payload: dict, scopes: object = None) -> subprocess.CompletedProcess:
        payload = json.dumps({"global": global_payload, "scopes": [] if scopes is None else scopes})
        env = {k: v for k, v in os.environ.items() if k != _CHILD_POLICY_ENV}
        return subprocess.run(  # nosec B603
            [sys.executable, "-c", self._SCRIPT, payload],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

    @pytest.mark.parametrize(
        ("global_payload", "scopes"),
        [
            ({"allow": [], "locked": True, "log_only": 0}, None),
            ({"allow": [], "locked": True, "from_a_newer_version": True}, None),
            ({"allow": ["://not-a-rule"], "locked": True}, None),
            ({"allow": [], "locked": True, "external_subprocess_policy": "sometimes"}, None),
            ({"locked": True}, None),
            ({"allow": [], "locked": True}, [{"allow": [5]}]),
            ({"allow": [], "fail_closed": True, "log_only": 0}, None),
            ({"allow": ["://not-a-rule"], "fail_closed": True}, None),
        ],
        ids=[
            "locked-wrong-type",
            "locked-unknown-field",
            "locked-bad-rule",
            "locked-bad-subprocess-policy",
            "locked-missing-allow",
            "locked-bad-scope",
            "fail-closed-wrong-type",
            "fail-closed-bad-rule",
        ],
    )
    def test_a_strict_policy_that_cannot_be_established_stops_startup(self, global_payload, scopes):
        child = self._child(global_payload, scopes)
        assert "USER CODE RAN" not in child.stdout
        if sys.version_info >= (3, 13):
            assert child.returncode == 0, child.stderr
            assert child.stdout.splitlines() == [
                "CREATE FAILED InterpreterError",
                "MAIN CONTINUES True",
            ]
        else:
            assert child.returncode == 1
            assert child.stdout == ""
            assert "tethered: refusing to start" in child.stderr

    def test_a_locked_payload_without_any_lock_is_enforced_from_python(self):
        """No guardian is active in this process; the allow list still holds, unlocked."""
        child = self._child({"allow": ["allowed.test"], "locked": True})
        assert child.returncode == 0, child.stderr
        assert child.stdout.splitlines() == [
            "USER CODE RAN locked=False",
            "ENFORCED Blocked by tethered: 203.0.113.9:443 is not in the allow list",
            # ... and the variable still carries the locked payload.
            "MAIN CONTINUES True",
        ]


class TestAJoinThatFails:
    """An interpreter that cannot join the lock starts all the same, outside it.

    Run in child processes: were startup stopped instead, up to Python 3.12
    the ``SystemExit`` would end the whole process — which is what a failed
    join must never do.

    The join is made to fail for real: the guardian is locked on its own,
    with a stand-in config whose payload says the same as the variable's
    policy in other bytes.  The interpreter rebuilds the policy, offers it,
    and the guardian — which compares byte for byte — refuses.
    """

    _SCRIPT = textwrap.dedent(
        """
        import json, os, sys, types
        try:
            import _interpreters as interps
        except ImportError:
            import _xxsubinterpreters as interps
        import tethered._core as core

        variable = sys.argv[1]
        locked_policy = {
            "allow": ["allowed.test"], "allow_localhost": True, "log_only": False,
            "fail_closed": False, "external_subprocess_policy": "allow", "locked": True,
        }
        # The same policy, serialized otherwise than tethered would.
        payload = json.dumps({"global": locked_policy, "scopes": []}, indent=1)
        stand_in = types.SimpleNamespace(locked=True, log_only=False, _serialized_payload=payload)
        core._c_guardian.activate(vars(core), stand_in, object(), [])
        os.environ["_TETHERED_CHILD_POLICY"] = variable
        print("LOCKED", core._c_guardian.locked_payload() == payload, flush=True)

        interp = interps.create()
        code = (
            "import sys\\n"
            "core = sys.modules.get('tethered._core')\\n"
            "config = core and core._config\\n"
            "print('USER CODE RAN config=%s' % (config and 'locked=%s' % config.locked),"
            " flush=True)\\n"
            "try:\\n"
            "    sys.audit('socket.connect', None, ('127.0.0.1', 9))\\n"
            "    print('CONNECTED', flush=True)\\n"
            "except RuntimeError as exc:\\n"
            "    print('REFUSED', exc, flush=True)\\n"
        )
        if hasattr(interps, "exec"):
            interps.exec(interp, code)
        else:
            interps.run_string(interp, code)
        interps.destroy(interp)
        print("MAIN CONTINUES", flush=True)
        """
    )

    def _child(self, variable: dict) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if k != _CHILD_POLICY_ENV}
        return subprocess.run(  # nosec B603
            [sys.executable, "-c", self._SCRIPT, json.dumps(variable)],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

    @pytest.mark.parametrize(
        ("locked_in_the_variable", "config"),
        [(True, "locked=False"), (False, "None")],
        ids=["variable-says-locked", "variable-says-unlocked"],
    )
    def test_the_interpreter_starts_and_stays_outside_the_lock(
        self, locked_in_the_variable, config
    ):
        variable = {
            "global": {"allow": ["allowed.test"], "locked": locked_in_the_variable},
            "scopes": [],
        }
        child = self._child(variable)
        assert child.returncode == 0, child.stderr
        assert child.stdout.splitlines() == [
            "LOCKED True",
            # It started.  Having failed to join, it went by the variable: a
            # locked policy is enforced unlocked there, and an unlocked one
            # cannot be activated under another interpreter's lock.
            f"USER CODE RAN config={config}",
            # Either way the guardian refuses it: loopback, which the policy allows.
            f"REFUSED Blocked by tethered: 127.0.0.1 {NO_NETWORK}",
            "MAIN CONTINUES",
        ]
        # Reported once, as a warning, with the guardian's reason.
        warning = (
            "tethered: this interpreter could not join the locked policy of its process "
            "(RuntimeError: " + CANNOT_JOIN + "the config offered does not carry the payload "
            "of the locked policy)"
        )
        assert child.stderr.count(warning) == 1
        assert "refusing to start" not in child.stderr
        assert TAMPER_ALERT not in child.stderr


@pytest.mark.skipif(not OWN_GIL, reason="before Python 3.12 every interpreter shares one GIL")
class TestConcurrency:
    def test_many_interpreters_created_at_once_all_join(self, ports, tmp_path, capfd):
        """Each on a thread of its own, starting, joining and connecting in parallel.

        What they share in the guardian — the lock, the record of who has
        finished starting, the pool of per-interpreter state — is reached
        from all of them at the same time, each under its own GIL.

        Every thread destroys the interpreter it created: on Python 3.12 an
        interpreter in which ``threading`` was imported while it started
        cannot be destroyed from another thread (its shutdown waits for the
        thread that started it), with or without tethered's guardian.
        """
        ports.lock()
        threads_per_round, rounds = 8, 2
        results: list[dict] = []
        failures: list[BaseException] = []
        guard = threading.Lock()

        def start_join_and_reach(index: int) -> None:
            try:
                interp = _Subinterpreter(tmp_path / f"concurrent-{index}.json")
                try:
                    found = ports.reach(interp, STATE)
                finally:
                    interp.close()
                with guard:
                    results.append(found)
            except BaseException as exc:
                with guard:
                    failures.append(exc)

        for round_ in range(rounds):
            # (The second round takes the state the first one gave back.)
            workers = [
                threading.Thread(target=start_join_and_reach, args=(round_ * 100 + n,))
                for n in range(threads_per_round)
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=120)
            assert not any(worker.is_alive() for worker in workers)

        assert not failures, failures
        assert len(results) == threads_per_round * rounds
        published = _core._config._serialized_payload
        for found in results:
            assert found["allowed"] == "ok", found["allowed"]
            assert found["forbidden"]["type"] == EGRESS_BLOCKED
            assert found["forbidden"]["message"] == ports.not_in_the_allow_list()
            assert found["state"] == {
                "locked": True,
                "log_only": False,
                "payload": published,
                "verify": True,
                "check_token": False,
            }
        # Every one of them reached the allowed listener, none the other.
        arrived = [ports.arrivals() for _ in range(len(results) + 1)]
        assert arrived == [(True, False)] * len(results) + [(False, False)]
        assert TAMPER_ALERT not in capfd.readouterr().err
        assert _core._c_guardian.verify() is True

    def test_events_from_an_interpreter_with_its_own_gil_while_the_lock_changes_hands(
        self, subinterpreter
    ):
        """The other interpreter's hook calls overlap this one's activations.

        It is outside every one of these locks, so its events are judged
        from the guardian's atomics and from none of its objects: each is
        either refused or passed — and nothing breaks.
        """
        interp = subinterpreter()
        results: list[dict] = []
        worker = threading.Thread(
            target=lambda: results.append(
                interp.run(
                    """
                    import time

                    refused = passed = 0
                    deadline = time.monotonic() + seconds
                    while time.monotonic() < deadline:
                        try:
                            sys.audit("socket.connect", None, ("203.0.113.9", 443))
                            passed += 1
                        except RuntimeError:
                            refused += 1
                        sys.audit("open", "site-packages/tethered.pth", "r", 0)
                        sys.audit("socket.bind", None, ("127.0.0.1", 0))
                    out["refused"], out["passed"] = refused, passed
                    """,
                    seconds=1.5,
                )
            )
        )
        worker.start()
        rounds = 0
        while worker.is_alive():
            token = _lock()
            with pytest.raises(tethered.EgressBlocked, match="is not in the allow list"):
                sys.audit("socket.connect", None, ELSEWHERE_ADDRESS)
            tethered.deactivate(lock_token=token)
            rounds += 1
        worker.join()
        assert rounds > 10
        (result,) = results
        assert result["refused"] > 0
        assert result["passed"] > 0
