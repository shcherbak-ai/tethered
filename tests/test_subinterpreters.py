"""Real subinterpreters next to a tethered policy.

A lock exists once per process: the C guardian holds it for the interpreter
that took it, and its audit hook sees the events of every interpreter.  While
a policy is locked, any other interpreter is refused the operations tethered
guards — connections, lookups, process launches, changes to ``tethered.pth``
/ ``tethered.start`` and to the policy variable — and keeps working for
everything else.

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
# the stdlib creates by default.  The C extension cannot be loaded there; it
# can in one that shares the main GIL ("legacy"), the only kind before 3.12.
OWN_GIL = sys.version_info >= (3, 12)

ELSEWHERE = "a locked tethered policy is active in another interpreter of this process"
NO_NETWORK = f"({ELSEWHERE}, so this interpreter gets no network access)"
NO_LAUNCHES = f"({ELSEWHERE}, so this interpreter cannot launch processes)"
NO_BOOTSTRAP_CHANGES = (
    f"({ELSEWHERE}, so this interpreter cannot change tethered.pth or tethered.start)"
)
NO_VARIABLE_CHANGES = (
    f"({ELSEWHERE}, so this interpreter cannot change the _TETHERED_CHILD_POLICY variable)"
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


class TestLockedPolicy:
    """A subinterpreter created while the main interpreter holds a locked policy."""

    def test_it_starts_computes_and_enforces_the_policy_unlocked(self, locked, subinterpreter):
        """Creating one used to fail: the bootstrap could not take the lock there."""
        result = subinterpreter().run(
            """
            out["sum"] = sum(range(1000))
            core = sys.modules.get("tethered._core")
            out["bootstrapped"] = core is not None
            out["locked"] = core._config.locked
            out["payload"] = core._config._serialized_payload
            out["environment"] = os.environ.get("_TETHERED_CHILD_POLICY")
            from tethered._autoactivate import _in_subinterpreter
            out["in_subinterpreter"] = _in_subinterpreter()
            """
        )
        assert result["sum"] == 499500
        assert result["bootstrapped"] is True
        assert result["in_subinterpreter"] is True
        assert _in_subinterpreter() is False

        # The same policy, unlocked ...
        published = _core._config._serialized_payload
        assert result["locked"] is False
        assert json.loads(result["payload"])["global"] == {
            **json.loads(published)["global"],
            "locked": False,
        }
        # ... and not published: the process still hands children the locked one.
        assert result["environment"] == published
        assert os.environ[_CHILD_POLICY_ENV] == published
        assert _core._config.locked is True

    def test_it_gets_no_network(self, locked, listener, subinterpreter):
        """Loopback is allowed by the policy, but the guardian matches no policy."""
        port = listener.getsockname()[1]
        result = subinterpreter().run(
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

    def test_it_gets_no_process_launches(self, locked, subinterpreter, tmp_path):
        marker = tmp_path / "launched.txt"
        result = subinterpreter().run(
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

    def test_it_cannot_change_the_policy_variable(self, locked, subinterpreter):
        """One variable serves the whole process: it is what child processes inherit."""
        result = subinterpreter().run(
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
        events = {
            "pop": "os.unsetenv",
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
        child = subprocess.run(  # nosec B603
            [sys.executable, "-c", f"import os; print(os.environ[{_CHILD_POLICY_ENV!r}])"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert child.returncode == 0, child.stderr
        assert child.stdout.strip() == published

    def test_it_cannot_change_the_bootstrap_files(self, scratch_site, locked, subinterpreter):
        result = subinterpreter().run(
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

    def test_everything_else_keeps_working(self, scratch_site, locked, subinterpreter):
        """Sockets that reach nobody, ordinary files, other variables, threads."""
        result = subinterpreter().run(
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

    def test_every_event_tethered_guards_is_refused(self, locked, subinterpreter):
        """The C event lists stay in step with the Python hook's, seen from outside."""
        events = {
            "connect": sorted(_core._CONNECT_EVENTS),
            "lookup": sorted(_core._DNS_EVENTS | {"socket.getaddrinfo"}),
            "launch": sorted(_core._SUBPROCESS_EVENTS | {"os.startfile/2"}),
            "fs": sorted(_core._PTH_FS_EVENTS),
            "env": sorted(_core._ENV_EVENTS),
        }
        result = subinterpreter().run(
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

    def test_which_filesystem_and_environment_events_are_refused(self, locked, subinterpreter):
        """Event by event: what counts as touching the bootstrap files or the variable."""
        result = subinterpreter().run(
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

    def test_other_events_pass(self, locked, subinterpreter):
        result = subinterpreter().run(
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

    def test_the_owning_interpreter_is_unaffected(self, locked, listener, subinterpreter, capfd):
        port = listener.getsockname()[1]
        _assert_refused(subinterpreter().run(CONNECT, port=port)["connect"], EGRESS_BLOCKED, "")

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

    def test_refusal_does_not_depend_on_the_exception_classes(self, locked, subinterpreter):
        """Whatever ``tethered._core`` is in that interpreter, the operation is refused."""
        result = subinterpreter().run(
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

    def test_unlocking_and_relocking(self, locked, listener, subinterpreter):
        """After ``deactivate(lock_token=...)`` the guardian restricts nobody."""
        port = listener.getsockname()[1]
        blocked = """
        attempt("elsewhere", sys.audit, "socket.connect", None, ("203.0.113.9", 443))
        out["bootstrapped"] = "tethered._core" in sys.modules
        """
        interp = subinterpreter()
        result = interp.run(CONNECT, blocked, port=port)
        _assert_refused(result["connect"], EGRESS_BLOCKED, NO_NETWORK)
        _assert_refused(result["elsewhere"], EGRESS_BLOCKED, NO_NETWORK)

        tethered.deactivate(lock_token=locked)
        # The interpreter created under the lock keeps the policy it inherited,
        # enforced by its own Python hook: loopback yes, elsewhere no.
        result = interp.run(CONNECT, blocked, port=port)
        assert result["connect"] == "ok"
        assert _connection_arrived(listener)
        assert result["elsewhere"]["type"] == EGRESS_BLOCKED
        assert result["elsewhere"]["message"] == (
            "Blocked by tethered: 203.0.113.9:443 is not in the allow list"
        )
        # One created now inherits nothing: deactivate() removed the variable.
        result = subinterpreter().run(CONNECT, blocked, port=port)
        assert result == {"connect": "ok", "elsewhere": "ok", "bootstrapped": False}
        assert _connection_arrived(listener)

        _lock()
        result = interp.run(CONNECT, blocked, port=port)
        _assert_refused(result["connect"], EGRESS_BLOCKED, NO_NETWORK)
        _assert_refused(result["elsewhere"], EGRESS_BLOCKED, NO_NETWORK)
        assert not _connection_arrived(listener)

    def test_inherited_scopes_are_kept(self, locked, subinterpreter, monkeypatch):
        """A payload with scopes (a launch-site payload) is inherited whole."""
        payload = json.loads(os.environ[_CHILD_POLICY_ENV])
        payload["scopes"] = [{"allow": ["scoped.test"], "label": "inherited"}]
        # Written in this, the owning interpreter; the canonical global is kept.
        monkeypatch.setenv(_CHILD_POLICY_ENV, json.dumps(payload))
        result = subinterpreter().run(
            """
            import tethered._core as core
            out["scopes"] = core._active_scope_count
            out["locked"] = core._config.locked
            """
        )
        # (The scope stack itself is context-local, and from Python 3.13 each
        # run in an interpreter starts with a fresh context.)
        assert result == {"scopes": 1, "locked": False}


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
    policy, so the guardian refuses none to the others either.  What is not
    an egress decision stays refused there: ``log_only`` does not soften
    process launches, the bootstrap files or the policy variable for the
    owner.
    """

    @pytest.fixture
    def log_only_lock(self) -> object:
        return _lock(log_only=True)

    def test_socket_events_pass(self, log_only_lock, listener, subinterpreter):
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
        # Its own copy of the policy is log-only too, and does the reporting.
        assert result.pop("config") == [False, True]
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
        self, scratch_site, log_only_lock, subinterpreter
    ):
        events = {
            "launch": sorted(_core._SUBPROCESS_EVENTS | {"os.startfile/2"}),
            "fs": sorted(_core._PTH_FS_EVENTS),
            "env": sorted(_core._ENV_EVENTS),
        }
        result = subinterpreter().run(
            """
            import pathlib

            pth = pathlib.Path(site_packages) / "tethered.pth"
            attempt("system", os.system, "exit 0")
            attempt("remove", os.remove, pth)
            attempt("write", pth.write_text, "gone")
            attempt("pop", os.environ.pop, "_TETHERED_CHILD_POLICY")
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
            "pop": NO_VARIABLE_CHANGES,
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
        """What other interpreters may do follows the policy that is locked now."""
        port = listener.getsockname()[1]
        token = _lock(log_only=True)
        interp = subinterpreter()

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

    @pytest.mark.parametrize("shared_gil", [False, True], ids=["default", "shared-gil"])
    def test_names_are_still_mapped_to_addresses(self, shared_gil, listener, subinterpreter):
        """Otherwise its log-only policy would report every connection made by hostname.

        Loopback is allowed here only by name.  An interpreter that shares the
        GIL resolves through the guardian, which serves a caller that does not
        hold the lock from that interpreter's own resolver.
        """
        _lock(allow=["localhost"], allow_localhost=False, log_only=True)
        port = listener.getsockname()[1]
        result = subinterpreter(shared_gil=shared_gil).run(
            COLLECT_WARNINGS,
            """
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
            out["warnings"] = warnings

            guardian = core._c_guardian
            out["through the guardian"] = guardian is not None and guardian.is_active()
            if out["through the guardian"]:
                found = guardian.resolve("localhost", port, socket.AF_INET, 0, 0, 0)
                out["resolve"] = sorted({entry[4][0] for entry in found})
                # (an address family that does not exist: fails without any lookup)
                attempt("resolve failure", guardian.resolve, "127.0.0.1", port, 12345, 0, 0, 0)
            """,
            port=port,
        )
        assert result["by name"] == "ok"
        assert _connection_arrived(listener)
        assert result["names"] == ["localhost"]
        assert result["by name warnings"] == []
        assert result["elsewhere"] == "ok"
        assert result["warnings"] == ["tethered: blocked connect to 203.0.113.9:443"]
        assert result["through the guardian"] is (shared_gil or not OWN_GIL)
        if result["through the guardian"]:
            assert result["resolve"] == ["127.0.0.1"]
            # A failed lookup is the resolver's own error, not a refusal.
            assert result["resolve failure"]["type"] == "socket.gaierror"

    def test_the_owner_is_still_refused_everything_once_tampered_with(
        self, log_only_lock, listener, subinterpreter, monkeypatch, capfd
    ):
        """A failed integrity check refuses the owner whatever ``log_only`` says."""
        port = listener.getsockname()[1]
        sys.audit("socket.connect", None, ELSEWHERE_ADDRESS)  # reported, not refused
        with monkeypatch.context() as patch:
            patch.setattr(_core, "_handle_connect", lambda *args: None)
            with pytest.raises(tethered.EgressBlocked):
                sys.audit("socket.connect", None, ("127.0.0.1", port))
            with pytest.raises(tethered.SubprocessBlocked, match="integrity"):
                sys.audit("os.system", "prog")
            # Nothing is verified on behalf of another interpreter: what it
            # may do was settled when the lock was taken.
            assert subinterpreter().run(CONNECT, port=port)["connect"] == "ok"
        assert "TAMPER DETECTED" in capfd.readouterr().err
        sys.audit("socket.connect", None, ELSEWHERE_ADDRESS)

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
    def test_a_pool_computes_under_a_locked_policy(self, locked):
        """Every worker is a new interpreter; ``BrokenInterpreterPool`` before."""
        from concurrent.futures import InterpreterPoolExecutor

        with InterpreterPoolExecutor(max_workers=2) as pool:
            assert list(pool.map(pow, [2, 3, 4], [5, 5, 5])) == [32, 243, 1024]
            assert pool.submit(sum, range(1000)).result(timeout=120) == 499500
            lookup = pool.submit(socket.getaddrinfo, "localhost", 80)
            with pytest.raises(Exception, match="gets no network access") as excinfo:
                lookup.result(timeout=120)
            assert ELSEWHERE in str(excinfo.value)
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
    """Interpreters that can load the C extension see one guardian, owned by one of them."""

    def test_the_guardians_functions_refuse_a_caller_from_another_interpreter(
        self, locked, subinterpreter, capfd
    ):
        result = subinterpreter(shared_gil=True).run(
            """
            import tethered
            import tethered._core as core

            guardian = core._c_guardian
            out["config locked"] = core._config.locked
            out["is_active"] = guardian.is_active()
            out["check_token"] = guardian.check_token(object())
            out["check_token None"] = guardian.check_token(None)
            out["verify"] = guardian.verify()
            attempt("guardian.activate", guardian.activate, {}, None, object(), [])
            attempt("guardian.deactivate", guardian.deactivate, object())
            attempt("guardian.resolve", guardian.resolve, "localhost", 80, 0, 0, 0, 0)
            attempt("tethered.activate", tethered.activate, allow=[])
            attempt("tethered.deactivate", tethered.deactivate)
            attempt("connect", sys.audit, "socket.connect", None, ("203.0.113.9", 443))
            attempt("getaddrinfo", sys.audit, "socket.getaddrinfo", "host.test", 80, 0, 0, 0)
            out["still active"] = guardian.is_active()
            """
        )
        assert result["config locked"] is False
        assert result["is_active"] is True
        assert result["check_token"] is False
        assert result["check_token None"] is False
        assert result["verify"] is False
        _assert_refused(result["guardian.activate"], RUNTIME_ERROR, "replaced from there")
        assert ELSEWHERE in result["guardian.activate"]["message"]
        _assert_refused(result["guardian.deactivate"], RUNTIME_ERROR, "deactivated from there")
        assert ELSEWHERE in result["guardian.deactivate"]["message"]
        _assert_refused(result["guardian.resolve"], EGRESS_BLOCKED, NO_NETWORK)
        assert result["guardian.resolve"]["host"] == "localhost"
        assert result["tethered.activate"]["type"] == TETHERED_LOCKED
        assert result["tethered.deactivate"]["type"] == TETHERED_LOCKED
        _assert_refused(result["connect"], EGRESS_BLOCKED, NO_NETWORK)
        _assert_refused(result["getaddrinfo"], EGRESS_BLOCKED, NO_NETWORK)
        assert result["still active"] is True

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


@pytest.mark.skipif(not OWN_GIL, reason="before Python 3.12 every interpreter shares one GIL")
class TestConcurrency:
    def test_events_from_an_interpreter_with_its_own_gil_while_the_lock_changes_hands(
        self, subinterpreter
    ):
        """The other interpreter's hook calls overlap this one's activations.

        They read two atomics and none of the guardian's objects, so every
        event is either refused or passed — and nothing breaks.
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
