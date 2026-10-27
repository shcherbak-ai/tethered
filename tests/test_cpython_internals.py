"""What tethered relies on that CPython and the standard library do not promise.

Each test asserts one such assumption directly, against the interpreter that
runs it, so that a change in CPython that breaks it fails here with a message
naming the mechanism, and not somewhere in the behaviour built on top of it.
The rows of the inventory in ``docs/ARCHITECTURE.md`` ("What tethered relies
on") name these tests; where another test already pins an assumption
precisely, the row names that test instead.

The CI job on the pre-releases of the next CPython (``next-python.yml``) is
where these are meant to fail first.  Nothing here touches the network: a
test that watches a call stops it at its audit event, before it does
anything, or calls something that stays on loopback.
"""

from __future__ import annotations

import contextlib
import contextvars
import json
import multiprocessing
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

import tethered._core as _core
from tethered._autoactivate import _in_subinterpreter
from tethered._core import _CHILD_POLICY_ENV

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from types import FrameType

try:
    import _interpreters as _interps  # Python 3.13+
except ImportError:
    try:
        import _xxsubinterpreters as _interps  # Python 3.11 - 3.12
    except ImportError:
        _interps = None


def _row(name: str) -> str:
    """The inventory row an assertion stands for, for its failure message."""
    return f' (docs/ARCHITECTURE.md, "What tethered relies on": {name})'


# ── Watching audit events ──────────────────────────────────────────────


class _Stop(Exception):
    """Raised by a test's handler at an audit event, to stop the call there."""


# The handler of the test that is watching, in its own context.  The hook is
# added once per process and does nothing for anyone else.
_watching: contextvars.ContextVar[Callable[[str, tuple, FrameType], None] | None] = (
    contextvars.ContextVar("cpython_internals_watching", default=None)
)
_hook_added = False


def _hook(event: str, args: tuple) -> None:
    handler = _watching.get()
    if handler is None:
        return
    # Not for the events the handler raises itself (sys._getframe is one).
    token = _watching.set(None)
    try:
        # Frame 1 is the frame that made the call raising the event: a
        # Python audit hook is called with no Python frame in between.
        handler(event, args, sys._getframe(1))
    finally:
        _watching.reset(token)


@contextlib.contextmanager
def _audit(handler: Callable[[str, tuple, FrameType], None]) -> Iterator[None]:
    """Call ``handler(event, args, frame)`` for every audit event raised in this context."""
    global _hook_added
    if not _hook_added:
        sys.addaudithook(_hook)
        _hook_added = True
    token = _watching.set(handler)
    try:
        yield
    finally:
        _watching.reset(token)


def _stop_at(*names: str) -> tuple[list[tuple[str, tuple]], Callable[..., None]]:
    """Return ``(seen, handler)``: the handler records the first of ``names`` and stops the call."""
    seen: list[tuple[str, tuple]] = []

    def handler(event: str, args: tuple, frame: FrameType) -> None:
        if event in names:
            seen.append((event, args))
            raise _Stop(event)

    return seen, handler


def _stopped(names: tuple[str, ...], call: Callable[[], object]) -> list[tuple[str, tuple]]:
    """Make ``call`` and return the events of ``names`` it raised before it was stopped."""
    seen, handler = _stop_at(*names)
    with _audit(handler), pytest.raises(_Stop):
        call()
    return seen


def _frames_from(frame: FrameType | None) -> list[tuple[str, str | None]]:
    """``(function, module)`` of ``frame`` and its callers, as far as tethered looks."""
    found = []
    while frame is not None and len(found) < _core._FRAME_WALK_DEPTH_CAP:
        found.append((frame.f_code.co_name, frame.f_globals.get("__name__")))
        frame = frame.f_back
    return found


# ── Audit events ───────────────────────────────────────────────────────


class TestSocketEvents:
    """The socket events and the order of their arguments, as ``_audit_hook`` reads them."""

    ROW = _row("the socket events")

    def test_getaddrinfo_names_host_port_family_type_and_protocol(self):
        seen = _stopped(
            ("socket.getaddrinfo",),
            lambda: socket.getaddrinfo(
                "127.0.0.1",
                8080,
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                socket.AI_NUMERICHOST,
            ),
        )
        expected = ("127.0.0.1", 8080, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        assert seen == [("socket.getaddrinfo", expected)], (
            "_handle_getaddrinfo reads (host, port, family, type, proto) from the event, "
            "and the caller's flags are not part of it" + self.ROW
        )

    @pytest.mark.parametrize("call", ["connect", "connect_ex"])
    def test_a_connection_names_the_socket_and_the_address(self, call):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            seen = _stopped(("socket.connect",), lambda: getattr(sock, call)(("127.0.0.1", 9)))
        assert seen == [("socket.connect", (sock, ("127.0.0.1", 9)))], (
            f"socket.{call}() raises socket.connect with (socket, address)" + self.ROW
        )

    def test_a_datagram_names_the_socket_and_the_address(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            seen = _stopped(("socket.sendto",), lambda: sock.sendto(b"x", ("127.0.0.1", 9)))
        assert seen == [("socket.sendto", (sock, ("127.0.0.1", 9)))], (
            "socket.sendto() raises socket.sendto with (socket, address)" + self.ROW
        )

    @pytest.mark.parametrize(
        ("call", "event"),
        [
            (socket.gethostbyname, "socket.gethostbyname"),
            (socket.gethostbyname_ex, "socket.gethostbyname"),
            (socket.gethostbyaddr, "socket.gethostbyaddr"),
        ],
        ids=["gethostbyname", "gethostbyname_ex", "gethostbyaddr"],
    )
    def test_the_other_lookups_name_the_host(self, call, event):
        seen = _stopped((event,), lambda: call("127.0.0.1"))
        assert seen == [(event, ("127.0.0.1",))], (
            f"{call.__name__}() raises {event} with (host,)" + self.ROW
        )

    def test_a_new_socket_raises_socket_new(self):
        seen, handler = _stop_at("socket.__new__")
        with _audit(handler), pytest.raises(_Stop):
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        assert [event for event, _args in seen] == ["socket.__new__"], (
            "the one-time event-loop warnings are given at socket.__new__" + self.ROW
        )


class TestLaunchEvents:
    """The launch events: where they are raised from, and what they carry."""

    ROW = _row("the launch events")

    def test_popen_is_raised_in_execute_child_which_reads_env_afterwards(self):
        """``subprocess.Popen`` comes from ``_execute_child``, whose ``env`` the hook rewrites."""
        found: dict[str, Any] = {}

        def handler(event: str, args: tuple, frame: FrameType) -> None:
            if event == "subprocess.Popen" and not found:
                found["args"] = args
                found["where"] = (frame.f_code.co_name, frame.f_globals.get("__name__"))
                found["locals"] = frame.f_code.co_varnames
                child_env = {**os.environ, "TETHERED_CANARY": "reached the child"}
                found["written"] = _core._inject_scope_env(frame, child_env)

        script = "import os; print(os.environ.get('TETHERED_CANARY'))"
        with _audit(handler):
            result = subprocess.run(  # nosec B603
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                timeout=60,
                check=True,
            )
        row = _row("the env of _execute_child")
        assert found["where"] == ("_execute_child", "subprocess"), (
            "the subprocess.Popen event is raised by subprocess.Popen._execute_child" + row
        )
        assert "env" in found["locals"], "_execute_child keeps the environment in `env`" + row
        assert len(found["args"]) == 4 and found["args"][3] is None, (
            "subprocess.Popen carries (executable, args, cwd, env)" + self.ROW
        )
        assert found["written"] is True
        assert result.stdout.strip() == "reached the child", (
            "a write to the env local at the event reaches the child "
            "(PEP 667 from 3.13, PyFrame_LocalsToFast before)" + row
        )

    @staticmethod
    def _nested_launches() -> list[Any]:
        """The event ``subprocess`` raises after its own, by platform and version."""
        cases = []
        if sys.platform == "win32":
            cases.append(pytest.param("_winapi.CreateProcess", {}, id="CreateProcess"))
        else:
            if sys.version_info >= (3, 14):
                # A new session rules posix_spawn out: this is the fork_exec route.
                cases.append(
                    pytest.param(
                        "_posixsubprocess.fork_exec", {"start_new_session": True}, id="fork_exec"
                    )
                )
            if getattr(subprocess, "_USE_POSIX_SPAWN", False):
                cases.append(pytest.param("os.posix_spawn", {"close_fds": False}, id="posix_spawn"))
        return cases

    @pytest.mark.parametrize(("event", "kwargs"), _nested_launches())
    def test_the_nested_launch_event_comes_from_inside_execute_child(self, event, kwargs):
        """``_handle_subprocess`` skips it there: the launch was handled at ``subprocess.Popen``."""
        found: list[tuple[tuple, list]] = []

        def handler(name: str, args: tuple, frame: FrameType) -> None:
            if name == event:
                found.append((args, _frames_from(frame)))
                raise _Stop(name)

        with _audit(handler), pytest.raises(_Stop):
            subprocess.run([sys.executable, "-c", "pass"], **kwargs)  # nosec B603
        ((args, frames),) = found
        # tethered's own frames take three of the frames it looks through.
        assert ("_execute_child", "subprocess") in frames[: _core._FRAME_WALK_DEPTH_CAP - 3], (
            f"{event} is raised with subprocess's _execute_child on the stack: {frames}" + self.ROW
        )
        assert len(args) == 3, f"{event} carries three arguments: {args!r}" + self.ROW

    @pytest.mark.skipif(
        sys.platform == "win32" or sys.version_info < (3, 14),
        reason="_posixsubprocess.fork_exec is audited on POSIX from Python 3.14",
    )
    def test_fork_exec_carries_executables_argv_and_environment_entries(self):
        argv = [sys.executable, "-c", "pass"]
        seen = _stopped(
            ("_posixsubprocess.fork_exec",),
            lambda: subprocess.run(  # nosec B603
                argv, env={"TETHERED_CANARY": "1"}, start_new_session=True
            ),
        )
        ((_event, (executables, args, env)),) = seen
        assert executables and all(isinstance(path, bytes) for path in executables), (
            "_resolve_fork_exec_launch takes the first of the executables (bytes)" + self.ROW
        )
        assert list(args) == argv, "the second argument is the argv" + self.ROW
        assert list(env) == [b"TETHERED_CANARY=1"], (
            "the environment arrives as b'NAME=value' entries (_snapshot_env)" + self.ROW
        )

    def test_exec_carries_path_argv_and_environment(self):
        """``os.exec*`` raises ``os.exec`` with ``(path, args, env)``; checked in a child."""
        script = (
            "import json, os, sys\n"
            "seen = []\n"
            "class Stop(Exception):\n"
            "    pass\n"
            "def hook(event, args):\n"
            "    if event == 'os.exec':\n"
            "        seen.append([args[0], list(args[1]), args[2]])\n"
            "        raise Stop\n"
            "sys.addaudithook(hook)\n"
            "argv = [sys.executable, '-c', 'print(1)']\n"
            "for call in (lambda: os.execv(sys.executable, argv),\n"
            "             lambda: os.execve(sys.executable, argv, {'A': '1'})):\n"
            "    try:\n"
            "        call()\n"
            "    except Stop:\n"
            "        pass\n"
            "print(json.dumps(seen))\n"
        )
        result = subprocess.run(  # nosec B603
            [sys.executable, "-c", script], capture_output=True, text=True, timeout=60, check=True
        )
        argv = [sys.executable, "-c", "print(1)"]
        assert json.loads(result.stdout) == [
            [sys.executable, argv, None],
            [sys.executable, argv, {"A": "1"}],
        ], "os.exec carries (path, args, env), env None for os.execv" + self.ROW

    @pytest.mark.skipif(not hasattr(os, "posix_spawn"), reason="no os.posix_spawn here")
    def test_posix_spawn_carries_path_argv_and_environment(self):
        argv = [sys.executable, "-c", "pass"]
        env = {"TETHERED_CANARY": "1"}
        seen = _stopped(("os.posix_spawn",), lambda: os.posix_spawn(sys.executable, argv, env))
        assert seen == [("os.posix_spawn", (sys.executable, argv, env))], (
            "os.posix_spawn carries (path, argv, env)" + self.ROW
        )

    @pytest.mark.skipif(sys.platform != "win32", reason="os.spawn* raises os.spawn on Windows only")
    def test_spawn_carries_mode_path_argv_and_environment(self):
        argv = [sys.executable, "-c", "pass"]
        env = {**os.environ, "TETHERED_CANARY": "1"}
        seen = _stopped(("os.spawn",), lambda: os.spawnve(os.P_NOWAIT, sys.executable, argv, env))
        assert seen == [("os.spawn", (os.P_NOWAIT, sys.executable, argv, env))], (
            "os.spawn carries (mode, path, args, env)" + self.ROW
        )


class TestFileAndEnvironmentEvents:
    """Where the locked-mode guards find the paths and names they look at."""

    ROW = _row("the file and environment events")

    @pytest.fixture
    def files(self, tmp_path: Path) -> tuple[str, str]:
        source = tmp_path / "source.txt"
        source.write_text("x")
        return str(source), str(tmp_path / "destination.txt")

    @staticmethod
    def _cases() -> list[Any]:
        windows = sys.platform == "win32"
        cases = [
            pytest.param("os.remove", lambda s, d: os.remove(s), lambda s, d: (s, -1), id="remove"),
            pytest.param("os.remove", lambda s, d: os.unlink(s), lambda s, d: (s, -1), id="unlink"),
            pytest.param(
                "os.rename", lambda s, d: os.rename(s, d), lambda s, d: (s, d, -1, -1), id="rename"
            ),
            pytest.param(
                "os.rename",
                lambda s, d: os.replace(s, d),
                lambda s, d: (s, d, -1, -1),
                id="replace",
            ),
            pytest.param(
                "os.symlink", lambda s, d: os.symlink(s, d), lambda s, d: (s, d, -1), id="symlink"
            ),
            pytest.param(
                "os.chmod", lambda s, d: os.chmod(s, 0o644), lambda s, d: (s, 0o644, -1), id="chmod"
            ),
            pytest.param(
                "os.truncate", lambda s, d: os.truncate(s, 0), lambda s, d: (s, 0), id="truncate"
            ),
        ]
        if hasattr(os, "link"):
            cases.append(
                pytest.param(
                    "os.link", lambda s, d: os.link(s, d), lambda s, d: (s, d, -1, -1), id="link"
                )
            )
        if windows and sys.version_info >= (3, 12):
            cases.append(
                pytest.param(
                    "_winapi.CopyFile2",
                    lambda s, d: shutil.copy2(s, d),
                    lambda s, d: (s, d),
                    id="copy2",
                )
            )
        return cases

    @pytest.mark.parametrize(("event", "call", "expected"), _cases())
    def test_the_paths_are_where_the_guard_reads_them(self, files, event, call, expected):
        source, destination = files
        seen = _stopped((event, "open"), lambda: call(source, destination))
        ((name, args),) = seen
        assert name == event, f"the first audited step is {event}, not {name}" + self.ROW
        want = expected(source, destination)
        assert args[: len(want)] == want, f"{event} carries {want!r} first: {args!r}" + self.ROW

    @pytest.mark.skipif(os.unlink not in os.supports_dir_fd, reason="no dir_fd for os.unlink here")
    def test_a_removal_relative_to_a_directory_carries_its_descriptor(self, files):
        """``shutil.rmtree`` removes files this way on POSIX."""
        source, _destination = files
        fd = os.open(os.path.dirname(source), os.O_RDONLY)
        try:
            name = os.path.basename(source)
            seen = _stopped(("os.remove",), lambda: os.unlink(name, dir_fd=fd))
        finally:
            os.close(fd)
        assert seen == [("os.remove", (name, fd))], (
            "os.unlink(dir_fd=...) raises os.remove with (path, dir_fd)" + self.ROW
        )

    @pytest.mark.parametrize(
        ("call", "has_mode"),
        [
            (lambda path: open(path, "w"), True),  # noqa: SIM115
            (lambda path: os.open(path, os.O_WRONLY | os.O_CREAT), False),
        ],
        ids=["open", "os.open"],
    )
    def test_open_carries_path_mode_and_flags(self, files, call, has_mode):
        _source, destination = files
        ((_event, args),) = _stopped(("open",), lambda: call(destination))
        assert args[0] == destination and isinstance(args[2], int), (
            f"open carries (path, mode, flags): {args!r}" + self.ROW
        )
        if has_mode:
            assert isinstance(args[1], str) and "w" in args[1], (
                f"open() reports its mode: {args!r}" + self.ROW
            )
        else:
            assert args[1] is None, f"os.open() reports no mode: {args!r}" + self.ROW
        assert args[2] & (os.O_WRONLY | os.O_RDWR), "the flags say it writes" + self.ROW

    @staticmethod
    def _native(name: str) -> str | bytes:
        """A variable name the way ``os.putenv`` and ``os.unsetenv`` report it."""
        return name if sys.platform == "win32" else os.fsencode(name)

    def test_putenv_and_unsetenv_carry_the_name(self):
        name = "TETHERED_CANARY_VARIABLE"
        native = self._native(name)
        assert _stopped(("os.putenv",), lambda: os.putenv(name, "1")) == [
            ("os.putenv", (native, self._native("1")))
        ], "os.putenv carries (name, value), bytes on POSIX and str on Windows" + self.ROW
        assert _stopped(("os.unsetenv",), lambda: os.unsetenv(name)) == [
            ("os.unsetenv", (native,))
        ], "os.unsetenv carries (name,)" + self.ROW

    def test_os_environ_raises_them_before_it_changes(self, monkeypatch):
        """``_handle_env_change`` sees every change made through ``os.environ`` as well."""
        name = "TETHERED_CANARY_VARIABLE"
        monkeypatch.delenv(name, raising=False)

        def assign() -> None:
            os.environ[name] = "1"

        assert [e for e, _ in _stopped(("os.putenv",), assign)] == ["os.putenv"], (
            "an assignment to os.environ raises os.putenv" + self.ROW
        )
        assert name not in os.environ, "os.environ changes only after the event" + self.ROW
        monkeypatch.setenv(name, "1")
        assert [e for e, _ in _stopped(("os.unsetenv",), lambda: os.environ.pop(name))] == [
            "os.unsetenv"
        ], "a deletion from os.environ raises os.unsetenv" + self.ROW
        assert os.environ.get(name) == "1"


# ── Frames, code objects and private names ─────────────────────────────


@pytest.mark.skipif(sys.platform != "win32", reason="multiprocessing's Windows spawner")
class TestWindowsSpawner:
    """``multiprocessing.popen_spawn_win32``: the environment of a worker, inside a venv."""

    ROW = _row("multiprocessing's Windows spawner")

    def test_the_environment_is_a_local_named_env_passed_to_create_process(self):
        import multiprocessing.popen_spawn_win32 as spawner

        code = spawner.Popen.__init__.__code__
        assert "env" in code.co_varnames, "_resolve_winapi_launch reads the env local" + self.ROW
        assert "CreateProcess" in code.co_names, (
            "the spawner calls _winapi.CreateProcess" + self.ROW
        )
        assert "_base_executable" in code.co_names and "__PYVENV_LAUNCHER__" in code.co_consts, (
            "inside a venv it launches sys._base_executable with __PYVENV_LAUNCHER__ "
            "(bpo-35797)" + self.ROW
        )
        assert isinstance(sys._base_executable, str), "sys._base_executable exists" + self.ROW

    def test_create_process_reads_the_mapping_after_its_event(self, tmp_path):
        """What lets the hook complete the spawner's private environment in place."""
        import _winapi

        out = tmp_path / "seen.txt"
        script = f"import os; open({str(out)!r}, 'w').write(os.environ.get('TETHERED_CANARY', ''))"
        env = dict(os.environ)

        def handler(event: str, args: tuple, frame: FrameType) -> None:
            if event == "_winapi.CreateProcess":
                env["TETHERED_CANARY"] = "completed in place"

        command_line = subprocess.list2cmdline([sys.executable, "-c", script])
        with _audit(handler):
            process, thread, _pid, _tid = _winapi.CreateProcess(
                sys.executable, command_line, None, None, False, 0, env, None, None
            )
        try:
            _winapi.WaitForSingleObject(process, 60_000)
        finally:
            _winapi.CloseHandle(thread)
            _winapi.CloseHandle(process)
        assert out.read_text() == "completed in place", (
            "_winapi.CreateProcess reads its environment after the audit event" + self.ROW
        )


class TestSocketpairFallback:
    """How ``_is_own_socketpair_connect`` recognises ``socket.socketpair()``'s own connection."""

    ROW = _row("socketpair()'s own connection")

    @staticmethod
    def _fallback() -> Callable[..., tuple[socket.socket, socket.socket]]:
        found = getattr(socket, "_fallback_socketpair", None)
        if found is not None:
            return found
        if sys.platform == "win32":
            return socket.socketpair  # up to 3.11.9 the fallback had no name of its own
        pytest.skip("this CPython keeps no fallback socketpair() on this platform")

    def test_the_fallback_is_the_code_tethered_took_at_import(self):
        fallback = self._fallback()
        assert fallback.__code__ is _core._SOCKETPAIR_FALLBACK_CODE, self.ROW
        assert "lsock" in fallback.__code__.co_varnames, (
            "the fallback's listening socket is the local `lsock`" + self.ROW
        )
        assert {socket._LOCALHOST, socket._LOCALHOST_V6} == _core._SOCKETPAIR_HOSTS, (
            "the fallback listens on 127.0.0.1 or ::1" + self.ROW
        )
        if sys.platform == "win32":
            assert socket.socketpair is fallback, (
                "on Windows socket.socketpair(), which asyncio's event loops call, "
                "is the fallback" + self.ROW
            )

    def test_it_connects_from_its_own_frame_to_its_own_listener(self):
        fallback = self._fallback()
        seen: list[tuple[bool, Any, Any]] = []

        def handler(event: str, args: tuple, frame: FrameType) -> None:
            if event == "socket.connect":
                listener = frame.f_locals.get("lsock")
                bound = listener.getsockname()[:2] if listener is not None else None
                seen.append((frame.f_code is fallback.__code__, args[1], bound))

        with _audit(handler):
            first, second = fallback()
        first.close()
        second.close()
        ((own_frame, target, bound),) = seen
        assert own_frame, "connect() is called directly from the fallback's frame" + self.ROW
        assert tuple(target[:2]) == tuple(bound), (
            "the connection goes to the frame's own listener" + self.ROW
        )


@pytest.mark.skipif(not hasattr(os, "register_at_fork"), reason="no fork here")
def test_lock_types_can_be_reset_after_a_fork():
    """``_reinit_locks_after_fork`` resets tethered's locks with their private methods."""
    row = _row("locks after fork")
    lock = threading.Lock()
    lock.acquire()
    lock._at_fork_reinit()
    assert lock.acquire(blocking=False), "Lock._at_fork_reinit() leaves it unlocked" + row
    rlock = threading.RLock()
    rlock.acquire()
    assert rlock._is_owned(), "RLock._is_owned() says the calling thread holds it" + row
    rlock._at_fork_reinit()
    assert not rlock._is_owned(), "RLock._at_fork_reinit() leaves it unowned" + row
    assert rlock.acquire(blocking=False)
    rlock.release()


@pytest.mark.skipif(
    "forkserver" not in multiprocessing.get_all_start_methods(), reason="no fork server here"
)
def test_the_fork_server_keeps_its_pid_where_tethered_reads_it():
    """``_warn_if_fork_server_runs`` reads a private attribute of ``multiprocessing.forkserver``."""
    script = (
        "import multiprocessing.forkserver as fs\n"
        "print(fs._forkserver._forkserver_pid)\n"
        "fs.ensure_running()\n"
        "print(type(fs._forkserver._forkserver_pid).__name__)\n"
    )
    result = subprocess.run(  # nosec B603
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60, check=True
    )
    assert result.stdout.split() == ["None", "int"], (
        "None until the fork server runs, its pid then" + _row("the fork server's process")
    )


def test_the_platform_module_keeps_what_it_learns_about_the_machine():
    """``_warm_platform_cache`` asks ``platform.platform()`` once, before a "block" policy."""
    row = _row("the platform module's answer")
    script = (
        "import json, platform, sys\n"
        "launched = []\n"
        "sys.addaudithook(lambda event, args: event == 'subprocess.Popen' and launched.append(1))\n"
        "platform.platform()\n"
        "first = len(launched)\n"
        "platform.platform(), platform.processor(), tuple(platform.uname())\n"
        "platform.system(), platform.machine(), platform.node(), platform.release()\n"
        "print(json.dumps([first, len(launched) - first]))\n"
    )
    # -S: nothing of site-packages (tethered.pth, coverage) asks it first.
    result = subprocess.run(  # nosec B603
        [sys.executable, "-S", "-c", script], capture_output=True, text=True, timeout=60, check=True
    )
    first, later = json.loads(result.stdout)
    assert (first > 0) is _core._PLATFORM_RUNS_A_PROGRAM, (
        "the first call runs a program where _PLATFORM_RUNS_A_PROGRAM says so, and only there" + row
    )
    assert later == 0, "the calls that share its answer run nothing afterwards" + row


@pytest.mark.skipif(
    not _core._FIND_LIBRARY_RUNS_LDCONFIG, reason="find_library runs ldconfig on Linux only"
)
def test_find_library_reads_the_linker_cache_with_ldconfig_at_every_call():
    """``_is_ldconfig_lookup`` lets through the launch ``ctypes.util.find_library()`` makes."""
    row = _row("find_library's look-up")
    script = (
        "import ctypes.util, json, sys\n"
        "launched = []\n"
        "def watch(event, args):\n"
        "    if event == 'subprocess.Popen':\n"
        "        executable, argv, _cwd, env = args\n"
        "        launched.append([type(executable).__name__, executable, type(argv).__name__,\n"
        "                         argv, type(env).__name__, sorted(env.items())])\n"
        "sys.addaudithook(watch)\n"
        "ctypes.util.find_library('c')\n"
        "ctypes.util.find_library('c')\n"
        "print(json.dumps(launched))\n"
    )
    result = subprocess.run(  # nosec B603
        [sys.executable, "-S", "-c", script], capture_output=True, text=True, timeout=60, check=True
    )
    expected = [
        "str",
        _core._LDCONFIG_ARGV[0],
        "list",
        list(_core._LDCONFIG_ARGV),
        "dict",
        [list(pair) for pair in _core._LDCONFIG_ENV],
    ]
    assert json.loads(result.stdout) == [expected, expected], (
        "each call runs /sbin/ldconfig -p with LC_ALL=C and LANG=C only, and nothing else" + row
    )


@pytest.mark.skipif(_interps is None, reason="this Python has no subinterpreter module")
class TestInterpreters:
    """The private interpreter module, and interpreter IDs."""

    @staticmethod
    def _create() -> Any:
        if sys.version_info >= (3, 13):
            return _interps.create("isolated")
        return _interps.create(isolated=sys.version_info >= (3, 12))

    @staticmethod
    def _run(interp: Any, script: str) -> None:
        if hasattr(_interps, "exec"):
            failure = _interps.exec(interp, script)
            assert failure is None, getattr(failure, "formatted", failure)
        else:
            _interps.run_string(interp, script)

    def test_it_tells_the_main_interpreter_from_a_subinterpreter(self, tmp_path):
        row = _row("which interpreter this is")
        for found in (_interps.get_current(), _interps.get_main()):
            if sys.version_info >= (3, 13):
                assert isinstance(found, tuple), "from 3.13 an (id, whence) pair" + row
            int(found[0] if isinstance(found, tuple) else found)
        assert _in_subinterpreter() is False, row
        out = tmp_path / "in-sub.txt"
        interp = self._create()
        try:
            self._run(
                interp,
                "from tethered._autoactivate import _in_subinterpreter\n"
                f"open({str(out)!r}, 'w').write(str(_in_subinterpreter()))\n",
            )
        finally:
            _interps.destroy(interp)
        assert out.read_text() == "True", row

    def test_an_interpreter_id_is_never_given_out_twice(self):
        """The guardian knows the lock holder by its ID, also after it is gone."""
        first = self._create()
        first_id = int(first)
        _interps.destroy(first)
        second = self._create()
        try:
            assert int(second) > first_id, (
                "IDs are given out in ascending order and never twice"
                + _row("interpreter IDs and hooks")
            )
        finally:
            _interps.destroy(second)


# ── The command line of a child ────────────────────────────────────────


def test_every_option_the_interpreter_lists_is_one_tethered_parses():
    """``_interpreter_flags`` knows CPython's options; any other makes a launch external."""
    usage = subprocess.run(  # nosec B603
        [sys.executable, "-h"], capture_output=True, text=True, timeout=60, check=True
    ).stdout
    flags, value_options, long_flags, long_value_options = set(), set(), set(), set()
    for line in usage.splitlines():
        short = re.match(r"-([A-Za-z?])[A-Za-z]*(?: (\w+))?\s*:", line)
        if short:
            (value_options if short.group(2) else flags).add(short.group(1))
        long = re.match(r"(--[a-z][a-z-]*)( \S+)?\s*:", line)
        if long:
            (long_value_options if long.group(2) else long_flags).add(long.group(1))
    row = _row("the interpreter's options")
    assert flags and value_options and long_flags, f"could not read the usage:\n{usage}"
    assert flags <= _core._INTERPRETER_FLAGS, (
        f"unknown flags {flags - _core._INTERPRETER_FLAGS}" + row
    )
    assert value_options <= _core._INTERPRETER_VALUE_OPTIONS, (
        f"unknown options with a value {value_options - _core._INTERPRETER_VALUE_OPTIONS}" + row
    )
    assert long_flags <= _core._INTERPRETER_LONG_FLAGS, (
        f"unknown long options {long_flags - _core._INTERPRETER_LONG_FLAGS}" + row
    )
    assert long_value_options <= {_core._INTERPRETER_LONG_VALUE_OPTION}, (
        f"unknown long options with a value {long_value_options}" + row
    )


@pytest.mark.skipif(sys.platform != "win32", reason="the C runtime's joining is Windows-only")
def test_windows_spawn_joins_its_arguments_unquoted(tmp_path):
    """``_join_windows_argv``: the C runtime joins ``os.spawn*`` / ``os.exec*`` argv with spaces."""
    if " " in str(tmp_path) or " " in sys.executable:
        pytest.skip("a path with a space would be split as well")
    out = tmp_path / "argv.json"
    script = tmp_path / "argv.py"
    script.write_text(
        f"import json, sys\nopen({str(out)!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
    )
    os.spawnv(os.P_WAIT, sys.executable, [sys.executable, str(script), "a b"])
    assert json.loads(out.read_text()) == ["a", "b"], (
        "an argument with a space arrives as two" + _row("Windows command lines")
    )


# ── Interpreter startup: site.py ───────────────────────────────────────

# Each line runs only when its variable is set, so that every test of the
# environment below asks for what it looks at and nothing else.
_TRACE_PTH = (
    'import os, sys; "CANARY_TRACE" in os.environ and ('
    "sys.addaudithook(lambda event, args, write=os.write: event == 'import' "
    "and args[0] == 'sitecustomize' and write(1, b'import sitecustomize\\n')), "
    "os.write(1, b'pth line ran\\n'))\n"
)
_EXIT_PTH = (
    'import os, sys; "CANARY_PTH_EXIT" in os.environ and '
    "sys.exit('canary: a .pth line refuses to start')\n"
)
_RAISE_PTH = 'import os; "CANARY_PTH_RAISE" in os.environ and 1 / 0\n'
# PEP 829 (3.15+): what a tethered.start would rely on.  Ignored before 3.15.
_ENTRY_MODULE = (
    "import os\n\n\n"
    "def main():\n"
    "    if 'CANARY_TRACE' in os.environ:\n"
    "        os.write(1, b'entry point ran\\n')\n"
    "    if 'CANARY_START_EXIT' in os.environ:\n"
    "        raise SystemExit('canary: an entry point refuses to start')\n"
)


@pytest.fixture(scope="module")
def bare_environment(tmp_path_factory) -> Path:
    """The interpreter of a venv with the canary's own startup files and nothing of tethered's."""
    venv = tmp_path_factory.mktemp("startup") / "venv"
    subprocess.run(  # nosec B603
        [sys.executable, "-m", "venv", "--without-pip", str(venv)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    python = venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    # Where installers put a venv's packages.  (The last of site.getsitepackages()
    # is not that everywhere: Debian's Python lists a dist-packages directory
    # last, which a venv does not have.)
    asked = subprocess.run(  # nosec B603
        [str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    site_packages = Path(asked.stdout.strip())
    for name, text in {
        "canary_exit.pth": _EXIT_PTH,
        "canary_raise.pth": _RAISE_PTH,
        "canary_trace.pth": _TRACE_PTH,
        "canary_start.start": "canary_start_entry:main\n",
        "canary_start_entry.py": _ENTRY_MODULE,
    }.items():
        (site_packages / name).write_text(text, encoding="utf-8")
    return python


def _start(python: Path, code: str, **variables: str) -> subprocess.CompletedProcess[str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("CANARY_") and k not in ("PYTHONPATH", _CHILD_POLICY_ENV)
    }
    return subprocess.run(  # nosec B603
        [str(python), "-c", code],
        env={**env, **variables},
        capture_output=True,
        text=True,
        timeout=60,
    )


# What one interpreter prints while it starts, with CANARY_TRACE set.
_STARTUP_TRACE = (
    ["pth line ran", "entry point ran", "import sitecustomize"]
    if sys.version_info >= (3, 15)
    else ["pth line ran", "import sitecustomize"]
)


def _steps(output: str) -> list[str]:
    """The lines of ``output``, a line that repeats the one before it counted once.

    Up to Python 3.14 ``site.py`` reads the ``.pth`` files of a venv's
    site-packages twice (once for the venv, once more among the prefixes),
    so a ``.pth`` line runs twice there, and an audit hook it adds is added
    twice.  The bootstrap is written for that: the second
    ``__import__("tethered._autoactivate")`` finds the module imported and
    does nothing.
    """
    steps: list[str] = []
    for line in output.splitlines():
        if not steps or steps[-1] != line:
            steps.append(line)
    return steps


class TestSiteStartup:
    """The ``tethered.pth`` bootstrap, and the end of startup the guardian watches for."""

    def test_the_import_line_runs_and_sitecustomize_is_imported_after_it(self, bare_environment):
        result = _start(bare_environment, "print('main')", CANARY_TRACE="1")
        assert result.returncode == 0, result.stderr
        assert _steps(result.stdout) == [*_STARTUP_TRACE, "main"], (
            "site.py runs a .pth import line, then .start entry points (3.15+), then imports "
            "sitecustomize, which it does not have"
            + _row("the .pth import line")
            + _row("the end of site's work")
        )

    @pytest.mark.skipif(_interps is None, reason="this Python has no subinterpreter module")
    def test_a_subinterpreter_starts_the_same_way_before_its_creation_returns(
        self, bare_environment
    ):
        script = (
            "import os, sys\n"
            "try:\n"
            "    import _interpreters as interps\n"
            "except ImportError:\n"
            "    import _xxsubinterpreters as interps\n"
            "if sys.version_info >= (3, 13):\n"
            "    interp = interps.create('isolated')\n"
            "else:\n"
            "    interp = interps.create(isolated=sys.version_info >= (3, 12))\n"
            "os.write(1, b'created\\n')\n"
            "interps.destroy(interp)\n"
        )
        result = _start(bare_environment, script, CANARY_TRACE="1")
        assert result.returncode == 0, result.stderr
        assert _steps(result.stdout) == [*_STARTUP_TRACE, *_STARTUP_TRACE, "created"], (
            "a subinterpreter runs the .pth lines and imports sitecustomize before the call "
            "that creates it returns" + _row("the end of site's work")
        )

    def test_system_exit_from_an_import_line_stops_startup(self, bare_environment):
        """How a child that cannot establish a strict policy refuses to start (``_fail``)."""
        result = _start(bare_environment, "print('main')", CANARY_PTH_EXIT="1")
        assert result.returncode != 0 and "main" not in result.stdout, (
            "site.py lets SystemExit out of a .pth line" + _row("the .pth import line")
        )
        assert "canary: a .pth line refuses to start" in result.stderr

    def test_any_other_exception_from_an_import_line_is_swallowed(self, bare_environment):
        result = _start(bare_environment, "print('main')", CANARY_PTH_RAISE="1")
        assert result.returncode == 0 and result.stdout.splitlines() == ["main"], (
            "site.py reports any other exception and goes on" + _row("the .pth import line")
        )
        assert "ZeroDivisionError" in result.stderr

    @pytest.mark.skipif(sys.version_info < (3, 15), reason=".start files are read from 3.15")
    def test_system_exit_from_a_start_entry_point_stops_startup(self, bare_environment):
        """For the move to ``tethered.start`` (AGENTS.md, Python version support)."""
        result = _start(bare_environment, "print('main')", CANARY_START_EXIT="1")
        assert result.returncode != 0 and "main" not in result.stdout, (
            "site.py lets SystemExit out of a .start entry point" + _row("a .start file beside it")
        )
        assert "canary: an entry point refuses to start" in result.stderr
