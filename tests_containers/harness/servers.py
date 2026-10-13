"""The processes under test: servers (``start_server``) and one-shot scripts (``run_python``).

These are the processes that hold a tethered policy.  Each is started with a
clean environment in a session of its own, so that everything it leaves
behind can be found, and its output is kept for the report of a failing test.
``tests_containers/AGENTS.md`` documents the functions.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from harness.helpers import APPS_DIR, LOG_DIR, SUITE_DIR, Response, http_get, probe_path

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Iterable, Mapping

__all__ = ["Completed", "Server", "run_python", "start_server"]

#: Never handed to a process under test: the policy variable would activate tethered at
#: startup, and what pytest sets for itself (``PYTEST_*``) is nobody else's business.
_DROPPED_ENV = ("_TETHERED_CHILD_POLICY", "PYTHONPATH", "PYTHONSTARTUP")


def _process_env(extra: Mapping[str, str] | None) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in _DROPPED_ENV and not key.startswith("PYTEST_")
    }
    env["PYTHONPATH"] = os.pathsep.join([str(APPS_DIR), str(SUITE_DIR)])
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.update(extra or {})
    return env


def _session_pids(session: int) -> list[int]:
    """The live (not zombie) processes of one session, lowest pid first."""
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            stat = Path("/proc", entry, "stat").read_text()
        except OSError:
            continue
        # "pid (comm) state ppid pgrp session ...": comm may contain spaces and brackets.
        fields = stat.rpartition(")")[2].split()
        if len(fields) > 3 and fields[0] != "Z" and int(fields[3]) == session:
            found.append(int(entry))
    return sorted(found)


def _end_session(session: int, deadline: float) -> list[int]:
    """Wait until a session is empty; SIGKILL what is left at the deadline and return it."""
    while True:
        left = _session_pids(session)
        if not left:
            return []
        if time.monotonic() >= deadline:
            break
        time.sleep(0.05)
    for pid in left:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
    kill_deadline = time.monotonic() + 5.0
    while _session_pids(session) and time.monotonic() < kill_deadline:
        time.sleep(0.05)
    return left


def _free_port(start: int) -> int:
    for port in range(start, start + 500):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError(f"no free port from {start}")


class _Registry:
    """What the plugin needs to stop servers and to attach their logs to a failed test."""

    def __init__(self) -> None:
        self.live: list[Server] = []
        self.ended: list[Server] = []
        self.outputs: list[tuple[str, str]] = []
        self.fixture_requests: list[Any] = []
        self.item: Any = None
        self.next_port = 8000
        self.counter = 0

    def begin_test(self, item: Any) -> None:
        self.item = item
        self.ended.clear()
        self.outputs.clear()
        for server in self.live:
            server.mark_log()

    def register(self, server: Server) -> None:
        """Have ``server`` stopped when the fixture or the test that is starting it ends."""
        self.live.append(server)
        if self.fixture_requests:
            self.fixture_requests[-1].addfinalizer(server.stop)
            return
        try:
            self.item.addfinalizer(server.stop)
        except Exception:
            # Outside a test, or in a teardown: the plugin stops it when the session ends.
            return

    def sections(self) -> Iterable[tuple[str, str]]:
        for server in [*self.live, *self.ended]:
            yield f"server log: {server.name}", server.log_for_report()
        yield from self.outputs


registry = _Registry()


class Server:
    """A server under test, started by :func:`start_server`."""

    def __init__(
        self, argv: list[str], *, env: dict[str, str], cwd: str, port: int, name: str
    ) -> None:
        self.argv = argv
        self.name = name
        self.port = port
        #: The base URL, without a trailing slash.
        self.url = f"http://127.0.0.1:{port}"
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.log_path = LOG_DIR / f"{registry.counter:03d}-server.log"
        self.returncode: int | None = None
        self._mark = 0
        self._stopped = False
        with open(self.log_path, "wb") as log:
            self._proc = subprocess.Popen(
                argv,
                env=env,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        #: The process that was started: a server's master or supervisor, or its only process.
        self.pid = self._proc.pid

    def __repr__(self) -> str:
        return f"<Server {self.name} pid={self.pid} {self.url}>"

    @property
    def log(self) -> str:
        """Everything the server and its children have written to stdout and stderr so far."""
        try:
            return self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    @property
    def log_of_this_test(self) -> str:
        """The part of the log that was written since the current test began.

        The same as ``log`` for a server the test started itself; shorter for
        one that a module or class fixture keeps running across tests.
        """
        return self.log[self._mark :]

    def mark_log(self) -> None:
        self._mark = len(self.log)

    def log_for_report(self) -> str:
        if not self._mark:
            return self.log or "(empty)"
        left_out = f"[... {self._mark} characters from earlier tests left out ...]\n"
        return left_out + (self.log_of_this_test or "(nothing since)")

    @property
    def running(self) -> bool:
        """Whether the process that was started is still there."""
        return self._proc.poll() is None

    def pids(self) -> list[int]:
        """The live processes of the server: the one started, its workers, their children."""
        return _session_pids(self.pid)

    def send_signal(self, signum: int, pid: int | None = None) -> None:
        """Send a signal to the process that was started, or to ``pid``."""
        os.kill(self.pid if pid is None else pid, signum)

    def get(self, path: str, timeout: float = 30.0) -> Response:
        """GET a path of the server."""
        return http_get(self.url + path, timeout=timeout)

    def probe(
        self, op: str, host: str | None = None, port: int | None = None, **params: object
    ) -> dict[str, Any]:
        """Ask a probe application for one operation and return its JSON report.

        The answer must be HTTP 200: a probe application reports a refusal in
        the body, with ``"outcome": "blocked"``.
        """
        path = probe_path(op, host, port, **params)
        reply = self.get(path)
        if reply.status != 200:
            raise AssertionError(f"GET {path}: HTTP {reply.status}: {reply.text[:2000]}")
        return reply.json()

    def each_worker(
        self,
        path: str,
        count: int,
        *,
        exclude: Collection[int] = (),
        timeout: float = 60.0,
    ) -> dict[int, dict[str, Any]]:
        """GET ``path`` until ``count`` different worker processes have answered it.

        Returns the last JSON report of each worker by its ``pid`` field.
        Workers in ``exclude`` are asked like the others and left out of the
        result, which is how a test waits for replacements.  The requests
        overlap and each holds its worker for a moment (the ``hold``
        parameter of the probe applications), so that the others get some.

        Several requests are made, more than ``count``, and the reports of
        the earlier ones are not returned: assert on the world's counters as
        well, which cover every one of them.
        """
        separator = "&" if "?" in path else "?"
        held = f"{path}{separator}hold=0.1"
        seen: dict[int, dict[str, Any]] = {}
        failures: list[str] = []
        deadline = time.monotonic() + timeout

        def ask(_: int) -> None:
            try:
                reply = self.get(held, timeout=30.0)
            except OSError as error:
                failures.append(f"{type(error).__name__}: {error}")
                return
            if reply.status != 200:
                failures.append(f"HTTP {reply.status}: {reply.text[:300]}")
                return
            report = reply.json()
            if report["pid"] not in exclude:
                seen[report["pid"]] = report

        with ThreadPoolExecutor(max_workers=max(4, 2 * count)) as pool:
            while True:
                list(pool.map(ask, range(max(4, 2 * count))))
                if len(seen) >= count:
                    return seen
                if time.monotonic() >= deadline:
                    raise AssertionError(
                        f"{len(seen)} of {count} workers answered {path} within {timeout} s "
                        f"(pids {sorted(seen)}, left out {sorted(exclude)}); "
                        f"last failures: {failures[-3:]}"
                    )
                time.sleep(0.05)

    def wait_log(self, pattern: str, timeout: float = 15.0) -> re.Match[str]:
        """Wait until the log matches a regular expression; returns the match.

        Only what was logged since the current test began is searched, so a
        line from an earlier test on the same server does not satisfy it.
        """
        deadline = time.monotonic() + timeout
        while True:
            match = re.search(pattern, self.log_of_this_test)
            if match:
                return match
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{pattern!r} did not appear in the log of {self.name} in {timeout} s"
                )
            time.sleep(0.1)

    def wait_ready(self, ready: str | Callable[[Server], bool], timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while True:
            if not self.running:
                raise AssertionError(
                    f"{self.name} exited with status {self._proc.returncode} while starting"
                )
            try:
                up = ready(self) if callable(ready) else self.get(ready, timeout=5.0).status < 500
            except OSError:
                up = False
            if up:
                return
            if time.monotonic() >= deadline:
                raise AssertionError(f"{self.name} was not ready within {timeout} s")
            time.sleep(0.1)

    def stop(
        self,
        timeout: float = 20.0,
        *,
        check: bool = True,
        exit_codes: Collection[int] = (0, -signal.SIGTERM),
    ) -> int | None:
        """Stop the server with SIGTERM and check that it stopped cleanly.

        Cleanly means: the process that was started exits within ``timeout``
        seconds with a status in ``exit_codes`` (0, or ended by the SIGTERM
        itself), and no process of the server is left.  Otherwise what is left
        is killed and an ``AssertionError`` says what went wrong; with
        ``check=False`` nothing is raised.  Returns the exit status.  Calling
        it again does nothing: every server is stopped at teardown anyway.
        """
        if self._stopped:
            return self.returncode
        self._stopped = True
        deadline = time.monotonic() + timeout
        problems = []
        if self.running:
            self._proc.send_signal(signal.SIGTERM)
            try:
                self._proc.wait(timeout)
            except subprocess.TimeoutExpired:
                problems.append(f"did not exit within {timeout} s of SIGTERM")
        else:
            problems.append("had already exited when it was stopped")
        left = _end_session(self.pid, deadline)
        if left:
            problems.append(f"left processes that had to be killed: {left}")
        self.returncode = self._proc.wait()
        if self.returncode not in exit_codes and not left:
            problems.append(f"exit status {self.returncode}")
        if self in registry.live:
            registry.live.remove(self)
            registry.ended.append(self)
        if check and problems:
            raise AssertionError(f"{self.name}: {'; '.join(problems)}")
        return self.returncode


def start_server(
    argv: Iterable[str],
    *,
    env: Mapping[str, str] | None = None,
    ready: str | Callable[[Server], bool] = "/whoami",
    timeout: float = 30.0,
    cwd: str | os.PathLike[str] | None = None,
) -> Server:
    """Start a server under test and wait until it answers.

    ``argv`` is the command; ``{port}`` in an argument is replaced by a free
    port on 127.0.0.1, which is also the ``PORT`` variable of the server's
    environment and the port of ``Server.url``.

    ``env`` is added to the environment, which is the container's without the
    tethered policy variable and with the shared applications and the suite
    directory on ``PYTHONPATH``.  A probe application needs ``TETH_ACTIVATE``.

    ``ready`` is a path that is polled until the server answers it with a
    status below 500, or a function of the ``Server`` that returns true.

    The server runs in ``cwd`` (the suite directory by default), its output
    goes to ``Server.log``, and it is stopped, with the check ``Server.stop``
    makes, when the test or the fixture that started it is torn down.  Its log
    is attached to the report of a test that fails while it is running.
    """
    port = _free_port(registry.next_port)
    registry.next_port = port + 1
    registry.counter += 1
    command = [argument.replace("{port}", str(port)) for argument in argv]
    server = Server(
        command,
        env=_process_env({"PORT": str(port), **(env or {})}),
        cwd=os.fspath(cwd or SUITE_DIR),
        port=port,
        name=f"#{registry.counter} {' '.join(command)}",
    )
    registry.register(server)
    try:
        server.wait_ready(ready, timeout)
    except BaseException:
        server.stop(5.0, check=False)
        raise
    return server


@dataclass(frozen=True)
class Completed:
    """A finished one-shot script."""

    returncode: int
    stdout: str
    stderr: str
    argv: list[str] = field(default_factory=list)

    def json(self) -> Any:
        """The last line the script printed to stdout, parsed as JSON."""
        lines = self.stdout.strip().splitlines()
        try:
            return json.loads(lines[-1])
        except (IndexError, ValueError):
            raise AssertionError(
                f"exit status {self.returncode}, no JSON on the last line of stdout:\n"
                f"{self.stdout[-2000:]}\n--- stderr ---\n{self.stderr[-4000:]}"
            ) from None


def run_python(
    source: str,
    *,
    activate: str = "plain",
    esp: str | None = None,
    env: Mapping[str, str] | None = None,
    args: Iterable[str] = (),
    timeout: float = 60.0,
) -> Completed:
    """Run Python source in a fresh interpreter in which tethered is already active.

    ``activate`` is what the probe applications understand as
    ``TETH_ACTIVATE`` (``none``, ``plain``, ``locked``, ``fail_closed``,
    ``log_only``, or several joined by commas) and ``esp`` is their
    ``TETH_ESP``; the policy is in place before the first line of ``source``
    runs.  The script can import the shared modules, ``probe_common`` among
    them.  A script that has not ended after ``timeout`` seconds is killed and
    the call raises ``AssertionError``.  The output is attached to the report
    of a failing test.
    """
    registry.counter += 1
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    script = LOG_DIR / f"{registry.counter:03d}-script.py"
    script.write_text(source, encoding="utf-8")
    command = [sys.executable, str(APPS_DIR / "run_under_policy.py"), str(script), *args]
    settings = {"TETH_ACTIVATE": activate, **({"TETH_ESP": esp} if esp else {}), **(env or {})}
    proc = subprocess.Popen(
        command,
        env=_process_env(settings),
        cwd=os.fspath(SUITE_DIR),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        stdout, stderr = proc.communicate()
    _end_session(proc.pid, time.monotonic() + 5.0)
    registry.outputs.append(
        (
            f"script #{registry.counter} (activate={activate}, exit status {proc.returncode})",
            f"{source.rstrip()}\n--- stdout ---\n{stdout}--- stderr ---\n{stderr}",
        )
    )
    if timed_out:
        raise AssertionError(f"the script did not end within {timeout} s")
    return Completed(proc.returncode, stdout, stderr, command)
