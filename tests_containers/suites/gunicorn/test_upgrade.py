"""gunicorn's binary upgrade: ``SIGUSR2`` makes the master fork and re-execute itself.

The copy of the master calls ``os.execvpe(sys.executable, ...)`` with the
environment gunicorn saved when it started.  Under ``--preload`` that was
before the application called ``activate()``, so the saved environment lacks
tethered's policy variable.  tethered carries such an exec of the same
interpreter out itself, with the variable added, under a locked policy too
(where every other launch that lacks the variable is refused).  A refused exec
is what used to take a deployment on a unix socket offline: the copy of the
master, still running gunicorn's code, stopped the workers and unlinked the
socket.

Each test follows one upgrade from the signal to the end of both masters, on
a TCP and a unix listener at once, while a thread keeps requesting both.
"""

from __future__ import annotations

import http.client
import json
import signal
import socket
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from harness import (
    ALLOWED_ADDR,
    ALLOWED_NAME,
    ALLOWED_PORT,
    FORBIDDEN_NAME,
    OTHER_PORT,
    Server,
    arrivals,
    probe_path,
    start_server,
)

if TYPE_CHECKING:
    from collections.abc import Callable

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
POLICY_VARIABLE = "_TETHERED_CHILD_POLICY"

#: What tethered logs when it completes the environment of the exec under a lock.  The
#: process that logs it is the copy of the old master, which the exec turns into the new one.
EXEC_COMPLETED = (
    r"LOG pid={pid} tethered WARNING tethered: os\.exec\*\(\S*python\S*\) was given an "
    r"environment without _TETHERED_CHILD_POLICY; carried out with the locked policy added"
)
#: What the new master's own activate() logs when the policy it asks for is already locked.
ACTIVATE_NO_OP = (
    r"LOG pid={pid} tethered INFO tethered: activate\(\) no-op — the requested policy is "
    r"identical to the active locked policy"
)


def wait_until(condition: Callable[[], Any], what: str, timeout: float = 20.0) -> Any:
    """Poll ``condition`` until it returns something true; that value is returned."""
    deadline = time.monotonic() + timeout
    while True:
        value = condition()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"not within {timeout} s: {what}")
        time.sleep(0.05)


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str) -> None:
        super().__init__("localhost", timeout=10.0)
        self._path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def unix_get(socket_path: Path, path: str) -> dict[str, Any]:
    """GET ``path`` over the unix listener and return the JSON report; HTTP 200 or an error."""
    connection = _UnixConnection(str(socket_path))
    try:
        connection.request("GET", path)
        reply = connection.getresponse()
        body = reply.read()
        if reply.status != 200:
            raise ConnectionError(f"HTTP {reply.status} over {socket_path}: {body[:300]!r}")
        return json.loads(body)
    finally:
        connection.close()


class Requests:
    """A thread that keeps requesting both listeners and notes every request that fails."""

    def __init__(self, server: Server, socket_path: Path) -> None:
        self.server = server
        self.socket_path = socket_path
        self.failures: list[str] = []
        self.answered = {"tcp": 0, "unix": 0}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self._stop.is_set():
            for listener in ("tcp", "unix"):
                try:
                    if listener == "tcp":
                        status = self.server.get("/whoami", timeout=10.0).status
                        if status != 200:
                            raise ConnectionError(f"HTTP {status}")
                    else:
                        unix_get(self.socket_path, "/whoami")
                except (OSError, ValueError, http.client.HTTPException) as error:
                    self.failures.append(f"{listener}: {type(error).__name__}: {error}")
                else:
                    self.answered[listener] += 1
            self._stop.wait(0.01)

    def __enter__(self) -> Requests:
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._stop.set()
        self._thread.join(30.0)


def environment_of(pid: int) -> dict[str, str]:
    """The environment a process was started with (``/proc/<pid>/environ``)."""
    entries = Path("/proc", str(pid), "environ").read_bytes().split(b"\0")
    return dict(
        entry.decode("utf-8", "replace").split("=", 1) for entry in entries if b"=" in entry
    )


@pytest.fixture
def paths(tmp_path: Path) -> tuple[Path, Path]:
    """The unix socket and the pid file of one server."""
    return tmp_path / "g.sock", tmp_path / "g.pid"


ARRANGEMENTS = [
    pytest.param("locked", None, True, id="locked-preload"),
    pytest.param("locked", "block", True, id="locked-block-preload"),
    pytest.param("plain", None, True, id="unlocked-preload"),
    pytest.param("locked", None, False, id="locked-no-preload"),
    pytest.param("plain", None, False, id="unlocked-no-preload"),
]


@pytest.mark.parametrize(("activate", "esp", "preload"), ARRANGEMENTS)
def test_sigusr2_starts_a_new_master_whose_workers_enforce_the_policy(
    activate: str, esp: str | None, preload: bool, paths: tuple[Path, Path]
) -> None:
    socket_path, pid_file = paths
    new_pid_file = pid_file.with_name(pid_file.name + ".2")
    locked = activate == "locked"
    command = [
        "gunicorn",
        "probe_wsgi:application",
        "--bind",
        "127.0.0.1:{port}",
        "--bind",
        f"unix:{socket_path}",
        "--workers",
        "2",
        "--pid",
        str(pid_file),
        *(["--preload"] if preload else []),
    ]
    env = {"TETH_ACTIVATE": activate, **({"TETH_ESP": esp} if esp else {})}
    server = start_server(command, env=env)
    old_master = server.pid
    assert int(pid_file.read_text()) == old_master
    # The environment gunicorn saved, and will re-execute with, has no policy in it.
    assert POLICY_VARIABLE not in environment_of(old_master)

    old_workers = server.each_worker("/whoami", 2)
    for pid, me in old_workers.items():
        assert me["ppid"] == old_master
        assert me["imported_in_pid"] == (old_master if preload else pid)
        assert (me["active"], me["locked"]) == (True, locked), me
    assert unix_get(socket_path, "/whoami")["pid"] in old_workers

    with Requests(server, socket_path) as requests:
        # ── The upgrade ───────────────────────────────────────────────
        server.send_signal(signal.SIGUSR2)
        new_master = int(
            wait_until(
                lambda: new_pid_file.exists() and new_pid_file.read_text().strip(),
                "the new master writes its pid file",
            )
        )
        assert new_master not in (old_master, *old_workers)
        server.wait_log(rf"Listening at: \S+ \({new_master}\)")
        # The old master is still there, with its own pid file and its workers.
        assert server.running
        assert int(pid_file.read_text()) == old_master

        # ── The new master ────────────────────────────────────────────
        # With --preload the old master holds the policy, so its copy executes
        # the new master under it and the new master starts with the policy.
        # Without --preload a master never holds one: only workers do.
        started_with = environment_of(new_master)
        assert started_with["GUNICORN_PID"] == str(old_master)
        assert (POLICY_VARIABLE in started_with) is preload
        if preload and locked:
            server.wait_log(EXEC_COMPLETED.format(pid=new_master))
            # ... and the application's own activate(), in the new master, changes nothing.
            server.wait_log(ACTIVATE_NO_OP.format(pid=new_master))
        else:
            assert "carried out with the locked policy added" not in server.log
        assert "SubprocessBlocked" not in server.log

        # ── Its workers ───────────────────────────────────────────────
        # Four workers share the listeners now; ask until the two new ones answered.
        new_workers = server.each_worker("/whoami", 2, exclude=old_workers)
        for pid, me in new_workers.items():
            assert me["ppid"] == new_master
            assert me["imported_in_pid"] == (new_master if preload else pid)
            assert (me["active"], me["locked"]) == (True, locked), me
            assert me["external_subprocess_policy"] == (esp or "warn")

        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2, exclude=old_workers).values():
            assert report["outcome"] == "blocked", report
            assert report["exception"] == EGRESS_BLOCKED, report
        # Nothing arrived from the old workers either, which answered some of those requests.
        assert arrivals() == {}

        path = probe_path("connect", ALLOWED_NAME, ALLOWED_PORT)
        for report in server.each_worker(path, 2, exclude=old_workers).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

        # ── The old master is stopped ─────────────────────────────────
        server.send_signal(signal.SIGTERM)
        wait_until(lambda: not server.running, "the old master exits after SIGTERM")
        server.wait_log("Master has been promoted")
        wait_until(lambda: not new_pid_file.exists(), "the new master takes over the pid file")
        assert int(pid_file.read_text()) == new_master
        # The old master left the unix socket in place for its successor.
        assert socket_path.is_socket()
        survivors = wait_until(
            lambda: sorted(server.pids()) == sorted([new_master, *new_workers]) and server.pids(),
            "only the new master and its workers are left",
        )
        assert set(server.each_worker("/whoami", 2)) == set(new_workers), survivors
        assert unix_get(socket_path, "/whoami")["pid"] in new_workers
        report = unix_get(socket_path, probe_path("connect", FORBIDDEN_NAME, OTHER_PORT))
        assert report["outcome"] == "blocked", report
        assert set(arrivals()) == {AT_ALLOWED}

    # Both listeners answered throughout: before, during and after the upgrade.
    assert requests.failures == []
    assert requests.answered["tcp"] > 0
    assert requests.answered["unix"] > 0

    # ── The new master is stopped like any gunicorn ───────────────────
    server.send_signal(signal.SIGTERM, new_master)
    wait_until(lambda: not server.pids(), "the new master and its workers exit after SIGTERM")
    assert not socket_path.exists()
    assert not pid_file.exists()
    # The harness started the old master: its exit status, and nothing left to kill.
    assert server.stop(check=False) == 0
