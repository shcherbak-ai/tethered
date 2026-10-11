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
    FORBIDDEN_ADDR,
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


def gunicorn(application: str, paths: tuple[Path, Path], preload: bool) -> list[str]:
    """Two sync workers on a TCP and a unix listener, with a pid file."""
    socket_path, pid_file = paths
    return [
        "gunicorn",
        application,
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
    env = {"TETH_ACTIVATE": activate, **({"TETH_ESP": esp} if esp else {})}
    server = start_server(gunicorn("probe_wsgi:application", paths, preload), env=env)
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
        # gunicorn removes the new master's own pid file first and writes this one after.
        wait_until(
            lambda: (
                not new_pid_file.exists() and pid_file.exists() and pid_file.read_text().strip()
            ),
            "the new master takes over the pid file",
        )
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


# ── An upgrade to a release that asks for another policy ──────────────

TO_FORBIDDEN = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
DEFAULT_RULE = f"{ALLOWED_NAME}:{ALLOWED_PORT}"
#: The rule the new release adds: it allows what the old policy forbids.
ADDED_RULE = f"{FORBIDDEN_NAME}:{OTHER_PORT}"
#: How gunicorn reports the exception that ends the new master while it preloads.
LOCKED_AND_DIFFERENT = (
    r"Error: tethered: activate\(\) blocked — a locked policy is active and the "
    r"requested policy differs from it"
)


def allow_file(tmp_path: Path, *rules: str) -> Path:
    path = tmp_path / "allow.txt"
    path.write_text("\n".join(rules) + "\n", encoding="utf-8")
    return path


def start_then_change_the_policy(
    tmp_path: Path, paths: tuple[Path, Path], activate: str, preload: bool
) -> tuple[Server, dict[int, Any]]:
    """A server under the default allow list, whose next import of the application adds a rule."""
    rules = allow_file(tmp_path, DEFAULT_RULE)
    env = {"TETH_ACTIVATE": activate, "TETH_ALLOW_FILE": str(rules)}
    server = start_server(gunicorn("policy_from_file:application", paths, preload), env=env)
    workers = server.each_worker(TO_FORBIDDEN, 2)
    for report in workers.values():
        assert report["outcome"] == "blocked", report
    assert arrivals() == {}
    allow_file(tmp_path, DEFAULT_RULE, ADDED_RULE)
    return server, workers


def test_an_upgrade_cannot_change_a_locked_policy_that_the_master_holds(
    tmp_path: Path, paths: tuple[Path, Path]
) -> None:
    """Limit: under ``--preload`` the master holds the locked policy and the new master is
    executed under it.  A new release that asks for another policy gets ``TetheredLocked``
    when the new master imports it; the new master does not start, and the old one goes on
    serving under the old policy.  Stop and start gunicorn to change a locked policy.
    """
    socket_path, pid_file = paths
    server, old_workers = start_then_change_the_policy(tmp_path, paths, "locked", True)

    server.send_signal(signal.SIGUSR2)
    server.wait_log(LOCKED_AND_DIFFERENT)
    wait_until(
        lambda: sorted(server.pids()) == sorted([server.pid, *old_workers]),
        "the new master is gone, and the old master and its workers are all there is",
    )
    assert not pid_file.with_name(pid_file.name + ".2").exists()
    assert int(pid_file.read_text()) == server.pid

    # The old server is untouched: both listeners, the old workers, the old policy.
    for report in server.each_worker(TO_FORBIDDEN, 2).values():
        assert report["pid"] in old_workers
        assert report["outcome"] == "blocked", report
    report = unix_get(socket_path, TO_FORBIDDEN)
    assert report["pid"] in old_workers
    assert report["outcome"] == "blocked", report
    assert arrivals() == {}


@pytest.mark.parametrize(
    ("activate", "preload"),
    [
        pytest.param("locked", False, id="locked-no-preload"),
        pytest.param("plain", True, id="unlocked-preload"),
        pytest.param("plain", False, id="unlocked-no-preload"),
    ],
)
def test_an_upgrade_changes_the_policy_when_no_lock_is_handed_on(
    tmp_path: Path, paths: tuple[Path, Path], activate: str, preload: bool
) -> None:
    # Without --preload a master holds no policy, so the workers of the new
    # master lock what the new release asks for.  An unlocked policy that
    # the new master inherited is replaced when it imports the new release.
    _, pid_file = paths
    server, old_workers = start_then_change_the_policy(tmp_path, paths, activate, preload)

    server.send_signal(signal.SIGUSR2)
    new_pid_file = pid_file.with_name(pid_file.name + ".2")
    new_master = int(
        wait_until(
            lambda: new_pid_file.exists() and new_pid_file.read_text().strip(),
            "the new master writes its pid file",
        )
    )
    for report in server.each_worker(TO_FORBIDDEN, 2, exclude=old_workers).values():
        assert report["ppid"] == new_master
        assert (report["active"], report["locked"]) == (True, activate == "locked"), report
        assert report["outcome"] == "reached", report
    # Only the new workers let it through; the old ones, still serving, refuse it.
    assert set(arrivals()) == {f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"}

    server.send_signal(signal.SIGTERM)
    wait_until(lambda: not server.running, "the old master exits after SIGTERM")
    server.send_signal(signal.SIGTERM, new_master)
    wait_until(lambda: not server.pids(), "the new master and its workers exit after SIGTERM")
    assert server.stop(check=False) == 0
