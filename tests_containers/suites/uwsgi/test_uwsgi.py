"""uWSGI, which embeds Python in its own binary.

The plain deployment is ``uwsgi --http :8000 --wsgi-file app.py --master
--processes 2`` with ``tethered.activate()`` at the top of ``app.py``: the
master imports the application, and with it the policy, and forks the
workers.  Every server here also gets ``--die-on-term``, because uWSGI treats
``SIGTERM`` as "reload" without it and the harness stops servers with ``SIGTERM``.

What makes uWSGI unlike the other servers, and what the classes below pin:

- **``sys.executable`` is the uwsgi binary**, not a Python interpreter.
  tethered recognizes a Python child by ``sys.executable``, so a launch of the
  real interpreter counts as external (warned about, refused under ``"block"``)
  although the child does inherit the policy, and a launch of
  ``sys.executable`` counts as a Python launch although it starts uWSGI.
  ``--py-sys-executable`` puts that right.
- **A reload re-executes the binary** (``SIGHUP``, ``--py-autoreload``,
  ``--touch-reload``) with the environment of the process, which carries the
  policy.  The new process inherits the policy as a child would: a locked
  policy cannot be changed by reloading.
- **Several mounted applications** share the process, each in an interpreter
  of its own unless ``--single-interpreter`` is given.  The first one is
  loaded in the main interpreter.  A lock is one per process.
- **A virtualenv** (``-H`` / ``--virtualenv``) is entered after the binary
  has started.

The applications are in ``uwsgi_app.py``.  The virtualenv tests install the
wheel of tethered that the image keeps in ``/wheels``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from harness import (
    ALLOWED_ADDR,
    ALLOWED_NAME,
    ALLOWED_PORT,
    FORBIDDEN_ADDR,
    FORBIDDEN_NAME,
    LOOPBACK_ADDR,
    OTHER_PORT,
    SUITE_DIR,
    Server,
    arrivals,
    probe_path,
    start_server,
)

if TYPE_CHECKING:
    from collections.abc import Callable

EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"
AT_LOOPBACK = f"{LOOPBACK_ADDR}:{OTHER_PORT}/tcp"

#: The Python interpreter uWSGI was built against: the one this process runs on.
PYTHON = sys.executable
#: The allow list every application asks for unless a test says otherwise ...
DEFAULT_RULE = f"{ALLOWED_NAME}:{ALLOWED_PORT}"
#: ... and a rule for the destination that list forbids.
OTHER_RULE = f"{FORBIDDEN_NAME}:{OTHER_PORT}"

OPS = ["connect", "urllib"]
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]

TO_FORBIDDEN = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
TO_ALLOWED = probe_path("connect", ALLOWED_NAME, ALLOWED_PORT)
TO_LOOPBACK = probe_path("connect", LOOPBACK_ADDR, OTHER_PORT)

#: tethered's words when activate() finds the policy it is asked for already locked.
ACTIVATE_NO_OP = (
    r"tethered: activate\(\) no-op — the requested policy is identical to the active locked policy"
)
LOCKED_AND_DIFFERENT = (
    "TetheredLocked: tethered: activate() blocked — a locked policy is active and the "
    "requested policy differs from it."
)
OUTSIDE_THE_LOCK = (
    "a locked tethered policy is active in another interpreter of this process, "
    "so this interpreter gets no network access"
)


def uwsgi(
    *options: str, processes: int = 2, listen: str = "--http", app: str | None = "app_a.py"
) -> list[str]:
    """A uWSGI command line: the plain deployment, plus ``options``."""
    command = ["uwsgi", listen, "127.0.0.1:{port}", "--master", "--processes", str(processes)]
    command.append("--die-on-term")
    if app is not None:
        command += ["--wsgi-file", str(SUITE_DIR / app)]
    return [*command, *options]


def mounts(*options: str, processes: int = 1) -> list[str]:
    """Two applications in one uWSGI: ``/a`` (loaded first) and ``/b``."""
    return uwsgi(
        "--mount",
        f"/a={SUITE_DIR / 'app_a.py'}",
        "--mount",
        f"/b={SUITE_DIR / 'app_b.py'}",
        "--manage-script-name",
        *options,
        processes=processes,
        app=None,
    )


def wait_until(condition: Callable[[], Any], what: str, timeout: float = 20.0) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        value = condition()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"not within {timeout} s: {what}")
        time.sleep(0.05)


def status_of(server: Server, path: str) -> int | None:
    """The HTTP status of one request, or None while the server does not answer."""
    try:
        return server.get(path, timeout=5.0).status
    except OSError:
        return None


def ask(server: Server, path: str) -> dict[str, Any]:
    reply = server.get(path)
    assert reply.status == 200, f"GET {path}: HTTP {reply.status}: {reply.text[:500]}"
    return reply.json()


def launch(server: Server, argv: list[str], **params: str) -> dict[str, Any]:
    """Have the application run ``argv`` with ``subprocess.run`` and report."""
    return server.probe("launch", argv=json.dumps(argv), **params)


def child(executable: str) -> list[str]:
    """The command of the probe child, which tries the forbidden destination itself."""
    return [executable, "{child}", FORBIDDEN_NAME, str(OTHER_PORT)]


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_locked(report: dict[str, Any]) -> None:
    assert (report["active"], report["locked"]) == (True, True), report


# ── The plain deployment, and the options that change who loads the application ──

ARRANGEMENTS: dict[str, dict[str, Any]] = {
    "plain": {},
    "http-socket": {"listen": "--http-socket"},
    "lazy-apps": {"options": ["--lazy-apps"]},
    "threads": {"options": ["--threads", "4"]},
}


@pytest.fixture(scope="module", params=list(ARRANGEMENTS))
def arrangement(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(arrangement: str) -> Server:
    chosen = ARRANGEMENTS[arrangement]
    command = uwsgi(*chosen.get("options", ()), listen=chosen.get("listen", "--http"))
    return start_server(command, env={"TETH_ACTIVATE": "locked"})


class TestEveryWorker:
    def test_every_worker_holds_the_locked_policy(self, server: Server, arrangement: str) -> None:
        answers = server.each_worker("/whoami", 2)
        assert server.pid not in answers
        for pid, me in answers.items():
            assert_locked(me)
            assert me["ppid"] == server.pid
            # The master imports the application and forks; with --lazy-apps each worker does.
            assert me["imported_in_pid"] == (pid if arrangement == "lazy-apps" else server.pid)
            assert me["interpreter"] == 0
            assert me["thread"].startswith("uWSGIWorker"), me
            assert os.path.basename(me["executable"]) == "uwsgi", me
        assert "tethered.pth not found" not in server.log

    @pytest.mark.parametrize("op", OPS)
    def test_every_worker_reaches_the_allowed_destination(self, server: Server, op: str) -> None:
        for report in server.each_worker(probe_path(op, ALLOWED_NAME, ALLOWED_PORT), 2).values():
            assert report["outcome"] == "reached", report
            assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize("op", OPS)
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_every_worker_refuses_a_destination_outside_the_allow_list(
        self, server: Server, op: str, host: str, port: int
    ) -> None:
        for report in server.each_worker(probe_path(op, host, port), 2).values():
            assert_refused(report)
        assert arrivals() == {}

    def test_an_uncaught_refusal_gets_no_response_and_the_workers_survive(
        self, server: Server
    ) -> None:
        # uWSGI logs an exception that the application raises before it starts
        # its response, and closes the connection: no 500.  (The control without
        # tethered is in TestOtherArrangements.)
        before = server.each_worker("/whoami", 2)
        with pytest.raises(OSError, match="closed connection without response"):
            server.get(TO_FORBIDDEN + "&uncaught=1")
        assert arrivals() == {}
        server.wait_log(f"EgressBlocked: Blocked by tethered: {FORBIDDEN_NAME} is not in the allow")
        assert set(server.each_worker("/whoami", 2)) == set(before)


class TestOtherArrangements:
    def test_every_thread_of_a_worker_enforces(self) -> None:
        server = start_server(uwsgi("--threads", "4"), env={"TETH_ACTIVATE": "locked"})

        def refused(_: int) -> tuple[int, str]:
            report = ask(server, TO_FORBIDDEN + "&hold=0.3")
            assert_refused(report)
            return report["pid"], report["thread"]

        with ThreadPoolExecutor(max_workers=16) as pool:
            answered = set(pool.map(refused, range(16)))
        # Two workers with four threads each; sixteen requests at once reach most of them.
        assert len({pid for pid, _ in answered}) == 2, answered
        assert len(answered) >= 4, answered
        assert arrivals() == {}

    def test_an_unlocked_policy_is_enforced_in_every_worker(self) -> None:
        server = start_server(uwsgi(), env={"TETH_ACTIVATE": "plain"})
        for report in server.each_worker(TO_FORBIDDEN, 2).values():
            assert (report["active"], report["locked"]) == (True, False), report
            assert_refused(report)
        assert arrivals() == {}
        for report in server.each_worker(TO_ALLOWED, 2).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    def test_without_tethered_the_forbidden_destination_is_reached(self) -> None:
        # The control: the same route, no policy.
        server = start_server(uwsgi(), env={"TETH_ACTIVATE": "none"})
        me = ask(server, "/whoami")
        assert me["tethered_imported"] is False, me
        assert ask(server, TO_FORBIDDEN)["outcome"] == "reached"
        assert arrivals() == {AT_FORBIDDEN: 1}
        # And what uWSGI does with any uncaught exception: here, a refused
        # connection to a loopback port nothing listens on.
        with pytest.raises(OSError, match="closed connection without response"):
            server.get(probe_path("connect", LOOPBACK_ADDR, 9, uncaught=1))
        server.wait_log("ConnectionRefusedError")


# ── Workers that are started later ────────────────────────────────────


class TestLaterWorkers:
    def test_a_worker_started_after_max_requests_enforces_the_policy(self) -> None:
        # uWSGI recycles no worker younger than --min-worker-lifetime (60 s by default).
        command = uwsgi("--max-requests", "20", "--min-worker-lifetime", "0")
        server = start_server(command, env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)
        for report in server.each_worker(TO_FORBIDDEN, 2, exclude=first).values():
            assert report["ppid"] == server.pid
            assert report["imported_in_pid"] == server.pid
            assert_locked(report)
            assert_refused(report)
        assert arrivals() == {}
        # uWSGI's own words for a worker that reached --max-requests.
        server.wait_log(r"The work of process \d+ is done")

    def test_a_worker_that_replaces_one_killed_by_harakiri_enforces_the_policy(self) -> None:
        server = start_server(uwsgi("--harakiri", "1"), env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)
        # A request that takes longer than a second: uWSGI kills the worker that serves it.
        with pytest.raises(OSError):
            server.get("/whoami?hold=20")
        killed = int(server.wait_log(r"HARAKIRI ON WORKER \d+ \(pid: (\d+)").group(1))
        new = int(server.wait_log(r"Respawned uWSGI worker \d+ \(new pid: (\d+)\)").group(1))
        assert killed in first
        replacement = server.each_worker(TO_FORBIDDEN, 1, exclude=first)
        assert set(replacement) == {new}
        assert replacement[new]["ppid"] == server.pid
        assert_locked(replacement[new])
        assert_refused(replacement[new])
        assert arrivals() == {}
        assert ask(server, TO_ALLOWED)["outcome"] == "reached"


# ── Reloads: uWSGI re-executes itself ─────────────────────────────────


def allow_file(tmp_path: Path, *rules: str) -> Path:
    path = tmp_path / "allow.txt"
    path.write_text("\n".join(rules) + "\n", encoding="utf-8")
    return path


def reloaded(server: Server, before: dict[int, Any]) -> dict[int, dict[str, Any]]:
    """Send ``SIGHUP`` and return ``/pyinfo`` of the two workers of the reloaded server."""
    server.send_signal(signal.SIGHUP)
    server.wait_log("binary reloading uWSGI")
    workers = server.each_worker("/pyinfo", 2, exclude=before)
    # The same process, executing a new image of the binary.
    assert server.running
    assert {me["ppid"] for me in workers.values()} == {server.pid}
    return workers


class TestReload:
    def test_a_reloaded_server_inherits_the_locked_policy_before_it_loads_the_application(
        self,
    ) -> None:
        """The reload is an exec of the uwsgi binary with the environment of the process, which
        carries the policy.  The new interpreter runs ``tethered.pth`` as it starts (a
        system-wide install) and holds the locked policy before the application is imported,
        whose own ``activate()`` then changes nothing.
        """
        server = start_server(uwsgi(), env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/pyinfo", 2)
        assert {me["bootstrap_ran"] for me in first.values()} == {False}
        for me in reloaded(server, first).values():
            assert_locked(me)
            assert me["bootstrap_ran"] is True, me
            assert me["imported_in_pid"] == server.pid
        server.wait_log(rf"LOG pid={server.pid} app=a tethered INFO {ACTIVATE_NO_OP}")
        for report in server.each_worker(TO_FORBIDDEN, 2, exclude=first).values():
            assert_refused(report)
        assert arrivals() == {}
        for report in server.each_worker(TO_ALLOWED, 2, exclude=first).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    def test_py_autoreload_reloads_into_the_same_locked_policy(self, tmp_path: Path) -> None:
        application = tmp_path / "watched.py"
        shutil.copy(SUITE_DIR / "app_a.py", application)
        command = uwsgi("--py-autoreload", "1", "--wsgi-file", str(application), app=None)
        server = start_server(command, env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)

        def touched_and_noticed() -> bool:
            # The reloader notes a file's time on its first pass and compares afterwards.
            application.touch()
            return "has been modified" in server.log_of_this_test

        wait_until(touched_and_noticed, "the reloader notices the touched application file")
        server.wait_log("binary reloading uWSGI")
        for report in server.each_worker(TO_FORBIDDEN, 2, exclude=first).values():
            assert_locked(report)
            assert_refused(report)
        assert arrivals() == {}
        server.wait_log(ACTIVATE_NO_OP)

    def test_a_reload_cannot_change_a_locked_policy(self, tmp_path: Path) -> None:
        """Limit: the reloaded server holds the old locked policy before it imports the
        application, so the application's ``activate()`` with a changed allow list raises
        ``TetheredLocked``.  An application that catches it runs under the old policy.
        """
        rules = allow_file(tmp_path, DEFAULT_RULE)
        env = {"TETH_ACTIVATE": "locked", "TETH_ALLOW_FILE": str(rules), "TETH_CATCH": "1"}
        server = start_server(uwsgi(), env=env)
        first = server.each_worker("/whoami", 2)
        assert {me["activation_error"] for me in first.values()} == {None}

        allow_file(tmp_path, DEFAULT_RULE, OTHER_RULE)
        for me in reloaded(server, first).values():
            assert_locked(me)
            assert me["activation_error"].startswith(LOCKED_AND_DIFFERENT), me
        # The new rule is not in force ...
        for report in server.each_worker(TO_FORBIDDEN, 2, exclude=first).values():
            assert_refused(report)
        assert arrivals() == {}
        # ... and the old one still is.
        assert ask(server, TO_ALLOWED)["outcome"] == "reached"

    def test_a_reload_into_a_changed_locked_policy_leaves_the_server_without_application(
        self, tmp_path: Path
    ) -> None:
        """Limit: when the application lets that ``TetheredLocked`` out, uWSGI has no
        application after the reload and answers every request with a 500, until the server is
        stopped and started.
        """
        rules = allow_file(tmp_path, DEFAULT_RULE)
        env = {"TETH_ACTIVATE": "locked", "TETH_ALLOW_FILE": str(rules)}
        server = start_server(uwsgi(), env=env)
        assert ask(server, TO_ALLOWED)["outcome"] == "reached"

        allow_file(tmp_path, DEFAULT_RULE, OTHER_RULE)
        server.send_signal(signal.SIGHUP)
        server.wait_log(LOCKED_AND_DIFFERENT.replace("(", r"\(").replace(")", r"\)"))
        server.wait_log("no app loaded")
        wait_until(lambda: status_of(server, "/whoami") == 500, "the reloaded server answers")
        assert status_of(server, TO_ALLOWED) == 500
        assert status_of(server, TO_FORBIDDEN) == 500
        server.wait_log("no python application found")
        assert arrivals() == {AT_ALLOWED: 1}  # the request before the reload

    def test_a_reload_changes_an_unlocked_policy(self, tmp_path: Path) -> None:
        rules = allow_file(tmp_path, DEFAULT_RULE)
        env = {"TETH_ACTIVATE": "plain", "TETH_ALLOW_FILE": str(rules)}
        server = start_server(uwsgi(), env=env)
        first = server.each_worker(TO_FORBIDDEN, 2)
        for report in first.values():
            assert_refused(report)
        assert arrivals() == {}

        allow_file(tmp_path, DEFAULT_RULE, OTHER_RULE)
        reloaded(server, first)
        for report in server.each_worker(TO_FORBIDDEN, 2, exclude=first).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_FORBIDDEN}

    def test_with_lazy_apps_a_reload_changes_a_locked_policy(self, tmp_path: Path) -> None:
        # The master never imports the application, so it holds no policy and
        # the reloaded server starts without one; each new worker locks the new list.
        rules = allow_file(tmp_path, DEFAULT_RULE)
        env = {"TETH_ACTIVATE": "locked", "TETH_ALLOW_FILE": str(rules)}
        server = start_server(uwsgi("--lazy-apps"), env=env)
        first = server.each_worker(TO_FORBIDDEN, 2)
        for report in first.values():
            assert_refused(report)
        assert arrivals() == {}

        allow_file(tmp_path, DEFAULT_RULE, OTHER_RULE)
        for me in reloaded(server, first).values():
            assert_locked(me)
            assert me["bootstrap_ran"] is False, me
        for report in server.each_worker(TO_FORBIDDEN, 2, exclude=first).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_FORBIDDEN}


# ── Launches: sys.executable is the uwsgi binary ──────────────────────


@pytest.fixture(scope="class")
def locked() -> Server:
    """One worker, a locked policy, the default ``external_subprocess_policy`` (warn)."""
    return start_server(uwsgi(processes=1), env={"TETH_ACTIVATE": "locked"})


@pytest.fixture(scope="class")
def blocking() -> Server:
    """The same, with ``external_subprocess_policy="block"``."""
    env = {"TETH_ACTIVATE": "locked", "TETH_ESP": "block"}
    return start_server(uwsgi(processes=1), env=env)


class TestLaunchesUnderALock:
    def test_sys_executable_is_the_uwsgi_binary(self, locked: Server) -> None:
        me = ask(locked, "/whoami")
        assert me["executable"] == shutil.which("uwsgi")
        assert me["executable"] != PYTHON

    def test_a_launch_of_sys_executable_starts_uwsgi_and_tethered_takes_it_for_python(
        self, locked: Server
    ) -> None:
        """Limit: the usual way to start a Python child starts uWSGI under uWSGI, which fails
        on the script it is given for a configuration file.  tethered says nothing: to it a
        launch of ``sys.executable`` is a launch of the interpreter.
        """
        report = launch(locked, child("{executable}"))
        assert report["outcome"] == "reached", report
        assert report["returncode"] != 0, report
        assert "unable to load configuration from" in report["stderr"], report
        assert arrivals() == {}
        assert "external subprocess" not in locked.log_of_this_test

    def test_a_child_started_with_the_real_interpreter_inherits_and_is_warned_about(
        self, locked: Server
    ) -> None:
        """Limit: the interpreter is not ``sys.executable`` here, so tethered cannot vouch for
        the child and warns.  The child does run the bootstrap and holds the locked policy.
        """
        report = launch(locked, child(PYTHON))
        assert report["outcome"] == "reached", report
        assert_locked(report["child"])
        assert_refused(report["child"])
        assert report["child"]["executable"] == PYTHON
        assert arrivals() == {}
        locked.wait_log(
            rf"external subprocess launch detected: subprocess\.Popen\({re.escape(PYTHON)}\)"
        )

    def test_a_child_given_an_environment_without_the_policy_is_not_launched(
        self, locked: Server
    ) -> None:
        report = launch(locked, child(PYTHON), env="clean")
        assert_refused(report, SUBPROCESS_BLOCKED)
        assert "env strips _TETHERED_CHILD_POLICY" in report["message"]
        assert arrivals() == {}

    def test_a_tool_is_warned_about_and_is_not_restricted(self, locked: Server) -> None:
        report = locked.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        locked.wait_log(r"external subprocess launch detected: subprocess\.Popen\(bash\)")


class TestLaunchesUnderBlock:
    def test_a_child_started_with_the_real_interpreter_is_not_launched(
        self, blocking: Server
    ) -> None:
        """Limit: under ``"block"`` no Python child can be started from a uWSGI worker, although
        the child would inherit the policy: the interpreter is not ``sys.executable``.
        """
        report = launch(blocking, child(PYTHON))
        assert_refused(report, SUBPROCESS_BLOCKED)
        assert arrivals() == {}
        blocking.wait_log(
            rf"blocked external subprocess launch: subprocess\.Popen\({re.escape(PYTHON)}\)"
        )

    def test_a_tool_is_not_launched(self, blocking: Server) -> None:
        report = blocking.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert_refused(report, SUBPROCESS_BLOCKED)
        assert arrivals() == {}

    def test_uwsgi_given_options_python_does_not_have_is_not_launched(
        self, blocking: Server
    ) -> None:
        # tethered reads the arguments as the interpreter's; what it cannot parse is external.
        report = launch(blocking, ["{executable}", "--exec-asap", "true"])
        assert_refused(report, SUBPROCESS_BLOCKED)

    def test_uwsgi_given_a_configuration_file_runs_a_command_from_it(
        self, blocking: Server, tmp_path: Path
    ) -> None:
        """Limit: ``[sys.executable, "file.ini"]`` reads to tethered like ``python file.ini``, a
        Python child that will inherit, so ``"block"`` does not refuse it.  It is uWSGI, and
        uWSGI runs the ``exec-asap`` command of that file without ever starting Python.
        """
        tool = (
            f"exec 3<>/dev/tcp/{FORBIDDEN_NAME}/{OTHER_PORT} "
            '&& printf "GET / HTTP/1.0\\r\\n\\r\\n" >&3 && tail -n 1 <&3'
        )
        configuration = tmp_path / "launch.ini"
        configuration.write_text(f"[uwsgi]\nexec-asap = bash -c '{tool}'\n", encoding="utf-8")
        report = launch(blocking, ["{executable}", str(configuration)])
        assert report["outcome"] == "reached", report
        assert f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}" in report["stdout"] + report["stderr"]
        assert arrivals() == {AT_FORBIDDEN: 1}
        assert "external subprocess" not in blocking.log_of_this_test


class TestPySysExecutable:
    """``--py-sys-executable`` makes ``sys.executable`` name the real interpreter."""

    def test_a_child_started_with_sys_executable_inherits_the_lock(self) -> None:
        command = uwsgi("--py-sys-executable", PYTHON, processes=1)
        server = start_server(command, env={"TETH_ACTIVATE": "locked"})
        assert ask(server, "/whoami")["executable"] == PYTHON
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert_locked(report["child"])
        assert_refused(report["child"])
        assert arrivals() == {}
        assert "external subprocess" not in server.log

        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT, how="clean_env")
        assert_refused(report, SUBPROCESS_BLOCKED)
        assert "env strips _TETHERED_CHILD_POLICY" in report["message"]

    def test_under_block_a_child_started_with_sys_executable_is_launched(self) -> None:
        command = uwsgi("--py-sys-executable", PYTHON, processes=1)
        server = start_server(command, env={"TETH_ACTIVATE": "locked", "TETH_ESP": "block"})
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert_locked(report["child"])
        assert report["child"]["external_subprocess_policy"] == "block"
        assert_refused(report["child"])
        assert arrivals() == {}
        for how in ("path_python", "no_site"):
            assert_refused(
                server.probe("child", FORBIDDEN_NAME, OTHER_PORT, how=how), SUBPROCESS_BLOCKED
            )
        assert_refused(server.probe("tool", FORBIDDEN_NAME, OTHER_PORT), SUBPROCESS_BLOCKED)
        assert arrivals() == {}


# ── A virtualenv ──────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def venv(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A virtualenv with tethered installed in it, from the wheel the image was built with."""
    path = tmp_path_factory.mktemp("uwsgi") / "venv"
    wheels = sorted(Path("/wheels").glob("tethered-*.whl"))
    assert wheels, "the image keeps the wheel of tethered in /wheels"
    install = [str(path / "bin" / "python"), "-m", "pip", "install", "--no-index", "--no-deps"]
    for command in ([PYTHON, "-m", "venv", str(path)], [*install, str(wheels[-1])]):
        done = subprocess.run(command, capture_output=True, text=True, check=False)
        assert done.returncode == 0, f"{command}: {done.stdout}\n{done.stderr}"
    return path


def assert_in_venv(me: dict[str, Any], venv: Path) -> None:
    assert me["prefix"] == str(venv), me
    assert me["base_prefix"] != str(venv), me
    assert me["tethered_file"].startswith(str(venv)), me
    # The system-wide site-packages, where the image has tethered too, is not on the path.
    site_packages = [entry for entry in me["path"] if entry.endswith("site-packages")]
    assert len(site_packages) == 1, me
    assert site_packages[0].startswith(str(venv)), me


class TestVirtualenv:
    def test_with_the_home_option_tethered_and_its_bootstrap_come_from_the_virtualenv(
        self, venv: Path
    ) -> None:
        server = start_server(uwsgi("-H", str(venv)), env={"TETH_ACTIVATE": "locked"})
        server.wait_log(f"PEP 405 virtualenv detected: {venv}")
        first = server.each_worker("/pyinfo", 2)
        for me in first.values():
            assert_in_venv(me, venv)
            assert_locked(me)
        assert "tethered.pth not found" not in server.log
        for report in server.each_worker(TO_FORBIDDEN, 2).values():
            assert_refused(report)
        assert arrivals() == {}

        # A reload shows that the virtualenv's tethered.pth is run: the new
        # interpreter holds the policy before the application is imported.
        for me in reloaded(server, first).values():
            assert_in_venv(me, venv)
            assert_locked(me)
            assert me["bootstrap_ran"] is True, me
        server.wait_log(ACTIVATE_NO_OP)

    def test_a_child_started_with_the_python_of_the_virtualenv_inherits(self, venv: Path) -> None:
        python = str(venv / "bin" / "python")
        server = start_server(uwsgi("-H", str(venv), processes=1), env={"TETH_ACTIVATE": "locked"})
        report = launch(server, child(python))
        assert report["outcome"] == "reached", report
        assert_locked(report["child"])
        assert_refused(report["child"])
        assert arrivals() == {}
        # As without a virtualenv: warned about, because sys.executable is the uwsgi binary.
        server.wait_log(r"external subprocess launch detected: subprocess\.Popen\(")

    def test_with_py_sys_executable_a_child_of_the_virtualenv_is_a_python_child(
        self, venv: Path
    ) -> None:
        python = str(venv / "bin" / "python")
        command = uwsgi("-H", str(venv), "--py-sys-executable", python, processes=1)
        server = start_server(command, env={"TETH_ACTIVATE": "locked", "TETH_ESP": "block"})
        assert ask(server, "/whoami")["executable"] == python
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert_locked(report["child"])
        assert report["child"]["executable"] == python
        assert_refused(report["child"])
        assert arrivals() == {}

    def test_a_uwsgi_binary_inside_the_virtualenv_needs_no_option(self, venv: Path) -> None:
        # Where "pip install uwsgi" in a virtualenv puts the binary: next to its python.
        binary = venv / "bin" / "uwsgi"
        if not binary.exists():
            shutil.copy2(shutil.which("uwsgi") or "uwsgi", binary)
        command = [str(binary), *uwsgi()[1:]]
        server = start_server(command, env={"TETH_ACTIVATE": "locked"})
        for me in server.each_worker("/pyinfo", 2).values():
            assert_in_venv(me, venv)
            assert_locked(me)
            assert me["executable"] == str(binary)
        for report in server.each_worker(TO_FORBIDDEN, 2).values():
            assert_refused(report)
        assert arrivals() == {}
        assert "tethered.pth not found" not in server.log


# ── Several mounted applications: one process, an interpreter each ────


def both(server: Server, path: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """The answers of the two mounted applications to the same request."""
    return ask(server, "/a" + path), ask(server, "/b" + path)


class TestMountedApplications:
    def test_the_first_application_is_in_the_main_interpreter_and_the_second_joins_its_lock(
        self,
    ) -> None:
        """Both applications ask for the same locked policy.  uWSGI loads "a" in the main
        interpreter, where it takes the lock, and creates an interpreter for "b" afterwards:
        that one joins the lock as it starts, and b's own ``activate()`` changes nothing.
        """
        server = start_server(
            mounts(processes=2), env={"TETH_ACTIVATE": "locked"}, ready="/a/whoami"
        )
        for mount, interpreter in (("/a", 0), ("/b", 1)):
            for pid, me in server.each_worker(mount + "/pyinfo", 2).items():
                assert me["app"] == mount[1:]
                assert me["interpreter"] == interpreter, me
                assert me["imported_in_pid"] == server.pid != pid
                assert_locked(me)
                assert me["activation_error"] is None
                # "b" got the policy from the lock of its process, through the bootstrap.
                assert me["bootstrap_ran"] is (mount == "/b"), me
            for report in server.each_worker(mount + TO_FORBIDDEN, 2).values():
                assert_refused(report)
            for path in (TO_ALLOWED, TO_LOOPBACK):
                for report in server.each_worker(mount + path, 2).values():
                    assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED, AT_LOOPBACK}
        server.wait_log(rf"app=b tethered INFO {ACTIVATE_NO_OP}")

    def test_an_application_that_does_not_use_tethered_is_held_to_the_lock_it_starts_under(
        self,
    ) -> None:
        env = {"TETH_ACTIVATE_A": "locked", "TETH_ACTIVATE_B": "none"}
        server = start_server(mounts(), env=env, ready="/a/whoami")
        a, b = both(server, "/pyinfo")
        assert (a["interpreter"], b["interpreter"]) == (0, 1)
        assert_locked(a)
        # "b" never called activate(): it joined the lock of "a" when its interpreter started.
        assert_locked(b)
        assert b["bootstrap_ran"] is True, b
        for report in both(server, TO_FORBIDDEN):
            assert_refused(report)
        assert arrivals() == {}
        for report in both(server, TO_ALLOWED):
            assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 2}
        # ... and so does a Python child of "b".
        report = ask(server, "/b" + probe_path("launch", argv=json.dumps(child(PYTHON))))
        assert_locked(report["child"])
        assert_refused(report["child"])

    def test_an_application_loaded_before_another_one_locks_gets_no_network(self) -> None:
        """Limit: "a" is in the main interpreter and does not use tethered; "b", loaded after
        it, locks a policy.  The interpreter of "a" existed before the lock, so it is outside
        it and is refused every connection, loopback included.
        """
        env = {"TETH_ACTIVATE_A": "none", "TETH_ACTIVATE_B": "locked"}
        server = start_server(mounts(), env=env, ready="/a/whoami")
        a, b = both(server, "/whoami")
        assert (a["interpreter"], b["interpreter"]) == (0, 1)
        assert a["tethered_imported"] is False, a
        assert_locked(b)
        for path in (TO_ALLOWED, TO_FORBIDDEN, TO_LOOPBACK):
            report = ask(server, "/a" + path)
            # tethered is not imported in that interpreter: a plain RuntimeError.
            assert report["outcome"] == "error", report
            assert report["exception"] == "builtins.RuntimeError", report
            assert OUTSIDE_THE_LOCK in report["message"], report
        assert arrivals() == {}
        # "b" is restricted by its own policy, as usual.
        assert_refused(ask(server, "/b" + TO_FORBIDDEN))
        assert ask(server, "/b" + TO_ALLOWED)["outcome"] == "reached"
        assert ask(server, "/b" + TO_LOOPBACK)["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1, AT_LOOPBACK: 1}

    def test_an_unlocked_policy_in_the_main_interpreter_is_overruled_by_a_later_lock(self) -> None:
        """Limit: "a" activates a policy of its own without locking it; "b" then locks.  "a" is
        outside that lock: what its own policy allows is refused too.
        """
        env = {"TETH_ACTIVATE_A": "plain", "TETH_ACTIVATE_B": "locked"}
        server = start_server(mounts(), env=env, ready="/a/whoami")
        a, b = both(server, "/whoami")
        assert (a["active"], a["locked"]) == (True, False), a
        assert_locked(b)
        for path in (TO_ALLOWED, TO_FORBIDDEN, TO_LOOPBACK):
            report = ask(server, "/a" + path)
            assert report["outcome"] == "blocked", report
            assert OUTSIDE_THE_LOCK in report["message"], report
        assert arrivals() == {}
        assert ask(server, "/b" + TO_ALLOWED)["outcome"] == "reached"

    def test_a_second_application_with_another_locked_policy_runs_under_the_first_one(
        self,
    ) -> None:
        """Limit: one lock per process.  "b" asks for a different locked policy, gets
        ``TetheredLocked``, catches it, and serves under the policy of "a".
        """
        env = {"TETH_ACTIVATE": "locked", "TETH_ALLOW_B": OTHER_RULE, "TETH_CATCH_B": "1"}
        server = start_server(mounts(), env=env, ready="/a/whoami")
        a, b = both(server, "/whoami")
        assert a["activation_error"] is None
        assert b["activation_error"].startswith(LOCKED_AND_DIFFERENT), b
        assert_locked(b)
        # What "b" asked for is refused, and what "a" allows is what "b" can reach.
        assert_refused(ask(server, "/b" + TO_FORBIDDEN))
        assert arrivals() == {}
        assert ask(server, "/b" + TO_ALLOWED)["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}

    def test_uwsgi_does_not_start_when_the_second_application_lets_that_exception_out(
        self,
    ) -> None:
        # What uWSGI does with any exception while it imports a mounted application.
        env = {"TETH_ACTIVATE": "locked", "TETH_ALLOW_B": OTHER_RULE}
        with pytest.raises(AssertionError, match="exited with status 22 while starting"):
            start_server(mounts(), env=env, ready="/a/whoami")

    def test_with_single_interpreter_both_applications_share_one_policy(self) -> None:
        server = start_server(
            mounts("--single-interpreter"), env={"TETH_ACTIVATE": "locked"}, ready="/a/whoami"
        )
        a, b = both(server, "/pyinfo")
        assert (a["interpreter"], b["interpreter"]) == (0, 0)
        for me in (a, b):
            assert_locked(me)
            assert me["activation_error"] is None
            assert me["bootstrap_ran"] is False, me
        for report in both(server, TO_FORBIDDEN):
            assert_refused(report)
        assert arrivals() == {}
        server.wait_log(ACTIVATE_NO_OP)

    def test_with_lazy_apps_each_worker_loads_both_and_the_second_joins(self) -> None:
        server = start_server(
            mounts("--lazy-apps", processes=2), env={"TETH_ACTIVATE": "locked"}, ready="/a/whoami"
        )
        for mount, interpreter in (("/a", 0), ("/b", 1)):
            for pid, me in server.each_worker(mount + "/pyinfo", 2).items():
                assert me["imported_in_pid"] == pid
                assert me["interpreter"] == interpreter, me
                assert_locked(me)
                assert me["activation_error"] is None
            for report in server.each_worker(mount + TO_FORBIDDEN, 2).values():
                assert_refused(report)
        assert arrivals() == {}

    def test_unlocked_policies_are_kept_apart_in_the_process_but_not_in_a_child(self) -> None:
        """Limit: without a lock each interpreter enforces its own policy, but the policy a
        Python child inherits is one variable of the process, written by whoever activated
        last.  A child of "a" gets the policy of "b" and reaches what "a" forbids.
        """
        env = {"TETH_ACTIVATE": "plain", "TETH_ALLOW_B": OTHER_RULE}
        server = start_server(mounts(), env=env, ready="/a/whoami")
        assert_refused(ask(server, "/a" + TO_FORBIDDEN))
        assert_refused(ask(server, "/b" + TO_ALLOWED))
        assert arrivals() == {}
        assert ask(server, "/a" + TO_ALLOWED)["outcome"] == "reached"
        assert ask(server, "/b" + TO_FORBIDDEN)["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1, AT_FORBIDDEN: 1}

        report = ask(server, "/a" + probe_path("launch", argv=json.dumps(child(PYTHON))))
        assert report["child"]["active"] is True, report
        assert report["child"]["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 1, AT_FORBIDDEN: 2}
