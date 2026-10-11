"""gunicorn with its own worker classes: sync and gthread, with and without ``--preload``.

Without ``--preload`` every worker imports the application, and with it the
policy, after the fork.  With ``--preload`` the master imports it once and the
workers are forked from a process that already holds the policy.

The application is ``probe_wsgi:application`` from ``harness/apps``; it allows
``allowed.test:9001``.  Each test asserts what the application reported and
what arrived in the world.
"""

from __future__ import annotations

import signal
from typing import Any

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

GUNICORN = ["gunicorn", "probe_wsgi:application", "--bind", "127.0.0.1:{port}"]
WORKER_MODELS = {
    "sync": [],
    "sync-preload": ["--preload"],
    "gthread": ["--worker-class", "gthread", "--threads", "4"],
    "gthread-preload": ["--worker-class", "gthread", "--threads", "4", "--preload"],
}
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"

OPS = ["connect", "urllib"]
#: Destinations the allow list does not cover.
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]


def gunicorn(model: str, *options: str, workers: int = 2) -> list[str]:
    return [*GUNICORN, "--workers", str(workers), *WORKER_MODELS[model], *options]


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_locked(report: dict[str, Any]) -> None:
    assert report["active"] is True, report
    assert report["locked"] is True, report


# ── Every worker class, two workers, a locked policy ──────────────────


@pytest.fixture(scope="module", params=list(WORKER_MODELS))
def model(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(model: str) -> Server:
    return start_server(gunicorn(model), env={"TETH_ACTIVATE": "locked"})


class TestWorkerModels:
    def test_every_worker_holds_the_locked_policy(self, server: Server, model: str) -> None:
        answers = server.each_worker("/whoami", 2)
        assert server.pid not in answers
        for pid, me in answers.items():
            assert_locked(me)
            assert me["ppid"] == server.pid
            # Where the application was imported, and so where activate() ran.
            assert me["imported_in_pid"] == (server.pid if "preload" in model else pid)
            assert (me["thread"] == "MainThread") is model.startswith("sync")

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

    def test_an_uncaught_refusal_is_a_500_and_the_workers_survive(self, server: Server) -> None:
        before = server.each_worker("/whoami", 2)
        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)
        assert server.get(path).status == 500
        assert arrivals() == {}
        server.wait_log("Error handling request")
        server.wait_log(f"EgressBlocked: Blocked by tethered: {FORBIDDEN_NAME} is not in the allow")
        assert set(server.each_worker("/whoami", 2)) == set(before)

    def test_a_python_child_of_every_worker_inherits_the_locked_policy(
        self, server: Server
    ) -> None:
        path = probe_path("child", FORBIDDEN_NAME, OTHER_PORT)
        for pid, report in server.each_worker(path, 2).items():
            assert report["outcome"] == "reached", report
            child = report["child"]
            assert child["ppid"] == pid
            assert_locked(child)
            assert_refused(child)
        assert arrivals() == {}


# ── Workers that are started later ────────────────────────────────────


class TestLaterWorkers:
    def test_a_worker_started_after_max_requests_enforces_the_policy(self, model: str) -> None:
        command = gunicorn(model, "--max-requests", "5")
        server = start_server(command, env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)

        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2, exclude=first).values():
            assert report["ppid"] == server.pid
            assert_locked(report)
            assert_refused(report)
        assert arrivals() == {}
        # gunicorn's own words: the new workers came from --max-requests, not from a crash.
        server.wait_log("Autorestarting worker after current request")

    def test_a_worker_started_by_a_reload_enforces_the_policy(self, model: str) -> None:
        server = start_server(gunicorn(model), env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)
        server.send_signal(signal.SIGHUP)

        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2, exclude=first).values():
            assert report["ppid"] == server.pid
            assert_locked(report)
            assert_refused(report)
        assert arrivals() == {}
        # gunicorn's own words for a reload.
        server.wait_log("Hang up: Master")

        path = probe_path("connect", ALLOWED_NAME, ALLOWED_PORT)
        for report in server.each_worker(path, 2, exclude=first).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}


# ── What a handler launches ───────────────────────────────────────────


@pytest.fixture(scope="class")
def locked() -> Server:
    """One sync worker, a locked policy, the default ``external_subprocess_policy`` (warn)."""
    return start_server(gunicorn("sync", workers=1), env={"TETH_ACTIVATE": "locked"})


@pytest.fixture(scope="class")
def blocking() -> Server:
    """The same, with ``external_subprocess_policy="block"``."""
    env = {"TETH_ACTIVATE": "locked", "TETH_ESP": "block"}
    return start_server(gunicorn("sync", workers=1), env=env)


class TestLaunchesUnderALock:
    def test_a_child_started_with_sys_executable_inherits_the_lock(self, locked: Server) -> None:
        report = locked.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert_locked(report["child"])
        assert_refused(report["child"])
        assert arrivals() == {}
        assert "external subprocess" not in locked.log_of_this_test

    def test_a_child_started_as_python3_is_warned_about_and_inherits_all_the_same(
        self, locked: Server
    ) -> None:
        # argv[0] is not sys.executable, so tethered cannot vouch for the
        # child and says so.  This python3 is the same installation.
        report = locked.probe("child", FORBIDDEN_NAME, OTHER_PORT, how="path_python")
        assert report["outcome"] == "reached", report
        assert_locked(report["child"])
        assert_refused(report["child"])
        assert arrivals() == {}
        locked.wait_log(r"external subprocess launch detected: subprocess\.Popen\(python3\)")

    def test_a_child_given_an_environment_without_the_policy_gets_the_lock_all_the_same(
        self, locked: Server
    ) -> None:
        # The lock promises that no Python starts without the policy.  It
        # keeps that by adding the variable to the child's environment (it
        # used to refuse the launch).
        report = locked.probe("child", FORBIDDEN_NAME, OTHER_PORT, how="clean_env")
        assert report["outcome"] == "reached", report
        assert_locked(report["child"])
        assert_refused(report["child"])
        assert arrivals() == {}

    def test_a_child_started_without_site_is_warned_about_and_holds_no_policy(
        self, locked: Server
    ) -> None:
        # "python -S" does not run the bootstrap: a documented limit, which
        # external_subprocess_policy="block" closes (see the next class).
        report = locked.probe("child", FORBIDDEN_NAME, OTHER_PORT, how="no_site")
        assert report["outcome"] == "reached", report
        assert report["child"]["active"] is False, report
        assert report["child"]["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        locked.wait_log("external subprocess launch detected")

    def test_a_tool_is_warned_about_and_is_not_restricted(self, locked: Server) -> None:
        report = locked.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["stdout"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}"
        assert arrivals() == {AT_FORBIDDEN: 1}
        locked.wait_log(r"external subprocess launch detected: subprocess\.Popen\(bash\)")


class TestLaunchesUnderBlock:
    @pytest.mark.parametrize("how", ["executable", "clean_env"])
    def test_a_child_started_with_sys_executable_is_launched_and_inherits(
        self, blocking: Server, how: str
    ) -> None:
        # With or without the policy in the environment it is given: a child
        # that gets the policy is not an external launch.
        report = blocking.probe("child", FORBIDDEN_NAME, OTHER_PORT, how=how)
        assert report["outcome"] == "reached", report
        assert_locked(report["child"])
        assert report["child"]["external_subprocess_policy"] == "block"
        assert_refused(report["child"])
        assert arrivals() == {}

    @pytest.mark.parametrize("how", ["path_python", "no_site"])
    def test_any_other_python_child_is_not_launched(self, blocking: Server, how: str) -> None:
        report = blocking.probe("child", FORBIDDEN_NAME, OTHER_PORT, how=how)
        assert_refused(report, SUBPROCESS_BLOCKED)
        assert arrivals() == {}

    def test_a_tool_is_not_launched(self, blocking: Server) -> None:
        assert_refused(blocking.probe("tool", FORBIDDEN_NAME, OTHER_PORT), SUBPROCESS_BLOCKED)
        assert arrivals() == {}
        blocking.wait_log(r"blocked external subprocess launch: subprocess\.Popen\(bash\)")


class TestLaunchesWithoutALock:
    def test_a_child_given_an_environment_without_the_policy_gets_it_all_the_same(self) -> None:
        # Not locked: the missing variable is added to the child's
        # environment instead of the launch being refused.
        server = start_server(gunicorn("sync", workers=1), env={"TETH_ACTIVATE": "plain"})
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT, how="clean_env")
        assert report["outcome"] == "reached", report
        assert report["child"]["active"] is True, report
        assert report["child"]["locked"] is False, report
        assert_refused(report["child"])
        assert arrivals() == {}


# ── The modes that do not refuse ──────────────────────────────────────


class TestNotEnforcing:
    def test_without_tethered_the_forbidden_destination_is_reached(self) -> None:
        # The control: the same route, no policy.  It shows that the world's
        # counters move when something does arrive.
        server = start_server(gunicorn("sync", workers=1), env={"TETH_ACTIVATE": "none"})
        assert server.get("/whoami").json()["tethered_imported"] is False
        report = server.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}

    def test_log_only_reports_the_connection_and_lets_it_through(self) -> None:
        server = start_server(gunicorn("sync", workers=1), env={"TETH_ACTIVATE": "log_only"})
        report = server.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(f"tethered: would block getaddrinfo for {FORBIDDEN_NAME}")
        server.wait_log(f"tethered: would block connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")
