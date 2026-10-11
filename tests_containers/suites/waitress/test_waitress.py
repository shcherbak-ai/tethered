"""waitress: a pure-Python WSGI server, one process, a fixed pool of threads.

There are no workers to follow: the process that is started serves every
request, on one of its threads.  Two arrangements: ``waitress-serve``, which
imports the application (and with it the policy) after the server has
started, and ``launcher.py``, which activates before it imports waitress.

The application is ``probe_wsgi:application``.
"""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from harness import (
    ALLOWED_ADDR,
    ALLOWED_NAME,
    ALLOWED_PORT,
    FORBIDDEN_ADDR,
    FORBIDDEN_NAME,
    OTHER_PORT,
    SUITE_DIR,
    Server,
    arrivals,
    probe_path,
    start_server,
)

ARRANGEMENTS = {
    "waitress-serve": [
        "waitress-serve",
        "--listen=127.0.0.1:{port}",
        "--threads=4",
        "probe_wsgi:application",
    ],
    "launcher": [sys.executable, str(SUITE_DIR / "launcher.py")],
}
WAITRESS = ARRANGEMENTS["waitress-serve"]
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"

OPS = ["connect", "urllib"]
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_locked(report: dict[str, Any]) -> None:
    assert (report["active"], report["locked"]) == (True, True), report


@pytest.fixture(scope="module", params=list(ARRANGEMENTS))
def arrangement(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(arrangement: str) -> Server:
    return start_server(ARRANGEMENTS[arrangement], env={"TETH_ACTIVATE": "locked"})


class TestThreads:
    def test_the_one_process_serves_on_its_threads_and_holds_the_locked_policy(
        self, server: Server
    ) -> None:
        me = server.get("/whoami").json()
        assert me["pid"] == server.pid
        assert me["imported_in_pid"] == server.pid
        assert me["thread"].startswith("waitress-"), me
        assert_locked(me)
        assert server.pids() == [server.pid]

    @pytest.mark.parametrize("op", OPS)
    def test_the_allowed_destination_is_reached(self, server: Server, op: str) -> None:
        report = server.probe(op, ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert arrivals() == {AT_ALLOWED: 1}

    @pytest.mark.parametrize("op", OPS)
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_destination_outside_the_allow_list_is_refused(
        self, server: Server, op: str, host: str, port: int
    ) -> None:
        assert_refused(server.probe(op, host, port))
        assert arrivals() == {}

    def test_requests_on_all_threads_at_once_each_get_their_own_answer(
        self, server: Server
    ) -> None:
        # Twenty-four requests on four threads: lookups and connections of
        # allowed and forbidden destinations interleave.
        destinations = [(ALLOWED_NAME, ALLOWED_PORT), (FORBIDDEN_NAME, ALLOWED_PORT)] * 12

        def ask(destination: tuple[str, int]) -> dict[str, Any]:
            return server.probe("connect", *destination, hold=0.05)

        with ThreadPoolExecutor(max_workers=len(destinations)) as pool:
            reports = list(pool.map(ask, destinations))
        for (host, _), report in zip(destinations, reports, strict=True):
            assert report["outcome"] == ("reached" if host == ALLOWED_NAME else "blocked"), report
        assert {report["pid"] for report in reports} == {server.pid}
        assert len({report["thread"] for report in reports}) == 4
        assert arrivals() == {AT_ALLOWED: 12}

    def test_an_uncaught_refusal_is_a_500_and_the_server_keeps_serving(
        self, server: Server
    ) -> None:
        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)
        assert server.get(path).status == 500
        assert arrivals() == {}
        server.wait_log(f"EgressBlocked: Blocked by tethered: {FORBIDDEN_NAME} is not in the allow")
        assert server.get("/whoami").json()["pid"] == server.pid

    def test_a_python_child_inherits_the_locked_policy(self, server: Server) -> None:
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["child"]["ppid"] == server.pid
        assert_locked(report["child"])
        assert_refused(report["child"])
        assert arrivals() == {}
        assert "external subprocess" not in server.log_of_this_test

    def test_a_child_given_an_environment_without_the_policy_gets_the_lock_all_the_same(
        self, server: Server
    ) -> None:
        # The lock adds the variable to the child's environment (it used to
        # refuse the launch).
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT, how="clean_env")
        assert report["outcome"] == "reached", report
        assert_locked(report["child"])
        assert_refused(report["child"])
        assert arrivals() == {}

    def test_a_tool_is_warned_about_and_is_not_restricted(self, server: Server) -> None:
        report = server.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(r"external subprocess launch detected: subprocess\.Popen\(bash\)")


class TestOtherPolicies:
    def test_under_block_only_a_child_started_with_sys_executable_is_launched(self) -> None:
        server = start_server(WAITRESS, env={"TETH_ACTIVATE": "locked", "TETH_ESP": "block"})
        for how in ("executable", "clean_env"):
            report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT, how=how)
            assert report["outcome"] == "reached", report
            assert_locked(report["child"])
            assert_refused(report["child"])
        for how in ("path_python", "no_site"):
            assert_refused(
                server.probe("child", FORBIDDEN_NAME, OTHER_PORT, how=how), SUBPROCESS_BLOCKED
            )
        assert_refused(server.probe("tool", FORBIDDEN_NAME, OTHER_PORT), SUBPROCESS_BLOCKED)
        assert arrivals() == {}

    def test_an_unlocked_policy_is_enforced_and_reaches_a_child_with_a_clean_environment(
        self,
    ) -> None:
        server = start_server(WAITRESS, env={"TETH_ACTIVATE": "plain"})
        me = server.get("/whoami").json()
        assert (me["active"], me["locked"]) == (True, False), me
        assert_refused(server.probe("connect", FORBIDDEN_NAME, OTHER_PORT))
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT, how="clean_env")
        assert report["outcome"] == "reached", report
        assert report["child"]["active"] is True, report
        assert_refused(report["child"])
        assert arrivals() == {}
        assert server.probe("connect", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}

    def test_log_only_reports_the_connection_and_lets_it_through(self) -> None:
        server = start_server(WAITRESS, env={"TETH_ACTIVATE": "log_only"})
        report = server.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(f"tethered: would block getaddrinfo for {FORBIDDEN_NAME}")
        server.wait_log(f"tethered: would block connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")

    def test_without_tethered_the_forbidden_destination_is_reached(self) -> None:
        # The control: the same route, no policy.
        server = start_server(WAITRESS, env={"TETH_ACTIVATE": "none"})
        assert server.get("/whoami").json()["tethered_imported"] is False
        report = server.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
