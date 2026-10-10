"""uvicorn on the standard asyncio event loop.

Every command line here names the loop (``--loop asyncio``), and the first
test of each group checks which loop the application really runs on: the
audit hook sees what asyncio's own loops do.  What uvicorn picks by default,
and uvloop, are not this suite's subject.

The application is ``probe_asgi:app`` from ``harness/apps``; it allows
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
    LOOPBACK_ADDR,
    OTHER_PORT,
    Server,
    arrivals,
    probe_path,
    start_server,
)

UVICORN = [
    "uvicorn",
    "probe_asgi:app",
    "--host=127.0.0.1",
    "--port={port}",
    "--loop=asyncio",
]
LAUNCHER = ["python", "launcher.py"]
STANDARD_LOOP = "asyncio.unix_events._UnixSelectorEventLoop"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"

#: The ways to open a TCP connection from a coroutine.
STREAM_OPS = ["open_connection", "create_connection", "sock_connect", "to_thread", "connect"]
#: Destinations the allow list does not cover.
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_enforcing(report: dict[str, Any], *, locked: bool) -> None:
    assert report["active"] is True, report
    assert report["locked"] is locked, report
    assert report["loop"] == STANDARD_LOOP, report


# ── One process ───────────────────────────────────────────────────────


@pytest.fixture(scope="module", params=["plain", "locked"])
def mode(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(mode: str) -> Server:
    """One uvicorn process whose application activates the policy when it is imported."""
    return start_server(UVICORN, env={"TETH_ACTIVATE": mode})


class TestOneProcess:
    def test_the_application_runs_on_the_standard_loop_with_the_policy(
        self, server: Server, mode: str
    ) -> None:
        me = server.get("/whoami").json()
        assert_enforcing(me, locked=mode == "locked")
        assert me["pid"] == server.pid
        assert server.pids() == [server.pid]

    @pytest.mark.parametrize("op", STREAM_OPS)
    def test_the_allowed_destination_is_reached(self, server: Server, op: str) -> None:
        report = server.probe(op, ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert arrivals() == {AT_ALLOWED: 1}

    @pytest.mark.parametrize("op", STREAM_OPS)
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_destination_outside_the_allow_list_is_refused(
        self, server: Server, op: str, host: str, port: int
    ) -> None:
        assert_refused(server.probe(op, host, port))
        assert arrivals() == {}

    @pytest.mark.parametrize("op", STREAM_OPS)
    def test_loopback_stays_reachable(self, server: Server, op: str) -> None:
        report = server.probe(op, LOOPBACK_ADDR, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {f"{LOOPBACK_ADDR}:{OTHER_PORT}/tcp": 1}

    def test_a_lookup_of_the_allowed_name_is_answered(self, server: Server) -> None:
        report = server.probe("getaddrinfo", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert report["addresses"] == [ALLOWED_ADDR]

    def test_a_lookup_of_a_forbidden_name_is_refused(self, server: Server) -> None:
        assert_refused(server.probe("getaddrinfo", FORBIDDEN_NAME, OTHER_PORT))
        assert arrivals() == {}

    @pytest.mark.parametrize("op", ["datagram_connected", "datagram_unconnected"])
    def test_a_datagram_reaches_the_allowed_destination(self, server: Server, op: str) -> None:
        report = server.probe(op, ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {f"{ALLOWED_ADDR}:{ALLOWED_PORT}/udp": 1}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_connected_datagram_endpoint_is_refused(
        self, server: Server, host: str, port: int
    ) -> None:
        assert_refused(server.probe("datagram_connected", host, port))
        assert arrivals() == {}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_refused_datagram_is_not_sent_and_closes_the_transport(
        self, server: Server, host: str, port: int
    ) -> None:
        # transport.sendto(data, addr) does not raise: asyncio hands the
        # refusal to the protocol and closes the transport.
        report = server.probe("datagram_unconnected", host, port)
        assert_refused(report)
        assert report["notes"] == ["delivered to the protocol's connection_lost()"]
        assert arrivals() == {}
        server.wait_log("Fatal write error on datagram transport")

    def test_an_uncaught_refusal_is_a_500_and_the_server_keeps_serving(
        self, server: Server
    ) -> None:
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)
        assert server.get(path).status == 500
        assert arrivals() == {}
        server.wait_log("Exception in ASGI application")
        server.wait_log(f"EgressBlocked: Blocked by tethered: {FORBIDDEN_NAME} is not in the allow")
        assert server.get("/whoami").json()["pid"] == server.pid
        assert server.probe("open_connection", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"

    def test_a_python_child_inherits_the_policy(self, server: Server, mode: str) -> None:
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        child = report["child"]
        assert child["ppid"] == server.pid
        assert child["active"] is True, child
        assert child["locked"] is (mode == "locked"), child
        assert_refused(child)
        assert arrivals() == {}

    def test_a_python_child_reaches_the_allowed_destination(self, server: Server) -> None:
        child = server.probe("child", ALLOWED_NAME, ALLOWED_PORT)["child"]
        assert child["outcome"] == "reached", child
        assert arrivals() == {AT_ALLOWED: 1}


# ── What the policy says about other launches ─────────────────────────


class TestExternalTools:
    def test_by_default_a_tool_is_launched_with_a_warning_and_is_not_restricted(self) -> None:
        server = start_server(UVICORN, env={"TETH_ACTIVATE": "locked"})
        report = server.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["stdout"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}"
        # The tool is not Python: nothing enforces the allow list inside it.
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(r"external subprocess launch detected: subprocess\.Popen\(bash\)")

    def test_under_block_a_tool_is_not_launched(self) -> None:
        server = start_server(UVICORN, env={"TETH_ACTIVATE": "locked", "TETH_ESP": "block"})
        assert_refused(server.probe("tool", FORBIDDEN_NAME, OTHER_PORT), SUBPROCESS_BLOCKED)
        assert arrivals() == {}
        server.wait_log(r"blocked external subprocess launch: subprocess\.Popen\(bash\)")

    def test_under_block_a_python_child_is_still_launched_and_inherits(self) -> None:
        server = start_server(UVICORN, env={"TETH_ACTIVATE": "locked", "TETH_ESP": "block"})
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["child"]["locked"] is True, report
        assert_refused(report["child"])
        assert arrivals() == {}

    def test_under_allow_a_tool_is_launched_without_a_warning(self) -> None:
        server = start_server(UVICORN, env={"TETH_ACTIVATE": "locked", "TETH_ESP": "allow"})
        report = server.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.stop()
        assert "external subprocess" not in server.log


# ── The modes that do not refuse ──────────────────────────────────────


class TestNotEnforcing:
    def test_without_tethered_the_forbidden_destination_is_reached(self) -> None:
        # The control: the same route, no policy.  It shows that the world's
        # counters move when something does arrive.
        server = start_server(UVICORN, env={"TETH_ACTIVATE": "none"})
        assert server.get("/whoami").json()["tethered_imported"] is False
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}

    def test_log_only_reports_the_connection_and_lets_it_through(self) -> None:
        server = start_server(UVICORN, env={"TETH_ACTIVATE": "log_only"})
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")
        server.wait_log(f"tethered: blocked connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")


# ── --workers ─────────────────────────────────────────────────────────


@pytest.fixture(scope="class")
def workers() -> Server:
    """uvicorn's supervisor with two worker processes; each imports the application."""
    return start_server([*UVICORN, "--workers", "2"], env={"TETH_ACTIVATE": "locked"})


class TestWorkers:
    def test_each_worker_activates_the_policy_when_it_imports_the_application(
        self, workers: Server
    ) -> None:
        answers = workers.each_worker("/whoami", 2)
        assert workers.pid not in answers
        for pid, me in answers.items():
            assert_enforcing(me, locked=True)
            assert me["ppid"] == workers.pid
            assert me["imported_in_pid"] == pid

    def test_every_worker_reaches_the_allowed_destination(self, workers: Server) -> None:
        path = probe_path("open_connection", ALLOWED_NAME, ALLOWED_PORT)
        for report in workers.each_worker(path, 2).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_every_worker_refuses_a_destination_outside_the_allow_list(
        self, workers: Server, host: str, port: int
    ) -> None:
        for report in workers.each_worker(probe_path("open_connection", host, port), 2).values():
            assert_refused(report)
        assert arrivals() == {}

    def test_a_worker_that_replaces_a_killed_one_enforces_the_policy(self) -> None:
        server = start_server([*UVICORN, "--workers", "2"], env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)
        server.send_signal(signal.SIGKILL, min(first))

        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        (replacement,) = server.each_worker(path, 1, exclude=first).values()
        assert replacement["ppid"] == server.pid
        assert_enforcing(replacement, locked=True)
        assert_refused(replacement)
        assert arrivals() == {}


# ── A launcher that locks the policy and then runs uvicorn ────────────

LAUNCHES = {
    "workers-only-inherit": {"TETH_ACTIVATE": "none"},
    "application-activates-the-same-policy": {"TETH_ACTIVATE": "locked"},
    "workers-only-inherit-under-block": {"TETH_ACTIVATE": "none", "TETH_ESP": "block"},
}


@pytest.fixture(scope="class", params=list(LAUNCHES))
def launched(request: pytest.FixtureRequest) -> Server:
    """``launcher.py``: ``activate(locked=True)``, then ``uvicorn.run(workers=2)``."""
    return start_server(LAUNCHER, env=LAUNCHES[request.param])


class TestLauncher:
    def test_both_workers_hold_the_locked_policy(self, launched: Server) -> None:
        answers = launched.each_worker("/whoami", 2)
        for me in answers.values():
            assert_enforcing(me, locked=True)
            assert me["ppid"] == launched.pid

    def test_both_workers_reach_the_allowed_destination(self, launched: Server) -> None:
        path = probe_path("open_connection", ALLOWED_NAME, ALLOWED_PORT)
        for report in launched.each_worker(path, 2).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_both_workers_refuse_a_destination_outside_the_allow_list(
        self, launched: Server, host: str, port: int
    ) -> None:
        for report in launched.each_worker(probe_path("open_connection", host, port), 2).values():
            assert_refused(report)
        assert arrivals() == {}

    def test_a_python_child_of_a_worker_inherits_the_locked_policy(self, launched: Server) -> None:
        report = launched.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["child"]["locked"] is True, report
        assert_refused(report["child"])
        assert arrivals() == {}

    def test_a_worker_that_replaces_a_killed_one_inherits_the_locked_policy(self) -> None:
        server = start_server(LAUNCHER, env={"TETH_ACTIVATE": "none"})
        first = server.each_worker("/whoami", 2)
        server.send_signal(signal.SIGKILL, min(first))

        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        (replacement,) = server.each_worker(path, 1, exclude=first).values()
        assert_enforcing(replacement, locked=True)
        assert_refused(replacement)
        assert arrivals() == {}

    def test_under_block_a_worker_does_not_launch_a_tool(self) -> None:
        server = start_server(LAUNCHER, env={"TETH_ACTIVATE": "none", "TETH_ESP": "block"})
        assert_refused(server.probe("tool", FORBIDDEN_NAME, OTHER_PORT), SUBPROCESS_BLOCKED)
        assert arrivals() == {}

    def test_the_applications_activation_of_the_policy_a_worker_inherited_is_a_no_op(
        self,
    ) -> None:
        server = start_server(LAUNCHER, env={"TETH_ACTIVATE": "locked"})
        server.each_worker("/whoami", 2)
        # Each worker says so once, when it imports the application.
        assert server.log.count("tethered: activate() no-op") == 2, server.log

    def test_a_worker_that_only_inherits_never_calls_activate(self) -> None:
        server = start_server(LAUNCHER, env={"TETH_ACTIVATE": "none"})
        for me in server.each_worker("/whoami", 2).values():
            assert_enforcing(me, locked=True)
        assert "activate() no-op" not in server.log
        assert "probe: pid" not in server.log, "the application activated after all"
