"""tornado: its HTTP server on asyncio, and its own client classes.

``probe_tornado.py`` is the application and the script that serves it.

* One process (``HTTPServer.listen`` and ``asyncio.run``), forked processes
  (``bind_sockets`` and ``fork_processes``, where the parent replaces a child
  that dies) and ``tornado.autoreload`` (which replaces the process with a new
  one of the same pid): all on the standard event loop, and the policy holds
  through each of them.
* ``AsyncHTTPClient`` as tornado ships it (``simple_httpclient``),
  ``TCPClient``, ``Resolver`` and ``tornado.process.Subprocess`` go through
  Python's ``socket`` and ``subprocess`` modules: seen and enforced, and a
  refusal is raised to the caller as it is.
* ``AsyncHTTPClient`` configured to use ``tornado.curl_httpclient`` hands the
  request to libcurl (pycurl).  Nothing of it is seen: the lookup, the
  connection and the request are made below Python, no audit event is raised,
  and a locked, fail-closed policy lets a request to a forbidden destination
  through without a word.  ``TestCurlHttpClient`` pins that.

The application allows ``allowed.test:9001``.  Each test asserts what the
application reported and what arrived in the world.
"""

from __future__ import annotations

import os
import signal
import time
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
    Server,
    arrivals,
    dns_queries,
    probe_path,
    start_server,
)

if TYPE_CHECKING:
    from pathlib import Path

STANDARD_LOOP = "asyncio.unix_events._UnixSelectorEventLoop"
SIMPLE_CLIENT = "tornado.simple_httpclient.SimpleAsyncHTTPClient"
CURL_CLIENT = "tornado.curl_httpclient.CurlAsyncHTTPClient"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"

TORNADO = ["python", "probe_tornado.py"]
#: The ways to open a TCP connection from a handler: tornado's own, then asyncio's.
STREAM_OPS = [
    "http_client",
    "tcp_client",
    "open_connection",
    "create_connection",
    "sock_connect",
    "to_thread",
    "connect",
]
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
    """tornado in one process; the application activates the policy when it is imported."""
    return start_server(TORNADO, env={"TETH_ACTIVATE": mode})


class TestOneProcess:
    def test_the_only_process_runs_the_standard_loop_with_the_policy(
        self, server: Server, mode: str
    ) -> None:
        me = server.get("/whoami").json()
        assert_enforcing(me, locked=mode == "locked")
        assert me["http_client"] == SIMPLE_CLIENT
        assert me["pid"] == server.pid
        assert server.pids() == [server.pid]

    def test_the_allowed_destination_is_reached(self, server: Server) -> None:
        for op in STREAM_OPS:
            report = server.probe(op, ALLOWED_NAME, ALLOWED_PORT)
            assert report["outcome"] == "reached", report
            assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert arrivals() == {AT_ALLOWED: len(STREAM_OPS)}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_destination_outside_the_allow_list_is_refused(
        self, server: Server, host: str, port: int
    ) -> None:
        for op in STREAM_OPS:
            assert_refused(server.probe(op, host, port))
        assert arrivals() == {}
        # Not even a lookup of the forbidden name left the process.
        assert not [query for query in dns_queries() if query.startswith(FORBIDDEN_NAME)]

    def test_loopback_stays_reachable(self, server: Server) -> None:
        for op in STREAM_OPS:
            report = server.probe(op, LOOPBACK_ADDR, OTHER_PORT)
            assert report["outcome"] == "reached", report
        assert arrivals() == {f"{LOOPBACK_ADDR}:{OTHER_PORT}/tcp": len(STREAM_OPS)}

    @pytest.mark.parametrize("op", ["resolver", "getaddrinfo"])
    def test_a_lookup_of_the_allowed_name_is_answered(self, server: Server, op: str) -> None:
        report = server.probe(op, ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert report["addresses"] == [ALLOWED_ADDR]

    @pytest.mark.parametrize("op", ["resolver", "getaddrinfo"])
    def test_a_lookup_of_a_forbidden_name_is_refused(self, server: Server, op: str) -> None:
        assert_refused(server.probe(op, FORBIDDEN_NAME, OTHER_PORT))
        assert arrivals() == {}

    @pytest.mark.parametrize("op", ["datagram_connected", "datagram_unconnected"])
    def test_a_datagram_reaches_the_allowed_destination(self, server: Server, op: str) -> None:
        report = server.probe(op, ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {f"{ALLOWED_ADDR}:{ALLOWED_PORT}/udp": 1}

    @pytest.mark.parametrize("op", ["datagram_connected", "datagram_unconnected"])
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_refused_datagram_is_not_sent(
        self, server: Server, op: str, host: str, port: int
    ) -> None:
        assert_refused(server.probe(op, host, port))
        assert arrivals() == {}

    def test_an_uncaught_refusal_is_a_500_and_the_server_keeps_serving(
        self, server: Server
    ) -> None:
        path = probe_path("http_client", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)
        assert server.get(path).status == 500
        assert arrivals() == {}
        server.wait_log("Uncaught exception GET /http_client")
        server.wait_log(f"EgressBlocked: Blocked by tethered: {FORBIDDEN_NAME} is not in the allow")
        assert server.get("/whoami").json()["pid"] == server.pid
        assert server.probe("http_client", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"

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

    def test_a_tool_is_launched_with_a_warning_and_is_not_restricted(self, server: Server) -> None:
        # tornado.process.Subprocess, under the default external_subprocess_policy.
        # The tool is not Python: nothing enforces the allow list inside it.
        report = server.probe("subprocess", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["stdout"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}"
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(r"external subprocess launch detected: subprocess\.Popen\(bash\)")

    def test_under_block_a_tool_is_not_launched(self) -> None:
        blocking = start_server(TORNADO, env={"TETH_ACTIVATE": "locked", "TETH_ESP": "block"})
        assert_refused(blocking.probe("subprocess", FORBIDDEN_NAME, OTHER_PORT), SUBPROCESS_BLOCKED)
        assert arrivals() == {}
        blocking.wait_log(r"blocked external subprocess launch: subprocess\.Popen\(bash\)")


# ── AsyncHTTPClient on libcurl ────────────────────────────────────────


class TestCurlHttpClient:
    def test_without_tethered_an_audit_hook_sees_nothing_of_a_request_made_by_libcurl(
        self,
    ) -> None:
        # The evidence under the limits below: no event, so nothing to act on.
        command = ["python", "traced_tornado.py", "client=curl"]
        server = start_server(command, env={"TETH_ACTIVATE": "none"})
        assert server.get("/whoami").json()["http_client"] == CURL_CLIENT
        for host in (FORBIDDEN_NAME, FORBIDDEN_ADDR):
            report = server.probe("http_client", host, OTHER_PORT)
            assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 2}
        # One event so far, from the server binding its own address; none for the requests.
        events = [line for line in server.log.splitlines() if line.startswith("AUDIT")]
        assert not [line for line in events if "forbidden" in line or FORBIDDEN_ADDR in line], (
            events
        )
        # The hook is there: tornado's own TCP client, in the same process, is seen.
        server.probe("tcp_client", FORBIDDEN_NAME, OTHER_PORT)
        server.wait_log(rf"AUDIT pid=\d+ socket\.getaddrinfo {FORBIDDEN_NAME}:{OTHER_PORT}")
        server.wait_log(rf"AUDIT pid=\d+ socket\.connect {FORBIDDEN_ADDR}:{OTHER_PORT}")

    @pytest.mark.parametrize("policy", ["plain", "locked", "locked,fail_closed"])
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_request_to_a_forbidden_destination_goes_through(
        self, policy: str, host: str, port: int
    ) -> None:
        """Limit: nothing ``curl_httpclient`` does is seen, so nothing of it is refused."""
        server = start_server([*TORNADO, "client=curl"], env={"TETH_ACTIVATE": policy})
        me = server.get("/whoami").json()
        assert me["active"] is True
        assert me["http_client"] == CURL_CLIENT

        report = server.probe("http_client", host, port)
        assert report["outcome"] == "reached", report
        address = FORBIDDEN_ADDR if host != ALLOWED_NAME else ALLOWED_ADDR
        assert report["reply"] == f"reached {address}:{port}"
        assert arrivals() == {f"{address}:{port}/tcp": 1}
        assert "tethered: blocked" not in server.log, server.log

        # The same destination through tornado's own client, in the same process, is refused.
        assert_refused(server.probe("tcp_client", host, port))
        assert arrivals() == {f"{address}:{port}/tcp": 1}

    def test_the_lookup_of_a_forbidden_name_leaves_the_process_too(self) -> None:
        """Limit: libcurl resolves the name itself; the query reaches the name server."""
        server = start_server([*TORNADO, "client=curl"], env={"TETH_ACTIVATE": "locked"})
        report = server.probe("http_client", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert [query for query in dns_queries() if query.startswith(FORBIDDEN_NAME)]

    def test_a_log_only_policy_does_not_report_the_request(self) -> None:
        """Limit: the same request is missing from a log-only policy's report."""
        server = start_server([*TORNADO, "client=curl"], env={"TETH_ACTIVATE": "log_only"})
        report = server.probe("http_client", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        assert "tethered: blocked" not in server.log, server.log
        # A connection made by tornado's own client is reported.
        server.probe("tcp_client", FORBIDDEN_NAME, OTHER_PORT)
        server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")


# ── fork_processes ────────────────────────────────────────────────────


@pytest.fixture(scope="class", params=["plain", "locked"])
def forked(request: pytest.FixtureRequest) -> Server:
    """A parent that imported the application, and with it the policy, and forked two children."""
    return start_server([*TORNADO, "processes=2"], env={"TETH_ACTIVATE": request.param})


class TestForkedProcesses:
    def test_every_child_holds_the_policy_it_was_forked_with(self, forked: Server) -> None:
        answers = forked.each_worker("/whoami", 2)
        assert forked.pid not in answers
        for me in answers.values():
            assert me["active"] is True, me
            assert me["loop"] == STANDARD_LOOP
            assert me["ppid"] == forked.pid
            assert me["imported_in_pid"] == forked.pid
        assert forked.log.count("probe: pid") == 1, forked.log

    @pytest.mark.parametrize("op", ["http_client", "open_connection"])
    def test_every_child_reaches_the_allowed_destination(self, forked: Server, op: str) -> None:
        for report in forked.each_worker(probe_path(op, ALLOWED_NAME, ALLOWED_PORT), 2).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize("op", ["http_client", "open_connection"])
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_every_child_refuses_a_destination_outside_the_allow_list(
        self, forked: Server, op: str, host: str, port: int
    ) -> None:
        for report in forked.each_worker(probe_path(op, host, port), 2).values():
            assert_refused(report)
        assert arrivals() == {}

    def test_a_python_child_of_every_child_inherits_the_policy(self, forked: Server) -> None:
        path = probe_path("child", FORBIDDEN_NAME, OTHER_PORT)
        for pid, report in forked.each_worker(path, 2).items():
            assert report["outcome"] == "reached", report
            child = report["child"]
            assert child["ppid"] == pid
            assert child["active"] is True, child
            assert child["locked"] is report["locked"], child
            assert_refused(child)
        assert arrivals() == {}

    def test_a_child_that_replaces_a_killed_one_enforces_the_policy(self) -> None:
        server = start_server([*TORNADO, "processes=2"], env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)
        server.send_signal(signal.SIGKILL, min(first))

        path = probe_path("http_client", FORBIDDEN_NAME, OTHER_PORT)
        (replacement,) = server.each_worker(path, 1, exclude=first).values()
        assert replacement["ppid"] == server.pid
        assert_enforcing(replacement, locked=True)
        assert_refused(replacement)
        assert arrivals() == {}
        # tornado's own words: the parent forked the replacement.
        server.wait_log(r"child \d+ \(pid \d+\) killed by signal 9, restarting")


# ── tornado.autoreload ────────────────────────────────────────────────


def reload_by_touching(server: Server, path: Path, before: dict[str, Any]) -> dict[str, Any]:
    """Touch ``path`` until autoreload has replaced the process; returns its new ``/whoami``.

    autoreload looks at its files twice a second and takes the first look as
    its baseline, so one touch right after the start can go unnoticed: the
    file is touched again every two seconds until the process is a new one.
    """
    stamp = time.time()
    touched = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            now = server.get("/whoami", timeout=2.0).json()
        except (OSError, AssertionError):
            now = None  # between the two processes nothing answers
        if now is not None and now["booted"] != before["booted"]:
            return now
        if touched is None or time.monotonic() - touched >= 2.0:
            stamp += 2.0
            os.utime(path, (stamp, stamp))
            touched = time.monotonic()
        time.sleep(0.1)
    raise AssertionError(f"autoreload did not replace the process:\n{server.log[-2000:]}")


class TestAutoreload:
    @pytest.mark.parametrize("policy", ["plain", "locked"])
    def test_the_process_that_replaces_this_one_holds_the_policy(
        self, policy: str, tmp_path: Path
    ) -> None:
        watched = tmp_path / "touch-me"
        watched.write_text("")
        environment = {"TETH_ACTIVATE": policy, "RELOAD_FILE": str(watched)}
        server = start_server([*TORNADO, "autoreload"], env=environment)
        before = server.get("/whoami").json()
        assert_enforcing(before, locked=policy == "locked")

        after = reload_by_touching(server, watched, before)
        # os.execv: the same pid, a new program image, the policy from the environment.
        assert after["pid"] == server.pid
        assert_enforcing(after, locked=policy == "locked")
        assert server.log.count(f"probe: pid {server.pid} activated tethered") == 2
        # Under a lock the new image inherited the policy when it started, so
        # the application's own activation of it changed nothing.
        expected = 1 if policy == "locked" else 0
        assert server.log.count("tethered: activate() no-op") == expected

        assert_refused(server.probe("http_client", FORBIDDEN_NAME, OTHER_PORT))
        assert_refused(server.probe("http_client", FORBIDDEN_ADDR, OTHER_PORT))
        assert arrivals() == {}
        assert server.probe("http_client", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}


# ── The modes that do not refuse ──────────────────────────────────────


class TestNotEnforcing:
    def test_without_tethered_the_forbidden_destination_is_reached(self) -> None:
        # The control: the same route, no policy.  It shows that the world's
        # counters move when something does arrive.
        server = start_server(TORNADO, env={"TETH_ACTIVATE": "none"})
        assert server.get("/whoami").json()["tethered_imported"] is False
        report = server.probe("http_client", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}

    def test_log_only_reports_the_connection_and_lets_it_through(self) -> None:
        server = start_server(TORNADO, env={"TETH_ACTIVATE": "log_only"})
        report = server.probe("http_client", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")
        server.wait_log(f"tethered: blocked connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")
