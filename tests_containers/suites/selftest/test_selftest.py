"""The harness tests itself: the suites rely on these properties.

No server framework is involved.  The world's counters, names and DNS
responder are exercised from the pytest process (which holds no policy),
``run_python`` with small scripts, and ``start_server`` with a server made of
the standard library that can be told to misbehave (``tiny_server.py``).
"""

from __future__ import annotations

import signal
import socket
import struct
import time

import pytest
from harness import (
    ALLOWED_ADDR,
    ALLOWED_NAME,
    ALLOWED_PORT,
    FORBIDDEN_ADDR,
    FORBIDDEN_NAME,
    LOOPBACK_ADDR,
    OTHER_PORT,
    PORTS,
    Server,
    arrivals,
    arrived,
    dns_queries,
    http_get,
    reset_arrivals,
    run_python,
    start_server,
)

TINY = ["python", "tiny_server.py", "{port}"]
REQUEST = b"GET / HTTP/1.0\r\n\r\n"

#: A script for run_python: one connection, reported the way the probe applications do.
CONNECT = """
import json, sys
import probe_common

host, port = sys.argv[1], int(sys.argv[2])
report = probe_common.whoami()
try:
    report.update(probe_common.tcp_connect(host, port), outcome="reached")
except Exception as exc:
    report.update(probe_common.describe_failure(exc))
print(json.dumps(report))
"""


def dns_query(name: str, qtype: int) -> tuple[int, list[str]]:
    """Ask the world's DNS responder; returns the response code and the A records."""
    question = b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
    question += b"\0" + struct.pack("!HH", qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5.0)
        sock.sendto(
            struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question, ("127.0.0.1", 53)
        )
        reply = sock.recv(512)
    ident, flags, _questions, answers = struct.unpack("!HHHH", reply[:8])
    assert ident == 0x1234
    assert flags & 0x8000, "not a response"
    records = []
    position = 12 + len(question)
    for _ in range(answers):
        rtype, _rclass, _ttl, length = struct.unpack("!HHIH", reply[position + 2 : position + 12])
        assert rtype == 1
        records.append(socket.inet_ntoa(reply[position + 12 : position + 12 + length]))
        position += 12 + length
    return flags & 0x000F, records


# ── The world ─────────────────────────────────────────────────────────


class TestWorld:
    @pytest.mark.parametrize("address", [ALLOWED_ADDR, FORBIDDEN_ADDR, LOOPBACK_ADDR])
    @pytest.mark.parametrize("port", PORTS)
    def test_a_connection_is_counted_where_it_arrived_and_answered(
        self, address: str, port: int
    ) -> None:
        with socket.create_connection((address, port), timeout=5.0) as sock:
            sock.sendall(REQUEST)
            answer = b""
            while chunk := sock.recv(4096):
                answer += chunk
        assert answer.startswith(b"HTTP/1.1 200 OK\r\n")
        assert answer.endswith(f"reached {address}:{port}\n".encode())
        assert arrivals() == {f"{address}:{port}/tcp": 1}
        assert arrived(address, port) == 1

    def test_a_connection_is_counted_as_soon_as_it_is_established(self) -> None:
        # Nothing is sent and nothing is read: the counter must not depend on
        # the conversation, nor on a settling time.
        for expected in (1, 2, 3):
            with socket.create_connection((FORBIDDEN_ADDR, OTHER_PORT), timeout=5.0):
                assert arrived(FORBIDDEN_NAME, OTHER_PORT) == expected

    @pytest.mark.parametrize("address", [ALLOWED_ADDR, FORBIDDEN_ADDR, LOOPBACK_ADDR])
    def test_a_datagram_is_counted_and_answered(self, address: str) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5.0)
            sock.sendto(b"ping", (address, OTHER_PORT))
            assert sock.recv(512) == f"reached {address}:{OTHER_PORT}\n".encode()
        assert arrivals() == {f"{address}:{OTHER_PORT}/udp": 1}
        assert arrived(address, OTHER_PORT, "udp") == 1
        assert arrived(address, OTHER_PORT) == 0

    def test_every_test_starts_with_the_counters_at_zero(self) -> None:
        assert arrivals() == {}
        assert dns_queries() == {}

    def test_reset_arrivals_sets_the_counters_to_zero(self) -> None:
        socket.create_connection((ALLOWED_ADDR, ALLOWED_PORT), timeout=5.0).close()
        dns_query(ALLOWED_NAME, 1)
        assert arrivals() and dns_queries()
        reset_arrivals()
        assert arrivals() == {}
        assert dns_queries() == {}

    @pytest.mark.parametrize(
        ("destination", "port", "proto"),
        [
            ("allowed.tset", 9001, "tcp"),
            ("10.77.0.30", 9001, "tcp"),
            (ALLOWED_NAME, 9004, "tcp"),
            (ALLOWED_NAME, 9001, "sctp"),
        ],
    )
    def test_asking_about_a_destination_the_world_does_not_have_is_an_error(
        self, destination: str, port: int, proto: str
    ) -> None:
        # Otherwise a typing mistake would read as "nothing arrived".
        with pytest.raises(ValueError, match=r"world|proto"):
            arrived(destination, port, proto)

    def test_the_names_resolve_without_dns(self) -> None:
        for name, address in ((ALLOWED_NAME, ALLOWED_ADDR), (FORBIDDEN_NAME, FORBIDDEN_ADDR)):
            found = socket.getaddrinfo(name, ALLOWED_PORT, type=socket.SOCK_STREAM)
            assert {info[4][0] for info in found} == {address}
        assert dns_queries() == {}

    def test_the_dns_responder_knows_the_two_names(self) -> None:
        assert dns_query(ALLOWED_NAME, 1) == (0, [ALLOWED_ADDR])
        assert dns_query(FORBIDDEN_NAME.upper(), 1) == (0, [FORBIDDEN_ADDR])
        # AAAA: the name exists and has no such record.
        assert dns_query(ALLOWED_NAME, 28) == (0, [])
        # NXDOMAIN for every other name.
        assert dns_query("elsewhere.test", 1) == (3, [])
        assert dns_queries() == {
            f"{ALLOWED_NAME}/A": 1,
            f"{FORBIDDEN_NAME}/A": 1,
            f"{ALLOWED_NAME}/AAAA": 1,
            "elsewhere.test/A": 1,
        }

    def test_a_name_the_world_does_not_know_fails_to_resolve_quickly(self) -> None:
        with pytest.raises(socket.gaierror):
            socket.getaddrinfo("elsewhere.test", 80)
        assert "elsewhere.test/A" in dns_queries()


# ── run_python ────────────────────────────────────────────────────────


class TestRunPython:
    @pytest.mark.parametrize("activate", ["plain", "locked", "fail_closed", "locked,fail_closed"])
    def test_the_policy_is_in_place_before_the_script_runs(self, activate: str) -> None:
        done = run_python(CONNECT, activate=activate, args=[FORBIDDEN_NAME, str(OTHER_PORT)])
        report = done.json()
        assert done.returncode == 0, done.stderr
        assert report["active"] is True
        assert report["locked"] is ("locked" in activate)
        assert report["fail_closed"] is ("fail_closed" in activate)
        assert report["outcome"] == "blocked", report
        assert report["exception"] == "tethered._core.EgressBlocked"
        assert arrivals() == {}

    def test_the_allowed_destination_is_reached(self) -> None:
        done = run_python(CONNECT, args=[ALLOWED_NAME, str(ALLOWED_PORT)])
        assert done.json()["outcome"] == "reached", done.stdout
        assert arrivals() == {f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp": 1}

    def test_none_runs_the_script_without_tethered(self) -> None:
        done = run_python(CONNECT, activate="none", args=[FORBIDDEN_NAME, str(OTHER_PORT)])
        report = done.json()
        assert report["tethered_imported"] is False
        assert report["outcome"] == "reached", report
        assert arrivals() == {f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp": 1}

    def test_the_external_subprocess_policy_and_extra_variables_are_passed(self) -> None:
        source = "import json, os, probe_common\n"
        source += "print(json.dumps({**probe_common.whoami(), 'extra': os.environ['EXTRA']}))\n"
        report = run_python(source, esp="block", env={"EXTRA": "yes"}).json()
        assert report["external_subprocess_policy"] == "block"
        assert report["extra"] == "yes"

    def test_an_uncaught_refusal_ends_the_script_with_a_traceback(self) -> None:
        done = run_python(f"import socket\nsocket.create_connection(({FORBIDDEN_ADDR!r}, 9002))\n")
        assert done.returncode == 1
        assert "tethered._core.EgressBlocked: Blocked by tethered" in done.stderr
        assert "-script.py" in done.stderr, "the traceback should name the script"
        assert arrivals() == {}

    def test_a_script_that_does_not_end_is_killed(self) -> None:
        with pytest.raises(AssertionError, match="did not end within 1"):
            run_python("import time\ntime.sleep(300)\n", activate="none", timeout=1.0)

    def test_an_unknown_setting_is_an_error_in_the_script(self) -> None:
        done = run_python("print('never')\n", activate="lokced")
        assert done.returncode != 0
        assert "unknown ['lokced']" in done.stderr
        assert done.stdout == ""

    def test_the_script_does_not_inherit_what_belongs_to_pytest(self) -> None:
        source = "import json, os\nprint(json.dumps(sorted(os.environ)))\n"
        names = run_python(source, activate="none").json()
        assert "TETH_ACTIVATE" in names
        assert "PYTHONPATH" in names
        assert not [name for name in names if name.startswith("PYTEST_")]
        assert "_TETHERED_CHILD_POLICY" not in names


# ── start_server ──────────────────────────────────────────────────────

_started: list[Server] = []


@pytest.fixture(scope="class")
def shared() -> Server:
    """A server that a class of tests shares."""
    server = start_server(TINY, ready="/")
    _started.append(server)
    return server


class TestServers:
    def test_the_handle_describes_a_running_server(self) -> None:
        server = start_server(TINY, ready="/")
        assert server.running
        assert server.url == f"http://127.0.0.1:{server.port}"
        assert server.pids() == [server.pid]
        assert server.get("/x?y=1").json() == {"pid": server.pid, "path": "/x?y=1"}
        assert http_get(server.url + "/z").status == 200
        assert f"tiny: listening on {server.port}" in server.log
        assert '"GET /x?y=1 HTTP/1.1" 200' in server.log_of_this_test
        assert server.wait_log(r"listening on (\d+)").group(1) == str(server.port)

    def test_stop_returns_the_exit_status_and_leaves_nothing(self) -> None:
        server = start_server(TINY, ready="/")
        assert server.stop() == 0
        assert not server.running
        assert server.pids() == []
        assert server.stop() == 0, "a second stop() is not an error"
        with pytest.raises(OSError, match="refused"):
            server.get("/")

    def test_a_server_that_a_test_started_is_stopped_after_the_test(self) -> None:
        _started.append(start_server(TINY, ready="/"))

    def test_and_the_next_test_finds_it_stopped(self) -> None:
        server = _started.pop()
        assert not server.running
        assert server.returncode == 0
        assert server.pids() == []

    def test_a_server_that_a_fixture_started_lives_as_long_as_the_fixture(
        self, shared: Server
    ) -> None:
        assert shared.running

    def test_a_fixture_server_is_still_running_in_the_next_test(self, shared: Server) -> None:
        assert shared.running
        assert shared.log_of_this_test == "", "nothing was logged since this test began"
        shared.get("/again")
        assert "GET /again" in shared.log_of_this_test
        assert "listening" in shared.log

    def test_each_server_gets_a_port_of_its_own(self, shared: Server) -> None:
        other = start_server(TINY, ready="/")
        assert other.port != shared.port
        assert other.get("/").json()["pid"] == other.pid
        assert shared.get("/").json()["pid"] == shared.pid

    def test_ready_can_be_a_function(self) -> None:
        calls = []

        def ready(server: Server) -> bool:
            calls.append(server)
            return "listening" in server.log

        server = start_server(TINY, ready=ready)
        assert calls and all(call is server for call in calls)

    def test_a_server_that_exits_while_starting_is_reported(self) -> None:
        with pytest.raises(AssertionError, match="exited with status 3 while starting"):
            start_server([*TINY, "exit-at-once"], ready="/")

    def test_a_server_that_never_answers_is_reported_and_stopped(self) -> None:
        with pytest.raises(AssertionError, match="was not ready within 1"):
            start_server(["sleep", "300"], ready="/", timeout=1.0)

    def test_a_server_that_ignores_sigterm_fails_the_stop_check(self) -> None:
        server = start_server([*TINY, "ignore-sigterm"], ready="/")
        with pytest.raises(AssertionError, match="did not exit within 1"):
            server.stop(timeout=1.0)
        assert server.pids() == [], "it is killed all the same"
        assert server.returncode == -signal.SIGKILL

    def test_a_process_left_behind_fails_the_stop_check(self) -> None:
        server = start_server([*TINY, "leave-a-child"], ready="/")
        assert len(server.pids()) == 2
        with pytest.raises(AssertionError, match="left processes that had to be killed"):
            server.stop(timeout=1.0)
        assert server.pids() == []

    def test_a_server_that_died_fails_the_stop_check(self) -> None:
        server = start_server(TINY, ready="/")
        server.send_signal(signal.SIGKILL)
        deadline = time.monotonic() + 10.0
        while server.running and time.monotonic() < deadline:
            time.sleep(0.01)
        with pytest.raises(AssertionError, match="had already exited"):
            server.stop()
        assert server.returncode == -signal.SIGKILL

    def test_check_false_stops_without_judging(self) -> None:
        server = start_server([*TINY, "ignore-sigterm"], ready="/")
        assert server.stop(timeout=0.5, check=False) == -signal.SIGKILL


def test_the_fixture_server_was_stopped_when_its_class_was_done() -> None:
    server = _started.pop()
    assert not server.running
    assert server.returncode == 0
