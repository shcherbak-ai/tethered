"""Quart, the ASGI framework with Flask's API, in the three ways it is run.

* ``hypercorn probe_quart:app``: what Quart recommends for deployment.
  hypercorn's master starts the worker as a new Python process, which imports
  the application and with it the policy.
* ``quart run``: the development server, hypercorn's ``serve()`` in the one
  process, and ``quart run --reload``, which replaces what serves when a
  source file changes.
* ``app.run()`` in a script: the development server started from Python,
  which has the reloader on by default.

The reloader is not the same in the two Quart releases the suite runs on
(0.23 needs Python 3.13, so 3.11 and 3.12 get 0.22.0).  In 0.22 the serving
process replaces itself in place and keeps its pid.  In 0.23 a parent only
supervises, and the child that serves is replaced by a new child.
``RELOADER_SUPERVISES`` says which one is installed, and the tests assert the
layout that belongs to it.

All of them serve on the standard asyncio event loop, where everything is
seen and enforced.  The hypercorn suite covers hypercorn's other worker
classes (trio, uvloop) and its worker lifecycle; this one is about Quart on
top of it.

``stop()`` is about Quart, not about tethered: with or without tethered, the
development server ends with status 3 on SIGTERM, and under the supervising
reloader a SIGTERM for the parent leaves the serving child running.  The
servers here are therefore stopped through their process group, and the check
that nothing is left is made here.

The application (``probe_quart.py``) allows ``allowed.test:9001``.  Each test
asserts what the application reported and what arrived in the world.
"""

from __future__ import annotations

import contextlib
import importlib.metadata
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
    SUITE_DIR,
    Server,
    arrivals,
    probe_path,
    start_server,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

STANDARD_LOOP = "asyncio.unix_events._UnixSelectorEventLoop"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"

HYPERCORN = ["hypercorn", "--bind", "127.0.0.1:{port}", "probe_quart:app"]
QUART_RUN = ["quart", "--app", "probe_quart:app", "run", "--host", "127.0.0.1", "--port", "{port}"]
ARRANGEMENTS = {
    "hypercorn": HYPERCORN,
    "quart-run": QUART_RUN,
    "app-run": ["python", "probe_quart.py"],
}
#: Quart 0.23 and later: the reloader is a parent that supervises a serving child.
#: Before that the serving process replaced itself in place.
RELOADER_SUPERVISES = tuple(
    int(part) for part in importlib.metadata.version("quart").split(".")[:2]
) >= (0, 23)
#: The ways to open a TCP connection from a view.
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


def stop(server: Server) -> None:
    """Stop a Quart server through its process group, and check that nothing is left.

    See the module docstring: Quart's development server does not stop the
    way ``Server.stop`` expects of a server, whatever tethered does.
    """
    if server.argv[0] == "hypercorn":
        server.stop()
        return
    os.killpg(server.pid, signal.SIGTERM)
    deadline = time.monotonic() + 15.0
    while server.pids() and time.monotonic() < deadline:
        time.sleep(0.05)
    left = server.pids()
    server.stop(check=False)
    assert not left, f"{server.name}: still running 15 s after SIGTERM: {left}"


@contextlib.contextmanager
def running(argv: list[str], env: dict[str, str]) -> Iterator[Server]:
    """A server for the length of a ``with`` block, stopped the way Quart needs."""
    server = start_server(argv, env=env)
    try:
        yield server
    finally:
        stop(server)


# ── Each way of running it ────────────────────────────────────────────


@pytest.fixture(scope="module", params=list(ARRANGEMENTS))
def arrangement(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module", params=["plain", "locked"])
def mode(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(arrangement: str, mode: str) -> Iterator[Server]:
    """Quart in one arrangement; the application activates the policy when it is imported."""
    with running(ARRANGEMENTS[arrangement], {"TETH_ACTIVATE": mode}) as started:
        yield started


class TestEveryArrangement:
    def test_the_views_run_on_the_standard_loop_with_the_policy(
        self, server: Server, arrangement: str, mode: str
    ) -> None:
        me = server.get("/whoami").json()
        assert_enforcing(me, locked=mode == "locked")
        assert me["imported_in_pid"] == me["pid"]
        if arrangement == "hypercorn":
            # A worker of hypercorn's master.
            assert me["ppid"] == server.pid
        elif arrangement == "app-run" and RELOADER_SUPERVISES:
            # The serving child of the reloader.  The parent ran the script
            # too and holds the policy itself; the child inherited it when it
            # started.
            assert me["ppid"] == server.pid
            assert f"probe: pid {server.pid} activated tethered" in server.log
            assert server.pids() == [server.pid, me["pid"]]
        else:
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

    def test_loopback_stays_reachable(self, server: Server) -> None:
        for op in STREAM_OPS:
            report = server.probe(op, LOOPBACK_ADDR, OTHER_PORT)
            assert report["outcome"] == "reached", report
        assert arrivals() == {f"{LOOPBACK_ADDR}:{OTHER_PORT}/tcp": len(STREAM_OPS)}

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
        me = server.get("/whoami").json()
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)
        assert server.get(path).status == 500
        assert arrivals() == {}
        server.wait_log(f"EgressBlocked: Blocked by tethered: {FORBIDDEN_NAME} is not in the allow")
        assert server.get("/whoami").json()["pid"] == me["pid"]
        report = server.probe("open_connection", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report

    def test_a_python_child_inherits_the_policy(self, server: Server, mode: str) -> None:
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        child = report["child"]
        assert child["ppid"] == report["pid"]
        assert child["active"] is True, child
        assert child["locked"] is (mode == "locked"), child
        assert_refused(child)
        assert arrivals() == {}

    def test_a_tool_is_launched_with_a_warning_and_is_not_restricted(self, server: Server) -> None:
        # The default external_subprocess_policy.  The tool is not Python:
        # nothing enforces the allow list inside it.
        report = server.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["stdout"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}"
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(r"external subprocess launch detected: subprocess\.Popen\(bash\)")

    def test_under_block_a_tool_is_not_launched(self, arrangement: str) -> None:
        # Under the reloader this also shows that its parent, which holds the
        # same policy, can still start the child that serves.
        environment = {"TETH_ACTIVATE": "locked", "TETH_ESP": "block"}
        with running(ARRANGEMENTS[arrangement], environment) as blocking:
            report = blocking.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
            assert_refused(report, SUBPROCESS_BLOCKED)
            assert arrivals() == {}
            blocking.wait_log(r"blocked external subprocess launch: subprocess\.Popen\(bash\)")


# ── hypercorn with two workers ────────────────────────────────────────


class TestHypercornWorkers:
    def test_every_worker_holds_the_locked_policy_and_refuses(self) -> None:
        server = start_server([*HYPERCORN, "--workers", "2"], env={"TETH_ACTIVATE": "locked"})
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        for pid, report in server.each_worker(path, 2).items():
            assert_enforcing(report, locked=True)
            assert report["ppid"] == server.pid
            assert report["imported_in_pid"] == pid
            assert_refused(report)
        assert arrivals() == {}
        path = probe_path("open_connection", ALLOWED_NAME, ALLOWED_PORT)
        for report in server.each_worker(path, 2).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}


# ── quart run --reload ────────────────────────────────────────────────


def reload_by_touching(server: Server, before: dict[str, Any]) -> dict[str, Any]:
    """Touch the application's source until Quart has replaced the process.

    Quart looks at the files of the imported modules once a second and takes
    its first look as the baseline, so a touch right after the start can go
    unnoticed: the file is touched again every three seconds until the
    application answers from a new process image.
    """
    source = SUITE_DIR / "probe_quart.py"
    stamp = time.time()
    touched = None
    deadline = time.monotonic() + 40.0
    while time.monotonic() < deadline:
        try:
            now = server.get("/whoami", timeout=2.0).json()
        except (OSError, AssertionError):
            now = None  # between the two processes nothing answers
        if now is not None and now["booted"] != before["booted"]:
            return now
        if touched is None or time.monotonic() - touched >= 3.0:
            stamp += 2.0
            os.utime(source, (stamp, stamp))
            touched = time.monotonic()
        time.sleep(0.1)
    raise AssertionError(f"the reloader did not replace the process:\n{server.log[-2000:]}")


class TestReloader:
    @pytest.mark.parametrize("policy", ["plain", "locked"])
    def test_the_process_that_replaces_this_one_holds_the_policy(self, policy: str) -> None:
        with running([*QUART_RUN, "--reload"], {"TETH_ACTIVATE": policy}) as server:
            before = server.get("/whoami").json()
            assert_enforcing(before, locked=policy == "locked")

            after = reload_by_touching(server, before)
            if RELOADER_SUPERVISES:
                # A new child of the same supervising parent.
                assert before["ppid"] == server.pid
                assert after["ppid"] == server.pid
                assert after["pid"] != before["pid"]
            else:
                # The same process, with a new program image.
                assert before["pid"] == server.pid
                assert after["pid"] == server.pid
            assert_enforcing(after, locked=policy == "locked")
            assert_refused(server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT))
            assert_refused(server.probe("open_connection", FORBIDDEN_ADDR, OTHER_PORT))
            assert arrivals() == {}
            report = server.probe("open_connection", ALLOWED_NAME, ALLOWED_PORT)
            assert report["outcome"] == "reached", report
            assert arrivals() == {AT_ALLOWED: 1}


# ── The modes that do not refuse ──────────────────────────────────────


class TestNotEnforcing:
    def test_without_tethered_the_forbidden_destination_is_reached(self, arrangement: str) -> None:
        # The control: the same route, no policy.  It shows that the world's
        # counters move when something does arrive.
        with running(ARRANGEMENTS[arrangement], {"TETH_ACTIVATE": "none"}) as server:
            assert server.get("/whoami").json()["tethered_imported"] is False
            report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
            assert report["outcome"] == "reached", report
            assert arrivals() == {AT_FORBIDDEN: 1}

    def test_log_only_reports_the_connection_and_lets_it_through(self, arrangement: str) -> None:
        with running(ARRANGEMENTS[arrangement], {"TETH_ACTIVATE": "log_only"}) as server:
            report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
            assert report["outcome"] == "reached", report
            assert arrivals() == {AT_FORBIDDEN: 1}
            server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")
            server.wait_log(f"tethered: blocked connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")
