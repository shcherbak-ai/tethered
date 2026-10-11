"""arq workers, with Redis as queue and result store.

``arq arq_tasks.WorkerSettings`` is one process with one asyncio event loop,
asyncio's own (the test checks which): jobs are coroutines in that loop.  The
application (``arq_tasks.py``) activates the policy when it is imported,
before the loop exists, or in arq's ``on_startup`` coroutine, inside the
running loop (``TETH_WHERE``).

A test asks for a job through the front end (``front.py``, a producer that
holds no policy) and asserts what the job reported, what the producer and
the worker's log say about a refused job, and what arrived in the world.

On Python 3.12 and later none of that works today: asyncio writes to its
sockets with ``socket.sendmsg`` there, tethered refuses ``sendmsg`` on a
connected socket, and the worker loses its connection to Redis.  The tests
of that limit (``TestAsyncioWritesFromPython312``) run on those versions and
all the others on Python 3.11.

Not covered: arq with uvloop (nothing that goes through a uvloop loop raises
an audit event; tethered refuses to load uvloop under a policy) and
``--watch``.
"""

from __future__ import annotations

import json
import re
import socket
import sys
import tempfile
import time
from dataclasses import dataclass
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
    Server,
    arrivals,
    start_server,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

REDIS = ["redis-server", "--bind", LOOPBACK_ADDR, "--port", "{port}"]
REDIS += ["--save", "", "--appendonly", "no"]
STANDARD_LOOP = "asyncio.unix_events._UnixSelectorEventLoop"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"
REFUSED_NAME = f"Blocked by tethered: {FORBIDDEN_NAME} is not in the allow list"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"

#: From Python 3.12 asyncio's socket transports write with socket.sendmsg:
#: writelines() always, and write() for what one send() could not take.  The
#: audit event of sendmsg on a connected socket carries no address, and
#: tethered refuses what it cannot read.  redis-py's asyncio client, which arq
#: uses, writes every command with writelines().
SENDMSG_REFUSED = sys.version_info >= (3, 12)
works = pytest.mark.skipif(
    SENDMSG_REFUSED,
    reason="asyncio writes with sendmsg from Python 3.12 and tethered refuses it: "
    "see TestAsyncioWritesFromPython312",
)
REFUSED_SENDMSG = (
    "tethered: blocked sendmsg for <unreadable None> (cannot be checked against the allow list)"
)

#: The ways a job opens a connection: blocking in the loop, with asyncio's
#: streams, in a thread, and with urllib (blocking).
CONNECT_OPS = ["connect", "open_connection", "to_thread", "urllib"]
#: Destinations the allow list does not cover.
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]


# ── A worker, its queue and a producer ────────────────────────────────


@dataclass
class Stack:
    """A Redis server, an arq worker and the front end that enqueues jobs."""

    redis: Server
    worker: Server
    front: Server
    #: Where jobs nobody waits for leave their reports (the cron job).
    record: Path

    def probe(
        self, op: str, host: str | None = None, port: int | None = None, **params: object
    ) -> dict[str, Any]:
        """One job."""
        return self.front.probe(op, host, port, **params)

    def wait_records(self, count: int, timeout: float = 30.0) -> list[dict[str, Any]]:
        """Wait until ``count`` recorded jobs have run; returns their reports."""
        deadline = time.monotonic() + timeout
        while True:
            try:
                lines = self.record.read_text(encoding="utf-8").splitlines()
            except OSError:
                lines = []
            if len(lines) >= count:
                return [json.loads(line) for line in lines]
            if time.monotonic() >= deadline:
                raise AssertionError(f"{len(lines)} of {count} recorded jobs in {timeout} s")
            time.sleep(0.05)


def start_stack(
    activate: str = "locked", where: str = "import", env: Mapping[str, str] | None = None
) -> Stack:
    """Start Redis, ``arq arq_tasks.WorkerSettings`` and a front end."""

    def accepting(server: Server) -> bool:
        socket.create_connection((LOOPBACK_ADDR, server.port), timeout=1.0).close()
        return True

    redis = start_server(REDIS, ready=accepting)
    record = Path(tempfile.gettempdir()) / f"tc-record-{redis.port}.jsonl"
    settings = {"REDIS_PORT": str(redis.port), "TC_RECORD": str(record), **(env or {})}
    worker = start_server(
        ["arq", "arq_tasks.WorkerSettings"],
        env={**settings, "TETH_ACTIVATE": activate, "TETH_WHERE": where},
        # What arq logs once it is connected to Redis.
        ready=lambda server: "redis_version=" in server.log,
    )
    front = start_server(
        ["python", "front.py"], env={**settings, "TETH_ACTIVATE": "none"}, ready="/front"
    )
    return Stack(redis, worker, front, record)


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_policy(report: dict[str, Any], mode: str) -> None:
    assert report["active"] is True, report
    assert report["locked"] is (mode == "locked"), report


# ── Both places to activate, a plain and a locked policy ──────────────


@pytest.fixture(scope="module", params=["import", "on_startup"])
def where(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module", params=["plain", "locked"])
def mode(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def stack(where: str, mode: str) -> Stack:
    return start_stack(mode, where)


@works
class TestWorker:
    def test_jobs_run_in_the_standard_event_loop_of_the_worker_under_the_policy(
        self, stack: Stack, mode: str
    ) -> None:
        me = stack.probe("whoami")
        assert me["pid"] == stack.worker.pid
        assert stack.worker.pids() == [stack.worker.pid]
        assert me["thread"] == "MainThread"
        assert me["loop"] == STANDARD_LOOP
        assert_policy(me, mode)

    @pytest.mark.parametrize("op", CONNECT_OPS)
    def test_a_job_reaches_the_allowed_destination(self, stack: Stack, op: str) -> None:
        report = stack.probe(op, ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert arrivals() == {AT_ALLOWED: 1}

    @pytest.mark.parametrize("op", CONNECT_OPS)
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_job_is_refused_a_destination_outside_the_allow_list(
        self, stack: Stack, op: str, host: str, port: int
    ) -> None:
        report = stack.probe(op, host, port)
        assert report["outcome"] == "blocked", report
        assert arrivals() == {}

    def test_an_uncaught_refusal_is_a_failed_job_that_is_not_retried(self, stack: Stack) -> None:
        task = stack.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)["task"]
        assert arrivals() == {}
        # arq pickles the exception: the producer gets the EgressBlocked itself,
        # with its attributes.
        assert task["exception"] == EGRESS_BLOCKED, task
        assert task["message"] == REFUSED_NAME
        assert task["host"] == FORBIDDEN_NAME
        # arq runs a job again only for its own Retry exception (and when the
        # worker is stopped under it): a refusal fails the job at the first try.
        assert task["job_try"] == 1, task
        # What the operator finds in the worker's log.
        stack.worker.wait_log(
            rf"{task['id']}:probe failed, EgressBlocked: {re.escape(REFUSED_NAME)}"
        )
        # The worker goes on with the next job.
        report = stack.probe("open_connection", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report

    @pytest.mark.parametrize("op", ["child", "child_exec"])
    def test_a_python_child_of_a_job_inherits_the_policy(
        self, stack: Stack, mode: str, op: str
    ) -> None:
        # subprocess.run, and asyncio.create_subprocess_exec.
        report = stack.probe(op, FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        child = report["child"]
        assert child["ppid"] == stack.worker.pid
        assert_policy(child, mode)
        assert_refused(child)
        assert arrivals() == {}

    def test_a_tool_launched_by_a_job_is_warned_about_and_is_not_restricted(
        self, stack: Stack
    ) -> None:
        report = stack.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["stdout"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}"
        assert arrivals() == {AT_FORBIDDEN: 1}
        stack.worker.wait_log(
            r"tethered: external subprocess launch detected: subprocess\.Popen\(bash\)"
        )


# ── Jobs nobody enqueued, and blocked launches ────────────────────────


@works
class TestCronJobs:
    @pytest.mark.parametrize("where", ["import", "on_startup"])
    def test_a_cron_job_runs_under_the_policy(self, where: str) -> None:
        # The worker starts cron jobs itself; here one that runs every second.
        stack = start_stack(where=where, env={"CRON_TARGET": f"{FORBIDDEN_NAME}:{OTHER_PORT}"})
        for report in stack.wait_records(2):
            assert report["pid"] == stack.worker.pid
            assert_policy(report, "locked")
            assert_refused(report)
        assert arrivals() == {}
        stack.worker.wait_log(r"cron:tick")


@works
class TestBlockingExternalLaunches:
    def test_the_worker_starts_and_works_and_a_tool_is_not_launched(self) -> None:
        stack = start_stack(env={"TETH_ESP": "block"})
        for op in ("child", "child_exec"):
            report = stack.probe(op, FORBIDDEN_NAME, OTHER_PORT)
            assert report["external_subprocess_policy"] == "block"
            assert report["outcome"] == "reached", report
            assert_policy(report["child"], "locked")
            assert_refused(report["child"])

        assert_refused(stack.probe("tool", FORBIDDEN_NAME, OTHER_PORT), SUBPROCESS_BLOCKED)
        assert arrivals() == {}
        assert stack.probe("connect", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"


# ── Python 3.12 and later ─────────────────────────────────────────────


def wait_until_gone(server: Server, timeout: float = 30.0) -> int | None:
    """Wait until the process has ended by itself; returns its exit status."""
    deadline = time.monotonic() + timeout
    while server.running:
        if time.monotonic() >= deadline:
            raise AssertionError(f"{server.name} is still running after {timeout} s")
        time.sleep(0.05)
    return server.stop(check=False)


class TestWithoutTethered:
    def test_the_worker_runs_jobs_and_reaches_the_forbidden_destination(self) -> None:
        # The control, on every Python version: the same worker, no policy.
        stack = start_stack("none")
        report = stack.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["tethered_imported"] is False
        assert report["loop"] == STANDARD_LOOP
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}


@pytest.mark.skipif(
    not SENDMSG_REFUSED, reason="asyncio does not write with sendmsg before Python 3.12"
)
class TestAsyncioWritesFromPython312:
    def start(self, where: str, ready: str) -> tuple[Server, Server]:
        def accepting(server: Server) -> bool:
            socket.create_connection((LOOPBACK_ADDR, server.port), timeout=1.0).close()
            return True

        redis = start_server(REDIS, ready=accepting)
        worker = start_server(
            ["arq", "arq_tasks.WorkerSettings"],
            env={"REDIS_PORT": str(redis.port), "TETH_ACTIVATE": "locked", "TETH_WHERE": where},
            ready=lambda server: ready in server.log,
        )
        return redis, worker

    def test_a_worker_that_holds_the_policy_from_the_start_cannot_talk_to_redis(self) -> None:
        """Limit: on Python 3.12+ an arq worker under a policy never gets its Redis connection.

        Redis is on loopback, which the policy allows, and the connection
        itself is made.  The first command is written with ``sendmsg`` and
        refused; asyncio closes the transport, arq retries five times and
        gives up.
        """
        _redis, worker = self.start("import", REFUSED_SENDMSG)
        assert wait_until_gone(worker) == 1
        log = worker.log
        assert "Fatal write error on socket transport" in log
        assert f"{EGRESS_BLOCKED}: Blocked by tethered: <unreadable None> is not in the" in log
        assert "redis connection error" in log
        assert "5 retries remaining" in log
        assert "Starting worker for" not in log
        assert arrivals() == {}

    def test_a_worker_that_activates_in_on_startup_loses_its_redis_connection(self) -> None:
        """Limit: on Python 3.12+ activating a policy breaks the asyncio connections that exist.

        The worker is connected and has started; ``on_startup`` activates the
        policy; the next command on the open connection is refused and the
        worker ends.
        """
        _redis, worker = self.start("on_startup", "redis_version=")
        worker.wait_log(r"probe: pid \d+ activated tethered \(locked\)")
        worker.wait_log(re.escape(REFUSED_SENDMSG))
        assert wait_until_gone(worker) == 1
        assert "Fatal write error on socket transport" in worker.log
        assert arrivals() == {}
