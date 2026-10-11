"""Dramatiq workers, with Redis as broker and result backend.

``dramatiq dramatiq_tasks --processes 2 --threads 2`` is a parent that starts
worker processes and never imports the application: every worker process
imports it, and runs actors in its worker threads.  How the worker processes
are started depends on the Python version: forked from the parent up to
3.13, forked from a fork server from 3.14, and spawned with ``--use-spawn``.

The application (``dramatiq_tasks.py``) activates the policy when it is
imported, or in the ``after_process_boot`` hook of a middleware
(``TETH_WHERE``): in both cases in every worker process, and the parent holds
none.

A test asks for a message through the front end (``front.py``, a producer
that holds no policy) and asserts what the actor reported, what the producer
and the log say about a refused message, and what arrived in the world.

Not covered: a worker process that dies (Dramatiq then shuts down as a whole
and leaves the restart to its supervisor), ``dramatiq-gevent``, and
``--fork-function`` processes.
"""

from __future__ import annotations

import re
import signal
import socket
import sys
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
    probe_path,
    start_server,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

REDIS = ["redis-server", "--bind", LOOPBACK_ADDR, "--port", "{port}"]
REDIS += ["--save", "", "--appendonly", "no"]
DRAMATIQ = ["dramatiq", "dramatiq_tasks", "--processes", "2", "--threads", "2"]
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"
REFUSED_NAME = f"Blocked by tethered: {FORBIDDEN_NAME} is not in the allow list"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"

#: Destinations the allow list does not cover.
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]
#: How Dramatiq starts its worker processes when it is not told to spawn them.
DEFAULT_START = "forkserver" if sys.version_info >= (3, 14) else "fork"


# ── The workers, their broker and a producer ──────────────────────────


@dataclass
class Stack:
    """A Redis server, ``dramatiq`` with two worker processes, and the front end."""

    redis: Server
    worker: Server
    front: Server

    def probe(
        self, op: str, host: str | None = None, port: int | None = None, **params: object
    ) -> dict[str, Any]:
        """One message."""
        return self.front.probe(op, host, port, **params)

    def each_process(
        self, path: str, exclude: Mapping[int, Any] | None = None
    ) -> dict[int, dict[str, Any]]:
        """The reports of messages handled by both worker processes."""
        return self.front.each_worker(path, 2, exclude=exclude or ())


def wait_for(condition: Callable[[], Any], what: str, timeout: float = 30.0) -> Any:
    """Wait until ``condition()`` is true and return what it returned."""
    deadline = time.monotonic() + timeout
    while True:
        value = condition()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: not within {timeout} s")
        time.sleep(0.05)


def start_stack(
    *options: str,
    activate: str = "locked",
    where: str = "import",
    env: Mapping[str, str] | None = None,
) -> Stack:
    """Start Redis, ``dramatiq`` with these options, and a front end."""

    def accepting(server: Server) -> bool:
        socket.create_connection((LOOPBACK_ADDR, server.port), timeout=1.0).close()
        return True

    redis = start_server(REDIS, ready=accepting)
    settings = {"REDIS_URL": f"redis://{LOOPBACK_ADDR}:{redis.port}/0", **(env or {})}
    worker = start_server(
        [*DRAMATIQ, *options],
        env={**settings, "TETH_ACTIVATE": activate, "TETH_WHERE": where},
        ready=lambda server: server.log.count("Worker process is ready for action") >= 2,
        timeout=60,
    )
    front = start_server(
        ["python", "front.py"], env={**settings, "TETH_ACTIVATE": "none"}, ready="/front"
    )
    return Stack(redis, worker, front)


def command_line(pid: int) -> str:
    return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode().strip()


def parent_of(pid: int) -> int:
    # "pid (comm) state ppid ...": comm may contain spaces and brackets.
    return int(Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[1])


def assert_started_by(start: str, report: dict[str, Any], worker: Server) -> None:
    """The worker process that wrote ``report`` was started the way ``start`` says."""
    started = command_line(report["pid"])
    if start == "fork":
        assert started == command_line(worker.pid)
        assert report["ppid"] == worker.pid
    elif start == "spawn":
        assert "from multiprocessing.spawn import spawn_main" in started, started
        assert report["ppid"] == worker.pid
    else:
        assert "from multiprocessing.forkserver import main" in started, started
        assert started == command_line(report["ppid"])
        assert parent_of(report["ppid"]) == worker.pid


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_policy(report: dict[str, Any], mode: str) -> None:
    assert report["active"] is True, report
    assert report["locked"] is (mode == "locked"), report


# ── Both ways to start the processes, both places to activate ─────────

#: (how the worker processes are started, where the policy is activated, which policy)
ARRANGEMENTS = [
    ("default", "import", "plain"),
    ("default", "import", "locked"),
    ("spawn", "import", "plain"),
    ("spawn", "import", "locked"),
    ("default", "process_boot", "locked"),
    ("spawn", "process_boot", "locked"),
]


@pytest.fixture(scope="module", params=ARRANGEMENTS, ids="-".join)
def arrangement(request: pytest.FixtureRequest) -> tuple[str, str, str]:
    return request.param


@pytest.fixture(scope="module")
def mode(arrangement: tuple[str, str, str]) -> str:
    return arrangement[2]


@pytest.fixture(scope="module")
def stack(arrangement: tuple[str, str, str]) -> Stack:
    start, where, mode = arrangement
    options = ["--use-spawn"] if start == "spawn" else []
    return start_stack(*options, activate=mode, where=where)


class TestWorkerProcesses:
    def test_every_worker_process_was_started_as_expected_and_holds_the_policy(
        self, stack: Stack, arrangement: tuple[str, str, str]
    ) -> None:
        start, _where, mode = arrangement
        answers = stack.each_process("/whoami")
        assert stack.worker.pid not in answers
        for pid, me in answers.items():
            assert_started_by(DEFAULT_START if start == "default" else start, me, stack.worker)
            assert_policy(me, mode)
            # The worker process imported the application itself, and held no
            # policy before: the parent has none to pass on.
            assert me["imported_in_pid"] == pid
            assert me["active_before_import"] is False
            assert me["thread"].startswith("Thread-"), me

    def test_every_worker_process_reaches_the_allowed_destination(self, stack: Stack) -> None:
        path = probe_path("connect", ALLOWED_NAME, ALLOWED_PORT)
        for report in stack.each_process(path).values():
            assert report["outcome"] == "reached", report
            assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert set(arrivals()) == {AT_ALLOWED}

    def test_every_worker_process_refuses_the_forbidden_destination(self, stack: Stack) -> None:
        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in stack.each_process(path).values():
            assert_refused(report)
        assert arrivals() == {}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_an_actor_is_refused_a_destination_outside_the_allow_list(
        self, stack: Stack, host: str, port: int
    ) -> None:
        # One message each from here on: an idle Dramatiq worker looks for
        # messages about once a second, and reaching both processes takes a while.
        assert_refused(stack.probe("connect", host, port))
        assert arrivals() == {}

    def test_an_uncaught_refusal_is_a_failed_message_and_the_workers_go_on(
        self, stack: Stack
    ) -> None:
        before = stack.worker.pids()
        task = stack.probe("connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)["task"]
        assert arrivals() == {}
        # The producer gets Dramatiq's ResultFailure, which names the exception.
        assert task["exception"] == "dramatiq.results.errors.ResultFailure", task
        assert task["message"] == f"actor raised EgressBlocked: {REFUSED_NAME}"
        assert task["orig_exc_type"] == "EgressBlocked"
        assert task["orig_exc_msg"] == REFUSED_NAME
        # What the operator finds in the log.
        stack.worker.wait_log(
            r"\[ERROR\] Failed to process message probe\('connect', .*\) "
            r"with unhandled exception\."
        )
        stack.worker.wait_log(rf"{re.escape(EGRESS_BLOCKED)}: {re.escape(REFUSED_NAME)}")
        assert stack.worker.pids() == before
        assert stack.probe("connect", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"

    def test_the_retries_middleware_retries_a_refused_message(self, stack: Stack) -> None:
        # max_retries=2: tried three times, refused three times.  (With Dramatiq's
        # defaults it would be twenty retries, the first after fifteen seconds.)
        answer = stack.probe(
            "connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1, actor="probe_retried"
        )
        task = answer["task"]
        assert task["orig_exc_type"] == "EgressBlocked", task
        assert arrivals() == {}
        worker = stack.worker
        worker.wait_log(rf"\[WARNING\] Retries exceeded for message '{task['id']}'")
        retrying = f"Retrying message '{task['id']}' in"
        wait_for(lambda: worker.log_of_this_test.count(retrying) >= 2, "two retries in the log")
        assert worker.log_of_this_test.count(retrying) == 2

    def test_a_python_child_of_an_actor_inherits_the_policy(self, stack: Stack, mode: str) -> None:
        report = stack.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        child = report["child"]
        assert child["ppid"] == report["pid"]
        assert_policy(child, mode)
        assert_refused(child)
        assert arrivals() == {}

    def test_a_tool_launched_by_an_actor_is_warned_about_and_is_not_restricted(
        self, stack: Stack
    ) -> None:
        report = stack.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["stdout"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}"
        assert arrivals() == {AT_FORBIDDEN: 1}
        stack.worker.wait_log(
            r"\[tethered\] \[WARNING\] tethered: external subprocess launch detected: "
            r"subprocess\.Popen\(bash\)"
        )


# ── Worker processes that are started later ───────────────────────────


class TestReload:
    def test_the_worker_processes_started_by_a_reload_enforce_the_policy(self) -> None:
        # SIGHUP: the parent stops its worker processes and starts new ones,
        # which import the application, and activate the policy, afresh.
        stack = start_stack()
        first = stack.each_process("/whoami")
        stack.worker.send_signal(signal.SIGHUP)

        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        later = stack.each_process(path, exclude=first)
        for report in later.values():
            assert_started_by(DEFAULT_START, report, stack.worker)
            assert_policy(report, "locked")
            assert_refused(report)
        assert arrivals() == {}
        assert stack.probe("connect", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}


class TestBlockingExternalLaunches:
    def test_the_workers_start_and_work_and_a_tool_is_not_launched(self) -> None:
        # external_subprocess_policy="block" in every worker process.
        stack = start_stack(env={"TETH_ESP": "block"})
        report = stack.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["external_subprocess_policy"] == "block"
        assert report["outcome"] == "reached", report
        assert_policy(report["child"], "locked")
        assert_refused(report["child"])

        assert_refused(stack.probe("tool", FORBIDDEN_NAME, OTHER_PORT), SUBPROCESS_BLOCKED)
        assert arrivals() == {}
        assert stack.probe("connect", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
