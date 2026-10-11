"""Huey consumers, with Redis as queue and result store.

``huey_consumer huey_tasks.huey -w 2`` imports the application and runs tasks
in worker threads (``-k thread``, the default) or in worker processes forked
from the consumer (``-k process``), next to a scheduler of the same kind.

The application (``huey_tasks.py``) activates the policy when it is
imported, which is in the consumer before the workers exist, or in an
``on_startup`` hook, which Huey runs in every worker (``TETH_WHERE``).  In
the second case, with worker processes, the consumer and its scheduler
process hold no policy; they run no task code.

A test asks for a task through the front end (``front.py``, a producer that
holds no policy) and asserts what the task reported, what the producer and
the log say about a refused task, and what arrived in the world.

Not covered: the greenlet worker type (gevent is covered with Celery and
gunicorn) and periodic tasks (the scheduler only enqueues them).
"""

from __future__ import annotations

import re
import signal
import socket
import time
from dataclasses import dataclass
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
    from collections.abc import Callable, Collection, Mapping

REDIS = ["redis-server", "--bind", LOOPBACK_ADDR, "--port", "{port}"]
REDIS += ["--save", "", "--appendonly", "no"]
CONSUMER = ["huey_consumer", "huey_tasks.huey", "--workers", "2"]
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
#: How many processes run task code, with two workers of each kind.
PROCESSES = {"thread": 1, "process": 2}


# ── A consumer, its queue and a producer ──────────────────────────────


@dataclass
class Stack:
    """A Redis server, a Huey consumer with two workers, and the front end."""

    redis: Server
    consumer: Server
    front: Server

    def probe(
        self, op: str, host: str | None = None, port: int | None = None, **params: object
    ) -> dict[str, Any]:
        """One task."""
        return self.front.probe(op, host, port, **params)

    def each_process(
        self, path: str, count: int, exclude: Collection[int] = ()
    ) -> dict[int, dict[str, Any]]:
        """The reports of tasks run by ``count`` different processes."""
        return self.front.each_worker(path, count, exclude=exclude)


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
    kind: str,
    *options: str,
    activate: str = "locked",
    where: str = "import",
    env: Mapping[str, str] | None = None,
) -> Stack:
    """Start Redis, ``huey_consumer`` with workers of this kind, and a front end."""

    def accepting(server: Server) -> bool:
        socket.create_connection((LOOPBACK_ADDR, server.port), timeout=1.0).close()
        return True

    redis = start_server(REDIS, ready=accepting)
    settings = {"REDIS_URL": f"redis://{LOOPBACK_ADDR}:{redis.port}/0", **(env or {})}
    consumer = start_server(
        [*CONSUMER, "--worker-type", kind, *options],
        env={**settings, "TETH_ACTIVATE": activate, "TETH_WHERE": where},
        ready=lambda server: f"Huey consumer started with 2 {kind}" in server.log,
    )
    front = start_server(
        ["python", "front.py"], env={**settings, "TETH_ACTIVATE": "none"}, ready="/front"
    )
    return Stack(redis, consumer, front)


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_policy(report: dict[str, Any], mode: str) -> None:
    assert report["active"] is True, report
    assert report["locked"] is (mode == "locked"), report


# ── Both worker types, both places to activate ────────────────────────

#: (worker type, where the policy is activated, which policy)
ARRANGEMENTS = [
    ("thread", "import", "plain"),
    ("thread", "import", "locked"),
    ("process", "import", "plain"),
    ("process", "import", "locked"),
    ("thread", "on_startup", "locked"),
    ("process", "on_startup", "locked"),
]


@pytest.fixture(scope="module", params=ARRANGEMENTS, ids="-".join)
def arrangement(request: pytest.FixtureRequest) -> tuple[str, str, str]:
    return request.param


@pytest.fixture(scope="module")
def kind(arrangement: tuple[str, str, str]) -> str:
    return arrangement[0]


@pytest.fixture(scope="module")
def mode(arrangement: tuple[str, str, str]) -> str:
    return arrangement[2]


@pytest.fixture(scope="module")
def stack(arrangement: tuple[str, str, str]) -> Stack:
    kind, where, mode = arrangement
    return start_stack(kind, activate=mode, where=where)


class TestWorkerTypes:
    def test_the_workers_are_of_the_type_asked_for_and_hold_the_policy(
        self, stack: Stack, kind: str, mode: str
    ) -> None:
        consumer = stack.consumer
        answers = stack.each_process("/whoami", PROCESSES[kind])
        for pid, me in answers.items():
            assert_policy(me, mode)
            # The consumer imported the application; a worker process is its copy.
            assert me["imported_in_pid"] == consumer.pid
            if kind == "thread":
                assert pid == consumer.pid
                assert me["thread"].startswith("Worker-"), me
            else:
                assert me["ppid"] == consumer.pid
                assert me["thread"] == "MainThread"
        if kind == "thread":
            assert consumer.pids() == [consumer.pid]
        else:
            # The consumer, the two workers and the scheduler.
            assert len(consumer.pids()) == 4
            assert set(answers) < set(consumer.pids())

    def test_every_worker_reaches_the_allowed_destination(self, stack: Stack, kind: str) -> None:
        path = probe_path("connect", ALLOWED_NAME, ALLOWED_PORT)
        for report in stack.each_process(path, PROCESSES[kind]).values():
            assert report["outcome"] == "reached", report
            assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_every_worker_refuses_a_destination_outside_the_allow_list(
        self, stack: Stack, kind: str, host: str, port: int
    ) -> None:
        path = probe_path("connect", host, port)
        for report in stack.each_process(path, PROCESSES[kind]).values():
            assert_refused(report)
        assert arrivals() == {}

    def test_an_uncaught_refusal_is_a_failed_task_and_the_workers_go_on(
        self, stack: Stack, kind: str
    ) -> None:
        before = stack.each_process("/whoami", PROCESSES[kind])
        task = stack.probe("connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)["task"]
        assert arrivals() == {}
        # The producer gets Huey's TaskException, with the repr of the exception
        # and the traceback as text.
        assert task["exception"] == "huey.exceptions.TaskException", task
        assert task["error"] == f"EgressBlocked('{REFUSED_NAME}')"
        assert task["traceback"].rstrip().endswith(f"{EGRESS_BLOCKED}: {REFUSED_NAME}")
        # What the operator finds in the consumer's log.
        stack.consumer.wait_log(rf"ERROR:huey:\S+:Unhandled exception in task {task['id']}\.")
        stack.consumer.wait_log(rf"{re.escape(EGRESS_BLOCKED)}: {re.escape(REFUSED_NAME)}")
        assert set(stack.each_process("/whoami", PROCESSES[kind])) == set(before)

    def test_retries_run_a_refused_task_again_like_any_failed_task(self, stack: Stack) -> None:
        # retries=2: tried three times, refused three times.
        answer = stack.probe(
            "connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1, task="probe_retried"
        )
        task = answer["task"]
        assert task["exception"] == "huey.exceptions.TaskException", task
        # Huey hands the producer the failure of the first attempt, and goes on
        # retrying: the log tells how often.
        consumer = stack.consumer
        failure = rf"ERROR:huey:\S+:Unhandled exception in task {task['id']}\."
        for left in (1, 0):
            consumer.wait_log(rf"INFO:huey:\S+:Requeueing {task['id']}, {left} retries")
        wait_for(
            lambda: len(re.findall(failure, consumer.log_of_this_test)) >= 3,
            "the third attempt in the log",
        )
        assert len(re.findall(failure, consumer.log_of_this_test)) == 3
        assert arrivals() == {}

    def test_a_python_child_of_a_task_inherits_the_policy(
        self, stack: Stack, kind: str, mode: str
    ) -> None:
        path = probe_path("child", FORBIDDEN_NAME, OTHER_PORT)
        for pid, report in stack.each_process(path, PROCESSES[kind]).items():
            assert report["outcome"] == "reached", report
            child = report["child"]
            assert child["ppid"] == pid
            assert_policy(child, mode)
            assert_refused(child)
        assert arrivals() == {}

    def test_a_tool_launched_by_a_task_is_warned_about_and_is_not_restricted(
        self, stack: Stack
    ) -> None:
        report = stack.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["stdout"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}"
        assert arrivals() == {AT_FORBIDDEN: 1}
        stack.consumer.wait_log(
            r"tethered: external subprocess launch detected: subprocess\.Popen\(bash\)"
        )


# ── Worker processes that are started later ───────────────────────────


class TestLaterWorkerProcesses:
    @pytest.mark.parametrize(
        ("where", "mode"),
        [("import", "plain"), ("import", "locked"), ("on_startup", "locked")],
    )
    def test_a_worker_started_after_max_tasks_enforces_the_policy(
        self, where: str, mode: str
    ) -> None:
        # --max-tasks 3: a worker process ends after three tasks, and the
        # consumer's health check (here every second) starts another.
        stack = start_stack(
            "process",
            "--max-tasks",
            "3",
            "--health-check-interval",
            "1",
            activate=mode,
            where=where,
        )
        first = stack.each_process("/whoami", 2)

        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in stack.each_process(path, 2, exclude=first).values():
            assert report["ppid"] == stack.consumer.pid
            assert_policy(report, mode)
            assert_refused(report)
        assert arrivals() == {}

    def test_a_worker_that_replaces_a_killed_one_and_a_restarted_consumer_enforce_the_policy(
        self,
    ) -> None:
        stack = start_stack("process", "--health-check-interval", "1")
        consumer = stack.consumer
        first = stack.each_process("/whoami", 2)

        # A worker process dies; the health check starts another.
        consumer.send_signal(signal.SIGKILL, min(first))
        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in stack.each_process(path, 1, exclude=first).values():
            assert report["ppid"] == consumer.pid
            assert_policy(report, "locked")
            assert_refused(report)
        assert arrivals() == {}

        # SIGHUP: the consumer stops its workers and replaces itself (os.execl
        # of the same command).  It inherits the locked policy at startup.
        seen = set(consumer.pids())
        consumer.send_signal(signal.SIGHUP)
        consumer.wait_log("Consumer will restart")
        for report in stack.each_process(path, 2, exclude=seen).values():
            assert report["ppid"] == consumer.pid
            assert_policy(report, "locked")
            assert_refused(report)
        assert arrivals() == {}
        # The application's own activate() in the new consumer changes nothing.
        consumer.wait_log("no-op — the requested policy is identical to the active locked")

    def test_a_restarted_consumer_with_a_plain_policy_enforces_it(self) -> None:
        stack = start_stack("thread", activate="plain")
        consumer = stack.consumer
        consumer.send_signal(signal.SIGHUP)
        consumer.wait_log("Consumer will restart")
        consumer.wait_log("Huey consumer started with 2 thread")
        report = stack.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert report["pid"] == consumer.pid
        assert_policy(report, "plain")
        assert_refused(report)
        assert arrivals() == {}
        assert stack.probe("connect", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"


class TestBlockingExternalLaunches:
    @pytest.mark.parametrize("kind", ["thread", "process"])
    def test_the_consumer_starts_and_works_and_a_tool_is_not_launched(self, kind: str) -> None:
        # external_subprocess_policy="block" in the consumer: starting a
        # worker process is a fork, not a launch.
        stack = start_stack(kind, env={"TETH_ESP": "block"})
        path = probe_path("child", FORBIDDEN_NAME, OTHER_PORT)
        for report in stack.each_process(path, PROCESSES[kind]).values():
            assert report["external_subprocess_policy"] == "block"
            assert report["outcome"] == "reached", report
            assert_policy(report["child"], "locked")
            assert_refused(report["child"])

        assert_refused(stack.probe("tool", FORBIDDEN_NAME, OTHER_PORT), SUBPROCESS_BLOCKED)
        assert arrivals() == {}
        assert stack.probe("connect", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
