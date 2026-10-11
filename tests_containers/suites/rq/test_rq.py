"""RQ workers, with Redis as the queue.

An RQ worker waits for jobs and, by default, forks a "work horse" for each
one: every job runs in a process of its own, and RQ imports the job's module
there.  ``SimpleWorker`` runs jobs in the worker process itself,
``SpawnWorker`` starts a new interpreter per job, and ``rq worker-pool``
runs several workers under one parent.

The policy is activated in one of the two places a user has: the module that
defines the jobs (``rq_tasks.py``; each work horse then activates it for
itself and the worker holds none) or the worker's settings module
(``rq_settings.py``, ``rq worker -c``; the worker holds it and the horses
start with it).  ``TETH_WHERE`` picks one.

A test asks for a job through the front end (``front.py``, which holds no
policy) and asserts what the job reported, what RQ recorded for a failed job,
what the worker logged, and what arrived in the world.

Not covered: a worker that is killed (RQ itself can lose a job then, with or
without tethered), ``rq cron``, and custom worker classes.
"""

from __future__ import annotations

import re
import socket
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
    start_server,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

REDIS = ["redis-server", "--bind", LOOPBACK_ADDR, "--port", "{port}"]
REDIS += ["--save", "", "--appendonly", "no"]
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
WORKER_CLASSES = ["Worker", "SimpleWorker", "SpawnWorker"]


# ── A worker, its queue and a producer ────────────────────────────────


@dataclass
class Stack:
    """A Redis server, an RQ worker (or worker pool) and the front end that enqueues jobs."""

    redis: Server
    worker: Server
    front: Server

    def probe(
        self, op: str, host: str | None = None, port: int | None = None, **params: object
    ) -> dict[str, Any]:
        """One job."""
        return self.front.probe(op, host, port, **params)


def start_stack(
    *options: str,
    command: str = "worker",
    workers: int = 1,
    activate: str = "locked",
    where: str = "tasks",
    env: Mapping[str, str] | None = None,
) -> Stack:
    """Start Redis, ``rq worker`` (or ``rq worker-pool``) with these options, and a front end."""

    def accepting(server: Server) -> bool:
        socket.create_connection((LOOPBACK_ADDR, server.port), timeout=1.0).close()
        return True

    redis = start_server(REDIS, ready=accepting)
    settings = {"REDIS_URL": f"redis://{LOOPBACK_ADDR}:{redis.port}/0", **(env or {})}
    worker = start_server(
        ["rq", command, "--config", "rq_settings", *options],
        env={**settings, "TETH_ACTIVATE": activate, "TETH_WHERE": where},
        ready=lambda server: server.log.count("Listening on default") >= workers,
    )
    front = start_server(
        ["python", "front.py"], env={**settings, "TETH_ACTIVATE": "none"}, ready="/front"
    )
    return Stack(redis, worker, front)


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_policy(report: dict[str, Any], mode: str) -> None:
    assert report["active"] is True, report
    assert report["locked"] is (mode == "locked"), report


# ── Every worker class, both places to activate, a plain and a locked policy ──


@pytest.fixture(scope="module", params=WORKER_CLASSES)
def worker_class(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module", params=["tasks", "settings"])
def where(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module", params=["plain", "locked"])
def mode(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def stack(worker_class: str, where: str, mode: str) -> Stack:
    return start_stack("--worker-class", f"rq.worker.{worker_class}", activate=mode, where=where)


class TestWorkerClasses:
    def test_a_job_runs_where_this_worker_runs_jobs_and_under_the_policy(
        self, stack: Stack, worker_class: str, where: str, mode: str
    ) -> None:
        worker = stack.worker
        reports = [stack.probe("whoami") for _ in range(2)]
        for report in reports:
            assert_policy(report, mode)
            # Whether the process held the policy before it imported the jobs module.
            assert report["active_before_import"] is (where == "settings"), report
            if worker_class == "SimpleWorker":
                assert report["pid"] == worker.pid
            else:
                assert report["ppid"] == worker.pid
            if worker_class == "SpawnWorker":
                # A new interpreter: "python -c ...".
                assert report["argv"] == ["-c"]
                assert report["imported_in_pid"] == report["pid"]
            else:
                # The worker itself, or a copy of it.
                assert report["argv"][1] == "worker", report
        if worker_class != "SimpleWorker":
            assert reports[0]["pid"] != reports[1]["pid"], "a process for every job"
        if worker_class == "Worker":
            # The settings module is the only one of ours the worker itself imports.
            imported_in_the_worker = reports[0]["imported_in_pid"] == worker.pid
            assert imported_in_the_worker is (where == "settings")

    def test_a_job_reaches_the_allowed_destination(self, stack: Stack) -> None:
        for _ in range(2):
            report = stack.probe("connect", ALLOWED_NAME, ALLOWED_PORT)
            assert report["outcome"] == "reached", report
            assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert arrivals() == {AT_ALLOWED: 2}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_job_is_refused_a_destination_outside_the_allow_list(
        self, stack: Stack, host: str, port: int
    ) -> None:
        for _ in range(2):
            assert_refused(stack.probe("connect", host, port))
        assert arrivals() == {}

    def test_an_uncaught_refusal_is_a_failed_job_with_the_traceback(self, stack: Stack) -> None:
        task = stack.probe("connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)["task"]
        assert arrivals() == {}
        # RQ moves the job to its failed-job registry and keeps the traceback as text.
        assert task["rq_status"] == "failed", task
        assert task["exception"] == EGRESS_BLOCKED, task
        assert task["message"] == REFUSED_NAME
        # What the operator finds in the worker's log.
        stack.worker.wait_log(
            rf"job {task['id']}: exception raised while executing \(rq_tasks\.probe\)"
        )
        stack.worker.wait_log(rf"{re.escape(EGRESS_BLOCKED)}: {re.escape(REFUSED_NAME)}")
        # The worker goes on with the next job.
        assert stack.probe("connect", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"

    def test_retry_runs_a_refused_job_again_like_any_failed_job(self, stack: Stack) -> None:
        # Retry(max=2): three attempts, each refused.
        answer = stack.probe("connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1, retries=2)
        task = answer["task"]
        assert task["rq_status"] == "failed", task
        assert task["exception"] == EGRESS_BLOCKED, task
        # RQ's own count: both retries were used up.
        assert task["retries_left"] == 0, task
        assert arrivals() == {}
        stack.worker.wait_log(rf"job {task['id']}: exception raised while executing")

    def test_a_python_child_of_a_job_inherits_the_policy(self, stack: Stack, mode: str) -> None:
        report = stack.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        child = report["child"]
        assert child["ppid"] == report["pid"]
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


# ── More processes around the worker ──────────────────────────────────


class TestWorkerPoolAndScheduler:
    @pytest.mark.parametrize("where", ["tasks", "settings"])
    def test_every_worker_of_a_worker_pool_runs_its_jobs_under_the_policy(self, where: str) -> None:
        # rq worker-pool: a parent that forks two workers (and a scheduler);
        # each worker forks a work horse per job.
        stack = start_stack("--num-workers", "2", command="worker-pool", workers=2, where=where)
        workers = [pid for pid in stack.worker.pids() if pid != stack.worker.pid]
        used = set()
        for _ in range(12):
            report = stack.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
            assert report["ppid"] in workers, "a work horse of one of the workers"
            assert report["active_before_import"] is (where == "settings")
            assert_policy(report, "locked")
            assert_refused(report)
            used.add(report["ppid"])
            if len(used) == 2:
                break
        assert len(used) == 2, "both workers have run a job"
        assert arrivals() == {}

    def test_a_job_that_the_scheduler_enqueues_runs_under_the_policy(self) -> None:
        # --with-scheduler: one more process, forked from the worker, moves
        # scheduled jobs to the queue when they are due.
        stack = start_stack("--with-scheduler", where="settings")
        stack.worker.wait_log(r"Scheduler for default started with PID \d+")
        assert len(stack.worker.pids()) == 2, "the worker and its scheduler"
        report = stack.probe("connect", FORBIDDEN_NAME, OTHER_PORT, delay="0.2")
        assert report["ppid"] == stack.worker.pid
        assert_policy(report, "locked")
        assert_refused(report)
        assert arrivals() == {}


class TestBlockingExternalLaunches:
    @pytest.mark.parametrize("worker_class", ["Worker", "SpawnWorker"])
    def test_the_worker_starts_and_runs_jobs_and_a_tool_is_not_launched(
        self, worker_class: str
    ) -> None:
        # external_subprocess_policy="block", in the worker itself: starting a
        # work horse is a fork, or a launch of this interpreter, and goes through.
        stack = start_stack(
            "--worker-class",
            f"rq.worker.{worker_class}",
            where="settings",
            env={"TETH_ESP": "block"},
        )
        report = stack.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["external_subprocess_policy"] == "block"
        assert report["outcome"] == "reached", report
        assert_policy(report["child"], "locked")
        assert_refused(report["child"])

        assert_refused(stack.probe("tool", FORBIDDEN_NAME, OTHER_PORT), SUBPROCESS_BLOCKED)
        assert arrivals() == {}
        assert stack.probe("connect", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
