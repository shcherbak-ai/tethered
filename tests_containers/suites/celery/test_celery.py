"""Celery workers, with Redis as broker and result backend.

What runs task code depends on the pool: children forked from the worker's
main process (prefork, the default), threads, the main thread itself (solo),
or greenlets (gevent, eventlet).  The application (``celery_tasks.py``)
activates the policy where a user would: when the module is imported, which
is in the main process before the pool exists, or in a worker-start signal
(``TETH_WHERE``).

A test asks for a task through the front end (``front.py``, a producer that
holds no policy unless the test says so), and asserts what the task reported,
what the producer and the worker's log say about a refused task, and what
arrived in the world.  Covered: every pool, pool processes that are started
later (recycled, killed and replaced, autoscaled, after a ``SIGHUP``
restart), ``celery beat`` embedded and on its own, launches from a task, a
broker that is not on loopback, and ``external_subprocess_policy="block"``.

Not covered: brokers other than Redis, ``celery multi`` and ``--detach``
(a daemonized worker leaves the harness's view), and Celery's own
``worker_pool_restarts`` remote control.
"""

from __future__ import annotations

import json
import re
import signal
import socket
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
    probe_path,
    start_server,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Mapping

REDIS = ["redis-server", "--port", "{port}", "--save", "", "--appendonly", "no"]
CELERY = ["celery", "--app", "celery_tasks"]
#: Mingle and gossip are how workers of one cluster find each other; here there is one.
WORKER = [*CELERY, "worker", "--loglevel", "INFO", "--without-mingle", "--without-gossip"]
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

#: Per pool, with ``--concurrency 2``: what Celery's banner calls it, how many
#: processes run task code, the thread a task reports, and the socket class it sees.
POOLS = {
    "prefork": ("prefork", 2, "MainThread", "socket.socket"),
    "threads": ("thread", 1, "ThreadPoolExecutor-", "socket.socket"),
    "solo": ("solo", 1, "MainThread", "socket.socket"),
    "gevent": ("gevent", 1, "Dummy-", "gevent._socket3.socket"),
}


# ── A worker, its broker and a producer ───────────────────────────────


@dataclass
class Stack:
    """A Redis server, a Celery worker that uses it, and the front end that sends it tasks."""

    redis: Server
    worker: Server
    front: Server
    #: What every process of the stack has in its environment.
    settings: dict[str, str]

    def probe(
        self, op: str, host: str | None = None, port: int | None = None, **params: object
    ) -> dict[str, Any]:
        """One task (or ``main``: the worker's main process over remote control)."""
        return self.front.probe(op, host, port, **params)

    def each_process(
        self, path: str, count: int, exclude: Collection[int] = ()
    ) -> dict[int, dict[str, Any]]:
        """The reports of tasks run by ``count`` different pool processes."""
        return self.front.each_worker(path, count, exclude=exclude)

    def records(self) -> list[dict[str, Any]]:
        """The reports of the tasks nobody waited for (``record=1``)."""
        try:
            lines = Path(self.settings["TC_RECORD"]).read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        return [json.loads(line) for line in lines]

    def wait_records(self, count: int) -> list[dict[str, Any]]:
        """Wait until ``count`` such tasks have run; returns the reports that are there then."""
        return wait_for(
            lambda: len(self.records()) >= count and self.records(), f"{count} recorded tasks"
        )


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


def start_redis(host: str = LOOPBACK_ADDR) -> Server:
    def accepting(server: Server) -> bool:
        socket.create_connection((host, server.port), timeout=1.0).close()
        return True

    return start_server([*REDIS, "--bind", host, "--protected-mode", "no"], ready=accepting)


def broker_settings(redis: Server, host: str = LOOPBACK_ADDR) -> dict[str, str]:
    """The environment of everything that uses this broker."""
    record = Path(tempfile.gettempdir()) / f"tc-record-{redis.port}.jsonl"
    return {"BROKER_URL": f"redis://{host}:{redis.port}/0", "TC_RECORD": str(record)}


def worker_ready(server: Server) -> bool:
    return " ready." in server.log


def start_front(settings: Mapping[str, str], activate: str = "none") -> Server:
    return start_server(
        ["python", "front.py"], env={**settings, "TETH_ACTIVATE": activate}, ready="/front"
    )


def start_stack(
    *worker_options: str,
    activate: str = "locked",
    where: str = "import",
    env: Mapping[str, str] | None = None,
    front_activate: str = "none",
) -> Stack:
    """Start Redis on loopback, ``celery worker`` with these options, and a front end."""
    redis = start_redis()
    settings = {**broker_settings(redis), **(env or {})}
    worker = start_server(
        [*WORKER, *worker_options],
        env={**settings, "TETH_ACTIVATE": activate, "TETH_WHERE": where},
        ready=worker_ready,
        timeout=60,
    )
    return Stack(redis, worker, start_front(settings, front_activate), settings)


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_policy(report: dict[str, Any], mode: str) -> None:
    assert report["active"] is True, report
    assert report["locked"] is (mode == "locked"), report


# ── Every pool, a plain and a locked policy ───────────────────────────


#: Each pool under a locked policy, and the two that differ most under a plain one.
ARRANGEMENTS = [
    ("prefork", "plain"),
    ("prefork", "locked"),
    ("threads", "plain"),
    ("threads", "locked"),
    ("solo", "locked"),
    ("gevent", "locked"),
]


@pytest.fixture(scope="module", params=ARRANGEMENTS, ids="-".join)
def arrangement(request: pytest.FixtureRequest) -> tuple[str, str]:
    return request.param


@pytest.fixture(scope="module")
def pool(arrangement: tuple[str, str]) -> str:
    return arrangement[0]


@pytest.fixture(scope="module")
def mode(arrangement: tuple[str, str]) -> str:
    return arrangement[1]


@pytest.fixture(scope="module")
def stack(pool: str, mode: str) -> Stack:
    """A worker whose application activates the policy when it is imported."""
    return start_stack("--pool", pool, "--concurrency", "2", activate=mode)


class TestPools:
    def test_the_pool_is_the_one_asked_for_and_holds_the_policy(
        self, stack: Stack, pool: str, mode: str
    ) -> None:
        banner, processes, thread, socket_class = POOLS[pool]
        worker = stack.worker
        assert re.search(rf"concurrency: \d+ \({banner}\)", worker.log)
        main = stack.probe("main")
        assert main["pid"] == worker.pid
        assert_policy(main, mode)

        answers = stack.each_process("/whoami", processes)
        for me in answers.values():
            assert_policy(me, mode)
            # The application, and with it activate(), ran in the main process.
            assert me["imported_in_pid"] == worker.pid
            assert me["thread"].startswith(thread), me
            assert me["socket_class"] == socket_class, me
            if pool == "prefork":
                assert me["ppid"] == worker.pid
        if pool == "prefork":
            assert worker.pids() == sorted([worker.pid, *answers])
        else:
            assert list(answers) == worker.pids() == [worker.pid]

    @pytest.mark.parametrize("op", ["connect", "urllib"])
    def test_every_pool_process_reaches_the_allowed_destination(
        self, stack: Stack, pool: str, op: str
    ) -> None:
        path = probe_path(op, ALLOWED_NAME, ALLOWED_PORT)
        for report in stack.each_process(path, POOLS[pool][1]).values():
            assert report["outcome"] == "reached", report
            assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_every_pool_process_refuses_a_destination_outside_the_allow_list(
        self, stack: Stack, pool: str, host: str, port: int
    ) -> None:
        if pool == "gevent":
            # One task, not several at once.  Under gevent's default resolver a refused
            # lookup that overlaps another one now and then never returns (the hazard
            # described in suites/gunicorn_gevent/test_gunicorn_gevent.py).  Its task
            # never ends, and the warm shutdown of the worker then waits for that task.
            reports = [stack.probe("connect", host, port)]
        else:
            path = probe_path("connect", host, port)
            reports = list(stack.each_process(path, POOLS[pool][1]).values())
        for report in reports:
            assert_refused(report)
        assert arrivals() == {}

    def test_an_uncaught_refusal_is_a_failed_task_and_the_pool_keeps_working(
        self, stack: Stack, pool: str
    ) -> None:
        before = stack.each_process("/whoami", POOLS[pool][1])
        task = stack.probe("connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)["task"]
        assert arrivals() == {}
        assert task["celery_state"] == "FAILURE", task
        # This producer has not imported tethered.  Celery's JSON result backend
        # then rebuilds the exception as a class of the same name of its own.
        assert task["exception"] == "celery.exceptions.EgressBlocked", task
        assert task["message"] == REFUSED_NAME
        assert task["traceback"].rstrip().endswith(f"{EGRESS_BLOCKED}: {REFUSED_NAME}")
        # What the operator finds in the worker's log: an ordinary task failure.
        stack.worker.wait_log(
            rf"ERROR/\S+\] Task probe\[{task['id']}\] raised unexpected: "
            rf"EgressBlocked\('{re.escape(REFUSED_NAME)}'\)"
        )
        stack.worker.wait_log(rf"{re.escape(EGRESS_BLOCKED)}: {re.escape(REFUSED_NAME)}")
        assert set(stack.each_process("/whoami", POOLS[pool][1])) == set(before)

    def test_autoretry_for_exception_retries_a_refused_task(self, stack: Stack) -> None:
        # autoretry_for=(Exception,), max_retries=2: tried three times, refused three times.
        answer = stack.probe(
            "connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1, task="probe_retry_any"
        )
        task = answer["task"]
        assert task["celery_state"] == "FAILURE", task
        assert arrivals() == {}
        log = stack.worker.log_of_this_test
        assert log.count(f"Task probe_retry_any[{task['id']}] received") == 3
        stack.worker.wait_log(
            rf"Task probe_retry_any\[{task['id']}\] retry: Retry in 0s: EgressBlocked\("
        )

    def test_autoretry_for_oserror_does_not_retry_a_refused_task(self, stack: Stack) -> None:
        # EgressBlocked is a RuntimeError, not an OSError: retry settings written
        # for network errors leave it alone, and the task fails at once.
        answer = stack.probe(
            "connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1, task="probe_retry_oserror"
        )
        task = answer["task"]
        assert task["celery_state"] == "FAILURE", task
        assert arrivals() == {}
        log = stack.worker.log_of_this_test
        assert log.count(f"Task probe_retry_oserror[{task['id']}] received") == 1
        assert f"probe_retry_oserror[{task['id']}] retry" not in log

    def test_a_python_child_of_a_task_inherits_the_policy(
        self, stack: Stack, pool: str, mode: str
    ) -> None:
        path = probe_path("child", FORBIDDEN_NAME, OTHER_PORT)
        for pid, report in stack.each_process(path, POOLS[pool][1]).items():
            assert report["outcome"] == "reached", report
            child = report["child"]
            assert child["ppid"] == pid
            assert_policy(child, mode)
            assert_refused(child)
        assert arrivals() == {}

    def test_a_tool_launched_by_a_task_is_warned_about_and_is_not_restricted(
        self, stack: Stack, pool: str
    ) -> None:
        report = stack.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["stdout"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}"
        assert arrivals() == {AT_FORBIDDEN: 1}
        if pool == "gevent":
            # gevent's subprocess forks and then execs in Python: the launch is seen in
            # the forked child, once per PATH directory, and the warning is written to
            # that child's stderr, which is the pipe the task reads.  The worker's log
            # has it only where Celery logs the result of the task.
            assert "external subprocess launch detected: os.exec*(b'" in report["stderr"]
            assert "/bash')" in report["stderr"]
        else:
            stack.worker.wait_log(
                r"WARNING/\S+\] tethered: external subprocess launch detected: "
                r"subprocess\.Popen\(bash\)"
            )


# ── Pool processes that are started later ─────────────────────────────


def prefork(*options: str, **kwargs: Any) -> Stack:
    return start_stack("--pool", "prefork", *options, **kwargs)


class TestLaterPoolProcesses:
    @pytest.mark.parametrize("mode", ["plain", "locked"])
    def test_a_process_started_after_max_tasks_per_child_enforces_the_policy(
        self, mode: str
    ) -> None:
        stack = prefork("--concurrency", "2", "--max-tasks-per-child", "3", activate=mode)
        first = stack.each_process("/whoami", 2)

        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in stack.each_process(path, 2, exclude=first).values():
            assert report["ppid"] == stack.worker.pid
            assert_policy(report, mode)
            assert_refused(report)
        assert arrivals() == {}

        path = probe_path("connect", ALLOWED_NAME, ALLOWED_PORT)
        for report in stack.each_process(path, 2, exclude=first).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    def test_a_process_that_replaces_a_killed_one_and_a_restarted_worker_enforce_the_policy(
        self,
    ) -> None:
        stack = prefork("--concurrency", "2")
        worker = stack.worker
        first = stack.each_process("/whoami", 2)

        # A pool process dies (the OOM killer, a hard time limit); Celery forks another.
        worker.send_signal(signal.SIGKILL, min(first))
        worker.wait_log(rf"pid:{min(first)} exited with 'signal 9 \(SIGKILL\)'")
        wait_for(lambda: set(worker.pids()) - {worker.pid, *first}, "a replacement process")
        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        replaced = stack.each_process(path, 1, exclude=first)
        for report in replaced.values():
            assert report["ppid"] == worker.pid
            assert_policy(report, "locked")
            assert_refused(report)
        assert arrivals() == {}

        # SIGHUP: the main process replaces itself (os.execv of the same command)
        # and inherits the locked policy at startup, before it imports anything.
        seen = {*first, *replaced}
        worker.send_signal(signal.SIGHUP)
        worker.wait_log("Restarting celery worker")
        for report in stack.each_process(path, 2, exclude=seen).values():
            assert report["ppid"] == worker.pid
            assert_policy(report, "locked")
            assert_refused(report)
        assert arrivals() == {}
        assert_policy(stack.probe("main"), "locked")
        # The application's own activate() in the new main process changes nothing.
        worker.wait_log("activate\\(\\) no-op — the requested policy is identical to the active")

    def test_processes_added_by_autoscaling_enforce_the_policy(self) -> None:
        stack = prefork("--autoscale", "3,1")
        assert len(stack.worker.pids()) == 2, "the main process and one pool process"

        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in stack.each_process(path, 3).values():
            assert report["ppid"] == stack.worker.pid
            assert_policy(report, "locked")
            assert_refused(report)
        assert arrivals() == {}
        stack.worker.wait_log("Scaling up 1 processes")


# ── Where the policy is activated ─────────────────────────────────────


class TestWorkerStartSignals:
    def test_worker_process_init_covers_every_prefork_process_and_not_the_main_one(self) -> None:
        stack = prefork(
            "--concurrency", "2", "--max-tasks-per-child", "3", where="worker_process_init"
        )
        main = stack.probe("main")
        assert main["tethered_imported"] is False, main

        first = stack.each_process("/whoami", 2)
        for report in first.values():
            assert_policy(report, "locked")
        # Processes that replace them get the signal too.
        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in stack.each_process(path, 2, exclude=first).values():
            assert_policy(report, "locked")
            assert_refused(report)
        assert arrivals() == {}

    @pytest.mark.parametrize("pool", ["threads", "gevent"])
    def test_worker_process_init_is_never_sent_in_a_thread_or_gevent_pool(self, pool: str) -> None:
        """Limit: a policy activated only in ``worker_process_init`` is not there in these pools.

        Celery sends that signal in the children of the prefork pool and in the
        solo pool.  With ``--pool threads`` or ``--pool gevent`` the handler
        never runs, tethered is never activated, and the worker runs unrestricted.
        """
        stack = start_stack("--pool", pool, "--concurrency", "2", where="worker_process_init")
        report = stack.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert report["tethered_imported"] is False, report
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}

    def test_worker_init_covers_a_thread_pool(self) -> None:
        # worker_init is sent in the main process, whatever the pool.
        stack = start_stack("--pool", "threads", "--concurrency", "2", where="worker_init")
        assert_policy(stack.probe("main"), "locked")
        report = stack.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert_policy(report, "locked")
        assert_refused(report)
        assert arrivals() == {}


# ── external_subprocess_policy="block" ────────────────────────────────


class TestBlockingExternalLaunches:
    def test_the_worker_does_not_start(self) -> None:
        """Limit: ``celery worker`` cannot start under ``external_subprocess_policy="block"``.

        Its startup banner calls ``platform.platform()``, which launches
        ``uname -p`` and catches only ``OSError``; the ``SubprocessBlocked``
        of the refused launch ends the worker.
        """
        redis = start_redis()
        started: list[Server] = []

        def ready(server: Server) -> bool:
            started.append(server)
            return worker_ready(server)

        env = {**broker_settings(redis), "TETH_ACTIVATE": "locked", "TETH_ESP": "block"}
        with pytest.raises(AssertionError, match="exited with status 1 while starting"):
            start_server([*WORKER, "--pool", "solo"], env=env, ready=ready)
        log = started[0].log
        assert "platform.py" in log
        assert f"{SUBPROCESS_BLOCKED}: Blocked by tethered: subprocess.Popen(uname)" in log

    def test_it_starts_when_platform_was_asked_before_the_policy(self) -> None:
        # platform caches the answer: asked once before activate(), it launches
        # nothing afterwards.  Then only what tasks launch is refused.
        stack = prefork("--concurrency", "2", env={"TETH_ESP": "block", "PLATFORM_FIRST": "1"})

        path = probe_path("child", FORBIDDEN_NAME, OTHER_PORT)
        for report in stack.each_process(path, 2).values():
            assert report["outcome"] == "reached", report
            assert_policy(report["child"], "locked")
            assert report["child"]["external_subprocess_policy"] == "block"
            assert_refused(report["child"])

        assert_refused(stack.probe("tool", FORBIDDEN_NAME, OTHER_PORT), SUBPROCESS_BLOCKED)
        stack.worker.wait_log(r"blocked external subprocess launch: subprocess\.Popen\(bash\)")
        report = stack.probe("child", FORBIDDEN_NAME, OTHER_PORT, how="path_python")
        assert_refused(report, SUBPROCESS_BLOCKED)
        assert arrivals() == {}


# ── What the producer gets back ───────────────────────────────────────


class TestTheProducer:
    def test_a_producer_under_a_locked_policy_sends_tasks_and_gets_egress_blocked(self) -> None:
        """With JSON results, a producer that has tethered loaded gets ``EgressBlocked``.

        Celery's JSON result backend stores the class name and ``args`` of an
        exception and rebuilds it by calling the class with them.  ``args``
        of ``EgressBlocked`` is its message, and the class accepts the
        message alone: ``except tethered.EgressBlocked`` around
        ``result.get()`` matches, and the attributes are read back out of
        the message.
        """
        stack = start_stack("--pool", "solo", front_activate="locked")
        assert_policy(stack.front.get("/front").json(), "locked")

        # The broker is on loopback, which the policy of the producer allows.
        report = stack.probe("connect", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 1}

        # Refused at the lookup: a name and no port.
        task = stack.probe("connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)["task"]
        assert task["celery_state"] == "FAILURE", task
        assert task["exception"] == EGRESS_BLOCKED, task
        assert task["message"] == REFUSED_NAME
        assert (task["host"], task["port"]) == (FORBIDDEN_NAME, None)

        # Refused at the connection: the address, the port, and the name it was looked up by.
        task = stack.probe("connect", ALLOWED_NAME, OTHER_PORT, uncaught=1)["task"]
        assert task["exception"] == EGRESS_BLOCKED, task
        assert task["message"] == (
            f"Blocked by tethered: {ALLOWED_ADDR}:{OTHER_PORT} "
            f"(resolved from {ALLOWED_NAME}) is not in the allow list"
        )
        assert (task["host"], task["port"]) == (ALLOWED_ADDR, OTHER_PORT)
        assert arrivals() == {AT_ALLOWED: 1}

    def test_with_pickled_results_the_producer_gets_egress_blocked(self) -> None:
        stack = start_stack("--pool", "solo", env={"RESULT_SERIALIZER": "pickle"})
        under_a_policy = start_front(stack.settings, "locked")
        # Unpickling imports tethered in a producer that had not loaded it.
        for front in (stack.front, under_a_policy):
            task = front.probe("connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)["task"]
            assert task["celery_state"] == "FAILURE", task
            assert task["exception"] == EGRESS_BLOCKED, task
            assert task["message"] == REFUSED_NAME
        assert arrivals() == {}


# ── celery beat ───────────────────────────────────────────────────────


def beat_schedule(name: str) -> str:
    """Where beat keeps its schedule: not in the suite directory."""
    return str(Path(tempfile.gettempdir()) / f"tc-beat-{name}")


class TestBeat:
    def test_tasks_sent_by_beat_inside_the_worker_are_refused(self) -> None:
        # --beat: the scheduler is a child process forked from the worker's main process.
        env = {"BEAT_TARGET": f"{FORBIDDEN_NAME}:{OTHER_PORT}"}
        stack = start_stack(
            "--pool", "solo", "--beat", "--schedule", beat_schedule("embedded"), env=env
        )
        assert len(stack.worker.pids()) == 2, "the worker and its beat process"
        stack.worker.wait_log(r"INFO/Beat\] Scheduler: Sending due task tick \(probe\)")
        reports = stack.wait_records(3)
        for report in reports:
            assert report["pid"] == stack.worker.pid
            assert_policy(report, "locked")
            assert_refused(report)
        assert arrivals() == {}

    def test_a_beat_process_of_its_own_runs_under_the_policy(self) -> None:
        env = {"BEAT_TARGET": f"{FORBIDDEN_NAME}:{OTHER_PORT}"}
        stack = start_stack("--pool", "solo", env=env)
        beat = start_server(
            [*CELERY, "beat", "--loglevel", "INFO", "--schedule", beat_schedule("own")],
            env={**stack.settings, "TETH_ACTIVATE": "locked"},
            ready=lambda server: "beat: Starting..." in server.log,
        )
        assert re.search(rf"probe: pid {beat.pid} activated tethered \(locked\)", beat.log)
        beat.wait_log(r"Scheduler: Sending due task tick \(probe\)")
        reports = stack.wait_records(3)
        for report in reports:
            assert_policy(report, "locked")
            assert_refused(report)
        assert arrivals() == {}


# ── eventlet ──────────────────────────────────────────────────────────


def eventlet(**env: str) -> Stack:
    stack = start_stack("--pool", "eventlet", "--concurrency", "2", env=env)
    assert re.search(r"concurrency: 2 \(eventlet\)", stack.worker.log)
    me = stack.probe("whoami")
    assert me["socket_class"] == "eventlet.greenio.base.GreenSocket", me
    assert_policy(me, "locked")
    return stack


class TestEventletPool:
    def test_a_hostname_rule_does_not_match_and_an_address_rule_does(self) -> None:
        """Limit: under eventlet a destination that a hostname rule allows is refused.

        eventlet resolves names with its own resolver (dnspython), which
        raises no ``socket.getaddrinfo`` event.  tethered sees only the
        connection to an address it has no name for, so ``allowed.test:9001``
        is refused as ``10.77.0.10:9001``.  Nothing forbidden gets out.
        """
        port = 9003
        stack = eventlet(TETH_ALLOW=f"{ALLOWED_NAME}:{ALLOWED_PORT},{ALLOWED_ADDR}:{port}")

        report = stack.probe("connect", ALLOWED_NAME, ALLOWED_PORT)
        assert_refused(report)
        assert report["message"] == (
            f"Blocked by tethered: {ALLOWED_ADDR}:{ALLOWED_PORT} is not in the allow list"
        )
        assert arrivals() == {}

        # The same host by name, on the port that the address rule allows.
        report = stack.probe("connect", ALLOWED_NAME, port)
        assert report["outcome"] == "reached", report
        assert arrivals() == {f"{ALLOWED_ADDR}:{port}/tcp": 1}

        report = stack.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert_refused(report)
        assert report["message"] == (
            f"Blocked by tethered: {FORBIDDEN_ADDR}:{OTHER_PORT} is not in the allow list"
        )
        assert arrivals() == {f"{ALLOWED_ADDR}:{port}/tcp": 1}

    def test_with_the_system_resolver_a_hostname_rule_matches(self) -> None:
        # EVENTLET_NO_GREENDNS=yes: eventlet leaves name resolution to the
        # standard library, and tethered sees the lookup.
        stack = eventlet(EVENTLET_NO_GREENDNS="yes")
        report = stack.probe("connect", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 1}

        report = stack.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert_refused(report)
        assert report["message"] == REFUSED_NAME
        assert arrivals() == {AT_ALLOWED: 1}


# ── A broker that is not on loopback ──────────────────────────────────


class TestBrokerByName:
    def test_a_broker_the_allow_list_names_is_used_by_every_process(self) -> None:
        redis = start_redis(ALLOWED_ADDR)
        settings = broker_settings(redis, ALLOWED_NAME)
        allow = f"{ALLOWED_NAME}:{ALLOWED_PORT},{ALLOWED_NAME}:{redis.port}"
        worker = start_server(
            [*WORKER, "--pool", "prefork", "--concurrency", "2"],
            env={**settings, "TETH_ACTIVATE": "locked", "TETH_ALLOW": allow},
            ready=worker_ready,
            timeout=60,
        )
        stack = Stack(redis, worker, start_front(settings), settings)

        path = probe_path("connect", ALLOWED_NAME, ALLOWED_PORT)
        for report in stack.each_process(path, 2).values():
            assert_policy(report, "locked")
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}
        for report in stack.each_process(probe_path("connect", FORBIDDEN_NAME, 9002), 2).values():
            assert_refused(report)
        assert set(arrivals()) == {AT_ALLOWED}

    def test_a_broker_the_allow_list_does_not_name_stops_the_worker_at_startup(self) -> None:
        # kombu retries connection errors; EgressBlocked is not one, so the
        # mistake is not retried for ever: the worker ends with the refusal.
        redis = start_redis(ALLOWED_ADDR)
        started: list[Server] = []

        def ready(server: Server) -> bool:
            started.append(server)
            return worker_ready(server)

        env = {**broker_settings(redis, ALLOWED_NAME), "TETH_ACTIVATE": "locked"}
        with pytest.raises(AssertionError, match="exited with status 1 while starting"):
            start_server([*WORKER, "--pool", "solo"], env=env, ready=ready)
        assert (
            f"{EGRESS_BLOCKED}: Blocked by tethered: {ALLOWED_ADDR}:{redis.port} "
            f"(resolved from {ALLOWED_NAME}) is not in the allow list"
        ) in started[0].log


# ── The modes that do not refuse ──────────────────────────────────────


class TestNotEnforcing:
    def test_log_only_reports_the_connection_in_the_log_of_the_pool_process(self) -> None:
        stack = prefork("--concurrency", "1", activate="log_only")
        report = stack.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        stack.worker.wait_log(
            rf"WARNING/ForkPoolWorker-1\] tethered: would block getaddrinfo for {FORBIDDEN_NAME}"
        )
        stack.worker.wait_log(f"tethered: would block connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")
