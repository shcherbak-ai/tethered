"""gunicorn with uvicorn's worker class and uvloop installed.

``UvicornWorker`` exists twice: in ``uvicorn.workers``, which uvicorn has
deprecated and still ships, and in the ``uvicorn-worker`` package that
replaces it.  Both ask uvicorn for the loop ``auto``, which is uvloop
whenever importing it works, and nothing that goes through a uvloop event
loop raises an audit event.

With either class a worker imports the application before it asks for its
loop, and under ``--preload`` it is forked from a master that has imported
it.  So the policy is active first in both arrangements: the import of
uvloop is refused, the worker runs on the standard asyncio loop, and the
policy is enforced.  Each test checks the loop through ``/whoami`` in every
worker and asserts what arrived in the world.

A log-only policy refuses nothing, uvloop included: asserted as a limit.

gunicorn's own ``asgi`` worker is here for comparison, because it makes the
same choice the other way round: it sets up its loop before it imports the
application.

The application is ``probe_asgi:app`` from ``harness/apps``.  The uvicorn
suite covers uvicorn without gunicorn; ``uvicorn_legacy`` repeats the worker
tests against uvicorn 0.46.
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
    OTHER_PORT,
    Server,
    arrivals,
    probe_path,
    start_server,
)
from one_shot import run_to_exit

GUNICORN = ["gunicorn", "probe_asgi:app", "--bind", "127.0.0.1:{port}"]
#: Where ``UvicornWorker`` comes from, by the name the tests use.
WORKER_CLASSES = {
    "uvicorn.workers": "uvicorn.workers.UvicornWorker",
    "uvicorn-worker": "uvicorn_worker.UvicornWorker",
}
ARRANGEMENTS = [
    pytest.param((source, preload), id=f"{source}{'-preload' if preload else ''}")
    for source in WORKER_CLASSES
    for preload in (False, True)
]

STANDARD_LOOP = "asyncio.unix_events._UnixSelectorEventLoop"
UVLOOP = "uvloop.Loop"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"

REFUSED_TO_LOAD = "tethered: refused to load uvloop while a policy is active"
ACTIVATE_REFUSED = "RuntimeError: tethered: activate() refused"
UVLOOP_WARNING = "tethered: uvloop is loaded in this process."
#: gunicorn's exit status when a worker could not boot.
WORKER_BOOT_ERROR = 3

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


def gunicorn(
    worker_class: str, *options: str, preload: bool = False, workers: int = 2
) -> list[str]:
    command = [*GUNICORN, "--workers", str(workers), "--worker-class", worker_class, *options]
    return [*command, "--preload"] if preload else command


def assert_refused(report: dict[str, Any]) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == EGRESS_BLOCKED, report


def assert_enforcing(report: dict[str, Any], *, locked: bool = True) -> None:
    assert report["active"] is True, report
    assert report["locked"] is locked, report
    assert report["loop"] == STANDARD_LOOP, report


# ── Both classes, with and without --preload, two workers, a locked policy ──


@pytest.fixture(scope="module", params=ARRANGEMENTS)
def arrangement(request: pytest.FixtureRequest) -> tuple[str, bool]:
    return request.param


@pytest.fixture(scope="module")
def server(arrangement: tuple[str, bool]) -> Server:
    source, preload = arrangement
    return start_server(
        gunicorn(WORKER_CLASSES[source], preload=preload), env={"TETH_ACTIVATE": "locked"}
    )


class TestUvicornWorker:
    def test_every_worker_runs_on_the_standard_loop_with_the_locked_policy(
        self, server: Server, arrangement: tuple[str, bool]
    ) -> None:
        _, preload = arrangement
        answers = server.each_worker("/whoami", 2)
        assert server.pid not in answers
        for pid, me in answers.items():
            assert_enforcing(me)
            assert me["ppid"] == server.pid
            # Where the application was imported, and so where activate() ran.
            assert me["imported_in_pid"] == (server.pid if preload else pid)

    def test_each_worker_asked_for_uvloop_once_and_was_refused(self, server: Server) -> None:
        server.each_worker("/whoami", 2)
        log = server.log
        # The master never asks: it runs no event loop.
        assert log.count(REFUSED_TO_LOAD) == 2, log
        assert log.index("activated tethered (locked)") < log.index(REFUSED_TO_LOAD), log
        assert "uvloop is loaded" not in log, log

    @pytest.mark.parametrize("op", STREAM_OPS)
    def test_every_worker_reaches_the_allowed_destination(self, server: Server, op: str) -> None:
        for report in server.each_worker(probe_path(op, ALLOWED_NAME, ALLOWED_PORT), 2).values():
            assert report["outcome"] == "reached", report
            assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize("op", STREAM_OPS)
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_every_worker_refuses_a_destination_outside_the_allow_list(
        self, server: Server, op: str, host: str, port: int
    ) -> None:
        for report in server.each_worker(probe_path(op, host, port), 2).values():
            assert_refused(report)
        assert arrivals() == {}

    @pytest.mark.parametrize("op", ["getaddrinfo", "datagram_connected", "datagram_unconnected"])
    def test_every_worker_refuses_a_lookup_and_a_datagram(self, server: Server, op: str) -> None:
        for report in server.each_worker(probe_path(op, FORBIDDEN_NAME, OTHER_PORT), 2).values():
            assert_refused(report)
        assert arrivals() == {}

    def test_an_uncaught_refusal_is_a_500_and_the_workers_survive(self, server: Server) -> None:
        before = server.each_worker("/whoami", 2)
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)
        assert server.get(path).status == 500
        assert arrivals() == {}
        server.wait_log("Exception in ASGI application")
        assert set(server.each_worker("/whoami", 2)) == set(before)

    def test_a_python_child_of_every_worker_inherits_the_locked_policy(
        self, server: Server
    ) -> None:
        path = probe_path("child", FORBIDDEN_NAME, OTHER_PORT)
        for pid, report in server.each_worker(path, 2).items():
            assert report["outcome"] == "reached", report
            child = report["child"]
            assert child["ppid"] == pid
            assert child["locked"] is True, child
            assert_refused(child)
        assert arrivals() == {}


# ── Workers that are started later ────────────────────────────────────


class TestLaterWorkers:
    def test_a_worker_that_replaces_a_killed_one_runs_on_the_standard_loop_and_enforces(
        self, arrangement: tuple[str, bool]
    ) -> None:
        source, preload = arrangement
        command = gunicorn(WORKER_CLASSES[source], preload=preload)
        server = start_server(command, env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)
        server.send_signal(signal.SIGKILL, min(first))

        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        (replacement,) = server.each_worker(path, 1, exclude=first).values()
        assert replacement["ppid"] == server.pid
        assert_enforcing(replacement)
        assert_refused(replacement)
        assert arrivals() == {}
        assert server.log.count(REFUSED_TO_LOAD) == 3, server.log

    def test_a_worker_started_after_max_requests_enforces(
        self, arrangement: tuple[str, bool]
    ) -> None:
        source, preload = arrangement
        command = gunicorn(WORKER_CLASSES[source], "--max-requests", "5", preload=preload)
        server = start_server(command, env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)

        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2, exclude=first).values():
            assert report["ppid"] == server.pid
            assert_enforcing(report)
            assert_refused(report)
        assert arrivals() == {}

    def test_a_worker_started_by_a_reload_enforces(self, arrangement: tuple[str, bool]) -> None:
        source, preload = arrangement
        command = gunicorn(WORKER_CLASSES[source], preload=preload)
        server = start_server(command, env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)
        server.send_signal(signal.SIGHUP)

        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2, exclude=first).values():
            assert report["ppid"] == server.pid
            assert_enforcing(report)
            assert_refused(report)
        assert arrivals() == {}
        server.wait_log("Hang up: Master")


# ── Other policies, other classes ─────────────────────────────────────


class TestOtherPolicies:
    @pytest.mark.parametrize("source", list(WORKER_CLASSES))
    def test_an_unlocked_policy_keeps_uvloop_out_as_well(self, source: str) -> None:
        server = start_server(gunicorn(WORKER_CLASSES[source]), env={"TETH_ACTIVATE": "plain"})
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2).values():
            assert_enforcing(report, locked=False)
            assert_refused(report)
        assert arrivals() == {}

    @pytest.mark.parametrize("source", list(WORKER_CLASSES))
    def test_without_tethered_the_worker_runs_on_uvloop(self, source: str) -> None:
        # The control: this image does give the worker uvloop when nothing refuses it.
        server = start_server(gunicorn(WORKER_CLASSES[source]), env={"TETH_ACTIVATE": "none"})
        for me in server.each_worker("/whoami", 2).values():
            assert me["loop"] == UVLOOP, me
            assert me["tethered_imported"] is False, me
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}

    @pytest.mark.parametrize("preload", [False, True], ids=["no-preload", "preload"])
    def test_under_a_log_only_policy_the_workers_run_on_uvloop_and_report_nothing(
        self, preload: bool
    ) -> None:
        """Limit: a log-only policy refuses nothing, so every worker gets uvloop.

        What goes through the loop is then neither refused nor reported;
        each worker says so once, in the warning it logs.
        """
        command = gunicorn(WORKER_CLASSES["uvicorn-worker"], preload=preload)
        server = start_server(command, env={"TETH_ACTIVATE": "log_only"})
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        answers = server.each_worker(path, 2)
        for report in answers.values():
            assert report["loop"] == UVLOOP, report
            assert report["log_only"] is True, report
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_FORBIDDEN}
        log = server.log
        assert log.count(UVLOOP_WARNING) == 2, log
        assert "tethered: would block" not in log, log

    @pytest.mark.parametrize(
        "worker_class", ["uvicorn.workers.UvicornH11Worker", "uvicorn_worker.UvicornH11Worker"]
    )
    def test_the_h11_worker_names_the_standard_loop_and_never_asks_for_uvloop(
        self, worker_class: str
    ) -> None:
        server = start_server(gunicorn(worker_class), env={"TETH_ACTIVATE": "locked"})
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2).values():
            assert_enforcing(report)
            assert_refused(report)
        assert arrivals() == {}
        assert REFUSED_TO_LOAD not in server.log, server.log


# ── gunicorn's own asgi worker, for comparison ────────────────────────


class TestGunicornAsgiWorker:
    def test_without_preload_no_worker_boots_and_gunicorn_exits(self) -> None:
        """Limit: ``-k asgi`` sets up its loop before it imports the application.

        With ``--asgi-loop auto`` (the default) and uvloop installed the
        worker has loaded uvloop when the application calls ``activate()``,
        which raises ``RuntimeError``; gunicorn reports that the worker
        failed to boot and exits.  It does not serve without the policy.
        """
        command = [argument.replace("{port}", "0") for argument in gunicorn("asgi")]
        done = run_to_exit(command, env={"TETH_ACTIVATE": "locked"})
        # 3 is gunicorn's status for a worker that failed to boot; with two
        # workers failing at once its shutdown can raise a second time and
        # end with 1.
        assert done["returncode"] in (WORKER_BOOT_ERROR, 1), done
        assert ACTIVATE_REFUSED in done["output"], done["output"]
        assert "Worker failed to boot" in done["output"], done["output"]
        assert arrivals() == {}

    @pytest.mark.parametrize(
        "options",
        [
            pytest.param(["--preload"], id="preload"),
            pytest.param(["--asgi-loop", "asyncio"], id="asgi-loop-asyncio"),
        ],
    )
    def test_it_enforces_when_the_policy_is_first_or_the_loop_is_named(
        self, options: list[str]
    ) -> None:
        server = start_server(gunicorn("asgi", *options), env={"TETH_ACTIVATE": "locked"})
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2).values():
            assert_enforcing(report)
            assert_refused(report)
        assert arrivals() == {}
        # Under --preload each worker asked for uvloop and fell back; with the
        # loop named nobody asked.
        expected = 2 if options == ["--preload"] else 0
        assert server.log.count(REFUSED_TO_LOAD) == expected, server.log
