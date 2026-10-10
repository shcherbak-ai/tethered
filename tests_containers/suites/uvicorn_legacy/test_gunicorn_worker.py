"""gunicorn with uvicorn's worker class, against uvicorn 0.46.0.

The uvicorn command of this release loads uvloop before the application
(``test_uvicorn_legacy.py``).  Its gunicorn worker does not: gunicorn imports
the application in ``init_process()`` and the worker asks uvicorn for its
loop afterwards, in ``run()``.  So under gunicorn this release behaves like
the current one: the policy is active first, the import of uvloop is
refused, and the worker runs on the standard asyncio loop.  The same holds
for the ``uvicorn-worker`` package, which calls into the installed uvicorn.

A shorter version of the ``gunicorn_uvicorn`` suite, which has the full set
against the current uvicorn.
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

GUNICORN = ["gunicorn", "probe_asgi:app", "--bind", "127.0.0.1:{port}", "--workers", "2"]
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
UVLOOP_WARNING = "tethered: uvloop is loaded in this process."

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"

STREAM_OPS = ["open_connection", "create_connection", "sock_connect", "to_thread", "connect"]
#: Destinations the allow list does not cover.
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]


def gunicorn(source: str, *, preload: bool = False) -> list[str]:
    command = [*GUNICORN, "--worker-class", WORKER_CLASSES[source]]
    return [*command, "--preload"] if preload else command


def assert_refused(report: dict[str, Any]) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == EGRESS_BLOCKED, report


def assert_enforcing(report: dict[str, Any]) -> None:
    assert report["active"] is True, report
    assert report["locked"] is True, report
    assert report["loop"] == STANDARD_LOOP, report


@pytest.fixture(scope="module", params=ARRANGEMENTS)
def arrangement(request: pytest.FixtureRequest) -> tuple[str, bool]:
    return request.param


@pytest.fixture(scope="module")
def server(arrangement: tuple[str, bool]) -> Server:
    source, preload = arrangement
    return start_server(gunicorn(source, preload=preload), env={"TETH_ACTIVATE": "locked"})


class TestUvicornWorker:
    def test_every_worker_runs_on_the_standard_loop_with_the_locked_policy(
        self, server: Server, arrangement: tuple[str, bool]
    ) -> None:
        _, preload = arrangement
        answers = server.each_worker("/whoami", 2)
        for pid, me in answers.items():
            assert_enforcing(me)
            assert me["ppid"] == server.pid
            assert me["imported_in_pid"] == (server.pid if preload else pid)
        log = server.log
        assert log.count(REFUSED_TO_LOAD) == 2, log
        assert "uvloop is loaded" not in log, log

    @pytest.mark.parametrize("op", STREAM_OPS)
    def test_every_worker_reaches_the_allowed_destination(self, server: Server, op: str) -> None:
        for report in server.each_worker(probe_path(op, ALLOWED_NAME, ALLOWED_PORT), 2).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize("op", ["open_connection", "create_connection"])
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


def test_a_worker_that_replaces_a_killed_one_enforces(arrangement: tuple[str, bool]) -> None:
    source, preload = arrangement
    server = start_server(gunicorn(source, preload=preload), env={"TETH_ACTIVATE": "locked"})
    first = server.each_worker("/whoami", 2)
    server.send_signal(signal.SIGKILL, min(first))

    path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
    (replacement,) = server.each_worker(path, 1, exclude=first).values()
    assert replacement["ppid"] == server.pid
    assert_enforcing(replacement)
    assert_refused(replacement)
    assert arrivals() == {}


@pytest.mark.parametrize("source", list(WORKER_CLASSES))
def test_without_tethered_the_worker_runs_on_uvloop(source: str) -> None:
    # The control: this image does give the worker uvloop when nothing refuses it.
    server = start_server(gunicorn(source), env={"TETH_ACTIVATE": "none"})
    for me in server.each_worker("/whoami", 2).values():
        assert me["loop"] == UVLOOP, me
    report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
    assert report["outcome"] == "reached", report
    assert arrivals() == {AT_FORBIDDEN: 1}


def test_under_a_log_only_policy_the_workers_run_on_uvloop_and_report_nothing() -> None:
    """Limit: a log-only policy refuses nothing, so every worker gets uvloop."""
    server = start_server(gunicorn("uvicorn.workers"), env={"TETH_ACTIVATE": "log_only"})
    path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
    for report in server.each_worker(path, 2).values():
        assert report["loop"] == UVLOOP, report
        assert report["outcome"] == "reached", report
    assert set(arrivals()) == {AT_FORBIDDEN}
    assert server.log.count(UVLOOP_WARNING) == 2, server.log
    assert "tethered: blocked" not in server.log, server.log
