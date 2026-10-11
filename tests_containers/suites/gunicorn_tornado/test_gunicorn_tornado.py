"""gunicorn with its tornado worker (``-k tornado``).

The worker runs tornado's IOLoop, which is asyncio's selector loop, and wraps
a WSGI application in tornado's ``WSGIContainer``: the application runs on the
loop's thread, and what it does with sockets and subprocesses is ordinary
blocking code.  The application is ``probe_wsgi:application``.

What differs from gunicorn's own workers is what the server does with an
exception the application lets out: nothing is sent, and the client waits.
"""

from __future__ import annotations

import socket
from typing import Any

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

GUNICORN = ["gunicorn", "probe_wsgi:application", "--bind", "127.0.0.1:{port}"]
WORKER_MODELS = {
    "tornado": ["--worker-class", "tornado"],
    "tornado-preload": ["--worker-class", "tornado", "--preload"],
}
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"

OPS = ["connect", "urllib"]
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]


def gunicorn(model: str, *options: str, workers: int = 2) -> list[str]:
    return [*GUNICORN, "--workers", str(workers), *WORKER_MODELS[model], *options]


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_locked(report: dict[str, Any]) -> None:
    assert (report["active"], report["locked"]) == (True, True), report


def answer_to(server: Server, path: str, pattern: str) -> bytes:
    """Request ``path``, wait until the server logged ``pattern``, and return what it sent.

    For a request that gets no response: once the server has logged what it
    made of the request, whatever it was going to send has been sent.
    """
    with socket.create_connection(("127.0.0.1", server.port), timeout=10.0) as connection:
        connection.sendall(f"GET {path} HTTP/1.1\r\nHost: probe\r\n\r\n".encode())
        server.wait_log(pattern)
        connection.settimeout(0.5)
        try:
            return connection.recv(4096)
        except TimeoutError:
            return b"(nothing, and the connection is still open)"


@pytest.fixture(scope="module", params=list(WORKER_MODELS))
def model(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(model: str) -> Server:
    return start_server(gunicorn(model), env={"TETH_ACTIVATE": "locked"})


class TestWorkers:
    def test_every_worker_runs_tornado_and_holds_the_locked_policy(
        self, server: Server, model: str
    ) -> None:
        server.wait_log("Using worker: tornado")
        answers = server.each_worker("/whoami", 2)
        assert server.pid not in answers
        for pid, me in answers.items():
            assert_locked(me)
            assert me["ppid"] == server.pid
            assert me["imported_in_pid"] == (server.pid if "preload" in model else pid)
            # The application runs on the thread of the IOLoop.
            assert me["thread"] == "MainThread", me

    @pytest.mark.parametrize("op", OPS)
    def test_every_worker_reaches_the_allowed_destination(self, server: Server, op: str) -> None:
        for report in server.each_worker(probe_path(op, ALLOWED_NAME, ALLOWED_PORT), 2).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize("op", OPS)
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_every_worker_refuses_a_destination_outside_the_allow_list(
        self, server: Server, op: str, host: str, port: int
    ) -> None:
        for report in server.each_worker(probe_path(op, host, port), 2).values():
            assert_refused(report)
        assert arrivals() == {}

    def test_a_python_child_of_every_worker_inherits_the_locked_policy(
        self, server: Server
    ) -> None:
        path = probe_path("child", FORBIDDEN_NAME, OTHER_PORT)
        for pid, report in server.each_worker(path, 2).items():
            assert report["outcome"] == "reached", report
            assert report["child"]["ppid"] == pid
            assert_locked(report["child"])
            assert_refused(report["child"])
        assert arrivals() == {}

    def test_launches_are_handled_as_under_any_gunicorn_worker(self, server: Server) -> None:
        # The standard library's subprocess: the events are subprocess.Popen events.
        # A child given an environment without the policy gets the lock all the same.
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT, how="clean_env")
        assert report["outcome"] == "reached", report
        assert report["child"]["locked"] is True, report
        assert_refused(report["child"])
        assert arrivals() == {}
        report = server.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(r"external subprocess launch detected: subprocess\.Popen\(bash\)")

    def test_an_uncaught_refusal_gets_no_response_and_the_workers_survive(
        self, server: Server
    ) -> None:
        """Limit: tornado logs an exception the WSGI application lets out and sends nothing, so
        the client of a refused request waits until its own timeout.  (The control is below.)
        """
        before = server.each_worker("/whoami", 2)
        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)
        sent = answer_to(server, path, r"EgressBlocked: Blocked by tethered: forbidden\.test")
        assert sent == b"(nothing, and the connection is still open)"
        assert arrivals() == {}
        server.wait_log("tornado.application ERROR Exception in callback")
        assert set(server.each_worker("/whoami", 2)) == set(before)


class TestLaterWorkers:
    def test_a_worker_started_after_max_requests_enforces_the_policy(self, model: str) -> None:
        command = gunicorn(model, "--max-requests", "5")
        server = start_server(command, env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)
        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2, exclude=first).values():
            assert report["ppid"] == server.pid
            assert_locked(report)
            assert_refused(report)
        assert arrivals() == {}


class TestNotEnforcing:
    def test_without_tethered_any_uncaught_exception_gets_no_response(self) -> None:
        # The control for the limit above, and for the counters: no policy,
        # and an exception that has nothing to do with tethered.
        server = start_server(gunicorn("tornado", workers=1), env={"TETH_ACTIVATE": "none"})
        report = server.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        # A loopback port that nothing listens on.
        path = probe_path("connect", LOOPBACK_ADDR, 9, uncaught=1)
        sent = answer_to(server, path, "ConnectionRefusedError")
        assert sent == b"(nothing, and the connection is still open)"
