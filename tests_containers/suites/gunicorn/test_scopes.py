"""``tethered.scope()`` under gunicorn's own workers: a scope around the work of one request.

A sync worker serves one request at a time, on its main thread: a scope
there can only be left behind for the next request.  A gthread worker serves
several at once, each on a thread of its pool: a scope there must stay with
the thread that entered it.

The application is ``probe_wsgi:application``; a request asks for a scope
with ``scope=...`` and the checks are those of ``harness.scopes``.  Every
server has one worker process, so that the requests of a test meet.
"""

from __future__ import annotations

import pytest
from harness import (
    ALLOWED_NAME,
    FORBIDDEN_ADDR,
    FORBIDDEN_NAME,
    OTHER_PORT,
    Server,
    arrivals,
    scopes,
    start_server,
)

GUNICORN = ["gunicorn", "probe_wsgi:application", "--bind", "127.0.0.1:{port}", "--workers", "1"]
WORKER_MODELS = {
    "sync": [],
    "gthread": ["--worker-class", "gthread", "--threads", "4"],
}
OPS = ["connect", "urllib"]


@pytest.fixture(scope="module", params=list(WORKER_MODELS))
def model(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(model: str) -> Server:
    """One worker under a locked policy that allows every port of ``allowed.test``."""
    return start_server([*GUNICORN, *WORKER_MODELS[model]], env=scopes.env("locked"))


class TestAScopeAroundARequest:
    @pytest.mark.parametrize("op", OPS)
    def test_the_scope_narrows_the_policy_and_ends_with_the_request(
        self, server: Server, op: str
    ) -> None:
        scopes.narrows(server.probe, op)

    @pytest.mark.parametrize("op", OPS)
    def test_a_scope_cannot_add_what_the_policy_refuses(self, server: Server, op: str) -> None:
        scopes.cannot_widen(server.probe, op)

    def test_a_log_only_scope_reports_and_refuses_nothing(self, server: Server) -> None:
        report = server.probe(
            "connect", ALLOWED_NAME, OTHER_PORT, scope=scopes.SCOPE, scope_log_only=1
        )
        scopes.assert_reached(report)
        assert arrivals() == {scopes.at(OTHER_PORT): 1}
        server.wait_log(
            rf"tethered: {scopes.LABEL} would block .*{OTHER_PORT}.* \(allowed by global policy\)"
        )

    def test_a_python_child_launched_inside_the_scope_is_held_to_it(self, server: Server) -> None:
        child = scopes.child_is_held_to_the_scope(server.probe)
        # The child holds the locked policy of the process as well.
        assert child["locked"] is True, child

    def test_a_thread_started_inside_the_scope_is_not_in_it(self, server: Server) -> None:
        """Limit: a scope belongs to the thread that entered it.  A thread started inside the
        block starts with no scope and reaches what the scope refuses; the policy of the
        process still applies to it.
        """
        report = server.probe("thread", ALLOWED_NAME, OTHER_PORT, scope=scopes.SCOPE)
        scopes.assert_reached(report)
        assert report["ran_in"] == "probe-thread", report
        assert arrivals() == {scopes.at(OTHER_PORT): 1}

        report = server.probe("thread", FORBIDDEN_NAME, OTHER_PORT, scope=scopes.SCOPE)
        scopes.assert_refused_by_the_policy(report)
        assert arrivals() == {scopes.at(OTHER_PORT): 1}


class TestRequestsThatOverlap:
    def test_the_scope_of_one_request_is_not_the_scope_of_another(self) -> None:
        threaded = start_server([*GUNICORN, *WORKER_MODELS["gthread"]], env=scopes.env("locked"))
        scoped, other = scopes.overlapping(threaded.probe)
        # Two threads of the worker's pool, at the same time.
        assert scoped["thread"] != other["thread"], (scoped, other)


@pytest.fixture(scope="class", params=list(WORKER_MODELS))
def unrestricted(request: pytest.FixtureRequest) -> Server:
    """One worker whose application never calls ``activate()``."""
    command = [*GUNICORN, *WORKER_MODELS[request.param]]
    return start_server(command, env={"TETH_ACTIVATE": "none"})


class TestAScopeWithoutAPolicy:
    """An application that never calls ``activate()``: the scope is all there is."""

    @pytest.mark.parametrize("op", OPS)
    def test_the_scope_restricts_the_request_and_nothing_else(
        self, unrestricted: Server, op: str
    ) -> None:
        scopes.narrows(unrestricted.probe, op)
        # Outside a scope nothing is refused in this process.
        scopes.assert_reached(unrestricted.probe(op, FORBIDDEN_NAME, OTHER_PORT))
        report = unrestricted.probe(op, FORBIDDEN_NAME, OTHER_PORT, scope=scopes.SCOPE)
        scopes.assert_refused_by_the_scope(report)
        assert arrivals().get(f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp") == 1, arrivals()

    def test_a_python_child_launched_inside_the_scope_is_held_to_it(
        self, unrestricted: Server
    ) -> None:
        child = scopes.child_is_held_to_the_scope(unrestricted.probe)
        # No policy of the process: the scope is what the child was given.
        assert child["active"] is False, child
