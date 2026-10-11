"""``tethered.scope()`` under gunicorn's gevent workers: a scope around one request.

Requests share the worker's one thread as greenlets, and switch at every
blocking call.  A scope lives in a context variable, so everything here
depends on each greenlet having a context of its own.

The application is ``gevent_app:application`` (the shared WSGI probe); a
request asks for a scope with ``scope=...`` and the checks are those of
``harness.scopes``.  Every server has one worker process.
"""

from __future__ import annotations

import pytest
from harness import (
    ALLOWED_NAME,
    ALLOWED_PORT,
    FORBIDDEN_NAME,
    OTHER_PORT,
    Server,
    arrivals,
    dns_queries,
    reset_arrivals,
    scopes,
    start_server,
)

GUNICORN = [
    "gunicorn",
    "gevent_app:application",
    "--bind",
    "127.0.0.1:{port}",
    "--workers",
    "1",
    # See "A known hazard" in test_gunicorn_gevent.py.
    "--graceful-timeout",
    "5",
]
WORKER_MODELS = {
    "gevent": ["--worker-class", "gevent"],
    "gevent_pywsgi": ["--worker-class", "gevent_pywsgi"],
}
OPS = ["connect", "urllib"]
#: A name that is not in /etc/hosts: looking it up takes a DNS query, which the world counts.
UNLISTED_NAME = f"secret-data.{FORBIDDEN_NAME}"


def looked_up(name: str) -> int:
    """How many queries for ``name`` the world's DNS responder received."""
    return sum(count for query, count in dns_queries().items() if query.startswith(f"{name}/"))


@pytest.fixture(scope="module", params=list(WORKER_MODELS))
def model(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(model: str) -> Server:
    """One worker under a locked policy that allows every port of ``allowed.test``."""
    return start_server([*GUNICORN, *WORKER_MODELS[model]], env=scopes.env("locked"))


class TestAScopeAroundARequest:
    def test_requests_are_greenlets_on_patched_sockets(self, server: Server) -> None:
        me = server.get("/arrangement").json()
        assert me["socket_patched"] is True, me
        assert me["greenlet"] == "Greenlet", me

    @pytest.mark.parametrize("op", OPS)
    def test_the_scope_narrows_the_policy_and_ends_with_the_request(
        self, server: Server, op: str
    ) -> None:
        scopes.narrows(server.probe, op)

    @pytest.mark.parametrize("op", OPS)
    def test_a_scope_cannot_add_what_the_policy_refuses(self, server: Server, op: str) -> None:
        scopes.cannot_widen(server.probe, op)


class TestRequestsThatOverlap:
    def test_the_scope_of_one_greenlet_is_not_the_scope_of_another(self, server: Server) -> None:
        scopes.overlapping(server.probe)


class TestWaysOutOfTheScope:
    def test_a_thread_started_inside_the_scope_is_not_in_it(self, server: Server) -> None:
        """Limit: under the patch a "thread" is another greenlet, and like a real thread it
        starts with no scope: it reaches what the scope refuses.  The policy still applies.
        """
        report = server.probe("thread", ALLOWED_NAME, OTHER_PORT, scope=scopes.SCOPE)
        scopes.assert_reached(report)
        assert arrivals() == {scopes.at(OTHER_PORT): 1}

        report = server.probe("thread", FORBIDDEN_NAME, OTHER_PORT, scope=scopes.SCOPE)
        scopes.assert_refused_by_the_policy(report)
        assert arrivals() == {scopes.at(OTHER_PORT): 1}

    def test_a_python_child_launched_inside_the_scope_is_held_to_it(self, server: Server) -> None:
        """gevent's ``Popen`` forks and calls ``os.exec*`` from Python, so there is no frame of
        the standard library's ``Popen`` to hand the scope on through.  tethered's hook in the
        forked child carries the exec out with the scope in its environment.  (Before that,
        the child held the policy of the process and reached what the scope refuses.)
        """
        child = scopes.child_is_held_to_the_scope(server.probe)
        assert child["locked"] is True, child
        # What the scope allows and the policy refuses stays refused.
        launched = server.probe("child", FORBIDDEN_NAME, OTHER_PORT, scope=scopes.SCOPE)
        assert launched["child"]["outcome"] == "blocked", launched
        assert arrivals() == {scopes.at(ALLOWED_PORT): 1, scopes.at(OTHER_PORT): 1}


@pytest.fixture(scope="class")
def wider() -> Server:
    """A policy that allows two names and the subdomains of one of them."""
    allow = f"{ALLOWED_NAME},{FORBIDDEN_NAME},*.{FORBIDDEN_NAME}"
    command = [*GUNICORN, *WORKER_MODELS["gevent"]]
    return start_server(command, env=scopes.env("locked", TETH_ALLOW=allow))


class TestANameTheScopeRefuses:
    """A policy that allows two names and the subdomains of one; a scope that allows one name."""

    @pytest.mark.parametrize("op", OPS)
    def test_the_connection_is_refused_by_the_scope(self, wider: Server, op: str) -> None:
        report = wider.probe(op, FORBIDDEN_NAME, OTHER_PORT, scope=scopes.SCOPE)
        scopes.assert_refused_by_the_scope(report)
        assert arrivals() == {}
        scopes.assert_reached(wider.probe(op, FORBIDDEN_NAME, OTHER_PORT))

    def test_the_lookup_is_made_all_the_same(self, wider: Server) -> None:
        """Limit: gevent's resolver calls ``getaddrinfo`` in a thread of its pool, which does
        not carry the scope, so the query for a name the scope refuses leaves the process.
        (The name does not exist, so nothing follows.)
        """
        reset_arrivals()
        report = wider.probe("connect", UNLISTED_NAME, OTHER_PORT, scope=scopes.SCOPE)
        assert report["outcome"] == "error", report
        assert report["exception"] == "socket.gaierror", report
        assert looked_up(UNLISTED_NAME) >= 1, dns_queries()


@pytest.fixture(scope="class")
def unrestricted() -> Server:
    """One worker whose application never calls ``activate()``."""
    command = [*GUNICORN, *WORKER_MODELS["gevent"]]
    return start_server(command, env={"TETH_ACTIVATE": "none"})


class TestAScopeWithoutAPolicy:
    """An application that never calls ``activate()``: the scope is all there is."""

    @pytest.mark.parametrize("op", OPS)
    def test_the_scope_restricts_the_request_and_nothing_else(
        self, unrestricted: Server, op: str
    ) -> None:
        scopes.narrows(unrestricted.probe, op)
        scopes.assert_reached(unrestricted.probe(op, FORBIDDEN_NAME, OTHER_PORT))

    def test_a_python_child_launched_inside_the_scope_is_held_to_it(
        self, unrestricted: Server
    ) -> None:
        child = scopes.child_is_held_to_the_scope(unrestricted.probe)
        # No policy of the process: the scope is what the child was given.
        assert child["active"] is False, child
