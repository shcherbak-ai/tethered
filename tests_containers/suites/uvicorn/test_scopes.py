"""``tethered.scope()`` under uvicorn on the standard asyncio loop: a scope around one request.

Requests share the process as tasks of one event loop, and a scope belongs to
the task that entered it.  What matters here is every way a coroutine has to
get work done: on the loop itself, in ``asyncio.to_thread`` (which takes the
scope along), in ``loop.run_in_executor`` and in a thread of its own (which
do not), and in a child process.

The application is ``probe_asgi:app``; a request asks for a scope with
``scope=...`` and the checks are those of ``harness.scopes``.  A scope in an
application that has no policy at all, with the loop left to uvicorn, is in
``test_default_loop.py``.
"""

from __future__ import annotations

import pytest
from harness import (
    ALLOWED_NAME,
    FORBIDDEN_NAME,
    OTHER_PORT,
    Server,
    arrivals,
    dns_queries,
    reset_arrivals,
    scopes,
    start_server,
)
from test_uvicorn import STANDARD_LOOP, STREAM_OPS, UVICORN

DATAGRAM_OPS = ["datagram_connected", "datagram_unconnected"]
#: A name that is not in /etc/hosts: looking it up takes a DNS query, which the world counts.
UNLISTED_NAME = f"secret-data.{FORBIDDEN_NAME}"


def looked_up(name: str) -> int:
    """How many queries for ``name`` the world's DNS responder received."""
    return sum(count for query, count in dns_queries().items() if query.startswith(f"{name}/"))


@pytest.fixture(scope="module")
def server() -> Server:
    """One process under a locked policy that allows every port of ``allowed.test``."""
    return start_server(UVICORN, env=scopes.env("locked"))


class TestAScopeAroundARequest:
    def test_the_application_runs_on_the_standard_loop(self, server: Server) -> None:
        assert server.probe("whoami")["loop"] == STANDARD_LOOP

    @pytest.mark.parametrize("op", STREAM_OPS)
    def test_the_scope_narrows_the_policy_and_ends_with_the_request(
        self, server: Server, op: str
    ) -> None:
        scopes.narrows(server.probe, op)

    @pytest.mark.parametrize("op", DATAGRAM_OPS)
    def test_the_scope_narrows_datagrams_too(self, server: Server, op: str) -> None:
        scopes.narrows(server.probe, op, proto="udp")

    @pytest.mark.parametrize("op", ["open_connection", "connect"])
    def test_a_scope_cannot_add_what_the_policy_refuses(self, server: Server, op: str) -> None:
        scopes.cannot_widen(server.probe, op)

    def test_a_python_child_launched_inside_the_scope_is_held_to_it(self, server: Server) -> None:
        # asyncio.create_subprocess_exec, on the standard loop.
        child = scopes.child_is_held_to_the_scope(server.probe)
        assert child["locked"] is True, child


class TestRequestsThatOverlap:
    @pytest.mark.parametrize("op", ["open_connection", "to_thread"])
    def test_the_scope_of_one_request_is_not_the_scope_of_another(
        self, server: Server, op: str
    ) -> None:
        scoped, other = scopes.overlapping(server.probe, op)
        # Two tasks of the one event loop, both on its thread.
        assert scoped["thread"] == other["thread"] == "MainThread", (scoped, other)
        assert scoped["loop"] == STANDARD_LOOP, scoped


class TestWaysOutOfTheScope:
    @pytest.mark.parametrize("op", ["run_in_executor", "thread"])
    def test_work_handed_to_another_thread_is_not_in_the_scope(
        self, server: Server, op: str
    ) -> None:
        """Limit: ``loop.run_in_executor`` and a thread started inside the block run without
        the scope and reach what it refuses (``asyncio.to_thread`` takes the scope along and
        is refused).  The policy of the process still applies to them.
        """
        report = server.probe(op, ALLOWED_NAME, OTHER_PORT, scope=scopes.SCOPE)
        scopes.assert_reached(report)
        assert arrivals() == {scopes.at(OTHER_PORT): 1}

        report = server.probe(op, FORBIDDEN_NAME, OTHER_PORT, scope=scopes.SCOPE)
        scopes.assert_refused_by_the_policy(report)
        assert arrivals() == {scopes.at(OTHER_PORT): 1}


@pytest.fixture(scope="class")
def wider() -> Server:
    """A policy that allows two names and the subdomains of one of them."""
    allow = f"{ALLOWED_NAME},{FORBIDDEN_NAME},*.{FORBIDDEN_NAME}"
    return start_server(UVICORN, env=scopes.env("locked", TETH_ALLOW=allow))


class TestANameTheScopeRefuses:
    """A policy that allows two names and the subdomains of one; a scope that allows one name."""

    @pytest.mark.parametrize("op", STREAM_OPS)
    def test_the_connection_is_refused_by_the_scope(self, wider: Server, op: str) -> None:
        report = wider.probe(op, FORBIDDEN_NAME, OTHER_PORT, scope=scopes.SCOPE)
        scopes.assert_refused_by_the_scope(report)
        assert arrivals() == {}
        scopes.assert_reached(wider.probe(op, FORBIDDEN_NAME, OTHER_PORT))

    def test_a_blocking_lookup_is_refused_before_any_query_is_sent(self, wider: Server) -> None:
        report = wider.probe("connect", UNLISTED_NAME, OTHER_PORT, scope=scopes.SCOPE)
        scopes.assert_refused_by_the_scope(report)
        assert looked_up(UNLISTED_NAME) == 0, dns_queries()

    @pytest.mark.parametrize("op", ["open_connection", "create_connection", "getaddrinfo"])
    def test_the_lookup_of_the_loop_is_made_all_the_same(self, wider: Server, op: str) -> None:
        """Limit: asyncio looks a name up in an executor thread, which does not carry the
        scope, so the query for a name the scope refuses leaves the process.  (The name does
        not exist, so nothing follows; a connection would be checked against the scope.)
        """
        reset_arrivals()
        report = wider.probe(op, UNLISTED_NAME, OTHER_PORT, scope=scopes.SCOPE)
        assert report["outcome"] == "error", report
        assert report["exception"] == "socket.gaierror", report
        assert looked_up(UNLISTED_NAME) >= 1, dns_queries()


@pytest.fixture(scope="class")
def unrestricted() -> Server:
    """One process whose application never calls ``activate()``, with the loop named."""
    return start_server(UVICORN, env={"TETH_ACTIVATE": "none"})


class TestAScopeWithoutAPolicy:
    """An application that never calls ``activate()``, with the loop named."""

    @pytest.mark.parametrize("op", STREAM_OPS)
    def test_the_scope_restricts_the_request_and_nothing_else(
        self, unrestricted: Server, op: str
    ) -> None:
        scopes.narrows(unrestricted.probe, op)
        scopes.assert_reached(unrestricted.probe(op, FORBIDDEN_NAME, OTHER_PORT))

    def test_a_python_child_launched_inside_the_scope_is_held_to_it(
        self, unrestricted: Server
    ) -> None:
        child = scopes.child_is_held_to_the_scope(unrestricted.probe)
        assert child["active"] is False, child
