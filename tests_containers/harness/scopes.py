"""Checks of ``tethered.scope()`` that a suite runs against its own server.

A probe application runs the operation of a request inside a scope when the
request asks for one: ``scope=<rule>,<rule>`` (``probe_common.scoped``).  The
servers of these checks hold a policy that allows ``allowed.test`` on every
port, so that a scope has something to take away:

    allowed.test:9001    allowed by the policy and by the scope
    allowed.test:9002    allowed by the policy, not by the scope
    forbidden.test       not allowed by the policy, and no scope can add it

Each check takes ``probe``, a callable like ``Server.probe``: whatever turns
``(op, host, port, **params)`` into the report of one operation, in a web
server or in a task.  A check resets the world's counters when it starts and
asserts both the reports and what arrived.

What a check cannot decide is where the two requests of an overlap run: the
suite starts a server with one worker process and says, with what
``overlapping`` returns, what kept the requests apart there (threads, tasks
of an event loop, greenlets).
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

from harness.helpers import (
    ALLOWED_ADDR,
    ALLOWED_NAME,
    ALLOWED_PORT,
    FORBIDDEN_NAME,
    OTHER_PORT,
    arrivals,
    reset_arrivals,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    Probe = Callable[..., dict[str, Any]]

#: ``TETH_ALLOW`` of a server these checks run against: every port of ``allowed.test``.
POLICY = ALLOWED_NAME
#: The scope a request asks for: one port of it.
SCOPE = f"{ALLOWED_NAME}:{ALLOWED_PORT}"
#: The label the probe applications give that scope (``probe_common.SCOPE_LABEL``).
LABEL = "probe-scope"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
#: How long the scoped request of an overlap stays inside its scope before it acts.
WAIT = 3.0


def env(activate: str = "locked", **more: str) -> dict[str, str]:
    """The environment of a server for these checks: ``TETH_ACTIVATE`` and the wider policy."""
    return {"TETH_ACTIVATE": activate, "TETH_ALLOW": POLICY, **more}


def at(port: int, proto: str = "tcp") -> str:
    """The key of ``allowed.test:<port>`` in the world's counters."""
    return f"{ALLOWED_ADDR}:{port}/{proto}"


def assert_reached(report: dict[str, Any]) -> None:
    assert report["outcome"] == "reached", report


def assert_refused_by_the_scope(report: dict[str, Any]) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == EGRESS_BLOCKED, report
    assert report.get("scope_label") == LABEL, report
    assert f"(blocked by {LABEL})" in report["message"], report


def assert_refused_by_the_policy(report: dict[str, Any]) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == EGRESS_BLOCKED, report
    assert "scope_label" not in report, report


def narrows(probe: Probe, op: str = "connect", proto: str = "tcp") -> None:
    """Inside the scope only what the scope allows is reached, and the scope ends with the request.

    The third request is the one the scope refused, made without a scope:
    it is reached, also where the same thread or greenlet serves it.
    """
    reset_arrivals()
    assert_reached(probe(op, ALLOWED_NAME, ALLOWED_PORT, scope=SCOPE))
    assert arrivals() == {at(ALLOWED_PORT, proto): 1}
    assert_refused_by_the_scope(probe(op, ALLOWED_NAME, OTHER_PORT, scope=SCOPE))
    assert arrivals() == {at(ALLOWED_PORT, proto): 1}
    assert_reached(probe(op, ALLOWED_NAME, OTHER_PORT))
    assert arrivals() == {at(ALLOWED_PORT, proto): 1, at(OTHER_PORT, proto): 1}


def cannot_widen(probe: Probe, op: str = "connect") -> None:
    """A scope that allows what the policy refuses changes nothing: the policy refuses it."""
    reset_arrivals()
    wider = f"{FORBIDDEN_NAME}:{OTHER_PORT}"
    assert_refused_by_the_policy(probe(op, FORBIDDEN_NAME, OTHER_PORT, scope=wider))
    assert_refused_by_the_policy(probe(op, FORBIDDEN_NAME, OTHER_PORT, scope=f"{SCOPE},{wider}"))
    assert arrivals() == {}


def overlapping(probe: Probe, op: str = "connect") -> tuple[dict[str, Any], dict[str, Any]]:
    """Two requests at the same time in one process: one inside a scope, one without.

    The scoped request enters its scope and waits there; meanwhile the other
    one reaches the destination that scope refuses; then the scoped request
    tries the same destination and is refused.  So the scope neither reached
    the other request nor was it undone by it.  Returns both reports, the
    scoped one first.
    """
    probe("whoami")  # the worker has imported everything by now
    reset_arrivals()
    with ThreadPoolExecutor(1) as pool:
        waiting = pool.submit(probe, op, ALLOWED_NAME, OTHER_PORT, scope=SCOPE, scope_wait=WAIT)
        time.sleep(WAIT / 3)
        sent = time.time()
        other = probe(op, ALLOWED_NAME, OTHER_PORT)
        answered = time.time()
        scoped = waiting.result(60.0)

    assert scoped["pid"] == other["pid"], (scoped, other)
    # The other request ran from start to end while the first one was inside its scope.
    inside = scoped["scope_entered"] < sent < answered < scoped["scope_left"]
    assert inside, (scoped, sent, answered)
    assert_reached(other)
    assert_refused_by_the_scope(scoped)
    assert arrivals() == {at(OTHER_PORT): 1}
    # Nothing is left behind where the scoped request ran.
    assert_reached(probe(op, ALLOWED_NAME, OTHER_PORT))
    return scoped, other


def child_is_held_to_the_scope(probe: Probe, **params: Any) -> dict[str, Any]:
    """A Python child launched inside the scope cannot reach what the scope refuses.

    The child is launched with ``sys.executable`` and holds, from its start,
    the policy of the process narrowed by the scope.  Launched without a
    scope, it reaches the same destination.  Returns the child's report.
    """
    reset_arrivals()
    launched = probe("child", ALLOWED_NAME, OTHER_PORT, scope=SCOPE, **params)
    assert_reached(launched)
    child = launched["child"]
    assert child["outcome"] == "blocked", launched
    assert child["exception"] == EGRESS_BLOCKED, launched
    assert arrivals() == {}

    launched = probe("child", ALLOWED_NAME, ALLOWED_PORT, scope=SCOPE, **params)
    assert_reached(launched)
    assert_reached(launched["child"])
    assert arrivals() == {at(ALLOWED_PORT): 1}

    launched = probe("child", ALLOWED_NAME, OTHER_PORT, **params)
    assert_reached(launched)
    assert_reached(launched["child"])
    assert arrivals() == {at(ALLOWED_PORT): 1, at(OTHER_PORT): 1}
    return child
