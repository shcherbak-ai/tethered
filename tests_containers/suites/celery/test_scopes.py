"""``tethered.scope()`` inside a Celery task, in every pool.

A task that narrows the policy for its own work is what a scope is for in a
worker.  The pools differ in what a task shares with the next one: a process
of its own (prefork), the one thread of the worker (solo), a thread of a pool
(threads), or a greenlet (gevent, eventlet).

The task is ``probe`` of ``celery_tasks.py``; a request asks for a scope with
``scope=...`` and the checks are those of ``harness.scopes``.  The worker's
policy allows every port of ``allowed.test``.
"""

from __future__ import annotations

import pytest
from harness import ALLOWED_NAME, OTHER_PORT, arrivals, scopes
from test_celery import Stack, start_stack

POOLS = ["prefork", "threads", "solo", "gevent", "eventlet"]
#: The pools in which two tasks run in one process at the same time.
SHARING = ["threads", "gevent", "eventlet"]
OPS = ["connect", "urllib"]


@pytest.fixture(scope="module", params=POOLS)
def pool(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def stack(pool: str) -> Stack:
    """A worker of this pool under a locked policy that allows every port of ``allowed.test``."""
    env = {"TETH_ALLOW": scopes.POLICY}
    if pool == "eventlet":
        # eventlet's own resolver is not seen by tethered: see TestEventlet in test_celery.py.
        env["EVENTLET_NO_GREENDNS"] = "yes"
    return start_stack("--pool", pool, "--concurrency", "2", activate="locked", env=env)


class TestAScopeInsideATask:
    @pytest.mark.parametrize("op", OPS)
    def test_the_scope_narrows_the_policy_and_ends_with_the_task(
        self, stack: Stack, op: str
    ) -> None:
        scopes.narrows(stack.probe, op)

    def test_a_scope_cannot_add_what_the_policy_refuses(self, stack: Stack) -> None:
        scopes.cannot_widen(stack.probe)

    def test_the_scope_of_one_task_is_not_the_scope_of_another(
        self, stack: Stack, pool: str
    ) -> None:
        if pool not in SHARING:
            pytest.skip("one task at a time in each process of this pool")
        scopes.overlapping(stack.probe)

    def test_a_python_child_launched_inside_the_scope_is_held_to_it(
        self, stack: Stack, pool: str
    ) -> None:
        if pool == "gevent":
            pytest.skip("gevent launches with a Popen of its own: see the next test")
        # Under eventlet too: its launches go through the standard library's Popen, which is
        # where tethered hands a scope on.
        child = scopes.child_is_held_to_the_scope(stack.probe)
        assert child["locked"] is True, child

    def test_under_gevent_a_python_child_is_not_held_to_the_scope(
        self, stack: Stack, pool: str
    ) -> None:
        """Limit: gevent's ``Popen`` forks and calls ``os.exec*`` from Python, and a scope
        reaches a child only through the standard library's ``Popen``.  The child holds the
        policy of the worker and not the scope of the task: it reaches what the scope refuses.
        """
        if pool != "gevent":
            pytest.skip("the gevent pool only")
        launched = stack.probe("child", ALLOWED_NAME, OTHER_PORT, scope=scopes.SCOPE)
        scopes.assert_reached(launched)
        child = launched["child"]
        assert child["locked"] is True, launched
        scopes.assert_reached(child)
        assert arrivals() == {scopes.at(OTHER_PORT): 1}
