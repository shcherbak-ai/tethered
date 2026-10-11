"""What a pool worker runs: ``pool_tasks.probe(op, params)``.

A module of its own, so that a spawned worker and a worker interpreter can
import the function by name.  It never calls ``tethered.activate()`` for the
policy under test: what a worker holds, it inherited or joined.

Besides the operations of ``taskprobe``, two that try to get rid of the
policy from inside a worker:

    deactivate   ``tethered.deactivate()`` with no token
    widen        ``tethered.activate()`` with an allow list that adds the forbidden
                 destination

and ``die``, with which the worker kills itself in the middle of the task.
"""

from __future__ import annotations

import os
import signal
from typing import Any

import probe_common
import taskprobe


def _attempt(op: str) -> dict[str, Any]:
    import tethered

    report: dict[str, Any] = {"op": op}
    try:
        if op == "deactivate":
            tethered.deactivate()
        else:
            tethered.activate(allow=["allowed.test:9001", "forbidden.test:9002"])
        report["outcome"] = "done"
    except Exception as exc:
        report.update(probe_common.describe_failure(exc))
    # After the attempt: what policy is there now.
    return {**report, **probe_common.whoami()}


def probe(op: str, params: dict[str, str]) -> dict[str, Any]:
    """One operation in the worker; the report is the result."""
    if op in ("deactivate", "widen"):
        return _attempt(op)
    if op == "die":
        os.kill(os.getpid(), signal.SIGKILL)
    return taskprobe.perform(op, params)
