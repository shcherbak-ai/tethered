"""The front end of the Celery suite: ``python front.py`` turns a request into one task.

It is a producer like any other: it imports the application, sends the task
to the broker and waits for the result in the result backend.  With
``TETH_ACTIVATE=none`` (what the tests use unless they say otherwise) it holds
no policy and tethered is not even imported in it.

``task=<name>`` picks another task than ``probe``; ``wait=<seconds>`` is how
long to wait for the result.
"""

from __future__ import annotations

from typing import Any

import celery_tasks
import taskprobe


def submit(op: str, params: dict[str, str]) -> dict[str, Any]:
    """Send one task and wait for it; a failed task is described as the producer sees it."""
    if op == "main":
        # Not a task: the worker's main process answers over Celery's remote control.
        replies = celery_tasks.app.control.broadcast("whoami", reply=True, timeout=10.0, limit=1)
        return next(iter(replies[0].values()))
    task = celery_tasks.app.tasks[params.pop("task", "probe")]
    wait = float(params.pop("wait", "60"))
    result = task.apply_async(args=[op, params])
    try:
        report = result.get(timeout=wait)
    except Exception as exc:
        failed = taskprobe.failure(exc, id=result.id, traceback=result.traceback)
        return {"task": {**failed, "celery_state": result.state}}
    return {**report, "task": {"state": "succeeded", "id": result.id, "celery_state": result.state}}


if __name__ == "__main__":
    taskprobe.serve(submit)
