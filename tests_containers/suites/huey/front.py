"""The front end of the Huey suite: ``python front.py`` turns a request into one task.

It is a producer like any other: it imports the application, calls the task
(which enqueues it) and waits for the result.  With ``TETH_ACTIVATE=none`` it
holds no policy.

``task=<name>`` picks another task than ``probe``; ``wait=<seconds>`` is how
long to wait for the result.
"""

from __future__ import annotations

from typing import Any

import huey_tasks
import taskprobe


def submit(op: str, params: dict[str, str]) -> dict[str, Any]:
    """Enqueue one task and wait for it; a failure is described as the producer gets it."""
    task = getattr(huey_tasks, params.pop("task", "probe"))
    wait = float(params.pop("wait", "60"))
    result = task(op, params)
    try:
        report = result.get(blocking=True, timeout=wait)
    except Exception as exc:
        # Huey's TaskException carries what the worker kept of the exception.
        metadata = getattr(exc, "metadata", None) or {}
        failed = taskprobe.failure(
            exc,
            id=result.id,
            error=metadata.get("error"),
            retries=metadata.get("retries"),
            traceback=metadata.get("traceback"),
        )
        return {"task": failed}
    return {**report, "task": {"state": "succeeded", "id": result.id}}


if __name__ == "__main__":
    taskprobe.serve(submit)
