"""The front end of the Dramatiq suite: ``python front.py`` turns a request into one message.

It is a producer like any other: it imports the application, sends the
message and waits for the result in the result backend.  With
``TETH_ACTIVATE=none`` it holds no policy.

``actor=<name>`` picks another actor than ``probe``; ``wait=<seconds>`` is how
long to wait for the result.
"""

from __future__ import annotations

from typing import Any

import dramatiq_tasks
import taskprobe


def submit(op: str, params: dict[str, str]) -> dict[str, Any]:
    """Send one message and wait for its result; a failure is described as the producer gets it."""
    actor = getattr(dramatiq_tasks, params.pop("actor", "probe"))
    wait = int(float(params.pop("wait", "60")) * 1000)
    message = actor.send(op, params)
    try:
        report = message.get_result(backend=dramatiq_tasks.backend, block=True, timeout=wait)
    except Exception as exc:
        failed = taskprobe.failure(
            exc,
            id=message.message_id,
            # What Dramatiq kept of the exception the actor raised.
            orig_exc_type=getattr(exc, "orig_exc_type", None),
            orig_exc_msg=getattr(exc, "orig_exc_msg", None),
        )
        return {"task": failed}
    return {**report, "task": {"state": "succeeded", "id": message.message_id}}


if __name__ == "__main__":
    taskprobe.serve(submit)
