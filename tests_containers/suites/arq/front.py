"""The front end of the arq suite: ``python front.py`` turns a request into one job.

It enqueues the job ``probe`` by name, so it never imports the worker's
module, and holds no policy.  arq pickles the result of a job, and for a
failed job the exception itself: the producer gets it back when it asks for
the result.

``wait=<seconds>`` is how long to wait for the result.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import taskprobe
from arq import create_pool
from arq.connections import RedisSettings

REDIS = RedisSettings(host="127.0.0.1", port=int(os.environ["REDIS_PORT"]))


async def _submit(op: str, params: dict[str, str]) -> dict[str, Any]:
    wait = float(params.pop("wait", "60"))
    pool = await create_pool(REDIS)
    try:
        job = await pool.enqueue_job("probe", op, params)
        try:
            report = await job.result(timeout=wait, poll_delay=0.02)
        except Exception as exc:
            info = await job.result_info()
            failed = taskprobe.failure(
                exc,
                id=job.job_id,
                # How often arq ran the job, and what the exception still knows.
                job_try=getattr(info, "job_try", None),
                host=getattr(exc, "host", None),
            )
            return {"task": failed}
        info = await job.result_info()
        tries = getattr(info, "job_try", None)
        return {**report, "task": {"state": "succeeded", "id": job.job_id, "job_try": tries}}
    finally:
        await pool.aclose()


def submit(op: str, params: dict[str, str]) -> dict[str, Any]:
    """Enqueue one job and wait for it, in an event loop of this request's thread."""
    return asyncio.run(_submit(op, params))


if __name__ == "__main__":
    taskprobe.serve(submit)
