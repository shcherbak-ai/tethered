"""The front end of the RQ suite: ``python front.py`` turns a request into one job.

It enqueues ``rq_tasks.probe`` by name, so it never imports the jobs module,
and holds no policy.  RQ keeps the traceback of a failed job as text and no
exception object: the last line of it is what a failed job is described with.

``retries=<n>`` enqueues the job with ``Retry(max=n)``, ``delay=<seconds>``
schedules it (the worker then needs ``--with-scheduler``), ``wait=<seconds>``
is how long to wait for the job to end.
"""

from __future__ import annotations

import os
import time
from datetime import timedelta
from typing import Any

import taskprobe
from redis import Redis
from rq import Queue, Retry
from rq.job import JobStatus

queue = Queue(connection=Redis.from_url(os.environ["REDIS_URL"]))
ENDED = (JobStatus.FINISHED, JobStatus.FAILED, JobStatus.STOPPED, JobStatus.CANCELED)


def submit(op: str, params: dict[str, str]) -> dict[str, Any]:
    """Enqueue one job and wait until it has ended."""
    retries = int(params.pop("retries", "0"))
    delay = params.pop("delay", None)
    deadline = time.monotonic() + float(params.pop("wait", "60"))
    options: dict[str, Any] = {"retry": Retry(max=retries)} if retries else {}
    if delay is None:
        job = queue.enqueue("rq_tasks.probe", op, params, **options)
    else:
        job = queue.enqueue_in(timedelta(seconds=float(delay)), "rq_tasks.probe", op, params)

    while (status := job.get_status(refresh=True)) not in ENDED:
        if time.monotonic() >= deadline:
            return {"task": {"state": "pending", "id": job.id, "rq_status": str(status)}}
        time.sleep(0.02)
    job.refresh()
    task = {"id": job.id, "rq_status": status.value, "retries_left": job.retries_left}
    if status == JobStatus.FINISHED:
        return {**job.return_value(), "task": {**task, "state": "succeeded"}}
    traceback = job.latest_result().exc_string or ""
    last_line = (traceback.strip().splitlines() or [""])[-1]
    exception, _, message = last_line.partition(": ")
    failed = {"state": "failed", "exception": exception, "message": message}
    return {"task": {**task, **failed, "traceback": traceback}}


if __name__ == "__main__":
    taskprobe.serve(submit)
