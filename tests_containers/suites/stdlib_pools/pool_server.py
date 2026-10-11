"""The process that owns a standard-library pool: ``python pool_server.py KIND METHOD``.

    KIND    mp-pool (``multiprocessing.Pool``), process-pool (``ProcessPoolExecutor``)
            or interpreter-pool (``InterpreterPoolExecutor``, Python 3.14+)
    METHOD  fork, spawn, forkserver, or default: no context is named and the pool
            starts its workers the way this Python version does by default

It is an HTTP front end (``taskprobe.serve``): ``GET /<op>?<params>`` runs one
task in the pool and answers with the worker's report (``wait=<seconds>``: how
long to wait for it), ``/owner`` answers for this process.

``TETH_WHERE`` says where this program activates the policy (``TETH_ACTIVATE``
says which one):

    main          in ``main()``, under the ``__main__`` guard, before the pool exists
                  (the default).  A spawned worker runs this module again as
                  ``__mp_main__`` but not ``main()``: what it holds, it inherited.
    module        at the top of the module, outside the guard: a spawned worker and
                  a fork server run that line too, and call ``activate()`` themselves.
    after_warmup  in ``main()``, after the pool was created and every worker has
                  run a task: the workers, and a fork server, are older than the policy.

``POOL_WORKERS`` (2) is the size of the pool and ``POOL_RECYCLE`` (0: never)
the number of tasks after which a worker process is replaced.
"""

from __future__ import annotations

import multiprocessing
import os
import signal
import sys
from concurrent.futures import ProcessPoolExecutor
from typing import Any

import pool_tasks
import probe_common
import taskprobe

WHERE = os.environ.get("TETH_WHERE", "main")
if WHERE == "module":
    probe_common.activate_from_env()


class Pool:
    """One pool of the kind and start method the command line names."""

    def __init__(self, kind: str, method: str) -> None:
        self.kind = kind
        self.workers = int(os.environ.get("POOL_WORKERS", "2"))
        recycle = int(os.environ.get("POOL_RECYCLE", "0")) or None
        self.pool: Any = None
        self.executor: Any = None
        if kind == "interpreter-pool":
            from concurrent.futures import InterpreterPoolExecutor

            self.executor = InterpreterPoolExecutor(max_workers=self.workers)
            return
        context = None if method == "default" else multiprocessing.get_context(method)
        if kind == "mp-pool":
            factory = multiprocessing.Pool if context is None else context.Pool
            self.pool = factory(processes=self.workers, maxtasksperchild=recycle)
        elif kind == "process-pool":
            self.executor = ProcessPoolExecutor(
                max_workers=self.workers, mp_context=context, max_tasks_per_child=recycle
            )
        else:
            raise SystemExit(f"KIND is mp-pool, process-pool or interpreter-pool, not {kind!r}")

    def start(self, op: str, params: dict[str, str]) -> Any:
        """Hand one task to the pool; ``finish`` waits for it."""
        if self.pool is not None:
            return self.pool.apply_async(pool_tasks.probe, (op, params))
        return self.executor.submit(pool_tasks.probe, op, params)

    def finish(self, task: Any, wait: float = 60.0) -> dict[str, Any]:
        """The result of a task, or the exception it raised as the pool delivers it."""
        return task.get(wait) if self.pool is not None else task.result(wait)

    def warm_up(self) -> None:
        """Run overlapping tasks, one per worker, and say which worker processes exist."""
        for task in [self.start("whoami", {"hold": "0.3"}) for _ in range(self.workers)]:
            self.finish(task)
        workers = sorted(process.pid for process in multiprocessing.active_children())
        print(f"owner: warmed up, workers {workers}", file=sys.stderr, flush=True)

    def submit(self, op: str, params: dict[str, str]) -> dict[str, Any]:
        """What ``taskprobe.serve`` calls for a request."""
        if op == "owner":
            method = multiprocessing.get_start_method(allow_none=True)
            return {**probe_common.whoami(), "default_start_method": method}
        wait = float(params.pop("wait", "60"))
        try:
            report = self.finish(self.start(op, params), wait)
        except Exception as exc:
            cause = type(exc.__cause__).__name__ if exc.__cause__ is not None else None
            failed = taskprobe.failure(exc, host=getattr(exc, "host", None), cause=cause)
            return {"task": failed}
        return {**report, "task": {"state": "succeeded"}}

    def close(self) -> None:
        """End the workers, so that nothing is left when this process ends."""
        if self.pool is not None:
            self.pool.terminate()
            self.pool.join()
        else:
            self.executor.shutdown(wait=True, cancel_futures=True)


def _exit(signum: int, frame: object) -> None:
    raise SystemExit(0)


def main(argv: list[str]) -> None:
    """Activate, create the pool (in the order ``TETH_WHERE`` says) and serve."""
    kind, method = argv
    if WHERE == "main":
        probe_common.activate_from_env()
    pool = Pool(kind, method)
    if WHERE == "after_warmup":
        pool.warm_up()
        probe_common.activate_from_env()
    signal.signal(signal.SIGTERM, _exit)
    try:
        taskprobe.serve(pool.submit)
    finally:
        pool.close()


if __name__ == "__main__":
    main(sys.argv[1:])
