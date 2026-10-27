"""The Celery application under test: ``celery --app celery_tasks worker ...``.

One task, ``probe(op, params)``, does one outbound operation in whatever the
pool runs task code in (a forked child, a thread, the worker's main thread, a
greenlet) and returns the report; see ``taskprobe``.

``TETH_WHERE`` says where the policy is activated (``TETH_ACTIVATE`` says
which policy, see ``probe_common``):

    import               when this module is imported: in the worker's main process,
                         before Celery starts its pool (the default)
    worker_process_init  in the handler of that signal, which Celery sends in every
                         child of the prefork pool right after the fork
    worker_init          in the handler of that signal, which Celery sends in the
                         worker's main process before the pool exists

Other settings from the environment: ``BROKER_URL`` (broker and result
backend), ``RESULT_SERIALIZER`` (``json``, the default, or ``pickle``),
``BEAT_TARGET`` (``host:port``: a beat schedule with one task that connects
there every half second).

The front end imports this module too, as any producer of tasks does.
"""

from __future__ import annotations

import os
from typing import Any

import probe_common
import taskprobe
from celery import Celery, signals
from celery.worker.control import inspect_command

WHERE = os.environ.get("TETH_WHERE", "import")
if WHERE == "import":
    probe_common.activate_from_env()
elif WHERE not in ("worker_process_init", "worker_init"):
    raise RuntimeError(f"TETH_WHERE={WHERE!r}: import, worker_process_init or worker_init")

app = Celery("celery_tasks", broker=os.environ["BROKER_URL"], backend=os.environ["BROKER_URL"])
app.conf.update(
    broker_connection_retry_on_startup=True,
    result_expires=600,
    task_track_started=True,
    result_serializer=os.environ.get("RESULT_SERIALIZER", "json"),
    result_accept_content=["json", "pickle"],
)

if os.environ.get("BEAT_TARGET"):
    # A periodic task for "celery beat": a connection attempt every half second.
    host, _, port = os.environ["BEAT_TARGET"].rpartition(":")
    app.conf.beat_schedule = {
        "tick": {
            "task": "probe",
            "schedule": 0.5,
            "args": ["connect", {"host": host, "port": port, "record": "1"}],
        }
    }


@signals.worker_process_init.connect
def _in_every_pool_child(**_: Any) -> None:
    if WHERE == "worker_process_init":
        probe_common.activate_from_env()


@signals.worker_init.connect
def _in_the_main_process(**_: Any) -> None:
    if WHERE == "worker_init":
        probe_common.activate_from_env()


@inspect_command()
def whoami(state: Any) -> dict[str, Any]:
    """Remote control: the worker's main process describes itself (``/main`` of the front end)."""
    return probe_common.whoami()


@app.task(name="probe")
def probe(op: str, params: dict[str, str]) -> dict[str, Any]:
    """One operation; the report is the result of the task."""
    return taskprobe.perform(op, params)


#: Retried twice, at once.
RETRY = {"max_retries": 2, "default_retry_delay": 0}


@app.task(name="probe_retry_any", autoretry_for=(Exception,), **RETRY)
def probe_retry_any(op: str, params: dict[str, str]) -> dict[str, Any]:
    """The same, retried twice after any exception."""
    return taskprobe.perform(op, params)


@app.task(name="probe_retry_oserror", autoretry_for=(OSError,), **RETRY)
def probe_retry_oserror(op: str, params: dict[str, str]) -> dict[str, Any]:
    """The same, retried twice after a network error, as retry settings for I/O usually say."""
    return taskprobe.perform(op, params)
