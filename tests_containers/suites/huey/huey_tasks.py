"""The Huey application under test: ``huey_consumer huey_tasks.huey -w 2 -k thread``.

The consumer imports this module to find the ``huey`` instance, and then
starts its workers: threads (``-k thread``, the default) or processes forked
from the consumer (``-k process``), and a scheduler of the same kind.
``TETH_WHERE`` says where the policy is activated (``TETH_ACTIVATE`` says
which one):

    import      when this module is imported: in the consumer, before it starts
                its workers (the default)
    on_startup  in an ``on_startup`` hook, which Huey runs in every worker when the
                worker starts

The front end imports this module too, as any producer of tasks does.
"""

from __future__ import annotations

import os
from typing import Any

import probe_common
import taskprobe
from huey import RedisHuey

WHERE = os.environ.get("TETH_WHERE", "import")
if WHERE == "import":
    probe_common.activate_from_env()
elif WHERE != "on_startup":
    raise RuntimeError(f"TETH_WHERE={WHERE!r}: import or on_startup")

huey = RedisHuey("tethered-ct", url=os.environ["REDIS_URL"])


@huey.on_startup()
def _in_every_worker() -> None:
    if WHERE == "on_startup":
        probe_common.activate_from_env()


@huey.task()
def probe(op: str, params: dict[str, str]) -> dict[str, Any]:
    """One operation; the report is the result of the task."""
    return taskprobe.perform(op, params)


@huey.task(retries=2, retry_delay=0)
def probe_retried(op: str, params: dict[str, str]) -> dict[str, Any]:
    """The same with Huey's retries: twice more after an exception, at once."""
    return taskprobe.perform(op, params)
