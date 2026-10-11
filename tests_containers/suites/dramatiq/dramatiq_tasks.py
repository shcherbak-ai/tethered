"""The Dramatiq application under test: ``dramatiq dramatiq_tasks --processes 2 --threads 2``.

The ``dramatiq`` command starts worker processes and never imports this
module itself: each worker process imports it, and then runs actors in its
worker threads.  ``TETH_WHERE`` says where the policy is activated
(``TETH_ACTIVATE`` says which one):

    import        when this module is imported, in every worker process (the default)
    process_boot  in the ``after_process_boot`` hook of a middleware, which Dramatiq
                  calls in every worker process right after it has imported the broker

The front end imports this module too, as any producer of messages does.
"""

from __future__ import annotations

import os
from typing import Any

import dramatiq
import probe_common
import taskprobe
from dramatiq.brokers.redis import RedisBroker
from dramatiq.middleware import Middleware
from dramatiq.results import Results
from dramatiq.results.backends import RedisBackend

WHERE = os.environ.get("TETH_WHERE", "import")
#: Whether this process held a policy before this module had a say.
ACTIVE_BEFORE_IMPORT = probe_common.whoami()["active"]

if WHERE == "import":
    probe_common.activate_from_env()
elif WHERE != "process_boot":
    raise RuntimeError(f"TETH_WHERE={WHERE!r}: import or process_boot")


class ActivateAtBoot(Middleware):
    """Activates the policy when a worker process has booted, if that is where it is asked for."""

    def after_process_boot(self, broker: dramatiq.Broker) -> None:
        """Called once in every worker process, before its worker threads start."""
        if WHERE == "process_boot":
            probe_common.activate_from_env()


backend = RedisBackend(url=os.environ["REDIS_URL"])
broker = RedisBroker(url=os.environ["REDIS_URL"])
broker.add_middleware(Results(backend=backend))
broker.add_middleware(ActivateAtBoot())
dramatiq.set_broker(broker)


def _report(op: str, params: dict[str, str]) -> dict[str, Any]:
    return {**taskprobe.perform(op, params), "active_before_import": ACTIVE_BEFORE_IMPORT}


@dramatiq.actor(store_results=True, max_retries=0)
def probe(op: str, params: dict[str, str]) -> dict[str, Any]:
    """One operation; the report is the result of the message.  Never retried."""
    return _report(op, params)


@dramatiq.actor(store_results=True, max_retries=2, min_backoff=10, max_backoff=20)
def probe_retried(op: str, params: dict[str, str]) -> dict[str, Any]:
    """The same with Dramatiq's retries: twice more after an exception, a few ms apart."""
    return _report(op, params)
