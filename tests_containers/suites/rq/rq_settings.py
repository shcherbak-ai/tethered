"""The settings module of the RQ worker: ``rq worker -c rq_settings``.

The worker imports it when it starts, before it waits for jobs.  It is the
one module of the application that an RQ worker process itself imports, and
so the place to activate a policy that the worker, and not only each job,
is to hold (``TETH_WHERE=settings``).
"""

from __future__ import annotations

import os

REDIS_URL = os.environ["REDIS_URL"]

if os.environ.get("TETH_WHERE") == "settings":
    import probe_common

    probe_common.activate_from_env()
