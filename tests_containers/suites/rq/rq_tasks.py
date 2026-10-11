"""The jobs of the RQ suite: ``rq_tasks.probe(op, params)``.

RQ imports a job's module where the job runs, not in the worker that waits
for jobs: with the default worker that is the "work horse", a process forked
for one job.  So when this module is the place that activates the policy
(``TETH_WHERE=tasks``, the default), every work horse activates it for
itself, right before its job, and the worker process holds none.  With
``TETH_WHERE=settings`` the worker's settings module does it instead
(``rq_settings.py``) and a work horse starts with the policy.

The report says which of the two happened (``active_before_import``) and how
the process that ran the job was started (``argv``).
"""

from __future__ import annotations

import os
import sys
from typing import Any

import probe_common
import taskprobe

#: Whether this process held a policy before this module had a say.
ACTIVE_BEFORE_IMPORT = probe_common.whoami()["active"]

if os.environ.get("TETH_WHERE", "tasks") == "tasks":
    probe_common.activate_from_env()


def probe(op: str, params: dict[str, str]) -> dict[str, Any]:
    """One operation; the report is the return value of the job."""
    report = taskprobe.perform(op, params)
    return {**report, "active_before_import": ACTIVE_BEFORE_IMPORT, "argv": sys.argv}
