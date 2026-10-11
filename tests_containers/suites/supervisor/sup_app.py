"""The program that supervisord runs: ``python sup_app.py``.

An HTTP server (``taskprobe.serve``) that does one outbound operation per
request in its own process.  It activates the policy ``TETH_ACTIVATE`` names
when it starts; with ``none`` it never calls ``activate()``, and whatever
policy it reports it has inherited.  ``configured`` in a report is the
variable that only supervisord's configuration sets.
"""

from __future__ import annotations

import os
from typing import Any

import probe_common
import taskprobe


def perform(op: str, params: dict[str, str]) -> dict[str, Any]:
    """One operation in this process."""
    return {**taskprobe.perform(op, params), "configured": os.environ.get("CONFIGURED")}


if __name__ == "__main__":
    probe_common.activate_from_env()
    taskprobe.serve(perform)
