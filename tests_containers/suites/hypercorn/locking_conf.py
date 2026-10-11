"""A hypercorn configuration file that locks the policy: ``hypercorn -c file:locking_conf.py``.

hypercorn executes this file in its master process, before it starts a
worker.  The master then holds the policy, and the workers, which hypercorn
starts as new Python processes, inherit it at startup, before they import
hypercorn's worker, an event loop or the application.

Only plain values may be left in this namespace: hypercorn copies every name
that is not a module into its configuration and pickles that for the workers.
"""

from __future__ import annotations

import os

import tethered

tethered.activate(
    allow=["allowed.test:9001"],
    locked=True,
    lock_token=object(),
    external_subprocess_policy=os.environ.get("TETH_ESP", "warn"),
)
