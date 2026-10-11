"""A launcher script: lock the policy first, then import and run daphne.

    python launcher.py APPLICATION

daphne has no master and no workers, so there is nothing to inherit here.
What this arrangement shows is that daphne, Twisted and what they depend on
can be imported and started when a locked policy is already in place, and
that the application's own activation of the same policy is then a no-op.
"""

from __future__ import annotations

import os
import sys


def main(application: str) -> None:
    """Activate a locked policy, then run daphne's command line in this process."""
    import tethered

    tethered.activate(
        allow=os.environ.get("TETH_ALLOW", "allowed.test:9001").split(","),
        locked=True,
        lock_token=object(),
        external_subprocess_policy=os.environ.get("TETH_ESP", "warn"),
    )

    from daphne.cli import CommandLineInterface

    CommandLineInterface().run(["-b", "127.0.0.1", "-p", os.environ["PORT"], application])


if __name__ == "__main__":
    main(sys.argv[1])
