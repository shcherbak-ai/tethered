"""Take a policy, then become Apache: ``python launcher.py <arguments of apache2>``.

This is a container entry point that sets the policy before the server
starts.  tethered writes the policy to an environment variable when it is
activated, and what a process executes inherits its environment: Apache,
its child processes, mod_wsgi's daemon processes.  Each Python interpreter
that mod_wsgi starts in them then begins with that policy, the main
interpreter of a process first, before any application is imported.

The policy is the one ``TETH_ACTIVATE`` names (``probe_common``).  Apache is
not Python, so tethered reports this ``os.execv`` as an external launch, and
refuses it under ``external_subprocess_policy="block"``.
"""

from __future__ import annotations

import os
import shutil
import sys

import probe_common

if __name__ == "__main__":
    probe_common.activate_from_env()
    apache = shutil.which("apache2")
    if apache is None:
        raise SystemExit("apache2 is not on PATH")
    os.execv(apache, ["apache2", *sys.argv[1:]])
