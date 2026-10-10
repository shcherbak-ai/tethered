"""Run a script with tethered already active: ``run_under_policy.py SCRIPT [ARGS...]``.

This is what ``harness.run_python`` starts.  The policy is activated as
``TETH_ACTIVATE`` says (see ``probe_common``) and then the script runs as
``__main__``, with its own path in tracebacks.
"""

from __future__ import annotations

import runpy
import sys

import probe_common

if __name__ == "__main__":
    probe_common.activate_from_env()
    sys.argv = sys.argv[1:]
    runpy.run_path(sys.argv[0], run_name="__main__")
