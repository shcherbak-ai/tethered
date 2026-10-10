"""Run a server command that is expected to end by itself, and report how it ended.

``start_server`` is for servers that come up: it fails the test when the
process exits while it is starting.  Some arrangements are tested for the
opposite, a server that refuses to start, and what matters then is the exit
status and what was written.  ``run_to_exit`` runs such a command through
``harness.run_python``, which gives it the environment of every process under
test, attaches its output to the report of a failing test and leaves no
process behind.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from harness import run_python

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

#: Runs ``sys.argv[1:]`` with ``CHILD_ENV`` added to the environment; prints one line of JSON.
_RUNNER = """
import json, os, subprocess, sys

env = {**os.environ, **json.loads(os.environ["CHILD_ENV"])}
del env["CHILD_ENV"]
try:
    done = subprocess.run(
        sys.argv[1:],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=float(os.environ["CHILD_TIMEOUT"]),
    )
    result = {"returncode": done.returncode, "output": done.stdout.decode("utf-8", "replace")}
except subprocess.TimeoutExpired as expired:
    result = {"returncode": None, "output": (expired.stdout or b"").decode("utf-8", "replace")}
print(json.dumps(result))
"""


def run_to_exit(
    argv: Iterable[str], env: Mapping[str, str], timeout: float = 30.0
) -> dict[str, Any]:
    """Run ``argv`` with ``env`` added to the environment until it exits.

    Returns ``{"returncode": ..., "output": ...}``: the exit status and
    everything written to stdout and stderr.  ``returncode`` is ``None`` when
    the command was still running after ``timeout`` seconds, which for a
    server means that it did start; it is killed then.
    """
    done = run_python(
        _RUNNER,
        activate="none",
        env={"CHILD_ENV": json.dumps(dict(env)), "CHILD_TIMEOUT": str(timeout)},
        args=list(argv),
        timeout=timeout + 20.0,
    )
    return done.json()
