"""A container entry point: activate a policy, then become supervisord.

    python entrypoint.py COMMAND

``COMMAND`` is the command line of the program that supervisord is to run
(``supervisord.conf`` reads it from the environment).  ``LAUNCHER_ACTIVATE``
says which policy this script activates before it replaces itself with
``supervisord`` (``none``: no policy, tethered is not even imported here).
``TETH_ACTIVATE`` is left for the program (``sup_app.py``).

supervisord is Debian's package: a Python program of the distribution's own
interpreter, which has no tethered.  The policy of this script can only reach
the supervised program through the environment that supervisord passes on.
"""

from __future__ import annotations

import os
import sys

import probe_common


def main(command: str) -> None:
    """Activate as ``LAUNCHER_ACTIVATE`` says, then exec ``supervisord`` in the foreground."""
    for_the_program = os.environ["TETH_ACTIVATE"]
    os.environ["TETH_ACTIVATE"] = os.environ.get("LAUNCHER_ACTIVATE", "none")
    probe_common.activate_from_env()
    os.environ["TETH_ACTIVATE"] = for_the_program
    os.environ["APP_COMMAND"] = command
    os.execvp("supervisord", ["supervisord", "--nodaemon", "--configuration", "supervisord.conf"])


if __name__ == "__main__":
    main(sys.argv[1])
