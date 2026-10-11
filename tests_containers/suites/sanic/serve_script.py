"""sanic started from a script: ``python serve_script.py [single] [workers=N]``.

The arrangement of sanic's "running from a script" documentation.  This file
is the first to import the application module, and that module the first to
import sanic, so the order in which ``probe_sanic`` activates the policy and
imports sanic (``TETH_ORDER``) is the order of the whole process.

Without ``single`` sanic runs its worker manager: this process becomes the
main process and each worker is a new Python process, which runs this file
again (as ``__mp_main__``) to find the application.
"""

from __future__ import annotations

import os
import sys

from probe_sanic import app

if __name__ == "__main__":
    options = sys.argv[1:]
    workers = next((int(o.partition("=")[2]) for o in options if o.startswith("workers=")), 1)
    app.run(
        host="127.0.0.1",
        port=int(os.environ["PORT"]),
        workers=workers,
        single_process="single" in options,
        motd=False,
        access_log=False,
    )
