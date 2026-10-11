"""The Quart probe application: ``probe_quart:app``.

    hypercorn probe_quart:app                 the deployment Quart recommends
    QUART_APP=probe_quart:app quart run       Quart's development server
    python probe_quart.py                     app.run(), on PORT

Quart is an ASGI framework with its own application object.  The routes, the
parameters and the reports are those of ``probe_asgi`` (``harness/apps``),
whose operations run unchanged in a Quart view; tethered is activated when
that module is imported, as ``TETH_ACTIVATE`` says.

``/whoami`` and every report carry ``booted``, which changes when the process
was replaced by Quart's reloader.
"""

from __future__ import annotations

import os
import time
from typing import Any

import probe_asgi
import probe_common
from quart import Quart, jsonify, request

#: Different in every process image: a reload keeps or changes the pid, and changes this.
BOOTED = time.time_ns()

app = Quart(__name__)


def _whoami() -> dict[str, Any]:
    return {**probe_common.whoami(probe_asgi._loop_name()), "booted": BOOTED}


@app.get("/<op>")
async def handle(op: str) -> Any:
    """Carry out one probe operation and report it, as ``probe_asgi`` does."""
    params = request.args.to_dict()
    status = 200
    if op == "whoami":
        report = _whoami()
    elif op in probe_asgi.OPERATIONS:
        host, port = params["host"], int(params["port"])
        report = {"op": op, "host": host, "port": port, **_whoami()}
        if params.get("uncaught"):
            report.update(await probe_asgi.OPERATIONS[op](host, port, params), outcome="reached")
        else:
            try:
                report.update(
                    await probe_asgi.OPERATIONS[op](host, port, params), outcome="reached"
                )
            except Exception as exc:
                report.update(probe_common.describe_failure(exc))
    else:
        status = 404
        report = {"error": f"no such route: /{op}", "pid": os.getpid()}
    probe_common.hold(params)
    return jsonify(report), status


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ["PORT"]))
