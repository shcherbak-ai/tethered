"""The sanic probe application: ``probe_sanic:app``.

sanic has its own application object and its own server.  The routes, the
parameters and the reports are those of ``probe_asgi`` (``harness/apps``),
whose operations run unchanged on the event loop sanic serves on.  One route
is sanic's own: ``/restart`` asks the worker manager to replace every worker
(``app.m.restart(all_workers=True, zero_downtime=True)``).

tethered is activated when ``probe_asgi`` is imported, as ``TETH_ACTIVATE``
says.  Whether that happens before or after ``import sanic`` matters, because
importing sanic imports uvloop when uvloop is installed.  ``TETH_ORDER`` says
which: ``activate_first`` (the default) or ``sanic_first``.  It only makes a
difference where this module is the first to import sanic, that is, in a
script; the ``sanic`` command has imported sanic long before.

``SANIC_USE_UVLOOP=false`` in the environment is sanic's own setting (any
``SANIC_`` variable becomes a configuration value) for serving on the
standard asyncio event loop.
"""

from __future__ import annotations

import os

# The order of these imports is the subject: keep them as they are.
# isort: off
if os.environ.get("TETH_ORDER", "activate_first") == "activate_first":
    import probe_asgi  # activates the policy

    from sanic import Sanic
    from sanic.response import json as json_response
else:
    from sanic import Sanic
    from sanic.response import json as json_response

    import probe_asgi  # activates the policy
# isort: on

import probe_common

app = Sanic("probe")


@app.get("/<op:str>")
async def handle(request, op: str):  # type: ignore[no-untyped-def]
    """Carry out one probe operation and report it, as ``probe_asgi`` does."""
    params = {key: request.args.get(key) for key in request.args}
    loop = probe_asgi._loop_name()
    status = 200
    if op == "whoami":
        report = probe_common.whoami(loop)
    elif op == "restart":
        # sanic's own way to replace the workers: a message to the worker manager.
        report = probe_common.whoami(loop)
        request.app.m.restart(all_workers=True, zero_downtime=True)
    elif op in probe_asgi.OPERATIONS:
        host, port = params["host"], int(params["port"])
        report = {"op": op, "host": host, "port": port, **probe_common.whoami(loop)}
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
        report = {"error": f"no such route: /{op}", "pid": probe_common.whoami()["pid"]}
    probe_common.hold(params)
    return json_response(report, status=status)
