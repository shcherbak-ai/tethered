"""The RSGI probe application, for granian's own interface: ``probe_rsgi:app``.

RSGI is the protocol granian speaks natively: the application is called with
a scope object and a protocol object in place of ASGI's three arguments.  The
handlers run on the same asyncio-compatible event loop, so the operations are
those of ``probe_asgi`` (``harness/apps``), which is also where tethered is
activated, when that module is imported.  Routes, parameters and reports are
the same.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl

import probe_asgi
import probe_common


async def app(scope: Any, proto: Any) -> None:
    """The RSGI callable."""
    op = scope.path.strip("/")
    params = dict(parse_qsl(scope.query_string))
    loop = probe_asgi._loop_name()
    status = 200
    if op == "whoami":
        report = probe_common.whoami(loop)
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
    proto.response_bytes(
        status=status,
        headers=[("content-type", "application/json")],
        body=json.dumps(report).encode(),
    )
