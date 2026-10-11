"""The aiohttp probe application: ``probe_aiohttp:app``, ``probe_aiohttp:init``.

aiohttp has its own application object and its own server.  The routes, the
parameters and the reports are those of ``probe_asgi`` (``harness/apps``),
whose operations run unchanged on the event loop aiohttp serves on; tethered
is activated when that module is imported, as ``TETH_ACTIVATE`` says.  One
route is aiohttp's own:

    /client    aiohttp.ClientSession: GET http://host:port/

The three ways to serve it:

    python probe_aiohttp.py                          web.run_app(app), on PORT
    python -m aiohttp.web -P PORT probe_aiohttp:init   aiohttp's command line
    gunicorn probe_aiohttp:app -k aiohttp.GunicornWebWorker
"""

from __future__ import annotations

import os
from typing import Any

import aiohttp
import probe_asgi
import probe_common
from aiohttp import web


async def _client(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    timeout = aiohttp.ClientTimeout(total=5.0)
    async with (
        aiohttp.ClientSession(timeout=timeout, trust_env=False) as session,
        session.get(f"http://{host}:{port}/") as reply,
    ):
        body = await reply.read()
        return {"status": reply.status, "reply": probe_common.last_line(body)}


OPERATIONS = {**probe_asgi.OPERATIONS, "client": _client}


async def handle(request: web.Request) -> web.Response:
    """Carry out one probe operation and report it, as ``probe_asgi`` does."""
    op = request.match_info["op"]
    params = dict(request.query)
    loop = probe_asgi._loop_name()
    status = 200
    if op == "whoami":
        report = probe_common.whoami(loop)
    elif op in OPERATIONS:
        host, port = params["host"], int(params["port"])
        report = {"op": op, "host": host, "port": port, **probe_common.whoami(loop)}
        if params.get("uncaught"):
            report.update(await OPERATIONS[op](host, port, params), outcome="reached")
        else:
            try:
                report.update(await OPERATIONS[op](host, port, params), outcome="reached")
            except Exception as exc:
                report.update(probe_common.describe_failure(exc))
    else:
        status = 404
        report = {"error": f"no such route: /{op}", "pid": probe_common.whoami()["pid"]}
    probe_common.hold(params)
    return web.json_response(report, status=status)


def make_app() -> web.Application:
    """Build the application: one route for every operation."""
    application = web.Application()
    application.router.add_get("/{op}", handle)
    return application


def init(argv: list[str]) -> web.Application:
    """The entry point for ``python -m aiohttp.web``."""
    return make_app()


def serve() -> None:
    """``web.run_app`` on ``PORT``, until SIGTERM."""
    web.run_app(make_app(), host="127.0.0.1", port=int(os.environ["PORT"]), print=None)


#: The application object, for gunicorn.
app = make_app()

if __name__ == "__main__":
    serve()
