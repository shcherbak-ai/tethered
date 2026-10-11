"""The tornado probe application and the script that serves it.

    python probe_tornado.py [client=simple|curl] [processes=N] [autoreload]

tornado has its own application object, its own HTTP server and its own
client classes, all on asyncio's event loop.  The routes, the parameters and
the reports are those of ``probe_asgi`` (``harness/apps``), whose operations
run unchanged here; tethered is activated when that module is imported, as
``TETH_ACTIVATE`` says.  The routes that are tornado's own:

    /http_client   AsyncHTTPClient().fetch("http://host:port/")
    /tcp_client    tornado.tcpclient.TCPClient().connect(host, port)
    /resolver      tornado.netutil.Resolver().resolve(host, port), no connection
    /subprocess    tornado.process.Subprocess: an external tool (bash) that connects itself

``client=`` picks the implementation behind ``AsyncHTTPClient``: ``simple``
(tornado's default, written in Python on its own ``IOStream``) or ``curl``
(``tornado.curl_httpclient``, which hands the whole request to libcurl).

How it is served:

* by default, one process: ``HTTPServer.listen`` and ``asyncio.run``;
* ``processes=N``: ``bind_sockets``, ``fork_processes(N)``, then a server and
  an event loop in each child.  The parent has imported this module, and with
  it the policy, before it forks; it replaces a child that dies;
* ``autoreload``: ``tornado.autoreload.start()``, which replaces the process
  with a new one (``os.execv``, same pid) when a watched file changes.
  ``RELOAD_FILE`` in the environment names one more file to watch.

``/whoami`` and every report carry ``booted``, which changes when the process
was replaced by a reload, and ``http_client``, the client class in use.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import time
from typing import Any

import probe_asgi
import probe_common
import tornado.autoreload
import tornado.httpclient
import tornado.httpserver
import tornado.netutil
import tornado.process
import tornado.tcpclient
import tornado.web

#: Different in every process image: a reload (``os.execv``) keeps the pid and changes this.
BOOTED = time.time_ns()


async def _http_client(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    client = tornado.httpclient.AsyncHTTPClient()
    reply = await client.fetch(f"http://{host}:{port}/", connect_timeout=5.0, request_timeout=5.0)
    return {"status": reply.code, "reply": probe_common.last_line(reply.body)}


async def _tcp_client(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    stream = await tornado.tcpclient.TCPClient().connect(host, port, timeout=5.0)
    try:
        await stream.write(probe_common.REQUEST)
        data = await stream.read_until_close()
    finally:
        stream.close()
    return {"reply": probe_common.last_line(data)}


async def _resolver(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    found = await tornado.netutil.Resolver().resolve(host, port)
    return {"addresses": sorted({address[0] for _family, address in found})}


async def _subprocess(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    stream = tornado.process.Subprocess.STREAM
    process = tornado.process.Subprocess(
        probe_common.tool_argv(host, port), stdout=stream, stderr=stream
    )
    stdout = await process.stdout.read_until_close()
    stderr = await process.stderr.read_until_close()
    returncode = await process.wait_for_exit(raise_error=False)
    return probe_common.launch_report(returncode, stdout.decode(), stderr.decode())


OPERATIONS = {
    **probe_asgi.OPERATIONS,
    "http_client": _http_client,
    "tcp_client": _tcp_client,
    "resolver": _resolver,
    "subprocess": _subprocess,
}


def _whoami() -> dict[str, Any]:
    client = tornado.httpclient.AsyncHTTPClient()
    return {
        **probe_common.whoami(probe_asgi._loop_name()),
        "booted": BOOTED,
        "http_client": f"{type(client).__module__}.{type(client).__qualname__}",
    }


class Probe(tornado.web.RequestHandler):
    """One route for every operation, reported as ``probe_asgi`` reports them."""

    async def get(self, op: str) -> None:
        """Carry out one probe operation and report it."""
        params = {key: self.get_query_argument(key) for key in self.request.query_arguments}
        if op == "whoami":
            report = _whoami()
        elif op in OPERATIONS:
            host, port = params["host"], int(params["port"])
            report = {"op": op, "host": host, "port": port, **_whoami()}
            if params.get("uncaught"):
                report.update(await OPERATIONS[op](host, port, params), outcome="reached")
            else:
                try:
                    report.update(await OPERATIONS[op](host, port, params), outcome="reached")
                except Exception as exc:
                    report.update(probe_common.describe_failure(exc))
        else:
            self.set_status(404)
            report = {"error": f"no such route: /{op}", "pid": os.getpid()}
        probe_common.hold(params)
        self.set_header("Content-Type", "application/json")
        self.finish(json.dumps(report))


def make_app() -> tornado.web.Application:
    """Build the application."""
    return tornado.web.Application([(r"/(\w+)", Probe)])


def _end_the_process_group(signum: int, frame: Any) -> None:
    # fork_processes leaves stopping the children to whoever runs the parent.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    os.killpg(os.getpgid(0), signal.SIGTERM)


def main(options: list[str]) -> None:
    """Serve on ``PORT`` as ``options`` say, until SIGTERM."""
    settings = dict(option.partition("=")[::2] for option in options)
    port = int(os.environ["PORT"])
    if settings.get("client") == "curl":
        tornado.httpclient.AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")

    if "processes" in settings:
        sockets = tornado.netutil.bind_sockets(port, address="127.0.0.1")
        signal.signal(signal.SIGTERM, _end_the_process_group)
        tornado.process.fork_processes(int(settings["processes"]))

        async def serve_in_a_child() -> None:
            tornado.httpserver.HTTPServer(make_app()).add_sockets(sockets)
            await asyncio.Event().wait()

        asyncio.run(serve_in_a_child())
        return

    async def serve() -> None:
        make_app().listen(port, address="127.0.0.1")
        if "autoreload" in settings:
            if os.environ.get("RELOAD_FILE"):
                tornado.autoreload.watch(os.environ["RELOAD_FILE"])
            tornado.autoreload.start()
        await asyncio.Event().wait()

    asyncio.run(serve())


if __name__ == "__main__":
    main(sys.argv[1:])
