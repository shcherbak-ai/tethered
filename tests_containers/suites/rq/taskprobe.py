"""What a probe task does, and the HTTP front end through which a test asks for one.

A worker is not an HTTP server, so the harness cannot talk to it directly.
Each worker suite therefore has two small programs next to its tests:

    the tasks module   defines the application and one task, ``probe(op, params)``,
                       which calls :func:`perform` in whatever process, thread or
                       interpreter the framework runs task code in
    front.py           an HTTP server (:func:`serve`) that turns ``GET /<op>?<params>``
                       into one task, waits for its result and answers with it

so that ``start_server``, ``Server.probe`` and ``Server.each_worker`` work for a
worker as they do for a web server: the ``pid`` of a report is the process that
ran the task.

The operations are those of the WSGI probe application (``harness/apps``):
``whoami``, ``connect``, ``urllib``, ``thread``, ``child`` (``how=...``) and
``tool``, with ``uncaught=1`` to let the exception out of the task,
``hold=<seconds>`` to keep the worker busy and ``scope=<rule>,<rule>`` to run
the operation inside a ``tethered.scope()`` (see ``probe_common.scoped``).
``record=1`` also appends the report to the file named by ``TC_RECORD``, for
tasks nobody waits for (scheduled ones).

This file is the same in every worker suite; a suite directory is all an
image gets, so it cannot be shared.  It never imports the ``harness`` package
and never imports tethered.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlsplit

import probe_common

if TYPE_CHECKING:
    from collections.abc import Callable

_record_lock = threading.Lock()


def _connect(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    return probe_common.tcp_connect(host, port)


def _urllib(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    return probe_common.urllib_get(host, port)


def _thread(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    return probe_common.connect_in_thread(host, port)


def _child(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    argv, popen_args = probe_common.child_argv(params.get("how", "executable"), host, port)
    return probe_common.launch(argv, **popen_args)


def _tool(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    return probe_common.launch(probe_common.tool_argv(host, port))


OPERATIONS: dict[str, Callable[[str, int, dict[str, str]], dict[str, Any]]] = {
    "connect": _connect,
    "urllib": _urllib,
    "thread": _thread,
    "child": _child,
    "tool": _tool,
}


def record(report: dict[str, Any]) -> None:
    """Append a report to the file ``TC_RECORD`` names, one JSON document per line."""
    line = json.dumps(report) + "\n"
    with _record_lock, open(os.environ["TC_RECORD"], "a", encoding="utf-8") as handle:
        handle.write(line)


def perform(op: str, params: dict[str, str]) -> dict[str, Any]:
    """Carry out one operation where the task runs, and return the report.

    With ``uncaught=1`` an exception leaves the task: the framework then
    decides what a refused task looks like.
    """
    # The socket class tells a pool that patches the standard library (gevent, eventlet).
    patched = f"{socket.socket.__module__}.{socket.socket.__qualname__}"
    who = {**probe_common.whoami(), "socket_class": patched}
    if op == "whoami":
        report = who
    else:
        host, port = params["host"], int(params["port"])
        report = {"op": op, "host": host, "port": port, **who}
        operation = OPERATIONS[op]
        if params.get("uncaught"):
            done = probe_common.run_scoped(operation, host, port, params, report)
            report.update(done, outcome="reached")
        else:
            try:
                done = probe_common.run_scoped(operation, host, port, params, report)
                report.update(done, outcome="reached")
            except Exception as exc:
                report.update(probe_common.describe_failure(exc))
    probe_common.hold(params)
    if params.get("record"):
        record(report)
    return report


def failure(exc: BaseException, **more: Any) -> dict[str, Any]:
    """How a failed task looks to the process that asked for it: the ``task`` part of an answer."""
    return {
        "state": "failed",
        "exception": f"{type(exc).__module__}.{type(exc).__qualname__}",
        "message": str(exc),
        **more,
    }


def serve(submit: Callable[[str, dict[str, str]], dict[str, Any]]) -> None:
    """Serve ``GET /<op>?<params>`` on ``127.0.0.1:$PORT`` until the process is terminated.

    ``submit(op, params)`` runs one task and returns the answer: the report
    of the task with a ``task`` entry that says how the framework delivered
    it, or only the ``task`` entry when the task failed.  ``/front`` answers
    for the front end itself.
    """

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            url = urlsplit(self.path)
            op, params = url.path.strip("/"), dict(parse_qsl(url.query))
            status = 200
            try:
                answer = probe_common.whoami() if op == "front" else submit(op, params)
            except Exception:
                status, answer = 500, {"error": traceback.format_exc()}
            body = json.dumps(answer).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            print(f"front: {format % args}", file=sys.stderr, flush=True)

    ThreadingHTTPServer.daemon_threads = True
    server = ThreadingHTTPServer(("127.0.0.1", int(os.environ["PORT"])), Handler)
    print(f"front: pid {os.getpid()} on port {server.server_port}", file=sys.stderr, flush=True)
    server.serve_forever()
