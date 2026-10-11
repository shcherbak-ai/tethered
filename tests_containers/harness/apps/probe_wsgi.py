"""The WSGI probe application: ``probe_wsgi:application``, no framework.

It activates tethered when it is imported, as ``TETH_ACTIVATE`` says (see
``probe_common``).  Every route but ``/whoami`` takes ``host`` and ``port``:

    /connect   a blocking socket connection
    /urllib    a request with urllib.request
    /thread    a blocking socket connection in a thread started for it
    /child     launch a Python child that tries host:port itself and reports
               (how=executable|clean_env|no_site|path_python)
    /tool      launch an external tool (bash) that connects to host:port itself
    /whoami    process, thread, interpreter and the state of tethered

Common parameters: ``uncaught=1`` lets the exception of a failed operation
reach the server instead of reporting it; ``hold=<seconds>`` keeps the worker
busy before it answers; ``scope=<rule>,<rule>`` runs the operation inside a
``tethered.scope()`` with those rules (see ``probe_common.scoped``).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

import probe_common

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

probe_common.activate_from_env()


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


def application(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
    """The WSGI callable."""
    op = environ.get("PATH_INFO", "/").strip("/")
    params = dict(parse_qsl(environ.get("QUERY_STRING", "")))
    status = "200 OK"
    if op == "whoami":
        report = probe_common.whoami()
    elif op in OPERATIONS:
        host, port = params["host"], int(params["port"])
        report = {"op": op, "host": host, "port": port, **probe_common.whoami()}
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
    else:
        status = "404 Not Found"
        report = {"error": f"no such route: /{op}", "pid": probe_common.whoami()["pid"]}
    probe_common.hold(params)
    body = json.dumps(report).encode()
    start_response(
        status, [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
    )
    return [body]
