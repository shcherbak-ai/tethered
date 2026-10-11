"""The views of the suite's Django project.

    /fetch     a GET with requests
    /connect   a blocking socket connection
    /child     launch a Python child that tries host:port itself (``how=...``)
    /whoami    process, thread and the state of tethered

Each of the first three takes ``host`` and ``port``; ``uncaught=1`` lets the
exception of a failed operation out of the view, to Django and its middleware.
"""

from __future__ import annotations

from typing import Any

import probe_common
import requests
from django.http import Http404, HttpRequest, JsonResponse


def fetch(host: str, port: int) -> dict[str, Any]:
    """One GET with requests; a session of its own, so that nothing is reused."""
    with requests.Session() as session:
        session.trust_env = False
        reply = session.get(f"http://{host}:{port}/", timeout=5.0)
        return {"status": reply.status_code, "reply": probe_common.last_line(reply.content)}


def _operation(op: str, request: HttpRequest) -> dict[str, Any]:
    host, port = request.GET["host"], int(request.GET["port"])
    if op == "fetch":
        return fetch(host, port)
    if op == "connect":
        return probe_common.tcp_connect(host, port)
    argv, popen_args = probe_common.child_argv(request.GET.get("how", "executable"), host, port)
    return probe_common.launch(argv, **popen_args)


def whoami(request: HttpRequest) -> JsonResponse:
    """Who is answering, and the state of tethered."""
    probe_common.hold(request.GET)
    return JsonResponse(probe_common.whoami())


def probe(request: HttpRequest, op: str) -> JsonResponse:
    """One outbound operation, reported as JSON."""
    if op not in ("fetch", "connect", "child"):
        raise Http404(op)
    report = {
        "op": op,
        "host": request.GET["host"],
        "port": int(request.GET["port"]),
        **probe_common.whoami(),
    }
    if request.GET.get("uncaught"):
        report.update(_operation(op, request), outcome="reached")
    else:
        try:
            report.update(_operation(op, request), outcome="reached")
        except Exception as exc:
            report.update(probe_common.describe_failure(exc))
    probe_common.hold(request.GET)
    return JsonResponse(report)
