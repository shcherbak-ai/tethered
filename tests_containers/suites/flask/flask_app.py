"""A Flask application whose factory activates tethered: ``flask_app:create_app``.

``create_app()`` activates the policy as ``TETH_ACTIVATE`` says (see
``probe_common``) before it builds the application, which is where a Flask
project puts start-up code.  Routes, each of which takes ``host`` and ``port``:

    /fetch     a GET with requests (``retries=N`` mounts an adapter that retries)
    /connect   a blocking socket connection
    /child     launch a Python child that tries host:port itself (``how=...``)
    /whoami    process, thread and the state of tethered

``uncaught=1`` lets the exception of a failed operation out of the view.  With
``TETH_HANDLER=1`` the application has an error handler for
``tethered.EgressBlocked`` that answers 503.  ``flask fetch HOST PORT`` is a
command of the application's command line that does what ``/fetch`` does.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import click
import probe_common
import requests
from flask import Flask, jsonify, request
from requests.adapters import HTTPAdapter


def fetch(host: str, port: int, retries: int = 0) -> dict[str, Any]:
    """One GET with requests; a session of its own, so that nothing is reused."""
    with requests.Session() as session:
        session.trust_env = False
        if retries:
            session.mount("http://", HTTPAdapter(max_retries=retries))
        reply = session.get(f"http://{host}:{port}/", timeout=5.0)
        return {"status": reply.status_code, "reply": probe_common.last_line(reply.content)}


def create_app() -> Flask:
    """Activate tethered, then build the application."""
    probe_common.activate_from_env()
    app = Flask(__name__)

    if os.environ.get("TETH_HANDLER"):
        import tethered

        @app.errorhandler(tethered.EgressBlocked)
        def egress_blocked(error: tethered.EgressBlocked) -> tuple[Any, int]:
            app.logger.error("Egress blocked: %s:%s", error.host, error.port)
            return jsonify(error="egress blocked", host=error.host, port=error.port), 503

    def operation(op: str) -> dict[str, Any]:
        host, port = request.args["host"], int(request.args["port"])
        if op == "fetch":
            return fetch(host, port, int(request.args.get("retries", "0")))
        if op == "connect":
            return probe_common.tcp_connect(host, port)
        argv, popen_args = probe_common.child_argv(
            request.args.get("how", "executable"), host, port
        )
        return probe_common.launch(argv, **popen_args)

    @app.get("/whoami")
    def whoami() -> Any:
        probe_common.hold(request.args)
        return jsonify(probe_common.whoami())

    @app.get("/<any(fetch, connect, child):op>")
    def probe(op: str) -> Any:
        report = {
            "op": op,
            "host": request.args["host"],
            "port": int(request.args["port"]),
            **probe_common.whoami(),
        }
        if request.args.get("uncaught"):
            report.update(operation(op), outcome="reached")
        else:
            try:
                report.update(operation(op), outcome="reached")
            except Exception as exc:
                report.update(probe_common.describe_failure(exc))
        probe_common.hold(request.args)
        return jsonify(report)

    @app.cli.command("fetch")
    @click.argument("host")
    @click.argument("port", type=int)
    def fetch_command(host: str, port: int) -> None:
        """GET http://HOST:PORT/ and print one line of JSON about it."""
        report = {"op": "fetch", "host": host, "port": port, **probe_common.whoami()}
        try:
            report.update(fetch(host, port), outcome="reached")
        except Exception as exc:
            report.update(probe_common.describe_failure(exc))
        sys.stdout.write(json.dumps(report) + "\n")

    return app
