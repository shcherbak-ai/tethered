"""The applications of the uWSGI suite: ``make(name)`` builds one WSGI callable.

uWSGI can serve several applications from one process, each in an interpreter
of its own, so an application here has a name and settings of its own.  It
activates tethered when ``make()`` is called, which is when uWSGI imports the
file that calls it (``app_a.py``, ``app_b.py``):

    TETH_ACTIVATE_<NAME>     none, plain or locked; ``TETH_ACTIVATE`` when unset
    TETH_ALLOW_<NAME>        the allow list, comma-separated; ``TETH_ALLOW``
    TETH_ALLOW_FILE_<NAME>   a file with the allow list, one rule per line, read at import
                             (how a test changes the policy between two reloads)
    TETH_ESP_<NAME>          external_subprocess_policy; ``TETH_ESP``
    TETH_CATCH_<NAME>        1: a failing activate() is caught and reported by /whoami
                             (``activation_error``); otherwise the import fails with it

The routes are those of ``probe_wsgi`` (``/connect``, ``/urllib``, ``/child``,
``/tool``, ``/whoami``, with ``hold`` and ``uncaught``), plus:

    /launch    run ``argv`` (a JSON list; "{executable}" stands for sys.executable,
               "{child}" for the probe child script), ``env=clean`` for an environment
               without the policy variable
    /pyinfo    whoami plus what uWSGI made of the interpreter: prefixes, sys.path,
               where tethered was imported from, whether the bootstrap ran

Under ``--manage-script-name`` an application mounted at ``/a`` answers ``/a/whoami``.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

import probe_common

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable


def _setting(name: str, key: str, default: str | None = None) -> str | None:
    return os.environ.get(f"{key}_{name.upper()}", os.environ.get(key, default))


def _activate(name: str) -> str | None:
    """Activate tethered as the settings of ``name`` say; returns a caught failure, if any."""
    flags = {flag.strip() for flag in (_setting(name, "TETH_ACTIVATE", "none") or "").split(",")}
    if "none" in flags:
        return None
    logging.basicConfig(
        level=logging.INFO,
        format=f"LOG pid=%(process)d app={name} %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    import tethered

    allow_file = _setting(name, "TETH_ALLOW_FILE")
    if allow_file:
        with open(allow_file, encoding="utf-8") as handle:
            allow = handle.read().split()
    else:
        allow = (_setting(name, "TETH_ALLOW", probe_common.DEFAULT_ALLOW) or "").split(",")
    kwargs: dict[str, Any] = {"allow": allow}
    if "locked" in flags:
        kwargs.update(locked=True, lock_token=object())
    esp = _setting(name, "TETH_ESP")
    if esp:
        kwargs["external_subprocess_policy"] = esp
    try:
        tethered.activate(**kwargs)
    except Exception as exc:
        if not _setting(name, "TETH_CATCH"):
            raise
        return f"{type(exc).__name__}: {exc}"
    print(f"app {name}: pid {os.getpid()} activated tethered {allow}", file=sys.stderr, flush=True)
    return None


def _pyinfo() -> dict[str, Any]:
    info: dict[str, Any] = {
        "prefix": sys.prefix,
        "base_prefix": sys.base_prefix,
        "path": sys.path,
        # The bootstrap module is only imported when tethered.pth ran in this
        # interpreter and found a policy to inherit.
        "bootstrap_ran": "tethered._autoactivate" in sys.modules,
        "tethered_file": getattr(sys.modules.get("tethered"), "__file__", None),
    }
    try:
        import uwsgi

        info["uwsgi_worker_id"] = uwsgi.worker_id()
        info["uwsgi_master_pid"] = uwsgi.masterpid()
    except ImportError:
        pass
    return info


def _launch(params: dict[str, str]) -> dict[str, Any]:
    stand_ins = {"{executable}": sys.executable, "{child}": probe_common.CHILD_SCRIPT}
    argv = [stand_ins.get(argument, argument) for argument in json.loads(params["argv"])]
    popen_args: dict[str, Any] = {}
    if params.get("env") == "clean":
        popen_args["env"] = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
        }
    return {"argv": argv, **probe_common.launch(argv, **popen_args)}


def _child(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    argv, popen_args = probe_common.child_argv(params.get("how", "executable"), host, port)
    return probe_common.launch(argv, **popen_args)


OPERATIONS: dict[str, Callable[[str, int, dict[str, str]], dict[str, Any]]] = {
    "connect": lambda host, port, params: probe_common.tcp_connect(host, port),
    "urllib": lambda host, port, params: probe_common.urllib_get(host, port),
    "child": _child,
    "tool": lambda host, port, params: probe_common.launch(probe_common.tool_argv(host, port)),
}


def make(name: str) -> Callable[..., Iterable[bytes]]:
    """Activate tethered for the application ``name`` and return its WSGI callable."""
    activation_error = _activate(name)
    imported_in_pid = os.getpid()

    def identity() -> dict[str, Any]:
        return {
            **probe_common.whoami(),
            "app": name,
            "imported_in_pid": imported_in_pid,
            "activation_error": activation_error,
        }

    def application(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        route = environ.get("PATH_INFO", "/").strip("/")
        params = dict(parse_qsl(environ.get("QUERY_STRING", "")))
        status = "200 OK"
        if route == "whoami":
            report = identity()
        elif route == "pyinfo":
            report = {**identity(), **_pyinfo()}
        elif route == "launch":
            report = {"op": route, **identity()}
            try:
                report.update(_launch(params), outcome="reached")
            except Exception as exc:
                report.update(probe_common.describe_failure(exc))
        elif route in OPERATIONS:
            host, port = params["host"], int(params["port"])
            report = {"op": route, "host": host, "port": port, **identity()}
            if params.get("uncaught"):
                report.update(OPERATIONS[route](host, port, params), outcome="reached")
            else:
                try:
                    report.update(OPERATIONS[route](host, port, params), outcome="reached")
                except Exception as exc:
                    report.update(probe_common.describe_failure(exc))
        else:
            status = "404 Not Found"
            report = {"error": f"no such route: /{route}", "app": name, "pid": os.getpid()}
        probe_common.hold(params)
        body = json.dumps(report).encode()
        start_response(
            status, [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
        )
        return [body]

    return application
