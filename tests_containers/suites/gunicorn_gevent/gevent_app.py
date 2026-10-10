"""The application of the gunicorn gevent suite: the shared WSGI probe, and what only gevent has.

Every route of ``probe_wsgi`` is served as it is.  Added here:

    /arrangement   whoami, plus what gevent patched, the resolver and the kind of greenlet
    /launch        a launch with a chosen routing of the child's stderr
                   (what=tool|executable|clean_env|no_site|path_python, stderr=pipe|stdout|inherit)

With ``GEVENT_QUIET=1`` every request first tells the hub that an
``EgressBlocked`` is not an error of the hub, which is what an application
does to keep gevent from printing a traceback for each refused name lookup.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

import probe_common
import probe_wsgi  # activates tethered as TETH_ACTIVATE says

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

STDERR = {"pipe": subprocess.PIPE, "stdout": subprocess.STDOUT, "inherit": None}


def _arrangement() -> dict[str, Any]:
    import gevent
    from gevent import monkey

    resolver = type(gevent.get_hub().resolver)
    return {
        **probe_common.whoami(),
        "gevent": gevent.__version__,
        "socket_patched": monkey.is_module_patched("socket"),
        "subprocess_patched": monkey.is_module_patched("subprocess"),
        # After monkey-patching, this is gevent's own Popen, not the standard library's.
        "popen": f"{subprocess.Popen.__module__}.{subprocess.Popen.__qualname__}",
        "resolver": f"{resolver.__module__}.{resolver.__qualname__}",
        "greenlet": type(gevent.getcurrent()).__name__,
    }


def _launch(params: dict[str, str]) -> dict[str, Any]:
    host, port = params["host"], int(params["port"])
    what = params.get("what", "tool")
    if what == "tool":
        argv, popen_args = probe_common.tool_argv(host, port), {}
    else:
        argv, popen_args = probe_common.child_argv(what, host, port)
    done = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=STDERR[params.get("stderr", "pipe")],
        text=True,
        timeout=60,
        check=False,
        **popen_args,
    )
    # Exactly what the application captured, unparsed.
    return {"returncode": done.returncode, "stdout": done.stdout, "stderr": done.stderr}


def _quiet_refusals() -> None:
    import gevent

    import tethered

    hub = gevent.get_hub()
    if tethered.EgressBlocked not in hub.NOT_ERROR:
        hub.NOT_ERROR += (tethered.EgressBlocked,)


def application(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
    """The WSGI callable."""
    if os.environ.get("GEVENT_QUIET"):
        _quiet_refusals()
    route = environ.get("PATH_INFO", "/").strip("/")
    if route not in ("arrangement", "launch"):
        return probe_wsgi.application(environ, start_response)
    params = dict(parse_qsl(environ.get("QUERY_STRING", "")))
    if route == "arrangement":
        report = _arrangement()
    else:
        report = {"op": "launch", **probe_common.whoami()}
        try:
            report.update(_launch(params), outcome="reached")
        except Exception as exc:
            report.update(probe_common.describe_failure(exc))
    probe_common.hold(params)
    body = json.dumps(report).encode()
    start_response(
        "200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
    )
    return [body]
