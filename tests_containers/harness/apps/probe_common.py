"""What the probe applications share: activation, reports, the blocking operations, launches.

A probe application does exactly one outbound operation per request and
reports it as JSON:

    {"op": "connect", "host": "forbidden.test", "port": 9002, "pid": 17,
     "outcome": "blocked",
     "exception": "tethered._core.EgressBlocked",
     "message": "Blocked by tethered: forbidden.test:9002 is not in the allow list"}

``outcome`` is ``reached`` (the operation was carried out), ``blocked``
(tethered refused it: the exception is ``EgressBlocked`` or
``SubprocessBlocked``, or contains one) or ``error`` (anything else).  The
report is what the application saw; what really happened is in the world's
counters, and the tests assert both.

The modules in this directory are on ``PYTHONPATH`` of every process the
harness starts.  They never import the ``harness`` package.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from typing import Any

#: What every probe application allows, unless ``TETH_ALLOW`` says otherwise.
DEFAULT_ALLOW = "allowed.test:9001"
ACTIVATE_FLAGS = ("none", "plain", "locked", "fail_closed", "log_only")
REQUEST = b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n"
CHILD_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probe_child.py")
#: The process in which this module was imported: the master, under a preloading server.
IMPORTED_IN_PID = os.getpid()
#: The external tool: bash makes the connection itself ($0 is the host, $1 the port).
TOOL = 'exec 3<>"/dev/tcp/$0/$1" && printf "GET / HTTP/1.0\\r\\n\\r\\n" >&3 && tail -n 1 <&3'


def activate_from_env() -> None:
    """Activate tethered as the environment says; called when an application is imported.

    ``TETH_ACTIVATE`` (required): ``none`` leaves tethered unimported;
    ``plain`` activates the allow list; ``locked``, ``fail_closed`` and
    ``log_only`` add that argument, and can be combined with commas.
    ``TETH_ESP``: ``external_subprocess_policy`` (``warn``, ``block``, ``allow``).
    ``TETH_ALLOW``: the allow list, comma-separated (``allowed.test:9001``).
    """
    logging.basicConfig(
        level=logging.INFO,
        format="LOG pid=%(process)d %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    setting = os.environ.get("TETH_ACTIVATE")
    if setting is None:
        raise RuntimeError("TETH_ACTIVATE is not set: " + ", ".join(ACTIVATE_FLAGS))
    flags = {flag.strip() for flag in setting.split(",")}
    unknown = flags - set(ACTIVATE_FLAGS)
    if unknown:
        raise RuntimeError(f"TETH_ACTIVATE={setting!r}: unknown {sorted(unknown)}")
    if "none" in flags:
        return

    import tethered

    kwargs: dict[str, Any] = {"allow": os.environ.get("TETH_ALLOW", DEFAULT_ALLOW).split(",")}
    if "locked" in flags:
        kwargs.update(locked=True, lock_token=object())
    if "fail_closed" in flags:
        kwargs["fail_closed"] = True
    if "log_only" in flags:
        kwargs["log_only"] = True
    if os.environ.get("TETH_ESP"):
        kwargs["external_subprocess_policy"] = os.environ["TETH_ESP"]
    tethered.activate(**kwargs)
    print(f"probe: pid {os.getpid()} activated tethered ({setting})", file=sys.stderr, flush=True)


# ── Reports ───────────────────────────────────────────────────────────


def _type_name(exc: BaseException) -> str:
    return f"{type(exc).__module__}.{type(exc).__qualname__}"


def _refusal(exc: BaseException) -> BaseException | None:
    """``exc`` if tethered raised it, or the first such exception inside an exception group."""
    tethered = sys.modules.get("tethered")
    if tethered is None:
        return None
    if isinstance(exc, tethered.EgressBlocked | tethered.SubprocessBlocked):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        for inner in exc.exceptions:
            found = _refusal(inner)
            if found is not None:
                return found
    return None


def describe_failure(exc: BaseException) -> dict[str, Any]:
    """The report fields for an operation that raised."""
    refusal = _refusal(exc)
    report: dict[str, Any] = {
        "outcome": "blocked" if refusal is not None else "error",
        "exception": _type_name(exc),
        "message": str(exc),
    }
    if refusal is not None and refusal is not exc:
        # A refusal delivered inside an exception group: say what it was.
        report["refusal"] = {"exception": _type_name(refusal), "message": str(refusal)}
    notes = getattr(exc, "__notes__", None)
    if notes:
        report["notes"] = list(notes)
    return report


def last_line(data: bytes) -> str:
    """The last line of what a destination answered: ``reached 10.77.0.10:9001``."""
    lines = data.decode("latin-1").strip().splitlines()
    return lines[-1] if lines else ""


def _interpreter_id() -> int | None:
    try:
        import _interpreters  # Python 3.13+

        current = _interpreters.get_current()
        return int(current[0] if isinstance(current, tuple) else current)
    except Exception:
        pass
    try:
        import _xxsubinterpreters  # Python 3.11 and 3.12

        return int(_xxsubinterpreters.get_current())
    except Exception:
        return None


def whoami(loop: str | None = None) -> dict[str, Any]:
    """Who is answering: process, thread, interpreter, event loop, and the state of tethered."""
    core = sys.modules.get("tethered._core")
    config = getattr(core, "_config", None)
    return {
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "imported_in_pid": IMPORTED_IN_PID,
        "thread": threading.current_thread().name,
        "interpreter": _interpreter_id(),
        "loop": loop,
        "executable": sys.executable,
        "tethered_imported": core is not None,
        "active": config is not None,
        "locked": bool(config is not None and config.locked),
        "log_only": bool(config is not None and config.log_only),
        "fail_closed": bool(config is not None and config.fail_closed),
        "external_subprocess_policy": getattr(config, "external_subprocess_policy", None),
        "policy_in_environ": "_TETHERED_CHILD_POLICY" in os.environ,
    }


# ── Blocking operations ───────────────────────────────────────────────


def tcp_connect(host: str, port: int) -> dict[str, Any]:
    """One blocking TCP connection: connect, send a request, read the answer."""
    with socket.create_connection((host, port), timeout=5.0) as sock:
        sock.sendall(REQUEST)
        data = b""
        while chunk := sock.recv(4096):
            data += chunk
    return {"reply": last_line(data)}


def urllib_get(host: str, port: int) -> dict[str, Any]:
    """One request with ``urllib.request``."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"http://{host}:{port}/", timeout=5.0) as reply:
        return {"status": reply.status, "reply": last_line(reply.read())}


def child_argv(how: str, host: str, port: int) -> tuple[list[str], dict[str, Any]]:
    """The command of a Python child that tries ``host:port``, and the ``Popen`` arguments.

    ``how``: ``executable`` (``sys.executable``, the kind that inherits the
    policy), ``clean_env`` (the same with an explicit ``env=`` that lacks the
    policy variable), ``no_site`` (``sys.executable -S``, which skips the
    bootstrap) and ``path_python`` (``python3`` looked up on ``PATH``).
    """
    target = [CHILD_SCRIPT, host, str(port)]
    if how == "executable":
        return [sys.executable, *target], {}
    if how == "clean_env":
        return [sys.executable, *target], {"env": {"PATH": os.environ.get("PATH", "")}}
    if how == "no_site":
        return [sys.executable, "-S", *target], {}
    if how == "path_python":
        return ["python3", *target], {}
    raise ValueError(f"how={how!r}: executable, clean_env, no_site or path_python")


def tool_argv(host: str, port: int) -> list[str]:
    """The command of the external tool that connects to ``host:port`` and prints the answer."""
    return ["bash", "-c", TOOL, host, str(port)]


def launch_report(returncode: int | None, stdout: str, stderr: str) -> dict[str, Any]:
    """The report fields for a launch that went through, with the child's own report if any."""
    report: dict[str, Any] = {"returncode": returncode, "stderr": stderr[-4000:]}
    try:
        report["child"] = json.loads(stdout)
    except ValueError:
        report["stdout"] = stdout[-2000:].strip()
    return report


def launch(argv: list[str], **popen_args: Any) -> dict[str, Any]:
    """Launch a command with ``subprocess.run`` and report what it printed."""
    done = subprocess.run(
        argv, capture_output=True, text=True, timeout=60, check=False, **popen_args
    )
    return launch_report(done.returncode, done.stdout, done.stderr)


def hold(params: dict[str, str]) -> None:
    """Keep this worker busy for ``hold`` seconds, so that its siblings get the next requests."""
    seconds = float(params.get("hold", "0"))
    if seconds > 0:
        time.sleep(seconds)
