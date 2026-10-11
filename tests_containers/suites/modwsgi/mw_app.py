"""The WSGI application of the mod_wsgi suite.

A WSGI script of the suite is two lines, written by ``apache.Site.script``:

    import mw_app
    application = mw_app.build("shop", activate="locked")

``build`` does what the WSGI script of a real application does when mod_wsgi
imports it, which is to call ``tethered.activate()``, and returns the
application.  The settings are arguments and not environment variables as in
``probe_wsgi``: under mod_wsgi several applications share one process, each in
an interpreter of its own, and the environment is the one thing they share.

The routes are those of ``probe_wsgi`` (``/connect``, ``/urllib``, ``/child``,
``/tool``, ``/whoami``, with ``uncaught`` and ``hold``), reported the same way
through ``probe_common``, and four more:

    /activate     call tethered.activate() again from a handler
                  (policy=same: the arguments of the script; policy=other: another allow list)
    /deactivate   call tethered.deactivate()
    /uvloop       import uvloop and connect to host:port on a uvloop event loop
    /fork_exec    os.fork(), then os.execve() of sys.executable with an environment
                  that lacks the policy variable; the child tries host:port

Every report says which application, application group, process and
interpreter answered, and what ``activate()`` did when the script was imported.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

import probe_common

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    Operation = Callable[[str, int, dict[str, str]], dict[str, Any]]

#: What a script allows unless it says otherwise: the allow list of the shared applications.
DEFAULT_ALLOW = (probe_common.DEFAULT_ALLOW,)
#: The allow list ``/activate?policy=other`` asks for.
OTHER_ALLOW = ("other.test:9003",)


def _interpreters() -> Any:
    try:
        import _interpreters  # Python 3.13+

        return _interpreters
    except ImportError:
        import _xxsubinterpreters  # Python 3.11 and 3.12

        return _xxsubinterpreters


def _interpreter_id(found: Any) -> int:
    return int(found[0] if isinstance(found, tuple) else found)


def interpreter_ids() -> tuple[int, int, int]:
    """The interpreter this runs in, the main interpreter, and how many there are."""
    module = _interpreters()
    return (
        _interpreter_id(module.get_current()),
        _interpreter_id(module.get_main()),
        len(module.list_all()),
    )


def tethered_state() -> dict[str, bool]:
    """Whether tethered is imported and holds a policy in this interpreter, right now."""
    core = sys.modules.get("tethered._core")
    config = getattr(core, "_config", None)
    return {
        "tethered_imported": core is not None,
        "active": config is not None,
        "locked": bool(config is not None and config.locked),
    }


def _holds_lock() -> bool | None:
    """Whether this interpreter is the one that took the lock of the process.

    The C extension's own answer, which tells the holder from an interpreter
    that joined: both have a locked policy.  ``None`` where tethered is not
    imported.  Like ``whoami()["locked"]`` it reads tethered's internals.
    """
    core = sys.modules.get("tethered._core")
    guardian = getattr(core, "_c_guardian", None)
    try:
        return bool(guardian.holds_lock()) if guardian is not None else None
    except Exception:
        return None


def _log(name: str, text: str) -> None:
    current, _main, _count = interpreter_ids()
    line = f"mw_app: {name}: {text} (interpreter {current} of process {os.getpid()})"
    print(line, file=sys.stderr, flush=True)


def _activation_arguments(activate: str, allow: Iterable[str], esp: str | None) -> dict[str, Any]:
    flags = {flag.strip() for flag in activate.split(",")}
    unknown = flags - set(probe_common.ACTIVATE_FLAGS)
    if unknown:
        raise RuntimeError(f"activate={activate!r}: unknown {sorted(unknown)}")
    if "none" in flags:
        return {}
    arguments: dict[str, Any] = {"allow": list(allow)}
    if "locked" in flags:
        arguments.update(locked=True, lock_token=object())
    if "fail_closed" in flags:
        arguments["fail_closed"] = True
    if "log_only" in flags:
        arguments["log_only"] = True
    if esp:
        arguments["external_subprocess_policy"] = esp
    return arguments


def _wait_for_interpreters(wanted: int, timeout: float = 20.0) -> dict[str, Any]:
    """Wait until the process has ``wanted`` interpreters; says how many it ended with.

    This is how a test makes two first requests overlap for certain: mod_wsgi
    creates the interpreter of an application group before it imports the
    group's script, and imports one script at a time.  A script that waits
    here does not go on to ``activate()`` before the other group's
    interpreter exists as well.
    """
    deadline = time.monotonic() + timeout
    while True:
        seen = interpreter_ids()[2]
        if seen >= wanted or time.monotonic() >= deadline:
            return {"wanted": wanted, "seen": seen}
        time.sleep(0.01)


def build(
    name: str,
    *,
    activate: str = "none",
    allow: Iterable[str] = DEFAULT_ALLOW,
    esp: str | None = None,
    catch: bool = True,
    wait_for_interpreters: int = 0,
    import_first: Iterable[str] = (),
) -> Callable[..., Iterable[bytes]]:
    """Activate tethered as told and return the WSGI application.

    ``activate`` takes the values of ``TETH_ACTIVATE`` (``none``, ``plain``,
    ``locked``, ``fail_closed``, ``log_only``, joined by commas), ``allow``
    the allow list and ``esp`` the ``external_subprocess_policy``.  With
    ``catch=False`` an exception of ``activate()`` leaves the script, as it
    does in an application that expects none.  ``wait_for_interpreters`` and
    ``import_first`` (modules to import before activating) arrange the
    situations the tests are about.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="LOG pid=%(process)d %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    boot: dict[str, Any] = {
        "app": name,
        "imported_in_interpreter": interpreter_ids()[0],
        # What this interpreter had before the script ran: a policy here was
        # put in place when the interpreter started, by tethered's bootstrap.
        "at_startup": tethered_state(),
    }
    _log(name, f"script imported, activate={activate}")
    if wait_for_interpreters:
        boot["waited"] = _wait_for_interpreters(wait_for_interpreters)
    for module in import_first:
        __import__(module)
    arguments = _activation_arguments(activate, allow, esp)
    if not arguments:
        boot["activation"] = {"outcome": "not asked"}
    else:
        import tethered

        try:
            tethered.activate(**arguments)
        except Exception as exc:
            boot["activation"] = {**probe_common.describe_failure(exc), "outcome": "raised"}
            _log(name, f"activate() raised {type(exc).__name__}")
            if not catch:
                raise
        else:
            boot["activation"] = {"outcome": "activated"}
            _log(name, "activate() returned")

    def whoami(environ: dict[str, Any]) -> dict[str, Any]:
        running_in, main_now, count = interpreter_ids()
        return {
            **probe_common.whoami(),
            **boot,
            "group": environ.get("mod_wsgi.application_group"),
            "process_group": environ.get("mod_wsgi.process_group"),
            "main_interpreter": running_in == main_now,
            "interpreters": count,
            "holds_lock": _holds_lock(),
            "prefix": sys.prefix,
        }

    def again(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
        import tethered

        policy = params.get("policy", "same")
        if policy == "same":
            tethered.activate(**_activation_arguments(activate, allow, esp))
        elif policy == "other":
            tethered.activate(**_activation_arguments(activate, OTHER_ALLOW, esp))
        else:
            raise ValueError(f"policy={policy!r}: same or other")
        return {"policy": policy}

    operations: dict[str, Operation] = {**OPERATIONS, "activate": again}

    def application(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        op = environ.get("PATH_INFO", "/").strip("/")
        params = dict(parse_qsl(environ.get("QUERY_STRING", "")))
        status = "200 OK"
        if op == "whoami":
            report = whoami(environ)
        elif op in operations:
            host, port = params.get("host", ""), int(params.get("port", "0"))
            report = {"op": op, "host": host, "port": port, **whoami(environ)}
            if params.get("uncaught"):
                report.update(operations[op](host, port, params), outcome="reached")
            else:
                try:
                    report.update(operations[op](host, port, params), outcome="reached")
                except Exception as exc:
                    report.update(probe_common.describe_failure(exc))
            # The state of tethered after the operation, for the ones that change it.
            report.update(tethered_state())
        else:
            status = "404 Not Found"
            report = {"error": f"no such route: /{op}", "pid": os.getpid()}
        probe_common.hold(params)
        body = json.dumps(report).encode()
        start_response(
            status, [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
        )
        return [body]

    return application


# ── The operations ────────────────────────────────────────────────────


def _connect(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    return probe_common.tcp_connect(host, port)


def _urllib(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    return probe_common.urllib_get(host, port)


def _child(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    argv, popen_args = probe_common.child_argv(params.get("how", "executable"), host, port)
    return probe_common.launch(argv, **popen_args)


def _tool(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    return probe_common.launch(probe_common.tool_argv(host, port))


def _deactivate(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    import tethered

    tethered.deactivate()
    return {}


def _uvloop(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    """Import uvloop and make one connection on a uvloop event loop.

    Nothing that goes through a uvloop event loop raises an audit event, so
    this connection is one tethered cannot see.  Under a policy the import is
    refused; ``import_only=1`` stops after it.
    """
    import asyncio

    import uvloop

    if params.get("import_only"):
        return {"uvloop": uvloop.__version__}

    async def connect() -> bytes:
        reader, writer = await asyncio.open_connection(host, port)
        writer.write(probe_common.REQUEST)
        await writer.drain()
        data = await reader.read()
        writer.close()
        return data

    loop = uvloop.new_event_loop()
    try:
        data = loop.run_until_complete(asyncio.wait_for(connect(), 5.0))
    finally:
        loop.close()
    return {"loop": f"{type(loop).__module__}.{type(loop).__qualname__}", "reply": _last(data)}


def _last(data: bytes) -> str:
    return probe_common.last_line(data)


def _fork_exec(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    """Fork, and in the child ``os.execve`` this Python with an environment of our own making.

    The environment lacks tethered's policy variable.  The child is
    ``probe_child.py``, which reports the policy it started with and tries
    ``host:port``.  A refusal of the exec is raised in the forked child and
    comes back as ``{"exec_failed": ...}``.
    """
    read_end, write_end = os.pipe()
    argv = [sys.executable, probe_common.CHILD_SCRIPT, host, str(port)]
    environment = {"PATH": os.environ.get("PATH", "")}
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read_end)
            os.dup2(write_end, 1)
            os.execve(sys.executable, argv, environment)
        except BaseException as exc:
            failure = {"exec_failed": probe_common.describe_failure(exc)}
            os.write(1, json.dumps(failure).encode())
        finally:
            os._exit(70)
    os.close(write_end)
    with os.fdopen(read_end, encoding="utf-8", errors="replace") as pipe:
        output = pipe.read()
    _pid, status = os.waitpid(pid, 0)
    return probe_common.launch_report(os.waitstatus_to_exitcode(status), output, "")


OPERATIONS: dict[str, Operation] = {
    "connect": _connect,
    "urllib": _urllib,
    "child": _child,
    "tool": _tool,
    "deactivate": _deactivate,
    "uvloop": _uvloop,
    "fork_exec": _fork_exec,
}
