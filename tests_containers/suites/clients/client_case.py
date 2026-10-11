"""One client library and one destination, in a process of its own.

    client_case.main()  with  sys.argv = [script, VARIANT, HOST, PORT, TAG]

``measure.py`` starts this through ``harness.run_python``, so the policy the
test asked for is in place before the first line here runs.  The process makes
exactly one attempt to reach ``HOST:PORT`` with the client library the variant
names (``catalog.VARIANTS``) and prints one line of JSON:

    {"variant": "requests", "host": "forbidden.test", "port": 9002,
     "outcome": "blocked", "surface": "raised",
     "exception": "tethered._core.EgressBlocked", "message": "Blocked by tethered: ...",
     "chain": [], "seconds": 0.2, "notes": {}, "policy": "plain"}

``outcome`` is what the caller of the library saw: ``completed`` (the call
returned), ``blocked`` (tethered's refusal reached the caller, see
``surface``) or ``error`` (anything else: the destinations speak HTTP, so a
database or broker client fails its handshake after connecting).  What really
happened is in the world's counters.

In a run without a policy (``TETH_ACTIVATE=none``) an audit hook records what
the library raised, and the report has it as ``events`` (the ``socket.*``
events), ``extensions`` (the extension modules loaded from outside the
standard library) and ``dlopen`` (the libraries ``ctypes`` opened), next to
the ``versions`` of the library's distributions.  That is the evidence of why
tethered does or does not see a library.

The process ends with ``os._exit``: what a library does while the interpreter
shuts down (threads that reconnect, exit handlers) is not measured.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import time
from typing import Any

#: What a client function wants reported besides the outcome (``note()``).
NOTES: dict[str, Any] = {}

_EVENT_LIMIT = 60


def note(**facts: Any) -> None:
    """Add facts about the arrangement to the report: which resolver, which implementation."""
    NOTES.update(facts)


def _text(value: Any) -> str:
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("latin-1")
    return str(value)


def _address(address: Any) -> str:
    if isinstance(address, tuple) and len(address) >= 2:
        return f"{_text(address[0])}:{address[1]}"
    return type(address).__name__


def _describe(event: str, args: tuple[Any, ...]) -> str:
    name = event.partition(".")[2]
    if event in ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr"):
        return f"{name}({_text(args[0])})"
    if event in ("socket.connect", "socket.sendto", "socket.sendmsg", "socket.bind"):
        return f"{name}({_address(args[1])})"
    return name


def record_events() -> dict[str, list[str]]:
    """Install the recording audit hook; returns the lists it fills."""
    recorded: dict[str, list[str]] = {"events": [], "extensions": [], "dlopen": []}

    def hook(event: str, args: tuple[Any, ...]) -> None:
        try:
            if event.startswith("socket."):
                if event == "socket.__new__":
                    return
                events = recorded["events"]
                described = _describe(event, args)
                if len(events) < _EVENT_LIMIT and (not events or events[-1] != described):
                    events.append(described)
            elif event == "import":
                # The second ``import`` event of an extension module carries its file.
                filename = args[1] if len(args) > 1 else None
                if isinstance(filename, str) and "/lib-dynload/" not in filename:
                    recorded["extensions"].append(str(args[0]))
            elif event == "ctypes.dlopen":
                recorded["dlopen"].append(_text(args[0]))
        except Exception:  # a recording hook must never change what the library does
            return

    sys.addaudithook(hook)
    return recorded


def _type_name(exc: BaseException) -> str:
    return f"{type(exc).__module__}.{type(exc).__qualname__}"


def _related(exc: BaseException, seen: set[int]) -> list[BaseException]:
    """``exc`` and everything it was raised from, was raised during, or groups."""
    if id(exc) in seen:
        return []
    seen.add(id(exc))
    found = [exc]
    for other in (exc.__cause__, exc.__context__, *getattr(exc, "exceptions", ())):
        if isinstance(other, BaseException):
            found += _related(other, seen)
    return found


def describe_failure(exc: BaseException) -> dict[str, Any]:
    """How a failed attempt looked to the caller, and whether tethered's refusal is in it."""
    related = _related(exc, set())
    refusals = [one for one in related if type(one).__name__ == "EgressBlocked"]
    text = " | ".join(f"{_type_name(one)}: {one}" for one in related)
    if refusals and refusals[0] is exc:
        surface = "raised"
    elif refusals:
        surface = "chained"
    elif "Blocked by tethered" in text:
        surface = "message"
    elif type(exc).__name__ == "NeverFinished":
        # A client function's own verdict: the library would not have returned.
        surface = "never returns"
    else:
        surface = None
    return {
        "outcome": "blocked" if surface in ("raised", "chained", "message") else "error",
        "surface": surface,
        "exception": _type_name(exc),
        "message": str(exc)[:600],
        "chain": [_type_name(one) for one in related[1:]][:8],
    }


def _versions(packages: tuple[str, ...]) -> dict[str, str]:
    import importlib.metadata

    versions = {}
    for package in packages:
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = "not installed"
    return versions


def _prepare(variant: Any) -> None:
    """What has to happen before the policy and the client: imports made unavailable, patching."""
    for name in variant.without:
        # As if the distribution were not installed: ``import name`` raises ImportError.
        sys.modules[name] = None  # type: ignore[assignment]
    if variant.patch == "gevent":
        from gevent import monkey

        monkey.patch_all()
    elif variant.patch == "eventlet":
        import eventlet

        eventlet.monkey_patch()
    for name in variant.import_first:
        importlib.import_module(name)
    activate = os.environ.get("CLIENT_ACTIVATE_LATER")
    if activate:
        # A monkey-patching runtime patches first and loads the application,
        # with its policy, afterwards: measure.py asked run_python for no policy.
        import probe_common

        os.environ["TETH_ACTIVATE"] = activate
        probe_common.activate_from_env()


def main() -> None:
    """Run the one attempt and print the report."""
    # The fourth argument only tells measure.py that this process exists.
    name, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    import catalog

    variant = catalog.VARIANTS[name]
    report: dict[str, Any] = {"variant": name, "host": host, "port": port}
    policy = os.environ.get("CLIENT_ACTIVATE_LATER") or os.environ["TETH_ACTIVATE"]
    recorded = record_events() if policy == "none" else None
    _prepare(variant)
    module_name, _, function_name = variant.call.partition(":")
    started = time.monotonic()
    try:
        function = getattr(importlib.import_module(module_name), function_name)
        if os.environ.get("CLIENT_LOOKUP_FIRST"):
            # The application looks the name up through Python's socket module
            # before it hands it to the library: the C function, so that a
            # monkey-patched socket.getaddrinfo does not stand in for it.
            import _socket

            _socket.getaddrinfo(host, port)
        function(host, port)
        report.update(outcome="completed", surface=None)
    except BaseException as exc:
        report.update(describe_failure(exc))
    report.update(seconds=round(time.monotonic() - started, 2), notes=NOTES, policy=policy)
    if recorded is not None:
        report.update(recorded, versions=_versions(variant.packages))
    print(json.dumps(report, default=str), flush=True)
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
