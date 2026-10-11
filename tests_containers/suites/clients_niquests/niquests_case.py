"""One niquests request, in a process of its own.

    niquests_case.main()  with  sys.argv = [script, RESOLVER, HOST, PORT]

``test_niquests.py`` starts this through ``harness.run_python``, so the policy
the test asked for is in place before the first line here runs.  ``RESOLVER``
is ``system`` (niquests' default: the operating system's resolver) or a
resolver URL of urllib3-future such as ``dou://127.0.0.1`` (DNS over UDP, made
by the library itself).  The process prints one line of JSON: how the request
ended for its caller and, in a run without tethered, the ``socket.*`` audit
events the library raised.
"""

from __future__ import annotations

import json
import sys
from typing import Any

TIMEOUT = 5.0


def _text(value: Any) -> str:
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("latin-1")
    return str(value)


def _describe(event: str, args: tuple[Any, ...]) -> str:
    name = event.partition(".")[2]
    if event in ("socket.getaddrinfo", "socket.gethostbyname"):
        return f"{name}({_text(args[0])})"
    if event in ("socket.connect", "socket.sendto"):
        address = args[1]
        if isinstance(address, tuple) and len(address) >= 2:
            return f"{name}({_text(address[0])}:{address[1]})"
    return name


def record_events() -> list[str]:
    """Install an audit hook that lists the ``socket.*`` events of this process."""
    events: list[str] = []

    def hook(event: str, args: tuple[Any, ...]) -> None:
        try:
            if event.startswith("socket.") and event != "socket.__new__" and len(events) < 60:
                described = _describe(event, args)
                if not events or events[-1] != described:
                    events.append(described)
        except Exception:  # a recording hook must never change what the library does
            return

    sys.addaudithook(hook)
    return events


def _related(exc: BaseException, seen: set[int]) -> list[BaseException]:
    if id(exc) in seen:
        return []
    seen.add(id(exc))
    found = [exc]
    for other in (exc.__cause__, exc.__context__, *getattr(exc, "exceptions", ())):
        if isinstance(other, BaseException):
            found += _related(other, seen)
    return found


def describe_failure(exc: BaseException) -> dict[str, Any]:
    """How a failed request looked to the caller, and whether tethered's refusal is in it."""
    related = _related(exc, set())
    refusals = [one for one in related if type(one).__name__ == "EgressBlocked"]
    if refusals and refusals[0] is exc:
        surface = "raised"
    elif refusals:
        surface = "chained"
    elif any("Blocked by tethered" in str(one) for one in related):
        surface = "message"
    else:
        surface = "hidden"
    return {
        "outcome": "error" if surface == "hidden" else "blocked",
        "surface": surface,
        "exception": f"{type(exc).__module__}.{type(exc).__qualname__}",
        "message": str(exc)[:600],
        "chain": [f"{type(one).__module__}.{type(one).__qualname__}" for one in related[1:]][:8],
    }


def main() -> None:
    """Make the one request and print the report."""
    resolver, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    events = record_events() if "tethered" not in sys.modules else None
    report: dict[str, Any] = {"resolver": resolver, "host": host, "port": port}
    try:
        import niquests
        import urllib3

        report["urllib3"] = f"{urllib3.__version__} at {urllib3.__file__}"
        options = {} if resolver == "system" else {"resolver": resolver}
        with niquests.Session(retries=0, **options) as session:
            session.trust_env = False
            session.get(f"http://{host}:{port}/", timeout=TIMEOUT)
        report.update(outcome="completed", surface="no exception")
    except BaseException as exc:
        report.update(describe_failure(exc))
    if events is not None:
        report["events"] = events
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
