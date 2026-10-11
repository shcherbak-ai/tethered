"""Print the audit events of outbound networking and of process launches.

This has nothing to do with tethered: it is the evidence of what an audit
hook can see at all under an event loop.  tethered acts on these events and
on nothing else, so an operation that prints no line here cannot be refused
by it.  One line per event goes to stderr, and so to the server's log:

    AUDIT pid=17 socket.getaddrinfo forbidden.test:9002
    AUDIT pid=17 socket.connect 10.77.0.20:9002
    AUDIT pid=17 subprocess.Popen bash

Use it through a module that calls ``install()`` before it imports the
application (``traced_asgi`` and its like), with ``TETH_ACTIVATE=none``.
"""

from __future__ import annotations

import os
import sys
from typing import Any

EVENTS = frozenset(
    {
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyaddr",
        "socket.connect",
        "socket.sendto",
        "socket.sendmsg",
        "subprocess.Popen",
        "os.posix_spawn",
        "os.exec",
        "os.fork",
        "os.system",
    }
)


def _text(value: Any) -> str:
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("latin-1")
    return str(value)


def _detail(event: str, args: tuple[Any, ...]) -> str:
    if event == "socket.getaddrinfo":
        return f"{_text(args[0])}:{_text(args[1])}"
    if event in ("socket.connect", "socket.sendto", "socket.sendmsg"):
        address = args[1]
        if isinstance(address, tuple) and len(address) >= 2:
            return f"{_text(address[0])}:{address[1]}"
        return _text(address)
    return _text(args[0]) if args else "-"


def _hook(event: str, args: tuple[Any, ...]) -> None:
    if event in EVENTS:
        try:
            line = f"AUDIT pid={os.getpid()} {event} {_detail(event, args)}\n"
        except Exception as error:  # an audit hook must not raise
            line = f"AUDIT pid={os.getpid()} {event} ?? {error!r}\n"
        sys.stderr.write(line)
        sys.stderr.flush()


def install() -> None:
    """Add the hook to this process.  It cannot be removed, like every audit hook."""
    sys.addaudithook(_hook)
