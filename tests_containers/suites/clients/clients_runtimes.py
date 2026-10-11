"""Other runtimes: trio, anyio, gevent and eventlet with monkey-patching, Twisted.

For gevent and eventlet, ``client_case`` has patched the standard library
before the policy was activated and before this module is imported, the order
a gevent or eventlet worker has.  The client is then the standard library's
``urllib.request``, running on green sockets.
"""

from __future__ import annotations

import urllib.request
from typing import TYPE_CHECKING, Any

from client_case import note

if TYPE_CHECKING:
    from collections.abc import Callable

#: Long enough for a lookup and a connection on a busy machine.
TIMEOUT = 5.0
REQUEST = b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n"
#: Twisted's connection timeout.  A refusal by tethered ends a Twisted
#: connection attempt only through this timeout, so it is waited out.
REFUSAL_TIMEOUT = 1.0
#: How long the reactor is given before the attempt counts as one that never ends.
NEVER = 2.5


class NeverFinished(Exception):
    """The library neither finished nor failed: its caller would wait for ever."""


def _urlopen(host: str, port: int) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"http://{host}:{port}/", timeout=TIMEOUT) as reply:
        reply.read()


# ── trio, anyio ───────────────────────────────────────────────────────


def trio_open_tcp_stream(host: str, port: int) -> None:
    import trio

    async def go() -> None:
        with trio.fail_after(TIMEOUT):
            async with await trio.open_tcp_stream(host, port) as stream:
                await stream.send_all(REQUEST)
                while await stream.receive_some(4096):
                    pass

    trio.run(go)


async def _anyio_connect(host: str, port: int) -> None:
    import anyio

    with anyio.fail_after(TIMEOUT):
        async with await anyio.connect_tcp(host, port) as stream:
            await stream.send(REQUEST)
            await stream.receive(4096)


def anyio_on_asyncio(host: str, port: int) -> None:
    import anyio

    anyio.run(_anyio_connect, host, port, backend="asyncio")


def anyio_on_trio(host: str, port: int) -> None:
    import anyio

    anyio.run(_anyio_connect, host, port, backend="trio")


# ── gevent, eventlet ──────────────────────────────────────────────────


def gevent_urlopen(host: str, port: int) -> None:
    import socket

    import gevent

    note(resolver=type(gevent.get_hub().resolver).__module__, socket=socket.socket.__module__)
    _urlopen(host, port)


def eventlet_urlopen(host: str, port: int) -> None:
    import socket

    note(getaddrinfo=socket.getaddrinfo.__module__, socket=socket.socket.__module__)
    _urlopen(host, port)


# ── Twisted ───────────────────────────────────────────────────────────


def _run_reactor(start: Callable[[], Any]) -> None:
    """Run the reactor until the Deferred ``start()`` returns has fired; raise its failure."""
    from twisted.internet import reactor
    from twisted.python.failure import Failure

    outcome: list[object] = []

    def finish(result: object) -> None:
        outcome.append(result)
        reactor.stop()

    def begin() -> None:
        start().addBoth(finish)

    reactor.callWhenRunning(begin)
    reactor.callLater(NEVER, reactor.stop)
    reactor.run()
    if not outcome:
        raise NeverFinished(f"the Deferred had not fired after {NEVER} s")
    if isinstance(outcome[0], Failure):
        outcome[0].raiseException()


def twisted_connect_tcp(host: str, port: int) -> None:
    """``reactor.connectTCP``, through the endpoint that wraps it."""
    from twisted.internet import defer, reactor
    from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
    from twisted.internet.protocol import Protocol

    class Once(Protocol):
        def __init__(self) -> None:
            self.closed: defer.Deferred = defer.Deferred()

        def connectionMade(self) -> None:
            self.transport.write(REQUEST)

        def connectionLost(self, reason: object = None) -> None:
            self.closed.callback(None)

    def start() -> defer.Deferred:
        note(resolver=type(reactor.resolver).__name__)
        endpoint = TCP4ClientEndpoint(reactor, host, port, timeout=REFUSAL_TIMEOUT)
        return connectProtocol(endpoint, Once()).addCallback(lambda protocol: protocol.closed)

    _run_reactor(start)


def twisted_agent(host: str, port: int) -> None:
    """``twisted.web.client.Agent``, which connects through ``HostnameEndpoint``."""
    from twisted.internet import defer, reactor
    from twisted.web.client import Agent, readBody

    def start() -> defer.Deferred:
        note(name_resolver=type(reactor.nameResolver).__name__)
        agent = Agent(reactor, connectTimeout=REFUSAL_TIMEOUT)
        return agent.request(b"GET", f"http://{host}:{port}/".encode()).addCallback(readBody)

    _run_reactor(start)
