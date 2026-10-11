"""An ASGI probe application that goes out through Twisted's own API: ``probe_twisted:app``.

daphne is a Twisted server: it runs Twisted's reactor on an asyncio event
loop, and the application's coroutines on that loop.  ``probe_asgi``
(``harness/apps``) covers what an application does with asyncio there.  This
one covers the other half: a handler that uses the reactor it is running on,
the way Twisted code does.  tethered is activated when ``probe_asgi`` is
imported, as ``TETH_ACTIVATE`` says.  Every route but ``/whoami`` takes
``host`` and ``port``:

    /connect_tcp     reactor.connectTCP(host, port, factory, timeout=...)
    /endpoint        HostnameEndpoint(reactor, host, port).connect(factory)
    /agent           twisted.web.client.Agent: GET http://host:port/
    /resolve         reactor.resolve(host), no connection
    /udp_write       reactor.listenUDP(0, protocol), transport.write(data, (host, port))
    /spawn_tool      reactor.spawnProcess: an external tool (bash) that connects itself
    /spawn_child     reactor.spawnProcess: a Python child that tries host:port and reports
                     (env=inherit, the default here, or env=empty, which is Twisted's default)
    /whoami          process, event loop class, reactor class and the state of tethered

Twisted is given ``CONNECT_TIMEOUT`` seconds for a connection attempt, and
the handler itself waits ``patience=<seconds>`` (4 by default) for Twisted to
come back with anything at all.  A report has one field more than those of
``probe_asgi``: ``seconds``, how long the operation took.  A refusal that
Twisted does not hand to its caller shows there: as a ``TimeoutError`` of
Twisted's after ``CONNECT_TIMEOUT``, or as the handler running out of patience.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

import probe_asgi
import probe_common
from twisted.internet import defer, protocol
from twisted.internet.endpoints import HostnameEndpoint
from twisted.web.client import Agent, readBody

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

#: The timeout handed to Twisted for a connection attempt, in seconds.
CONNECT_TIMEOUT = 1.0
#: How long a handler waits for Twisted before it gives up itself, unless ``patience`` says.
PATIENCE = 4.0


def _reactor() -> Any:
    # Imported when it is used: daphne has installed the asyncio reactor by then.
    from twisted.internet import reactor

    return reactor


async def _wait(deferred: defer.Deferred[Any], params: dict[str, str]) -> Any:
    patience = float(params.get("patience", PATIENCE))
    return await asyncio.wait_for(deferred.asFuture(asyncio.get_running_loop()), patience)


class _Collect(protocol.Protocol):
    """Sends one request and collects the answer until the peer closes."""

    def __init__(self) -> None:
        self.data = b""
        self.done: defer.Deferred[bytes] = defer.Deferred()

    def connectionMade(self) -> None:
        """Send the request."""
        self.transport.write(probe_common.REQUEST)

    def dataReceived(self, data: bytes) -> None:
        """Collect the answer."""
        self.data += data

    def connectionLost(self, reason: Any = None) -> None:
        """Hand over what was collected."""
        if not self.done.called:
            self.done.callback(self.data)


class _CollectFactory(protocol.ClientFactory):
    """Builds one ``_Collect`` and fails its deferred when the connection is not made."""

    def __init__(self) -> None:
        self.collector = _Collect()

    def buildProtocol(self, addr: Any) -> _Collect:
        """Return the one protocol."""
        return self.collector

    def clientConnectionFailed(self, connector: Any, reason: Any) -> None:
        """Pass the failure on to whoever waits for the answer."""
        if not self.collector.done.called:
            self.collector.done.errback(reason)


async def _connect_tcp(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    factory = _CollectFactory()
    _reactor().connectTCP(host, port, factory, timeout=CONNECT_TIMEOUT)
    return {"reply": probe_common.last_line(await _wait(factory.collector.done, params))}


async def _endpoint(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    endpoint = HostnameEndpoint(_reactor(), host, port, timeout=CONNECT_TIMEOUT)
    collector = await _wait(endpoint.connect(protocol.Factory.forProtocol(_Collect)), params)
    return {"reply": probe_common.last_line(await _wait(collector.done, params))}


async def _agent(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    agent = Agent(_reactor(), connectTimeout=CONNECT_TIMEOUT)
    response = await _wait(agent.request(b"GET", f"http://{host}:{port}/".encode()), params)
    body = await _wait(readBody(response), params)
    return {"status": response.code, "reply": probe_common.last_line(body)}


async def _resolve(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    found = await _wait(_reactor().resolve(host, timeout=(CONNECT_TIMEOUT,)), params)
    return {"addresses": [found]}


class _OneDatagram(protocol.DatagramProtocol):
    """Waits for one datagram."""

    def __init__(self) -> None:
        self.answer: defer.Deferred[bytes] = defer.Deferred()

    def datagramReceived(self, datagram: bytes, addr: Any) -> None:
        """Hand over the datagram."""
        if not self.answer.called:
            self.answer.callback(datagram)


async def _udp_write(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    receiver = _OneDatagram()
    listening = _reactor().listenUDP(0, receiver)
    try:
        listening.write(b"ping", (host, port))
        data = await asyncio.wait_for(receiver.answer.asFuture(asyncio.get_running_loop()), 2.0)
    finally:
        listening.stopListening()
    return {"reply": probe_common.last_line(data)}


class _Output(protocol.ProcessProtocol):
    """Collects what a process prints, until it ends."""

    def __init__(self) -> None:
        self.out = b""
        self.err = b""
        self.ended: defer.Deferred[int | None] = defer.Deferred()

    def outReceived(self, data: bytes) -> None:
        """Collect stdout."""
        self.out += data

    def errReceived(self, data: bytes) -> None:
        """Collect stderr."""
        self.err += data

    def processEnded(self, reason: Any) -> None:
        """Hand over the exit status."""
        self.ended.callback(reason.value.exitCode)


async def _spawn(argv: list[str], params: dict[str, str]) -> dict[str, Any]:
    # For spawnProcess, env=None means "inherit" and its default, {}, an empty environment.
    env = {} if params.get("env") == "empty" else None
    output = _Output()
    _reactor().spawnProcess(output, argv[0], argv, env=env)
    returncode = await _wait(output.ended, params)
    return probe_common.launch_report(returncode, output.out.decode(), output.err.decode())


async def _spawn_tool(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    return await _spawn(probe_common.tool_argv(host, port), params)


async def _spawn_child(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    argv, _ = probe_common.child_argv("executable", host, port)
    return await _spawn(argv, params)


OPERATIONS: dict[str, Callable[[str, int, dict[str, str]], Awaitable[dict[str, Any]]]] = {
    "connect_tcp": _connect_tcp,
    "endpoint": _endpoint,
    "agent": _agent,
    "resolve": _resolve,
    "udp_write": _udp_write,
    "spawn_tool": _spawn_tool,
    "spawn_child": _spawn_child,
}


async def app(scope: dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
    """The ASGI callable."""
    if scope["type"] != "http":
        return
    op = scope["path"].strip("/")
    params = dict(parse_qsl(scope["query_string"].decode()))
    loop = probe_asgi._loop_name()
    status = 200
    if op == "whoami":
        report = probe_common.whoami(loop)
        report["reactor"] = f"{type(_reactor()).__module__}.{type(_reactor()).__qualname__}"
    elif op in OPERATIONS:
        host, port = params["host"], int(params["port"])
        report = {"op": op, "host": host, "port": port, **probe_common.whoami(loop)}
        started = time.monotonic()
        try:
            report.update(await OPERATIONS[op](host, port, params), outcome="reached")
        except Exception as exc:
            report.update(probe_common.describe_failure(exc))
        report["seconds"] = round(time.monotonic() - started, 2)
    else:
        status = 404
        report = {"error": f"no such route: /{op}", "pid": probe_common.whoami()["pid"]}
    await probe_asgi._respond(send, status, report)
