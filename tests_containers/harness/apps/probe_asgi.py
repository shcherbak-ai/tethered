"""The ASGI probe application: ``probe_asgi:app``, no framework.

It activates tethered when it is imported, as ``TETH_ACTIVATE`` says (see
``probe_common``).  Every route but ``/whoami`` takes ``host`` and ``port``:

    /open_connection       asyncio.open_connection (streams)
    /create_connection     loop.create_connection with a protocol
    /sock_connect          loop.sock_connect on a non-blocking socket
    /getaddrinfo           loop.getaddrinfo, no connection
    /datagram_connected    create_datagram_endpoint(remote_addr=...), one datagram
    /datagram_unconnected  create_datagram_endpoint(local_addr=...), sendto(data, addr)
    /to_thread             a blocking socket connection in asyncio.to_thread
    /run_in_executor       a blocking socket connection in loop.run_in_executor
    /thread                a blocking socket connection in a thread started for it
    /connect               a blocking socket connection in the event loop itself
    /child                 launch a Python child that tries host:port itself and reports
                           (how=executable|clean_env|no_site|path_python)
    /tool                  launch an external tool (bash) that connects to host:port itself
    /whoami                process, event loop class and the state of tethered

Common parameters: ``uncaught=1`` lets the exception of a failed operation
reach the server instead of reporting it; ``hold=<seconds>`` blocks the event
loop before the answer, so that the other workers get the next requests;
``scope=<rule>,<rule>`` runs the operation inside a ``tethered.scope()`` with
those rules (see ``probe_common.scoped``).

Which event loop this runs on is the server's decision (``/whoami`` reports
its class).  tethered sees these operations on asyncio's own loops only.
"""

from __future__ import annotations

import asyncio
import json
import socket
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

import probe_common

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

probe_common.activate_from_env()

_TIMEOUT = 5.0


def _loop_name() -> str:
    loop = asyncio.get_running_loop()
    return f"{type(loop).__module__}.{type(loop).__qualname__}"


async def _open_connection(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), _TIMEOUT)
    try:
        writer.write(probe_common.REQUEST)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), _TIMEOUT)
    finally:
        writer.close()
    return {"reply": probe_common.last_line(data)}


class _Collect(asyncio.Protocol):
    """Sends one request and collects the answer until the peer closes."""

    def __init__(self) -> None:
        self.data = b""
        self.closed: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    def connection_made(self, transport: Any) -> None:
        transport.write(probe_common.REQUEST)

    def data_received(self, data: bytes) -> None:
        self.data += data

    def connection_lost(self, exc: Exception | None) -> None:
        if not self.closed.done():
            self.closed.set_result(None)


async def _create_connection(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    transport, protocol = await asyncio.wait_for(
        loop.create_connection(_Collect, host, port), _TIMEOUT
    )
    try:
        await asyncio.wait_for(protocol.closed, _TIMEOUT)
    finally:
        transport.close()
    return {"reply": probe_common.last_line(protocol.data)}


async def _sock_connect(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setblocking(False)
        await asyncio.wait_for(loop.sock_connect(sock, (host, port)), _TIMEOUT)
        await loop.sock_sendall(sock, probe_common.REQUEST)
        data = b""
        while chunk := await asyncio.wait_for(loop.sock_recv(sock, 4096), _TIMEOUT):
            data += chunk
    return {"reply": probe_common.last_line(data)}


async def _getaddrinfo(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    found = await asyncio.wait_for(loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), _TIMEOUT)
    return {"addresses": sorted({info[4][0] for info in found})}


class _OneDatagram(asyncio.DatagramProtocol):
    """Waits for one datagram, or for the error that asyncio delivers instead."""

    def __init__(self) -> None:
        self.answer: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr: Any) -> None:
        if not self.answer.done():
            self.answer.set_result(data)

    def _fail(self, exc: Exception, where: str) -> None:
        if not self.answer.done():
            exc.add_note(f"delivered to the protocol's {where}()")
            self.answer.set_exception(exc)

    def error_received(self, exc: Exception) -> None:
        self._fail(exc, "error_received")

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is not None:
            self._fail(exc, "connection_lost")


async def _datagram_connected(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    transport, protocol = await asyncio.wait_for(
        loop.create_datagram_endpoint(_OneDatagram, remote_addr=(host, port)), _TIMEOUT
    )
    try:
        transport.sendto(b"ping")
        data = await asyncio.wait_for(protocol.answer, 2.0)
    finally:
        transport.close()
    return {"reply": probe_common.last_line(data)}


async def _datagram_unconnected(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    transport, protocol = await asyncio.wait_for(
        loop.create_datagram_endpoint(_OneDatagram, local_addr=("0.0.0.0", 0)), _TIMEOUT
    )
    try:
        transport.sendto(b"ping", (host, port))
        data = await asyncio.wait_for(protocol.answer, 2.0)
    finally:
        transport.close()
    return {"reply": probe_common.last_line(data)}


async def _to_thread(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    return await asyncio.to_thread(probe_common.tcp_connect, host, port)


async def _run_in_executor(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, probe_common.tcp_connect, host, port)


async def _thread(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    return probe_common.connect_in_thread(host, port)


async def _connect(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    return probe_common.tcp_connect(host, port)


async def _launch(argv: list[str], **popen_args: Any) -> dict[str, Any]:
    process = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, **popen_args
    )
    stdout, stderr = await asyncio.wait_for(process.communicate(), 60.0)
    return probe_common.launch_report(process.returncode, stdout.decode(), stderr.decode())


async def _child(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    argv, popen_args = probe_common.child_argv(params.get("how", "executable"), host, port)
    return await _launch(argv, **popen_args)


async def _tool(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    return await _launch(probe_common.tool_argv(host, port))


OPERATIONS: dict[str, Callable[[str, int, dict[str, str]], Awaitable[dict[str, Any]]]] = {
    "open_connection": _open_connection,
    "create_connection": _create_connection,
    "sock_connect": _sock_connect,
    "getaddrinfo": _getaddrinfo,
    "datagram_connected": _datagram_connected,
    "datagram_unconnected": _datagram_unconnected,
    "to_thread": _to_thread,
    "run_in_executor": _run_in_executor,
    "thread": _thread,
    "connect": _connect,
    "child": _child,
    "tool": _tool,
}


async def _run_scoped(
    op: str, host: str, port: int, params: dict[str, str], report: dict[str, Any]
) -> dict[str, Any]:
    """The asynchronous counterpart of ``probe_common.run_scoped``: the wait does not block."""
    wait = float(params.get("scope_wait", "0"))
    with probe_common.scoped(params):
        if not wait:
            return await OPERATIONS[op](host, port, params)
        report["scope_entered"] = time.time()
        try:
            await asyncio.sleep(wait)
            return await OPERATIONS[op](host, port, params)
        finally:
            report["scope_left"] = time.time()


async def _respond(send: Callable[..., Awaitable[None]], status: int, report: dict) -> None:
    body = json.dumps(report).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


async def app(scope: dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
    """The ASGI callable."""
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    if scope["type"] != "http":
        return
    op = scope["path"].strip("/")
    params = dict(parse_qsl(scope["query_string"].decode()))
    status = 200
    if op == "whoami":
        report = probe_common.whoami(_loop_name())
    elif op in OPERATIONS:
        host, port = params["host"], int(params["port"])
        report = {"op": op, "host": host, "port": port, **probe_common.whoami(_loop_name())}
        if params.get("uncaught"):
            report.update(await _run_scoped(op, host, port, params, report), outcome="reached")
        else:
            try:
                done = await _run_scoped(op, host, port, params, report)
                report.update(done, outcome="reached")
            except Exception as exc:
                report.update(probe_common.describe_failure(exc))
    else:
        status = 404
        report = {"error": f"no such route: /{op}", "pid": probe_common.whoami()["pid"]}
    probe_common.hold(params)
    await _respond(send, status, report)
