"""The ASGI probe application for hypercorn's trio worker: ``probe_trio:app``.

``probe_asgi`` (``harness/apps``) is written against asyncio and cannot run
under trio, which has no asyncio event loop.  This one offers the same routes
and the same report format with trio's own API.  It activates tethered when it
is imported, as ``TETH_ACTIVATE`` says (see ``probe_common``).  Every route but
``/whoami`` takes ``host`` and ``port``:

    /open_tcp_stream       trio.open_tcp_stream (lookup, then one attempt per address)
    /socket_connect        trio.socket: socket(), connect((host, port))
    /getaddrinfo           trio.socket.getaddrinfo, no connection
    /datagram_connected    a UDP trio socket: connect(), then send()
    /datagram_unconnected  a UDP trio socket: sendto(data, (host, port))
    /to_thread             a blocking socket connection in trio.to_thread.run_sync
    /connect               a blocking socket connection in the trio thread itself
    /child                 trio.run_process: a Python child that tries host:port and reports
                           (how=executable|clean_env|no_site|path_python)
    /tool                  trio.run_process: an external tool (bash) that connects itself
    /whoami                process, async library and the state of tethered

``uncaught=1`` and ``hold=<seconds>`` work as in ``probe_asgi``.
"""

from __future__ import annotations

import json
import socket
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

import probe_common
import trio

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

probe_common.activate_from_env()

_TIMEOUT = 5.0
#: What ``/whoami`` reports as the event loop: there is none, trio schedules the tasks itself.
LOOP = "trio"


async def _read_all(stream: trio.abc.ReceiveStream) -> bytes:
    data = b""
    while chunk := await stream.receive_some(4096):
        data += chunk
    return data


async def _open_tcp_stream(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    with trio.fail_after(_TIMEOUT):
        stream = await trio.open_tcp_stream(host, port)
        async with stream:
            await stream.send_all(probe_common.REQUEST)
            data = await _read_all(stream)
    return {"reply": probe_common.last_line(data)}


async def _socket_connect(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    with trio.fail_after(_TIMEOUT), trio.socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        await sock.connect((host, port))
        await sock.send(probe_common.REQUEST)
        data = b""
        while chunk := await sock.recv(4096):
            data += chunk
    return {"reply": probe_common.last_line(data)}


async def _getaddrinfo(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    with trio.fail_after(_TIMEOUT):
        found = await trio.socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return {"addresses": sorted({info[4][0] for info in found})}


async def _datagram_connected(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    with trio.fail_after(_TIMEOUT), trio.socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        await sock.connect((host, port))
        await sock.send(b"ping")
        with trio.fail_after(2.0):
            data = await sock.recv(4096)
    return {"reply": probe_common.last_line(data)}


async def _datagram_unconnected(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    with trio.fail_after(_TIMEOUT), trio.socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        await sock.sendto(b"ping", (host, port))
        with trio.fail_after(2.0):
            data = await sock.recv(4096)
    return {"reply": probe_common.last_line(data)}


async def _to_thread(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    return await trio.to_thread.run_sync(probe_common.tcp_connect, host, port)


async def _connect(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    return probe_common.tcp_connect(host, port)


async def _launch(argv: list[str], **popen_args: Any) -> dict[str, Any]:
    with trio.fail_after(60.0):
        done = await trio.run_process(
            argv, capture_stdout=True, capture_stderr=True, check=False, **popen_args
        )
    return probe_common.launch_report(done.returncode, done.stdout.decode(), done.stderr.decode())


async def _child(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    argv, popen_args = probe_common.child_argv(params.get("how", "executable"), host, port)
    return await _launch(argv, **popen_args)


async def _tool(host: str, port: int, params: dict[str, str]) -> dict[str, Any]:
    return await _launch(probe_common.tool_argv(host, port))


OPERATIONS: dict[str, Callable[[str, int, dict[str, str]], Awaitable[dict[str, Any]]]] = {
    "open_tcp_stream": _open_tcp_stream,
    "socket_connect": _socket_connect,
    "getaddrinfo": _getaddrinfo,
    "datagram_connected": _datagram_connected,
    "datagram_unconnected": _datagram_unconnected,
    "to_thread": _to_thread,
    "connect": _connect,
    "child": _child,
    "tool": _tool,
}


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
        report = probe_common.whoami(LOOP)
    elif op in OPERATIONS:
        host, port = params["host"], int(params["port"])
        report = {"op": op, "host": host, "port": port, **probe_common.whoami(LOOP)}
        if params.get("uncaught"):
            report.update(await OPERATIONS[op](host, port, params), outcome="reached")
        else:
            try:
                report.update(await OPERATIONS[op](host, port, params), outcome="reached")
            except Exception as exc:
                report.update(probe_common.describe_failure(exc))
    else:
        status = 404
        report = {"error": f"no such route: /{op}", "pid": probe_common.whoami()["pid"]}
    probe_common.hold(params)
    await _respond(send, status, report)
