"""The endpoints of the FastAPI applications of this suite: one outbound call per request.

A refusal is not caught here: it travels to the exception handler of the
cookbook's recipe, and the test asserts the HTTP status the recipe promises.
The two exceptions are ``/httpx_caught``, which is the call-site pattern of
the cookbook, and ``/httpx_shape``, which reports what was raised.

    /whoami                 process, event loop class, the state of tethered
    /httpx_async            httpx.AsyncClient, in an ``async def`` endpoint
    /httpx_caught           the same inside the cookbook's ``except*`` block
    /httpx_shape            the same, reporting the exception as it arrived
    /httpx_sync             httpx.Client, in a ``def`` endpoint (FastAPI's thread pool)
    /streams                asyncio.open_connection
    /websocket              the client of the ``websockets`` package
    /task_group_failure     an exception group that has nothing to do with tethered
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx
import probe_common
import websockets
from cookbook_recipe import find_egress_blocked
from fastapi import APIRouter

import tethered

logger = logging.getLogger(__name__)
router = APIRouter()


def _loop_name() -> str:
    loop = asyncio.get_running_loop()
    return f"{type(loop).__module__}.{type(loop).__qualname__}"


def _answer(response: httpx.Response) -> dict[str, Any]:
    return {"status": response.status_code, "reply": response.text.strip()}


@router.get("/whoami")
async def whoami(hold: float = 0.0) -> dict[str, Any]:
    """Who is answering.  ``hold`` keeps this worker busy, as in the probe applications."""
    probe_common.hold({"hold": str(hold)})
    return probe_common.whoami(_loop_name())


@router.get("/httpx_async")
async def httpx_async(host: str, port: int) -> dict[str, Any]:
    """One request with ``httpx.AsyncClient``; a refusal is not caught here."""
    async with httpx.AsyncClient() as client:
        response = await client.get(f"http://{host}:{port}/")
    return _answer(response)


@router.get("/httpx_caught")
async def httpx_caught(host: str, port: int) -> dict[str, Any]:
    """The call-site pattern of the cookbook: ``except*`` catches both shapes of a refusal."""
    url = f"http://{host}:{port}/"
    # --- docs/COOKBOOK.md: begin ---
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
    except* tethered.EgressBlocked as group:
        blocked = find_egress_blocked(group)
        logger.error("Egress blocked: %s:%s", blocked.host, blocked.port)
        response = None
    # --- docs/COOKBOOK.md: end ---
    if response is None:
        return {"caught": True, "host": blocked.host, "port": blocked.port}
    return {"caught": False, **_answer(response)}


@router.get("/httpx_shape")
async def httpx_shape(host: str, port: int, hold: float = 0.0) -> dict[str, Any]:
    """Report the exception of a refused request as it reached the endpoint, and who saw it."""
    report = probe_common.whoami(_loop_name())
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://{host}:{port}/")
    except Exception as exc:
        report.update(probe_common.describe_failure(exc))
    else:
        report.update(_answer(response), outcome="reached")
    probe_common.hold({"hold": str(hold)})
    return report


@router.get("/httpx_sync")
def httpx_sync(host: str, port: int) -> dict[str, Any]:
    """One request with the synchronous ``httpx.Client``, in FastAPI's thread pool."""
    with httpx.Client() as client:
        response = client.get(f"http://{host}:{port}/")
    return _answer(response)


@router.get("/streams")
async def streams(host: str, port: int) -> dict[str, Any]:
    """One connection with asyncio streams."""
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(probe_common.REQUEST)
        await writer.drain()
        data = await reader.read()
    finally:
        writer.close()
    return {"reply": probe_common.last_line(data)}


@router.get("/websocket")
async def websocket(host: str, port: int) -> dict[str, Any]:
    """Open a WebSocket connection with the client that ``uvicorn[standard]`` installs.

    The world answers with plain HTTP, so the handshake fails once the
    connection is made; that failure is the sign that the destination was
    reached.
    """
    try:
        async with websockets.connect(f"ws://{host}:{port}/", open_timeout=5):
            pass
    except websockets.exceptions.InvalidHandshake as exc:
        return {"connected": True, "handshake": type(exc).__name__}
    return {"connected": True, "handshake": "accepted"}


@router.get("/task_group_failure")
async def task_group_failure() -> dict[str, Any]:
    """Raise an exception group with no ``EgressBlocked`` in it."""

    async def fail() -> None:
        raise ValueError("not a refusal")

    async with asyncio.TaskGroup() as group:
        group.create_task(fail())
    return {}
