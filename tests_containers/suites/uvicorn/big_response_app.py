"""The ASGI probe application with one more route: ``/big?size=N`` answers with N bytes.

A response longer than one ``send()`` takes is written with ``sendmsg()`` on
the connected socket by asyncio's selector transport from Python 3.12, and so
is every ``writelines()``.  tethered once took that for a destination it
could not read and refused it, which cut every large response short.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs

import probe_asgi


async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
    """The ASGI callable."""
    if scope["type"] != "http" or scope["path"] != "/big":
        await probe_asgi.app(scope, receive, send)
        return
    size = int(parse_qs(scope["query_string"].decode())["size"][0])
    headers = [(b"content-type", b"application/octet-stream")]
    await send({"type": "http.response.start", "status": 200, "headers": headers})
    await send({"type": "http.response.body", "body": b"x" * size})
