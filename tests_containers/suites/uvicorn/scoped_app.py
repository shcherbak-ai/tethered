"""The ASGI probe application with every request inside a ``tethered.scope()``.

``scoped_app:app`` is for an application that never calls ``activate()`` and
restricts each request with a scope instead, which is what a library does.
Run it with ``TETH_ACTIVATE=none``: the scope is then the only policy in the
process.  With no policy active nothing keeps uvloop from being loaded.
"""

from __future__ import annotations

from typing import Any

import probe_asgi

import tethered

ALLOW = ["allowed.test:9001"]


async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
    """The ASGI callable."""
    if scope["type"] != "http":
        await probe_asgi.app(scope, receive, send)
        return
    with tethered.scope(allow=ALLOW, label="scoped_app"):
        await probe_asgi.app(scope, receive, send)
