"""The ASGI probe application with the activation in its lifespan handler: ``lifespan_app:app``.

No framework: the handler below is all there is between the server and the
application's startup code.  Importing the module activates nothing (run it
with ``TETH_ACTIVATE=none``); the policy named by ``LIFESPAN_ACTIVATE`` is
activated when the server sends ``lifespan.startup``, which is after the
server has chosen and started its event loop.

An exception from ``activate()`` leaves the handler, as it does in an
application that does not expect one.  What the server makes of that is the
subject of the tests.
"""

from __future__ import annotations

import os
from typing import Any

import probe_asgi
import probe_common


async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
    """The ASGI callable."""
    if scope["type"] != "lifespan":
        await probe_asgi.app(scope, receive, send)
        return
    await receive()  # lifespan.startup
    os.environ["TETH_ACTIVATE"] = os.environ["LIFESPAN_ACTIVATE"]
    probe_common.activate_from_env()
    await send({"type": "lifespan.startup.complete"})
    await receive()  # lifespan.shutdown
    await send({"type": "lifespan.shutdown.complete"})
