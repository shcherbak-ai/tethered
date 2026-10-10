"""The same application with the activation in a lifespan handler: ``lifespan_main:app``.

Importing this module activates nothing.  The policy is activated when the
server runs the application's startup, which is where many applications
configure things, and which is after the server has chosen and started its
event loop.  The exception handler is the cookbook's, registered on this
application for the same two exception types.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import probe_common
from cookbook_recipe import egress_blocked_handler
from endpoints import router
from fastapi import FastAPI

import tethered

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Activate the policy at startup, as ``TETH_ACTIVATE`` says."""
    probe_common.activate_from_env()
    yield


app = FastAPI(lifespan=lifespan)
app.add_exception_handler(tethered.EgressBlocked, egress_blocked_handler)
app.add_exception_handler(ExceptionGroup, egress_blocked_handler)
app.include_router(router)
