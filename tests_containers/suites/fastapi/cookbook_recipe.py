"""The FastAPI recipe of ``docs/COOKBOOK.md``, exactly as it is printed there.

Everything between the two marker lines is the code block under "Django /
FastAPI middleware" in the cookbook, character for character: the code blocks
of the cookbook are meant to work as printed, and this suite is what checks
it for this one.  Do not tidy it up.  When the cookbook changes, copy the
block again.  ``main.py`` and ``lifespan_main.py`` add the activation and
the endpoints.
"""

# ruff: noqa: I001, I002
# fmt: off
# --- docs/COOKBOOK.md: begin ---
# main.py
import logging

import tethered
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
app = FastAPI()


def find_egress_blocked(exc: BaseException) -> tethered.EgressBlocked | None:
    """Return exc if it is an EgressBlocked, or the first one inside an exception group."""
    if isinstance(exc, tethered.EgressBlocked):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        for inner in exc.exceptions:
            found = find_egress_blocked(inner)
            if found is not None:
                return found
    return None


@app.exception_handler(tethered.EgressBlocked)
@app.exception_handler(ExceptionGroup)
async def egress_blocked_handler(request: Request, exc: Exception) -> JSONResponse:
    blocked = find_egress_blocked(exc)
    if blocked is None:
        raise exc  # an exception group with no EgressBlocked in it
    logger.error(
        "Egress blocked: %s:%s (resolved_from=%s)",
        blocked.host,
        blocked.port,
        blocked.resolved_from,
    )
    return JSONResponse({"detail": "Service unavailable"}, status_code=503)
# --- docs/COOKBOOK.md: end ---
# fmt: on
