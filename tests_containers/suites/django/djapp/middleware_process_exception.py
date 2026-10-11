"""The same middleware written with Django's hook for exceptions of a view.

Django turns an exception that a view lets out into a response before it
gets back to the middleware that called ``get_response()``, so a ``try`` /
``except`` around that call never sees it.  ``process_exception()`` is what
Django calls with the exception instead.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.http import HttpResponse

import tethered

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest

logger = logging.getLogger(__name__)


class EgressBlockedMiddleware:
    """Answer a request whose view was refused a connection with a 503."""

    def __init__(self, get_response: Callable[[HttpRequest], Any]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> Any:
        """Nothing to do on the way in or out."""
        return self.get_response(request)

    def process_exception(self, request: HttpRequest, exception: Exception) -> HttpResponse | None:
        """Called by Django with an exception that a view raised."""
        if not isinstance(exception, tethered.EgressBlocked):
            return None
        logger.error(
            "Egress blocked: %s:%s (resolved_from=%s)",
            exception.host,
            exception.port,
            exception.resolved_from,
        )
        return HttpResponse("Service unavailable", status=503)
