"""The middleware the cookbook used to print: ``try`` / ``except`` around ``get_response()``.

It does not work, and is kept to show why the recipe is written with
``process_exception()``: Django turns an exception that a view lets out into
a 500 response before ``get_response()`` returns, so the ``except`` clause
never sees it.
"""
# ruff: noqa: I001, E501
# fmt: off

from __future__ import annotations

import logging

import tethered
from django.http import HttpResponse

logger = logging.getLogger(__name__)


class EgressBlockedMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            return self.get_response(request)
        except tethered.EgressBlocked as e:
            logger.error("Egress blocked: %s:%s (resolved_from=%s)", e.host, e.port, e.resolved_from)
            return HttpResponse("Service unavailable", status=503)
