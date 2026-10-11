"""The Django middleware of docs/COOKBOOK.md ("Django / FastAPI middleware"), as printed.

Everything from the ``# middleware.py`` line on is the code block of the
cookbook, character for character; keep it that way when the cookbook
changes, so that the suite tests what the documentation tells people to write.
"""
# ruff: noqa: I001, E501
# fmt: off

from __future__ import annotations

# middleware.py
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
