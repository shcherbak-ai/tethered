"""The Django middleware of ``docs/COOKBOOK.md``, exactly as it is printed there.

Everything between the two marker lines is the code block under "Django /
FastAPI middleware" in the cookbook, character for character: the code blocks
of the cookbook are meant to work as printed, and this suite is what checks
it for this one.  Do not tidy it up.  When the cookbook changes, copy the
block again (``tests/test_docs_recipes.py`` fails until the two agree).
"""

# ruff: noqa: I001, I002
# fmt: off
# --- docs/COOKBOOK.md: begin ---
# middleware.py
import logging

import tethered
from django.http import HttpResponse

logger = logging.getLogger(__name__)


class EgressBlockedMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        if not isinstance(exception, tethered.EgressBlocked):
            return None
        logger.error(
            "Egress blocked: %s:%s (resolved_from=%s)",
            exception.host,
            exception.port,
            exception.resolved_from,
        )
        return HttpResponse("Service unavailable", status=503)
# --- docs/COOKBOOK.md: end ---
# fmt: on
