"""``probe_asgi:app`` with the audit events printed (``audit_trace``): ``traced_asgi:app``.

For ``TETH_ACTIVATE=none`` only: what an audit hook sees under an event loop.
"""

from __future__ import annotations

import audit_trace

audit_trace.install()

from probe_asgi import app  # noqa: E402  (the hook is in place before the application)

__all__ = ["app"]
