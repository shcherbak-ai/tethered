"""``probe_twisted:app`` with the audit events printed (``audit_trace``): ``traced_twisted:app``.

For ``TETH_ACTIVATE=none`` only: what an audit hook sees of Twisted's networking.
"""

from __future__ import annotations

import audit_trace

audit_trace.install()

from probe_twisted import app  # noqa: E402  (the hook is in place before the application)

__all__ = ["app"]
