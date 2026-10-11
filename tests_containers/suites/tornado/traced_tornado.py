"""``probe_tornado.py`` with the audit events printed: ``python traced_tornado.py [options]``.

For ``TETH_ACTIVATE=none`` only: what an audit hook sees of tornado's clients
(``audit_trace``).  The options are those of ``probe_tornado.py``.
"""

from __future__ import annotations

import sys

import audit_trace

audit_trace.install()

import probe_tornado  # noqa: E402  (the hook is in place before the application)

if __name__ == "__main__":
    probe_tornado.main(sys.argv[1:])
