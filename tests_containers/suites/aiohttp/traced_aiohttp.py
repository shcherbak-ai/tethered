"""``probe_aiohttp`` with the audit events printed (``audit_trace``).

    gunicorn traced_aiohttp:app -k aiohttp.GunicornUVLoopWebWorker
    python traced_aiohttp.py                  web.run_app, on PORT

For ``TETH_ACTIVATE=none`` only: what an audit hook sees under an event loop.
"""

from __future__ import annotations

import audit_trace

audit_trace.install()

import probe_aiohttp  # noqa: E402  (the hook is in place before the application)

app = probe_aiohttp.app

if __name__ == "__main__":
    probe_aiohttp.serve()
