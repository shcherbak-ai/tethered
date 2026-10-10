"""A FastAPI application for ``fastapi run``: ``main:app``, activation at import.

``fastapi run`` with a path wants a ``FastAPI`` object, so this is one, with
the ASGI probe application of ``harness/apps`` mounted at the root: every
route of the probe (``/whoami``, ``/open_connection``, ...) is served through
FastAPI.  Importing the probe application activates the policy, as
``TETH_ACTIVATE`` says.
"""

from __future__ import annotations

import probe_asgi
from fastapi import FastAPI

app = FastAPI()
app.mount("/", probe_asgi.app)
