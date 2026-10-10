"""An application factory: ``uvicorn --factory factory_app:create_app``.

Importing this module activates nothing.  The policy is activated when
uvicorn calls the factory, because that is when the probe application is
imported (it activates as ``TETH_ACTIVATE`` says).
"""

from __future__ import annotations

from typing import Any


def create_app() -> Any:
    """Import the probe application, and with it the policy; return the ASGI callable."""
    import probe_asgi

    return probe_asgi.app
