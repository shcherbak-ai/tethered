"""Shared code of the container suites: what the tests import.

``from harness import start_server, arrived, FORBIDDEN_NAME`` is all a test
module needs; the fixtures come from ``harness.plugin``, which the image's
entry point (``python -m harness``) loads.  See ``tests_containers/AGENTS.md``.
"""

from __future__ import annotations

from harness.helpers import (
    ALLOWED_ADDR,
    ALLOWED_NAME,
    ALLOWED_PORT,
    APPS_DIR,
    FORBIDDEN_ADDR,
    FORBIDDEN_NAME,
    LOOPBACK_ADDR,
    OTHER_PORT,
    PORTS,
    SUITE_DIR,
    Response,
    arrivals,
    arrived,
    dns_queries,
    http_get,
    probe_path,
    reset_arrivals,
)
from harness.servers import Completed, Server, run_python, start_server

__all__ = [
    "ALLOWED_ADDR",
    "ALLOWED_NAME",
    "ALLOWED_PORT",
    "APPS_DIR",
    "FORBIDDEN_ADDR",
    "FORBIDDEN_NAME",
    "LOOPBACK_ADDR",
    "OTHER_PORT",
    "PORTS",
    "SUITE_DIR",
    "Completed",
    "Response",
    "Server",
    "arrivals",
    "arrived",
    "dns_queries",
    "http_get",
    "probe_path",
    "reset_arrivals",
    "run_python",
    "start_server",
]
