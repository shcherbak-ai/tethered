"""Stops pytest when it is pointed at this directory on the host.

The suites below run inside their images, where this file does not exist:
the image holds ``harness/`` and one suite, and its entry point loads the
fixtures as a plugin.  On the host there is no world to connect to, so say
what to run instead of failing on the first import.
"""

from __future__ import annotations

import os

import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Refuse to collect the container suites outside a harness container."""
    if os.environ.get("TC_IN_CONTAINER") != "1":
        raise pytest.UsageError(
            "the container suites run inside their images, not on the host: "
            "use `uv run python tests_containers/run.py` (see tests_containers/README.md)"
        )
