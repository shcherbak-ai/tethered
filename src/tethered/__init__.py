"""Tethered — Runtime network egress control for Python."""

from __future__ import annotations

__version__ = "0.5.0"

from tethered._core import (
    EgressBlocked,
    SubprocessBlocked,
    TetheredLocked,
    activate,
    deactivate,
    scope,
)

__all__ = [
    "EgressBlocked",
    "SubprocessBlocked",
    "TetheredLocked",
    "__version__",
    "activate",
    "deactivate",
    "scope",
]
