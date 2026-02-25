"""Tethered — Runtime network egress control for Python."""

from __future__ import annotations

__version__ = "0.1.4"

from tethered._core import EgressBlocked, TetheredLocked, activate, deactivate

__all__ = ["EgressBlocked", "TetheredLocked", "__version__", "activate", "deactivate"]
