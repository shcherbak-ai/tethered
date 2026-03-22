"""Tethered — Runtime network egress control for Python."""

from __future__ import annotations

__version__ = "0.3.2"

from tethered._core import EgressBlocked, TetheredLocked, activate, deactivate, scope

__all__ = ["EgressBlocked", "TetheredLocked", "__version__", "activate", "deactivate", "scope"]
