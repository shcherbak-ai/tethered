"""scope() as a context manager — restrict a code path."""

from __future__ import annotations

import httpx

import tethered

# No activate() or deactivate() needed — scope is self-contained

with tethered.scope(allow=["api.github.com:443"]):
    # Allowed — matches the scope's allow list
    resp = httpx.head("https://api.github.com", timeout=5)
    print(f"api.github.com inside scope: allowed (HTTP {resp.status_code})")

    # Blocked — not in the scope's allow list
    try:
        httpx.head("https://evil.test", timeout=5)
        print("evil.test inside scope: allowed (unexpected)")
    except tethered.EgressBlocked:
        print("evil.test inside scope: blocked")
