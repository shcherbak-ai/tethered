"""Basic activate() — set a process-wide allow list."""

from __future__ import annotations

import httpx

import tethered

# Allow any GitHub subdomain on HTTPS
tethered.activate(allow=["*.github.com:443"])

# Allowed — matches *.github.com:443
resp = httpx.head("https://api.github.com", timeout=5)
print(f"api.github.com:443: allowed (HTTP {resp.status_code})")

# Blocked — evil.test is not in the allow list
try:
    httpx.head("https://evil.test", timeout=5)
    print("evil.test: allowed (unexpected)")
except tethered.EgressBlocked as e:
    print(f"evil.test: blocked — {e}")

tethered.deactivate()
