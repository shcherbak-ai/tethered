"""Log-only mode — monitor without blocking.

Useful for gradual rollout: see what would be blocked before enforcing.
"""

from __future__ import annotations

import httpx

import tethered

blocked_hosts: list[str] = []


def on_blocked(host: str, port: int | None) -> None:
    blocked_hosts.append(f"{host}:{port}")


# Allow list does NOT include api.github.com — but log_only means
# connections proceed anyway, and the callback logs what would be blocked.
tethered.activate(
    allow=["api.internal.test:443"],
    log_only=True,
    on_blocked=on_blocked,
)

# In enforcing mode this would raise EgressBlocked.
# In log-only mode it succeeds — and the callback records it.
resp = httpx.head("https://api.github.com", timeout=5)
print(f"api.github.com: allowed in log-only mode (HTTP {resp.status_code})")
print(f"Blocked hosts logged by callback: {blocked_hosts}")

tethered.deactivate()
