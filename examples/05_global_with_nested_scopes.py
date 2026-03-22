"""Global policy + nested scopes — each level restricts further."""

from __future__ import annotations

import httpx

import tethered

# Process ceiling: allow three API services
tethered.activate(allow=["api.github.com:443", "api.payments.test:443", "api.analytics.test:443"])

# Outer scope: cuts out analytics
with tethered.scope(allow=["api.github.com:443", "api.payments.test:443"]):
    print("--- outer scope ---")

    # analytics is in global policy but not in outer scope
    try:
        httpx.head("https://api.analytics.test", timeout=5)
        print("api.analytics.test: allowed (unexpected)")
    except tethered.EgressBlocked:
        print("api.analytics.test: blocked by outer scope")

    # Inner scope: cuts out payments too — only GitHub remains
    with tethered.scope(allow=["api.github.com:443"]):
        print("--- inner scope ---")

        # ... business logic, helpers, dependency calls —
        # only api.github.com:443 is reachable here

        # payments is in global and outer, but not inner
        try:
            httpx.head("https://api.payments.test", timeout=5)
            print("api.payments.test: allowed (unexpected)")
        except tethered.EgressBlocked:
            print("api.payments.test: blocked by inner scope")

tethered.deactivate()
