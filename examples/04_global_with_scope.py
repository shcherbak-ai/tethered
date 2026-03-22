"""Global policy + scope — intersection semantics.

The global policy is the ceiling. Scopes restrict further within it.
A connection must be allowed by both the global policy and every active scope.
"""

from __future__ import annotations

import httpx

import tethered

# Process ceiling: allow GitHub API and an internal database
tethered.activate(allow=["api.github.com:443", "db.internal:5432"])

# Scope restricts to GitHub API only — db.internal is cut out
with tethered.scope(allow=["api.github.com:443"]):
    # ... business logic, helpers, dependency calls —
    # only api.github.com:443 is reachable here

    # db.internal is in the global policy, but the scope's allow list
    # does not include it — intersection blocks it
    try:
        httpx.head("https://db.internal:5432", timeout=5)
        print("db.internal:5432: allowed (unexpected)")
    except tethered.EgressBlocked:
        print("db.internal:5432: blocked by scope (global allows it, scope does not)")

tethered.deactivate()
