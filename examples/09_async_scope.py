"""scope() with async functions — works with both decorator and context manager."""

from __future__ import annotations

import asyncio

import httpx

import tethered

# Global policy as a safety net — some async libraries resolve DNS
# in background threads where scopes don't carry over.
tethered.activate(allow=["api.github.com:443"])


@tethered.scope(allow=["api.github.com:443"])
async def fetch_allowed() -> str:
    """Async function scoped to GitHub API — allowed."""
    async with httpx.AsyncClient() as client:
        # ... parse data, run business logic, call other async helpers
        resp = await client.head("https://api.github.com", timeout=5)
        return f"api.github.com — allowed (HTTP {resp.status_code})"


@tethered.scope(allow=["api.github.com:443"])
async def fetch_blocked() -> str:
    """Simulates a compromised dependency inside a scoped async function."""
    loop = asyncio.get_running_loop()
    # A dependency trying to exfiltrate data — blocked by the scope
    await loop.getaddrinfo("evil.test", 443)
    return "evil.test — allowed (unexpected)"


async def scope_as_context_manager() -> str:
    """Using scope() as a context manager inside an async function."""
    with tethered.scope(allow=["api.github.com:443"]):
        async with httpx.AsyncClient() as client:
            resp = await client.head("https://api.github.com", timeout=5)
            return f"api.github.com — allowed (HTTP {resp.status_code})"


async def main() -> None:
    result = await fetch_allowed()
    print(f"fetch_allowed: {result}")

    try:
        await fetch_blocked()
    except tethered.EgressBlocked as e:
        print(f"fetch_blocked: blocked — {e}")

    result = await scope_as_context_manager()
    print(f"scope_as_context_manager: {result}")


asyncio.run(main())
tethered.deactivate()
