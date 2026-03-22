"""Locked mode — prevent policy tampering in production."""

from __future__ import annotations

import httpx

import tethered

# Create a token (any object — compared by identity, not equality)
secret = object()

# Activate with lock
tethered.activate(
    allow=["api.github.com:443"],
    locked=True,
    lock_token=secret,
)
print("Policy activated and locked")

# A dependency trying to replace the policy fails
try:
    tethered.activate(allow=["*.evil.test:443"])
    print("Policy replaced (unexpected)")
except tethered.TetheredLocked:
    print("activate() without token: TetheredLocked raised")

# A dependency trying to deactivate fails
try:
    tethered.deactivate()
    print("Policy deactivated (unexpected)")
except tethered.TetheredLocked:
    print("deactivate() without token: TetheredLocked raised")

# The original policy still works
resp = httpx.head("https://api.github.com", timeout=5)
print(f"api.github.com: still allowed (HTTP {resp.status_code})")

# With the correct token, the owner can deactivate
tethered.deactivate(lock_token=secret)
print("deactivate(lock_token=secret): success")
