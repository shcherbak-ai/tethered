---
title: "Quick start"
description: "Install tethered, set an allow list for the process, narrow a code path, and lock the policy in production."
---

# Quick start

## Install

```bash
uv add tethered
```

Or `pip install tethered`. Python 3.11+ on Linux, macOS and Windows, with no runtime dependencies. Wheels are prebuilt; a source install needs a C compiler.

Upgrading from 0.5.x? 1.0 refuses to run where 0.5.x went on without enforcing, so a deployment can stop at start-up after the upgrade. Read the [migration guide](migrating-to-v1.md) first.

## Protect the process

```python
# main.py, wsgi.py, manage.py: your entry point
import tethered

tethered.activate(allow=["*.stripe.com:443", "db.internal:5432"])

from myapp import create_app  # import the application afterwards
app = create_app()
```

Activate first, before your application and its dependencies are imported. Connections that are already open keep working, and worker processes that already exist are not reached.

A connection that the policy does not allow raises `tethered.EgressBlocked`. The [cookbook](COOKBOOK.md#handling-blocked-connections) shows how to handle it in Django, FastAPI and Celery, and what [each server](COOKBOOK.md#servers-and-interpreter-pools) needs.

## Narrow a code path

```python
import httpx
import tethered

@tethered.scope(allow=["*.stripe.com:443"])
def charge(amount: int, token: str) -> dict:
    # this function, and everything it calls, reaches *.stripe.com:443 only
    return httpx.post("https://api.stripe.com/v1/charges", ...).json()
```

A scope is a decorator or a `with` block, for sync and async code, and it works without `activate()`. With both in place a connection must be allowed by both: a scope narrows the policy and never widens it.

Writing a library? Use `scope()` and leave `activate()` to the application, which owns the process ([guide for package authors](COOKBOOK.md#for-package-authors)).

## Child processes

Python children started with the same interpreter inherit the policy as they start: `multiprocessing` and `ProcessPoolExecutor` workers, gunicorn and uvicorn workers, `subprocess.run([sys.executable, ...])`. A child launched through `subprocess` inside a scope inherits the scope too.

Every other launch (`curl`, another interpreter, `python -S`) is external: logged by default, refused with `external_subprocess_policy="block"`. The rules are on the [subprocess page](SUBPROCESS.md).

## Lock it down in production

```python
tethered.activate(
    allow=["api.stripe.com:443", "db.internal:5432"],
    locked=True,                         # replacing or switching off the policy takes the token
    lock_token=object(),                 # ... and nobody keeps it
    fail_closed=True,                    # an error inside the check blocks instead of allowing
    external_subprocess_policy="block",  # no shelling out to a program that does the egress
)
```

Under a lock, tampering with tethered's own code or with the active policy is detected and fails closed, and a Python child that cannot establish the locked policy refuses to start. Activate before importing third-party code: whatever runs earlier is not covered.

`"block"` also stops the helper programs some libraries launch when they are imported, so import those first ([details](SUBPROCESS.md#what-block-also-refuses)). Locked mode is not a sandbox: the [security model](security.md#locked-mode--what-it-does-and-does-not-do) lists what it checks and what it does not stop.

## Allow list syntax

| Rule | Matches |
|---|---|
| `"api.stripe.com"` | That host, on any port |
| `"*.stripe.com"` | Any subdomain, `a.b.stripe.com` included; not `stripe.com` itself |
| `"api.stripe.com:443"` | That host on port 443 only |
| `"198.51.100.1"`, `"10.0.0.0/8"` | An IPv4 address; a CIDR range |
| `"10.0.0.0/8:5432"` | A CIDR range on one port |
| `"[2001:db8::1]:443"`, `"[2001:db8::]/32"` | IPv6, in brackets where a port or a prefix follows |

Wildcards follow Python's `fnmatch` and match text, not address ranges: `10.*` also allows `10.attacker.example`, so use CIDR for ranges. Localhost is allowed unless you pass `allow_localhost=False`. A malformed rule raises `ValueError` when the policy is set. The full syntax is in the [API reference](API.md#allow-list-syntax).

## Limits

- **A guardrail, not a sandbox.** tethered works at Python's audit-event layer. Code that goes below it (`ctypes`, `cffi`, a C extension making its own system calls) is not stopped, with or without locked mode. Where you need hard isolation, combine tethered with OS-level controls: containers, seccomp, network namespaces. The [security model](security.md) has the full threat model.
- **Libraries that connect in C are not seen.** tethered sees what goes through Python's `socket` module: requests, httpx, urllib3, aiohttp and the pure-Python database and broker clients. A library that resolves and connects inside its own C code (psycopg2, pycurl, grpcio) is not checked. The [compatibility page](COMPATIBILITY.md) says what was measured, server by server and library by library.
- **Under asyncio, the standard event loop only.** A uvloop event loop raises no audit events, so tethered refuses to enforce a policy next to it, and uvicorn picks uvloop whenever it is installed. Name the loop (`uvicorn main:app --loop asyncio`) or activate in a launcher script before the server is imported ([server setup](COOKBOOK.md#servers-and-interpreter-pools)).
- **On Windows, run asyncio on `asyncio.SelectorEventLoop`.** The default `ProactorEventLoop` connects through calls that raise no audit event, so only DNS-time hostname checks apply there.
