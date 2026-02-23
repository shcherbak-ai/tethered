# tethered

[![CI](https://github.com/shcherbak-ai/tethered/actions/workflows/ci.yml/badge.svg)](https://github.com/shcherbak-ai/tethered/actions/workflows/ci.yml)
[![CodeQL](https://github.com/shcherbak-ai/tethered/actions/workflows/codeql.yml/badge.svg)](https://github.com/shcherbak-ai/tethered/actions/workflows/codeql.yml)
[![PyPI](https://img.shields.io/pypi/v/tethered)](https://pypi.org/project/tethered/)
[![Python](https://img.shields.io/pypi/pyversions/tethered)](https://pypi.org/project/tethered/)
[![codecov](https://codecov.io/gh/shcherbak-ai/tethered/graph/badge.svg)](https://codecov.io/gh/shcherbak-ai/tethered)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/shcherbak-ai/tethered/blob/main/LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)

Runtime network egress control for Python. One function call to restrict which hosts your code can connect to.

```python
import tethered

tethered.activate(allow=["*.stripe.com:443", "db.internal:5432"])

import urllib.request
urllib.request.urlopen("https://api.stripe.com/v1/charges")  # works — matches *.stripe.com:443
urllib.request.urlopen("https://evil.com/exfil")             # raises tethered.EgressBlocked
```

Tethered is a lightweight in-process policy check — not a proxy, not a firewall. It intercepts Python socket operations via [`sys.addaudithook`](https://docs.python.org/3/library/sys.html#sys.addaudithook) ([PEP 578](https://peps.python.org/pep-0578/)) and blocks disallowed connections before any packet leaves the machine. No admin privileges, no infrastructure changes, no effect on other processes.

## Why

Python has no built-in way to restrict outbound network access at runtime. Infrastructure-level controls (firewalls, network policies, proxies) operate outside your application — they require platform teams, separate services, or admin privileges. None of them give you a single line of Python that says "this process may only talk to these hosts."

Tethered fills this gap at the application layer. It's complementary to infrastructure controls, not a replacement.

### Use cases

- **Supply chain defense.** A compromised dependency can't phone home if egress is locked to your known services.
- **AI agent guardrails.** Constrain LLM-powered agents to only the APIs they need.
- **Test isolation.** Ensure your test suite never accidentally hits production endpoints.
- **Least-privilege networking.** Declare your app's network surface the same way you declare its dependencies.

## Install

```bash
uv add tethered
```

Or with pip:

```bash
pip install tethered
```

Requires Python 3.10+. Zero runtime dependencies.

## Getting started

Call `activate()` as early as possible — **before** any library makes network connections:

```python
# manage.py, wsgi.py, main.py, or your entrypoint
import tethered
tethered.activate(allow=["*.stripe.com:443", "db.internal:5432"])

# Then import and run your app
from myapp import create_app
app = create_app()
```

This pattern works the same for Django, Flask, FastAPI, scripts, and AI agents — activate tethered before your application and its dependencies start making connections.

Existing connections (e.g., connection pools) established before `activate()` will continue to work — tethered intercepts at connect time, not at read/write time.

## Allow list syntax

| Pattern | Example | Matches |
|---|---|---|
| Exact hostname | `"api.stripe.com"` | `api.stripe.com` only |
| Wildcard subdomain | `"*.stripe.com"` | `api.stripe.com`, `dashboard.stripe.com` (not `stripe.com`) |
| Hostname + port | `"api.stripe.com:443"` | `api.stripe.com` on port 443 only |
| IPv4 address | `"198.51.100.1"` | That IP only |
| IPv4 CIDR range | `"10.0.0.0/8"` | Any IP in `10.x.x.x` |
| CIDR + port | `"10.0.0.0/8:5432"` | Any IP in `10.x.x.x` on port 5432 |
| IPv6 address | `"2001:db8::1"` or `"[2001:db8::1]"` | That IPv6 address |
| IPv6 + port | `"[2001:db8::1]:443"` | That IPv6 address on port 443 only |
| IPv6 CIDR | `"[2001:db8::]/32"` | Any IP in that IPv6 prefix |

**Wildcard matching:** Uses Python's `fnmatch` syntax. `*` matches any characters **including dots**, so `*.stripe.com` matches both `api.stripe.com` and `a.b.stripe.com`. This differs from TLS certificate wildcards. The characters `?` (single character) and `[seq]` (character set) are also supported.

Localhost (`127.0.0.0/8`, `::1`) is always allowed by default. The addresses `0.0.0.0` and `::` (INADDR_ANY) are also treated as localhost.

## API

### `tethered.activate()`

```python
tethered.activate(
    *,
    allow: list[str],
    log_only: bool = False,
    fail_closed: bool = False,
    allow_localhost: bool = True,
    on_blocked: Callable[[str, int | None], None] | None = None,
    locked: bool = False,
    lock_token: object | None = None,
)
```

| Parameter | Description |
|---|---|
| `allow` | Required. Allowed destinations — see [Allow list syntax](#allow-list-syntax). Pass `[]` to block all non-localhost connections. |
| `log_only` | Log blocked connections instead of raising `EgressBlocked`. Default `False`. |
| `fail_closed` | Block when the policy check itself errors, instead of failing open. Default `False`. |
| `allow_localhost` | Allow loopback addresses (`127.0.0.0/8`, `::1`). Default `True`. |
| `on_blocked` | Callback `(host, port) -> None` invoked on every blocked connection, including in log-only mode. |
| `locked` | Prevent `deactivate()` without the correct `lock_token`. Default `False`. |
| `lock_token` | Opaque token required to `deactivate()` when locked. |

Can be called multiple times to replace the active policy — calling `activate()` again does not require `deactivate()` first. Each call creates a completely new policy; no parameters or state carry over from previous calls.

#### Log-only mode

Monitor without blocking — useful for rollout or auditing:

```python
tethered.activate(
    allow=["*.stripe.com"],
    log_only=True,
    on_blocked=lambda host, port: print(f"would block: {host}:{port}"),
)
```

#### Locked mode

Prevent in-process code from disabling enforcement:

```python
secret = object()
tethered.activate(allow=["*.stripe.com:443"], locked=True, lock_token=secret)

# Only works with the correct token
tethered.deactivate(lock_token=secret)
```

### `tethered.deactivate(*, lock_token=None)`

Disable enforcement. All connections are allowed again. Internal state (IP-to-hostname mappings, callback references) is fully cleared — a subsequent `activate()` starts fresh.

If activated with `locked=True`, the matching `lock_token` must be provided or `TetheredLocked` is raised.

### `tethered.EgressBlocked`

Raised when a connection is blocked. Subclass of `RuntimeError`.

```python
try:
    urllib.request.urlopen("https://evil.com")
except tethered.EgressBlocked as e:
    print(e.host)           # "evil.com"
    print(e.port)           # 443
    print(e.resolved_from)  # original hostname if connecting by resolved IP
```

### `tethered.TetheredLocked`

Raised when `deactivate()` is called on a locked policy without the correct token. Subclass of `RuntimeError`.

## How it works

Tethered uses [`sys.addaudithook`](https://docs.python.org/3/library/sys.html#sys.addaudithook) (PEP 578) to intercept socket operations at the interpreter level:

- **`socket.getaddrinfo`** — blocks DNS resolution for disallowed hostnames and records IP-to-hostname mappings for allowed hosts.
- **`socket.gethostbyname` / `socket.gethostbyaddr`** — intercepts alternative DNS resolution paths.
- **`socket.connect` / `socket.connect_ex`** — enforces the allow list on TCP connections.
- **`socket.sendto` / `socket.sendmsg`** — enforces the allow list on UDP datagrams.

When `getaddrinfo` resolves a hostname, tethered records the IP-to-hostname mapping in a bounded LRU cache. When a subsequent `connect()` targets that IP, tethered looks up the original hostname and checks it against the allow list. If denied, `EgressBlocked` is raised before any packet leaves the machine.

This works transparently with any Python networking library (requests, httpx, urllib3, aiohttp) and any framework (Django, Flask, FastAPI) — they all call `socket.getaddrinfo` and `socket.connect` under the hood. Async is fully supported: audit hooks fire at the C socket level, so `asyncio`, `aiohttp`, and `httpx` async use the same enforcement path as synchronous code.

The per-connection overhead is a Python function call with a string comparison and dictionary lookup — negligible compared to actual network I/O.

## Security model

> **Tethered is a defense-in-depth guardrail, not a security sandbox.** It intercepts
> Python-level socket operations. Code that uses `ctypes`, `cffi`, subprocesses, or
> C extensions with direct syscalls can bypass it. For full process isolation, combine
> tethered with OS-level controls (containers, seccomp, network namespaces).

### What tethered protects against

Trusted-but-buggy code and supply chain threats: dependencies that use Python's standard `socket` module (directly or through libraries like `requests`, `urllib3`, `httpx`, `aiohttp`). Tethered prevents these from connecting to destinations not in your allow list.

### What tethered does NOT protect against

- **`ctypes` / `cffi` / direct syscalls.** Native code can call libc's `connect()` directly, bypassing the audit hook.
- **Subprocesses.** `subprocess.Popen`, `os.system`, and `os.exec*` create new processes without the audit hook.
- **C extensions with raw socket calls.** Extensions calling C-level socket functions are not intercepted.
- **In-process disabling.** Code in the same interpreter can call `deactivate()` unless `locked=True` is used. Even locked mode can be bypassed by code that modifies module state — Python has no true encapsulation.

### Design trade-offs

- **Fail-open by default.** If tethered's matching logic raises an unexpected exception, the connection is allowed and a warning is logged. A bug in tethered should not break your application. Use `fail_closed=True` for stricter environments.
- **Audit hooks are irremovable.** `sys.addaudithook` has no remove function (by design — PEP 578). `deactivate()` makes the hook a no-op but cannot unregister it. This is per-process only — no persistent state, no system changes, everything is gone when the process exits.
- **IP-to-hostname mapping is bounded.** The LRU cache holds up to 4096 entries. In long-running processes with many unique DNS lookups, older mappings are evicted. A connection to an evicted IP is checked against IP/CIDR rules only.
- **Direct IP connections skip hostname matching.** Connecting to a raw IP without prior DNS resolution means only IP/CIDR rules apply — hostname wildcards won't match.

### Recommendations

For defense-in-depth, combine tethered with:

- OS-level sandboxing (containers, seccomp-bpf, network namespaces) for hard isolation.
- Subprocess restrictions (audit hooks on `subprocess.Popen` events, or seccomp filters).
- Import restrictions to prevent `ctypes`/`cffi` loading in untrusted code paths.

## License

MIT
