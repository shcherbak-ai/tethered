# API reference

[← Back to README](../README.md)

- [`tethered.activate()`](#tetheredactivate)
- [`tethered.scope()`](#tetheredscope)
- [`tethered.deactivate()`](#tethereddeactivate)
- [`tethered.EgressBlocked`](#tetheredegressblocked)
- [`tethered.SubprocessBlocked`](#tetheredsubprocessblocked)
- [`tethered.TetheredLocked`](#tetheredtetheredlocked)
- [Locked mode](#locked-mode)
- [Log-only mode](#log-only-mode)
- [Intersection semantics — `activate()` + `scope()`](#intersection-semantics--activate--scope)
- [Nested scopes](#nested-scopes)

## `tethered.activate()`

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
    external_subprocess_policy: str = "warn",
)
```

| Parameter | Description |
|---|---|
| `allow` | Required. Allowed destinations — see [Allow list syntax](../README.md#allow-list-syntax). Pass `[]` to block all non-localhost connections. |
| `log_only` | Log blocked connections instead of raising `EgressBlocked`. Default `False`. |
| `fail_closed` | Block when the policy check itself errors, instead of failing open. Default `False`. |
| `allow_localhost` | Allow loopback addresses (`127.0.0.0/8`, `::1`). Default `True`. |
| `on_blocked` | Callback `(host, port) -> None` invoked on every blocked connection, including in log-only mode. |
| `locked` | Enable tamper-resistant enforcement via C extension. Prevents `deactivate()` and `activate()` without the correct `lock_token`, and installs a C-level integrity verifier that blocks ALL network access on tamper detection. Default `False`. See [Locked mode](#locked-mode). |
| `lock_token` | Opaque, non-internable token required when `locked=True`. Must be an instance like `object()` — internable types (`str`, `int`, `float`, `bytes`, `bool`) are rejected with `TypeError`. Compared by identity (`is`), not equality. |
| `external_subprocess_policy` | Parent-side enforcement for *external* subprocess launches — non-Python tools, different Python interpreters, or `sys.executable` launched with `-S` (which disables `site.py`). Regular Python children of `sys.executable` auto-inherit unconditionally and are unaffected by this — including launches with `-I` or `-E` (those keep `site.py` enabled). Values: `"warn"` (default — supply-chain visibility), `"allow"`, `"block"`. See [SUBPROCESS.md](SUBPROCESS.md). |

Can be called multiple times to replace the active policy — calling `activate()` again does not require `deactivate()` first. If the current policy is locked, the correct `lock_token` must be provided. Each call creates a completely new policy; no parameters or state carry over from previous calls.

## `tethered.scope()`

```python
tethered.scope(
    *,
    allow: list[str],
    allow_localhost: bool = True,
    log_only: bool = False,
    fail_closed: bool = False,
    on_blocked: Callable[[str, int | None], None] | None = None,
    label: str | None = None,
)
```

| Parameter | Description |
|---|---|
| `allow` | Required. Allowed destinations — see [Allow list syntax](../README.md#allow-list-syntax). |
| `allow_localhost` | Allow loopback addresses. Default `True`. |
| `log_only` | Log blocked connections instead of raising. Default `False`. |
| `fail_closed` | Block when the policy check itself errors. Default `False`. |
| `on_blocked` | Callback `(host, port) -> None` on every blocked connection. |
| `label` | Human-readable name for this scope. Appears in log messages and as `EgressBlocked.scope_label` when this scope produces a block. Library authors should use it to identify call sites — e.g. `label="WeatherClient.get_forecast"`. Defaults to an auto-derived `"scope(<first 3 allow rules>)"` summary. |

Use as a **context manager** (`with tethered.scope(allow=[...]):`) or a **decorator** (`@tethered.scope(allow=[...])`). Supports both sync and async functions. Cleanup is automatic — no `deactivate()` call needed.

`scope()` works on its own — no `activate()` required. When used alone, the scope IS the policy for that code path. Code outside the scope is unaffected.

Scopes can only **restrict**, never widen. If the app also called `activate()`, the effective policy is the intersection — a connection must be allowed by both.

> **Package maintainers:** Use `scope()`, never `activate()`. Your library doesn't own the process — the app does. `activate()` is a process-wide operation that would interfere with the host application's own policy. `scope()` is context-local and safe to use from any library.

## `tethered.deactivate()`

```python
tethered.deactivate(*, lock_token: object | None = None)
```

Disable enforcement. All connections are allowed again. Internal state (IP-to-hostname mappings, callback references) is fully cleared — a subsequent `activate()` starts fresh.

If activated with `locked=True`, the matching `lock_token` must be provided or `TetheredLocked` is raised.

## `tethered.EgressBlocked`

Raised when a connection is blocked. Subclass of `RuntimeError`.

```python
try:
    urllib.request.urlopen("https://evil.test")
except tethered.EgressBlocked as e:
    print(e.host)           # "evil.test"
    print(e.port)           # 443
    print(e.resolved_from)  # original hostname if connecting by resolved IP
    print(e.scope_label)    # "scope(api.mylib.com:443)" if a scope blocked it; None for global blocks
```

| Attribute | Type | Meaning |
|---|---|---|
| `host` | `str` | The host (or IP) the call attempted to reach. |
| `port` | `int \| None` | The port, when known (`None` for `getaddrinfo` / DNS-only events). |
| `resolved_from` | `str \| None` | When connecting by a resolved IP, the original hostname tethered mapped that IP to. `None` for direct hostname connects or when no mapping is known. |
| `scope_label` | `str \| None` | The label of the `scope()` that blocked the call (e.g. `"scope(api.mylib.com:443)"`), or `None` if the block came from the global `activate()` policy. Useful for libraries that wrap `EgressBlocked` and want to attribute the block to the right scope when multiple are nested. See [COOKBOOK.md#for-package-authors](COOKBOOK.md#for-package-authors). |

When `scope_label` is non-`None`, the message includes a trailing `(blocked by <label>)` suffix so the source of the block is visible in tracebacks even without inspecting the attribute.

`EgressBlocked` is intentionally a `RuntimeError`, not an `OSError` — a policy violation is not a network error and should not be silently caught by HTTP libraries or retry logic. See [COOKBOOK.md](COOKBOOK.md#handling-blocked-connections) for handling patterns at framework boundaries (Django, FastAPI, Celery, retry decorators).

## `tethered.SubprocessBlocked`

Raised when a subprocess launch is blocked by the `external_subprocess_policy` or by the locked-mode env-strip protection. Subclass of `RuntimeError`. See [SUBPROCESS.md](SUBPROCESS.md) for the full behavior.

## `tethered.TetheredLocked`

Raised when `deactivate()` or `activate()` is called on a locked policy without the correct token. Subclass of `RuntimeError`.

## Locked mode

Tamper-resistant enforcement backed by a C extension:

```python
secret = object()
tethered.activate(allow=["*.stripe.com:443"], locked=True, lock_token=secret)

# Both deactivate() and activate() require the correct token
tethered.deactivate(lock_token=secret)
```

Calling `activate()` or `deactivate()` without the correct `lock_token` raises `TetheredLocked`. See [SECURITY.md](../SECURITY.md) for the full threat analysis, including what locked mode catches and what its residual bypasses are.

In addition, locked mode hardens the subprocess auto-propagation channel against in-process tampering — payload-integrity checks at every subprocess launch, and Python-level FS-tamper protection on the `tethered.pth` file. See [SUBPROCESS.md](SUBPROCESS.md#locked-mode-hardening-of-the-auto-propagation-channel) for the details.

## Log-only mode

Monitor without blocking — useful for rollout or auditing:

```python
tethered.activate(
    allow=["*.stripe.com"],
    log_only=True,
    on_blocked=lambda host, port: print(f"would block: {host}:{port}"),
)
```

tethered logs to the `"tethered"` logger via stdlib `logging`. To see log-only warnings, ensure your application has logging configured (e.g., `logging.basicConfig()`).

## Intersection semantics — `activate()` + `scope()`

- `activate()` sets a **process-wide ceiling**. No code anywhere in the process can reach destinations outside it.
- `scope()` creates a **temporary restriction** within the current context. It can only narrow the effective policy, never widen it.
- When both are active, the effective policy is the **intersection** — a connection must be allowed by both the global policy and every active scope.

```python
# Process ceiling: allow Stripe and Twilio
tethered.activate(allow=["*.stripe.com:443", "*.twilio.com:443"])

# Payment endpoint: scope restricts to Stripe only
# (tethered logs a warning that *.sendgrid.com has no overlap with the global policy)
with tethered.scope(allow=["*.stripe.com:443", "*.sendgrid.com:443"]):
    # *.stripe.com:443   — allowed (in both global and scope)
    # *.sendgrid.com:443 — blocked (not in global policy — scope cannot widen)
    # *.twilio.com:443   — blocked (not in scope)
    httpx.post("https://api.stripe.com/v1/charges")  # works
    httpx.post("https://api.sendgrid.com/v3/mail")   # raises EgressBlocked
```

## Nested scopes

Scopes nest naturally — each level further restricts:

```python
tethered.activate(allow=["*.stripe.com:443", "*.twilio.com:443", "db.internal:5432"])

with tethered.scope(allow=["*.stripe.com:443", "*.twilio.com:443"]):
    # db.internal:5432 is excluded by this scope

    with tethered.scope(allow=["*.stripe.com:443"]):
        # Now only *.stripe.com:443 is allowed
        httpx.post("https://api.stripe.com/v1/charges")    # works
        httpx.post("https://api.twilio.com/v1/messages")   # raises EgressBlocked
```
