# Cookbook — handling blocked connections

[← Back to README](../README.md)

- [Django / FastAPI middleware](#django--fastapi-middleware)
- [Celery tasks](#celery-tasks)
- [Retry decorators](#retry-decorators)
- [For package authors](#for-package-authors)

`EgressBlocked` is a `RuntimeError`, not an `OSError`. This is intentional — a policy violation is not a network error and should not be silently caught by HTTP libraries or retry logic. You'll want to handle it explicitly at your application boundaries.

## Django / FastAPI middleware

```python
# middleware.py
import tethered

class EgressBlockedMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            return self.get_response(request)
        except tethered.EgressBlocked as e:
            logger.error("Egress blocked: %s:%s (resolved_from=%s)", e.host, e.port, e.resolved_from)
            return HttpResponse("Service unavailable", status=503)
```

## Celery tasks

```python
# EgressBlocked is a RuntimeError, so autoretry_for=(ConnectionError, TimeoutError)
# already won't retry it — the task fails immediately on a policy violation.
@app.task(autoretry_for=(ConnectionError, TimeoutError))
def sync_data():
    requests.post("https://api.stripe.com/v1/charges", ...)
```

## Retry decorators

```python
# Catch EgressBlocked before your retry logic — retrying a policy block is pointless
try:
    response = retry_with_backoff(make_request)
except tethered.EgressBlocked:
    raise  # don't retry policy violations
except ConnectionError:
    handle_network_failure()
```

## For package authors

Patterns for libraries that want to use tethered for self-defense without interfering with the host application.

### Use `scope()`, never `activate()`

`activate()` is process-wide. A library doesn't own the process — the application does. Calling `activate()` from a library would override the host application's policy and is treated as hostile. Use `scope()`: it's context-local, intersection-only (can never widen the host's policy), and safe to combine with whatever the host already has set up.

```python
import tethered

class WeatherClient:
    @tethered.scope(
        allow=["api.weatherapi.com:443"],
        label="WeatherClient.get_forecast",
    )
    def get_forecast(self, city: str) -> str:
        # nothing in this method or what it calls can reach
        # anything except api.weatherapi.com:443
        ...
```

The `label=` is what users will see in `EgressBlocked.scope_label` and tethered's log messages when this scope blocks something. Use a descriptive name (`"<class>.<method>"` or `"<module>.<function>"`) so blocks are attributable to your library, not to a generic `"scope(api.weatherapi.com:443)"` derived from the allow list. Without `label=`, tethered auto-derives the label from the first few allow rules.

### Surface actionable guidance via `hint=`

When a `scope()` blocks a connection inside your library, the host process sees `EgressBlocked` with a default message that names the host and the scope label — but not what to do next. `hint=` gives you a single source of truth for the egress contract (and the docs URL) so that one line of guidance lands in the host's traceback automatically:

```python
@tethered.scope(
    allow=["api.weatherapi.com:443"],
    label="WeatherClient.get_forecast",
    hint=(
        "WeatherClient needs api.weatherapi.com:443. "
        "If your app uses tethered.activate(), add it to the allowlist. "
        "See https://example.com/weatherclient#security-model"
    ),
)
def get_forecast(self, city: str) -> str:
    ...
```

The hint surfaces both as `EgressBlocked.scope_hint` (a `str | None` attribute readable by host code) and as a trailing `Hint: …` line on the default exception message.

**When does the hint fire?** Whenever any `EgressBlocked` is raised while a hinted `scope()` is on the stack — regardless of which layer produced the block:

- **Your own scope blocks** — destination outside the scope's allowlist. This is the primary case; it works whether or not the host has called `activate()` at all, since `scope()` self-enforces.
- **An inner (nested) scope blocks** — for example, a sub-helper inside your library entered a tighter `scope()` of its own. Your outer scope's hint still surfaces (the deepest hinted scope on the stack wins; an unhinted inner scope falls through to the outer hint).
- **The host's `activate()` policy blocks** — the host has tethered configured but forgot to allowlist your endpoint. Your guidance still reaches them.
- **An outer scope set by the host or a higher-level library blocks** — same rule. App developers combining `activate()` with `scope()` can put their own `hint=` on outer scopes (e.g. `scope(allow=["*.stripe.com"], hint="Payment flow — only Stripe is reachable here")`) and have it surface through any block downstream that doesn't set its own.

So `hint=` is useful in three audiences' code:

1. **Library authors** publishing a package — attach the egress contract and docs URL once at the scope.
2. **App developers** using `scope()` to tighten request handlers, jobs, or calls into third-party packages — attach context about the call site.
3. **Mixed setups** with `activate()` + nested scopes — outer scopes can guide the developer about which surface they're in even when an inner scope or the global ceiling is what rejected the call.

`hint=` does not replace per-package CLI translation. If your package presents bespoke error UX (e.g. raising `ClickException` from a CLI), keep doing that — the wrapper can read `exc.scope_hint` and forward it without duplicating the contract in code:

```python
import click

try:
    return _do_fetch()
except tethered.EgressBlocked as exc:
    raise click.ClickException(exc.scope_hint or str(exc)) from exc
```

The hint travels with the scope through subprocess auto-propagation, so a worker process spawned inside your scope and blocked on the same call sees the same guidance.

#### A note on Unicode in hints (and labels)

Tethered stores `hint=` and `label=` as Python `str` and round-trips them through subprocess auto-propagation as JSON (`ensure_ascii=True`, so non-ASCII characters cross the env-var boundary as `\uXXXX` and are decoded back losslessly in the child). Whether a non-ASCII character *renders* correctly in the host's traceback or log output depends on the host's stdio / log-handler encoding — not on tethered. Modern Python (UTF-8 default on Windows from 3.15, and on Linux/macOS since forever) handles arbitrary Unicode fine; legacy non-UTF-8 environments may mis-render exotic characters. ASCII is always safe; common Latin-1 / cp1252 typography (en/em dashes, curly quotes, ellipsis) is safe almost everywhere; CJK, Cyrillic, Arabic, and emoji are the higher-risk cases on legacy hosts. If you ship to environments where you can't assume UTF-8 stdio, prefer ASCII for hints and labels — the same advice that already applies to every exception message and log line in any Python library.

### Adding `tethered` to your deps imposes `tethered.pth` on every downstream

`tethered` ships a top-level `tethered.pth` file that CPython's `site.py` processes at every interpreter startup (the same mechanism `coverage.py` uses for subprocess instrumentation). By depending on tethered, your library installs that `.pth` into every consumer's environment — even consumers who never directly import your library. The `.pth` is a one-line short-circuit that costs ~50µs when `_TETHERED_CHILD_POLICY` is unset (the common case), but it IS a global side effect of your dependency. Mention it in your release notes; security-conscious teams will want to know.

### Route scope blocks to your library's logger

`scope()` accepts an `on_blocked=(host, port) -> None` callback. Use it to surface unexpected blocks under your library's own logger so users can attribute the event to your library, not to tethered itself:

```python
import logging
import tethered

mylib_log = logging.getLogger("mylib.security")

def _on_block(host: str, port: int | None) -> None:
    mylib_log.warning(
        "mylib unexpected egress to %s:%s — likely a bug; please file an issue",
        host, port,
    )

@tethered.scope(allow=["api.mylib.com:443"], on_blocked=_on_block)
def fetch_data(): ...
```

Tethered will still log under the `"tethered"` logger as well — your callback is additive, not a replacement (today). If you want to fully isolate the event from the `"tethered"` namespace, configure a logging filter on `"tethered"` or wrap the call as shown below.

### Wrap `EgressBlocked` in a library-specific exception

When `tethered.EgressBlocked` propagates from inside your library, the user's traceback shows your library's stack — but the exception class is `tethered.EgressBlocked`. Wrapping it in a library-specific exception with `from e` gives users a class they can catch with library-aware semantics, and lets you decorate the message with library context:

```python
class MyLibPolicyViolation(RuntimeError):
    """Raised when mylib code attempted unexpected egress."""

@tethered.scope(allow=["api.mylib.com:443"])
def fetch_data():
    try:
        return _do_fetch()
    except tethered.EgressBlocked as e:
        raise MyLibPolicyViolation(
            f"mylib attempted egress to {e.host} (scope={e.scope_label}); "
            "this is a bug — please file an issue"
        ) from e
```

The `EgressBlocked.scope_label` attribute carries the human-readable label of the scope that blocked the call (e.g. `"scope(api.mylib.com:443)"`), or `None` if the block came from the host's global policy. Use it to attribute blocks to the right scope when multiple are nested.

### Make `tethered` a regular runtime dependency

Don't try to "soft-depend" on tethered (`try: import tethered; except ImportError: pass`). Partial activation is worse than no activation — half your code paths defended, half not, with no consistent signal to users about which is which. If your library's threat model justifies tethered, depend on it unconditionally and document the egress contract in your README so users know what hosts your library is allowed to reach.
