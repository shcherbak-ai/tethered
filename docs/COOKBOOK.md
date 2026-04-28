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
