# Cookbook — frameworks, servers, blocked connections

[← Back to README](../README.md)

- [Handling blocked connections](#handling-blocked-connections)
  - [Django / FastAPI middleware](#django--fastapi-middleware)
  - [Celery tasks](#celery-tasks)
  - [Retry decorators](#retry-decorators)
- [Servers and interpreter pools](#servers-and-interpreter-pools)
  - [uvicorn and FastAPI](#uvicorn-and-fastapi)
  - [gunicorn](#gunicorn)
  - [mod_wsgi](#mod_wsgi)
  - [Interpreter pools](#interpreter-pools)
- [For package authors](#for-package-authors)

## Handling blocked connections

`EgressBlocked` is a `RuntimeError`, not an `OSError`. This is intentional — a policy violation is not a network error and should not be silently caught by HTTP libraries or retry logic. You'll want to handle it explicitly at your application boundaries.

### Django / FastAPI middleware

Django — a middleware class:

```python
# middleware.py
import logging

import tethered
from django.http import HttpResponse

logger = logging.getLogger(__name__)


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

FastAPI — an exception handler, registered for the two shapes in which a refusal arrives:

```python
# main.py
import logging

import tethered
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
app = FastAPI()


def find_egress_blocked(exc: BaseException) -> tethered.EgressBlocked | None:
    """Return exc if it is an EgressBlocked, or the first one inside an exception group."""
    if isinstance(exc, tethered.EgressBlocked):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        for inner in exc.exceptions:
            found = find_egress_blocked(inner)
            if found is not None:
                return found
    return None


@app.exception_handler(tethered.EgressBlocked)
@app.exception_handler(ExceptionGroup)
async def egress_blocked_handler(request: Request, exc: Exception) -> JSONResponse:
    blocked = find_egress_blocked(exc)
    if blocked is None:
        raise exc  # an exception group with no EgressBlocked in it
    logger.error(
        "Egress blocked: %s:%s (resolved_from=%s)",
        blocked.host,
        blocked.port,
        blocked.resolved_from,
    )
    return JSONResponse({"detail": "Service unavailable"}, status_code=503)
```

The handler is registered twice because a refusal does not always arrive as a bare `EgressBlocked`. `httpx.AsyncClient` runs on anyio, and when tethered refuses its connection (a port rule, or a URL with a raw IP address) the exception comes out of an anyio task group as an `ExceptionGroup` ("unhandled errors in a TaskGroup") with the `EgressBlocked` inside. A handler registered for `tethered.EgressBlocked` alone does not match that, and neither does `except tethered.EgressBlocked`: the connection is blocked all the same, but the request ends as a 500. A refusal at the name lookup arrives bare, and so do the refusals that the synchronous httpx client, aiohttp and asyncio streams get. A group that carries no `EgressBlocked` is raised again, so other task-group failures end as the 500 they were before.

At a call site, `except*` catches both shapes:

```python
try:
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
except* tethered.EgressBlocked as group:
    blocked = find_egress_blocked(group)
    logger.error("Egress blocked: %s:%s", blocked.host, blocked.port)
    response = None
```

One refusal raises nothing where the call is made: `transport.sendto(data, addr)` on an unconnected asyncio datagram transport. The datagram is not sent; asyncio logs "Fatal write error on datagram transport", closes the transport and hands the `EgressBlocked` to the protocol's `connection_lost()`. A connected endpoint (`remote_addr=`) raises `EgressBlocked` from `create_datagram_endpoint()`.

All of this presupposes the standard asyncio event loop. Under uvloop, which uvicorn uses by default when it is installed, nothing that goes through the loop is blocked and the handler is never reached: see [uvicorn and FastAPI](#uvicorn-and-fastapi).

### Celery tasks

```python
# EgressBlocked is a RuntimeError, so autoretry_for=(ConnectionError, TimeoutError)
# already won't retry it — the task fails immediately on a policy violation.
@app.task(autoretry_for=(ConnectionError, TimeoutError))
def sync_data():
    requests.post("https://api.stripe.com/v1/charges", ...)
```

### Retry decorators

Retrying a policy block is pointless, and catching `EgressBlocked` around the retry wrapper is too late: a wrapper that retries on any exception has already retried it. Exclude it inside the retry policy itself:

```python
import time

import tethered


def retry_with_backoff(fn, attempts=3):
    for attempt in range(attempts):
        try:
            return fn()
        except tethered.EgressBlocked:
            raise  # policy violation — a retry cannot succeed
        except ConnectionError:
            if attempt == attempts - 1:
                raise
            time.sleep(2**attempt)
```

With a retry library, pass the exception types to retry explicitly (for example `ConnectionError`, `TimeoutError`) instead of retrying on every exception. `EgressBlocked` is a `RuntimeError`, so a policy limited to network errors never retries it.

## Servers and interpreter pools

What a deployment has to get right so that the policy is enforced in every process and interpreter that serves requests. Everything here was observed in container tests on Linux (x86-64, glibc) with Python 3.11 to 3.15, uvicorn 0.54, gunicorn 26.2, uvloop 0.23, gevent 26.9, FastAPI 0.143, httpx 0.28 on anyio 4.15, aiohttp 3.14, and Apache 2.4 with mod_wsgi 6.1. Other servers, and other platforms, were not tested. The limits behind this guidance are stated in [SECURITY.md](../SECURITY.md#what-tethered-does-not-protect-against).

### uvicorn and FastAPI

**Run on the standard asyncio event loop.** uvicorn runs on uvloop by default whenever uvloop is installed, as it is with `uvicorn[standard]`, and `fastapi run` starts uvicorn the same way. A uvloop event loop does its networking outside Python's `socket` module, and tethered sees nothing that goes through it. With an application built on the handler above and started by `fastapi run`, under a locked and fail-closed policy, a request whose endpoint called a forbidden host through `httpx.AsyncClient` returned HTTP 200 and the connection arrived: no exception, no log line. Start the server on the standard loop instead:

```bash
uvicorn main:app --loop asyncio
```

The same application was then blocked. It was also blocked under `fastapi run` once uvloop had been uninstalled (`pip uninstall uvloop`), because uvicorn then falls back to the standard loop.

Two ways to check a running server. tethered logs one warning when it finds uvloop loaded, at `activate()`, when a scope is entered, or at the first socket created under either; it starts with `tethered: uvloop is loaded in this process.` and ends with `Run the application on the standard asyncio event loop for enforcement (uvicorn: --loop asyncio).` And inside the application, `type(asyncio.get_running_loop()).__module__` is `uvloop` on a uvloop loop.

Under uvloop the gap is not the same for every library. Blocking `socket` code is still checked, also when it runs through `asyncio.to_thread` or in one of FastAPI's synchronous (`def`) endpoints. aiohttp fails the other way: its connection is checked but the lookup uvloop made for it is not seen, so an allowed hostname is refused as a bare IP address. Launches through `asyncio.create_subprocess_exec` / `create_subprocess_shell` are not seen at all.

**Workers.** With `--workers N`, each worker activates when it imports the application, and the supervisor process holds no policy. Workers that replace others (after a kill, or with `--limit-max-requests`) enforce as well. When the launching script calls `activate()` before `uvicorn.run(..., workers=N)`, the workers inherit the policy at start-up, locked if it is locked and also under `external_subprocess_policy="block"`, and the identical `activate()` in the application module is a no-op there.

**An uncaught `EgressBlocked`** in an endpoint ends the request with a 500 and "Exception in ASGI application" in the log. The worker keeps serving.

### gunicorn

**With sync and gthread workers** every worker enforces the policy, with and without `--preload`, on Python 3.11 to 3.15. That includes the workers that replace others under `--max-requests`, and the workers started by a `SIGHUP` reload (checked on Python 3.13). An uncaught `EgressBlocked` ends the request with a 500 and a traceback in the error log; the worker survives.

**`-k uvicorn.workers.UvicornWorker`** runs on uvloop when it is installed and is then not enforced, as described above. The tests did not include a configuration of this worker on the standard loop, so if you use it, confirm the loop with the two checks above.

**`-k gevent`**: connections are enforced. A process launch is seen differently, as `os.exec*` events inside the forked child, one for each `PATH` directory that is tried. `external_subprocess_policy="block"` and the locked-mode check of the launch environment still refuse it. Under the default `"warn"`, the warning is written to the stderr of that forked child, so it ends up in the output the application captures from its subprocess and not in the server log.

**Launching processes from a request handler**, under a locked policy:

| Launch | Result |
|---|---|
| `[sys.executable, ...]` | The child inherits the locked policy and enforces it. |
| `["python3", ...]` | Warned about as external, although this child does inherit. Refused under `"block"`. |
| `[sys.executable, ...]` with an `env=` that lacks `_TETHERED_CHILD_POLICY` | Refused: `SubprocessBlocked` ("env strips _TETHERED_CHILD_POLICY"). |
| `[sys.executable, "-S", ...]` | Warned about; the child has no policy. Refused under `"block"`. |
| `["bash", ...]` | Warned about; the child can reach anything. Refused under `"block"`. |

So launch Python children with `sys.executable`, and when you pass `env=`, build it from `os.environ` so that it carries the policy variable.

**`--preload`, a locked policy and `SIGUSR2`.** For a binary upgrade gunicorn re-executes itself with the environment it saved when it started. Under `--preload` that was before the application called `activate()`, so the saved environment lacks `_TETHERED_CHILD_POLICY`, and locked mode refuses the `os.execvpe` like any other launch that strips the variable (`SubprocessBlocked`). gunicorn does not recover cleanly from that: in the test it stopped both workers, unlinked its unix listening socket and about 30 seconds later deleted the pid file, while the old master kept serving over TCP and started new workers. Without tethered the upgrade works, and with an unlocked policy too, which only logs a warning. To keep it working under a lock, copy the variable into the saved environment in a `pre_exec` server hook:

```python
# gunicorn.conf.py
import os


def pre_exec(server):
    payload = os.environ.get("_TETHERED_CHILD_POLICY")
    if payload is not None:
        server.cfg.env_orig["_TETHERED_CHILD_POLICY"] = payload
```

The new master then auto-activates the locked policy as it starts, and its own `activate()` is the idempotent no-op (checked on Python 3.13).

**Interpreter pools under `--preload`.** Do not start an `InterpreterPoolExecutor` worker at import time, which under `--preload` is in the master process: every worker process forked afterwards died with `SIGSEGV`, with or without tethered. Create the pool in the worker process, when it is first needed.

### mod_wsgi

mod_wsgi runs each application group in an interpreter of its own, and by default creates that interpreter when the group gets its first request. A locked tethered policy belongs to the process, not to the application group: one interpreter takes the lock, and the others either join it as they start or are left outside it with no network. The guidance below follows from that. The outcomes were the same on Python 3.11 to 3.14 with mod_wsgi 6.1.

**One application per process works.** It works in the default application group, where the application runs in a subinterpreter and takes the lock there, and in `%{GLOBAL}`; in daemon mode and in embedded mode; and through stop, graceful restart, and `maximum-requests` and `inactivity-timeout` recycling. `mod_wsgi-express` with its defaults (main interpreter, preloaded) works as it is. Give each application a daemon process group of its own:

```apache
WSGIDaemonProcess shop python-home=/opt/venv processes=2 threads=15
WSGIScriptAlias /shop /srv/shop/wsgi.py
<Location /shop>
    WSGIProcessGroup shop
</Location>
```

**Use `python-home`, not `python-path`,** to point mod_wsgi at a virtual environment. With `python-path`, mod_wsgi adds the directory with `site.addsitedir()` after the interpreter has started. tethered then logs "tethered.pth not found ... Python child processes will NOT auto-inherit", a second application group cannot join the lock ("a policy can only be joined once, while an interpreter starts, and this interpreter's startup is over"), and `sys.executable` remains the system Python, so with tethered installed only in the virtual environment a Python child of the lock holder runs without it.

**Two application groups in one process, loaded lazily, race for the lock.** Lazy loading is the default. When the first requests for both applications arrive together, the interpreter of the second already exists at the moment the first application takes the lock. It is outside the lock: its `activate()` raises `TetheredLocked`, also for the identical policy, and it has no network at all, loopback included. If the application lets that exception out of its WSGI script, mod_wsgi tries the import again on every request, and every request is a 500. In a concurrent cold start this happened in 24 of 24 processes on Python 3.11 to 3.13 and in 23 of 24 on 3.14, which application lost varied, and embedded mode and `WSGIPerInterpreterGIL On` made no difference. When the first requests come one after the other, the first application holds the lock, the interpreter of the second joins as it starts, and its identical `activate()` is a no-op; a deployment cannot count on that order.

What avoids the race is one `WSGIDaemonProcess` per application, as above, or loading every script of the process at process start with `WSGIImportScript`, the script that takes the lock first:

```apache
WSGIDaemonProcess apps python-home=/opt/venv processes=2 threads=15

WSGIScriptAlias /shop /srv/shop/wsgi.py
<Location /shop>
    WSGIProcessGroup apps
    WSGIApplicationGroup shop
</Location>
WSGIScriptAlias /blog /srv/blog/wsgi.py
<Location /blog>
    WSGIProcessGroup apps
    WSGIApplicationGroup blog
</Location>

# shop calls activate(locked=True): import it first
WSGIImportScript /srv/shop/wsgi.py process-group=apps application-group=shop
WSGIImportScript /srv/blog/wsgi.py process-group=apps application-group=blog
```

With both scripts preloaded in that order, 24 of 24 processes came up correctly. In the other order the application that is imported before the lock is taken is locked out every time.

**One policy per process.** With different locked policies in two groups, the application that comes second gets `TetheredLocked`, and if it catches the exception it runs under the first application's policy. An application in the same process that does not use tethered at all is covered too: when its interpreter is created after the lock it joins and is restricted by the other application's policy, and when it was created before, it has no network. Unlocked policies in different groups each enforce their own inside the process, but they share the one `_TETHERED_CHILD_POLICY` variable: a Python child launched by either application gets the policy of whichever application activated last, and an interpreter created afterwards is restricted by that policy even if its application never imported tethered. Applications that need different policies need different daemon processes.

**Do not mix `%{GLOBAL}` with other application groups in one process.** A request for the `%{GLOBAL}` group that is handled by a worker thread which has served a subinterpreter group before runs inside that subinterpreter. This was reproduced without tethered installed; in one run on Python 3.12, 196 of 200 `%{GLOBAL}` requests ran in the subinterpreter. With tethered the result is no network on some requests and the other application's policy on others.

**Reloading a WSGI script.** In embedded mode a script that is reloaded with a changed policy gets `TetheredLocked`, and requests are answered with a 500 until Apache is restarted; reloaded with the same policy, its `activate()` is a no-op. In daemon mode touching the script restarts the process, and the new policy is in place.

**Subprocesses from a handler** under a lock: a Python child inherits the locked policy; a non-Python child is launched with a warning, or refused under `external_subprocess_policy="block"`.

### Interpreter pools

`concurrent.futures.InterpreterPoolExecutor` (Python 3.14 and later) under a locked policy:

- **A worker joins the lock if its interpreter starts under it.** What counts is when the interpreter starts, not when the executor object is created: an executor built before the lock and first used after it joins. Workers are started on demand, so a pool can end up mixed. With `max_workers=2`, one worker warmed up before the lock and one started afterwards gave both outcomes within one request. Take the lock first and submit the first task afterwards.
- **A joined worker** reaches what the policy allows, loopback included, and gets the ordinary `EgressBlocked` for the rest. `deactivate()` and an `activate()` with a different policy raise `TetheredLocked` there, and the identical `activate()` is a no-op. A Python child launched from a task inherits the locked policy. An uncaught `EgressBlocked` reaches the submitter as `tethered.EgressBlocked`, chained from the interpreter's `ExecutionFailed`, so `except tethered.EgressBlocked` around `future.result()` works.
- **A worker outside the lock** is refused everything, the allowed hosts and loopback included, and nothing is logged. The exception is `RuntimeError` until tethered has been imported in that interpreter and `EgressBlocked` afterwards; process launches raise `SubprocessBlocked`.
- **Task functions that live in the application module** make the worker import that module, which runs its `activate()` again. In a joined worker that is the no-op. In a worker outside the lock, the submitter gets `concurrent.interpreters.NotShareableError`, caused by the `TetheredLocked` raised there.
- **Logging is configured per interpreter.** Until it is configured in a worker, tethered's refusals there appear as bare `tethered: blocked ...` lines.

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

### `scope()` in generators and under asyncio

`@tethered.scope` cannot decorate a generator or async generator function; it raises `TypeError`. Inside a generator, wrap each I/O call in its own `with tethered.scope(...)` block and do not `yield` inside one. A scope that is open across a `yield` stays active in the consumer's context until the generator resumes, so your caller's code would run under your restriction.

```python
def iter_pages(client):
    url = FIRST_PAGE
    while url:
        with tethered.scope(allow=["api.mylib.com:443"], label="mylib.iter_pages"):
            page = client.get(url).json()  # the I/O call is scoped
        yield page["items"]  # no scope is open across the yield
        url = page.get("next")
```

When your library is used from asyncio:

- **Lookups run in an executor thread.** asyncio resolves names with `loop.getaddrinfo`, which runs in a thread that does not carry your scope. The scope's DNS-time check does not apply to that lookup; the connection that follows is checked against the scope. If the host application has called `activate()`, its policy does apply to the lookup.
- **Await tasks inside the block.** A task created inside a `with tethered.scope(...)` block keeps the scope after the block exits. If the application has not called `activate()`, a hostname such a task looks up after the block has exited is no longer recorded, and its connection is blocked.
- **uvloop.** On a uvloop event loop, nothing your library does through the loop raises an audit event: connections, lookups, datagrams and `asyncio.create_subprocess_exec` launches are not checked against your scope at all, and nothing is logged for them. tethered logs a one-time warning when a scope is entered with uvloop loaded. uvicorn uses uvloop by default when it is installed, so this is a common setup and not an exotic one.
- **Windows.** On the default `ProactorEventLoop`, connections raise no audit event, so your scope's connect-time check does not run. tethered logs a one-time warning.
- **The event loop belongs to the application**, so a library can fix neither of the two. State in your documentation that enforcement under asyncio needs asyncio's own selector event loop: not uvloop, and on Windows `asyncio.SelectorEventLoop` in place of the default `ProactorEventLoop`.
- **`httpx.AsyncClient` wraps connect-time refusals.** A refused connection reaches your code inside an `ExceptionGroup`, which `except tethered.EgressBlocked` does not catch; use `except*` (see [Django / FastAPI middleware](#django--fastapi-middleware)). Keep that in mind for the wrapper patterns below, which are written with a plain `except`.

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

The hint travels with the scope through subprocess auto-propagation, so a child process launched through `subprocess` inside your scope and blocked on the same call sees the same guidance. (Spawn-mode `multiprocessing` workers do not receive scopes; see [SUBPROCESS.md](SUBPROCESS.md#scopes-propagate-to-subprocesses-too).)

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
