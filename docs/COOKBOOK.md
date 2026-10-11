# Cookbook — frameworks, servers, blocked connections

[← Back to README](../README.md)

- [Handling blocked connections](#handling-blocked-connections)
  - [Django / FastAPI middleware](#django--fastapi-middleware)
  - [Celery tasks](#celery-tasks)
  - [Retry decorators](#retry-decorators)
- [Servers and interpreter pools](#servers-and-interpreter-pools)
  - [The launcher pattern](#the-launcher-pattern)
  - [uvicorn and FastAPI](#uvicorn-and-fastapi)
  - [gunicorn](#gunicorn)
  - [hypercorn and Quart](#hypercorn-and-quart)
  - [granian](#granian)
  - [sanic](#sanic)
  - [aiohttp](#aiohttp)
  - [daphne and Twisted](#daphne-and-twisted)
  - [tornado](#tornado)
  - [uWSGI](#uwsgi)
  - [waitress](#waitress)
  - [mod_wsgi](#mod_wsgi)
  - [Flask and Django](#flask-and-django)
  - [Changing a locked policy](#changing-a-locked-policy)
  - [Celery and other task queues](#celery-and-other-task-queues)
  - [Process pools and the fork server](#process-pools-and-the-fork-server)
  - [Interpreter pools](#interpreter-pools)
- [For package authors](#for-package-authors)

## Handling blocked connections

`EgressBlocked` is a `RuntimeError`, not an `OSError`. This is intentional — a policy violation is not a network error and should not be silently caught by HTTP libraries or retry logic. You'll want to handle it explicitly at your application boundaries.

### Django / FastAPI middleware

Django — a middleware class with `process_exception()`:

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
        return self.get_response(request)

    def process_exception(self, request, exception):
        if not isinstance(exception, tethered.EgressBlocked):
            return None
        logger.error(
            "Egress blocked: %s:%s (resolved_from=%s)",
            exception.host,
            exception.port,
            exception.resolved_from,
        )
        return HttpResponse("Service unavailable", status=503)
```

Add it to `MIDDLEWARE` in the settings. The hook is what matters: Django turns an exception that a view lets out into a 500 response before `get_response()` returns to the middleware that called it, so a `try` / `except tethered.EgressBlocked` around `get_response()` never sees the refusal. `process_exception()` is what Django calls with the exception instead. Earlier versions of this page printed the `try` / `except` form; with it the connection is refused all the same, but the request ends as a 500 and nothing is logged by the middleware.

Flask — register an error handler with `@app.errorhandler(tethered.EgressBlocked)`; it is reached for a refused lookup and for a refused connection.

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

The handler is registered twice because a refusal does not always arrive as a bare `EgressBlocked`. `httpx.AsyncClient` runs on anyio, and when tethered refuses its connection (a port rule, or a URL with a raw IP address) the exception comes out of an anyio task group as an `ExceptionGroup` ("unhandled errors in a TaskGroup") with the `EgressBlocked` inside. A handler registered for `tethered.EgressBlocked` alone does not match that, and neither does `except tethered.EgressBlocked`: the connection is blocked all the same, but the request ends as a 500. A refusal at the name lookup arrives bare, and so do the refusals that the synchronous httpx client, aiohttp and asyncio streams get. A group that carries no `EgressBlocked` is raised again, so other task-group failures end as the 500 they were before. For a refusal at the lookup the handler logs `Egress blocked: forbidden.example:None (resolved_from=None)`: a name is refused whatever the port, so `EgressBlocked.port` is `None` there.

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

All of this is on the standard asyncio event loop, which is the only one tethered enforces on. uvicorn prefers uvloop when it is installed; with a policy active it falls back to the standard loop or does not start, depending on how it is started: see [uvicorn and FastAPI](#uvicorn-and-fastapi).

### Celery tasks

```python
# EgressBlocked is a RuntimeError, so autoretry_for=(ConnectionError, TimeoutError)
# already won't retry it — the task fails immediately on a policy violation.
@app.task(autoretry_for=(ConnectionError, TimeoutError))
def sync_data():
    requests.post("https://api.stripe.com/v1/charges", ...)
```

`autoretry_for=(OSError,)` does not retry a refused task either; `autoretry_for=(Exception,)` does. The task ends in the state `FAILURE` with the traceback in the worker's log, and the worker keeps running. Where to call `activate()` in a worker, for Celery and for RQ, Dramatiq, Huey and arq, is under [Celery and other task queues](#celery-and-other-task-queues).

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

What a deployment has to get right so that the policy is enforced in every process and interpreter that serves requests. This section is written from container suites that run the real servers on Linux (x86-64, glibc) with Python 3.11 to 3.15. [COMPATIBILITY.md](COMPATIBILITY.md) has the full tables, the version each row was measured with and the suite behind it, and what was not tested. A statement that no suite asserts says "measured once"; the notes on `InterpreterPoolExecutor` that go beyond joining a lock, and the one on interpreter pools under gunicorn's `--preload`, come from earlier container runs on Python 3.14 and are not part of a suite either. The limits behind this guidance are stated in [SECURITY.md](../SECURITY.md#what-tethered-does-not-protect-against).

Three rules cover most of it:

- **Activate before the server, where you can.** A policy that is active when the server is imported is inherited by every worker it starts, and keeps uvloop from being loaded. The [launcher pattern](#the-launcher-pattern) does that for any server.
- **On asyncio, tethered runs on the standard event loop only.** With a policy active, `import uvloop` raises `ImportError`; with uvloop already loaded, `activate()` raises `RuntimeError`. A server that picks uvloop on its own either falls back to the standard loop or does not start. It never serves without the policy, with the exceptions listed under [uvicorn and FastAPI](#uvicorn-and-fastapi).
- **A locked policy is one per process, and it survives a re-execution.** Take the lock before other interpreters of the process exist, and stop and start the server to change it ([changing a locked policy](#changing-a-locked-policy)).

### The launcher pattern

A script that calls `activate()` and only then imports and starts the server. It works with every server tested, whatever the server imports first and whichever event loop it prefers, because the policy is in place before any of that happens:

```python
# serve.py
import tethered


def main():
    tethered.activate(
        allow=["api.stripe.com:443", "db.internal:5432"],
        locked=True,
        lock_token=object(),
    )

    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, workers=2)


if __name__ == "__main__":
    main()
```

Run it with `python serve.py`. The workers are new Python processes: each inherits the locked policy as it starts, before it imports anything of the server or the application, and a worker that replaces a dead one does too. If `main.py` calls `activate()` with the same policy, that call is a no-op in the workers. The activation is under the `__main__` guard because a worker runs this file again, as multiprocessing's `__mp_main__`; without the guard the call is repeated there, which is the same no-op.

The same shape works for granian (`from granian import Granian`), sanic, waitress (`from waitress import serve`), daphne, and for a container entry point that ends by executing a server that is not Python, such as Apache or supervisord: the policy travels in the environment of the process. Executing a program that is not Python is an external launch, so such an entry point is logged under the default `external_subprocess_policy="warn"` and cannot use `"block"`.

### uvicorn and FastAPI

uvicorn runs on uvloop whenever uvloop is installed, as it is with `uvicorn[standard]` and `fastapi[standard]`, unless it is told otherwise. What happens with a policy depends on whether uvicorn imports the application, and with it the policy, before it asks for uvloop. That order differs between uvicorn releases and between ways of starting it, so do not rely on it: **name the loop.**

```bash
uvicorn main:app --loop asyncio
uvicorn main:app --loop asyncio --workers 4
uvicorn main:app --loop asyncio --reload
```

`UVICORN_LOOP=asyncio` in the environment does the same for the `uvicorn` command, and only for the command: `uvicorn.run()` and `fastapi run` do not read it. In a script, pass the argument: `uvicorn.run("main:app", loop="asyncio")`, with `workers=N` if you want workers.

Without the loop named, with uvloop installed and an application that calls `activate()` when it is imported:

| How it is started | uvicorn 0.54 | uvicorn 0.46 |
|---|---|---|
| `uvicorn main:app` | Works: the import of uvloop is refused and uvicorn falls back to the standard loop. One warning is logged (`tethered: refused to load uvloop while a policy is active`). | Does not start: `RuntimeError` from `activate()`. |
| `uvicorn main:app --workers N` or `--reload` | Never serves: every worker dies at `activate()` and the supervisor keeps starting new ones. | Never serves. |
| `uvicorn.run("main:app")` | Works. | Does not start. |
| `uvicorn.run("main:app", workers=N)` | Never serves. | Not tested. |
| The [launcher pattern](#the-launcher-pattern), with or without workers | Works. | Works. |

uvicorn 0.47.0 is the first release that imports the application before it chooses the loop, and from 0.50.0 its worker and reload processes choose the loop first again (measured once per release, not part of a suite).

**`fastapi run`** has no option for the event loop. `fastapi run main.py`, or `fastapi run` finding `main.py` on its own, imports the application itself, so the policy is active before uvicorn starts: it works, with `--workers` too, and so does `fastapi dev`. With `--entrypoint main:app` (or the entry point in `pyproject.toml`) the import is left to uvicorn: that works in one process with uvicorn 0.54, does not start with uvicorn 0.46, and never serves with `--workers`. Give `fastapi run` the path, or serve with `uvicorn main:app --loop asyncio --workers N`.

**Activate at import, not in a lifespan handler.** By the time a lifespan handler runs, uvicorn has chosen its loop. With FastAPI or Starlette the server then exits ("Application startup failed. Exiting."), which is at least loud. With a hand-written ASGI lifespan handler, uvicorn's default `--lifespan auto` takes the `RuntimeError` for "this application does not support lifespan" and serves on uvloop **with no policy**; the only trace is the error line `tethered: activate() refused — uvloop is loaded in this process.` in the log. With the loop named, activation in a lifespan handler works.

**Where uvloop still ends up in the process.** A `log_only` policy refuses nothing, uvloop included: the server runs on uvloop and nothing that goes through the loop is reported, so a log-only rollout of an asyncio application tells you nothing about its asynchronous calls unless the loop is named. A `scope()` with no `activate()` under it does not keep uvloop out either, and on uvloop it is not applied to `asyncio.open_connection` or `loop.create_connection`. In both cases tethered logs one warning that starts with `tethered: uvloop is loaded in this process.`

**Two ways to check a running server.** Inside the application, `type(asyncio.get_running_loop()).__module__` is `uvloop` on a uvloop loop and, on Linux, `asyncio.unix_events` on the standard one. And the log: `tethered: refused to load uvloop while a policy is active` means that the server asked for uvloop and fell back; with the loop named, nothing is logged.

**Workers.** With the loop named, each worker activates when it imports the application, and the supervisor process holds no policy. A worker that replaces a killed one enforces as well. With the launcher pattern the supervisor holds the policy and the workers inherit it at start-up, locked if it is locked and also under `external_subprocess_policy="block"`.

**An uncaught `EgressBlocked`** in an endpoint ends the request with a 500 and "Exception in ASGI application" in the log. The worker keeps serving.

### gunicorn

**With sync and gthread workers** every worker enforces the policy, with and without `--preload`. That includes the workers that replace others under `--max-requests` and the workers started by a `SIGHUP` reload. An uncaught `EgressBlocked` ends the request with a 500 and a traceback in the error log; the worker survives.

**`-k uvicorn.workers.UvicornWorker`** and the `uvicorn-worker` package's `-k uvicorn_worker.UvicornWorker` work as they are, with uvloop installed, with and without `--preload`: the worker imports the application before it asks uvicorn for its loop, the import of uvloop is refused, and the worker runs on the standard loop. Replaced workers do the same. This holds for uvicorn 0.54 and 0.46; with uvicorn 0.35 the worker set its loop up first and did not boot without `--preload` (measured once). gunicorn's own `-k asgi` worker sets its loop up first: use it with `--preload` or `--asgi-loop asyncio`, otherwise gunicorn exits with "Worker failed to boot."

**`-k gevent`** and `-k gevent_pywsgi`: connections are enforced, in every worker and for greenlets that overlap. Three things are particular to gevent.

- A refused name lookup now and then never returns. tethered logs the refusal from one of gevent's resolver threads, and after monkey-patching the lock of a logging handler is gevent's: when several of those threads log at the same moment, one of them is sometimes never woken. The request hangs, and a worker that is told to restart or stop waits for it until `--graceful-timeout` (30 seconds by default). In stress runs on Python 3.13 with gevent 26.9 this happened in about one in ten new processes that refused several lookups at once; a plain audit hook that logs and raises did the same with no tethered in the process, and one that only raises did not. One mitigation was measured: with `logging.getLogger("tethered").setLevel(logging.ERROR)`, tethered writes no warning for a refusal, and none of 180 processes had a stuck greenlet. Take it for what it is: a measurement, at the price of tethered's own log line for each refusal (the exception is still raised, so log refusals where you catch them). A shorter `--graceful-timeout` limits how long a stuck request can hold a worker.
- gevent's hub prints a traceback for every refused lookup, in addition to tethered's warning. Telling the hub that `EgressBlocked` is not its error silences that:

  ```python
  def _quiet_refusals() -> None:
      import gevent

      import tethered

      hub = gevent.get_hub()
      if tethered.EgressBlocked not in hub.NOT_ERROR:
          hub.NOT_ERROR += (tethered.EgressBlocked,)
  ```

  Call it from the worker, for example at the start of a request.
- A process launch is seen differently, as `os.exec*` events inside the forked child, one for each `PATH` directory that is tried. `external_subprocess_policy="block"` still refuses an external launch, and a Python child still inherits the policy. What changes is where tethered's log lines go: they are written to the stderr of that forked child, so they end up in the output the application captures from its subprocess and not in the server log. Under `"block"` with captured stderr the refusal is logged nowhere; the `SubprocessBlocked` exception is all there is.

With `GEVENT_RESOLVER=ares` lookups are made by c-ares, which tethered does not see: hosts the allow list names are refused, and names are sent to the DNS server unchecked. Use gevent's default resolver.

**`-k tornado`**: enforced. An exception the application lets out gets no response at all; tornado logs it and leaves the connection open, with or without tethered. Catch `EgressBlocked` in the application.

**Launching processes from a request handler**, under a locked policy:

| Launch | Result |
|---|---|
| `[sys.executable, ...]` | The child inherits the locked policy and enforces it. |
| `[sys.executable, ...]` with an `env=` that lacks `_TETHERED_CHILD_POLICY` | The child is given the variable and inherits the locked policy. |
| `["python3", ...]` | Warned about as external, although this child does inherit. Refused under `"block"`. |
| `[sys.executable, "-S", ...]` | Warned about; the child has no policy. Refused under `"block"`. |
| `["bash", ...]` | Warned about; the child can reach anything. Refused under `"block"`. |

So launch Python children with `sys.executable`.

**Binary upgrade (`SIGUSR2`).** It works as it is, with a locked policy too, with and without `--preload`. gunicorn re-executes itself with the environment it saved when it started, which under `--preload` lacks the policy variable; tethered carries that exec out with the variable added and logs `tethered: os.exec*(...) was given an environment without _TETHERED_CHILD_POLICY; carried out with the locked policy added`. The new master starts under the policy, its own `activate()` is the idempotent no-op, and a client that kept requesting during the upgrade saw no failed request. The `pre_exec` hook that earlier versions of this page printed is no longer needed; it does no harm where it is still in place.

**Interpreter pools under `--preload`.** Do not start an `InterpreterPoolExecutor` worker at import time, which under `--preload` is in the master process: every worker process forked afterwards died with `SIGSEGV`, with or without tethered. Create the pool in the worker process, when it is first needed.

### hypercorn and Quart

hypercorn's master never imports the application; every worker is a new Python process that does. With the default asyncio worker nothing has to be configured: `hypercorn main:app` with `activate()` at the top of `main.py` is enforced, with `--workers`, with workers started after `--max-requests`, a `SIGHUP` or `--reload`, and with `serve()` called from a script. Quart is enforced under hypercorn, with `quart run` and with `app.run()`.

- **`-k trio`** is enforced: trio does its networking through Python's `socket` module.
- **`-k uvloop`** does not start under a policy, and there is nothing to fall back to: that worker class asked for uvloop.
- To hold the policy in the master, call `activate()` in a configuration file (`hypercorn -c file:conf.py main:app`); the workers inherit it. Leave only plain values in that file's namespace: hypercorn copies every name that is not a module into its configuration and pickles it for the workers.

### granian

granian imports every event-loop package it finds as soon as granian itself is imported, in the main process and in every worker, whichever `--loop` is asked for. So:

- **uvloop not installed** (`pip install granian`, or `granian[rloop]`): `granian --interface asgi main:app` with `activate()` at the top of `main.py` is enforced, for ASGI, RSGI and WSGI, with `--workers`, and in workers started later.
- **uvloop installed** (`granian[uvloop]`): the server does not start under a policy, with `--loop asyncio` or `--loop rloop` either, because uvloop is loaded all the same. Uninstall uvloop, or use the launcher pattern, with which uvloop is not loaded and `auto` goes on to rloop or asyncio:

```python
# serve.py
import tethered


def main():
    tethered.activate(
        allow=["api.stripe.com:443", "db.internal:5432"],
        locked=True,
        lock_token=object(),
    )

    from granian import Granian

    Granian("main:app", address="0.0.0.0", port=8000, interface="asgi", workers=2).serve()


if __name__ == "__main__":
    main()
```

On rloop one way out is not seen: `transport.sendto(data, addr)` on an unconnected datagram endpoint is sent below Python. Connections, lookups, connected datagram endpoints and launches are enforced there.

### sanic

`import sanic` imports uvloop when uvloop is installed, and `pip install sanic` installs it. The `sanic` command has imported sanic before it imports the application, so under a policy it does not start: `activate()` raises `RuntimeError`. `SANIC_USE_UVLOOP=false` does not help, because uvloop is loaded all the same. Two arrangements work:

- Uninstall uvloop (`pip uninstall uvloop`). The `sanic` command then works as it is.
- Start sanic from a script that calls `activate()` before it imports sanic:

```python
# server.py
import tethered

tethered.activate(
    allow=["api.stripe.com:443", "db.internal:5432"],
    locked=True,
    lock_token=object(),
)

from sanic import Sanic
from sanic.response import text

app = Sanic("app")


@app.get("/")
async def index(request):
    return text("ok")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, workers=2)
```

sanic logs that uvloop is not installed and serves on the standard loop. Each worker is a new Python process that inherits the policy; the `activate()` at the top of the file, which a worker runs again, is the no-op there. Workers started by `app.m.restart()` and by `--auto-reload` inherit it too.

### aiohttp

**As a server**, `web.run_app(app)`, `python -m aiohttp.web` and gunicorn with `-k aiohttp.GunicornWebWorker` are enforced. `-k aiohttp.GunicornUVLoopWebWorker` does not start under a policy.

**As a client**, aiohttp resolves names through c-ares when aiodns is installed, as it is with `aiohttp[speedups]`. tethered does not see such a lookup, so it could not tell which host an address belongs to, and a host the allow list names would be refused. tethered therefore keeps pycares, the c-ares binding under aiodns, from being imported while a policy is active: aiohttp then uses its threaded resolver on its own, and everything is enforced. That works when `activate()` comes before the first import of aiohttp. Where aiohttp is imported first (your module imports it above the `activate()` call, or `python -m aiohttp.web` or gunicorn's aiohttp worker class imported it before your application), choose the resolver yourself:

```python
connector = aiohttp.TCPConnector(resolver=aiohttp.ThreadedResolver())
async with aiohttp.ClientSession(connector=connector) as session:
    async with session.get(url) as response:
        body = await response.read()
```

The sign of the problem is an allowed host refused by its address (`Blocked by tethered: 203.0.113.7:443 is not in the allow list`), together with a one-time warning that starts with `tethered: no hostname is known for the refused address`.

### daphne and Twisted

daphne is one process and runs on a standard asyncio event loop: an ASGI application under it is enforced with `activate()` at import.

Code that uses Twisted's own client API is enforced too, but a refusal does not come back as `EgressBlocked`. Twisted expects `OSError` from a connection attempt and `socket.gaierror` from a lookup, and tethered's refusal is neither:

- a refused connection (`reactor.connectTCP`, `TCP4ClientEndpoint`) reaches the caller as Twisted's `TimeoutError`, when the connection timeout is over (30 seconds unless you pass one);
- a refused lookup is never reported: the `Deferred` of `HostnameEndpoint.connect`, `twisted.web.client.Agent.request` and `reactor.resolve` never fires. Put a timeout of your own around such calls;
- `reactor.spawnProcess` with its default, empty environment cannot be given the policy: under a plain policy a Python child started that way runs without it (a warning is logged), and under a lock or `"block"` the launch is refused. Pass `env=None`, which makes the child inherit the environment, and with it the policy.

tethered's warning is in the log in every case, so the log says what the caller is not told.

### tornado

tornado's `HTTPServer` is enforced in one process, with `fork_processes` and under `tornado.autoreload`, and so are `AsyncHTTPClient` as tornado ships it, `TCPClient`, `Resolver` and `tornado.process.Subprocess`.

Do not configure `AsyncHTTPClient` to use `tornado.curl_httpclient`. It hands every request to libcurl, and tethered sees none of it: a request to a forbidden destination goes through under a locked, fail-closed policy with no exception and no log line.

### uWSGI

The plain deployment works as it is: with `activate()` at the top of the WSGI file, every worker enforces the policy, also with `--lazy-apps`, with threads, and in workers that replace others.

```bash
uwsgi --http :8000 --wsgi-file app.py --master --processes 2
```

**Add `--py-sys-executable` if the application launches Python children.** Under uWSGI `sys.executable` is the uwsgi binary, so `subprocess.run([sys.executable, "script.py"])` starts uWSGI, not Python. tethered says so when the policy is activated (`tethered: sys.executable is /usr/local/bin/uwsgi, the program that embeds Python here, not a Python interpreter. ...`) and counts every launch as external: warned about, and refused under `"block"`, a launch of the real interpreter included, although that child does inherit the policy. Naming the interpreter puts it right:

```bash
uwsgi --http :8000 --wsgi-file app.py --master --processes 2 --py-sys-executable /usr/local/bin/python
```

With a virtualenv (`-H /opt/venv`), name the virtualenv's interpreter (`--py-sys-executable /opt/venv/bin/python`).

**A reload does not change a locked policy.** `SIGHUP`, `--py-autoreload` and, without `--die-on-term`, `SIGTERM` re-execute the uwsgi binary, and the new process inherits the locked policy before it loads the application. See [changing a locked policy](#changing-a-locked-policy).

**Several applications with `--mount`** share one process, the first in the main interpreter and each later one in an interpreter of its own, and a locked policy is one per process. Lock the same policy in every application, or in the first one only: later applications join the lock as they are loaded. An application that is loaded before another one locks is outside that lock and has no network at all. Applications that need different policies need different uWSGI instances.

An exception the application lets out makes uWSGI close the connection without a response, with or without tethered.

### waitress

waitress is one process with a pool of threads. `waitress-serve main:application` with `activate()` at the top of `main.py` is enforced on every thread, and so is a launcher that activates before it imports waitress.

### mod_wsgi

mod_wsgi runs each application group in an interpreter of its own, and by default creates that interpreter when the group gets its first request. A locked tethered policy belongs to the process, not to the application group: one interpreter takes the lock, and the others either join it as they start or are left outside it with no network. The guidance below follows from that.

**One application per process works.** It works in the default application group, where the application runs in a subinterpreter and takes the lock there, and in `%{GLOBAL}`; in daemon mode and in embedded mode; and through stop, graceful restart, and `maximum-requests` and `inactivity-timeout` recycling. `mod_wsgi-express` with its defaults (main interpreter, preloaded) works as it is. Give each application a daemon process group of its own:

```apache
WSGIDaemonProcess shop python-home=/opt/venv processes=2 threads=15
WSGIScriptAlias /shop /srv/shop/wsgi.py
<Location /shop>
    WSGIProcessGroup shop
</Location>
```

**Use `python-home`, not `python-path`,** to point mod_wsgi at a virtual environment. With `python-path`, mod_wsgi adds the directory with `site.addsitedir()` after the interpreter has started. tethered then logs "tethered.pth not found ... Python child processes will NOT auto-inherit", a second application group cannot join the lock ("a policy can only be joined once, while an interpreter starts, and this interpreter's startup is over"), and `sys.executable` remains the system Python, so with tethered installed only in the virtual environment a Python child of the lock holder runs without it.

**Several applications in one process: take the lock in the main interpreter when the process starts.** The main interpreter is the first one of a process. A script that does nothing but lock the policy, imported into it at process start, makes every application group's interpreter come into being under the lock, whenever its first request arrives, so every application joins:

```python
# /srv/policy/lock.wsgi
import tethered

tethered.activate(
    allow=["api.stripe.com:443", "db.internal:5432"],
    locked=True,
    lock_token=object(),
)
```

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

# One line per process group: the lock is taken before any application is loaded.
WSGIImportScript /srv/policy/lock.wsgi process-group=apps application-group=%{GLOBAL}
```

The applications stay lazy, their order does not matter, and they need not import tethered at all; one that calls `activate(locked=True)` with the same policy gets the no-op. No request is routed to `%{GLOBAL}`. In embedded mode the line is `WSGIImportScript /srv/policy/lock.wsgi process-group=%{GLOBAL} application-group=%{GLOBAL}`. A container entry point that activates and then executes Apache has the same effect for every process of the server.

**What happens without it.** With lazy loading, which is the default, the first requests of two applications can overlap. The interpreter of the second then already exists at the moment the first application takes the lock. It is outside the lock: its `activate()` raises `TetheredLocked`, also for the identical policy, and it has no network at all, loopback included. If the application lets that exception out of its WSGI script, mod_wsgi tries the import again on every request, and every request is a 500. Which application loses is open. Embedded mode and `WSGIPerInterpreterGIL On` make no difference. Nothing forbidden is reached in any of this; what breaks is the application.

Two other arrangements avoid the race: one `WSGIDaemonProcess` per application, as above, or loading every script of the process at process start with `WSGIImportScript`, the script that takes the lock first. In the other order the application that is imported before the lock is taken is locked out every time.

**One policy per process.** With different locked policies in two groups, the application that comes second gets `TetheredLocked`, and if it catches the exception it runs under the first application's policy. An application in the same process that does not use tethered at all is covered too: when its interpreter is created after the lock it joins and is restricted by the other application's policy, and when it was created before, it has no network. Unlocked policies in different groups each enforce their own inside the process, but they share the one `_TETHERED_CHILD_POLICY` variable: a Python child launched by either application gets the policy of whichever application activated last, and an interpreter created afterwards is restricted by that policy even if its application never imported tethered. Applications that need different policies need different daemon processes.

**Do not mix `%{GLOBAL}` with other application groups that serve requests in one process.** mod_wsgi does not always run a `%{GLOBAL}` request in the main interpreter: a request handled by a worker thread that has served another group before can run inside that group's subinterpreter, with or without tethered. With tethered the result is no network on some requests and the other application's policy on others.

**Reloading a WSGI script.** In embedded mode a script that is reloaded with a changed locked policy gets `TetheredLocked`, and requests are answered with a 500 until Apache is restarted; reloaded with the same policy, its `activate()` is a no-op. In daemon mode touching the script restarts the process, and the new policy is in place.

**Subprocesses from a handler** under a lock are handled as under gunicorn (the table above), in the lock holder and in an interpreter that joined. An interpreter outside the lock launches nothing.

### Flask and Django

**Flask**: call `activate()` in the application factory, before the application is built. It is then in force in every gunicorn worker, in `flask` commands, and in both processes of `flask run` with its reloader. An error handler registered with `@app.errorhandler(tethered.EgressBlocked)` is reached for a refused lookup and for a refused connection.

**Django**: call `activate()` in `settings.py`. Every entry point of a project imports the settings first: the WSGI application under gunicorn, with and without `--preload`, every management command, and both processes of `runserver` with its autoreloader. The middleware that turns a refusal into a 503 is under [Django / FastAPI middleware](#django--fastapi-middleware).

`requests` passes `EgressBlocked` through unwrapped, and an adapter configured to retry makes one attempt.

### Changing a locked policy

Whatever re-executes the server keeps a locked policy. The new process image inherits the policy from the environment and has it in place before the application is imported, and a locked policy cannot be replaced without its token. An application that then asks for a different locked policy gets `TetheredLocked`:

- **uWSGI reload** (`SIGHUP`, `--py-autoreload`): if the application lets the exception out, uWSGI has no application and answers every request with a 500 until it is stopped and started; if it catches it, the old policy silently stays.
- **gunicorn `SIGUSR2` with `--preload`**: the new master prints the error and exits; the old master keeps serving under the old policy.
- **Django `runserver`**: the process the autoreloader starts cannot import its settings, and `runserver` exits.

The same policy asked for again is a no-op, so a reload that changes nothing about the policy is unaffected. uWSGI with `--lazy-apps`, gunicorn without `--preload` and unlocked policies are not affected either. To change a locked policy, stop the server and start it.

Upgrade tethered itself the same way: from the deployment, with the server stopped. A `pip install --upgrade tethered` that a locked application starts for itself is refused when it reaches `tethered.pth`, and pip leaves the installation half changed; [COMPATIBILITY.md](COMPATIBILITY.md#installing-upgrading-and-removing-tethered) has what that looks like and how to repair it.

### Celery and other task queues

What matters is where `activate()` is called: it has to run in every process that runs task code, before the first task.

**Celery.** Call `activate()` when the application module is imported. That is in the worker's main process, before Celery creates its pool, and it covers every pool: prefork (also processes started later by `--max-tasks-per-child`, `--autoscale`, or after one was killed), threads, solo and gevent, and beat inside the worker or as a process of its own. If the module is also imported by processes that should not get this policy (a web application that only sends tasks), use the `worker_init` signal, which Celery sends in the worker's main process whatever the pool:

```python
# tasks.py
import tethered
from celery import Celery, signals

app = Celery("tasks", broker="redis://127.0.0.1:6379/0", backend="redis://127.0.0.1:6379/0")


@signals.worker_init.connect
def activate_tethered(**kwargs):
    tethered.activate(allow=["api.stripe.com:443"])
```

- **Do not rely on `worker_process_init` alone.** Celery sends it in the children of the prefork pool and in the solo pool. With `--pool threads` or `--pool gevent` it is never sent, the handler never runs, and the worker has no policy at all.
- **The broker has to be allowed.** Loopback is allowed by default. A broker addressed by name has to be in the allow list, otherwise the worker ends at start-up with `EgressBlocked` for the broker's address.
- **`external_subprocess_policy="block"` stops `celery worker` from starting**: its banner calls `platform.platform()`, which launches `uname` and catches only `OSError`. Call `platform.platform()` once before `activate()`; it caches the answer.
- **The eventlet pool** resolves names with its own resolver, which tethered does not see: a host the allow list names is refused. Set `EVENTLET_NO_GREENDNS=yes`, or allow the address.
- **What the producer sees.** `result.get()` for a refused task raises `tethered.EgressBlocked` in a producer that has tethered loaded, with Celery's default JSON result serializer and with `result_serializer="pickle"`. With JSON, Celery rebuilds the exception from its message, and `host`, `port` and the other attributes are read back out of it. A producer that has not imported tethered gets a class of Celery's own that is named `EgressBlocked`; with pickle, reading the result imports tethered.

**RQ.** Call `activate()` in the settings module and start the worker with `rq worker -c settings`: the worker holds the policy, and every job starts with it, whichever worker class runs it. With `activate()` only in the module that defines the jobs, every job is still covered, because RQ imports that module where the job runs, but the worker process itself holds no policy.

**Dramatiq.** Call `activate()` when the actors' module is imported, or in the `after_process_boot` hook of a middleware. Both run in every worker process, however it was started (forked, from a fork server, or with `--use-spawn`), and after a reload. Dramatiq's parent process never imports the application and holds no policy; it runs no actor.

**Huey.** Call `activate()` when the module that holds the `huey` instance is imported, or in an `@huey.on_startup()` hook, which Huey runs in every worker. Both cover thread and process workers and the workers that replace them.

**arq.** Call `activate()` when the module with `WorkerSettings` is imported, or in `on_startup`. The worker runs on asyncio's own event loop.

**Under supervisord**, or any process manager, a policy activated by the entry point reaches a Python program through the environment, and its restarts too. A program whose environment is wiped on the way (`env -i`) starts without it. Activate in the program itself where that matters.

In all of these a refused task fails like any task that raises: the workers keep running, and whether it is retried depends on the retry settings ([Celery tasks](#celery-tasks), [Retry decorators](#retry-decorators)).

### Process pools and the fork server

`multiprocessing.Pool` and `ProcessPoolExecutor` workers hold the policy of the process that owns the pool, with the fork, spawn and forkserver start methods, including workers that replace others. A blocked call in a worker reaches the owner as `tethered.EgressBlocked` from `.get()` or `.result()`, and the pool is not broken by it.

**Call `activate()` before the first pool or process is started.** A policy reaches a process when it starts:

- Worker processes that were started before `activate()` hold no policy until they are replaced.
- **A fork server that was started before `activate()` keeps producing workers without a policy**, under a locked policy too. A forkserver worker is a copy of the fork server process, not of the process that asks for it, and asking for one raises no audit event, so tethered can neither refuse nor repair it. forkserver is the default start method on Linux from Python 3.14. `activate()` logs one warning when it finds a fork server already running (`tethered: multiprocessing's fork server was started before this policy.`).

### Interpreter pools

`concurrent.futures.InterpreterPoolExecutor` (Python 3.14 and later) under a locked policy:

- **A worker joins the lock if its interpreter starts under it.** What counts is when the interpreter starts, not when the executor object is created: an executor built before the lock and first used after it joins. Workers are started on demand, so a pool can end up mixed. With `max_workers=2`, one worker warmed up before the lock and one started afterwards gave both outcomes within one request. Take the lock first and submit the first task afterwards.
- **A joined worker** reaches what the policy allows, loopback included, and gets the ordinary `EgressBlocked` for the rest. `deactivate()` and an `activate()` with a different policy raise `TetheredLocked` there, and the identical `activate()` is a no-op. A Python child launched from a task inherits the locked policy. An uncaught `EgressBlocked` reaches the submitter as `tethered.EgressBlocked`, chained from the interpreter's `ExecutionFailed`, so `except tethered.EgressBlocked` around `future.result()` works.
- **A worker outside the lock** is refused everything, the allowed hosts and loopback included, and nothing is logged. The exception is `RuntimeError` until tethered has been imported in that interpreter and `EgressBlocked` afterwards; process launches raise `SubprocessBlocked`.
- **Task functions that live in the application module** make the worker import that module, which runs its `activate()` again. In a joined worker that is the no-op. In a worker outside the lock, the submitter gets `concurrent.interpreters.NotShareableError`, caused by the `TetheredLocked` raised there.
- **Logging is configured per interpreter.** Until it is configured in a worker, tethered's refusals there appear as bare `tethered: blocked ...` lines.

Under an unlocked policy a worker interpreter that starts after `activate()` activates the same policy for itself; one that already existed holds none.

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
- **uvloop.** On a uvloop event loop, nothing your library does through the loop raises an audit event: connections, lookups, datagrams and `asyncio.create_subprocess_exec` launches are not checked against your scope at all, and nothing is logged for them. Where the application has called `activate()` with an enforcing policy this cannot happen, because tethered keeps uvloop out of such a process. A `scope()` used on its own does not: it neither refuses the import of uvloop nor refuses to be entered over a loaded one. tethered logs a one-time warning when a scope is entered with uvloop loaded. uvicorn uses uvloop by default when it is installed, so an application without a policy of its own may well run on it.
- **Windows.** On the default `ProactorEventLoop`, connections raise no audit event, so your scope's connect-time check does not run. tethered logs a one-time warning.
- **The event loop belongs to the application**, so a library can fix neither of the two. State in your documentation that enforcement under asyncio needs asyncio's own selector event loop: not uvloop, and on Windows `asyncio.SelectorEventLoop` in place of the default `ProactorEventLoop`.
- **`httpx.AsyncClient` wraps connect-time refusals.** A refused connection reaches your code inside an `ExceptionGroup`, which `except tethered.EgressBlocked` does not catch; use `except*` (see [Django / FastAPI middleware](#django--fastapi-middleware)). Keep that in mind for the wrapper patterns below, which are written with a plain `except`.

Whatever the application runs on:

- **A thread you start does not carry your scope.** A scope belongs to the thread, task or greenlet that entered it. A `threading.Thread` started inside the block, a `ThreadPoolExecutor` job and `loop.run_in_executor` run without it; `asyncio.to_thread` takes it along. Enter the scope inside the function the thread runs (the decorator form does that).
- **Under gevent, a child process does not receive your scope.** gevent replaces `subprocess.Popen` with a class of its own, and a scope reaches a child only through the standard library's. The child still inherits the application's `activate()` policy.

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
