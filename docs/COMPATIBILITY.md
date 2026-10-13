---
title: "Compatibility"
description: "What tethered enforces, what needs configuration, what it refuses at start-up and what it does not see, measured under real servers, task queues and client libraries."
---

# Compatibility — servers, task queues, client libraries

What tethered enforces under the servers, task queues and client libraries people deploy, what needs a particular configuration, what tethered refuses at start-up, and what it does not see at all. Everything on this page was measured: each row names the container suite in [`tests_containers/`](https://github.com/shcherbak-ai/tethered/blob/main/tests_containers/AGENTS.md) that asserts it, and the versions it was measured with. [The cookbook](COOKBOOK.md#servers-and-interpreter-pools) has the configuration for each server; [the security model](security.md#what-tethered-does-not-protect-against) has the limits as part of the threat model.

## How to read this page

**What was measured.** Each suite builds a wheel of tethered from the source tree, installs it into the official `python:X.Y-slim` Docker image the way a user installs it, starts the real server or library, and asks it to reach four destinations: a host the policy allows (`allowed.test:9001`), a forbidden name, a forbidden raw address, and the allowed name on a port the rule does not cover. The destinations count every connection and datagram that arrives. "Refused" on this page means that nothing arrived, not only that the application saw an exception. Every suite runs on Python 3.11, 3.12, 3.13, 3.14 and 3.15, on Linux x86-64 with glibc.

**The results.**

| Result | Meaning |
|---|---|
| Enforced | The forbidden name, the forbidden address and the other port are refused and nothing arrives; the allowed destination is reached. Under `locked=True` the result is the same. |
| Needs configuration | Enforced once the setting named in the row is in place. Without it the arrangement ends in one of the results below. |
| Refused at start-up | tethered does not run in this arrangement, and says so: `activate()` raises `RuntimeError`, or an import raises `ImportError`, and the server does not start. Nothing is served without the policy. |
| Never serves | The same refusal inside a worker that a supervisor keeps replacing: the server process stays up and answers no request. |
| Allowed host refused | Nothing forbidden is reached, but a host the allow list names is refused as well, because the library looked the name up where tethered could not see it. The forbidden name is still sent to the name server. |
| Partly enforced | The name is checked; the connection is made in C, so a raw address or a port outside the rule is reached. |
| Not seen | Neither refused nor reported. See the next section. |

**The versions.** Every table names the release it was measured with. A row holds for that release; where a behaviour depends on the release (uvicorn's does), the row says so. To run a suite yourself: `uv run python tests_containers/run.py --suite uvicorn --python 3.13`.

**Measured once.** A few statements come from single runs made while the suites were written and are not asserted by a test. They are marked "measured once".

## What "not seen" means

tethered is an audit hook. CPython raises an audit event when Python code calls into the `socket` module (`socket.getaddrinfo`, `socket.connect`, `socket.sendto`) or launches a process (`subprocess.Popen`, `os.exec*`), and tethered's hook decides at that event. The hook is called by the interpreter. It cannot add an event where the interpreter raises none.

A library that resolves names and opens connections inside its own compiled code never calls Python's `socket` module. libcurl, libpq, the gRPC core, librdkafka and the libuv loop inside uvloop are examples. No event is raised, the hook is not called, and tethered has nothing to decide. For such a library, under any policy:

- the forbidden name is looked up, and the forbidden address and port are reached;
- no exception is raised and no log line is written;
- `locked=True` and `fail_closed=True` change nothing, because they act on events that never come;
- `log_only=True` reports nothing, so a log-only rollout does not reveal these connections either;
- `on_blocked` is not called and a `scope()` does not apply.

No setting of tethered changes this, and no later version of tethered can, for as long as it works through audit events. Where tethered knows of a common case it refuses to run instead of running unenforced: it keeps uvloop and pycares from being imported under a policy (below). For everything else on this page that is "not seen", the remedy is a pure-Python driver where one exists (the tables name it), or a control below Python: a network policy, a firewall rule, seccomp.

## Event loops and green threads

| Runtime | Result | Detail | Pinned by |
|---|---|---|---|
| asyncio's own selector event loop (the default on Linux) | Enforced | Streams, `loop.create_connection`, `loop.sock_connect`, `loop.getaddrinfo`, connected and unconnected datagram endpoints, `asyncio.to_thread`, and `asyncio.create_subprocess_exec` / `create_subprocess_shell`. | `uvicorn` and every other asynchronous server suite |
| uvloop | Refused at start-up | With a policy active that is not `log_only`, `import uvloop` raises `ImportError`; with uvloop already loaded, `activate()` raises `RuntimeError`. A server that takes uvloop only when it can be imported runs on the standard loop instead. Four cases still end on uvloop, see below. | `uvicorn`, `uvicorn_legacy`, `gunicorn_uvicorn`, `fastapi`, `hypercorn`, `granian`, `sanic`, `aiohttp`, `modwsgi` (uvloop 0.23.0) |
| rloop | Enforced, with one gap | Connections, lookups and launches go through Python's `socket` and `subprocess` modules. `transport.sendto(data, addr)` on an unconnected datagram endpoint is sent below Python and is not seen. | `granian` (rloop 0.5.0) |
| trio | Enforced | trio uses Python's `socket` and `subprocess` modules. `trio.open_tcp_stream` delivers a refused connection inside an `ExceptionGroup`; a refused lookup arrives bare. | `hypercorn`, `clients` (trio 0.34.0) |
| Twisted | Enforced | Nothing forbidden gets out. A refusal does not reach the caller as `EgressBlocked`: see [daphne and Twisted](#daphne-and-twisted). | `daphne`, `clients` (Twisted 26.4.0) |
| tornado's IOLoop | Enforced | It is asyncio's selector loop. | `tornado`, `gunicorn_tornado` (tornado 6.5.10) |
| gevent, its default resolver (a thread pool) or `GEVENT_RESOLVER=block` | Enforced | One hazard with the thread-pool resolver: a refused lookup now and then never returns. See [gunicorn](#gunicorn). | `gunicorn_gevent`, `clients`, `celery` (gevent 26.9.0) |
| gevent with `GEVENT_RESOLVER=ares` | Allowed host refused | c-ares resolves in C. | `gunicorn_gevent`, `clients` |
| eventlet, its default resolver (greendns) | Allowed host refused | greendns is a DNS client of its own (dnspython) and raises no `socket.getaddrinfo` event. | `clients`, `celery` (eventlet 0.41.2) |
| eventlet with `EVENTLET_NO_GREENDNS=yes` | Enforced | | `clients`, `celery` |
| asyncio's `ProactorEventLoop` (the Windows default) | Not tested here | That loop raises no connect events, so there is no connect-time enforcement on it: see [the security model](security.md#what-tethered-does-not-protect-against). | |

**Where a process still ends on uvloop.** The refusal works where a policy that enforces is active in the interpreter that imports uvloop. It does not cover:

- **A `log_only` policy.** It refuses nothing, the import of uvloop included. The server runs on uvloop, and nothing that goes through the loop is reported: the list of what would be blocked stays empty for every asynchronous call. tethered logs one warning (`tethered: uvloop is loaded in this process.`). Code that uses the `socket` module itself is still reported. Run a log-only rollout of an asyncio application with the loop named (`uvicorn --loop asyncio`). Pinned by `uvicorn`, `fastapi`, `gunicorn_uvicorn`, `hypercorn`, `granian`, `sanic`, `aiohttp`.
- **A `scope()` with no `activate()` under it.** A scope alone does not keep uvloop out. On uvloop, `asyncio.open_connection` and `loop.create_connection` inside the scope reach refused destinations; `loop.sock_connect`, `asyncio.to_thread` and blocking code are refused by the scope. One warning is logged. With `--loop asyncio` everything is refused. Pinned by `uvicorn`.
- **An interpreter outside a lock.** Under mod_wsgi, an application whose interpreter existed before another application locked a policy is refused every socket, but it holds no policy of its own, so it can import uvloop, and a connection on a uvloop loop then arrives at a forbidden destination. Pinned by `modwsgi`.
- **A server that swallows the refusal.** uvicorn's default `--lifespan auto` takes any exception from a hand-written ASGI lifespan handler for "this application does not support lifespan". An application that activates there, after uvicorn has loaded uvloop, is served on uvloop with no policy at all. tethered logs the refusal as an error before it raises it, and that one line is all that is left. FastAPI and Starlette report a failed start-up and the server exits. Pinned by `uvicorn`.

## Web servers

### uvicorn

Measured with uvloop 0.23.0 installed, as it is with `uvicorn[standard]`, and an application that calls `activate()` when it is imported. Suites: `uvicorn` (uvicorn 0.54.0) and `uvicorn_legacy` (uvicorn 0.46.0).

| Arrangement | uvicorn 0.54.0 | uvicorn 0.46.0 |
|---|---|---|
| `uvicorn main:app`, the loop left to uvicorn | Enforced. uvicorn imports the application first, its import of uvloop is refused, and it falls back to the standard loop on its own. | Refused at start-up: uvloop is loaded first, `activate()` raises `RuntimeError`, exit status 1. |
| `--loop asyncio`, or `UVICORN_LOOP=asyncio` in the environment of the `uvicorn` command | Enforced. uvloop is never asked for. | Enforced. |
| `--loop uvloop` | Refused at start-up (`ImportError`, exit status 1). | Refused at start-up (`RuntimeError`, exit status 1). |
| `--workers N`, the loop left to uvicorn | Never serves: every worker loads uvloop before it imports the application and dies at `activate()`; the supervisor starts another one without end. | Never serves. |
| `--workers N` with `--loop asyncio` or `UVICORN_LOOP=asyncio` | Enforced in every worker, and in a worker that replaces a killed one. | Enforced. |
| `--reload`, the loop left to uvicorn | Never serves. | Not tested. |
| `--reload --loop asyncio` | Enforced. | Not tested. |
| `uvicorn.run("main:app")` | Enforced on the standard loop. | Refused at start-up. `uvicorn.run()` does not read `UVICORN_LOOP`. |
| `uvicorn.run(app)` with an application object the script imported | Enforced. | Enforced. |
| `uvicorn.run("main:app", workers=2)` with no `loop` argument | Never serves. `UVICORN_LOOP` does not help. | Not tested. |
| `uvicorn.run("main:app", loop="asyncio")`, with or without `workers=2` | Enforced (measured once, on Python 3.13; the suites pass `loop="asyncio"` only together with a launcher that activates first). | Not tested. |
| A launcher that calls `activate()` and then `uvicorn.run(...)`, with or without workers | Enforced. Workers inherit the policy as they start; a worker that replaces a killed one too. | Enforced. |
| `uvicorn.Server(uvicorn.Config("main:app")).run()` | Refused at start-up: this route picks the loop before it imports the application. | Not tested. |
| `asyncio.run(uvicorn.Server(config).serve())` | Enforced. uvloop is never asked for. | Enforced. |
| `--factory`, with `activate()` inside the factory | Refused at start-up; enforced with `--loop asyncio`. | Not tested. |
| `activate()` in a hand-written ASGI lifespan handler | **Served on uvloop with no policy** under the default `--lifespan auto` (see above). Exit status 3 with `--lifespan on`. Enforced with `--loop asyncio`. | Not tested. |
| A `log_only` policy | Runs on uvloop; what goes through the loop is not reported. | The same. |

On the standard loop the `uvicorn` suite covers every way out of a coroutine listed under [Event loops](#event-loops-and-green-threads), a response of 20 MB under a plain and a locked policy, Python children and external tools launched from a handler, and `external_subprocess_policy="block"`.

**Which releases import the application first** (measured once, on Python 3.13, not asserted by a suite): uvicorn 0.47.0 is the first release whose `uvicorn main:app` imports the application before it chooses the loop. From 0.50.0 the worker and reload processes choose the loop first again, which is the "never serves" row; 0.49.0 with `--workers 2` worked. Do not build on the order: name the loop.

### FastAPI

Measured with fastapi 0.143.0 installed as `fastapi[standard]` (fastapi-cli 0.0.32, starlette 1.7.0, httpx 0.28.1 on anyio 4.15.1, uvloop 0.23.0). Suites: `fastapi` (uvicorn 0.54.0) and `uvicorn_legacy` (uvicorn 0.46.0). `fastapi run` has no option for the event loop, and `UVICORN_LOOP` does not reach it.

| Arrangement | Result | Pinned by |
|---|---|---|
| `fastapi run main.py`, or `fastapi run` finding `main.py`, with or without `--workers` | Enforced. The command imports the application itself, so the policy is active before uvicorn starts; workers inherit it. | `fastapi`, `uvicorn_legacy` |
| `fastapi dev main.py` | Enforced: the process the reloader starts inherits the policy. | `fastapi` |
| `fastapi run --entrypoint main:app` (or the entry point in `pyproject.toml`) | Enforced with uvicorn 0.54.0. Refused at start-up with uvicorn 0.46.0. | `fastapi`, `uvicorn_legacy` |
| `fastapi run --entrypoint main:app --workers 2` | Never serves. Use a path, or `uvicorn main:app --workers 2 --loop asyncio`. | `fastapi`, `uvicorn_legacy` |
| `activate()` in a FastAPI lifespan handler | Refused at start-up: "Application startup failed. Exiting.", exit status 3. Enforced with `uvicorn --loop asyncio`. | `fastapi` |
| Starlette's `TestClient` | Enforced. It runs the application on the standard loop; asking anyio for uvloop (`backend_options={"use_uvloop": True}`) fails with tethered's `ImportError`. | `fastapi` |
| The exception handler of [the cookbook](COOKBOOK.md#django--fastapi-middleware) | Every refusal ends as the HTTP 503 of the recipe and nothing arrives: a refused lookup, a port rule and a raw address, for `httpx.AsyncClient`, `httpx.Client`, asyncio streams and the `websockets` client. | `fastapi` |

Of the compiled modules a `fastapi[standard]` installation brings, uvloop is the only one that imports the C library's `connect` and `getaddrinfo` itself (a test of the `fastapi` suite).

### gunicorn

Measured with gunicorn 26.2.0.

| Arrangement | Result | Pinned by |
|---|---|---|
| `sync` and `gthread` workers, with and without `--preload` | Enforced in every worker, in workers started after `--max-requests`, and after a `SIGHUP` reload. | `gunicorn` |
| Binary upgrade (`SIGUSR2`) | Works with no `pre_exec` hook, with a locked or an unlocked policy, with and without `--preload`, and under `external_subprocess_policy="block"`: the new master starts under the policy and its workers enforce. A client that kept requesting the TCP and the unix listener saw no failed request. | `gunicorn` |
| Binary upgrade into a release that asks for a different locked policy, with `--preload` | The new master does not start (`TetheredLocked`); the old one keeps serving under the old policy. See [what holds under every server](#what-holds-under-every-server). | `gunicorn` |
| `-k uvicorn.workers.UvicornWorker` and `-k uvicorn_worker.UvicornWorker`, with and without `--preload` | Enforced on the standard loop: the worker imports the application before it asks for its loop, and the import of uvloop is refused. Replaced workers too. | `gunicorn_uvicorn` (uvicorn 0.54.0, uvicorn-worker 0.4.0), `uvicorn_legacy` (uvicorn 0.46.0) |
| `UvicornH11Worker` | Enforced. It names the standard loop and never asks for uvloop. | `gunicorn_uvicorn` |
| `-k asgi` (gunicorn's own ASGI worker) | Refused at start-up without `--preload`: the worker sets its loop up before it imports the application ("Worker failed to boot."). Enforced with `--preload` or `--asgi-loop asyncio`. | `gunicorn_uvicorn` |
| `-k gevent` and `-k gevent_pywsgi`, with and without `--preload` | Enforced in every worker and for overlapping greenlets. See the notes below. | `gunicorn_gevent` (gevent 26.9.0) |
| `-k tornado` | Enforced. An uncaught exception gets no response at all: tornado logs it and leaves the connection open, with or without tethered. | `gunicorn_tornado` (tornado 6.5.10) |
| `-k aiohttp.GunicornWebWorker` | Enforced. | `aiohttp` |
| `-k aiohttp.GunicornUVLoopWebWorker` | Refused at start-up ("Worker failed to boot."). | `aiohttp` |

For gunicorn's uvicorn worker the release that changed the order is older than for the `uvicorn` command (measured once, not asserted by a suite): with uvicorn 0.35.0 the worker set the loop up first, and gunicorn exited with "Worker failed to boot" unless `--preload` was given; from 0.36.0 it imports the application first.

**The gevent worker.**

- **Hazard: a refused lookup sometimes never returns.** tethered logs a refusal in the thread in which the audit event is raised, and for a lookup under gevent's default resolver that is one of gevent's pool threads. After monkey-patching, the lock of a logging handler is gevent's, and when several pool threads log at the same moment one of them is now and then never woken. Its lookup never returns, the request hangs, and a worker that is told to restart or to stop waits for that request until gunicorn's graceful timeout (30 seconds by default). Measured on Python 3.13 with gevent 26.9.0: a stuck request in 8 of 30 stress runs of a gunicorn gevent worker (4 of 30 with `--preload`, 0 of 60 without tethered), and, without gunicorn, a greenlet that never came back in 9 and 15 of 120 new processes that each made 40 refused lookups from 8 greenlets. It is not specific to tethered: an audit hook that logs and raises did the same in 7 of 120 processes, one that only raises in none. Allowed lookups and connections were never affected (0 of 360). How often it happens in a long-lived worker was not established. One mitigation was measured: with the `tethered` logger set to `ERROR`, so that tethered does not log its warning for a refusal, 0 of 180 processes had a stuck greenlet. That is a measurement, not a guarantee, it removes tethered's own line about each refusal (the exception is still raised), and anything else that logs from the resolver's threads can trigger the same.
- **gevent's hub prints a traceback for every refused lookup.** Adding `tethered.EgressBlocked` to the hub's `NOT_ERROR` silences it.
- **Process launches** go through gevent's own `subprocess`, which forks and calls `os.exec*` from Python. tethered sees `os.exec*` events inside the forked child, one for each `PATH` directory that is tried. A child started with `sys.executable` inherits the policy, with an explicit environment that lacks the policy variable too. What changes is where tethered's log lines go: the forked child writes them to its stderr, which is the pipe the application captures. A warning about an external launch (one per `PATH` directory tried) is therefore in the captured stderr of the tool, or ahead of its output with `stderr=subprocess.STDOUT`, and in the server log only when stderr is inherited. Under `"block"` with captured stderr the refusal is logged nowhere; the `SubprocessBlocked` exception is all there is.
- gunicorn 26.2.0 has no eventlet worker.

### hypercorn and Quart

Measured with hypercorn 0.18.0, trio 0.34.0, uvloop 0.23.0; Quart 0.23.1 (0.22.0 on Python 3.11 and 3.12). hypercorn's master never imports the application; each worker is a new Python process that does.

| Arrangement | Result | Pinned by |
|---|---|---|
| The asyncio worker (the default), `--workers`, workers started after `--max-requests`, `SIGHUP` and `--reload`, `serve()` in a script, a WSGI application | Enforced. | `hypercorn` |
| `-k trio` | Enforced. Importing trio launches `ldconfig`: see [what holds under every server](#what-holds-under-every-server). | `hypercorn` |
| `-k uvloop` | Refused at start-up: the worker imports uvloop before the application. When the master holds the policy the worker's import is refused and hypercorn reports "uvloop is not installed". There is no fallback: this worker class asked for uvloop. | `hypercorn` |
| A configuration file that locks the policy in the master (`-c file:conf.py`) | Enforced: the workers inherit the locked policy at start-up, replaced ones too. | `hypercorn` |
| Quart under hypercorn, `quart run`, `quart run --reload`, `app.run()` | Enforced. | `quart` |

### granian

Measured with granian 2.8.4, rloop 0.5.0, uvloop 0.23.0. granian's main process never imports the application; each worker does, after granian has created the worker's event loop. `--loop auto` (the default) takes rloop if it can be imported, then uvloop, then asyncio's own. And granian imports every loop package it finds as soon as granian itself is imported, whichever `--loop` was asked for.

| Arrangement | Result | Pinned by |
|---|---|---|
| granian with neither rloop nor uvloop installed: ASGI, RSGI, WSGI, `--workers`, `SIGHUP`, a respawned worker | Enforced. | `granian` |
| rloop installed (`granian[rloop]`) | Enforced, except an unconnected datagram: `transport.sendto(data, addr)` reaches a forbidden address and raises no event. | `granian` |
| uvloop installed (`granian[uvloop]`), any `--loop`, `--loop asyncio` and `--loop rloop` included | Refused at start-up: uvloop is loaded although it is not used, and `activate()` goes by that. | `granian` |
| uvloop installed, and a launcher that calls `activate()` before it imports granian | Enforced: uvloop is not loaded, `auto` goes on to rloop or asyncio, and the workers inherit the policy. Asking for `--loop uvloop` by name does not start. | `granian` |

### sanic

Measured with sanic 25.12.1 and uvloop 0.23.0, which sanic installs as a dependency. `import sanic` itself imports uvloop.

| Arrangement | Result | Pinned by |
|---|---|---|
| The `sanic` command, as installed | Refused at start-up: the command has imported sanic, and with it uvloop, before it imports the application. `SANIC_USE_UVLOOP=false` does not help: uvloop is loaded all the same. | `sanic` |
| A script that calls `activate()` before it imports sanic | Enforced: sanic logs that uvloop is not installed and serves on the standard loop. Workers inherit the policy, also workers started by `app.m.restart()` and by `--auto-reload`. | `sanic` |
| A script that imports sanic first | Refused at start-up. | `sanic` |
| sanic with uvloop uninstalled | Enforced, with the `sanic` command as it is. | `sanic` |

### aiohttp

Measured with aiohttp 3.14.4, aiodns 4.0.4, pycares 5.1.0, gunicorn 26.2.0.

| Arrangement | Result | Pinned by |
|---|---|---|
| `web.run_app(app)` in a script, `python -m aiohttp.web`, gunicorn with `aiohttp.GunicornWebWorker` | Enforced, `aiohttp.ClientSession` included. | `aiohttp` |
| gunicorn with `aiohttp.GunicornUVLoopWebWorker` | Refused at start-up. | `aiohttp` |
| `aiohttp.ClientSession` with aiodns installed (`aiohttp[speedups]`), the policy active before aiohttp is imported | Enforced: tethered keeps pycares from loading and aiohttp uses its threaded resolver. | `clients` |
| The same with aiohttp imported before `activate()` | Allowed host refused. `python -m aiohttp.web` and gunicorn's aiohttp worker class import aiohttp before the application, so this is what they get. Set the resolver (`aiohttp.TCPConnector(resolver=aiohttp.ThreadedResolver())`), uninstall aiodns, or allow the address. | `aiohttp`, `clients` |

### daphne and Twisted

Measured with daphne 4.2.3 and Twisted 26.4.0. daphne is one process and runs Twisted's reactor on a standard asyncio event loop.

| Arrangement | Result | Pinned by |
|---|---|---|
| An ASGI application that uses asyncio | Enforced. | `daphne` |
| Twisted's own client API in a handler: connections, lookups, datagrams, `reactor.spawnProcess` | Enforced: nothing forbidden gets out. How the refusal comes back differs, see below. | `daphne`, `clients` |
| A launcher that locks the policy and then runs daphne | Enforced. | `daphne` |

A refusal is raised inside the reactor, and Twisted expects `OSError` and `socket.gaierror` there, not a `RuntimeError`:

- A refused connection attempt (`reactor.connectTCP`, `TCP4ClientEndpoint`) reaches the caller as Twisted's own `TimeoutError`, when the attempt's timeout is over: 30 seconds unless the caller says otherwise.
- A refused lookup is never reported: the `Deferred` of `HostnameEndpoint.connect`, `twisted.web.client.Agent.request` and `reactor.resolve` never fires.
- A refused datagram (`transport.write(data, addr)`) and a refused `reactor.spawnProcess` raise to the caller.
- tethered's own warning is in the log in every case. Twisted's traceback of the refusal is only there with `daphne -v 2`.
- `reactor.spawnProcess` with its default, empty environment is an `os.posix_spawn` whose environment lacks the policy variable: under a plain policy a Python child is launched with a warning and runs without the policy; under a lock or `"block"` it is refused.

### tornado

Measured with tornado 6.5.10 and pycurl 7.48.0.

| Arrangement | Result | Pinned by |
|---|---|---|
| `HTTPServer` in one process, `fork_processes` (a child that replaces a killed one too), `tornado.autoreload` | Enforced. | `tornado` |
| `AsyncHTTPClient` as tornado ships it (`simple_httpclient`), `TCPClient`, `Resolver`, `tornado.process.Subprocess` | Enforced; a refusal is raised to the caller. | `tornado`, `clients` |
| `AsyncHTTPClient` configured to use `tornado.curl_httpclient` | **Not seen**: libcurl makes the lookup and the connection. A request to a forbidden destination goes through under a locked, fail-closed policy. | `tornado`, `clients` |

### uWSGI

Measured with uWSGI 2.0.31, which embeds Python in its own binary.

| Arrangement | Result | Pinned by |
|---|---|---|
| `uwsgi --http :8000 --wsgi-file app.py --master --processes 2` with `activate()` at the top of `app.py` | Enforced in every worker, with no further configuration. Also with `--http-socket`, `--lazy-apps`, `--threads 4`, a thread the application starts under `--enable-threads`, and workers replaced after `--max-requests` and after harakiri. | `uwsgi` |
| A virtualenv: `-H venv`, or the uwsgi binary inside the virtualenv | Enforced; `tethered.pth` of the virtualenv is processed. | `uwsgi` |
| A reload (`SIGHUP`, `--py-autoreload`) | The reloaded process inherits the policy before it loads the application. A locked policy cannot be changed by reloading: see [what holds under every server](#what-holds-under-every-server). | `uwsgi` |
| A Python child process launched from a handler | **Needs configuration**: `--py-sys-executable /path/to/python`. See below. | `uwsgi` |
| Several applications with `--mount` | Each later application runs in an interpreter of its own, and a lock is one per process: see below. | `uwsgi` |

**`sys.executable` is the uwsgi binary.** tethered recognizes a Python child by `sys.executable`, and under uWSGI that is not an interpreter: `subprocess.run([sys.executable, "script.py"])` starts uWSGI, not Python ("unable to load configuration from ..."). tethered notices, logs a warning when the policy is activated (`tethered: sys.executable is /usr/local/bin/uwsgi, the program that embeds Python here, not a Python interpreter. ...`), and counts every launch as external: warned about, and refused under `"block"`, with the reason in the log line. That includes a launch of the real interpreter (`["/usr/local/bin/python", "script.py"]`), although that child does inherit the policy; under a lock it is given the policy variable when its explicit environment lacks it, like any program started through `subprocess`. `--py-sys-executable /path/to/python` puts it right, with a virtualenv too: the warning is gone and a child started with `sys.executable` is a Python child that inherits.

**Mounted applications.** uWSGI loads the first application in the main interpreter and each later one in a new interpreter, unless `--single-interpreter` is given. With the same locked policy in both, the second joins the lock and its `activate()` is a no-op. A first application that does not lock, followed by one that does, is outside the lock and has no network at all, loopback included. After a reload the same deployment behaves differently: the main interpreter inherits the lock, and the first application is held to the second's policy. With different locked policies the second application gets `TetheredLocked`; if it lets the exception out, uWSGI does not start. Unlocked policies in several interpreters share the policy variable, as under mod_wsgi. One policy for all mounted applications, locked by the first, is the arrangement that holds.

uWSGI's own behaviour that matters here: `SIGTERM` reloads unless `--die-on-term` is given, and an uncaught exception closes the connection without a response.

### waitress

Measured with waitress 3.0.2: one process and a pool of threads.

| Arrangement | Result | Pinned by |
|---|---|---|
| `waitress-serve module:application`, and a launcher that calls `activate()` before it imports waitress | Enforced on every thread, with requests on all threads at once. | `waitress` |

### mod_wsgi

Measured with mod_wsgi 6.1.0 and Apache 2.4 as Debian packages it (2.4.68 when measured). mod_wsgi runs each application group in an interpreter of its own, and a locked policy is one per process, so what counts is the order in which the interpreters of a process come into being. [The cookbook](COOKBOOK.md#mod_wsgi) has the configurations.

| Arrangement | Result | Pinned by |
|---|---|---|
| One application per process: daemon mode and embedded mode, the default application group and `%{GLOBAL}`, `mod_wsgi-express`; processes started by a graceful restart, `maximum-requests`, `inactivity-timeout` and a touched script | Enforced. | `modwsgi` |
| A daemon process group for each application | Enforced; each application has its own policy. | `modwsgi` |
| Several application groups in one process, and a script that only takes the lock imported into the main interpreter at process start (`WSGIImportScript ... application-group=%{GLOBAL}`) | Enforced: every group's interpreter is created under the lock and joins it, whenever its first request comes, overlapping first requests included. Also in embedded mode, with applications that never import tethered, and after a graceful restart. | `modwsgi` |
| Several groups, every script imported at process start, the locking one first | Enforced. | `modwsgi` |
| A launcher that activates and then executes Apache | Enforced: every interpreter of every process starts under the policy. | `modwsgi` |
| Several groups, loaded at their first requests, with nothing arranged | **One application can end up with no network.** When two first requests overlap, one application takes the lock and the other, whose interpreter already existed, is outside it: `TetheredLocked`, and every connection and launch refused. Nothing forbidden is reached. With `threads=1` in the daemon process, and every application locking the same policy, the requests cannot overlap. | `modwsgi` |
| Several groups, a script imported before the lock is taken | No network for that application, in every process. | `modwsgi` |
| A virtual environment through `python-home` | Enforced, child processes included. | `modwsgi` |
| A virtual environment through `python-path` | Only the interpreter that activates is covered: a second group cannot join the lock, and a Python child is the system Python without tethered (warned about; refused under `"block"`). | `modwsgi` |
| Unlocked policies in two groups of one process | Each enforces its own on its connections; a Python child, and an interpreter created later, get the policy activated last. | `modwsgi` |
| `%{GLOBAL}` next to other groups in one process | mod_wsgi does not always run a `%{GLOBAL}` request in the main interpreter: it can run inside the interpreter of another group, with or without tethered. Under a lock held by that other group, such a request gets the other group's policy or no network. Nothing forbidden is reached. | `modwsgi` |

On Python 3.12, `WSGIPerInterpreterGIL On` crashed the daemon process as soon as a second group loaded an application, with and without tethered (measured once, 32 of 32 starts); the suite does not run that combination.

### Flask and Django

Measured with Flask 3.1.3 (Werkzeug 3.1.9) and Django 6.1.2 (5.2.18 on Python 3.11), under gunicorn 26.2.0, with requests 2.34.2.

| Arrangement | Result | Pinned by |
|---|---|---|
| Flask, `activate()` in the application factory: gunicorn with and without `--preload`, a `flask` command, `flask run` with and without its reloader | Enforced. The process the reloader starts inherits the policy. | `flask` |
| Flask, an error handler registered for `tethered.EgressBlocked` | Reached for a refused lookup and a refused connection. | `flask` |
| Django, `activate()` in `settings.py`: gunicorn with and without `--preload`, a management command, `runserver` with and without its autoreloader | Enforced. | `django` |
| Django, a middleware that catches `EgressBlocked` around `get_response()` | Does not work: Django has turned the view's exception into a 500 before `get_response()` returns. A middleware with `process_exception()` gives the 503: see [the cookbook](COOKBOOK.md#django--fastapi-middleware). | `django` |
| `requests` | Passes `EgressBlocked` through unwrapped; an adapter with `max_retries=3` makes one attempt. | `flask` |

### What holds under every server

**An uncaught `EgressBlocked` does not take a worker down.** The request fails the way any uncaught exception does on that server, and the worker keeps serving: a 500 under uvicorn, hypercorn, granian, sanic, aiohttp, daphne, tornado's own server, gunicorn's sync, gthread and gevent workers, waitress, mod_wsgi, Flask and Django; no response under gunicorn's tornado worker (the connection stays open) and under uWSGI (the connection is closed). Those two servers do the same with any uncaught exception when tethered is not installed.

**Process launches from a handler**, under a locked policy with the default `external_subprocess_policy="warn"` (suites `gunicorn`, `modwsgi`, and each server suite for the first and the last row):

| Launch | Result |
|---|---|
| `[sys.executable, ...]` | The child inherits the locked policy and enforces it. |
| `[sys.executable, ...]` with an `env=` that lacks `_TETHERED_CHILD_POLICY` | The child is given the variable and inherits the locked policy. |
| `["python3", ...]` | Warned about as external, although this child does inherit. Refused under `"block"`. |
| `[sys.executable, "-S", ...]` | Warned about; the child has no policy. Refused under `"block"`. |
| `["bash", ...]` or any other program | Warned about; the program can reach anything. Refused under `"block"`. |

**`external_subprocess_policy="block"` refuses what libraries launch, too.** On Linux, `ctypes.util.find_library()` runs `ldconfig`, and `platform.platform()` runs `uname`. Under `"block"`:

- `ctypes.util.find_library()` raises `SubprocessBlocked` (suite `clients`), and with it the import of trio (suite `hypercorn`). asyncssh and psycopg 3 in its Python implementation make the same call while they are imported. Import such libraries before `activate()`.
- `celery worker` does not start: its banner calls `platform.platform()`, which catches only `OSError` (suite `celery`). Call `platform.platform()` once before `activate()`; it caches the answer.

Under the default `"warn"` these launches are logged as external launches and carried out, under a locked policy as well.

**A locked policy survives whatever re-executes the server.** The new process image inherits the locked policy from its environment before the application is imported, and a locked policy cannot be changed without its token. So an application that asks for a different locked policy after a re-execution gets `TetheredLocked`:

| Re-execution | What happens with a changed locked policy | Pinned by |
|---|---|---|
| uWSGI reload (`SIGHUP`, `--py-autoreload`) | Uncaught, uWSGI has no application and answers every request with a 500 until it is stopped and started. Caught, the old policy stays in force. | `uwsgi` |
| gunicorn `SIGUSR2` with `--preload` | The new master does not start; the old one keeps serving under the old policy. | `gunicorn` |
| Django `runserver` with its autoreloader | The child cannot import its settings and `runserver` exits with status 1. | `django` |
| mod_wsgi in embedded mode, a touched script | Every request is a 500 until Apache's child processes are replaced. | `modwsgi` |

Not affected: uWSGI with `--lazy-apps`, gunicorn without `--preload`, mod_wsgi in daemon mode (a touched script restarts the process), and unlocked policies. The same policy asked for again is a no-op everywhere. To change a locked policy, stop the server and start it.

## Task queues and process pools

In every system below, each process that runs task code held the policy, plain and locked, including processes started later, and a Python child of a task inherited it. The suites use Redis 8 on loopback as broker and result store.

| System | Arrangement | Result | Pinned by |
|---|---|---|---|
| Celery | `activate()` when the application module is imported: prefork, threads, solo and gevent pools; `--max-tasks-per-child`, a replacement for a killed pool process, `--autoscale`, a `SIGHUP` restart; `--beat` and a beat process of its own | Enforced. The gevent pool has the hazard described below the table. | `celery` (celery 5.6.3, kombu 5.6.2, billiard 4.3.1) |
| Celery | `activate()` in a `worker_init` handler | Enforced in every pool. | `celery` |
| Celery | `activate()` only in a `worker_process_init` handler | Enforced in the prefork pool's children (recycled ones too) and in the solo pool. **No policy at all** with `--pool threads` and `--pool gevent`: Celery never sends that signal there. | `celery` |
| Celery | eventlet pool | Allowed host refused; enforced with `EVENTLET_NO_GREENDNS=yes`, or with a rule for the address. | `celery` (eventlet 0.41.2) |
| Celery | `external_subprocess_policy="block"` | `celery worker` does not start, unless `platform.platform()` was called before `activate()`. | `celery` |
| RQ | `Worker` (a work horse forked per job), `SimpleWorker`, `SpawnWorker`, `rq worker-pool`, the scheduler | Enforced. With `activate()` in the jobs module every job is covered and the worker process itself holds no policy; with `rq worker -c settings` and `activate()` in the settings module both are. | `rq` (rq 2.12.0) |
| Dramatiq | Worker processes forked, from a fork server, or spawned (`--use-spawn`); a reload; `activate()` at import or in an `after_process_boot` middleware hook | Enforced in every worker process. The parent never imports the application and holds no policy. | `dramatiq` (dramatiq 2.2.1) |
| Huey | Thread and process workers; `--max-tasks`, a replacement for a killed worker, a `SIGHUP` restart; `activate()` at import or in an `on_startup` hook | Enforced. | `huey` (huey 3.4.0) |
| arq | `arq module.WorkerSettings`, coroutine jobs and cron jobs; `activate()` at import or in `on_startup` | Enforced, on asyncio's own loop. | `arq` (arq 0.28.0) |
| `multiprocessing.Pool`, `ProcessPoolExecutor` | fork, spawn and forkserver; recycled workers and a replacement for a dead one; `external_subprocess_policy="block"` | Enforced. A worker can neither release nor replace a locked policy. | `stdlib_pools` |
| `multiprocessing.Pool`, `ProcessPoolExecutor` | Workers started before `activate()` | **No policy** until they are replaced; the replacements enforce. | `stdlib_pools` |
| `multiprocessing`, the forkserver start method | A fork server started before `activate()` | **Every later worker has no policy**, under a locked policy too. See below. | `stdlib_pools` |
| `InterpreterPoolExecutor` (Python 3.14+) | A worker interpreter started under a lock | Enforced: it joins the lock. Under a plain policy it activates the policy it finds. | `stdlib_pools` |
| `InterpreterPoolExecutor` | A worker interpreter that existed before the lock | No network at all while the lock is held. One that existed before a plain `activate()` holds no policy. | `stdlib_pools` |
| supervisord | An entry point that activates and then executes supervisord, which starts a Python program | Enforced in the program and in its restarts: the policy travels in the environment. A program whose environment is wiped (`env -i`) starts without it. | `supervisor` (supervisord 4.2.5) |

**The fork server.** A worker of the `forkserver` start method is a copy of the fork server process, not of the process that asks for it. A fork server that was started before `activate()` holds no policy, and neither does any worker it produces from then on, also after `activate(locked=True)`. Asking it for a worker goes over a socket and raises no launch event, so tethered can neither refuse nor complete it. forkserver is the default start method on Linux from Python 3.14. `activate()` logs one warning when it finds a fork server already running. Call `activate()` before the first pool or process is started; a fork server that starts under the policy passes it on.

**A broker that is addressed by name has to be in the allow list.** Otherwise the Celery worker ends at start-up with `EgressBlocked` for the broker's address (suite `celery`). kombu retries connection errors; `EgressBlocked` is not one, so the mistake is not retried for ever.

**Celery's gevent pool and a lookup that never returns.** The hazard of gevent's thread-pool resolver, described under [gunicorn](#gunicorn), is there with `--pool gevent` too: when refused lookups overlap, the task of one of them now and then never finishes. The worker goes on running other tasks. A warm shutdown (`SIGTERM`) waits for running tasks without a time limit, so with such a task it does not end. Measured once, on Python 3.12 and 3.13 with Celery 5.6.3 and gevent 26.9.0, not asserted by a suite: under eight refused lookups at a time a task was stuck after 152 and after 328 lookups, the worker was still running two minutes after `SIGTERM`, and it ended at once when it was then sent `SIGQUIT`, Celery's cold shutdown.

**What an operator sees for a refused task.** Nothing arrived in any of these, and in no system did the workers die.

| System | Task state and log | Retries | What the producer gets |
|---|---|---|---|
| Celery | `FAILURE`; `Task ... raised unexpected: EgressBlocked('Blocked by tethered: ...')` with the traceback | `autoretry_for=(Exception,)` retries it; `autoretry_for=(OSError,)` does not | `result.get()` raises `tethered.EgressBlocked` in a producer that has tethered loaded, with the JSON result serializer (the attributes are read back out of the message) and with `result_serializer="pickle"`. With JSON, a producer that has not imported tethered gets a class of Celery's own that is named `EgressBlocked`. |
| RQ | `failed`; the traceback is stored with the job | `Retry(max=2)` is used up | The traceback text. |
| Dramatiq | `Failed to process message ... with unhandled exception.` | The Retries middleware retries it | `ResultFailure` naming `EgressBlocked`. |
| Huey | `Unhandled exception in task ...` | `retries=2` gives three attempts | `TaskException`. |
| arq | `... failed, EgressBlocked: ...` | Not retried | The `EgressBlocked` itself, with its attributes. |
| The standard library's process pools | | | `EgressBlocked` from `.get()` / `.result()`; the pool is not broken. |

## Scopes

A `tethered.scope()` around the work of one request or one task, in a process whose policy allows more than the scope does. Measured with gunicorn 26.2.0, uvicorn 0.54.0 on the standard loop, gevent 26.9.0, Celery 5.6.3 and eventlet 0.41.2.

| Where the scope is entered | Result | Pinned by |
|---|---|---|
| A request under gunicorn's sync and gthread workers | Enforced. Inside the scope only what the scope allows is reached. The request that follows on the same thread is not restricted, and a request served at the same time on another thread is not affected. | `gunicorn` |
| A request under uvicorn, on the standard loop | Enforced for everything the request does on the loop (streams, `loop.create_connection`, `loop.sock_connect`, datagrams), for a blocking call made in the loop and for `asyncio.to_thread`. A request handled at the same time by another task is not affected. | `uvicorn` |
| A request under gunicorn's gevent workers (`gevent`, `gevent_pywsgi`) | Enforced. A request served at the same time by another greenlet is not affected. | `gunicorn_gevent` |
| A Celery task, in the prefork, threads, solo, gevent and eventlet pools | Enforced. Tasks that run at the same time in one process (threads, gevent, eventlet) do not see each other's scope. | `celery` |
| A scope in an application that never calls `activate()` | Enforced inside the scope; nothing is refused outside it. | `gunicorn`, `uvicorn`, `gunicorn_gevent` |
| A scope that allows what the policy refuses | Refused by the policy. A scope cannot widen it. | `gunicorn`, `uvicorn`, `gunicorn_gevent`, `celery` |
| A log-only scope | Refuses nothing and logs `would block`. | `gunicorn` |
| A Python child launched inside the scope with `subprocess` or, on the standard loop, `asyncio.create_subprocess_exec` | The child holds, from its start, the policy of the process narrowed by the scope. Also under gevent, whose `Popen` forks and calls `os.exec*` itself (gunicorn's gevent workers, Celery's gevent pool), and from a Celery task in the eventlet pool. | `gunicorn`, `uvicorn`, `gunicorn_gevent`, `celery` |

What a scope does not reach:

- **Another thread.** A thread started inside the block, and work handed to `loop.run_in_executor`, run without the scope and reach what it refuses; the policy of the process still applies to them. `asyncio.to_thread` copies the context and stays inside the scope. Under gevent a "thread" is a greenlet, and it starts without the scope in the same way. Suites: `gunicorn`, `uvicorn`, `gunicorn_gevent`.
- **A name lookup made in a pool thread.** asyncio's loop and gevent's default resolver call `getaddrinfo` in a thread of a pool, which does not carry the scope. The DNS query for a name the scope refuses therefore leaves the process; a connection to that name is refused by the scope. A blocking lookup in the thread that entered the scope is refused before any query is sent. Suites: `uvicorn`, `gunicorn_gevent`.

Scopes were not measured under the other servers and task queues of this page.

## Client libraries

Each library was asked for the four destinations under the policy `allow=["allowed.test:9001"]`, and, as a control, with no tethered and an audit hook that records what events the library raises. The table is the one the `clients` suite prints at the end of a run; this copy is from a run on Python 3.13. `clients_niquests` measures niquests in the same way. Every row is the same under a locked policy as under a plain one.

Of the 70 arrangements of the `clients` suite, 47 are enforced, 13 are not seen, 4 are partly enforced, and in 6 an allowed host is refused. The two niquests arrangements are one of each of the first and the last kind.

| Result | Forbidden name | Forbidden address | Allowed name | Allowed name, other port | Was the forbidden name sent to the name server? |
|---|---|---|---|---|---|
| Enforced | refused | refused | reached | refused | no |
| Not seen | **reached** | **reached** | reached | **reached** | yes |
| Partly enforced | refused | **reached** | reached | **reached** | no |
| Allowed host refused | refused | refused | **refused** | refused | yes |

The column "A refused name reaches the caller as" says what the code that called the library gets when the forbidden name is refused.

### HTTP and WebSocket clients

| Library and arrangement | Result | Why | A refused name reaches the caller as | Measured with |
|---|---|---|---|---|
| `urllib.request` | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | standard library |
| `http.client` | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | standard library |
| requests | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | requests 2.34.2, urllib3 2.8.0 |
| urllib3 | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | urllib3 2.8.0 |
| httplib2 | Enforced | `socket.getaddrinfo`, then `socket.connect` with the host name | `EgressBlocked` | httplib2 0.32.0 |
| httpx, sync | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | httpx 0.28.1, httpcore 1.0.9 |
| httpx, async on asyncio | Enforced | asyncio: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets | `EgressBlocked` | httpx 0.28.1, httpcore 1.0.9, anyio 4.15.1 |
| httpx, async on trio | Enforced | trio: `socket.getaddrinfo` in a worker thread, `socket.connect` on its sockets | `EgressBlocked` | httpx 0.28.1, httpcore 1.0.9, trio 0.34.0 |
| aiohttp, aiodns installed, the policy active before aiohttp is imported | Enforced | tethered keeps pycares from loading, and aiohttp uses its threaded resolver: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets | `EgressBlocked` | aiohttp 3.14.4, aiodns 4.0.4, pycares 5.1.0 |
| aiohttp, aiodns installed, aiohttp imported before the policy | **Allowed host refused** | c-ares resolves in C; the connection is a Python socket's | `EgressBlocked` | aiohttp 3.14.4, aiodns 4.0.4, pycares 5.1.0 |
| aiohttp, aiodns not installed | Enforced | asyncio: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets | `EgressBlocked` | aiohttp 3.14.4 |
| aiohttp, aiodns installed, `TCPConnector(resolver=ThreadedResolver())` | Enforced | asyncio: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets | `EgressBlocked` | aiohttp 3.14.4, aiodns 4.0.4 |
| pycurl | **Not seen** | libcurl resolves and connects in C | nothing is refused | pycurl 7.48.0 |
| curl_cffi | **Not seen** | libcurl resolves and connects in C | nothing is refused | curl_cffi 0.16.3 |
| tornado, `SimpleAsyncHTTPClient` (its default) | Enforced | asyncio: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets | `EgressBlocked` | tornado 6.5.10 |
| tornado, `CurlAsyncHTTPClient` | **Not seen** | libcurl resolves and connects in C | nothing is refused | tornado 6.5.10, pycurl 7.48.0 |
| websockets, asyncio client | Enforced | asyncio: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets | `EgressBlocked` | websockets 17.2 |
| websockets, sync client | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | websockets 17.2 |
| niquests, as it comes (the system resolver) | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | niquests 3.21.2, urllib3-future 2.25.902 |
| niquests with a resolver of its own (`Session(resolver="dou://...")`) | **Allowed host refused** | urllib3-future makes the DNS queries itself; the connection is a Python socket's | not asserted (the refusal comes at the connection, by address) | niquests 3.21.2, urllib3-future 2.25.902 |

### PostgreSQL

| Library and arrangement | Result | Why | A refused name reaches the caller as | Measured with |
|---|---|---|---|---|
| psycopg2 (psycopg2-binary) | **Not seen** | libpq resolves and connects in C | nothing is refused | psycopg2-binary 2.9.13 |
| psycopg 3, binary implementation, sync | **Partly enforced** | `socket.getaddrinfo` in Python, then libpq connects to the address in C | `EgressBlocked` | psycopg 3.3.6, psycopg-binary 3.3.6 |
| psycopg 3, binary implementation, async | **Partly enforced** | `socket.getaddrinfo` in Python, then libpq connects to the address in C | `EgressBlocked` | psycopg 3.3.6, psycopg-binary 3.3.6 |
| psycopg 3, Python implementation (libpq through ctypes), sync | **Partly enforced** | `socket.getaddrinfo` in Python, then libpq connects to the address in C | `EgressBlocked` | psycopg 3.3.6 |
| psycopg 3, Python implementation (libpq through ctypes), async | **Partly enforced** | `socket.getaddrinfo` in Python, then libpq connects to the address in C | `EgressBlocked` | psycopg 3.3.6 |
| asyncpg | Enforced | asyncio: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets | `EgressBlocked` | asyncpg 0.32.0 |
| pg8000 | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | pg8000 1.31.5 |

### MySQL

| Library and arrangement | Result | Why | A refused name reaches the caller as | Measured with |
|---|---|---|---|---|
| PyMySQL | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | PyMySQL 1.2.3 |
| aiomysql | Enforced | asyncio: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets | `EgressBlocked` | aiomysql 0.3.2 |
| mysqlclient (MySQLdb) | **Not seen** | the MariaDB / MySQL client library resolves and connects in C | nothing is refused | mysqlclient 2.3.0 |
| mysql-connector-python, `use_pure=True` | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | mysql-connector-python 26.7.0 |
| mysql-connector-python, C extension (its default when the extension is there) | **Not seen** | the bundled MySQL client library resolves and connects in C | nothing is refused | mysql-connector-python 26.7.0 |

### SQL Server and Oracle

| Library and arrangement | Result | Why | A refused name reaches the caller as | Measured with |
|---|---|---|---|---|
| pymssql | **Not seen** | FreeTDS resolves and connects in C | nothing is refused | pymssql 2.4.4 |
| pyodbc with the FreeTDS ODBC driver | **Not seen** | the ODBC driver resolves and connects in C | nothing is refused | pyodbc 5.3.0 |
| oracledb, thin mode | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | oracledb 26.0.1 |
| oracledb, thin mode, async | Enforced | asyncio: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets | `EgressBlocked` | oracledb 26.0.1 |

### Redis, MongoDB, memcached

| Library and arrangement | Result | Why | A refused name reaches the caller as | Measured with |
|---|---|---|---|---|
| redis-py, hiredis installed | Enforced | `socket.getaddrinfo` and `socket.connect`; hiredis only parses replies | `EgressBlocked` | redis 8.1.0, hiredis 3.4.2 |
| redis-py, hiredis not installed | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | redis 8.1.0 |
| redis-py asyncio, hiredis installed | Enforced | asyncio: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets; hiredis only parses replies | `redis.ConnectionError`, with `EgressBlocked` chained | redis 8.1.0, hiredis 3.4.2 |
| redis-py asyncio, hiredis not installed | Enforced | asyncio: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets | `redis.ConnectionError`, with `EgressBlocked` chained | redis 8.1.0 |
| pymongo, `MongoClient` | Enforced | `socket.getaddrinfo` and `socket.connect` | `ServerSelectionTimeoutError`; the refusal is in its text only | pymongo 4.18.3 |
| pymongo, `AsyncMongoClient` | Enforced | asyncio: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets | `ServerSelectionTimeoutError`; the refusal is in its text only | pymongo 4.18.3 |
| pymemcache | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | pymemcache 4.0.0 |

### Messaging and RPC

| Library and arrangement | Result | Why | A refused name reaches the caller as | Measured with |
|---|---|---|---|---|
| grpcio | **Not seen** | the gRPC core resolves and connects in C | nothing is refused | grpcio 1.84.0 |
| grpcio, `grpc.aio` | **Not seen** | the gRPC core resolves and connects in C | nothing is refused | grpcio 1.84.0 |
| pika | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | pika 1.4.4 |
| amqp (py-amqp, the transport of kombu and Celery) | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | amqp 5.4.1 |
| kafka-python | Enforced | `socket.getaddrinfo` and `socket.connect` | `KafkaTimeoutError: Unable to bootstrap`, which does not mention tethered | kafka-python 3.0.11 |
| confluent-kafka | **Not seen** | librdkafka resolves and connects in C | nothing is refused | confluent-kafka 2.16.0 |
| nats-py | Enforced | asyncio: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets | `NoServersError`, which does not mention tethered | nats-py 2.16.0 |
| pyzmq | **Not seen** | libzmq resolves and connects in C | nothing is refused | pyzmq 27.2.0 |

### Cloud SDKs

| Library and arrangement | Result | Why | A refused name reaches the caller as | Measured with |
|---|---|---|---|---|
| boto3 / botocore, awscrt installed | Enforced | urllib3: `socket.getaddrinfo` and `socket.connect` | botocore's `HTTPClientError`, with `EgressBlocked` chained | boto3 1.43.111, botocore 1.43.111, urllib3 2.8.0, awscrt 0.37.0 |
| awscrt (`awscrt.http`), the transport of boto3's optional CRT transfer manager | **Not seen** | the AWS Common Runtime resolves and connects in C | nothing is refused | awscrt 0.37.0 |
| google-cloud-storage | Enforced | requests: `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | google-cloud-storage 3.17.0, requests 2.34.2 |

### Sockets, standard-library protocol clients, SSH

| Library and arrangement | Result | Why | A refused name reaches the caller as | Measured with |
|---|---|---|---|---|
| `socket.create_connection` | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | standard library |
| `asyncio.open_connection` | Enforced | asyncio: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets | `EgressBlocked` | standard library |
| smtplib | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | standard library |
| ftplib | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | standard library |
| paramiko | Enforced | `socket.getaddrinfo` and `socket.connect` | `EgressBlocked` | paramiko 5.0.0 |
| asyncssh | Enforced | asyncio: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets | `EgressBlocked` | asyncssh 2.24.1 |

### A resolver of the library's own, then a Python socket

| Library and arrangement | Result | Why | A refused name reaches the caller as | Measured with |
|---|---|---|---|---|
| dnspython lookup (`dns.resolver`), then a socket connection to the address | **Allowed host refused** | its own DNS client: `socket.sendto` to the name server, no `socket.getaddrinfo` | `EgressBlocked` | dnspython 2.9.0 |
| pycares imported before the policy: a lookup, then a socket connection to the address | **Allowed host refused** | c-ares resolves in C; the connection is a Python socket's | `EgressBlocked` | pycares 5.1.0 |
| aiodns imported before the policy: a lookup, then `asyncio.open_connection` to the address | **Allowed host refused** | c-ares resolves in C; the connection is a Python socket's | `EgressBlocked` | aiodns 4.0.4, pycares 5.1.0 |

### Other runtimes

| Library and arrangement | Result | Why | A refused name reaches the caller as | Measured with |
|---|---|---|---|---|
| `trio.open_tcp_stream` | Enforced | trio: `socket.getaddrinfo` in a worker thread, `socket.connect` on its sockets | `EgressBlocked` | trio 0.34.0 |
| `anyio.connect_tcp` on asyncio | Enforced | asyncio: `socket.getaddrinfo` in the loop's executor, `socket.connect` on its sockets | `EgressBlocked` | anyio 4.15.1 |
| `anyio.connect_tcp` on trio | Enforced | trio: `socket.getaddrinfo` in a worker thread, `socket.connect` on its sockets | `EgressBlocked` | anyio 4.15.1, trio 0.34.0 |
| gevent, `monkey.patch_all()`, `urllib.request` (its default resolver, a thread pool) | Enforced | `socket.getaddrinfo` in gevent's thread pool; the green socket calls `socket.connect` | `EgressBlocked` | gevent 26.9.0 |
| gevent, `monkey.patch_all()`, `GEVENT_RESOLVER=ares` | **Allowed host refused** | c-ares resolves in C; the green socket calls `socket.connect` | `EgressBlocked` | gevent 26.9.0 |
| eventlet, `monkey_patch()`, `urllib.request` (greendns, its default) | **Allowed host refused** | greendns (dnspython): `socket.sendto` to the name server, no `socket.getaddrinfo` for the name; the green socket calls `socket.connect` | `EgressBlocked` | eventlet 0.41.2, dnspython 2.9.0 |
| eventlet, `monkey_patch()`, `EVENTLET_NO_GREENDNS=yes` | Enforced | `socket.getaddrinfo` itself; the green socket calls `socket.connect` | `EgressBlocked` | eventlet 0.41.2 |
| Twisted, `reactor.connectTCP` (`TCP4ClientEndpoint`) | Enforced | `socket.getaddrinfo` in the reactor's thread pool, `socket.connect_ex` on its sockets | Twisted's `TimeoutError`, after the connection timeout | Twisted 26.4.0 |
| Twisted, `twisted.web.client.Agent` (`HostnameEndpoint`) | Enforced | `socket.getaddrinfo` in the reactor's thread pool, `socket.connect_ex` on its sockets | nothing: the request never completes | Twisted 26.4.0 |

### Notes on the table

**Refusals at the connection can arrive inside an `ExceptionGroup`.** The last column is about a refused name, which is refused at the lookup. `httpx.AsyncClient`, `anyio.connect_tcp` and `trio.open_tcp_stream` deliver a refusal at the connection (a port rule, or a raw address) inside an `ExceptionGroup`, which `except tethered.EgressBlocked` does not catch. Use `except*` ([the cookbook](COOKBOOK.md#django--fastapi-middleware)).

**What makes a library that resolves names itself work.** Each of these was measured:

- aiohttp: call `activate()` before aiohttp is imported, or pass `aiohttp.TCPConnector(resolver=aiohttp.ThreadedResolver())`, or uninstall aiodns.
- eventlet: `EVENTLET_NO_GREENDNS=yes`.
- gevent: its default resolver, not `ares`.
- niquests: no `resolver=` argument.
- Any of them: one lookup of the name through the standard resolver by the application before the library is used, which gives tethered the name. The suite calls `_socket.getaddrinfo(host, port)` or `_socket.gethostbyname(host)`, the C functions behind the `socket` module's, because gevent and eventlet replace `socket.getaddrinfo` with their own resolver. Or a rule for the address itself; the library's own resolver then still sends every name it is asked for to the name server.

The first time a connection is refused to an address that tethered has no name for, under a policy with hostname rules, tethered logs one line that says where the name may have gone (`tethered: no hostname is known for the refused address ...`). It is said once per process.

**pycares is kept from loading.** With a policy active that is not `log_only`, `import pycares` raises `ImportError`, and so does `import aiodns`. aiohttp then uses `ThreadedResolver`. A pycares that was imported before `activate()` is left alone, and `activate()` is not refused: what it resolves is refused at the connection, so nothing gets out unnoticed, with one exception. c-ares sends its DNS queries in C: a query to a name server at a forbidden address is sent (pinned by `clients`), where the same query by dnspython is refused at `socket.sendto`. Under a `log_only` policy pycares loads, and aiohttp with aiodns then reports the allowed host as blocked, by its address.

**Loaded is not used.** Whether a C library's networking is in play cannot be read from what is imported: `_awscrt` is loaded by every botocore import when awscrt is installed, although boto3 keeps using urllib3; `grpc._cython.cygrpc` is loaded by google-cloud-storage, which makes its requests with requests; `psycopg2._psycopg` is loaded by `eventlet.monkey_patch()`.

**Not in the table:** psycopg 3's `c` implementation (the same code as `binary`, built against the system's libpq); boto3's CRT transfer manager (it could not be pointed at the test destinations; its transport is the `awscrt` row); gevent's dnspython resolver (with gevent 26.9.0 and dnspython 2.9.0 it resolves nothing, with or without tethered). On Python 3.15 confluent-kafka and the C extension of mysql-connector-python had no wheel when this was measured, so those two rows are from Python 3.11 to 3.14.

## Installing, upgrading and removing tethered

What tethered puts on disk is what its wheel holds: the `tethered/` package with the compiled extension, `tethered.pth` beside it, and the `.dist-info` directory. At run time it writes no file. While a policy is active it keeps `_TETHERED_CHILD_POLICY` in the environment of the process, where every child program finds the allow list, and `deactivate()` removes it. `tethered.pth` is read by every interpreter that starts in the environment, and it imports tethered only when that variable is set.

The rows below are measured once, with pip 26.2.1 and uv 0.13.0 on Python 3.13, on Linux (the image of a suite; `python:3.13-slim` for uv) and on Windows 11. No suite asserts them.

| Arrangement | What happens |
|---|---|
| `pip uninstall tethered` from a shell, or from a process that holds no policy | Nothing is left in site-packages. |
| The same from a Python child of a process that holds an unlocked policy, on Linux | Works, and nothing is left. The pip process itself runs under the policy it inherited. |
| The same on Windows, and `pip install --force-reinstall` there | pip removes or replaces the package but cannot delete the extension module, which is loaded: `site-packages\~ethered\_guardian.cp313-win_amd64.pyd` stays behind, with a warning from pip. Delete the directory once the process has ended. |
| `pip uninstall tethered` or `pip install --force-reinstall` (an upgrade takes the same route) from a Python child of a process that holds a **locked** policy | Refused. pip gets `SubprocessBlocked` when it moves `tethered.pth` and exits with status 2. By then it has renamed `tethered-<version>.dist-info` to `~ethered-<version>.dist-info`, and it does not rename it back: tethered still works and enforces, and pip no longer lists it (`WARNING: Ignoring invalid distribution ~ethered`). To repair, rename the directory back from outside the locked processes; pip then lists and removes the package as before. |
| `shutil.rmtree()` of the environment a locked process runs from, on Linux | Refused at `tethered.pth`, with whatever it had removed before that gone. |
| `uv pip uninstall tethered` launched from a locked process, on Windows | uv is not Python, so the guard does not see what it does; the launch is logged as external (and refused under `external_subprocess_policy="block"`). It removed `tethered.pth` and most of the package, then failed at the loaded extension module. |
| tethered installed by uv (`uv add`, `uv pip install`), on Linux and on Windows | `tethered.pth` in site-packages is a hard link to a file of the same name in uv's cache; with `--link-mode=copy` it is a file of its own, as with pip. Under a locked policy a write to the cache's file is refused like a write to the hook itself. |
| Another distribution that ships a top-level `tethered.pth`, installed after tethered with pip or with uv | It replaces tethered's file, and neither installer says so. tethered does not take that file for its bootstrap: `activate()` logs a warning, and a Python child is an external launch (refused under `external_subprocess_policy="block"`). Uninstalling that distribution with pip removes `tethered.pth` altogether; reinstall tethered. |

Install, upgrade and remove tethered from outside the processes that hold a locked policy: a deployment step or a shell, not a child of the application. The locked-mode guard on `tethered.pth` is described in [the subprocess page](SUBPROCESS.md#locked-mode-hardening-of-the-auto-propagation-channel); it refuses the file by its name and directory, however the installer names that directory, and the same file where uv keeps it in its cache. Windows does not delete a loaded extension module for any installer, so the `~ethered` directory is to be expected whenever tethered is upgraded while a process has it imported.

## What was not tested

- **Installers.** Anything but pip 26.2.1 and uv 0.13.0 on Python 3.13, and of uv only the arrangements above. conda, poetry and pipx were not run.
- **Platforms.** Windows and macOS servers, musl (Alpine), ARM, and free-threaded builds of Python. Everything here ran on Linux x86-64 with glibc. The unit tests in `tests/` run on Windows and Linux; they do not start servers.
- **The network itself.** The destinations are on the loopback interface of a container without a network. TLS, proxies, connection reuse, HTTP/2 and HTTP/3, and real DNS were not exercised. WebSockets were tested as a client (`websockets`), not as a server protocol.
- **Client libraries.** oracledb in thick mode, pyodbc with Microsoft's driver, the `c` implementation of psycopg 3, pyarrow, polars and duckdb, DNS over HTTPS, TLS or QUIC in niquests, and what any client library does on uvloop.
- **Asynchronous servers.** Litestar, Django Channels itself and Django's ASGI entry point, gunicorn's own ASGI worker beyond its choice of loop, granian `--reload` and its embedded server, sanic's inspector and ASGI mode, hypercorn and sanic with a worker that is killed, arq with `--watch`.
- **WSGI servers.** uWSGI's emperor, mules, spooler, cheaper mode and `--touch-reload`, its gevent and asyncio plugins, and uWSGI behind a web server that speaks the uwsgi protocol; waitress on anything but TCP; a mod_wsgi packaged by a distribution, Apache's worker MPM, and mod_wsgi on Windows; the Flask reloader with a changed locked policy.
- **Task queues.** Brokers other than Redis, `celery multi` and `--detach`, Celery's pool-restart remote control, `rq cron`, `dramatiq-gevent`, Huey's greenlet workers, `supervisorctl`, `multiprocessing.Process` on its own and managers.
- **uvicorn releases other than 0.54.0 and 0.46.0.** The statements about 0.47.0, 0.50.0 and 0.36.0 come from single runs.
