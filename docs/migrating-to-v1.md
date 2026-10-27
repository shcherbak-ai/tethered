---
title: "Migrating to 1.0"
description: "Upgrading tethered from 0.5.x to 1.0.0: the breaking changes by what a deployment uses, the message each one shows, and the change that puts it right."
---

# Migrating to 1.0

For a deployment that runs tethered 0.5.x and moves to 1.0.0. The page is written against 0.5.3, the last release before it. The [changelog](https://github.com/shcherbak-ai/tethered/blob/main/CHANGELOG.md#100--2026-10-13) lists every change; this page has the ones that ask something of you, ordered by what a deployment uses.

No function, parameter or exception was renamed or removed: `activate()`, `scope()` and `deactivate()` take what they took in 0.5.3. What changed is what tethered does where a policy would not be applied. 0.5.3 went on in those cases, and the process ran under a policy that covered less than it said: nothing that went through a uvloop event loop, no Python child of an editable install, and for some malformed rules more destinations than were written. 1.0.0 refuses instead, when the policy is set or at the call, with a message that names the way out. The upgrade therefore tends to show at start-up, and most of what it shows was not enforced before.

## Which sections apply

| If the deployment | Read |
|---|---|
| runs on Python 3.10 | [Python version](#python-version) |
| serves with uvicorn, FastAPI, hypercorn, granian or sanic, or has uvloop installed for another reason | [uvloop](#uvloop) |
| uses aiohttp with aiodns, or pycares itself | [pycares and aiodns](#pycares-and-aiodns) |
| has an allow list that was never checked rule by rule | [Allow rules](#allow-rules) |
| starts Python child processes, sets `external_subprocess_policy="block"`, or runs from an editable or `--target` install | [Child processes](#child-processes) |
| passes `locked=True` | [Locked mode](#locked-mode) |
| locks a policy in a process with several interpreters (mod_wsgi, uWSGI mounts, `InterpreterPoolExecutor`) | [Interpreters under a lock](#interpreters-under-a-lock) |
| installs audit hooks of its own, or has an allow list of a thousand rules and more | [Errors from activate() and scope()](#errors-from-activate-and-scope) |
| runs a `log_only` rollout, or filters and alerts on tethered's log lines | [Log lines and messages](#log-lines-and-messages) |
| copied the Django middleware from the cookbook | [Recipes and links](#recipes-and-links) |

Two further sections are for everyone: [fixes that refuse more](#fixes-that-refuse-more) than 0.5.3 did, and [what became less strict](#what-became-less-strict), with the workarounds that are no longer needed.

## How to upgrade

1. **Move to Python 3.11 or later** if the environment is on 3.10 ([below](#python-version)).
2. **Upgrade from a shell or a deployment step, with the application stopped.**

    ```bash
    uv add "tethered>=1.0"
    ```

    Or `pip install --upgrade tethered`. Do not let the application upgrade its own environment: pip started as a Python child of a process with a locked policy inherits the lock, is refused the change to `tethered.pth`, and stops halfway ([what that leaves behind](COMPATIBILITY.md#installing-upgrading-and-removing-tethered)).

3. **Stop and start; do not reload.** A process that keeps running keeps the tethered it imported, while the Python children it starts load the new one, and a 1.0.0 child that is handed a locked or fail-closed policy with a rule it rejects does not start. A reload that re-executes the server (gunicorn's `SIGUSR2`, a uWSGI reload) also hands a locked policy on to the new process, which cannot replace it ([changing a locked policy](COOKBOOK.md#changing-a-locked-policy)).
4. **Start it once where a failed start costs nothing, and read the log.** Everything below shows as an exception or as a `tethered:` line in the log, and each message says what to change.

## Python version

tethered 1.0.0 requires Python 3.11 and has no wheels for 3.10, which reached the end of its security support in October 2026. An installer leaves an environment on Python 3.10 at 0.5.3, without the fixes of this release.

What to do: move the environment to Python 3.11 or later. 3.11 to 3.15 are supported.

## uvloop

**Who is affected.** An asyncio server in an environment that has uvloop installed. uvloop comes with `uvicorn[standard]` and `fastapi[standard]`, sanic depends on it, and uvicorn uses it whenever it can be imported.

**What changed.** Nothing that goes through a uvloop event loop raises an audit event. On 0.5.3 the policy was therefore applied to none of the asynchronous networking of such a process, with `locked=True` and `fail_closed=True` too, and nothing was logged. 1.0.0 does not run next to uvloop: while a policy that is not `log_only` is active, `import uvloop` raises `ImportError`, and when uvloop is already loaded, `activate()` raises `RuntimeError` and changes nothing.

**What you see** depends on whether the server imports the application, and with it the policy, before it asks for uvloop:

| What happens | What it means |
|---|---|
| The server starts and logs `tethered: refused to load uvloop while a policy is active ...` once | The policy came first. The server fell back to the standard asyncio event loop, where the policy is enforced. |
| The server exits with `RuntimeError: tethered: activate() refused — uvloop is loaded in this process. ...` | uvloop came first. |
| The server stays up and answers no request | The same error in every worker, and a supervisor that keeps starting new ones (`uvicorn --workers`, `--reload`). |

**What to do.** Any one of:

- **Name the standard loop** in the server's configuration: `uvicorn main:app --loop asyncio`, `UVICORN_LOOP=asyncio` for the `uvicorn` command, `loop="asyncio"` in `uvicorn.run()`. Do this for uvicorn also where it works without: which of the two comes first differs between uvicorn releases and between ways of starting it.
- **Activate in a launcher script**, before the server is imported ([the launcher pattern](COOKBOOK.md#the-launcher-pattern)). For a server that imports uvloop whenever it is installed, this and the next one are the only ways.
- **Keep uvloop out of the environment.**

With uvloop installed and `activate()` called where the application is imported:

| Server | On 1.0.0 | Change |
|---|---|---|
| `uvicorn main:app` and `uvicorn.run("main:app")`, uvicorn 0.54 | Works, on the standard loop | Name the loop all the same |
| The same, uvicorn 0.46 | Does not start | `--loop asyncio`, `loop="asyncio"` |
| uvicorn with `--workers` or `--reload` | Never serves | `--loop asyncio` |
| `fastapi run main.py`, `fastapi dev` | Works | None |
| `fastapi run --entrypoint main:app --workers N` | Never serves | Give `fastapi run` the path, or serve with `uvicorn main:app --loop asyncio --workers N` |
| gunicorn with `-k uvicorn.workers.UvicornWorker` | Works | None |
| gunicorn with `-k asgi` | "Worker failed to boot." | `--preload` or `--asgi-loop asyncio` |
| hypercorn, its default worker | Works | None; `-k uvloop` does not start |
| granian with uvloop installed | Does not start, whichever `--loop` | Uninstall uvloop, or a launcher script |
| The `sanic` command | Does not start | Exclude uvloop from the environment, or a launcher script |
| gunicorn with `-k aiohttp.GunicornUVLoopWebWorker` | Does not start | `-k aiohttp.GunicornWebWorker` |

[The cookbook](COOKBOOK.md#servers-and-interpreter-pools) has each server in full, and [the compatibility page](COMPATIBILITY.md#web-servers) the versions these rows were measured with.

Three things to check while you are there:

- **Activate where the application is imported, not in a lifespan handler.** By the time a lifespan handler runs, the server has chosen its loop. FastAPI and Starlette then exit with "Application startup failed. Exiting." With a hand-written ASGI lifespan handler, uvicorn's default `--lifespan auto` swallows the `RuntimeError` and serves on uvloop **with no policy**; the error line `tethered: activate() refused ...` in the log is the only trace. With the loop named, activation in a lifespan handler works.
- **A `log_only` policy refuses nothing, uvloop included.** It runs next to uvloop as before and reports nothing that goes through the loop, now with one warning (`tethered: uvloop is loaded in this process. ...`). Name the loop for a log-only rollout of an asyncio application, or its list of what would be blocked stays empty for every asynchronous call.
- **A `scope()` with no `activate()` under it** does not keep uvloop out either, and logs the same warning.

## pycares and aiodns

**Who is affected.** aiohttp in an environment that has aiodns installed, as `aiohttp[speedups]` does, and code that uses pycares or aiodns itself.

**What changed.** c-ares looks names up in C, where tethered sees neither the lookup nor which host an address belongs to. On 0.5.3 every host that the allow list names was then refused by its address, while the lookup of a forbidden name still left the process. In 1.0.0, while a policy that is not `log_only` is active, `import pycares` and `import aiodns` raise `ImportError`, logged once at info level. aiohttp falls back to its threaded resolver on its own and is then enforced like any other client.

**What to do.**

- For aiohttp, nothing, as long as `activate()` comes before the first import of aiohttp.
- Where aiohttp is imported first (`python -m aiohttp.web`, gunicorn's aiohttp worker class, an import above the `activate()` call), choose the resolver yourself: `aiohttp.TCPConnector(resolver=aiohttp.ThreadedResolver())` ([the cookbook](COOKBOOK.md#aiohttp)).
- Code that needs pycares or aiodns itself has to import it before `activate()` and allow the addresses it connects to. A pycares that is already loaded is left alone, and `activate()` is not refused because of it.

The sign of a resolver that works outside Python's `socket` module is an allowed host refused by its address (`... 203.0.113.7:443 is not in the allow list`), now together with a one-time `tethered: no hostname is known for the refused address ...`.

## Allow rules

A malformed rule raises `ValueError` at `activate()` and `scope()`. 0.5.3 accepted these rules, and they either never matched or allowed more than was written:

| Rejected | Example | Write |
|---|---|---|
| A port that is not a number from 0 to 65535 | `host:abc`, `host:`, `host:-1`, `host:70000` | `host:443`, or `host` for any port |
| Text or a bad port after the `]` of a bracketed address | `[2001:db8::1]:abc`, which allowed the address on every port | `[2001:db8::1]:443` |
| An invalid network prefix | `[2001:db8::]/200` | `[2001:db8::]/32` |
| No host | `:443` | `host:443` |
| A hostname with a `:` in it, wildcards over IPv6 text included | `fe80::*` | CIDR: `fe80::/10` |
| A dot after the port, or after a bracketed address | `host:443.`, `[::1].` | `host:443`, `[::1]` |
| A `*` with nothing beside it but a character set | `*[!/]`, which matched every destination | A pattern with a literal character: `*.example.com` |

Two rules are read differently without an error, and one draws a warning:

- `[ab].example.com:443` is a hostname pattern that begins with a character set. 0.5.3 read every rule that starts with `[` as a bracketed IP address, which dropped the port and the rest of the pattern.
- `api.example.com.:443` matches: a trailing dot in front of a port is ignored, as it already was without a port. Such a rule never matched before.
- `10.*` and other address-shaped wildcards match as before and log a warning, once per rule: the pattern is text, so it also allows `10.attacker.example`. Write `10.0.0.0/8`.

To check an allow list before deploying, construct a scope from it in an environment that has 1.0.0. The rules are parsed there, and nothing is activated:

```python
import tethered

tethered.scope(allow=["*.stripe.com:443", "db.internal:5432"])  # ValueError for a malformed rule
```

[Rule validation](API.md#rule-validation) in the API reference has the full list.

## Child processes

**Install tethered into site-packages.** A Python child inherits the policy through `tethered.pth`, which `site.py` runs only from a site directory. An editable install (`-e`) and a `--target` install used through `PYTHONPATH` put no such file there. 0.5.3 took the file next to the package for the bootstrap and trusted children that never ran it. 1.0.0 logs `tethered: tethered.pth not found at ...` at `activate()` and treats every launch of `sys.executable` as external. What to do: a regular install (`uv add tethered`, `pip install tethered`) in every environment that should pass the policy on.

**More launches count as external.** They are logged under the default `external_subprocess_policy="warn"` and refused with `SubprocessBlocked` under `"block"`. The log line and `SubprocessBlocked.description` end with the reason.

| Launch | Why it is external | What to do |
|---|---|---|
| Any Python launch from an editable or `--target` install | No `tethered.pth` in a site directory the interpreter processes | Install into site-packages |
| On POSIX, `subprocess.run(["python", ...], executable=sys.executable)` | `argv[0]` is not `sys.executable` | Pass `sys.executable` as the first argument |
| `sys.executable` with interpreter options that cannot be parsed | The options decide whether `site.py` runs | Use options the interpreter knows |
| `sys.executable -s` or `-I`, with tethered in the per-user site-packages | Those options skip that directory | Install into the environment's site-packages |
| `os.spawn*` or `os.posix_spawn` of `sys.executable` with an explicit environment that lacks `_TETHERED_CHILD_POLICY` | That environment cannot be completed | Launch through `subprocess`, or let the child inherit the environment |
| Every launch under uWSGI without `--py-sys-executable` | `sys.executable` is the uwsgi binary, not an interpreter | `--py-sys-executable /path/to/python` ([uWSGI](COOKBOOK.md#uwsgi)) |
| `multiprocessing` workers after `multiprocessing.set_executable()` named another interpreter (Windows; POSIX from Python 3.14) | Another interpreter, which need not have tethered installed | Keep `sys.executable`, or expect the warning and, under `"block"`, the refusal |
| Any Python launch when `tethered.pth` is another distribution's file, or from Python 3.15 has a `tethered.start` file beside it | The child would not run tethered's bootstrap | Remove that distribution or that file, and reinstall tethered |

[The subprocess page](SUBPROCESS.md#parent-side-enforcement-of-external-subprocess-launches) has the full table of what counts as external. `"block"` also refuses the helper programs that libraries run (`file`, for `platform.architecture()`), as it did before: [what "block" also refuses](SUBPROCESS.md#what-block-also-refuses).

**A child that cannot establish a locked or fail-closed policy does not start.** When the inherited policy has `locked` or `fail_closed` set and the child's bootstrap cannot put it in place (an invalid payload, a rule the child rejects, the C extension missing), the interpreter exits at start-up with status 1 and `tethered: refusing to start — the inherited policy asks for locked or fail_closed enforcement and could not be established (...)`. 0.5.3 logged a warning and ran without the policy, or without the lock. With neither flag set, nothing changes: a warning is logged and the child continues. What to do: give child interpreters the same tethered installation as the parent, the C extension included.

## Locked mode

### Interpreters under a lock

**Who is affected.** A process that locks a policy and runs more than one interpreter: mod_wsgi application groups, uWSGI with several mounted applications, `concurrent.futures.InterpreterPoolExecutor`, subinterpreters of your own.

**What changed.** The lock is held once per process. An interpreter created while it is held joins it as it starts, through the `tethered.pth` bootstrap, and is then held to the policy like the interpreter that took the lock. Every other interpreter gets no connection, lookup or process launch for as long as the lock is held, whatever the allow list says, loopback included: one that existed before the lock was taken, one that started without the bootstrap, and one whose join failed. On 0.5.3 a subinterpreter had an unlocked copy of the policy, which it could switch off with `tethered.deactivate()`.

**What you see.** In an interpreter outside the lock every connection fails, with `EgressBlocked` once tethered is imported there and `RuntimeError` before, and nothing is logged for it. `activate()` raises `TetheredLocked` there, for the identical policy too: `... a policy is locked by another interpreter of this process, and this interpreter is outside that lock ...`.

**What to do.**

- Take the lock before any other interpreter of the process is created. For an `InterpreterPoolExecutor` that means before the first task is submitted: its workers are started on demand.
- Install tethered into site-packages, so that the bootstrap runs in each new interpreter.
- Under mod_wsgi, which creates an application group's interpreter at that group's first request, give each application a daemon process of its own, or take the lock in the main interpreter at process start with a script of its own (`WSGIImportScript ... application-group=%{GLOBAL}`). Point mod_wsgi at a virtual environment with `python-home`, not `python-path` ([mod_wsgi](COOKBOOK.md#mod_wsgi)).
- Under uWSGI with several mounted applications, lock the same policy in the first one ([uWSGI](COOKBOOK.md#uwsgi)).
- Applications that need different policies need different processes.

A locked `log_only` policy lets every interpreter's connections and lookups pass. [Locked mode](API.md#locked-mode) in the API reference describes both positions, and [the security model](security.md#locked-mode--what-it-does-and-does-not-do) what a join is worth.

### A hook that is lost

Under a locked policy, the launch of a Python child raises `SubprocessBlocked` once `tethered.pth` no longer holds tethered's line, whatever `external_subprocess_policy` says: the child would start without the locked policy. That is what a locked process meets after tethered was removed from its environment while it ran, or upgraded to a version whose hook differs.

What to do: restart a locked process after tethered was upgraded or removed in its environment, and make such a change from outside the processes that hold a locked policy.

### Tokens, tampering and the exception for a failed check

- **More token types are rejected.** `lock_token` rejects `complex`, `tuple` and `frozenset` values and the singletons `Ellipsis` and `NotImplemented` with `TypeError`, in addition to `str`, `int`, `float`, `bytes` and `bool`. Pass `object()`, or an instance of a class of your own.
- **A tampered policy stays locked.** A locked policy that has failed its integrity check can be neither replaced nor deactivated, with the correct token either: `activate()` and `deactivate()` raise `TetheredLocked` (`tethered: the locked policy has failed its integrity check ...`) until the original objects are restored. Restart the process.
- **A failed integrity check on a process launch raises `SubprocessBlocked`,** where it raised `EgressBlocked`. The same check also refuses the guarded operations on `tethered.pth` and `os.putenv` / `os.unsetenv` of the policy variable. Catch `SubprocessBlocked` around process launches, or `RuntimeError`, the base class of both.

## Errors from activate() and scope()

- **`RuntimeError` when another audit hook refuses tethered's.** `sys.addaudithook` drops a new hook without an error when a hook that is already installed raises on its event. 0.5.3 then reported success with nothing enforced, in locked mode too. `activate()` and entering a scope now raise `tethered: its audit hook could not be installed — another audit hook in this process refused it, so nothing would be enforced. ...`. What to do: install tethered's hook first, by calling `activate()` or entering a scope before the other hook is added, or have that hook let tethered's through.
- **`ValueError` for a policy too large to publish to child processes, with nothing changed.** Windows limits an environment variable to 32,767 characters, which is roughly 1,500 short rules. 0.5.3 raised as well, but with the new policy already enforcing in the parent and nothing published to children; a caller that caught the error and went on now runs under the previous policy, or under none. What to do: shorten the allow list, for example by merging addresses into CIDR ranges.
- **`RuntimeError` over a loaded uvloop:** see [uvloop](#uvloop).

Both calls are all-or-nothing in 1.0.0: when one raises, the previous policy, the lock and the policy published to child processes are exactly as they were.

## Log lines and messages

- **A log-only policy or scope logs `would block`, where it logged `blocked`:** `tethered: would block connect to evil.test:443`, and the same for lookups and scopes. The lines of an enforcing policy are unchanged. What to do: a log filter or an alert that matches `tethered: blocked` for a log-only policy has to match `tethered: would block`.
- **The message of `EgressBlocked` writes an IPv6 address with a port as `[2001:db8::1]:443`,** where it was `2001:db8::1:443`. The attributes and the log lines are unchanged; read `host` and `port`, not the text.
- **The line for a launch of this interpreter that counts as external ends with the reason,** and so does `SubprocessBlocked.description`: `... subprocess.Popen(/usr/local/bin/python) — -S skips site.py and the tethered.pth bootstrap with it: the child holds no policy`. On Windows both name the program, where they said `subprocess.Popen(None)`.

New lines, each logged once per process (the one about a rule once per rule):

| The line begins | It says | What to do |
|---|---|---|
| `tethered: refused to load uvloop while a policy is active` | A server asked for uvloop and fell back to the standard loop | Name the loop, and the line is gone |
| `tethered: uvloop is loaded in this process.` | A log-only policy, or a scope with no policy under it, runs next to uvloop and sees nothing of its loop | Name the standard loop |
| `tethered: multiprocessing's fork server was started before this policy.` | The workers it forks hold no policy, under a locked policy either | Call `activate()` before the first pool or process is started |
| `tethered: no hostname is known for the refused address` | A name may have been looked up outside Python's `socket` module | Use the system resolver, or allow the address |
| `tethered: allow rule '10.*' looks like an IP address range` | The rule is a text pattern and also allows hostnames that fit it | CIDR notation |
| `tethered: an asyncio ProactorEventLoop (the Windows default) is running.` | That loop gets no connect-time enforcement | Run the loop as `asyncio.SelectorEventLoop` |
| `tethered: sys.executable is ..., the program that embeds Python here` | uWSGI: every launch counts as external | `--py-sys-executable` |
| `tethered: ... is not the file tethered installs under that name` | Another distribution replaced `tethered.pth`; Python children will not inherit | Remove that distribution and reinstall tethered |
| `tethered: ... is switched off by the tethered.start file beside it` | From Python 3.15 that file stops the bootstrap | Remove the file |

## Fixes that refuse more

The changelog does not mark these as breaking: each closes a way around a policy. They can still show as a refusal that 0.5.3 did not make.

- **A log-only layer no longer switches off an enforcing one.** An outer `scope(log_only=True)` used to disable an inner enforcing scope, and a log-only `activate()` policy that denied a lookup used to skip the scope checks for it. An enforcing scope inside a log-only rollout now enforces.
- **A Python child gets the policy when its environment was built without it.** A child launched with an explicit `env=` that lacks `_TETHERED_CHILD_POLICY`, or after the variable was cleaned out of `os.environ`, ran with no policy. The variable is now added at the launch.
- **Addresses are checked in every form CPython accepts.** `bytes` and `bytearray` hosts and ports given through `__index__` (`numpy.int64`) skipped the policy, and an address tethered cannot read is refused.
- **More launches are seen.** `multiprocessing` and `ProcessPoolExecutor` launches on Windows and, from Python 3.14, on POSIX are subject to `external_subprocess_policy` and to the locked-mode check. `-S` is detected when it is quoted inside a Windows command line, when `executable=` is passed on Windows, and after `-X -c`.
- **Under a lock, `tethered.pth` is guarded however it is named:** through a symlink or a junction, by a Windows short name, relative to a directory descriptor, and as the same file in uv's cache; against `os.truncate`, a copy onto it and a second name (`os.link`, `os.symlink`); and against a `tethered.start` file beside it. `pip uninstall tethered` from a locked process in an environment that is reached through a symlink, and `shutil.rmtree()` of the environment on POSIX, went through on 0.5.3 and are refused now.
- **Under a lock, a launch environment is compared exactly.** A value that differs in type (`"log_only": 0`), two spellings of the variable name, and a variable that was changed from another interpreter or below Python are refused.

## What became less strict

Workarounds that 1.0.0 makes unnecessary:

- **Under a lock, a `subprocess` environment that merely lacks the policy variable is completed, not refused.** On 0.5.3 with a locked policy, `ctypes.util.find_library()` raised `SubprocessBlocked` on Linux, and with it `import trio`, `import asyncssh` and psycopg 3 in its Python implementation. Importing them before `activate()` is no longer needed for the lock, nor, from 1.1.1, under `external_subprocess_policy="block"`, which no longer counts the `ldconfig` launch as external.
- **gunicorn's binary upgrade (`SIGUSR2`) with `--preload` completes under a locked policy,** with no `pre_exec` hook.
- **`scope()` on its own under asyncio no longer blocks the hosts it allows,** and two allowed hostnames that share an address (CDNs, load balancers) no longer block each other.
- **A blocked call in a `ProcessPoolExecutor` or `multiprocessing.Pool` worker reaches the parent as `EgressBlocked`,** where the pool broke. With Celery's JSON result serializer, `result.get()` for a refused task raises `tethered.EgressBlocked`, where it raised a bare `Exception`.

## Recipes and links

- **The Django middleware that the cookbook printed for 0.5.x did not work.** Django turns a view's exception into a 500 response before `get_response()` returns, so the `try` / `except tethered.EgressBlocked` around it never saw the refusal. If you copied it, replace it with [the current one](COOKBOOK.md#django--fastapi-middleware), which uses `process_exception()`.
- **With `httpx.AsyncClient`, catch `except* tethered.EgressBlocked`.** A refused connection arrives inside an `ExceptionGroup`, which `except tethered.EgressBlocked` does not catch; the connection is blocked either way. The FastAPI handler in the same section of the cookbook catches both shapes.
- **The security model moved** from `SECURITY.md` to [a page of its own](security.md); a link to one of its sections in `SECURITY.md` has to follow. The full allow list syntax moved from the README to [the API reference](API.md#allow-list-syntax), and the overhead measurements to [the architecture page](ARCHITECTURE.md#performance).
