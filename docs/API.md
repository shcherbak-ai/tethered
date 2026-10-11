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
| `allow` | Required. Allowed destinations — see [Allow list syntax](../README.md#allow-list-syntax). Pass `[]` to block all non-localhost connections. A malformed rule raises `ValueError` (see *Rule validation* below). |
| `log_only` | Log what would be blocked instead of raising `EgressBlocked`. Default `False`. |
| `fail_closed` | Block when the policy check itself errors, instead of failing open. Default `False`. |
| `allow_localhost` | Allow loopback addresses (`127.0.0.0/8`, `::1`). Default `True`. |
| `on_blocked` | Callback `(host, port) -> None` invoked on every blocked connection, including in log-only mode. |
| `locked` | Enable tamper-resistant enforcement via C extension. Replacing or deactivating the policy then requires the `lock_token`, and a C-level integrity verifier refuses ALL socket operations, process launches, and the guarded `tethered.pth` / policy-variable operations while it detects tampering with tethered's own code or the active policy. Default `False`. See [Locked mode](#locked-mode). |
| `lock_token` | Opaque token required when `locked=True` (`None` counts as missing: `ValueError`). Must be an instance like `object()` — singletons and values of immutable built-in types (`str`, `int`, `float`, `complex`, `bytes`, `bool`, `tuple`, `frozenset`, `Ellipsis`, `NotImplemented`) are rejected with `TypeError`, because an equal value created elsewhere can be the very same object. Compared by identity (`is`), not equality. tethered keeps no copy of the token outside the C extension; keep your own reference if you intend to unlock. |
| `external_subprocess_policy` | Parent-side enforcement for *external* subprocess launches — non-Python tools, different Python interpreters, `sys.executable` launched with `-S` (which disables `site.py`), and Python launches that cannot be shown to inherit the policy. A Python child of `sys.executable` auto-inherits and is unaffected by this setting when all of the following hold: a `tethered.pth` is in a site directory of this interpreter (not the case for an editable install); its interpreter options can be parsed and do not include `-S`; on POSIX, its `argv[0]` is `sys.executable`; and its environment carries the policy payload or can be given it. `-I` and `-E` keep `site.py` enabled and do not break this, except that `-I` and `-s` skip the per-user site-packages, which matters when tethered is installed there (`pip install --user`). Values: `"warn"` (default — supply-chain visibility), `"allow"`, `"block"`. See [SUBPROCESS.md](SUBPROCESS.md). |

Can be called multiple times to replace the active policy — calling `activate()` again does not require `deactivate()` first. If the current policy is locked, the correct `lock_token` must be provided. Each call creates a completely new policy; no parameters carry over from previous calls. The addresses recorded for hostnames are dropped when the policy changes. A call that puts the same policy in place again (the same rules and settings) keeps them, so that a thread which has just looked a name up is not refused the connection that follows.

**Event loops.** Under asyncio the policy is enforced on the standard event loop. uvloop does its networking outside Python's `socket` module and raises no audit event, so nothing that goes through a uvloop event loop could be checked. tethered therefore does not run next to it:

- **`activate()` raises `RuntimeError` when uvloop is already loaded in the process**, unless `log_only=True`. Nothing is changed. The message begins `tethered: activate() refused — uvloop is loaded in this process.` and names the ways out; it is also logged at error level before it is raised, because a server can swallow the exception (uvicorn does for a hand-written ASGI lifespan handler).
- **While a policy that is not log-only is active, `import uvloop` raises `ImportError`** (`tethered: uvloop was not loaded — a policy is active ...`). A server that takes uvloop only when the import works, as uvicorn and its gunicorn worker do, then runs on the standard loop. The refusal is logged once per process as a warning (`tethered: refused to load uvloop while a policy is active ...`), since such a server catches the error without a word. Nothing is refused or logged when uvloop is not installed.
- **A log-only policy refuses nothing**, neither the import nor the activation. It logs one warning (`tethered: uvloop is loaded in this process. ...`) when it finds uvloop loaded, at `activate()` or when a socket is created, and reports nothing that goes through the loop. A `scope()` with no policy under it behaves the same way.

uvicorn uses uvloop by default when it is installed; name the loop (`--loop asyncio`) or activate before the server is imported. [COOKBOOK.md](COOKBOOK.md#servers-and-interpreter-pools) says what each server needs. On Windows the default `ProactorEventLoop` is enforced only in part; run the loop as `asyncio.SelectorEventLoop`. Both are described in [SECURITY.md](../SECURITY.md#what-tethered-does-not-protect-against).

**pycares.** The same import refusal applies to pycares, the c-ares binding under aiodns: while a policy that is not log-only is active, `import pycares` raises `ImportError` (`tethered: pycares was not loaded — a policy is active ...`), and so does `import aiodns`. c-ares looks names up where tethered sees neither the lookup nor which host an address belongs to, so with it every host allowed by name would be refused. aiohttp falls back to its threaded resolver on its own. The refusal is logged once per process, at info level. A pycares that was imported before `activate()` is left alone, and `activate()` is not refused because of it.

**What `activate()` logs.** One info line on success (`tethered: activated with N rules (log_only=...)`). A warning when no `tethered.pth` is in a directory this interpreter's `site.py` processes (Python children will not inherit). One warning per process when multiprocessing's fork server was started before the policy: its workers are copies of the fork server and are not restricted, under a locked policy either (see [SECURITY.md](../SECURITY.md#what-tethered-does-not-protect-against)). And, later, one warning per process the first time the policy refuses (or, under `log_only`, reports) a connection to an IP address that no hostname is known for while the policy has hostname rules (`tethered: no hostname is known for the refused address ...`): usually that is an address nothing allows, but it is also what a library that resolves names outside Python's `socket` module produces for a host the allow list names.

The call is all-or-nothing, and calls are serialized, across threads and across the interpreters of the process: a call waits while another thread or interpreter is in the middle of an `activate()` or `deactivate()`, and when it gets its turn it sees the result (an interpreter that waited for a lock being taken elsewhere gets `TetheredLocked`). Whenever it raises, the previously active policy (or none), the lock, and the policy published to child processes are exactly as they were. It raises `ValueError` and changes nothing when the policy cannot be published to child processes because its serialized form does not fit in an environment variable. On Windows the limit is 32,767 characters, which is roughly 1,500 short rules. It raises `RuntimeError` and changes nothing in two cases in which the policy would not be applied: when tethered's audit hook cannot be installed because another audit hook in the process refuses new hooks, and when uvloop is loaded (above).

**Rule validation.** Rules are parsed when `activate()` or `scope()` is called, and a malformed rule raises `ValueError`. That covers an empty rule; a URL; a port that is non-numeric, empty, negative or outside 0–65535 (`host:abc`, `host:`, `host:-1`, `host:70000`); text after the `]` of a bracketed IP address (`[::1]x`); an invalid network prefix (`[2001:db8::]/200`); a rule with no host (`:443`); a hostname containing `:`, which includes wildcards over IPv6 text such as `fe80::*` (use CIDR); and a `*` pattern with no literal character (`*`, `*.*`, `*[!/]`). One trailing dot on the host part is ignored, so `api.example.com.` and `api.example.com.:443` are the same rules as without it; a dot after the port (`host:443.`) is an error.

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
    hint: str | None = None,
)
```

| Parameter | Description |
|---|---|
| `allow` | Required. Allowed destinations — see [Allow list syntax](../README.md#allow-list-syntax). A malformed rule raises `ValueError`, as for `activate()`. |
| `allow_localhost` | Allow loopback addresses. Default `True`. |
| `log_only` | Log what would be blocked instead of raising. Default `False`. |
| `fail_closed` | Block when the policy check itself errors. Default `False`. |
| `on_blocked` | Callback `(host, port) -> None` on every blocked connection. |
| `label` | Human-readable name for this scope. Appears in log messages and as `EgressBlocked.scope_label` when this scope produces a block. Library authors should use it to identify call sites — e.g. `label="WeatherClient.get_forecast"`. Defaults to an auto-derived `"scope(<first 3 allow rules>)"` summary. |
| `hint` | Actionable guidance attached to any `EgressBlocked` raised while this scope is the deepest hinted scope on the stack — e.g. `hint="mylib needs api.mylib.com:443 — see https://…/security"`. Surfaces as `EgressBlocked.scope_hint` and as a trailing `Hint: …` line on the message. Whitespace is normalized at construction (runs of any whitespace, including embedded newlines, collapse to a single space). `None`, empty, and whitespace-only inputs are equivalent to no hint. The hint travels with the scope through subprocess auto-propagation, so a child blocked by an inherited scope sees the same guidance. |

Use as a **context manager** (`with tethered.scope(allow=[...]):`) or a **decorator** (`@tethered.scope(allow=[...])`). Supports both sync and async functions. Cleanup is automatic — no `deactivate()` call needed.

A scope is active in the context (thread or asyncio task) that entered it, from entry until its block exits. Generator and async generator functions cannot be decorated (`TypeError`). Inside a generator, wrap each I/O call in its own `with tethered.scope(...)` block and do not `yield` inside one: a scope that is open across a `yield` stays active in the consumer's context until the generator resumes. Exiting a scope removes that scope's own entry from the stack, whatever has been entered or exited in between. Exiting it in a context that never entered it removes nothing and logs a warning.

`scope()` works on its own — no `activate()` required. When used alone, the scope IS the policy for that code path. Code outside the scope is unaffected. Entering a scope (`with`, or calling a decorated function) raises `RuntimeError` when tethered's audit hook cannot be installed, for the same reason as `activate()`; the body does not run and no scope is left active.

Three caveats apply under asyncio. A scope's DNS-time check does not apply to `loop.getaddrinfo`, which runs `socket.getaddrinfo` in an executor thread that does not carry the scope; the connection that follows is still checked against the scope. Under uvloop a scope is not applied to anything that goes through the event loop, connections included, and nothing is logged for it. An enforcing `activate()` policy keeps uvloop out of the process (see [Event loops](#tetheredactivate) above); a scope used on its own does not, and only logs a one-time warning when it is entered with uvloop loaded. And on Windows the default `ProactorEventLoop` gets no connect-time enforcement at all, for scopes or for `activate()`: run the loop as `asyncio.SelectorEventLoop` (see [SECURITY.md](../SECURITY.md#what-tethered-does-not-protect-against)).

Scopes can only **restrict**, never widen. If the app also called `activate()`, the effective policy is the intersection — a connection must be allowed by both.

> **Package maintainers:** Use `scope()`, never `activate()`. Your library doesn't own the process — the app does. `activate()` is a process-wide operation that would interfere with the host application's own policy. `scope()` is context-local and safe to use from any library.

## `tethered.deactivate()`

```python
tethered.deactivate(*, lock_token: object | None = None)
```

Disable enforcement. All connections are allowed again. Internal state (IP-to-hostname mappings, callback references) is fully cleared — a subsequent `activate()` starts fresh.

If activated with `locked=True`, the matching `lock_token` must be provided or `TetheredLocked` is raised. `TetheredLocked` is also raised, even with the right token, when the locked policy has failed its integrity check (the message says so). The process then has to be restarted, or the original objects restored.

Like `activate()`, the call is serialized with other `activate()` / `deactivate()` calls, in this interpreter and in the others, and leaves everything as it was if it raises. Both raise `RuntimeError` in the two cases where waiting could never end: when the call is made from inside another interpreter's `activate()` / `deactivate()` on the same thread, and when Python is shutting down while another thread holds its turn.

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
    print(e.scope_hint)     # actionable guidance from the deepest hinted scope, or None
```

| Attribute | Type | Meaning |
|---|---|---|
| `host` | `str` | The host (or IP) the call attempted to reach. |
| `port` | `int \| None` | The port, when known (`None` for `getaddrinfo` / DNS-only events). |
| `resolved_from` | `str \| None` | When connecting by a resolved IP, the hostname most recently seen resolving to that IP. `None` for direct hostname connects or when no mapping is known. |
| `scope_label` | `str \| None` | The label of the `scope()` that blocked the call (e.g. `"scope(api.mylib.com:443)"`), or `None` if the block came from the global `activate()` policy. Useful for libraries that wrap `EgressBlocked` and want to attribute the block to the right scope when multiple are nested. See [COOKBOOK.md#for-package-authors](COOKBOOK.md#for-package-authors). |
| `scope_hint` | `str \| None` | The `hint=` set on the deepest hinted `scope()` on the stack at block-time, or `None` when no hinted scope was active. Named to mirror `scope_label`: both attributes are scope-derived, and `activate()` has no hint API by design. The deepest hinted scope wins regardless of which scope's rule produced the block — outer hints surface only when no closer scope set one. The hint also fires when the global `activate()` policy is what blocks (provided a hinted scope is active), so library guidance still surfaces in host-app-driven blocks. Wrapper exceptions can read `exc.scope_hint` to forward the guidance into their own UX without duplicating it in code. |

When `scope_label` is non-`None`, the message includes a trailing `(blocked by <label>)` suffix so the source of the block is visible in tracebacks even without inspecting the attribute. When `scope_hint` is non-`None`, the message gains a trailing line of the form `Hint: <hint>` so the guidance is visible in tracebacks too. An IPv6 address with a port is written the way an allow rule writes it: `[2001:db8::1]:443`.

A host or address that tethered cannot read (for example a non-ASCII byte string) cannot match any rule and is refused; it surfaces as `host="<unreadable …>"` with `port=None`. `sendmsg()` called without an address is not such a case: it is a write on a connected socket, names no destination, and is let through.

`EgressBlocked` can be pickled and copied with all its attributes, so a blocked call in a `multiprocessing.Pool` or `ProcessPoolExecutor` worker is re-raised in the parent as `EgressBlocked`. The same holds for a `concurrent.futures.InterpreterPoolExecutor` worker (Python 3.14+): an `EgressBlocked` that a task lets out reaches the submitter as `EgressBlocked` from `future.result()`.

It can also be rebuilt from its message alone, `tethered.EgressBlocked(*exc.args)`, which is how a transport that does not pickle hands an exception on. Celery's JSON result serializer keeps the class name and `args`, and `result.get()` in a producer that has tethered loaded raises `EgressBlocked`. The message is kept as it is and the attributes are read back out of it, as far as it holds them: a `resolved_from` equal to `host` was never written into it, and a message from an older tethered, which wrote an IPv6 address with a port as `2001:db8::1:443`, gives all of that as `host`. Any other single argument is a `TypeError`.

The exception is raised inside the socket call, and the code around that call decides what its caller sees. Most client libraries pass it on unchanged; some wrap it, and a few hide it (Twisted reports a timeout, kafka-python and nats-py an error of their own): [COMPATIBILITY.md](COMPATIBILITY.md#client-libraries) lists what was measured. Two cases under asyncio differ from a plain `raise`. `httpx.AsyncClient` (and anyio's `connect_tcp`) deliver a refused connection inside an `ExceptionGroup`, which `except tethered.EgressBlocked` does not catch; a refused lookup arrives bare. Use `except* tethered.EgressBlocked`, or look inside the group. And `transport.sendto(data, addr)` on an unconnected asyncio datagram transport raises nothing: the datagram is not sent, asyncio closes the transport and passes the `EgressBlocked` to the protocol's `connection_lost()`. [COOKBOOK.md](COOKBOOK.md#django--fastapi-middleware) has a handler for both shapes.

`EgressBlocked` is intentionally a `RuntimeError`, not an `OSError` — a policy violation is not a network error and should not be silently caught by HTTP libraries or retry logic. See [COOKBOOK.md](COOKBOOK.md#handling-blocked-connections) for handling patterns at framework boundaries (Django, FastAPI, Celery, retry decorators).

## `tethered.SubprocessBlocked`

Raised when tethered refuses a process launch or, in locked mode, a guarded operation. Subclass of `RuntimeError`. See [SUBPROCESS.md](SUBPROCESS.md) for the full behavior. It is raised:

- for an external launch under `external_subprocess_policy="block"`;
- in locked mode, for a launch whose environment fails the payload-integrity check (a different policy, an invalid value, two spellings of the variable) or cannot be given the payload; for a launch that inherits the environment, that includes a policy variable that was changed from another interpreter or below Python. An explicit environment that merely lacks the variable is not refused where tethered can add it: a `subprocess` launch gets it, and so does an `os.exec*` of the same interpreter. `os.posix_spawn`, `os.spawn*` and an `os.exec*` of another program with such an environment are refused;
- in locked mode, for a refused operation on `tethered.pth` (delete, rename, write-mode open, chmod, truncate);
- in locked mode, by the C guardian for a launch, a guarded filesystem operation, or an `os.putenv` / `os.unsetenv` of the policy variable while the integrity check fails;
- in locked mode, by the C guardian in an interpreter that neither holds the lock nor has joined it, for every launch and every change to the bootstrap files or the policy variable, and in an interpreter that has joined it for a change to the policy variable (see [Locked mode](#locked-mode)).

For launches it comes out of whichever call raised the audit event: `subprocess`, `os.system`, `os.exec*`, `os.spawn*`, `os.posix_spawn`, `os.startfile`, `multiprocessing` `Process.start()` and pool construction (Windows; POSIX from Python 3.14), and direct `_winapi.CreateProcess` calls (Windows).

| Attribute | Type | Meaning |
|---|---|---|
| `event` | `str` | The audit event that was refused, e.g. `"subprocess.Popen"`, `"os.system"`, `"_winapi.CreateProcess"`, `"os.remove"`. |
| `description` | `str` | What was refused and, where it applies, why — e.g. `subprocess.Popen(curl)`, `os.system('curl evil.test')`. A `subprocess` launch is described by its program, without its arguments. |

Like `EgressBlocked`, it can be pickled and copied with its attributes, and rebuilt from its message alone (`tethered.SubprocessBlocked(*exc.args)`). `description` comes back from the message, and `event` where the description starts with it, as it does for every launch; otherwise `event` is the empty string.

## `tethered.TetheredLocked`

Raised when `deactivate()` or `activate()` is called on a locked policy without the correct token — except when `activate()` re-requests a policy identical to the active one, which is an idempotent no-op (see [Locked mode](#locked-mode)). Also raised, even with the correct token, when the locked policy has failed its integrity check. Subclass of `RuntimeError`.

Only the interpreter that took the lock can present its token, so in every other interpreter of the process `deactivate()` raises it while the lock is held, and so does `activate()` unless it is that no-op. The no-op exists where the interpreter has a locked policy of its own to compare with: in the lock holder and in an interpreter that joined the lock. The message says which situation the caller is in:

| Caller | Message |
|---|---|
| The lock holder without its token, or an interpreter that joined the lock: `deactivate()` | `tethered: deactivate() blocked — policy is locked. Pass the same lock_token to deactivate() to unlock.` |
| The same callers: `activate()` with a policy that differs from the locked one | `tethered: activate() blocked — a locked policy is active and the requested policy differs from it. Pass the original lock_token to replace a locked policy.` |
| An interpreter outside the lock (it holds no locked policy of its own): `activate()` with any policy, the identical one included, and `deactivate()` | `tethered: activate() blocked — a policy is locked by another interpreter of this process, and this interpreter is outside that lock: it existed before the lock was taken, or did not join it when it started. It can neither change nor release that policy, whatever token it passes. Take the lock before the other interpreters of the process are created.` (`deactivate()` likewise.) |
| The lock holder with the correct token, when the locked policy has failed its integrity check | `tethered: the locked policy has failed its integrity check, so it can be neither replaced nor deactivated — re-activating would take a fresh snapshot of whatever has been put in place. Restart the process.` |

A joined interpreter is told to pass the token although it has none: the token never leaves the interpreter that took the lock. The third message is the one an application sees when its interpreter was created before another application of the same process took the lock, for example a second mod_wsgi application group under concurrent first requests (see [COOKBOOK.md](COOKBOOK.md#mod_wsgi)).

## Locked mode

Tamper-resistant enforcement backed by a C extension:

```python
secret = object()
tethered.activate(allow=["*.stripe.com:443"], locked=True, lock_token=secret)

# Both deactivate() and activate() require the correct token
tethered.deactivate(lock_token=secret)
```

Calling `activate()` or `deactivate()` without the correct `lock_token` raises `TetheredLocked` — with one deliberate exception: `activate()` whose requested policy is identical to the active one (same rules in any order, same flags) is an idempotent no-op. This keeps applications that call `activate(locked=True)` at import time working inside auto-activated child processes, where the `tethered.pth` bootstrap has already re-engaged the parent's policy before the app's own startup code runs. Nothing changes on the no-op path — `on_blocked` and `lock_token` from the no-op call are ignored, so untrusted code cannot use it to register a callback or swap in a token it controls.

While a policy is locked, the C extension re-checks a snapshot of tethered's own code and of the active policy on every socket event, every process launch, and the guarded `tethered.pth` / policy-variable operations. If something it recorded has been replaced, those operations are refused (`EgressBlocked` for socket events, `SubprocessBlocked` for the others) until the original objects are back, and during that time the policy can be neither replaced nor deactivated, even with the token.

The lock is held once per process, by the interpreter that called `activate(locked=True)`. An interpreter created while it is held (a subinterpreter, a `concurrent.futures.InterpreterPoolExecutor` worker) joins the lock as it starts, through the `tethered.pth` bootstrap. It gets its own locked copy of the policy, checked like the lock holder's: it reaches what the policy allows and gets `EgressBlocked` for the rest. It has no token, so `deactivate()` raises `TetheredLocked` there and `activate()` behaves as it does without the token: a no-op for the identical policy, `TetheredLocked` for any other. It cannot change the policy variable either.

An interpreter that has not joined is refused every connection, lookup and process launch and any change to the bootstrap files or the policy variable for as long as the lock is held (`EgressBlocked` / `SubprocessBlocked` when tethered is loaded there, otherwise `RuntimeError`); these refusals are not logged. `activate()` and `deactivate()` raise `TetheredLocked` there. In an interpreter that never joined, that includes an `activate()` with a policy identical to the locked one, and the message says that the interpreter is outside the lock (see [`TetheredLocked`](#tetheredtetheredlocked)). It can still be created and can compute. This is the case for an interpreter that existed before the lock was taken, for one that started without the bootstrap (tethered not installed in site-packages, or a process started with `-S`), and for one that joined a policy the lock holder has since replaced with a different one. So take the lock before creating subinterpreters or interpreter pools, and install tethered normally (not editable, not `--target`). An `InterpreterPoolExecutor` starts its workers on demand, so for a pool this means before the first task is submitted. A server that creates interpreters itself decides the order for you: see [COOKBOOK.md](COOKBOOK.md#servers-and-interpreter-pools) for mod_wsgi and interpreter pools. `log_only` holds in every interpreter: under a locked log-only policy nobody's connections and lookups are refused, while an interpreter outside the lock is still refused launches and the other guarded operations. [SECURITY.md](../SECURITY.md#locked-mode--what-it-does-and-does-not-do) has the full rules: when a join is accepted, what it does and does not protect, and what happens when the lock is released or its holder is destroyed.

Locked mode is not a sandbox. [SECURITY.md](../SECURITY.md#locked-mode--what-it-does-and-does-not-do) lists what is checked and what in-process Python code can still do. Two practical points from there: set `fail_closed=True` together with `locked=True`, and remember that a token reference you keep (`secret` above) can also be found by other code in the process — pass `lock_token=object()` without keeping it if the policy should never be unlocked.

In addition, locked mode hardens the subprocess auto-propagation channel against in-process tampering — payload-integrity checks at every process launch tethered sees, and Python-level FS-tamper protection on the `tethered.pth` file. See [SUBPROCESS.md](SUBPROCESS.md#locked-mode-hardening-of-the-auto-propagation-channel) for the details.

## Log-only mode

Monitor without blocking — useful for rollout or auditing:

```python
tethered.activate(
    allow=["*.stripe.com"],
    log_only=True,
    on_blocked=lambda host, port: print(f"would block: {host}:{port}"),
)
```

tethered logs to the `"tethered"` logger via stdlib `logging`. To see log-only warnings, ensure your application has logging configured (e.g., `logging.basicConfig()`). What a log-only policy or scope lets through is logged as `tethered: would block ...` (`would block connect to evil.test:443`); an enforcing one logs `tethered: blocked ...` for what it refuses.

`log_only` is per layer: the global policy and each scope have their own. A log-only layer never switches off an enforcing one. When a log-only global policy denies, the scopes are still checked. Scopes are evaluated outermost first: each denying log-only scope logs and calls its `on_blocked`, and the first denying scope that enforces raises `EgressBlocked`.

## Intersection semantics — `activate()` + `scope()`

- `activate()` sets a **process-wide ceiling**. No code anywhere in the process can reach destinations outside it.
- `scope()` creates a **temporary restriction** within the current context. It can only narrow the effective policy, never widen it.
- When both are active, the effective policy is the **intersection** — a connection must be allowed by both the global policy and every active scope.
- At connect time a destination can be known by several names: the hostnames remembered for its address (up to 8, most recent first) and the raw IP. Each layer — the global policy and each scope — is satisfied if it allows any one of them, and then every layer must be satisfied. Lookups are checked by name only, so a scope that allows only IP addresses still refuses a hostname lookup made inside it.

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
