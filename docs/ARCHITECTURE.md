# Architecture — how tethered works

[← Back to README](../README.md)

tethered uses [`sys.addaudithook`](https://docs.python.org/3/library/sys.html#sys.addaudithook) (PEP 578) to intercept socket operations at the interpreter level:

- **`socket.getaddrinfo`** — blocks DNS resolution for disallowed hostnames and records IP-to-hostname mappings for allowed hosts.
- **`socket.gethostbyname` / `socket.gethostbyaddr`** — intercept alternative DNS resolution paths, including reverse-DNS lookups of raw IPs.
- **`socket.connect`** (including `connect_ex`, which raises the `socket.connect` audit event in CPython) — enforces the allow list on TCP connections.
- **`socket.sendto` / `socket.sendmsg`** — enforces the allow list on UDP datagrams.

When `getaddrinfo` resolves a hostname, tethered records the IP-to-hostname mapping in a bounded LRU cache. When a subsequent `connect()` targets that IP, tethered looks up the original hostname and checks it against the allow list. If denied, `EgressBlocked` is raised before any packet leaves the machine.

## DNS-divergence fallback

The audit-hook architecture has an inherent limitation: tethered's resolution (called from inside the `socket.getaddrinfo` audit hook) and CPython's own resolution (whose result is returned to the application) are **two independent DNS queries**. For load-balanced services with short TTLs, and especially under gevent's threadpool resolver, the two queries can return different IP sets — leaving the connect-time IP unmapped. Eager population can never be perfect within the audit API.

When `_handle_connect` sees an unmapped IP, `_fallback_resolve` re-resolves up to 30 most-recently-allowed hostnames (LRU order, newest first) and checks if any maps to the connecting IP. On a hit it returns the hostname and enriches the IP map so future connects to that IP take the fast path. On a miss it returns `None` and the connect-time policy check then sees the bare IP, which doesn't match any hostname allow rule, and blocks. Hot path (mapped IP) is unaffected — the fallback fires only on misses.

In locked mode, `_fallback_resolve` is the second authorized caller of `_c_guardian.resolve` (slot 1 in the C guardian's `expected_caller_codes` array; slot 0 is `_handle_getaddrinfo`). It is also added to the C guardian's integrity snapshot, so an attacker cannot replace it with a no-op that defeats the divergence repair while leaving the rest of the system green.

This works with libraries built on CPython sockets (requests, httpx, urllib3, aiohttp) and frameworks like Django, Flask, and FastAPI — they all call `socket.getaddrinfo` and `socket.connect` under the hood. Asyncio and async libraries using CPython sockets are supported: audit hooks fire at the C socket level, so `asyncio`, `aiohttp`, and `httpx` async use the same enforcement path as synchronous code.

`scope()` uses `contextvars.ContextVar` to push a per-context policy onto a stack. The audit hook checks the context-local scope stack in addition to the global policy. When a scope is active, a connection must pass both the global policy and every scope on the stack. When the context manager exits (or the decorated function returns), the scope is automatically popped. Because `ContextVar` is async-safe, scopes propagate correctly through `await` chains and `asyncio.create_task()`. Scopes do **not** automatically propagate to child threads — use `scope()` at the I/O point inside the thread, or use `activate()` for a process-wide ceiling.

The per-connection overhead is a Python function call with hostname normalization, a dictionary lookup, and pattern matching — designed to add minimal overhead relative to actual network I/O.

## Subprocess audit handling

In addition to socket events, the audit hook also intercepts subprocess launches (`subprocess.Popen`, `os.system`, `os.exec*`, `os.posix_spawn`, `os.spawn*`, `os.startfile`) for `external_subprocess_policy` enforcement, locked-mode payload-integrity checks, and scope propagation to spawn-mode children. See [SUBPROCESS.md](SUBPROCESS.md) for the full mechanics.

In locked mode, the audit hook also intercepts filesystem events (`os.remove`, `os.rename`, `open` write-mode, `os.chmod`) on the cached `tethered.pth` path to refuse Python-level tampering with the auto-propagation hook.

## C guardian — tamper-resistant locked mode

When `activate(locked=True)` is called, a C extension (`_guardian.c`) snapshots the identity of every critical Python object — `_Config` fields, `AllowPolicy` internals, enforcement handler functions and their `__code__`, the `EgressBlocked` class, event filter sets — at activation time. On every socket audit event, it re-fetches each attribute and compares pointers. Any mismatch (object replaced, method monkey-patched, frozen field mutated via `object.__setattr__`, bytecode swapped) triggers fail-closed: ALL network access is blocked and a tamper alert is written to fd 2.

The C guardian also owns the lock state — `deactivate()` and `activate()` go through C for token verification, so swapping `_config` to an unlocked configuration doesn't help. `locked=True` requires the C extension; the extension is always built during installation, and a C compiler is required for source installs.

## Thread safety

`AllowPolicy` is immutable after construction. The `_Config` bundle is a frozen `dataclass` swapped atomically (single reference assignment) under nested `_state_lock` + `_ip_map_lock`. The IP-to-hostname map is an `OrderedDict` guarded by `_ip_map_lock` with LRU eviction. Reentrancy guard uses `contextvars.ContextVar` (async-safe, faster than `threading.local()`). This is safe on free-threaded Python (PEP 703).
