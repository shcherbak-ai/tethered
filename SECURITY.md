# Security Policy

- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Threat model](#threat-model)
- [What tethered protects against](#what-tethered-protects-against)
- [What tethered does NOT protect against](#what-tethered-does-not-protect-against)
- [Locked mode — what it does and does not do](#locked-mode--what-it-does-and-does-not-do)
- [Known residual DNS divergence](#known-residual-dns-divergence)
- [Design trade-offs](#design-trade-offs)
- [Supply chain defense — early activation](#supply-chain-defense--early-activation)
- [Recommendations](#recommendations)

## Reporting a Vulnerability

If you discover a security vulnerability in tethered, please report it **privately** using [GitHub's private vulnerability reporting](https://github.com/shcherbak-ai/tethered/security/advisories/new).

Please avoid opening public issues for security vulnerabilities.

Confirmed vulnerabilities will be addressed in a patch release.

## Threat model

> **tethered is a defense-in-depth guardrail, not a security sandbox.** It intercepts Python-level socket operations. Code that uses `ctypes`, `cffi`, subprocesses, or C extensions with direct syscalls can bypass it. For full process isolation, combine tethered with OS-level controls (containers, seccomp, network namespaces).

tethered's protections are scoped at Python audit events. They defend against:

- **Trusted-but-buggy code** that calls `socket.connect`, `requests.get`, or similar without thinking about egress (a logging library that phones home for telemetry, a misconfigured dep that fetches metadata from prod).
- **Opportunistic supply-chain compromise** — a dep that was hijacked, its attacker doesn't know tethered is in the process and writes the same Python-level network code anyone would write.

They do **not** make tethered into a sandbox against a deliberately-malicious dependency that knows tethered is installed and writes a few lines of bypass code. The audit-event surface is one trust boundary; `ctypes` and `cffi` are another, and they live in the same process with the same permissions. Python code that targets tethered's own internals is a third, and locked mode narrows it without closing it (see [Locked mode](#locked-mode--what-it-does-and-does-not-do)).

## What tethered protects against

Trusted-but-buggy code and supply chain threats: dependencies that use Python's standard `socket` module (directly or through libraries like `requests`, `urllib3`, `httpx`, `aiohttp`). tethered prevents these from connecting to destinations not in your allow list.

The check covers every address form CPython's socket layer accepts: `str`, `bytes` and `bytearray` hosts, and ports given as any object with `__index__`. An address on an IP-family socket that tethered cannot read is refused, not allowed. A log-only layer (the global policy or a scope) never suppresses an enforcing one: every layer is evaluated, and an enforcing layer that denies still raises.

## What tethered does NOT protect against

- **`ctypes` / `cffi` / direct syscalls — the universal bypass.** Native code can call libc's `connect()` (egress), `unlink()` (delete `tethered.pth`), `setenv()`/`unsetenv()` (mutate `_TETHERED_CHILD_POLICY`), or `execve()` (spawn) directly, all of which skip the Python audit-event machinery tethered hooks into. (Python's own `os.putenv()` / `os.unsetenv()` raise audit events and are detected; the libc calls are not.) None of tethered's locked-mode hardenings catch a `ctypes`-armed attacker; they raise the bar for opportunistic attacks but don't close it for deliberate ones.
- **Egress inside non-Python child processes.** Python children auto-inherit tethered (via `tethered.pth` + the `_TETHERED_CHILD_POLICY` env var), and `external_subprocess_policy` can monitor or block the *launch* of any subprocess. But tethered cannot enforce egress rules *inside* a non-Python executable (curl, ffmpeg, bash, etc.). For hard subprocess isolation, combine with OS-level controls (seccomp, containers). See [docs/SUBPROCESS.md](docs/SUBPROCESS.md).
- **Spawning a different Python interpreter** (e.g. `subprocess.run(["/usr/bin/python3", …])`) where tethered isn't installed — the child has no `tethered.pth` to fire, so it runs uncontrolled. `external_subprocess_policy="block"` shuts this down.
- **Spawning Python with `-S`** which disables `site.py` and so skips the auto-activation `tethered.pth`. `-I` / `-E` keep `site.py` enabled and so are NOT a bypass, with one exception: when tethered is installed in the per-user site-packages (`pip install --user`), `-s` and `-I` skip that directory and the bootstrap with it. Such launches are treated as external, and so are a launch whose interpreter options cannot be parsed and, on POSIX, a launch whose `argv[0]` is not `sys.executable` (an interpreter works out which installation or virtual environment it belongs to from `argv[0]`, so started as `python` it can come up where no `tethered.pth` is processed). `external_subprocess_policy="block"` refuses them.
- **Python children when tethered is not installed into site-packages.** `site.py` runs `tethered.pth` only from a site directory: the interpreter's site-packages or the enabled per-user site-packages. An editable install (`pip install -e .`) and `pip install --target` + `PYTHONPATH` have no such file. `activate()` then logs a warning, no Python child auto-inherits, and every `sys.executable` launch is treated as external.
- **Known gaps in the Python-launch classification.** A `tethered.pth` processed only through an explicit `site.addsitedir()` call is not recognized (this fails closed: the warning above, and launches treated as external). Environment variables in the child's environment that change its site configuration (`PYTHONNOUSERSITE`, `PYTHONUSERBASE`, `PYTHONHOME`) are not inspected. If the tethered package is importable only through `PYTHONPATH`, a child started with `-E` or `-I` runs the `.pth` line but cannot import tethered, and starts without a policy.
- **External tools deleting `tethered.pth`** (e.g. `subprocess.run(["rm", "...tethered.pth"])`). The launch fires `subprocess.Popen` audit, but the deletion happens in the `rm` process — outside this Python interpreter. `external_subprocess_policy="block"` shuts this down.
- **C extensions with raw socket calls.** Extensions calling C-level socket functions are not intercepted.
- **asyncio on the Windows default event loop (`ProactorEventLoop`).** Windows only. That loop connects and sends datagrams through overlapped I/O calls (`_overlapped.ConnectEx`, `_overlapped.WSASendTo`) that raise no `socket.connect` / `socket.sendto` audit event. On it, raw-IP destinations, port rules and `scope()` connect checks are **not enforced**; only the global policy's DNS-time hostname check applies. tethered logs a one-time warning when a socket is created while a Proactor loop is running. Run the loop as `asyncio.SelectorEventLoop` for full enforcement (`asyncio.run(main(), loop_factory=asyncio.SelectorEventLoop)` on Python 3.12+). Synchronous code on Windows, and asyncio on other platforms, are not affected.
- **Lookups for hostnames passed directly to `connect()` / `sendto()`.** CPython resolves the address before it raises the `socket.connect` / `socket.sendto` audit event, so for `sock.connect(("host.example", 443))` the DNS lookup happens before tethered sees the call. The connection or datagram itself is still refused. Code that resolves first (`socket.getaddrinfo`, `socket.create_connection`, and the HTTP libraries built on them) is checked before the lookup.
- **`socket.getnameinfo`.** Not checked. Its audit event carries the address but not the flags, so a reverse lookup cannot be told apart from numeric formatting (`NI_NUMERICHOST`), which libraries call on every peer and local address. Reverse lookups through `socket.gethostbyaddr` are checked.
- **Connections that are already open.** tethered checks connection, DNS and datagram events, not reads and writes. A connection opened before `activate()`, or before entering a narrower `scope()`, stays usable. That includes a pooled HTTP connection reused inside a request-scoped `scope()`.
- **`multiprocessing` spawn / forkserver launches on POSIX with Python 3.10–3.13.** They raise no audit event (`_posixsubprocess.fork_exec` raises one from Python 3.14), so tethered sees neither the launch nor its environment: no `external_subprocess_policy`, no locked-mode payload check, and no repair of a cleaned `os.environ`. Workers still inherit the policy while `_TETHERED_CHILD_POLICY` is intact in the process environment. On Windows, and on POSIX from Python 3.14, these launches are handled.
- **Workers of the `forkserver` start method.** They are forked from the fork server and keep the policy it started with, whatever the parent activates later.
- **The environment and command line of a direct `_winapi.CreateProcess` call (Windows).** The audit event does not carry the environment. tethered reads it for `multiprocessing` and, inside a virtual environment, for third-party copies of its spawner (joblib's loky, billiard); for any other direct caller the launch is judged as if it inherited the process environment. The event does not deliver a usable command line either (CPython 3.10–3.15 pass that argument incorrectly), so on this route a launch is judged by its executable alone: `-S` and other interpreter options are not seen. Launches through `subprocess` are not affected; they are checked from the `subprocess.Popen` event.
- **In-process disabling (without `locked=True`).** Code in the same interpreter can call `deactivate()` or `activate()` unless `locked=True` is used.
- **In-process tampering with scopes.** `scope()` is best-effort narrowing within the global ceiling — there is no `scope(locked=...)` equivalent. A compromised dep inside a scoped function can wipe `_scopes.set(())`, mutate frozen `_ScopeConfig` fields via `object.__setattr__`, or monkey-patch `_check_scopes` — all of which lose the narrowing and fall back to whatever the global policy allows. This is **bounded by intersection semantics**: scope tampering can never widen egress beyond the global policy, only release the additional narrowing. For a ceiling that takes a token to replace, use `activate(locked=True)`. Scopes inside a locked global remain soft; the global has the protection, and the limits, described under [Locked mode](#locked-mode--what-it-does-and-does-not-do).
- **Scope lifetime under generators, executor threads and tasks.** A generator suspended inside `with scope():` leaves the scope active in the consumer's context between yields. A lookup made in another thread on the scope's behalf is not checked against the scope at DNS time (asyncio's `loop.getaddrinfo` runs in an executor thread); the connection that follows is checked. A task created inside a `with scope():` block keeps the scope after the block exits, but with no `activate()` policy its later `loop.getaddrinfo` lookups are no longer recorded, so its connections by hostname are blocked.
- **In-process Python code written against tethered (with `locked=True`).** Locked mode requires the token to replace or deactivate the policy and detects changes to the objects it has recorded. It is not a sandbox: code in the same process that targets tethered can still defeat it, without `ctypes`. The next section lists what is checked and what is not.

## Locked mode — what it does and does not do

`activate(locked=True, lock_token=...)` requires the C extension and does the following:

- **Token.** Replacing or deactivating the policy requires the token object passed at activation, compared by identity. Only the C extension holds a reference to it; tethered keeps no Python-visible copy.
- **Snapshot.** At activation the extension records several hundred facts about tethered's own code and the active policy: what every module-level name in `tethered._core` and `tethered._policy` is bound to (except the active config, which the extension tracks itself, and lower-case scalar runtime state such as flags and counters); every class attribute of the classes defined there; the code object of every Python function found; that no builtin those modules use is shadowed in their namespaces; that no `__getattribute__` / `__getattr__` has been added to those classes; and the class and every slot of the active config and policy.
- **When it is checked.** The facts are re-checked on every socket audit event, every process-launch event, every `open` / `os.remove` / `os.rename` / `os.chmod` / `os.truncate` / `os.link` / `os.symlink` / `_winapi.CopyFile2` event whose path mentions `tethered.pth` or `tethered.start`, and every `os.putenv` / `os.unsetenv` of `_TETHERED_CHILD_POLICY`.
- **On a mismatch.** The operation is refused for as long as the mismatch lasts: `EgressBlocked` for socket events (creating a socket included), `SubprocessBlocked` for the others. One alert line is written to stderr the first time. Restoring the original objects ends the refusals. While the check fails, the policy can be neither replaced nor deactivated, even with the token (`TetheredLocked`).
- **tethered's own lookups.** The DNS lookups tethered makes to map addresses to hostnames go through the extension, which calls the resolver it captured when the policy was locked. Setting tethered's Python-side reentrancy flag by hand is detected on the next socket event, and a connection or datagram attempted from inside such a lookup is refused.
- **Immutable policy data.** Allow rules are immutable tuples of strings and integers, and the child-policy payload is compared against an immutable string, so neither can be edited in place.
- **Propagation channel.** Launch environments and `tethered.pth` are guarded as described in [docs/SUBPROCESS.md](docs/SUBPROCESS.md#locked-mode-hardening-of-the-auto-propagation-channel). That includes path-based `os.truncate` of `tethered.pth`; `os.ftruncate` carries only a file descriptor and cannot be matched, but a writable descriptor for the file cannot be obtained through `open` / `os.open` while the policy is locked. It also includes creating `tethered.start` beside the hook: from Python 3.15, `site.py` ignores the `import` line of `tethered.pth` when that file exists (PEP 829).

Locked mode is **not a sandbox**. It stops accidental and casual disabling and detects the tampering described above. Python code written against tethered can still do the following, without `ctypes`:

- **Replace builtins or the standard-library functions the policy calls** (`fnmatch.fnmatchcase`, `ipaddress.ip_address`, `json.loads`, `os.path` functions). The snapshot covers tethered's two modules, not the modules they call into.
- **Write into containers whose identity is pinned but whose contents are not:** the IP-to-hostname map (an entry naming an allowed host for an address lets a connection to that address through) and the fallback candidate set.
- **Change function defaults or closure cells.** Code objects are pinned; defaults and closures are not.
- **Rebind names in `tethered/__init__.py` or `tethered._autoactivate`**, which are not in the snapshot.
- **Tamper before activation.** The snapshot records whatever is in place when `activate()` runs.
- **Recover the token.** Any reference the application keeps (a module global, an attribute, a live frame local) can be found by code in the same process. Only a token nobody keeps, such as `lock_token=object()` passed inline, cannot be recovered; such a policy can then never be unlocked.
- **Run code in a subinterpreter.** An audit hook added from Python belongs to one interpreter, and the C extension ignores events from interpreters other than the one that locked it. A subinterpreter is covered only through the `tethered.pth` bootstrap, which reads `_TETHERED_CHILD_POLICY`. With an unlocked policy it gets its own, unlocked instance. With a locked policy the bootstrap cannot establish the lock there, so creating a subinterpreter fails. If the variable has been removed from `os.environ`, which locked mode does not refuse (it refuses the next process launch), a new subinterpreter starts with no policy.

Other limits:

- With the default `fail_closed=False`, a policy check that raises allows the connection, so making a standard-library function raise during matching lets the connection through. Set `fail_closed=True` together with `locked=True`.
- Scopes are not protected (see above).
- The `tethered.pth` guard compares paths lexically. A different path to the same file (a symlinked directory, a hard link) is not matched.
- On Python 3.15 and later a `tethered.start` file beside `tethered.pth` stops Python children from auto-activating. Locked mode refuses the ways of creating it that raise an audit event. `os.mknod` (POSIX) raises none, and a file that is already there when the policy is locked is not detected.
- A process launch on another thread during an authorized replacement of a locked policy can be refused spuriously.

## Known residual DNS divergence

Tethered's audit-time `getaddrinfo` and CPython's own `getaddrinfo` are **independent DNS queries**. For load-balanced services with short TTLs (Microsoft Entra ID, M365, large CDNs), and especially under gevent's threadpool resolver, the two queries can return different IP sets — leaving the connect-time IP unmapped and producing a spurious block. To repair this without monkey-patching, tethered re-resolves recently-allowed hostnames at connect-time when the IP map misses (`_fallback_resolve`, bounded to 30 candidates per miss). The same search matches an address obtained through `socket.gethostbyname` / `gethostbyname_ex` back to its name: those lookups record a candidate but no mapping. A name becomes a candidate only when its lookup was let through by the global policy and by every enforcing scope that saw it, so tethered does not itself resolve a name a layer has just refused. The search is skipped when every layer already allows the raw IP (loopback, an IP or CIDR rule). Works in locked mode — the C guardian's caller verification accepts `_fallback_resolve` as a second authorized caller of `_c_guardian.resolve`, and `_fallback_resolve` is integrity-snapshotted so replacing it with a no-op is detected.

In rare cases where the hostname rotates between the application's query and the fallback's own query (sub-second IP rotation faster than the OS resolver cache, or extreme gevent threadpool latency), the fallback may also miss the connecting IP and produce a spurious block. Mitigation: preflight known hostnames at startup, allow the upstream's published IP/CIDR ranges, or accept the residual rate as a defense-in-depth trade-off.

## Design trade-offs

- **Fail-open by default.** If tethered's matching logic raises an unexpected exception, the connection is allowed and a warning is logged. A bug in tethered should not break your application. Use `fail_closed=True` for stricter environments. The child-process bootstrap follows the same rule: when the inherited policy has `locked` or `fail_closed` set and cannot be established in a child, the child refuses to start; otherwise a warning is logged and the child continues without it. See [docs/SUBPROCESS.md](docs/SUBPROCESS.md#locked-mode-propagation).
- **Audit hooks are irremovable.** `sys.addaudithook` has no remove function (by design — PEP 578). `deactivate()` makes the hook a no-op but cannot unregister it. This is per-process only — no persistent state, no system changes, everything is gone when the process exits.
- **IP-to-hostname mapping is bounded.** The LRU cache holds up to 4096 addresses, keyed by canonical address, with up to 8 hostnames per address (most recent first). In long-running processes with many unique DNS lookups, older mappings are evicted. A connection to an evicted IP is checked against IP/CIDR rules only.
- **Direct IP connections skip hostname matching.** Connecting to a raw IP without prior DNS resolution means only IP/CIDR rules apply — hostname wildcards won't match. On shared-IP infrastructure (CDNs, cloud hosting), multiple hostnames may resolve to the same IP. A connection is allowed if any hostname remembered for the address, or the raw IP, is allowed, so two allowed names on one address do not block each other. The other side of that: if an allowed hostname shares an IP with a disallowed one, a raw-IP connection to that address will pass hostname policy via the cached mapping. This is inherent to any system that cannot bind a socket to a specific hostname identity.
- **Wildcards match text, not address ranges.** An address-shaped wildcard such as `10.*` or `192.0.2.*` is an `fnmatch` pattern over the host string: it matches the addresses it looks like and also every hostname that fits the pattern, such as `10.attacker.example`, and through the IP map whatever address that name resolves to. tethered logs a warning for such a rule (once per rule per process). Use CIDR notation (`10.0.0.0/8`) for ranges.
- **Localhost allows local relays.** With the default `allow_localhost=True`, any proxy, tunnel, or forwarding agent listening on `127.0.0.1` or `::1` can relay traffic to external destinations, bypassing the intent of the egress policy. In high-security environments where local relays are a concern, set `allow_localhost=False` and explicitly allow only the loopback addresses and ports your application needs. On Windows, `socket.socketpair()` and asyncio's event-loop creation open a loopback connection on an ephemeral port, so with `allow_localhost=False` either allow `127.0.0.1` on any port or create the event loop before activating.

## Supply chain defense — early activation

tethered is most effective when activated **before** importing untrusted or third-party packages. Any code that runs before `activate()` executes in an unprotected window — a compromised dependency could make network calls during its import-time initialization.

```python
# ✅ Correct: activate before importing third-party code
import tethered
tethered.activate(allow=["*.stripe.com:443", "db.internal:5432"])

import stripe          # safe — tethered is already active
import compromised_pkg # safe — any network calls are blocked
```

```python
# ❌ Wrong: third-party code runs before tethered is active
import stripe
import compromised_pkg  # could phone home during import!

import tethered
tethered.activate(allow=["*.stripe.com:443"])  # too late
```

For maximum protection, combine early activation with `locked=True` (which also propagates to spawn-mode children with their own per-process tokens and refuses launches that strip the policy env var), `fail_closed=True` (so that an error inside the policy check blocks instead of allowing) and, if your workload doesn't legitimately launch external programs, `external_subprocess_policy="block"` to refuse every external launch. Python children of the same interpreter still start under `"block"`; they inherit the policy instead.

## Recommendations

For defense-in-depth, combine tethered with:

- OS-level sandboxing (containers, seccomp-bpf, network namespaces) for hard isolation.
- Subprocess restrictions (`external_subprocess_policy="block"` for hardened environments, plus seccomp filters for non-Python binaries).
- Import restrictions to prevent `ctypes`/`cffi` loading in untrusted code paths.
