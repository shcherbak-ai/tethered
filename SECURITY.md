# Security Policy

- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Threat model](#threat-model)
- [What tethered protects against](#what-tethered-protects-against)
- [What tethered does NOT protect against](#what-tethered-does-not-protect-against)
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

They do **not** make tethered into a sandbox against a deliberately-malicious dependency that knows tethered is installed and writes a few lines of bypass code. The audit-event surface is one trust boundary; `ctypes` and `cffi` are another, and they live in the same process with the same permissions.

## What tethered protects against

Trusted-but-buggy code and supply chain threats: dependencies that use Python's standard `socket` module (directly or through libraries like `requests`, `urllib3`, `httpx`, `aiohttp`). tethered prevents these from connecting to destinations not in your allow list.

## What tethered does NOT protect against

- **`ctypes` / `cffi` / direct syscalls — the universal bypass.** Native code can call libc's `connect()` (egress), `unlink()` (delete `tethered.pth`), `setenv()`/`unsetenv()` (mutate `_TETHERED_CHILD_POLICY`), or `execve()` (spawn) directly, all of which skip the Python audit-event machinery tethered hooks into. None of tethered's locked-mode hardenings catch a `ctypes`-armed attacker; they raise the bar for opportunistic attacks but don't close it for deliberate ones.
- **Egress inside non-Python child processes.** Python children auto-inherit tethered (via `tethered.pth` + the `_TETHERED_CHILD_POLICY` env var), and `external_subprocess_policy` can monitor or block the *launch* of any subprocess. But tethered cannot enforce egress rules *inside* a non-Python executable (curl, ffmpeg, bash, etc.). For hard subprocess isolation, combine with OS-level controls (seccomp, containers). See [docs/SUBPROCESS.md](docs/SUBPROCESS.md).
- **Spawning a different Python interpreter** (e.g. `subprocess.run(["/usr/bin/python3", …])`) where tethered isn't installed — the child has no `tethered.pth` to fire, so it runs uncontrolled. `external_subprocess_policy="block"` shuts this down.
- **Spawning Python with `-S`** which disables `site.py` and so skips the auto-activation `tethered.pth`. (`-I` / `-E` keep `site.py` enabled and so are NOT a bypass — auto-inherit still works under those flags.) `external_subprocess_policy="block"` refuses `-S` launches.
- **`os.truncate("...tethered.pth", 0)`.** CPython doesn't fire an audit event for `os.truncate`, so the locked-mode FS hook can't see it. Truncating the .pth to zero bytes neutralizes the auto-activation. This is a structural CPython gap, not a tethered-specific one — closing it would require a CPython change.
- **External tools deleting `tethered.pth`** (e.g. `subprocess.run(["rm", "...tethered.pth"])`). The launch fires `subprocess.Popen` audit, but the deletion happens in the `rm` process — outside this Python interpreter. `external_subprocess_policy="block"` shuts this down.
- **C extensions with raw socket calls.** Extensions calling C-level socket functions are not intercepted.
- **In-process disabling (without `locked=True`).** Code in the same interpreter can call `deactivate()` or `activate()` unless `locked=True` is used.
- **In-process tampering with scopes.** `scope()` is best-effort narrowing within the global ceiling — there is no `scope(locked=...)` equivalent. A compromised dep inside a scoped function can wipe `_scopes.set(())`, mutate frozen `_ScopeConfig` fields via `object.__setattr__`, or monkey-patch `_check_scopes` — all of which lose the narrowing and fall back to whatever the global policy allows. This is **bounded by intersection semantics**: scope tampering can never widen egress beyond the global policy, only release the additional narrowing. For a tamper-resistant ceiling, use `activate(locked=True)` — the C guardian protects the global. Scopes inside a locked global remain soft, but the ceiling holds.
- **`ctypes` memory manipulation (with `locked=True`).** Locked mode catches Python-level tampering: config replacement, method monkey-patching, frozen field mutation, bytecode swapping, exception class replacement, reentrancy ContextVar tampering, `_TETHERED_CHILD_POLICY` env-var strip/substitution (both via os.environ and via passing `env=` to subprocess), and Python-level deletion / rename / write-overwrite / chmod of `tethered.pth`. `sys.modules` replacement is ineffective — the C guardian holds direct references to critical objects cached at activation time. The remaining bypasses require `ctypes` to manipulate raw process memory — targeting CPython internals, the C extension's private state, or libc functions directly. These attacks are version-specific, platform-specific, and fragile. They are not practical for opportunistic supply-chain attacks — they require a payload tailored to the exact Python version, OS, and tethered build — but they are *trivial* for a dep deliberately written to bypass tethered.

## Known residual DNS divergence

Tethered's audit-time `getaddrinfo` and CPython's own `getaddrinfo` are **independent DNS queries**. For load-balanced services with short TTLs (Microsoft Entra ID, M365, large CDNs), and especially under gevent's threadpool resolver, the two queries can return different IP sets — leaving the connect-time IP unmapped and producing a spurious block. To repair this without monkey-patching, tethered re-resolves recently-allowed hostnames at connect-time when the IP map misses (`_fallback_resolve`, bounded to 30 candidates per miss). Works in locked mode — the C guardian's caller verification accepts `_fallback_resolve` as a second authorized caller of `_c_guardian.resolve`, and `_fallback_resolve` is integrity-snapshotted so an attacker can't replace it with a no-op.

In rare cases where the hostname rotates between the application's query and the fallback's own query (sub-second IP rotation faster than the OS resolver cache, or extreme gevent threadpool latency), the fallback may also miss the connecting IP and produce a spurious block. Mitigation: preflight known hostnames at startup, allow the upstream's published IP/CIDR ranges, or accept the residual rate as a defense-in-depth trade-off.

## Design trade-offs

- **Fail-open by default.** If tethered's matching logic raises an unexpected exception, the connection is allowed and a warning is logged. A bug in tethered should not break your application. Use `fail_closed=True` for stricter environments.
- **Audit hooks are irremovable.** `sys.addaudithook` has no remove function (by design — PEP 578). `deactivate()` makes the hook a no-op but cannot unregister it. This is per-process only — no persistent state, no system changes, everything is gone when the process exits.
- **IP-to-hostname mapping is bounded.** The LRU cache holds up to 4096 entries. In long-running processes with many unique DNS lookups, older mappings are evicted. A connection to an evicted IP is checked against IP/CIDR rules only.
- **Direct IP connections skip hostname matching.** Connecting to a raw IP without prior DNS resolution means only IP/CIDR rules apply — hostname wildcards won't match. On shared-IP infrastructure (CDNs, cloud hosting), multiple hostnames may resolve to the same IP. If an allowed hostname shares an IP with a disallowed one, a raw-IP connection to that address will pass hostname policy via the cached mapping. This is inherent to any system that cannot bind a socket to a specific hostname identity.
- **Localhost allows local relays.** With the default `allow_localhost=True`, any proxy, tunnel, or forwarding agent listening on `127.0.0.1` or `::1` can relay traffic to external destinations, bypassing the intent of the egress policy. In high-security environments where local relays are a concern, set `allow_localhost=False` and explicitly allow only the loopback addresses and ports your application needs.

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

For maximum protection, combine early activation with `locked=True` (which also propagates to spawn-mode children with their own per-process tokens and refuses launches that strip the policy env var) and, if your workload doesn't legitimately spawn subprocesses, `external_subprocess_policy="block"` to forbid them entirely.

## Recommendations

For defense-in-depth, combine tethered with:

- OS-level sandboxing (containers, seccomp-bpf, network namespaces) for hard isolation.
- Subprocess restrictions (`external_subprocess_policy="block"` for hardened environments, plus seccomp filters for non-Python binaries).
- Import restrictions to prevent `ctypes`/`cffi` loading in untrusted code paths.
