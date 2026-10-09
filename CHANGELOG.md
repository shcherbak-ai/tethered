# Changelog

All notable changes to this project will be documented in this file. Each version listed corresponds to a release published on [PyPI](https://pypi.org/project/tethered/).

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Python 3.15 support: the test matrix runs on 3.15 and wheels are built for it. The `tethered.pth` bootstrap keeps working there; [PEP 829](https://peps.python.org/pep-0829/) deprecates `import` lines in `.pth` files but Python 3.15–3.17 still run them.
- A warning for address-shaped wildcard rules (`10.*`, `192.0.2.*`). Such a rule is a text pattern, so it also allows every hostname that fits it, such as `10.attacker.example`. Matching is unchanged; the warning is logged once per rule per process and points to CIDR notation (`10.0.0.0/8`).
- A one-time warning on Windows when a policy or scope is active and a socket is created under asyncio's default `ProactorEventLoop`. That loop connects through calls that raise no audit event, so raw-IP destinations, port rules and scope connect checks are not enforced on it; run the loop as `asyncio.SelectorEventLoop`. The gap is not new; it is now reported at run time and documented in [`SECURITY.md`](SECURITY.md).

### Changed

Entries marked **Breaking**, here and under Security, can break a configuration or code that worked on 0.5.3; each one says what to do. Other fixes under Security also refuse things 0.5.3 let through.

- **Breaking: malformed allow rules raise `ValueError`** at `activate()` / `scope()`. Before, they were accepted and either never matched or allowed more than was written. Affected: a non-numeric, empty, negative or out-of-range port (`host:abc`, `host:`, `host:-1`); text or a bad port after the `]` of a bracketed IP address (`[2001:db8::1]:abc` used to allow the address on every port); an invalid network prefix; a rule with no host (`:443`); a hostname containing `:`, which includes wildcards over IPv6 text such as `fe80::*` (use CIDR); a dot after the port (`host:443.`) or after a bracketed IP (`[::1].`); and a `*` pattern whose only other content is a character set (`*[!/]`), which matched every destination. What to do: correct the rule; for an IPv6 range use CIDR notation (`fe80::/10`).
- **Breaking: more launches are treated as external**, so they are warned about or, under `external_subprocess_policy="block"`, refused. These are: any Python launch when no `tethered.pth` is in a directory `site.py` processes (an editable install, or `pip install --target` + `PYTHONPATH`); on POSIX, a launch whose `argv[0]` is not `sys.executable` (`["python", ...]` with `executable=sys.executable`); a launch whose interpreter options cannot be parsed; `-s` / `-I` launches when tethered is installed in the per-user site-packages; and a Python launch through `os.exec*` / `os.spawn*` / `os.posix_spawn` with an explicit environment that lacks the policy variable. `multiprocessing` workers started after `multiprocessing.set_executable()` named another interpreter, and direct `_winapi.CreateProcess` calls, are now subject to the policy as well (Windows; `multiprocessing` on POSIX from Python 3.14). What to do: install tethered into site-packages (a regular install, not editable and not `--target`) so that Python children inherit the policy; `external_subprocess_policy` then decides whether the launches that remain external are logged (`"warn"`), ignored (`"allow"`) or refused (`"block"`).
- **Breaking: a child process refuses to start when it cannot establish a locked or fail-closed policy.** When the inherited policy has `locked` or `fail_closed` set and the child's bootstrap cannot establish it (an invalid payload, a rule the child rejects, the C extension missing), the interpreter exits at startup with status 1. Before, it logged a warning and ran without the policy, or fell back to unlocked enforcement. Without either flag nothing changes: a warning is logged and the child continues. A subinterpreter is the one exception for `locked`: it starts with the policy unlocked and is covered by the process-wide lock described under Security. What to do: give child interpreters the same tethered installation as the parent, C extension included.
- **Breaking: lock tokens of more types are rejected, and a tampered policy stays locked.** `lock_token` now also rejects `complex`, `tuple` and `frozenset` values and the singletons `Ellipsis` and `NotImplemented` (`TypeError`), in addition to `str`, `int`, `float`, `bytes` and `bool`. A locked policy that has failed its integrity check can be neither replaced nor deactivated, even with the correct token: `activate()` and `deactivate()` raise `TetheredLocked` until the original objects are restored or the process is restarted. What to do: pass `object()`, or an instance of a class of your own, as the token.
- **Breaking: `activate()` raises `ValueError` and changes nothing when the policy is too large to publish to child processes.** Windows limits an environment variable to 32,767 characters, which is roughly 1,500 short rules. Before, the call raised with the new policy already enforcing and nothing published to children. What to do: shorten the allow list, for example by merging addresses into CIDR ranges; a caller that ignored the error no longer ends up with the new policy enforcing in the parent.
- **Breaking: in locked mode, a failed integrity check on a process launch raises `SubprocessBlocked`**, where it raised `EgressBlocked`. The same check now also refuses the guarded `tethered.pth` operations and `os.putenv` / `os.unsetenv` of the policy variable. What to do: catch `SubprocessBlocked`, or `RuntimeError` (the base class of both exceptions), around process launches.
- `activate()` and `deactivate()` are all-or-nothing and serialized across threads: when either raises, the previous policy, the lock and the policy published to child processes are exactly as they were.
- The `activate()` warning about a missing `tethered.pth` now says what it means: no directory this interpreter's `site.py` processes holds the file, so Python children will not inherit the policy and `sys.executable` launches are treated as external.
- Performance: `with tethered.scope(...)` enter + exit costs about 1 µs (was about 0.5 µs). `activate(locked=True)` takes longer (still under a millisecond) because it generates a larger integrity snapshot; verifying the snapshot on each event is faster than before.

### Fixed

- `EgressBlocked` and `SubprocessBlocked` can be pickled and copied with all their attributes. A blocked call in a `ProcessPoolExecutor` or `multiprocessing.Pool` worker now reaches the parent as `EgressBlocked`; before, the pool broke (`BrokenProcessPool`) or the result never arrived.
- A rule that begins with a character set (`[ab].example.com:443`) is a hostname pattern. Before, every rule starting with `[` was read as a bracketed IP address, which dropped the port and the rest of the pattern.
- A trailing FQDN dot in front of a port (`api.example.com.:443`, `*.example.com.:443`) is ignored, as it already was without a port. Such rules never matched before.
- `scope()` used on its own under asyncio no longer blocks the hosts it allows. `loop.getaddrinfo` runs in an executor thread that does not carry the scope, so the lookup was not recorded and the connection was judged as a bare IP.
- Two allowed hostnames that share an address (CDNs, load balancers) no longer block each other. tethered remembers up to 8 hostnames per address instead of the last one, and a connection is allowed if any of them, or the raw IP, is allowed. Addresses are matched in canonical form, so a dual-stack connect to `::ffff:a.b.c.d` finds the name recorded for `a.b.c.d`.
- `socket.gethostbyname()` followed by a connect to the returned address now works for an allowed host, as the same sequence through `getaddrinfo` did.
- A hostname-only scope combined with an IP-only scope no longer blocks a connection that each of them allows.
- `with tethered.scope():` inside a generator no longer removes the caller's scope or leaves its own behind when scopes exit out of order. A scope exited in a context that never entered it logs a warning instead of raising `ValueError`.
- tethered no longer resolves a hostname that a scope has just refused: the connect-time fallback search only considers names whose lookup every enforcing layer let through. It also skips that search when the address is already allowed by IP (loopback, an IP or CIDR rule), where it could cost up to 30 DNS lookups per connect.
- Interpreter options of a Python launch are read the way CPython reads them. A script argument `-S`, a joined `-cCODE` and `-Wignore::SyntaxWarning` are no longer mistaken for the `-S` flag and treated as external.
- Inside a scope, a child launched with an explicit `env=` that is not a `dict` (`UserDict`, `MappingProxyType`) receives a copy of that mapping. Before, it received the parent's environment instead.
- On Windows, log messages and `SubprocessBlocked.description` for an external launch name the program instead of `subprocess.Popen(None)`.
- `_normalize_host` re-strips whitespace hidden behind a trailing dot (`"host\r."`).
- `scope()` overlap warnings judge each rule the way the policy parses it. A scope rule identical to a rule of the global policy no longer draws "has no overlap with global policy" when it starts with or contains a character set (`[ab].example.com:443`), is an unbracketed IPv6 address whose last group is numeric (`2001:db8::1`, `::1`), or is a wildcard with a trailing dot. Also no longer reported as broader: a port-specific rule inside an any-port rule of the same pattern or of a containing network, a wildcard inside a `*`-suffix wildcard (`*.s3.amazonaws.com` under `*.amazonaws.com`), and `localhost` or a loopback address without a port when localhost is allowed. A hostname rule containing `/` is now reported like any other hostname rule; it used to be skipped. A warning is logged only when the overlap is certain. Where it cannot be told from the rule text, nothing is reported; such rules used to be reported as never matching or as broader, sometimes wrongly. That covers two wildcards of which the global one is not `*` + text (`*.example.com` under `*.example.*`, `[ab].example.com` next to `??.example.com`), a wildcard over address text next to a network rule (`10.0.0.*` under `10.0.0.0/24`, or the reverse), and a wildcard or range that may reach localhost while localhost is allowed (`local*`, `127.0.0.0/8`).

### Security

- Socket addresses are checked in every form CPython accepts. `bytes` / `bytearray` hosts and ports given through `__index__` (`numpy.int64` and the like) used to skip the policy entirely, including under `fail_closed` and `locked`. An address on an IP-family socket that tethered cannot read is now refused.
- A log-only layer no longer switches off an enforcing one. An outer `scope(log_only=True)` used to disable an inner enforcing scope, and a log-only global denial used to skip the scope checks for the lookup.
- A Python child launched with an explicit `env=` that lacks `_TETHERED_CHILD_POLICY`, or after the variable was cleaned out of `os.environ`, now receives the policy: tethered establishes the payload in the launch environment. Before, such a child ran with no policy and neither `"warn"` nor `"block"` noticed. Locked mode refuses these launches instead, as before.
- `-S` is detected when it is quoted inside a Windows command line, when `executable=` is passed on Windows, and after `-X -c`; these forms used to get through `external_subprocess_policy="block"`.
- An editable or `--target` install no longer counts as having the bootstrap. Before, the mere existence of a `tethered.pth` next to the package made tethered trust `sys.executable` children that never ran it.
- `multiprocessing` / `ProcessPoolExecutor` launches are seen by tethered on Windows and, from Python 3.14, on POSIX: `external_subprocess_policy`, the locked-mode payload check and the repair of a cleaned environment now apply to them. Workers started inside a virtual environment by third-party copies of the Windows spawner (joblib's loky, billiard) are recognized as children of `sys.executable`. On POSIX with Python 3.10–3.13 these launches raise no audit event and remain out of reach.
- Locked mode, launch environments: the payload check reads an explicit environment of any mapping type (a `UserDict` without the variable used to pass), compares type-exactly (`"log_only": 0` used to pass and leave the child with no policy), refuses more than one spelling of the variable name (a case-variant duplicate won on Windows), and detects changes made through `os.putenv()` / `os.unsetenv()`. The earlier claim that libc `setenv` / `unsetenv` called through `ctypes` is caught was wrong and has been withdrawn.
- Locked mode, integrity: the snapshot now covers every module-level name (runtime flags and counters aside), class attribute and function of `tethered._core` and `tethered._policy` instead of sixteen hand-picked handlers, so rebinding a helper no longer disables enforcement silently. It is also verified on the guarded `tethered.pth` and policy-variable events, not only on socket and launch events. Allow rules are immutable tuples of strings and integers and can no longer be edited in place.
- Locked mode, token: the lock token is held only by the C extension and can no longer be read back from tethered's module state.
- Locked mode, other interpreters: the lock is process-wide. A subinterpreter created while a policy is locked can compute, and `concurrent.futures.InterpreterPoolExecutor` works, but it gets no connections, lookups or process launches and cannot change `tethered.pth` or the policy variable, with or without `_TETHERED_CHILD_POLICY` in the environment. Before, a subinterpreter was limited only by its own unlocked copy of the policy, and by nothing once the variable had been removed. A locked `log_only` policy lets other interpreters' connections and lookups pass. The lock stays with the interpreter that took it, which the guardian knows by its interpreter ID: if that interpreter is destroyed, the process stays locked and no other interpreter, existing or created later, takes the lock over.
- **Breaking: `activate()` and `scope()` raise `RuntimeError` when another audit hook in the process refuses tethered's hook.** `sys.addaudithook` drops a new hook without an error when an existing hook raises on its event. Before, tethered then reported success with nothing enforced, in locked mode too. What to do: install tethered's hook first, by calling `activate()` or entering a scope before the other hook is added, or have that hook let tethered's through.
- Locked mode: `os.truncate()` of `tethered.pth` is refused. The earlier statement that CPython raises no audit event for it was wrong.
- Locked mode: `shutil.copy2()` onto `tethered.pth` is refused on Windows. From Python 3.12 it replaces its destination through `_winapi.CopyFile2`, which raises no `open` event, so it got past the guard and could empty the hook.
- Locked mode: creating a `tethered.start` file beside `tethered.pth` is refused (write-mode `open`, a rename or copy onto the name, `os.link`, `os.symlink`). From Python 3.15, `site.py` ignores the `import` line of a `.pth` file when a `.start` file of the same name sits beside it (PEP 829), so an empty file there stopped Python children from auto-activating. `os.mknod` raises no audit event and is not caught.
- Locked mode: tethered's own DNS lookups call the resolver captured when the policy was locked, and a connection attempted from inside such a lookup is refused. A replaced `_socket.getaddrinfo` could previously connect from there.
- [`SECURITY.md`](SECURITY.md) now states what locked mode checks and what it does not stop. It no longer says that the remaining bypasses require `ctypes`: Python code written against tethered can still defeat locked mode, for example by replacing the standard-library functions the policy calls or by writing into the IP-to-hostname map. Newly documented limitations: the Windows `ProactorEventLoop`, hostnames resolved by `connect()` before the hook sees them, `socket.getnameinfo`, and connections that are already open. The claim that the design is safe on free-threaded Python has been withdrawn; the C extension does not declare free-threading support.

## [0.5.3] — 2026-08-19

### Fixed

- `TetheredLocked` crash in auto-activated child processes whose application startup code calls `activate(locked=True)` at import time (e.g. Django settings). The `tethered.pth` bootstrap re-engages the parent's locked policy before user code runs, so the app's own `activate()` call in a spawn-mode child hit the locked-replacement check and crashed. `activate()` over a locked policy is now an idempotent no-op when the requested policy's canonical payload is identical to the active one; `on_blocked` and `lock_token` from the no-op call are ignored (adopting a caller-supplied token would let untrusted code unlock the policy), and a differing policy still raises `TetheredLocked` — now with an `activate()`-specific message.

## [0.5.2] — 2026-08-19

### Added

- Standalone overhead microbenchmark ([`benchmarks/overhead.py`](benchmarks/overhead.py)) measuring per-event cost across deactivated / activated / activated+scope / activated+locked, and Hypothesis property tests for `AllowPolicy`.

### Fixed

- False "substitution attempt" `SubprocessBlocked` in locked mode under process managers (honcho, supervisord-style runners). The canonical `_TETHERED_CHILD_POLICY` payload serialized exact-host rules from frozensets, whose iteration order follows per-process hash randomization (`PYTHONHASHSEED`) — so a spawn-mode child rebuilding its canonical payload ordered the same entries differently than the parent that serialized it. Any launch passing an env dict captured in another process (e.g. a manager pickling `os.environ` snapshots to runner children) then failed the payload-integrity check and was blocked. The `allow` list is now sorted, making the canonical payload deterministic across interpreters. Workaround on affected versions (0.5.0–0.5.1): set `PYTHONHASHSEED` to a fixed value for all processes.
- `_normalize_host` re-strips whitespace after IPv6 scope-ID removal — splitting on the `%` separator could leave trailing whitespace that the initial strip missed.

## [0.5.1] — 2026-05-01

### Added

- `hint=` parameter on `tethered.scope()`. Library authors (and app developers using `scope()` to tighten request handlers, jobs, or third-party calls) can attach a one-line egress contract — typically the hosts the scope needs plus a docs URL — that surfaces whenever any `EgressBlocked` fires while the scope is on the stack. The hint is configuration metadata on the scope: dormant in normal operation, emerging only when something is actually blocked. The hint travels with the scope through subprocess auto-propagation alongside `label=`, so a child blocked by an inherited scope sees the same guidance. See [`docs/COOKBOOK.md`](docs/COOKBOOK.md#surface-actionable-guidance-via-hint).
- `EgressBlocked.scope_hint` attribute. When a hinted `scope()` is on the stack at block-time, `EgressBlocked` carries the deepest hinted scope's hint and the default message gains a trailing `Hint: <text>` line. The deepest-hinted-scope rule applies regardless of which layer produced the block — your own scope, an inner scope, the host's global `activate()` policy, or an outer scope set by the host or a higher-level library — so a host that has tethered configured but forgot to allowlist your endpoints still sees actionable guidance. Outer hints fall through when the inner scope is unhinted.

## [0.5.0] — 2026-04-28

### Added

- `label=` parameter on `tethered.scope()`. Library authors can pass a human-readable label (e.g. `label="WeatherClient.get_forecast"`) that surfaces in log messages and as `EgressBlocked.scope_label` when the scope blocks. Defaults to the auto-derived `"scope(<first 3 allow rules>)"` summary, so existing call sites are unchanged. See [`docs/COOKBOOK.md`](docs/COOKBOOK.md#for-package-authors).
- `EgressBlocked.scope_label` attribute. When a `scope()` (rather than the global policy) blocks the call, `EgressBlocked` carries the scope's label and the message gains a trailing `(blocked by <label>)` suffix. `None` for global-policy blocks. Helps libraries that wrap `EgressBlocked` in their own exception type attribute the block to the right scope when scopes are nested.
- Scope-aware subprocess propagation. A child process launched from inside `with tethered.scope(allow=[...])` inherits the parent's effective policy at the launch site (global ∩ scopes), not just the at-rest global. Works without `activate()` — a library can use `scope()` alone for self-defense and the narrowing extends through subprocess boundaries. Race-free across threads, no monkey-patching, no opt-in helper required. Limitations: scope cannot propagate through `os.system` / `os.exec*` / `os.startfile` (no env channel to inject), nor through `multiprocessing.Pool` / `ProcessPoolExecutor` in spawn mode (these bypass the `subprocess.Popen` audit event); for multiprocessing scope propagation, use fork mode on Linux.
- Subprocess auto-propagation. Python child processes (multiprocessing pools, `ProcessPoolExecutor`, gunicorn/uvicorn workers, `subprocess.run([sys.executable, ...])`) automatically inherit the parent's tethered policy via a `tethered.pth` site-packages bootstrap. Inherited fields: `allow`, `allow_localhost`, `log_only`, `fail_closed`, `external_subprocess_policy`, and `locked`. Locked-mode children get a fresh per-process `lock_token`. If `locked=True` is requested but the C extension is unavailable in the child, the child logs a warning and falls back to non-locked enforcement.
- `external_subprocess_policy` for parent-side control of *external* subprocess launches. Three values: `"warn"` (default — log every external launch for supply-chain visibility), `"allow"` (silent — for workloads that legitimately shell out frequently), `"block"` (refuse with `SubprocessBlocked`). Applies only to launches that auto-inherit cannot reach: non-Python executables, different Python interpreters, or `sys.executable` launched with `-S` (the only flag that disables `site.py` and the `.pth` bootstrap; `-I` and `-E` keep auto-inherit working). Regular `sys.executable` launches are auto-inheriting and skip this policy entirely. Intercepts `subprocess.Popen`, `os.system`, `os.exec*`, `os.posix_spawn`, `os.spawn*`, and `os.startfile`.
- Locked-mode payload-integrity check on subprocess launches. Tethered verifies that each launch carries the parent's canonical `_TETHERED_CHILD_POLICY` payload byte-for-byte. Catches env stripping (`env={}`), corrupted payloads, payload substitution in explicit `env={...}`, and mutation of `os.environ` itself — Python-level (`os.environ.pop` / `__setitem__`) or via `ctypes` calling libc `setenv`/`unsetenv`.
- Locked-mode `tethered.pth` filesystem-tamper check. Refuses Python-level deletion, rename, write-mode `open`, and `chmod` of the cached `tethered.pth` path while locked, defeating attempts to disable the `.pth` bootstrap from inside the same process (covers `os.unlink`, `pathlib.Path.unlink`, `shutil.rmtree`, `os.replace`, `shutil.copy`, `pathlib.Path.write_*`, etc.).
- `tethered.SubprocessBlocked` exception raised when a subprocess launch is blocked by `external_subprocess_policy="block"` or by the locked-mode payload-integrity / FS tamper checks.
- C guardian integrity checks now cover subprocess audit events in locked mode.
- Runnable examples for the new subprocess features: [`examples/11_subprocess_control.py`](examples/11_subprocess_control.py) (`external_subprocess_policy` warn/allow/block) and [`examples/12_scope_subprocess.py`](examples/12_scope_subprocess.py) (scope-aware propagation to child processes).
- Documentation reorganized. README is now focused on the pitch + quick start + pointers. Detailed API reference moved to [`docs/API.md`](docs/API.md), subprocess deep-dive to [`docs/SUBPROCESS.md`](docs/SUBPROCESS.md), audit-hook architecture to [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and framework integration patterns to [`docs/COOKBOOK.md`](docs/COOKBOOK.md). The threat model and bypass enumeration moved to [`SECURITY.md`](SECURITY.md).

### Fixed

- Self-introspection of the local hostname no longer raises `EgressBlocked`. `socket.getfqdn()`, `socket.gethostbyaddr(socket.gethostname())`, `socket.gethostbyname(socket.gethostname())`, and `socket.getaddrinfo(socket.gethostname(), …)` all consult the local resolver / `/etc/hosts` / NSS to retrieve the canonical name string without making any network connection — tethered now captures `socket.gethostname()` at `activate()` time and exempts these DNS-introspection paths from the policy check when the lookup target equals it. Affects any caller that introspects its own machine identity: `smtplib`'s `HELO`/`EHLO` greeting, `email.utils.make_msgid()`, `logging.handlers.SMTPHandler` (and downstream users like Django's `AdminEmailHandler`), `paramiko`/`fabric` host-identification paths, etc. The most visible production failure mode was the Django email-on-error cascade (any logged 4xx escalated into a 500), but the fix is general. Connect-time enforcement is unchanged — `connect((gethostname(), port))` to a non-loopback IP still requires an explicit allow rule. Locked-mode tamper of the captured hostname is detected by the C guardian.
- DNS-divergence false-blocks under gevent / load-balanced hostnames. Tethered's audit-time `getaddrinfo` and CPython's own `getaddrinfo` are independent DNS queries; for services with short TTLs and high IP-rotation rates (Microsoft Entra ID, M365, large CDNs), the two queries can disagree and leave the connect-time IP unmapped, producing a spurious `EgressBlocked`. At connect time, when an IP isn't in the IP→hostname map, tethered re-resolves up to 30 most-recently-allowed hostnames (LRU order) and checks if any maps to the connecting IP; on hit it allows the connect and enriches the map. Hot path (mapped IPs) is zero-cost; cost only on the miss path. Works in locked mode — the connect-time fallback is an authorized caller of the C guardian's resolver and is integrity-snapshotted, so it can't be replaced with a no-op without tripping tamper detection.

### Security

- `-S` site-bypass detection decodes bytes / PathLike argv elements via `os.fsdecode`, mirroring what CPython actually sees at `execve` time. Without this, a malicious dep on POSIX could pass `[sys.executable, b"-S", b"-c", payload]` to `subprocess.Popen` and have the bytes flag survive while a string-only check missed it, letting the child run with `site.py` disabled (no auto-activation) under `external_subprocess_policy="block"`. Closes the bypass for opportunistic attackers; deliberate attackers with `ctypes` access can still bypass tethered entirely (existing universal-bypass caveat — see [`SECURITY.md`](SECURITY.md)).

### Changed

- C guardian's per-event ContextVar consistency check now uses `PyContextVar_Get` (direct C API) instead of `PyObject_CallMethod` — removes Python-level method dispatch from the audit-event hot path.
- C guardian caller-verification on `_guardian.resolve()` now fails closed when `PyEval_GetFrame()` returns NULL (previously skipped silently). Closes a narrow defense-in-depth gap for non-Python C-API callers.

## [0.4.0] — 2026-03-29

### Added

- C extension (`_guardian.c`) for tamper-resistant locked mode. Snapshots the identity of every critical Python object at activation time and verifies integrity on every socket event. Detects config replacement, method monkey-patching, frozen field mutation via `object.__setattr__`, and bytecode swapping. On tamper detection, blocks ALL network access (fail-closed) and writes a tamper alert to stderr via `os.write(fd 2)`.
- The C extension is now required — installation fails without a C compiler (pre-built wheels include the compiled extension for all platforms).
- `cibuildwheel` CI job builds platform-specific wheels with the compiled C extension for Linux, macOS, and Windows across Python 3.10–3.14.
- Publish workflow split into a separate GitHub Actions workflow, triggered via `workflow_run` after CI succeeds.
- CodeQL now scans both Python and C/C++ code.
- `cppcheck` static analysis for C code via Docker-based pre-commit hook.

### Changed

- Build backend switched from `hatchling` to `setuptools` for native C extension support.

## [0.3.3] — 2026-03-22

### Fixed

- `lock_token` now rejects internable types (`str`, `int`, `float`, `bytes`, `bool`) when `locked=True`. CPython interns these types, so separate literals can share identity and defeat the lock. Use `object()` or a custom instance instead.

### Changed

- Moved `_reset_state()` logic from production code to test fixtures.

## [0.3.2] — 2026-03-22

### Added

- Context-local `scope()` API for narrowing allowed destinations within a block of code. Usable as both a context manager (`with tethered.scope(allow=[...]):`) and a decorator (`@tethered.scope(allow=[...])`). Supports `log_only`, `fail_closed`, `allow_localhost`, and `on_blocked` options. Scopes use intersection semantics — they can only narrow the global policy, never widen it. Safe for concurrent use across threads and async tasks.
- Input validation on `activate()` and `scope()` parameters (type checks for `allow`, `on_blocked`, `locked`, `log_only`, `fail_closed`, `allow_localhost`).
- Runnable examples in `examples/`.

## [0.2.0] — 2026-03-15

### Added

- Unicode NFC normalization and fullwidth dot normalization for hostnames and allow rules.
- Hostname validation rejects control characters, null bytes, and invisible Unicode.
- `gethostbyaddr` reverse-DNS lookups are now subject to policy enforcement.

### Changed

- `activate(locked=True)` now requires `lock_token` (raises `ValueError` if omitted).
- `activate()` over a locked policy now requires the correct `lock_token` (raises `TetheredLocked`).
- `getaddrinfo` hook forwards all caller arguments (family, socktype, proto, flags) to C-level resolver.
- Locked mode documentation clarified to better reflect the security model.

### Fixed

- IP-to-hostname map now refreshes existing entries on re-resolution.
- Config and IP map updates are now atomic under nested locks.

### Security

- Documented shared-IP/CDN cache mapping as a known limitation in the security model.
- Documented localhost relay risk with default `allow_localhost=True` in the security model.

[Unreleased]: https://github.com/shcherbak-ai/tethered/compare/v0.5.3...HEAD
[0.5.3]: https://github.com/shcherbak-ai/tethered/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/shcherbak-ai/tethered/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/shcherbak-ai/tethered/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/shcherbak-ai/tethered/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/shcherbak-ai/tethered/compare/v0.3.3...v0.4.0
[0.3.3]: https://github.com/shcherbak-ai/tethered/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/shcherbak-ai/tethered/compare/v0.2.0...v0.3.2
[0.2.0]: https://github.com/shcherbak-ai/tethered/compare/v0.1.4...v0.2.0
