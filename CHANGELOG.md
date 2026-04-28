# Changelog

All notable changes to this project will be documented in this file. Each version listed corresponds to a release published on [PyPI](https://pypi.org/project/tethered/).

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

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

[0.5.0]: https://github.com/shcherbak-ai/tethered/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/shcherbak-ai/tethered/compare/v0.3.3...v0.4.0
[0.3.3]: https://github.com/shcherbak-ai/tethered/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/shcherbak-ai/tethered/compare/v0.2.0...v0.3.2
[0.2.0]: https://github.com/shcherbak-ai/tethered/compare/v0.1.4...v0.2.0
