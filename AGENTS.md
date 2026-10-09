# AGENTS.md — tethered

## What is tethered

tethered is a zero-dependency Python library for runtime network egress control. It uses `sys.addaudithook` (PEP 578) to intercept outbound socket connections and enforce an allow list of permitted destinations. One function call, no sidecar containers, no infrastructure changes.

```python
import tethered

tethered.activate(allow=["*.stripe.com:443", "db.internal:5432"])
```

## Architecture

```text
src/tethered/
    __init__.py        # Public API: activate, deactivate, scope, EgressBlocked, TetheredLocked, SubprocessBlocked
    _policy.py         # AllowPolicy — pattern parsing and matching (pure logic, no side effects)
    _core.py           # Audit hook, _Config bundle, scope, subprocess propagation, IP-to-hostname resolution
    _autoactivate.py   # Child-process bootstrap — reads _TETHERED_CHILD_POLICY and re-activates tethered
    _guardian.c        # C extension — integrity verifier for tamper-resistant locked mode
    _guardian.pyi      # Type stub for the C extension
src/tethered.pth       # Run by site.py at interpreter startup when installed in a site directory — runs _autoactivate
setup.py               # Build config: C extension + packaging of tethered.pth (setuptools)
scripts/
    cppcheck.sh            # Docker-based cppcheck runner for pre-commit
    wheel_smoke_test.py    # Post-build check run by cibuildwheel — .pth installed, extension imports, child auto-activates
tests/
    conftest.py                # Test-suite egress guard (uses AllowPolicy), .pth installer, per-test state cleanup
    test_policy.py             # Unit tests for AllowPolicy (no hooks, no network)
    test_policy_properties.py  # Hypothesis property tests for AllowPolicy and the serialization round trip
    test_core.py               # Integration tests with real sockets (sync, async, scopes)
    test_exceptions.py         # Pickle/copy round trips of the exceptions, blocked calls in worker pools
    test_lifecycle.py          # activate()/deactivate() serialization, failure safety, token rules, hook installation
    test_subinterpreters.py    # Real subinterpreters under locked, log-only and unlocked policies
    test_subprocess.py         # Launch classification, launch-environment handling, scope propagation, locked-mode integrity, perf
    test_autoactivate.py       # Child-side bootstrap: payload validation, scope inheritance, fail-closed startup
    test_guardian.py           # C extension: snapshot coverage, tamper detection, guarded events, resolver window
tests_examples/
    conftest.py        # Installs tethered.pth into site-packages for the example run
    test_examples.py   # Runs each example/ script as a subprocess (requires network)
benchmarks/
    overhead.py        # Standalone microbenchmark — per-event overhead activated vs deactivated vs locked
examples/
    *.py               # Runnable usage examples (httpx + api.github.com)
docs/
    API.md             # Full API reference (activate, scope, deactivate, exceptions, locked mode)
    SUBPROCESS.md      # Subprocess auto-propagation, scope propagation, external_subprocess_policy
    ARCHITECTURE.md    # Audit-hook mechanics, scope ContextVar, C guardian
    COOKBOOK.md        # Django/FastAPI middleware, Celery, retry decorators
README.md              # Pitch + quick start + pointers (deliberately slim)
SECURITY.md            # Threat model, what tethered does/doesn't protect against, vulnerability reporting
```

### Module responsibilities

- **`_policy.py`** is pure logic. `AllowPolicy` is deeply immutable after construction and thread-safe to read: rules are `NamedTuple`s of strings and integers (a network is stored as integers), and the matching methods read plain-tuple copies of the rule fields, so nothing can be reassigned in place. It handles hostname wildcards (`*.stripe.com`), CIDR ranges (`10.0.0.0/8`), port filtering (`host:443`), and localhost detection. It also keeps every parsed rule in allow-list order (`_parsed_rules`) and classifies one rule of a scope against a global policy (`_check_rule_overlap`); `scope()` pairs that with the rule text for its overlap warnings, so a rule string is parsed in exactly one place. Malformed rules raise `ValueError` at construction. Its only side effect is logging (a warning, once per rule per process, for an address-shaped wildcard such as `10.*`), and it has no imports beyond stdlib (`fnmatch`, `ipaddress`, `logging`, `re`, `typing`, `unicodedata`).

- **`_core.py`** owns the audit hook lifecycle. It installs a single `sys.addaudithook` that intercepts: (1) socket events — `socket.getaddrinfo`, `socket.gethostbyname`/`gethostbyaddr` (DNS-level policy + IP↔hostname mapping; `socket.getnameinfo` is deliberately not handled, because its event carries no flags), `socket.connect`/`sendto`/`sendmsg` (connection policy), and `socket.__new__` (no enforcement — a one-time warning on Windows when a `ProactorEventLoop` is running, since that loop raises no connect events); (2) process-launch events — `subprocess.Popen`, `os.system`, `os.exec*`, `os.posix_spawn`, `os.spawn*`, `os.startfile`, plus `_winapi.CreateProcess` and (Python 3.14+) `_posixsubprocess.fork_exec` for launches that bypass `subprocess.Popen` such as `multiprocessing` workers (launch classification, `external_subprocess_policy` enforcement, establishing the policy payload in the child's launch environment, locked-mode payload-integrity check, scope-to-subprocess propagation via frame-locals mutation in `_execute_child`); (3) `os.putenv`/`os.unsetenv` of the policy variable, which `os.environ` does not show (tracked in the `_env_dirty` flag); (4) FS events in locked mode — `os.remove`, `os.rename`, `open` (write-mode), `os.chmod`, `os.truncate`, `os.link`, `os.symlink`, `_winapi.CopyFile2` (refuses tampering with `tethered.pth`, and creating a `tethered.start` beside it, which from Python 3.15 switches the `.pth` import line off). All per-activation state (`policy`, `log_only`, `fail_closed`, `on_blocked`, `locked`, `external_subprocess_policy`, `_serialized_payload`, `_global_payload_dict`, `_pth_path`, `_local_hostname`) is bundled into a frozen `_Config` dataclass; a hook reads `_config` once and works from that object, which eliminates TOCTOU bugs between fields. The lock token is not in `_Config`: only the C guardian holds it. `activate()` and `deactivate()` are serialized from start to finish by the re-entrant `_lifecycle_lock` and are all-or-nothing; `_state_lock` only guards the one-time hook installation. The IP-to-hostname map is an `OrderedDict` with LRU eviction, guarded by `_ip_map_lock`. The hook is installed once and can never be removed — after `deactivate()`, `_config` is `None` and the hook is a no-op. `_install_hook()` confirms the hook is live with the private audit event `tethered.hook_probe` (the hook answers through the list passed with it; `_audit_hook` tests `_ENV_AND_PROBE_EVENTS`, and `_ENV_EVENTS` remains the list to keep in step with the C `classify_event`) and raises `RuntimeError` when another audit hook refused it. Context-local scopes are managed by a `_ScopeConfig` dataclass, a `_scopes` `ContextVar` holding a per-context scope stack, and the `scope` class (usable as both a context manager and a decorator); entries are pushed and removed by identity (`_push_scope`/`_pop_scope`), and `_active_scope_count` counts them process-wide. The `_check_scopes` and `_enforce_scope_block` helpers are called from the audit hook to intersect scope rules with the global policy. `_build_integrity_snapshot` generates the list of facts the C guardian pins in locked mode.

- **`_autoactivate.py`** runs at interpreter startup, via `tethered.pth`, in every Python process whose `site.py` processes that file and whose environment carries `_TETHERED_CHILD_POLICY`. Reads the variable (nested JSON: `{"global": {...}, "scopes": [...]}`), validates the payload schema (exact types), calls `tethered.activate(**global)` if a non-null global is present, then pushes inherited scopes onto the `_scopes` ContextVar of the context the child starts in (no `__exit__` ever fires — they stay for the child's lifetime, but like any scope they are context-local, not a process-wide floor). When the inherited global has `locked` or `fail_closed` set and the policy cannot be established, it raises `SystemExit` so the interpreter does not start (`site.py` swallows ordinary exceptions from a `.pth` line); otherwise it logs a warning and continues. One exception: inside a subinterpreter an inherited `locked` policy is established unlocked (`_establish_unlocked`, which binds a `_Config` directly and never writes the process-wide policy variable), because a lock exists once per process and the C guardian refuses that interpreter the guarded operations. Idempotent (skips if `_config` is already set, which is the fork-mode case where state is inherited via process-state copy).

- **`__init__.py`** re-exports the public API (`activate`, `deactivate`, `scope`, `EgressBlocked`, `TetheredLocked`, `SubprocessBlocked`). Nothing else lives here.

- **`_guardian.c`** is a C extension that provides tamper-resistant locked mode. It does NOT reimplement policy matching — all matching stays in Python. At `activate(locked=True)` it records a list of `(owner, name, kind)` facts that `_core._build_integrity_snapshot()` generates from the namespaces of `_core` and `_policy`: every module-level binding (except `_config` and lower-case scalar runtime state), every class attribute of the classes defined there, the `__code__` of every function, the absence of shadowed builtins and of `__getattribute__`/`__getattr__` hooks, and the class and every slot of the active `_Config` and `AllowPolicy`. It re-checks them, comparing pointers, on every socket audit event, every process-launch event, and — pre-filtered in C — filesystem events whose path mentions `tethered.pth` or `tethered.start` and `os.putenv`/`os.unsetenv` of the policy variable. Any mismatch (object replaced, method monkey-patched, frozen field mutated via `object.__setattr__`) refuses the operation — `EgressBlocked` for socket events, `SubprocessBlocked` for the others — and a tamper alert is written to fd 2. The C guardian also owns the lock state: it alone holds the token, `deactivate()` and `activate()` go through C for token verification, and it rebinds `_core._config` as part of its own commit, so swapping `_config` to an unlocked config doesn't help; a policy that fails the check can be neither replaced nor deactivated. It also owns the trusted DNS-resolution window (`resolve()`, calling the resolver captured at lock time), and its lock is process-wide, held under the owner's interpreter ID (never its address, which a later interpreter can be given): for events raised in other interpreters it touches none of the owner's objects (only atomics and the event's arguments) and refuses them the guarded operations, letting socket events pass under a `log_only` lock. When it adds its hook it confirms the hook is live with a private probe event and fails activation otherwise. The event lists in `classify_event` must stay in step with `_SUBPROCESS_EVENTS`, `_PTH_FS_EVENTS` and `_ENV_EVENTS` in `_core.py`. `locked=True` requires the C extension. The extension is always built during installation — a C compiler is required for source installs. It uses single-phase initialisation and does not declare free-threading support.

### Key design decisions

1. **Fail-open by default, fail-closed optional.** If the matching logic itself raises an unexpected exception, the connection is allowed and a warning is logged (fail-open). Users can set `fail_closed=True` for stricter environments where errors should block rather than allow. The child bootstrap follows the same rule: a child that cannot establish an inherited policy logs a warning and continues, unless that policy has `locked` or `fail_closed` set, in which case it refuses to start.

2. **Audit hooks are irremovable.** `sys.addaudithook` has no corresponding remove function. This is a feature for security (malicious code can't unhook it) but means tests must use `deactivate()` or reset internal state directly in fixtures for cleanup rather than removing the hook.

3. **IP-to-hostname mapping via getaddrinfo interception.** When `socket.getaddrinfo("api.stripe.com", 443)` fires, we resolve it ourselves (with a reentrancy guard) and record the hostname under the canonical text of each resolved IP. The map value is a tuple of up to 8 hostnames per address, most recent first. When `socket.connect(sock, (resolved_ip, 443))` fires later, we look up the names and allow the connect if the policy allows any of them or the raw IP. `gethostbyname` records no mapping, only a candidate for the connect-time fallback search (`_fallback_resolve`), which runs on a map miss unless every layer already allows the raw IP.

4. **Thread safety.** `AllowPolicy` is deeply immutable. The `_Config` bundle is a frozen dataclass swapped by a single reference assignment, and `activate()`/`deactivate()` are serialized by the re-entrant `_lifecycle_lock` (`_state_lock` only guards hook installation). `_ip_to_hostname` is an `OrderedDict` guarded by `_ip_map_lock` with LRU eviction. `_active_scope_count` is guarded by `_scope_count_lock`. Reentrancy guard uses `contextvars.ContextVar` (async-safe, faster than `threading.local()`). None of this has been validated on free-threaded Python: the C extension does not declare free-threading support (the GIL is re-enabled when it is imported on a free-threaded build) and no free-threaded wheels are published.

5. **Zero runtime dependencies.** Everything uses stdlib only: `sys`, `os`, `_socket`, `threading`, `collections`, `contextvars`, `dataclasses`, `fnmatch`, `functools`, `inspect`, `ipaddress`, `json`, `logging`, `operator`, `re`, `reprlib`, `types`, `typing`, `unicodedata`, plus `site` (imported lazily) and, on Python 3.10–3.12 only, `ctypes` (imported lazily for `PyFrame_LocalsToFast`). The C extension (`_guardian.c`) uses only the CPython C API. Build dependencies (`setuptools`) are build-time only.

6. **Context-local scopes.** `scope()` uses `contextvars.ContextVar` to maintain a per-context stack of scope configurations, making it safe for concurrent use across threads and async tasks. Scopes use intersection semantics with the global policy — they can only narrow the set of allowed destinations, never widen it. `scope` works as both a context manager (`with tethered.scope(allow=[...]):`) and a decorator (`@tethered.scope(allow=[...])`); generator functions cannot be decorated. A scope exits by removing its own entry from the stack, by identity, not by restoring a snapshot, so out-of-order exits (a generator suspended inside a `with scope():` block) do not disturb other scopes. A process-wide count of active scope entries lets the hook record lookups made in threads that do not carry the scope (asyncio's executor).

7. **Tamper-resistant locked mode via C extension.** When `activate(locked=True)` is called, the C guardian records a snapshot generated from the `_core` and `_policy` namespaces and verifies it on every socket event, every process-launch event, and the guarded `tethered.pth` / policy-variable events. This catches `_config` replacement, rebinding of any module-level function or helper, method monkey-patching, `object.__setattr__` on the frozen config, and `__code__` swapping. It is not a sandbox, and `ctypes` is not the only way around it: builtins and the standard-library functions the policy calls, the contents of pinned containers (the IP map), function defaults and closures, and anything done before activation are outside the snapshot. `SECURITY.md` ("Locked mode — what it does and does not do") is the authoritative statement; update it whenever `_build_integrity_snapshot` or the guardian's event list changes.

8. **Subprocess auto-propagation via `tethered.pth`.** `activate()` writes a JSON-serialized policy to `os.environ["_TETHERED_CHILD_POLICY"]`, and the subprocess hook establishes the same payload in each Python child's launch environment (injected into an explicit `env=` of any mapping type, re-asserted in `os.environ` if it was cleaned; locked mode refuses instead). A Python interpreter runs `tethered._autoactivate` on startup when `tethered.pth` is in a site directory it processes — site-packages or the enabled user site, not an editable install's `src/`. The child re-engages tethered with the parent's policy before user code runs. This covers `multiprocessing.Pool`, `ProcessPoolExecutor`, gunicorn/uvicorn workers, and plain `subprocess.run([sys.executable, ...])`. `external_subprocess_policy` (`warn`/`block`/`allow`, default `warn`) controls parent-side enforcement for launches that auto-inherit can't reach: non-Python tools, different Python interpreters, `sys.executable` with `-S` (the only site-bypass flag; `-s` and `-I` count only when the hook is in the per-user site-packages, and `-E` never does), a POSIX launch whose `argv[0]` is not `sys.executable`, interpreter options that cannot be parsed, any Python launch when no processed `tethered.pth` exists, and a Python launch whose environment cannot be given the payload.

9. **Scope-to-subprocess propagation via frame-locals mutation.** `tethered.scope()` propagates to spawn-mode child processes: a child launched from inside `with scope(allow=[...])` inherits the parent's effective policy at the launch site (global ∩ scopes), not just the at-rest global. Implemented by mutating `subprocess.Popen._execute_child`'s `env` local from inside the `subprocess.Popen` audit hook (PEP 667 write-through proxy on 3.13+; `ctypes.pythonapi.PyFrame_LocalsToFast` on 3.10–3.12). The same mechanism injects the global payload when an explicit `env=` lacks it, with or without a scope. Race-free across threads because frame locals are per-call, not shared global state. Audit hooks are read-only on `args`, so frame-locals mutation is the only mechanism that satisfies the no-monkey-patch and no-opt-in constraints. Limitation: scope cannot propagate through `os.system` / `os.exec*` / `os.startfile` (no env channel to inject) or through spawn-mode `multiprocessing` workers (they never reach `_execute_child`); those launches still receive the at-rest global only.

## Conventions

### Code style

- Use `from __future__ import annotations` in all modules.
- Private modules are prefixed with `_` (e.g., `_core.py`, `_policy.py`).
- Type hints on all public function signatures.
- No docstrings on private helpers unless the logic is non-obvious.
- Keep modules small and focused. If a module exceeds ~500 lines, consider splitting.

### Testing

- **Egress guard** (`conftest.py`): An independent audit hook that uses `AllowPolicy` to block unexpected network access between tests (when tethered is deactivated). Only `dns.google` and localhost are allowed. When tethered IS active, its own hook handles enforcement and the guard is a no-op. Because the guard raises `EgressBlocked` too, a test that expects a block from a scope should assert where it came from (e.g. `scope_label`). The lock token lives only in the C guardian, so a session fixture wraps `tethered.activate` to record every token a test passes; the autouse `_cleanup` fixture uses it to unlock the guardian, then resets `_config`, `_ip_to_hostname`, `_allowed_hostnames`, the `_scopes` ContextVar, the active-scope count and the native-env dirty flag, and clears `_TETHERED_CHILD_POLICY` from `os.environ` between tests. A second session fixture copies `tethered.pth` into site-packages when it is missing (editable installs), because the bootstrap is only recognized in a site directory.
- **Unit tests** (`test_policy.py`): Test `AllowPolicy` in isolation. No audit hooks, no network calls. This is where the bulk of pattern-matching coverage lives.
- **Property tests** (`test_policy_properties.py`): Hypothesis tests for `AllowPolicy` invariants (CIDR membership, port restriction, monotonicity, wildcard suffixes) and for the allow-list serialization round trip. Pure: no hooks, no network.
- **Integration tests** (`test_core.py`): Test `activate()`/`deactivate()` with real sockets (sync and async). Includes scope tests covering context manager usage, decorator usage, nesting, intersection semantics with the global policy, and concurrent scope isolation. Async tests use `pytest-asyncio` with `asyncio_mode = "auto"`.
- **Exception tests** (`test_exceptions.py`): Pickle, copy and deepcopy round trips of `EgressBlocked` / `SubprocessBlocked` / `TetheredLocked` (and subclasses), and spawn-mode `ProcessPoolExecutor` / `multiprocessing.Pool` tasks whose blocked loopback connect has to reach the parent as `EgressBlocked`.
- **Lifecycle tests** (`test_lifecycle.py`): `activate()`/`deactivate()` as one serialized, failure-safe transition — thread interleavings driven by a line tracer, a policy too large for an environment variable, the guardian's commit, and the lock-token rules. `TestHookInstallation` covers an audit hook that another hook refuses; a real refusing hook is only ever installed in a child process, because audit hooks cannot be removed.
- **Subprocess tests** (`test_subprocess.py`): Audit hook + `external_subprocess_policy` enforcement, launch classification (interpreter-option parsing, Windows command-line parser, bootstrap lookup), establishing the payload in the launch environment (any mapping type, one spelling of the key, `os.putenv`/`os.unsetenv` tracking), launches that bypass `subprocess.Popen`, locked-mode payload-integrity check, scope-to-subprocess propagation (round-trip, multi-thread, locked + scope), frame-locals helper unit tests, locked-mode `tethered.pth` FS-tamper hook, and microbenchmarks (`TestScopeSubprocessPerformance`, `TestLaunchEnvPerformance`) bounding the audit-hook helpers' per-call cost. Tests are offline; the propagation tests use `subprocess.run` to spawn real Python children but no network.
- **Autoactivate tests** (`test_autoactivate.py`): Direct unit tests for `_autoactivate_from_env()` (no env, malformed JSON, idempotency, locked-mode propagation, payload schema validation, children that refuse to start when a locked or fail-closed policy cannot be established) and end-to-end integration tests that spawn real Python subprocesses to verify the .pth bootstrap. Includes `TestInheritScopes` for scope chain inheritance.
- **Subinterpreter tests** (`test_subinterpreters.py`): real subinterpreters (skipped where the stdlib offers none) under a locked policy — creation and computation work, connections, lookups, launches and changes to the bootstrap files or the policy variable are refused with or without the variable in the environment, a log-only lock lets socket events pass, the owner is unaffected, and `InterpreterPoolExecutor` works on 3.14+. Every subinterpreter a test creates is destroyed.
- **Guardian tests** (`test_guardian.py`): C extension tamper detection. Replaces `_config`, monkey-patches `is_allowed`, mutates frozen dataclass slots via `object.__setattr__`, replaces helper functions (e.g., `_inject_scope_env`, `_find_execute_child_frame`) — all should fail-closed. `TestSnapshotCoverage` enumerates the globals of `_core` and `_policy` and fails for any name that is neither pinned nor on an explicit allowlist of runtime-state names, so a new module-level name must be one or the other. Also covers the guarded non-socket events, replaced Python-side guards, the resolver window, and the token being held only in C.
- Run core tests: `uv run pytest tests/ -v`
- Run with coverage: `uv run pytest tests/ -v --cov`
- Run example tests (requires network): `uv run pytest tests_examples/ -v`
- **Example tests** (`tests_examples/test_examples.py`): Run each `examples/*.py` as a subprocess. They make real HTTP calls to `api.github.com`. Not included in coverage (subprocesses aren't measured). Kept in a separate directory to avoid affecting coverage thresholds. `tests_examples/conftest.py` copies `tethered.pth` into site-packages for the session, as `tests/conftest.py` does: without the hook in a site directory, examples 11 and 12 would have their own Python children treated as external.
- **Adding a new example**: when adding `examples/<NN>_*.py`, register it in `EXAMPLE_SCRIPTS` in `tests_examples/test_examples.py`. The list is intentionally explicit (not a glob) so draft scripts don't enter the test rotation. Each registered example must exit with code 0 on the happy path, produce stdout, and print the literal token `(unexpected)` on any branch that should have been blocked by tethered — the test asserts `(unexpected)` is NOT present, so a tethered regression that allows a blocked call surfaces immediately.
- Core tests that need DNS resolution (log-only, fail-open, IP map tests) are marked `@requires_network` and skip automatically if DNS is unavailable. The majority of core tests run fully offline.
- **Microbenchmark** (`benchmarks/overhead.py`): Standalone, zero-dep script measuring per-event wall-clock overhead — `socket.connect` (TCP, against a daemon-thread accept-and-close listener on 127.0.0.1), `socket.getaddrinfo`, `sys.audit` synthetic event, and `with tethered.scope(...)` enter+exit — across deactivated / activated / activated+scope / activated+locked. Run with `uv run python benchmarks/overhead.py` (default 5k per-event iterations, 3k TCP iterations with a median-of-3 to reject load-spike outliers on Windows where the connect baseline is ~700 µs vs ~30 µs on Linux) or `--iterations N`. Not part of the test suite; intended for ad-hoc measurement.

### Linting and formatting

- Ruff handles linting and formatting. Configuration is in `pyproject.toml` under `[tool.ruff]`.
- Bandit handles security scanning. Configuration is in `pyproject.toml` under `[tool.bandit]`. Tests are excluded. Intentional suppressions use inline `# nosec BXXX` comments.
- Interrogate enforces docstring coverage on public items in `src/`. Configuration is in `pyproject.toml` under `[tool.interrogate]`. Private/magic/init are excluded (consistent with the "no docstrings on private helpers" convention). `fail-under = 100`.
- Lint: `uv run ruff check .` (auto-fix with `--fix`)
- Format: `uv run ruff format .`
- Type check: `uv run ty check src/ examples/`
- Docstrings: `uv run interrogate src/ -v`
- Security: `uv run bandit -c pyproject.toml -r src/`
- Cppcheck runs C static analysis on `_guardian.c` via a Docker-based pre-commit hook (`scripts/cppcheck.sh`). Requires Docker. Also runs in the CI lint job via `apt-get install cppcheck`.
- Pre-commit hooks run ruff, bandit, ty, interrogate, markdownlint, and cppcheck on every commit, and commitizen on commit messages. Ty and interrogate run as local hooks via `uv run`. Cppcheck runs via Docker (builds a `tethered-cppcheck` image from `ubuntu:24.04` on first use). Tests run in CI only (not in pre-commit) to avoid conflicts with `uv.lock` during version bumps. Third-party hooks are pinned by commit SHA for supply-chain integrity. Install with `uv run pre-commit install --hook-type pre-commit --hook-type commit-msg`.
- CI runs `pre-commit run --all-files` (lint job, includes ty), `cppcheck` on the C extension, and the full test matrix. The publish job uses `cibuildwheel` to build platform-specific wheels with the compiled C extension. GitHub Actions are pinned by commit SHA. The workflow uses `permissions: { contents: read }` for least privilege. A separate CodeQL workflow scans both Python and C/C++ code on push to main, on PRs, and weekly.

### What NOT to do

- Do not add runtime dependencies. This library must remain zero-dep. The C extension uses only the CPython C API (no external C libraries).
- Do not monkey-patch `socket.socket` or any other stdlib class. The audit hook API is the only interception mechanism.
- Do not catch `EgressBlocked` inside tethered itself (except in tests). It must propagate to the caller.
- Do not add framework-specific code (Django, Flask, etc.) to the core package. Framework integrations belong in documentation, not code.
- Do not add features speculatively. Every addition must serve a concrete, current use case.
- Do not stage or commit changes. The developer reviews and commits manually.

### Adding new allow rule types

If adding a new rule type (e.g., regex patterns, deny lists):

1. Add a new `_XxxRule` `NamedTuple` in `_policy.py` with primitive fields only (strings and integers), plus a plain-tuple fields slot on `AllowPolicy` that the matching methods read. Rules must stay deeply immutable: the locked-mode guardian pins the identity of each policy slot, not what is reachable through it.
2. Parse it in `AllowPolicy.__init__`, appending exactly one parsed rule per allow-list entry to `parsed_rules`: the scope overlap warnings pair `_parsed_rules` with the allow list by position.
3. Check it in `is_allowed()` or `_check_hostname()`/`_check_ip()`.
4. Serialize it in `_serialize_allow_list()` (`_core.py`) so that child processes rebuild the same rule; the serialized form must re-parse to an identical policy.
5. Classify it in `AllowPolicy._check_rule_overlap()`, so that `scope()` overlap warnings understand the new kind.
6. Add unit tests in `test_policy.py` first, then integration tests if needed.

### Documentation

- **`README.md`** is the pitch — what tethered is, why you'd use it, basic quick start, and pointers to deeper docs. Keep it short (~200 lines). Detailed API reference, threat-model enumeration, and framework recipes do NOT live here.
- **`SECURITY.md`** holds the threat model, the full "what tethered does NOT protect against" enumeration, the statement of what locked mode does and does not do, design tradeoffs, and vulnerability reporting. Adversarial detail belongs here, not in the README. The README and `docs/API.md` must not promise more than this file does.
- **`docs/API.md`** holds full API signatures and behavior — every parameter, every exception, locked mode, log-only mode, intersection semantics.
- **`docs/SUBPROCESS.md`** holds the subprocess control deep-dive — auto-propagation, `external_subprocess_policy`, scope-to-subprocess propagation, locked-mode hardening.
- **`docs/ARCHITECTURE.md`** holds implementation mechanics — audit hook events, scope ContextVar, C guardian.
- **`docs/COOKBOOK.md`** holds framework integration patterns (Django, FastAPI, Celery, retry decorators).
- **`CHANGELOG.md`** follows [Keep a Changelog](https://keepachangelog.com/) with `## [version] — YYYY-MM-DD` headings and `### Added` / `### Changed` / `### Fixed` / `### Security` subsections. Each version also gets a compare-link reference at the bottom of the file: `[version]: https://github.com/shcherbak-ai/tethered/compare/vPREV...vNEW`. New version sections go at the top of the file; the matching compare-link reference goes at the top of the link-reference block. Don't forget the compare link — a CHANGELOG entry without one is incomplete. Start an entry that can break an existing configuration or calling code with `**Breaking: …**` and end it with a "What to do:" sentence, so breaking changes can be found by search and do not depend on their position in the list.
- README docs/ links use absolute GitHub URLs (`https://github.com/.../docs/X.md`) so they render on PyPI; cross-references between docs/ files use relative paths.
- **Source style: one line per paragraph.** Do not hard-wrap prose, list items, or blockquote text at a column limit — write each paragraph (and each list item) on a single source line. CommonMark / GFM collapse soft line-breaks to spaces, so the rendered output is identical either way; the single-line form gives cleaner git diffs (a one-word edit doesn't churn the whole paragraph) and avoids re-wrap busywork. Code blocks (fenced and indented), tables, headings, link-reference definitions (`[label]: url`), and HTML blocks are left verbatim.

### Python version support

- Python 3.10–3.15. `sys.addaudithook` was added in 3.8, so this is well within range.
- The bootstrap is an `import` line in `tethered.pth`. PEP 829 (Python 3.15) deprecates such lines in favour of `<name>.start` entry-point files: they still run on 3.15–3.17 unless a `<name>.start` file sits beside the `.pth`, and Python 3.18 is to ignore them. tethered ships no `tethered.start`; locked mode refuses creating one. `test_cpython_ignores_a_pth_import_line_beside_a_start_file` in `tests/test_guardian.py` pins that behaviour and will fail on 3.18.
- Do not use syntax or features unavailable in 3.10 (e.g., no `type` statement from 3.12, no `except*` from 3.11).
