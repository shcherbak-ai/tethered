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
src/tethered.pth       # Auto-imported by site.py in every Python interpreter — runs _autoactivate
setup.py               # Build config: C extension + packaging of tethered.pth (setuptools)
scripts/
    cppcheck.sh        # Docker-based cppcheck runner for pre-commit
tests/
    conftest.py            # Test-suite egress guard — uses AllowPolicy
    test_policy.py         # Unit tests for AllowPolicy (no hooks, no network)
    test_core.py           # Integration tests with real sockets (sync, async, scopes)
    test_subprocess.py     # Subprocess audit hook, scope propagation, locked-mode integrity, perf
    test_autoactivate.py   # Child-side bootstrap parsing + scope inheritance
    test_guardian.py       # C extension tamper detection
tests_examples/
    test_examples.py   # Runs each example/ script as a subprocess (requires network)
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

- **`_policy.py`** is pure logic. `AllowPolicy` is immutable after construction and thread-safe to read. It handles hostname wildcards (`*.stripe.com`), CIDR ranges (`10.0.0.0/8`), port filtering (`host:443`), and localhost detection. It has zero side effects and no imports beyond stdlib (`fnmatch`, `ipaddress`, `logging`, `re`, `dataclasses`, `unicodedata`).

- **`_core.py`** owns the audit hook lifecycle. It installs a single `sys.addaudithook` that intercepts: (1) socket events — `socket.getaddrinfo`, `socket.gethostbyname`/`gethostbyaddr` (DNS-level policy + IP↔hostname mapping), `socket.connect`/`sendto`/`sendmsg` (connection policy); (2) subprocess events — `subprocess.Popen`, `os.system`, `os.exec*`, `os.posix_spawn`, `os.spawn*`, `os.startfile` (locked-mode payload-integrity check, `external_subprocess_policy` enforcement, scope-to-subprocess propagation via frame-locals mutation in `_execute_child`); (3) FS events in locked mode — `os.remove`, `os.rename`, `open` (write-mode), `os.chmod` (refuses tampering with `tethered.pth`). All per-activation state (`policy`, `log_only`, `fail_closed`, `on_blocked`, `locked`, `lock_token`, `external_subprocess_policy`, `_serialized_payload`, `_global_payload_dict`, `_pth_path`) is bundled into a frozen `_Config` dataclass swapped atomically under nested `_state_lock` + `_ip_map_lock` — eliminates TOCTOU bugs, safe on free-threaded Python (PEP 703). The IP-to-hostname map is an `OrderedDict` with LRU eviction. The hook is installed once and can never be removed — `deactivate()` sets `_config` to `None`, making the hook a no-op. Context-local scopes are managed by a `_ScopeConfig` dataclass, a `_scopes` `ContextVar` holding a per-context scope stack, and the `scope` class (usable as both a context manager and a decorator). The `_check_scopes` and `_enforce_scope_block` helpers are called from the audit hook to intersect scope rules with the global policy.

- **`_autoactivate.py`** runs in every Python child process via `tethered.pth` at interpreter startup. Reads `_TETHERED_CHILD_POLICY` (nested JSON: `{"global": {...}, "scopes": [...]}`), calls `tethered.activate(**global)` if a non-null global is present, then pushes inherited scopes onto the child's `_scopes` ContextVar (no `__exit__` ever fires — they persist for the child's lifetime). Idempotent (skips if `_config` is already set, which is the fork-mode case where state is inherited via process-state copy).

- **`__init__.py`** re-exports the public API (`activate`, `deactivate`, `scope`, `EgressBlocked`, `TetheredLocked`, `SubprocessBlocked`). Nothing else lives here.

- **`_guardian.c`** is a C extension that provides tamper-resistant locked mode. It does NOT reimplement policy matching — all matching stays in Python. Instead, it snapshots the identity (`id()`) of every critical Python object at `activate(locked=True)` time: all `_Config` fields, all `AllowPolicy` internals, enforcement handler functions (+ their `__code__`), and the `EgressBlocked` class. On every socket audit event, it re-fetches each attribute and compares pointers. Any mismatch (object replaced, method monkey-patched, frozen field mutated via `object.__setattr__`) triggers fail-closed: ALL network access is blocked and a tamper alert is written to fd 2. The C guardian also owns the lock state — `deactivate()` and `activate()` go through C for token verification, so swapping `_config` to an unlocked config doesn't help. `locked=True` requires the C extension. The extension is always built during installation — a C compiler is required for source installs.

### Key design decisions

1. **Fail-open by default, fail-closed optional.** If the matching logic itself raises an unexpected exception, the connection is allowed and a warning is logged (fail-open). Users can set `fail_closed=True` for stricter environments where errors should block rather than allow.

2. **Audit hooks are irremovable.** `sys.addaudithook` has no corresponding remove function. This is a feature for security (malicious code can't unhook it) but means tests must use `deactivate()` or reset internal state directly in fixtures for cleanup rather than removing the hook.

3. **IP-to-hostname mapping via getaddrinfo interception.** When `socket.getaddrinfo("api.stripe.com", 443)` fires, we resolve it ourselves (with a reentrancy guard) and store `{resolved_ip: "api.stripe.com"}`. When `socket.connect(sock, (resolved_ip, 443))` fires later, we look up the hostname and check it against the policy.

4. **Thread safety.** `AllowPolicy` is immutable. The `_Config` bundle is a frozen dataclass swapped atomically (single reference assignment). `_ip_to_hostname` is an `OrderedDict` guarded by `_ip_map_lock` with LRU eviction. Reentrancy guard uses `contextvars.ContextVar` (async-safe, faster than `threading.local()`).

5. **Zero runtime dependencies.** Everything uses stdlib only: `sys`, `_socket`, `threading`, `collections`, `ipaddress`, `fnmatch`, `logging`, `re`, `dataclasses`, `unicodedata`, `contextvars`. The C extension (`_guardian.c`) uses only the CPython C API. Build dependencies (`setuptools`) are build-time only.

6. **Context-local scopes.** `scope()` uses `contextvars.ContextVar` to maintain a per-context stack of scope configurations, making it safe for concurrent use across threads and async tasks. Scopes use intersection semantics with the global policy — they can only narrow the set of allowed destinations, never widen it. `scope` works as both a context manager (`with tethered.scope(allow=[...]):`) and a decorator (`@tethered.scope(allow=[...])`).

7. **Tamper-resistant locked mode via C extension.** When `activate(locked=True)` is called, the C guardian snapshots all critical Python objects and verifies their integrity on every socket event. This catches `_config` replacement, method monkey-patching, `object.__setattr__` on frozen dataclasses, and `__code__` swapping. The only remaining bypass is raw memory manipulation via `ctypes` (requires reverse-engineering the compiled extension).

8. **Subprocess auto-propagation via `tethered.pth`.** `activate()` writes a JSON-serialized policy to `os.environ["_TETHERED_CHILD_POLICY"]`. Every Python interpreter that has tethered installed runs `tethered._autoactivate` on startup via the `.pth` file shipped at the top of site-packages. The child re-engages tethered with the parent's policy before user code runs. This covers `multiprocessing.Pool`, `ProcessPoolExecutor`, gunicorn/uvicorn workers, and plain `subprocess.run([sys.executable, ...])` — anywhere a Python child is spawned. `external_subprocess_policy` (`warn`/`block`/`allow`, default `warn`) controls parent-side enforcement for launches that auto-inherit can't reach: non-Python tools, different Python interpreters, or `sys.executable` with site-bypass flags (`-S`/`-I`/`-E`).

9. **Scope-to-subprocess propagation via frame-locals mutation.** `tethered.scope()` propagates to spawn-mode child processes: a child launched from inside `with scope(allow=[...])` inherits the parent's effective policy at the launch site (global ∩ scopes), not just the at-rest global. Implemented by mutating `subprocess.Popen._execute_child`'s `env` local from inside the `subprocess.Popen` audit hook (PEP 667 write-through proxy on 3.13+; `ctypes.pythonapi.PyFrame_LocalsToFast` on 3.10–3.12). Race-free across threads because frame locals are per-call, not shared global state. Audit hooks are read-only on `args`, so frame-locals mutation is the only mechanism that satisfies the no-monkey-patch and no-opt-in constraints. Limitation: scope cannot propagate through `os.system` / `os.exec*` / `os.startfile` (no env channel to inject); those launches still receive the at-rest global only.

## Conventions

### Code style

- Use `from __future__ import annotations` in all modules.
- Private modules are prefixed with `_` (e.g., `_core.py`, `_policy.py`).
- Type hints on all public function signatures.
- No docstrings on private helpers unless the logic is non-obvious.
- Keep modules small and focused. If a module exceeds ~500 lines, consider splitting.

### Testing

- **Egress guard** (`conftest.py`): An independent audit hook that uses `AllowPolicy` to block unexpected network access between tests (when tethered is deactivated). Only `dns.google` and localhost are allowed. When tethered IS active, its own hook handles enforcement and the guard is a no-op. The autouse `_cleanup` fixture resets `_config`, `_ip_to_hostname`, the `_scopes` ContextVar, deactivates the C guardian, and clears `_TETHERED_CHILD_POLICY` from `os.environ` between tests.
- **Unit tests** (`test_policy.py`): Test `AllowPolicy` in isolation. No audit hooks, no network calls. This is where the bulk of pattern-matching coverage lives.
- **Integration tests** (`test_core.py`): Test `activate()`/`deactivate()` with real sockets (sync and async). Includes scope tests covering context manager usage, decorator usage, nesting, intersection semantics with the global policy, and concurrent scope isolation. Async tests use `pytest-asyncio` with `asyncio_mode = "auto"`.
- **Subprocess tests** (`test_subprocess.py`): Audit hook + `external_subprocess_policy` enforcement, locked-mode payload-integrity check, scope-to-subprocess propagation (round-trip, multi-thread, locked + scope), frame-locals helper unit tests, Windows command-line parser tests, locked-mode `tethered.pth` FS-tamper hook, and microbenchmarks (`TestScopeSubprocessPerformance`) bounding the audit-hook helpers' per-call cost. Tests are offline; the propagation tests use `subprocess.run` to spawn real Python children but no network.
- **Autoactivate tests** (`test_autoactivate.py`): Direct unit tests for `_autoactivate_from_env()` (no env, malformed JSON, idempotency, locked-mode propagation, C-extension fallback) and end-to-end integration tests that spawn real Python subprocesses to verify the .pth bootstrap. Includes `TestInheritScopes` for scope chain inheritance.
- **Guardian tests** (`test_guardian.py`): C extension tamper detection. Replaces `_config`, monkey-patches `is_allowed`, mutates frozen dataclass slots via `object.__setattr__`, replaces helper functions (e.g., `_inject_scope_env`, `_find_execute_child_frame`) — all should fail-closed.
- Run core tests: `uv run pytest tests/ -v`
- Run with coverage: `uv run pytest tests/ -v --cov`
- Run example tests (requires network): `uv run pytest tests_examples/ -v`
- **Example tests** (`tests_examples/test_examples.py`): Run each `examples/*.py` as a subprocess. They make real HTTP calls to `api.github.com`. Not included in coverage (subprocesses aren't measured). Kept in a separate directory to avoid affecting coverage thresholds.
- **Adding a new example**: when adding `examples/<NN>_*.py`, register it in `EXAMPLE_SCRIPTS` in `tests_examples/test_examples.py`. The list is intentionally explicit (not a glob) so draft scripts don't enter the test rotation. Each registered example must exit with code 0 on the happy path, produce stdout, and print the literal token `(unexpected)` on any branch that should have been blocked by tethered — the test asserts `(unexpected)` is NOT present, so a tethered regression that allows a blocked call surfaces immediately.
- Core tests that need DNS resolution (log-only, fail-open, IP map tests) are marked `@requires_network` and skip automatically if DNS is unavailable. The majority of core tests run fully offline.

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

1. Add a new `_XxxRule` dataclass in `_policy.py`.
2. Parse it in `AllowPolicy.__init__`.
3. Check it in `is_allowed()` or `_check_hostname()`/`_check_ip()`.
4. Add unit tests in `test_policy.py` first, then integration tests if needed.

### Documentation

- **`README.md`** is the pitch — what tethered is, why you'd use it, basic quick start, and pointers to deeper docs. Keep it short (~200 lines). Detailed API reference, threat-model enumeration, and framework recipes do NOT live here.
- **`SECURITY.md`** holds the threat model, the full "what tethered does NOT protect against" enumeration, design tradeoffs, and vulnerability reporting. Adversarial detail belongs here, not in the README.
- **`docs/API.md`** holds full API signatures and behavior — every parameter, every exception, locked mode, log-only mode, intersection semantics.
- **`docs/SUBPROCESS.md`** holds the subprocess control deep-dive — auto-propagation, `external_subprocess_policy`, scope-to-subprocess propagation, locked-mode hardening.
- **`docs/ARCHITECTURE.md`** holds implementation mechanics — audit hook events, scope ContextVar, C guardian.
- **`docs/COOKBOOK.md`** holds framework integration patterns (Django, FastAPI, Celery, retry decorators).
- README docs/ links use absolute GitHub URLs (`https://github.com/.../docs/X.md`) so they render on PyPI; cross-references between docs/ files use relative paths.
- **Source style: one line per paragraph.** Do not hard-wrap prose, list items, or blockquote text at a column limit — write each paragraph (and each list item) on a single source line. CommonMark / GFM collapse soft line-breaks to spaces, so the rendered output is identical either way; the single-line form gives cleaner git diffs (a one-word edit doesn't churn the whole paragraph) and avoids re-wrap busywork. Code blocks (fenced and indented), tables, headings, link-reference definitions (`[label]: url`), and HTML blocks are left verbatim. The repo helper `scripts/reflow_md.py` collapses any stray hard-wraps and is idempotent on already-flowed files; run it before committing if you've been editing in an editor that auto-wraps.

### Python version support

- Python 3.10–3.14. `sys.addaudithook` was added in 3.8, so this is well within range.
- Do not use syntax or features unavailable in 3.10 (e.g., no `type` statement from 3.12, no `except*` from 3.11).
