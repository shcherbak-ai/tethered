# AGENTS.md — Tethered

## What is Tethered

Tethered is a zero-dependency Python library for runtime network egress control. It uses `sys.addaudithook` (PEP 578) to intercept outbound socket connections and enforce an allow list of permitted destinations. One function call, no sidecar containers, no infrastructure changes.

```python
import tethered

tethered.activate(allow=["*.stripe.com:443", "db.internal:5432"])
```

## Architecture

```text
src/tethered/
    __init__.py    # Public API surface: activate(), deactivate(), EgressBlocked, TetheredLocked
    _policy.py     # AllowPolicy — pattern parsing and matching (pure logic, no side effects)
    _core.py       # Audit hook, _Config bundle, state management, IP-to-hostname resolution
tests/
    conftest.py     # Test-suite egress guard — uses AllowPolicy
    test_policy.py  # Unit tests for AllowPolicy (no hooks, no network)
    test_core.py    # Integration tests with real sockets (sync and async)
```

### Module responsibilities

- **`_policy.py`** is pure logic. `AllowPolicy` is immutable after construction and thread-safe to read. It handles hostname wildcards (`*.stripe.com`), CIDR ranges (`10.0.0.0/8`), port filtering (`host:443`), and localhost detection. It has zero side effects and no imports beyond stdlib (`fnmatch`, `ipaddress`, `logging`, `dataclasses`).

- **`_core.py`** owns the audit hook lifecycle. It installs a single `sys.addaudithook` that intercepts `socket.getaddrinfo` and `socket.gethostbyname`/`gethostbyaddr` (to enforce DNS-level policy and map IPs back to hostnames) and `socket.connect`/`sendto`/`sendmsg` (to enforce the connection policy). All per-activation state (`policy`, `log_only`, `fail_closed`, `on_blocked`, `locked`, `lock_token`) is bundled into a frozen `_Config` dataclass that is swapped atomically — this eliminates TOCTOU bugs between separate state reads and is safe on free-threaded Python (PEP 703). The IP-to-hostname map is an `OrderedDict` with LRU eviction. The hook is installed once and can never be removed — `deactivate()` sets `_config` to `None`, making the hook a no-op.

- **`__init__.py`** re-exports the public API. Nothing else lives here.

### Key design decisions

1. **Fail-open by default, fail-closed optional.** If the matching logic itself raises an unexpected exception, the connection is allowed and a warning is logged (fail-open). Users can set `fail_closed=True` for stricter environments where errors should block rather than allow.

2. **Audit hooks are irremovable.** `sys.addaudithook` has no corresponding remove function. This is a feature for security (malicious code can't unhook it) but means tests must use `deactivate()` + `_reset_state()` for cleanup rather than removing the hook.

3. **IP-to-hostname mapping via getaddrinfo interception.** When `socket.getaddrinfo("api.stripe.com", 443)` fires, we resolve it ourselves (with a reentrancy guard) and store `{resolved_ip: "api.stripe.com"}`. When `socket.connect(sock, (resolved_ip, 443))` fires later, we look up the hostname and check it against the policy.

4. **Thread safety.** `AllowPolicy` is immutable. The `_Config` bundle is a frozen dataclass swapped atomically (single reference assignment). `_ip_to_hostname` is an `OrderedDict` guarded by `_ip_map_lock` with LRU eviction. Reentrancy guard uses `contextvars.ContextVar` (async-safe, faster than `threading.local()`).

5. **Zero dependencies.** Everything uses stdlib only: `sys`, `socket`, `threading`, `collections`, `ipaddress`, `fnmatch`, `logging`, `dataclasses`.

## Conventions

### Code style

- Use `from __future__ import annotations` in all modules.
- Private modules are prefixed with `_` (e.g., `_core.py`, `_policy.py`).
- Type hints on all public function signatures.
- No docstrings on private helpers unless the logic is non-obvious.
- Keep modules small and focused. If a module exceeds ~200 lines, consider splitting.

### Testing

- **Egress guard** (`conftest.py`): An independent audit hook that uses `AllowPolicy` to block unexpected network access between tests (when tethered is deactivated). Only `dns.google` and localhost are allowed. When tethered IS active, its own hook handles enforcement and the guard is a no-op.
- **Unit tests** (`test_policy.py`): Test `AllowPolicy` in isolation. No audit hooks, no network calls. This is where the bulk of pattern-matching coverage lives.
- **Integration tests** (`test_core.py`): Test `activate()`/`deactivate()` with real sockets (sync and async). Use the `_cleanup` autouse fixture that calls `_reset_state()` after each test. Async tests use `pytest-asyncio` with `asyncio_mode = "auto"`.
- Run tests with: `uv run pytest tests/ -v`
- Run with coverage: `uv run pytest tests/ -v --cov`
- Tests must not depend on external network availability for correctness. Use known IPs, localhost, and `settimeout()` to handle network-level failures gracefully.

### Linting and formatting

- Ruff handles linting and formatting. Configuration is in `pyproject.toml` under `[tool.ruff]`.
- Bandit handles security scanning. Configuration is in `pyproject.toml` under `[tool.bandit]`. Tests are excluded. Intentional suppressions use inline `# nosec BXXX` comments.
- Lint: `uv run ruff check .` (auto-fix with `--fix`)
- Format: `uv run ruff format .`
- Security: `uv run bandit -c pyproject.toml -r src/`
- Pre-commit hooks run ruff, bandit, and markdownlint on every commit, and commitizen on commit messages. Tests run in CI only (not in pre-commit) to avoid conflicts with `uv.lock` during version bumps. All hooks are pinned by commit SHA for supply-chain integrity. Install with `uv run pre-commit install --hook-type pre-commit --hook-type commit-msg`.
- CI runs `pre-commit run --all-files` (lint job) and the full test matrix. GitHub Actions are pinned by commit SHA. The workflow uses `permissions: { contents: read }` for least privilege. A separate CodeQL workflow runs on push to main, on PRs, and weekly.

### What NOT to do

- Do not add runtime dependencies. This library must remain zero-dep.
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

### Python version support

- Python 3.10–3.14. `sys.addaudithook` was added in 3.8, so this is well within range.
- Do not use syntax or features unavailable in 3.10 (e.g., no `type` statement from 3.12, no `except*` from 3.11).
