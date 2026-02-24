# Contributing to Tethered

## Setup

```bash
git clone https://github.com/shcherbak-ai/tethered.git
cd tethered
uv sync
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
```

## Branching

The default branch is `dev`. All pull requests should target `dev`.
The `main` branch is for releases only.

```text
feature-branch → dev (PR) → main (release merge)
```

## Running tests

```bash
uv run pytest tests/ -v
```

With coverage:

```bash
uv run pytest tests/ -v --cov
```

## Linting and formatting

Pre-commit hooks run all checks automatically on every commit, but you can also run them manually:

```bash
uv run pre-commit run --all-files
```

Individual tools:

```bash
uv run ruff check .        # lint
uv run ruff check --fix .  # lint with auto-fix
uv run ruff format .       # format
uv run bandit -c pyproject.toml -r src/  # security scan
```

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/) enforced by [commitizen](https://commitizen-tools.github.io/commitizen/). The commit-msg hook validates every commit message automatically. Run `uv run cz commit` for an interactive session that guides you through the format.

## Project structure

```text
src/tethered/
    __init__.py    # Public API: activate(), deactivate(), EgressBlocked
    _policy.py     # AllowPolicy — pattern parsing and matching (pure logic)
    _core.py       # Audit hook, state management, IP-to-hostname resolution
tests/
    test_policy.py  # Unit tests for AllowPolicy (no network)
    test_core.py    # Integration tests with real sockets
```

## Network safety in tests

### IP addresses

Use only reserved, unroutable ranges for IP addresses in tests:

| Range | Name | RFC |
|---|---|---|
| `192.0.2.0/24` | TEST-NET-1 | RFC 5737 |
| `198.51.100.0/24` | TEST-NET-2 | RFC 5737 |
| `203.0.113.0/24` | TEST-NET-3 | RFC 5737 |
| `2001:db8::/32` | Documentation IPv6 | RFC 3849 |
| `127.0.0.0/8`, `::1` | Loopback | — |

Never use real, routable IPs (e.g., `8.8.8.8`, `93.184.215.14`). Even in "allow" tests, TEST-NET addresses ensure no packets reach real servers.

### Hostnames

Some integration tests need real DNS resolution to verify that allowed hostnames pass through correctly. Use `dns.google` or `localhost` for this. These are the only real hostnames permitted in tests — they perform only a harmless DNS lookup, no application-level connection is made.

Never use hostnames that could trigger unexpected connections to services with side effects (e.g., API endpoints, webhook URLs).

## Code conventions

- Zero runtime dependencies — stdlib only.
- `from __future__ import annotations` in all modules.
- Private modules prefixed with `_`.
- Type hints on all public functions.
- Python 3.10+ only — no syntax from 3.12+ (`type` statement) or 3.11+ (`except*`).

## Testing conventions

- **Policy tests** (`test_policy.py`): Pure logic, no audit hooks, no network. Bulk of coverage lives here.
- **Integration tests** (`test_core.py`): Use real sockets. The `_cleanup` autouse fixture calls `_reset_state()` after each test.
- Tests must not depend on external network availability for correctness.
- Blocked connection tests verify `EgressBlocked` is raised before any packet leaves the machine.
