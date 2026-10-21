# Contributing to tethered

## Setup

**Prerequisites:** Python 3.11+, a C compiler, [uv](https://docs.astral.sh/uv/), Docker (for the `cppcheck` pre-commit hook and for the container suites), and [Node.js](https://nodejs.org/) 22 or later for the development tools that `package.json` lists: the Markdown linter of the pre-commit hooks, the stylesheet of the README preview and the agents' browser. None of them is part of the package, and none runs a script when it is installed (`ignore-scripts` in `.npmrc`).

```bash
git clone https://github.com/shcherbak-ai/tethered.git
cd tethered
uv sync
npm ci
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
```

`uv sync` builds the environment on the Python that `.python-version` names (3.14), and downloads it if the machine has none. That is the interpreter for development; tethered supports 3.11 to 3.15, and CI tests every one of them. To run the tests on another version without rebuilding that environment:

```bash
uv run --isolated --python 3.12 pytest tests/ -n 8
```

## Branching

The default branch is `main`. All pull requests should target `dev`. The `main` branch is for releases only — `dev` is the working branch.

```text
feature-branch → dev (PR) → main (release merge)
```

## Running tests

Core tests (unit + integration, some tests skip if DNS is unavailable). `-n 8` runs them in parallel with [pytest-xdist](https://pytest-xdist.readthedocs.io/), in eight worker processes; more workers do not make the run shorter. CI passes `-n auto`, one worker per CPU of its runner.

```bash
uv run pytest tests/ -n 8
```

Without `-n` the tests run in one process, which is what a debugger and `-s` need:

```bash
uv run pytest tests/test_policy.py -v
```

With coverage (100% is required — the command will fail if coverage drops below that):

```bash
uv run pytest tests/ -n 8 --cov
```

Example tests (run each example script as a subprocess, requires network):

```bash
uv run pytest tests_examples/ -v
```

Container suites (real servers, task queues and client libraries in Docker, on every supported Python version; requires Docker with Linux containers):

```bash
# Everything: every suite on every supported Python version.
uv run python tests_containers/run.py

# One suite, one Python version.
uv run python tests_containers/run.py --suite uvicorn --python 3.13

# Only the tests whose name matches, with the full output of every run.
uv run python tests_containers/run.py --suite gunicorn -k reload --verbose

# What is there to run?
uv run python tests_containers/run.py --list
```

**Run the container suites before merging a change to `src/tethered/_core.py`, `src/tethered/_autoactivate.py`, `src/tethered/_guardian.c`, `src/tethered.pth` or `setup.py`.** The unit tests drive tethered from inside one pytest process; whether a policy survives a server's forks, reloads and choice of event loop only shows under the server. CI runs these suites on every pull request that touches `src/`, `setup.py`, `pyproject.toml` or `tests_containers/`, and weekly, on one Python version, against the latest release of a week ago of every server. They are not collected by `uv run pytest tests/` and are not part of the coverage figure. [tests_containers/AGENTS.md](tests_containers/AGENTS.md) explains how they work and how to add a suite.

## Linting and formatting

Pre-commit hooks run all checks automatically on every commit, but you can also run them manually. The Python tools (ruff, bandit, ty, interrogate, deptry, commitizen, and the checks of whitespace, YAML and TOML) run from the project environment, so a hook and the matching command below always use the same version, the one pinned in `uv.lock`; markdownlint-cli2 runs in the version of `package-lock.json`, which `npm ci` installs. No hook is installed by pre-commit itself, which would resolve its dependencies afresh, past the cooldown described below:

```bash
uv run pre-commit run --all-files
```

Individual tools:

```bash
uv run ruff check .        # lint
uv run ruff check --fix .  # lint with auto-fix
uv run ruff format .       # format
uv run ty check src/ examples/   # type check
uv run interrogate src/ -v # docstring coverage
uv run bandit -c pyproject.toml -r src/  # security scan
uv run deptry .            # imports against declared dependencies
uv lock --check            # uv.lock matches pyproject.toml
uv run python scripts/check_advisories.py  # the one-week cooldown is set, and osv.dev has no advisory of a locked version
node --test .claude/hooks/playwright-files.test.mjs  # the Claude Code hook that keeps the agents' browser files in one folder
```

A release enters the lockfiles only a week after its upload, when a compromised one has been found and removed: `[tool.uv] exclude-newer = "7 days"` in `pyproject.toml` holds back `uv.lock` and the build requirements of `uv build`, and `min-release-age=7` in `.npmrc` holds back `package-lock.json`. The `advisories` hook checks both settings and asks [osv.dev](https://osv.dev) for the advisories of each version that `uv.lock`, `package-lock.json` and `.github/docs-constraints.txt` hold, and fails on a known vulnerability or a report of a malicious package, but for those listed with their reasons in `ACCEPTED_ADVISORIES` in [scripts/check_advisories.py](scripts/check_advisories.py). An advisory can come out at any time, so the hook can fail on a change that touches no dependency: commit with `SKIP=advisories` in front of the command, and the maintainer upgrades the dependency. CI skips it, as its result depends on the day.

The licences of the package's dependencies are checked in CI (`.github/workflows/licenseal.yml`), with [licenseal](https://github.com/shcherbak-ai/licenseal). tethered has none, so the check passes with nothing to judge. To run it locally:

```bash
uv run licenseal check --exclude-dirs tests_containers,benchmarks/dns_lookups
```

The two directories hold what the container suites and the DNS benchmark install into their Docker images, which tethered neither depends on nor ships.

## Documentation

The user documentation is a site built from the Markdown pages under `docs/` with [Zensical](https://zensical.org/) (`zensical.toml`), and published to <https://tethered.shcherbak.ai/> from `main`.

```bash
uv run inv docs-live   # preview at http://localhost:9000, rebuilt when a page changes (--port N for another port)
uv run inv docs        # what CI runs: fails on a broken link or anchor
```

Both are [Invoke](https://www.pyinvoke.org/) tasks in `tasks.py`; `uv run inv --list` lists them. They run Zensical with `uvx`, as a tool at the versions pinned in `.github/docs-constraints.txt`. It is not a dependency of the package.

- Write GitHub-flavoured Markdown, with relative links between pages (`COOKBOOK.md#gunicorn`) and absolute GitHub URLs for files outside `docs/`.
- Indent what belongs to a list item (a nested item, a further paragraph, a code block) by four spaces, and put a blank line before the item that follows such a paragraph or code block. GitHub reads two spaces the same way; the site does not.
- A page begins with front matter: a `title` and a `description` of one sentence, which is the page's meta description on the site and its line in `llms.txt`.
- A new page goes into the `nav` list of `zensical.toml`, and into a section of the `llms.txt` index in the same file (`[project.plugins.llmstxt.sections]`), at the same place and with the `description` of its front matter; a test fails until the two agree. The build writes that index to the root of the site, <https://tethered.shcherbak.ai/llms.txt>, for language models and coding agents.
- `docs/index.md` and `docs/quickstart.md` repeat the README's pitch and quick start. Change them together.
- The footer of the site names the version, in the `copyright` line of `zensical.toml`. `cz bump` rewrites it with the other version fields; do not edit it by hand.

### README and package description

`README.md` is what GitHub shows. Link to a page of the documentation at its address on the site (`https://tethered.shcherbak.ai/API/`); the site describes the last release, so a page or a heading that is new on `dev` is not there yet. Use relative paths for images and for other files of the repository (`docs/assets/tethered-mark.svg`, `examples/`): they work in a local preview and follow the branch being viewed. Badges, GitHub service pages such as Actions, and other sites keep absolute URLs.

`assets/tethered-separator.svg` is the pixel rule between the README's main parts: the mark's kite at rest, with the first steps of its tether, between dashes in the mark's orange, shaded as the mark is. It is pixel art of 222 by 14 pixels, one path of rectangles per colour. Show it at twice that size (`width="444"`) with an empty `alt`, and keep section headings as text, so that their anchors, GitHub's outline and page search keep working. When the mark's kite changes, draw the rule again from it.

The README's last section shows the pixel names of the sibling projects. `assets/contextgem-wordmark.svg` and `assets/licenseal-wordmark.svg` are the README's own images, not part of the site: each is the name drawn at twice its size in a transparent image of one size (336 by 80), so that the two share a baseline. Show them at that width. They are copies of the files licenseal and ContextGem keep under the same names.

Look at a change as GitHub will show it before pushing it. `uv run inv readme-preview` serves `README.md` in GitHub's light theme at <http://127.0.0.1:9110/> and in its dark theme at <http://127.0.0.1:9111/> (`--port N` serves them at N and N+1):

- The HTML is what GitHub's Markdown API returns for the file, so what GitHub removes from a README is removed here too.
- The look comes from github-markdown-css, in GitHub's colours, each page in its theme whatever the browser is set to. The column is as wide as GitHub's at 1280 pixels and wider, and below 768.
- A reload sends the README to GitHub again when it has changed, once for both pages. GitHub allows 60 of those an hour without a token.

The picture that a link to the repository is shown with on other sites is `social/github-social-preview.png`. It is drawn in the SVG beside it as the game's share card from shcherbak.ai: the duck at work by a path in pixel art and a gate shut across it, and on paper the mark, the README's heading, the tagline's claims and the company's name. When one of those changes, change the SVG with it, render the picture again with `uv run inv social-preview` (the task needs Chrome, Edge or Chromium; it also writes `docs/assets/social-preview.png`, the picture a link to the documentation site shows) and say so in the pull request: GitHub reads no file for the social preview, so a maintainer uploads the picture in the repository's settings.

The package description on PyPI is [PYPI.md](PYPI.md) (`project.readme` in `pyproject.toml`). Keep it short and without images, use absolute HTTPS links, and update it when the summary, the install command or the limits change.

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/) enforced by [commitizen](https://commitizen-tools.github.io/commitizen/). The commit-msg hook validates every commit message automatically. Run `uv run cz commit` for an interactive session that guides you through the format.

## Project structure

```text
src/tethered/
    __init__.py           # Public API: activate, deactivate, scope, EgressBlocked, TetheredLocked, SubprocessBlocked
    _policy.py            # AllowPolicy — pattern parsing and matching (pure logic)
    _core.py              # Audit hook, scope, subprocess propagation, state management, IP-to-hostname, refused imports (uvloop, pycares)
    _autoactivate.py      # Child-process bootstrap — reads _TETHERED_CHILD_POLICY and re-activates
    _guardian.c           # C extension — integrity verifier for tamper-resistant locked mode
    _guardian.pyi         # Type stub for the C extension
src/tethered.pth          # Auto-imported by site.py — runs _autoactivate in every Python interpreter
setup.py                  # Build config: C extension + tethered.pth packaging (setuptools)
scripts/
    cppcheck.sh           # Docker-based cppcheck runner for pre-commit
    check_advisories.py   # Pre-commit check: the one-week cooldown, and the advisories of the locked versions
    wheel_smoke_test.py   # Post-build smoke test invoked by cibuildwheel
tests/
    conftest.py           # Test-suite egress guard + .pth installer for editable installs
    test_policy.py        # Unit tests for AllowPolicy (no network)
    test_policy_properties.py  # Hypothesis property tests for rule parsing and matching
    test_core.py          # Integration tests with real sockets (sync, async, scopes)
    test_exceptions.py    # Pickling/copying of the exceptions, including through worker pools
    test_lifecycle.py     # activate()/deactivate() transitions, concurrency, oversized policies, hook installation
    test_subinterpreters.py  # Real subinterpreters under locked, log-only and unlocked policies
    test_subprocess.py    # Subprocess audit, scope propagation, locked-mode integrity, perf
    test_autoactivate.py  # Child-side bootstrap parsing + scope inheritance
    test_guardian.py      # C extension tamper detection
    test_docs_recipes.py  # The recipes docs/COOKBOOK.md prints against the copies the container suites run
    test_docs_site.py     # The version in the site's footer against the package version
    test_llms_index.py    # The llms.txt index against nav and the description each page gives itself
    test_changelog.py     # The compare link of every changelog version, and the version and date in CITATION.cff
tests_examples/
    conftest.py           # .pth installer for editable installs (same as tests/)
    test_examples.py      # Runs each example/ script as a subprocess (requires network)
tests_containers/
    run.py                # Host runner: one image per suite and Python version, each run in a container without a network
    AGENTS.md             # How the suites work, the helpers, adding a suite
    images/               # The Dockerfile: tethered built as a wheel and installed like a user's
    harness/              # Shared in-container code: pytest plugin, the destinations that count arrivals, probe applications
    suites/<name>/        # One directory per server, task queue or library family
benchmarks/
    overhead.py           # Standalone microbenchmark of the per-event overhead (not part of the test suite)
examples/
    README.md             # The list of the examples and how to run them
    01_basic_activate.py ... 12_scope_subprocess.py  # Runnable usage examples
docs/                     # The pages of the documentation site
    index.md, quickstart.md  # The site's home page and quick start
    API.md, ARCHITECTURE.md, COOKBOOK.md, SUBPROCESS.md  # Detailed reference
    COMPATIBILITY.md      # What was measured under which server, task queue and client library
    migrating-to-v1.md    # The 1.0.0 migration guide: the changelog's breaking changes by what a deployment uses
    security.md           # The security model (SECURITY.md at the root says how to report a vulnerability)
    changelog.md          # CHANGELOG.md, included as a page of the site
    robots.txt            # Points search engines to the site's sitemap
    assets/, stylesheets/ # The images of the site and the README, the site's share image, and the site's look
assets/                   # The README's own images: the pixel rule between its parts and the pixel names of the sibling projects
social/                   # The repository's social preview: the SVG it is drawn in and the PNG that is uploaded to GitHub
zensical.toml             # The documentation site: navigation, theme, the footer with the version, Markdown extensions, the llms.txt index
overrides/main.html       # The site's page template: the title, description and picture a link to a page shows on other sites
tasks.py                  # Invoke tasks: docs, docs-live, readme-preview, social-preview
package.json              # Development tools from npm, not part of the package: the agents' browser, the README preview's stylesheet, the Markdown linter
.npmrc                    # A release enters package-lock.json a week after its publication; no install scripts
.mcp.json                 # Starts the agents' browser (Playwright MCP)
.claude/                  # Claude Code's shared settings and the hook that keeps the browser's files in .playwright-mcp/
.python-version           # The Python that uv builds the development environment on
README.md                 # What GitHub shows: pitch, quick start, pointers
PYPI.md                   # The package description PyPI shows
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

## C extension

The `_guardian.c` C extension provides tamper-resistant locked mode. It is built automatically by `setuptools` during `uv sync`. A C compiler is required — the build will fail without one.

Importing tethered does not load the extension: `activate()`, `deactivate()` and the startup bootstrap load it (`_load_guardian()` in `_core.py`). `tests/conftest.py` loads it when the tests start, so a test that is about the loading resets that state or runs in a fresh process, and a script a test runs in another process or interpreter calls `_load_guardian()` before it reads `_c_guardian` there.

### cppcheck

C static analysis runs via Docker in pre-commit. Requires Docker installed and running:

```bash
uv run pre-commit run cppcheck --all-files
```

On first run, a `tethered-cppcheck:<version>` Docker image is built, with cppcheck compiled from the upstream source at the release `scripts/cppcheck.sh` names (this takes a minute or two). The image is cached by Docker for subsequent runs. CI runs the same hook, so it analyses with the same version. To upgrade cppcheck, change `CPPCHECK_VERSION` and `CPPCHECK_COMMIT` in that script; an image of an earlier version can then be removed with `docker image rm`.

## Code conventions

- Zero runtime dependencies — stdlib only (including the C extension, which uses the CPython C API, the C standard library and a few operating-system calls, and links against no external library).
- `from __future__ import annotations` in all Python modules.
- Private modules prefixed with `_`.
- Type hints on all public functions.
- Python 3.11+ only — no syntax from 3.12+ (`type` statement).

## Testing conventions

- **Policy tests** (`test_policy.py`): Pure logic, no audit hooks, no network. Bulk of pattern-matching coverage lives here.
- **Integration tests** (`test_core.py`): Use real sockets. Sync + async + scope intersection semantics. The `_cleanup` autouse fixture resets internal state, unlocks the C guardian (with the token a session fixture records from `tethered.activate`), and clears `_TETHERED_CHILD_POLICY` between tests. The conftest egress guard can raise `EgressBlocked` on tethered's behalf in a thread where no tethered state is visible, so a test that expects a block from a scope should assert `scope_label`.
- **Subprocess tests** (`test_subprocess.py`): `external_subprocess_policy` enforcement, locked-mode payload-integrity check, scope-to-subprocess propagation (round-trip, multi-thread, locked + scope), frame-locals helper unit tests, Windows command-line parser tests, locked-mode `tethered.pth` FS-tamper hook, and microbenchmarks bounding the audit-hook helpers' per-call cost.
- **Autoactivate tests** (`test_autoactivate.py`): Direct unit tests for `_autoactivate_from_env()` plus end-to-end integration tests that spawn real Python subprocesses to verify the `.pth` bootstrap chain and scope inheritance.
- **Guardian tests** (`test_guardian.py`): C extension tamper detection — replaces `_config`, monkey-patches `is_allowed`, mutates frozen-dataclass slots via `object.__setattr__`, replaces helper functions; all should fail-closed. One test fails when a new module-level name in `_core.py` or `_policy.py` is neither covered by the integrity snapshot nor on its allowlist of runtime state: name constants in UPPER_CASE, keep runtime flags and counters as lower-case scalars and add them to that allowlist, and never rebind other module-level objects at runtime (the one exception is `_load_guardian()`, which binds the extension before any policy can be locked).
- **Exception tests** (`test_exceptions.py`) and **lifecycle tests** (`test_lifecycle.py`): pickling and copying of `EgressBlocked` / `SubprocessBlocked` (including real spawn-mode pools), and `activate()` / `deactivate()` transitions under interleaving and failure.
- **Example tests** (`tests_examples/test_examples.py`): Run each `examples/*.py` script as a subprocess. Requires network (examples make real HTTP calls to `api.github.com`). Not included in coverage — they run in separate processes.
- **Container suites** (`tests_containers/suites/<name>/`): A suite starts a real server, task queue or client library in a container that has no network, with tethered installed from a wheel. Destinations on the container's loopback interface count what arrives, and a test asserts both what the application reported and what arrived: "blocked" means that the counter did not move. A known limit is pinned as what happens today, in a test whose docstring starts with `Limit:`. Every requirement is pinned; a suite is added by adding its directory. `docs/COMPATIBILITY.md` is written from these suites: when a result changes, change the page with it.
- **Documentation that is tested.** The code and configuration blocks of `docs/COOKBOOK.md` are meant to work as printed. Run a block in a container before you change it, or take it from a suite where it already runs. The FastAPI recipe and the Django middleware have a copy in their suite (`tests_containers/suites/fastapi/cookbook_recipe.py`, `tests_containers/suites/django/djapp/`): change the copy with the block and run the suite. `tests/test_docs_recipes.py` fails when a copy and its block differ.
- Core tests that need DNS resolution are marked `@requires_network` and skip automatically if DNS is unavailable. The majority of core tests run fully offline.
- Blocked connection tests verify `EgressBlocked` is raised before the connection is opened.
- **Tests run in parallel.** CI runs `tests/` with `-n auto`, so a test has to pass in whichever worker process it lands, beside tests that run at the same time. The workers share no tethered state, but they share the file system: write below `tmp_path` only, bind port 0, and do not rely on another test having run first in the same process. What has to be in site-packages for the whole run (`tethered.pth`) is installed once by the `pytest_configure` hook in `tests/conftest.py`, not by a session fixture, which every worker would run for itself.
