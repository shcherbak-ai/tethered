# Container tests

Real application servers, task queues and client libraries, in Docker, on every supported Python version, with tethered installed the way a user installs it. The unit and integration tests in `tests/` drive tethered from inside one pytest process; these suites start what people deploy (uvicorn, gunicorn, hypercorn, granian, uWSGI, Apache with mod_wsgi, Celery and the other task queues, some seventy client-library arrangements; `run.py --list` has them all), let the servers fork, spawn, recycle and reload their workers, and check from the outside that the policy holds in every process. [`docs/COMPATIBILITY.md`](../docs/COMPATIBILITY.md) is written from their results.

**The gating rule.** Run the container suites before merging a change to `src/tethered/_core.py`, `src/tethered/_autoactivate.py`, `src/tethered/_guardian.c`, `src/tethered.pth` or `setup.py`. CI runs them on every pull request that touches `src/`, `setup.py`, `pyproject.toml` or this directory (`.github/workflows/container-tests.yml`).

These suites are not collected by `uv run pytest tests/`, are not part of the coverage figure, and cannot run outside their containers.

## Prerequisites

- Docker with BuildKit (Docker Desktop on Windows and macOS, Docker Engine 23 or later on Linux), running, with Linux containers.
- Python 3.11 or later for the runner. It uses the standard library only, so `uv run python`, a system `python3` or the project's virtual environment all do.
- Network access while images are built (base images, PyPI, Debian packages). The tests themselves run with no network.

## Quick start

Run these from the repository root.

```bash
# Everything: every suite on every supported Python version.
uv run python tests_containers/run.py

# One suite, one Python version.
uv run python tests_containers/run.py --suite uvicorn --python 3.13

# Only the tests whose name matches (pytest's -k), with the full output of every run.
uv run python tests_containers/run.py --suite gunicorn -k reload --verbose

# What is there to run?
uv run python tests_containers/run.py --list
```

| Option | Meaning |
| --- | --- |
| `--python X.Y` | A Python version; repeatable. Default: every supported version (3.11 to 3.15). |
| `--suite NAME` | A suite; repeatable. Default: every suite. |
| `-k EXPR` | Passed to pytest in the container. A suite in which nothing matches counts as passed ("no tests"). |
| `--jobs N` | How many suite and Python combinations build and run at once. Default: half the CPUs, at most 4. |
| `--unpinned` | Install the latest release of every requirement instead of the pinned one. The images are tagged `...-unpinned` and are refreshed at most once a day; add `--no-cache` to force it. |
| `--list` | List the suites and stop. With `--json`: the matrix CI uses. |
| `--logs DIR` | Write the full output of every run (build and tests) to `DIR/<suite>-py<X.Y>.log`. |
| `--no-cache` | Build the images without Docker's cache. |
| `--timeout SECONDS` | Kill a container that has not finished by then. Default: 1800. |
| `-v`, `--verbose` | Print the output of passing runs too. A failing run is always printed in full. |
| `-- ARGS` | Everything after `--` goes to pytest in the container, for example `-- -x --durations=0`. |

The exit status is 0 when every run passed, 1 when one failed, 2 when the request could not be carried out (Docker is not available, an unknown suite or Python version) and 130 after Ctrl-C. The run ends with a table:

```text
suite     python   result  passed  failed  errors  skipped  build  tests  versions
--------  -------  ------  ------  ------  ------  -------  -----  -----  ---------------
gunicorn  3.13.16  passed      73       0       0        0    1 s   29 s  gunicorn 26.2.0
uvicorn   3.13.16  passed     130       0       0        0    1 s   27 s  uvicorn 0.54.0
tethered 0.5.3, built from the working tree
all 2 passed in 31 s
```

`build` is the time to build (or find in the cache) the image, `tests` the time of the container, and `versions` the suite's `key_packages` as they are installed in the image. The container is started from the id of the image that was just built, so two checkouts that run the same suite at the same time do not get each other's image.

## How it works

```text
host:       tests_containers/run.py
              docker build -f tests_containers/images/base.Dockerfile  (context: the repository root)
              docker run --rm --init --network none --cap-add NET_ADMIN <image> [pytest arguments]

container:  python -m harness                the entry point: runs pytest on /tc/suites/<suite>
              the world                      a process of its own: listeners, counters, DNS
              pytest                         holds no policy, never imports tethered
                start_server(...)            a server under test: tethered is active in here
                  workers, children          and in here
```

**The host runner** (`run.py`) finds the suites by listing `suites/`, builds one image per suite and Python version, runs each in a container and reads the result from the last lines of its output. It mounts nothing: the working tree reaches the image through the build context, which `images/base.Dockerfile.dockerignore` cuts down to `src/`, the packaging files and this directory. The mapping from a Python version to its base image is `PYTHON_IMAGE_TAGS` at the top of `run.py`, and nowhere else.

**The image** (`images/base.Dockerfile`) has two stages. The builder, on the full `python:X.Y` image, builds a wheel of tethered from the working tree (`pip wheel . --no-deps`). The runtime stage, on `python:X.Y-slim`, installs pytest, the suite's requirements and then the wheel, as a regular install, so that `tethered.pth` is in site-packages as it is for a user. The build fails if `tethered.pth` is missing or `tethered._guardian` does not import (`images/verify_install.py`). `pip freeze` is saved as `/tc/pip-freeze.txt`. In the image, this directory is `/tc`: `/tc/harness` and `/tc/suites/<suite>`.

**pytest runs inside the container** and the tests are ordinary pytest tests. The pytest process never holds a tethered policy; the plugin refuses to start if it does. tethered is active only in the processes under test, which the helpers start with a clean environment.

**The world** is what a process under test can try to reach. The container has no network at all (`--network none`). A session fixture adds two addresses to the loopback interface (which is what `NET_ADMIN` is for), writes the two names to `/etc/hosts`, points `/etc/resolv.conf` at 127.0.0.1 and starts `harness/world.py` as a process of its own:

| Name | Address | Role |
| --- | --- | --- |
| `allowed.test` | `10.77.0.10` | The probe applications allow `allowed.test:9001`. |
| `forbidden.test` | `10.77.0.20` | Never allowed. |
| (none) | `127.0.0.1` | Loopback, which tethered allows by default. |

On each address, ports 9001 to 9003 have a TCP listener that answers with a minimal HTTP response and a UDP listener that answers with one datagram. The destinations are deliberately not in `127.0.0.0/8`: tethered allows loopback unless told otherwise. A minimal DNS responder on `127.0.0.1:53` answers A queries for the two names, gives an empty answer for AAAA and NXDOMAIN for anything else, for client libraries that do not read `/etc/hosts`.

The world counts every accepted connection and every received datagram per address, port and protocol. **Those counters are the ground truth.** "Blocked" means that the counter of the destination did not move, not only that the application reported an exception; "allowed" means that it did move. Assert both, the report and the counter: an application can swallow an exception, and a client library can retry over another route. The counting is done in one thread, which first handles everything that is already waiting on the listeners when it is asked for the counters, so a connection that was established before the question is in the answer and tests need no settling time.

## Layout

```text
tests_containers/
    run.py                    the host runner
    conftest.py               stops a pytest that is pointed at this directory on the host
    images/
        base.Dockerfile       the image every suite uses so far
        base.Dockerfile.dockerignore
        verify_install.py     run during the build
    harness/                  shared in-container code, copied into every image
        __main__.py           the entry point of the image
        plugin.py             the pytest plugin: the world fixture, teardown, logs on failure
        helpers.py            constants, the world's counters, HTTP
        servers.py            start_server and run_python: the processes under test
        scopes.py             checks of tethered.scope() that suites run against their own servers
        world.py              the destinations
        requirements.txt      pytest, pinned
        apps/                 the shared applications under test
            probe_asgi.py     ASGI probe application
            probe_wsgi.py     WSGI probe application
            probe_common.py   activation from the environment, reports, launches
            probe_child.py    the Python child a probe application launches
            run_under_policy.py   what run_python() starts
    suites/
        <name>/
            suite.toml        description, image, system packages, Python versions
            requirements.txt  pinned
            test_*.py
            ...               applications and scripts of this suite only
```

`run.py --list` prints the suites with the one-line description from each `suite.toml`, and the docstring at the top of a suite's test module says what it covers and what it leaves to others. There is deliberately no table of suites in this file: a suite is added by adding its directory, and nothing else has to change.

`selftest` is the harness testing itself, with no server framework: the world's counters and DNS responder, `start_server` and its stop check, `run_python`. Run it first when a change to `harness/` misbehaves.

## Writing tests

A test module imports what it needs from `harness`; the fixtures come from the plugin (`harness/plugin.py`), so a suite needs no `conftest.py`.

```python
from harness import ALLOWED_NAME, ALLOWED_PORT, FORBIDDEN_NAME, OTHER_PORT, arrivals, start_server


def test_the_forbidden_destination_is_refused():
    server = start_server(
        ["gunicorn", "probe_wsgi:application", "--bind", "127.0.0.1:{port}"],
        env={"TETH_ACTIVATE": "locked"},
    )
    report = server.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
    assert report["outcome"] == "blocked", report      # what the application saw
    assert arrivals() == {}                            # what really happened

    report = server.probe("connect", ALLOWED_NAME, ALLOWED_PORT)
    assert report["outcome"] == "reached", report
    assert arrivals() == {"10.77.0.10:9001/tcp": 1}
```

The server is stopped, and its stop is checked, when the test ends. If the test fails, the server's log is in the report.

### The helpers

| Name | What it is |
| --- | --- |
| `ALLOWED_NAME`, `ALLOWED_ADDR` | `allowed.test`, `10.77.0.10`. |
| `FORBIDDEN_NAME`, `FORBIDDEN_ADDR` | `forbidden.test`, `10.77.0.20`. |
| `LOOPBACK_ADDR` | `127.0.0.1`, which has the same listeners. |
| `ALLOWED_PORT`, `OTHER_PORT`, `PORTS` | 9001 (the port the probe applications allow), 9002 (a port no rule allows), and all three ports the world listens on. |
| `world` | The session fixture that prepares the network and runs the world. It is autouse: a test does not have to ask for it. |
| `arrivals()` | Everything that arrived since the last reset, as `{"10.77.0.20:9002/tcp": 1}`. Destinations nothing reached are absent, so `arrivals() == {}` reads "nothing left the process". |
| `arrived(name_or_address, port, proto="tcp")` | The count for one destination. A destination the world does not have raises `ValueError`, so that a typing mistake cannot pass as "nothing arrived". |
| `dns_queries()` | Queries the DNS responder received, as `{"allowed.test/A": 1}`. |
| `reset_arrivals()` | Sets every counter to zero. The harness does this before each test. |
| `start_server(argv, env=None, ready="/whoami", timeout=30, cwd=None)` | Starts a server and waits until it answers. Returns a `Server`. See below. |
| `http_get(url, timeout=30)` | A GET with the standard library, ignoring proxy settings. Returns a `Response` (`status`, `headers`, `body`, `text`, `json()`); an HTTP error status is a response, not an exception. No response at all raises `OSError`. |
| `run_python(source, activate="plain", esp=None, env=None, args=(), timeout=60)` | Runs Python source in a fresh interpreter in which tethered is already active as `activate` says (the values of `TETH_ACTIVATE` below). Returns `returncode`, `stdout`, `stderr` and `json()` (the last line of stdout). For client libraries and one-shot scripts that need no server. |
| `probe_path(op, host, port, **params)` | The path of one probe request: `/connect?host=forbidden.test&port=9002`. |
| `APPS_DIR`, `SUITE_DIR` | Where the shared applications and the suite's own files are in the image. Both are on `PYTHONPATH` of everything the helpers start. |

`start_server` replaces `{port}` in the command with a free port on 127.0.0.1 (also `PORT` in the server's environment). The environment is the container's without the tethered policy variable; `env` is added to it. `ready` is a path that is polled until the server answers with a status below 500, or a function of the `Server`. The server runs in the suite directory unless `cwd` says otherwise.

| `Server` | What it is |
| --- | --- |
| `url`, `port` | The base URL (`http://127.0.0.1:<port>`) and its port. |
| `pid` | The process that was started: a master or supervisor, or the only process. |
| `pids()` | The live processes of the server: that one, its workers, their children. |
| `log` | Everything the server and its children wrote to stdout and stderr so far. |
| `log_of_this_test` | The part of it written since the current test began. |
| `wait_log(pattern, timeout=15)` | Waits until `log_of_this_test` matches a regular expression. |
| `get(path)` | `http_get` on the server. |
| `probe(op, host, port, **params)` | Asks a probe application for one operation and returns its JSON report; anything but HTTP 200 is an `AssertionError`. |
| `each_worker(path, count, exclude=(), timeout=60)` | Requests `path` with overlapping requests until `count` different worker processes have answered; returns `{pid: report}`. With `exclude=<pids seen before>` it waits for replacements. |
| `send_signal(signum, pid=None)` | Signals the started process, or one of its workers. |
| `running`, `returncode` | Whether the started process is still there, and its exit status after `stop()`. |
| `stop(timeout=20, check=True, exit_codes=(0, -SIGTERM))` | Sends SIGTERM and checks that the server stopped cleanly: the started process exited in time with an accepted status and no process of the server is left. Otherwise what is left is killed and `AssertionError` says what went wrong. |

**Servers are always stopped.** A server started in a test body is stopped when that test is torn down; one started in a fixture is stopped with that fixture, whatever its scope, so a module or class fixture that returns `start_server(...)` needs no `yield` and no cleanup. The stop check runs then too, and a server that hangs on SIGTERM or leaves a worker behind turns into a teardown error. Call `stop()` yourself only when the test is about stopping, or to read the complete log.

**Logs on failure.** When a test fails, in setup, call or teardown, the report gets the log of every server that was running during it (for a long-lived server, the part written during that test) and the source and output of every `run_python` script. `run.py` prints the output of a failing run in full.

### The probe applications

`harness/apps/probe_wsgi.py` (`probe_wsgi:application`) and `harness/apps/probe_asgi.py` (`probe_asgi:app`) are framework-free. Each request performs exactly one outbound operation and reports it as JSON. They are importable in every server the helpers start.

The application activates tethered when it is imported, as the environment says:

| Variable | Values |
| --- | --- |
| `TETH_ACTIVATE` (required) | `none` (tethered is not imported at all), `plain`, `locked`, `fail_closed`, `log_only`; several can be joined with commas (`locked,fail_closed`). |
| `TETH_ESP` | `external_subprocess_policy`: `warn` (the default), `block`, `allow`. |
| `TETH_ALLOW` | The allow list, comma-separated. Default: `allowed.test:9001`. |

Every route but `/whoami` takes `host` and `port`.

| Route | Application | The one operation |
| --- | --- | --- |
| `/connect` | both | A blocking socket connection (in the event loop itself, under ASGI). |
| `/urllib` | WSGI | A request with `urllib.request`. |
| `/open_connection` | ASGI | `asyncio.open_connection`. |
| `/create_connection` | ASGI | `loop.create_connection` with a protocol. |
| `/sock_connect` | ASGI | `loop.sock_connect` on a non-blocking socket. |
| `/getaddrinfo` | ASGI | `loop.getaddrinfo`; no connection. |
| `/datagram_connected` | ASGI | `create_datagram_endpoint(remote_addr=...)` and one datagram. |
| `/datagram_unconnected` | ASGI | `create_datagram_endpoint(local_addr=...)` and `sendto(data, addr)`. |
| `/to_thread` | ASGI | A blocking socket connection in `asyncio.to_thread`. |
| `/run_in_executor` | ASGI | A blocking socket connection in `loop.run_in_executor`. |
| `/thread` | both | A blocking socket connection in a thread started for it. |
| `/child` | both | Launches a Python child that tries `host:port` itself and prints its own report. `how=executable` (the default: `sys.executable`), `clean_env` (an explicit `env=` without the policy variable), `no_site` (`sys.executable -S`), `path_python` (`python3` from `PATH`). |
| `/tool` | both | Launches an external tool (bash) that connects to `host:port` itself. |
| `/whoami` | both | No operation: pid, parent pid, the pid the application was imported in, thread, interpreter id, event loop class, and whether tethered is imported, active, locked. |

Parameters for every route: `uncaught=1` lets the exception of a failed operation reach the server instead of being reported (for "what does the server do with an uncaught `EgressBlocked`"), and `hold=<seconds>` keeps the worker busy before it answers (which is how `each_worker` reaches all of them).

`scope=<rule>,<rule>` runs the operation inside `tethered.scope(allow=[...], label="probe-scope")`; `scope=` with nothing after it is a scope that allows nothing, and `scope_log_only=1` makes the scope log-only. `scope_wait=<seconds>` waits inside the scope before the operation, without blocking the other requests of the process, and the report then says when the scope was entered and left (`scope_entered`, `scope_left`). A refusal that came from a scope has `scope_label` in its report; one from the policy of the process has not. The task probes of the worker suites (`taskprobe.py`) take the same parameters.

`harness/scopes.py` has the checks built on this, for a suite to run against its own server: `narrows(probe, op)`, `cannot_widen(probe, op)`, `overlapping(probe, op)` (two requests at the same time in one process, one inside a scope) and `child_is_held_to_the_scope(probe)`. `probe` is `Server.probe` or anything that takes the same arguments; `scopes.env()` is the environment of a server whose policy leaves a scope something to take away.

A report has the fields of `/whoami` plus:

```json
{
  "op": "connect", "host": "forbidden.test", "port": 9002,
  "outcome": "blocked",
  "exception": "tethered._core.EgressBlocked",
  "message": "Blocked by tethered: forbidden.test is not in the allow list"
}
```

`outcome` is `reached` (the operation was carried out: `reply` holds what the destination answered, or `child` the child's own report), `blocked` (tethered refused it: the exception is `EgressBlocked` or `SubprocessBlocked`, or an exception group that contains one, then described under `refusal`) or `error` (anything else). `notes` says how asyncio delivered an exception that was not raised to the caller.

## Adding a suite

A suite is a directory. Nothing else has to be edited: the runner and CI find it by listing `suites/`.

1. Create `tests_containers/suites/<name>/` with a `suite.toml`:

   ```toml
   description = "one line: which server or library, in which arrangements"

   # tests_containers/images/<image>.Dockerfile
   image = "base"
   # Extra Debian packages for the image, and whether it needs a C compiler.
   apt = []
   compiler = false
   # The packages whose versions the runner prints in its summary.
   key_packages = ["hypercorn"]

   # Python versions the suite does not run on, each with the reason.
   [unsupported_python]
   "3.15" = "no wheel of <package> for 3.15 yet, and it does not build from source"
   ```

2. Add `requirements.txt` with every package pinned by `==`, the packages they depend on included. A package the harness pins too (`harness/requirements.txt`) must have the same pin.
3. Add `test_<something>.py`. Use the shared probe applications where they fit; put applications and scripts that belong to this suite only next to the tests (they are importable, and the suite directory is the working directory of the servers).
4. Say at the top of the test module what the suite covers and what it leaves out.
5. Run it: `uv run python tests_containers/run.py --suite <name>`, then everything once.

Set `compiler = true` only when a requirement has to be built from source; `apt` is for runtime packages such as `apache2`. If a suite needs an image that `base.Dockerfile` cannot give it, add `images/<other>.Dockerfile` with its own `<other>.Dockerfile.dockerignore` and name it in `image`; it receives the same build arguments (`PYTHON_TAG`, `SUITE`, `APT_PACKAGES`, `COMPILER`, `UNPINNED`, `UNPINNED_STAMP`) and must keep the layout under `/tc` and the entry point.

What makes a good test here:

- It names the arrangement on the command line (worker class, event loop, preload) rather than relying on a default, and checks through `/whoami` that it got it.
- It asserts the application's report and the world's counter.
- It asserts on every worker when there are several (`each_worker`), and on workers that were started later.
- A limit that is documented (an external tool is not restricted under `warn`) is asserted as what it is, with the counter that moves; it then also serves as the proof that the counter can move. The docstring of such a test starts with `Limit:`, so that the limits a suite pins can be listed.
- It does not sleep. `wait_log`, `each_worker` and `start_server` wait for a condition.

## Pins

Every requirement is pinned, so that a pull request is tested against the same servers as the one before it. The weekly CI run uses `--unpinned` and tells when the ecosystem has moved.

To bump: run `uv run python tests_containers/run.py --suite <name> --unpinned --verbose`, read what was installed (the line that starts with `installed:` at the top of the container's output is the image's `pip freeze`), write the versions into the suite's `requirements.txt` and run the suite pinned. For pytest it is `harness/requirements.txt`, and then every suite. When a new version changes what tethered has to do, that is a finding: write it down where the behaviour is documented before changing the test. [`docs/COMPATIBILITY.md`](../docs/COMPATIBILITY.md) names the version each of its rows was measured with and the suite behind it, and [`docs/COOKBOOK.md`](../docs/COOKBOOK.md) says what each server needs: a bump that changes a result changes those two pages.

A new Python version is one line in `PYTHON_IMAGE_TAGS` in `run.py`. Before it is released, its tag is that of the pre-release image (`3.16-rc`); change it to the version alone when the release is out.

## CI

`.github/workflows/container-tests.yml` runs one job per suite and Python version, from the matrix that `run.py --list --json` prints. It runs on pull requests that touch `src/`, `setup.py`, `pyproject.toml`, `tests_containers/` or the workflow itself; on demand (`workflow_dispatch`, with an optional Python version, suite and "unpinned"); and every Monday with `--unpinned`, on one Python version only, the one `.python-version` names: what that run looks for, a server or a library that has changed, does not depend on the Python version.

## What a run costs

Measured on a 32-CPU Windows machine with Docker Desktop, base images already pulled, the default `--jobs 4`. This table is from when there were three suites (`selftest`, `uvicorn`, `gunicorn`, the last two smaller than they are now). There are thirty today, and a run of everything has not been timed since: expect a multiple of the first two rows.

| Run | Time |
| --- | --- |
| Everything (3 suites on 5 Python versions, 15 runs), images cached | 2 to 3 minutes |
| The same when every image has to be built | about 4 minutes |
| One run: `selftest` | 11 to 20 s |
| One run: `uvicorn` or `gunicorn`, as they were then | 30 s alone, 30 to 50 s next to three others |
| Building one image without cache | 15 to 30 s |

Single runs measured since, on Python 3.13 with the image cached (the time of the container, as the summary's `tests` column gives it):

| Run | Time |
| --- | --- |
| `waitress` | 4 s |
| `clients_niquests` | 10 s |
| `django` | 25 s |
| `clients` | 68 s |
| `modwsgi` | 2 to 4 minutes, depending on the Python version |

On top of that, the first build for a Python version downloads its two base images (the full one, which the builder stage uses, is about 1.6 GB unpacked). A change under `src/` rebuilds the wheel and the layers after it, a few seconds per Python version; a change to a test or to the harness rebuilds only the last layers. A suite that needs system packages or a compiler (`modwsgi`, `clients`, `uwsgi`) takes longer to build the first time; that was not timed. The time of a CI job has not been measured: the workflow has not run yet.

## Troubleshooting

- **`run.py: Docker is not available`** (exit status 2): Docker is not installed or its daemon is not running.
- **A build fails in `pip wheel`**: the C extension did not compile on that Python version. That is a finding about tethered, not about the harness.
- **A build fails in `pip install -r`**: a pinned version does not exist for that Python version, or two pins disagree. For a new Python version without wheels, add it to `[unsupported_python]` in the suite's `suite.toml` with the reason.
- **`... failed: the container needs --cap-add NET_ADMIN`**: the image was started by hand without the options `run.py` passes.
- **The container suites run inside their image**: someone ran pytest on this directory on the host. Use `run.py`.
- **Looking around in an image**: `docker run --rm -it --network none --cap-add NET_ADMIN --entrypoint bash tethered-ct/<suite>:py3.13`, then `python -m harness -x -k <expression>` in `/tc`. Server logs of the run are in `/tmp/tc-logs`. In Git Bash on Windows prefix the command with `MSYS_NO_PATHCONV=1`.
- **A test hangs**: every server start, stop, request and script has a timeout, and `run.py` kills a container after `--timeout` seconds; the output so far is printed.
- **Disk space**: each suite and Python version is an image of about 220 MB, most of it layers shared with the others. `docker image prune` removes the layers that rebuilding left behind; `docker rmi $(docker images -q "tethered-ct/*")` removes the images.

## Limits

- Linux containers only (glibc, the architecture of the Docker host). Nothing here says anything about Windows or macOS servers, musl, or free-threaded builds.
- The world is on the loopback interface. Traffic never leaves the kernel, so nothing here depends on, or tests, real routing, TLS or DNS over the network.
- A server is followed through its session: `pids()` and the stop check see the process that was started, its workers and their children. A server that daemonizes (starts a session of its own) leaves that view; run servers in the foreground.
- `each_worker` returns the last report of each worker; the reports of the other requests it made are not kept. The world's counters cover all of them.
- The pytest process reads tethered's state through `/whoami`, which looks at `tethered._core._config`: a private attribute, and the one place where the suites depend on tethered's internals.
- The CI workflow can only be exercised on GitHub.
