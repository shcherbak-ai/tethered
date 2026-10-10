"""FastAPI, installed as ``fastapi[standard]`` and served the way its documentation says.

``fastapi run`` and ``uvicorn main:app``, neither with a word about the event
loop: ``fastapi run`` has no option for it, and uvloop is installed, so the
loop is uvloop whenever importing it works.  The application (``main.py``)
activates the policy when it is imported and is otherwise the FastAPI recipe
of ``docs/COOKBOOK.md``, exactly as printed (``cookbook_recipe.py``), with
endpoints that call out through ``httpx``.

What is asserted:

* which loop the application runs on, for each way of starting it.  With a
  path (or nothing) ``fastapi run`` imports the application itself to find
  the ``FastAPI`` object, before it starts uvicorn; with ``--entrypoint`` it
  leaves the import to uvicorn.  That decides where the policy is active
  first, and matters as soon as there are workers;
* that a refused request ends as the HTTP 503 the recipe promises, for the
  three ways a refusal reaches ``httpx.AsyncClient`` (at the lookup, at the
  connection by a port rule, at the connection to a raw address), and that
  nothing arrived in the world; the same for the synchronous client, asyncio
  streams and the ``websockets`` client;
* activation in a lifespan handler instead of at import: under a server and
  under Starlette's ``TestClient``;
* that uvloop is the only compiled module of this installation that asks the
  C library for the network itself.

The uvicorn suite covers uvicorn itself in more arrangements; uvicorn 0.46,
the last release that loads uvloop before the application, is the subject of
``uvicorn_legacy``.
"""

from __future__ import annotations

import json
import re
import signal
import sysconfig
from pathlib import Path
from typing import Any

import pytest
from harness import (
    ALLOWED_ADDR,
    ALLOWED_NAME,
    ALLOWED_PORT,
    FORBIDDEN_ADDR,
    FORBIDDEN_NAME,
    OTHER_PORT,
    Server,
    arrivals,
    probe_path,
    run_python,
    start_server,
)
from native_imports import network_functions
from one_shot import run_to_exit

FASTAPI_RUN = ["fastapi", "run", "--host", "127.0.0.1", "--port", "{port}"]
FASTAPI_RUN_ONCE = ["fastapi", "run", "--host", "127.0.0.1", "--port", "0"]
UVICORN = ["uvicorn", "--host=127.0.0.1", "--port={port}"]
UVICORN_ONCE = ["uvicorn", "--host=127.0.0.1", "--port=0"]

#: The ways of serving ``main.py`` in one process.
SERVED = {
    "fastapi-run-with-a-path": [*FASTAPI_RUN, "main.py"],
    "fastapi-run-discovering-main.py": FASTAPI_RUN,
    "fastapi-run-with-an-entrypoint": [*FASTAPI_RUN, "--entrypoint", "main:app"],
    "uvicorn": [*UVICORN, "main:app"],
}

STANDARD_LOOP = "asyncio.unix_events._UnixSelectorEventLoop"
UVLOOP = "uvloop.Loop"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"

REFUSED_TO_LOAD = "tethered: refused to load uvloop while a policy is active"
ACTIVATE_REFUSED = "RuntimeError: tethered: activate() refused"
UVLOOP_WARNING = "tethered: uvloop is loaded in this process."
#: uvicorn's exit status when the application's startup fails.
STARTUP_FAILURE = 3

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"
SERVICE_UNAVAILABLE = {"detail": "Service unavailable"}

#: The three ways a refusal reaches an HTTP client, with what the recipe logs for each.
#: A refusal at the lookup carries no port (``EgressBlocked.port`` is ``None``: a name is
#: refused whatever the port), so the recipe's "%s:%s" prints "forbidden.test:None".
REFUSALS = [
    pytest.param(
        FORBIDDEN_NAME,
        f"Egress blocked: {FORBIDDEN_NAME}:None (resolved_from=None)",
        id="at-the-lookup",
    ),
    pytest.param(
        ALLOWED_NAME,
        f"Egress blocked: {ALLOWED_ADDR}:{OTHER_PORT} (resolved_from={ALLOWED_NAME})",
        id="at-the-connection-by-the-port-rule",
    ),
    pytest.param(
        FORBIDDEN_ADDR,
        f"Egress blocked: {FORBIDDEN_ADDR}:{OTHER_PORT} (resolved_from=None)",
        id="at-the-connection-to-a-raw-address",
    ),
]


def assert_enforcing(report: dict[str, Any]) -> None:
    assert report["active"] is True, report
    assert report["locked"] is True, report
    assert report["loop"] == STANDARD_LOOP, report


def two_workers_refused(server: Server) -> bool:
    """Ready, for a server that is expected never to serve: two workers gave up."""
    return server.log.count(ACTIVATE_REFUSED) >= 2


def never_answers(server: Server) -> bool:
    try:
        server.get("/whoami", timeout=2.0)
    except OSError:
        return True
    return False


def test_fastapi_run_has_no_option_for_the_event_loop() -> None:
    # Everything below follows from this: under "fastapi run" the loop is
    # whatever uvicorn picks.  If the command grows such an option, the
    # documentation should name it.
    done = run_to_exit(
        ["fastapi", "run", "--help"],
        env={"TETH_ACTIVATE": "none", "COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"},
    )
    assert done["returncode"] == 0, done
    assert "--workers" in done["output"], done["output"]
    assert "loop" not in done["output"].lower(), done["output"]


def test_uvloop_is_the_only_installed_extension_that_reaches_the_network_by_itself() -> None:
    # tethered sees what goes through Python's socket module.  Of the compiled
    # modules that "fastapi[standard]" installs, the ones that import the C
    # library's own networking functions are the ones that could go around
    # it: today that is uvloop alone.  A new name here is a new thing to test.
    site_packages = Path(sysconfig.get_paths()["platlib"])
    modules = sorted(site_packages.rglob("*.so"))
    assert len(modules) >= 5, modules
    reaching = {}
    for module in modules:
        functions = network_functions(module)
        if functions:
            reaching[module.relative_to(site_packages).parts[0]] = sorted(functions)
    assert set(reaching) == {"uvloop"}, reaching
    assert {"connect", "getaddrinfo"} <= set(reaching["uvloop"]), reaching


# ── One process, every way of starting it ─────────────────────────────


@pytest.fixture(scope="module", params=list(SERVED))
def served(request: pytest.FixtureRequest) -> Server:
    """``main.py`` under a locked policy, served in one process."""
    return start_server(SERVED[request.param], env={"TETH_ACTIVATE": "locked"})


class TestServed:
    def test_uvloop_is_refused_and_the_application_runs_on_the_standard_loop(
        self, served: Server
    ) -> None:
        me = served.get("/whoami").json()
        assert_enforcing(me)
        assert me["pid"] == served.pid
        assert served.pids() == [served.pid]
        log = served.log
        assert log.count(REFUSED_TO_LOAD) == 1, log
        assert log.index("activated tethered (locked)") < log.index(REFUSED_TO_LOAD), log
        assert "uvloop is loaded" not in log, log

    def test_starting_the_server_under_the_policy_reaches_for_nothing(self, served: Server) -> None:
        # With a path, "fastapi run" itself runs under the policy from the
        # moment it has imported the application.  It has no business on the
        # network, and the policy has nothing to refuse it.
        served.get("/whoami")
        assert "tethered: blocked" not in served.log, served.log
        assert arrivals() == {}

    @pytest.mark.parametrize("endpoint", ["httpx_async", "httpx_sync", "streams"])
    def test_the_allowed_destination_is_reached(self, served: Server, endpoint: str) -> None:
        reply = served.get(probe_path(endpoint, ALLOWED_NAME, ALLOWED_PORT))
        assert reply.status == 200, reply.text
        assert reply.json()["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert arrivals() == {AT_ALLOWED: 1}

    @pytest.mark.parametrize(("host", "logged"), REFUSALS)
    def test_a_refused_request_of_the_async_client_ends_as_the_503_of_the_recipe(
        self, served: Server, host: str, logged: str
    ) -> None:
        reply = served.get(probe_path("httpx_async", host, OTHER_PORT))
        assert reply.status == 503, reply.text
        assert reply.json() == SERVICE_UNAVAILABLE
        assert arrivals() == {}
        assert logged in served.log_of_this_test, served.log_of_this_test

    @pytest.mark.parametrize(("host", "logged"), REFUSALS)
    def test_a_refused_request_of_the_sync_client_ends_as_the_503_of_the_recipe(
        self, served: Server, host: str, logged: str
    ) -> None:
        reply = served.get(probe_path("httpx_sync", host, OTHER_PORT))
        assert reply.status == 503, reply.text
        assert reply.json() == SERVICE_UNAVAILABLE
        assert arrivals() == {}
        assert logged in served.log_of_this_test, served.log_of_this_test

    @pytest.mark.parametrize(("host", "logged"), REFUSALS)
    def test_a_refused_stream_ends_as_the_503_of_the_recipe(
        self, served: Server, host: str, logged: str
    ) -> None:
        reply = served.get(probe_path("streams", host, OTHER_PORT))
        assert reply.status == 503, reply.text
        assert reply.json() == SERVICE_UNAVAILABLE
        assert arrivals() == {}
        assert logged in served.log_of_this_test, served.log_of_this_test

    @pytest.mark.parametrize(("host", "logged"), REFUSALS)
    def test_a_refused_websocket_connection_ends_as_the_503_of_the_recipe(
        self, served: Server, host: str, logged: str
    ) -> None:
        reply = served.get(probe_path("websocket", host, OTHER_PORT))
        assert reply.status == 503, reply.text
        assert reply.json() == SERVICE_UNAVAILABLE
        assert arrivals() == {}
        assert logged in served.log_of_this_test, served.log_of_this_test

    def test_a_websocket_connection_to_the_allowed_destination_is_made(
        self, served: Server
    ) -> None:
        reply = served.get(probe_path("websocket", ALLOWED_NAME, ALLOWED_PORT))
        assert reply.status == 200, reply.text
        assert reply.json()["connected"] is True, reply.text
        assert arrivals() == {AT_ALLOWED: 1}

    def test_the_async_client_gets_a_bare_refusal_at_the_lookup(self, served: Server) -> None:
        report = served.get(probe_path("httpx_shape", FORBIDDEN_NAME, OTHER_PORT)).json()
        assert report["outcome"] == "blocked", report
        assert report["exception"] == EGRESS_BLOCKED, report
        assert arrivals() == {}

    @pytest.mark.parametrize("host", [ALLOWED_NAME, FORBIDDEN_ADDR])
    def test_the_async_client_gets_a_refused_connection_inside_an_exception_group(
        self, served: Server, host: str
    ) -> None:
        # anyio connects in a task group; this is why the recipe registers its
        # handler for ExceptionGroup as well.
        report = served.get(probe_path("httpx_shape", host, OTHER_PORT)).json()
        assert report["outcome"] == "blocked", report
        assert report["exception"] == "builtins.ExceptionGroup", report
        assert report["refusal"]["exception"] == EGRESS_BLOCKED, report
        assert arrivals() == {}

    @pytest.mark.parametrize(("host", "logged"), REFUSALS)
    def test_the_except_star_of_the_cookbook_catches_every_shape(
        self, served: Server, host: str, logged: str
    ) -> None:
        reply = served.get(probe_path("httpx_caught", host, OTHER_PORT))
        assert reply.status == 200, reply.text
        assert reply.json()["caught"] is True, reply.text
        assert arrivals() == {}
        assert logged.partition(" (")[0] in served.log_of_this_test, served.log_of_this_test

    def test_an_exception_group_without_a_refusal_is_still_a_500(self, served: Server) -> None:
        reply = served.get("/task_group_failure")
        assert reply.status == 500, reply.text
        # The handler raised it again; the server goes on.
        assert served.get("/whoami").status == 200


# ── Workers ───────────────────────────────────────────────────────────

#: A request every worker refuses, with a report that says which worker it was.
BLOCKED_BY_EVERY_WORKER = probe_path("httpx_shape", FORBIDDEN_NAME, OTHER_PORT)


class TestWorkers:
    @pytest.mark.parametrize("target", [["main.py"], []], ids=["a-path", "discovered"])
    def test_with_a_path_the_workers_inherit_the_policy_and_enforce(
        self, target: list[str]
    ) -> None:
        # "fastapi run" imported main.py to find the application object, so
        # the policy is active in the supervisor before any worker starts,
        # and each worker inherits it before it asks for uvloop.
        server = start_server(
            [*FASTAPI_RUN, *target, "--workers", "2"], env={"TETH_ACTIVATE": "locked"}
        )
        first = server.each_worker(BLOCKED_BY_EVERY_WORKER, 2)
        for report in first.values():
            assert_enforcing(report)
            assert report["ppid"] == server.pid
            assert report["outcome"] == "blocked", report
        assert server.get(probe_path("httpx_async", ALLOWED_NAME, OTHER_PORT)).status == 503
        assert arrivals() == {}
        # The supervisor holds the policy and never asks for uvloop; each
        # worker asked once.
        assert server.log.count(REFUSED_TO_LOAD) == 2, server.log

        server.send_signal(signal.SIGKILL, min(first))
        (replacement,) = server.each_worker(BLOCKED_BY_EVERY_WORKER, 1, exclude=first).values()
        assert_enforcing(replacement)
        assert replacement["outcome"] == "blocked", replacement
        assert arrivals() == {}

    def test_with_an_entrypoint_no_worker_starts(self) -> None:
        """Limit: ``fastapi run --entrypoint main:app --workers 2`` never serves.

        With an entry point ``fastapi run`` does not import the application,
        so nothing is active in the supervisor.  Each worker loads uvloop,
        then imports the application, ``activate()`` raises ``RuntimeError``
        and the worker dies; the supervisor replaces it without end.
        ``fastapi run`` has no option for the event loop and ``UVICORN_LOOP``
        does not reach it: tethered's message names two remedies that this
        command does not have.
        """
        server = start_server(
            [*FASTAPI_RUN, "--entrypoint", "main:app", "--workers", "2"],
            env={"TETH_ACTIVATE": "locked", "UVICORN_LOOP": "asyncio"},
            ready=two_workers_refused,
        )
        assert "(uvicorn: --loop asyncio, or UVICORN_LOOP=asyncio in the environment)" in server.log
        assert server.running
        assert never_answers(server)
        assert arrivals() == {}

    def test_uvicorn_with_workers_and_the_standard_loop_named_enforces(self) -> None:
        # What the refusal above tells the user to run instead.
        server = start_server(
            [*UVICORN, "main:app", "--workers", "2", "--loop", "asyncio"],
            env={"TETH_ACTIVATE": "locked"},
        )
        for report in server.each_worker(BLOCKED_BY_EVERY_WORKER, 2).values():
            assert_enforcing(report)
            assert report["outcome"] == "blocked", report
        assert arrivals() == {}


def test_fastapi_dev_reloads_in_a_process_that_inherited_the_policy() -> None:
    # "fastapi dev" is "fastapi run" with the reloader: the command imports
    # main.py itself, so the process the reloader starts inherits the policy.
    server = start_server(
        ["fastapi", "dev", "main.py", "--host", "127.0.0.1", "--port", "{port}"],
        env={"TETH_ACTIVATE": "plain"},
    )
    report = server.get(BLOCKED_BY_EVERY_WORKER).json()
    assert report["loop"] == STANDARD_LOOP, report
    assert report["active"] is True, report
    assert report["ppid"] == server.pid, report
    assert report["outcome"] == "blocked", report
    assert arrivals() == {}


# ── A log-only policy ─────────────────────────────────────────────────


def test_under_a_log_only_policy_fastapi_run_serves_on_uvloop_and_reports_nothing() -> None:
    """Limit: a log-only policy does not keep uvloop out, and on uvloop it sees no async call.

    The request to a forbidden host is answered with 200, the connection
    arrives, and no "tethered: blocked" line is written for it: what a
    log-only policy is run for, the list of what would be blocked, stays
    empty for everything that goes through the loop.  One warning at
    startup says so.
    """
    server = start_server([*FASTAPI_RUN, "main.py"], env={"TETH_ACTIVATE": "log_only"})
    me = server.get("/whoami").json()
    assert me["loop"] == UVLOOP, me
    assert me["log_only"] is True, me
    assert server.log.count(UVLOOP_WARNING) == 1, server.log

    reply = server.get(probe_path("httpx_async", FORBIDDEN_NAME, OTHER_PORT))
    assert reply.status == 200, reply.text
    assert reply.json()["reply"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}"
    assert arrivals() == {AT_FORBIDDEN: 1}
    assert "tethered: blocked" not in server.log, server.log

    # The synchronous client uses the socket module and is reported.
    assert server.get(probe_path("httpx_sync", FORBIDDEN_NAME, OTHER_PORT)).status == 200
    server.wait_log(f"tethered: blocked connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")


# ── Activation in a lifespan handler ──────────────────────────────────


class TestActivationInALifespanHandler:
    @pytest.mark.parametrize(
        "command",
        [
            pytest.param([*UVICORN_ONCE, "lifespan_main:app"], id="uvicorn"),
            pytest.param([*FASTAPI_RUN_ONCE, "lifespan_main.py"], id="fastapi-run"),
        ],
    )
    def test_with_the_loop_left_to_uvicorn_the_startup_fails(self, command: list[str]) -> None:
        """Limit: a policy activated at startup comes after uvloop, and the server exits.

        Nothing is active while uvicorn picks its loop, so it gets uvloop;
        ``activate()`` in the lifespan handler then raises ``RuntimeError``,
        FastAPI reports the failed startup and uvicorn exits with status 3.
        The server does not run without the policy.
        """
        done = run_to_exit(command, env={"TETH_ACTIVATE": "locked"})
        assert done["returncode"] == STARTUP_FAILURE, done
        output = done["output"]
        assert ACTIVATE_REFUSED in output, output
        assert "Application startup failed. Exiting." in output, output
        assert not re.search(r"probe: pid \d+ activated tethered", output), output
        assert arrivals() == {}

    def test_with_the_standard_loop_named_it_starts_and_enforces(self) -> None:
        server = start_server(
            [*UVICORN, "lifespan_main:app", "--loop", "asyncio"], env={"TETH_ACTIVATE": "locked"}
        )
        assert_enforcing(server.get("/whoami").json())
        for host in (FORBIDDEN_NAME, ALLOWED_NAME, FORBIDDEN_ADDR):
            reply = server.get(probe_path("httpx_async", host, OTHER_PORT))
            assert reply.status == 503, reply.text
            assert reply.json() == SERVICE_UNAVAILABLE
        assert arrivals() == {}
        reply = server.get(probe_path("httpx_async", ALLOWED_NAME, ALLOWED_PORT))
        assert reply.status == 200, reply.text
        assert arrivals() == {AT_ALLOWED: 1}

    def test_a_log_only_policy_is_activated_over_the_loaded_uvloop_with_a_warning(self) -> None:
        """Limit: the one policy that ``activate()`` accepts over uvloop reports no async call."""
        server = start_server([*UVICORN, "lifespan_main:app"], env={"TETH_ACTIVATE": "log_only"})
        me = server.get("/whoami").json()
        assert me["loop"] == UVLOOP, me
        assert me["log_only"] is True, me
        assert server.log.count(UVLOOP_WARNING) == 1, server.log
        assert server.get(probe_path("httpx_async", FORBIDDEN_NAME, OTHER_PORT)).status == 200
        assert arrivals() == {AT_FORBIDDEN: 1}
        assert "tethered: blocked" not in server.log, server.log


# ── Starlette's TestClient ────────────────────────────────────────────

#: argv: the module, the policy, the options of TestClient and the calls to make, as JSON.
_TEST_CLIENT = """
import importlib, json, os, sys

module, policy, options = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
os.environ["TETH_ACTIVATE"] = policy
result = {}
try:
    from starlette.testclient import TestClient

    application = importlib.import_module(module).app
    with TestClient(application, **options) as client:
        result["whoami"] = client.get("/whoami").json()
        for name, host, port in json.loads(sys.argv[4]):
            reply = client.get("/httpx_async", params={"host": host, "port": port})
            result[name] = [reply.status_code, reply.json()]
except Exception as exc:
    result["exception"] = f"{type(exc).__name__}: {exc}"
print(json.dumps(result))
"""
_CALLS = json.dumps(
    [
        ["lookup", FORBIDDEN_NAME, OTHER_PORT],
        ["port", ALLOWED_NAME, OTHER_PORT],
        ["address", FORBIDDEN_ADDR, OTHER_PORT],
        ["allowed", ALLOWED_NAME, ALLOWED_PORT],
    ]
)


def drive_with_test_client(module: str, policy: str, **options: Any) -> dict[str, Any]:
    """Drive an application with ``starlette.testclient.TestClient`` in a fresh interpreter."""
    done = run_python(
        _TEST_CLIENT, activate="none", args=[module, policy, json.dumps(options), _CALLS]
    )
    return done.json()


class TestStarletteTestClient:
    @pytest.mark.parametrize("module", ["main", "lifespan_main"])
    def test_the_policy_is_enforced_whenever_it_was_activated(self, module: str) -> None:
        # The client runs the application on an asyncio loop of anyio's
        # making: the standard one, whatever is installed.
        result = drive_with_test_client(module, "locked")
        assert "exception" not in result, result
        assert_enforcing(result["whoami"])
        for name in ("lookup", "port", "address"):
            assert result[name] == [503, SERVICE_UNAVAILABLE], result
        assert result["allowed"][0] == 200, result
        assert arrivals() == {AT_ALLOWED: 1}

    def test_asking_anyio_for_uvloop_fails_when_the_policy_was_activated_at_import(self) -> None:
        result = drive_with_test_client("main", "locked", backend_options={"use_uvloop": True})
        assert result.get("exception", "").startswith(
            "ImportError: tethered: uvloop was not loaded"
        ), result
        assert arrivals() == {}

    def test_asking_anyio_for_uvloop_fails_the_activation_in_the_lifespan_handler(self) -> None:
        """Limit: here the loop comes first, and the application's startup raises."""
        result = drive_with_test_client(
            "lifespan_main", "locked", backend_options={"use_uvloop": True}
        )
        assert result.get("exception", "").startswith(
            "RuntimeError: tethered: activate() refused"
        ), result
        assert arrivals() == {}
