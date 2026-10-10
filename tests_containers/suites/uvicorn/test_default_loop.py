"""uvicorn with uvloop installed and the choice of the event loop left to uvicorn.

No command line here names a loop, except where a test says so.  With
``uvicorn[standard]`` that is the most common deployment there is: uvicorn
then runs on uvloop whenever importing uvloop works, and nothing that goes
through a uvloop event loop raises an audit event.  tethered answers in two
ways, and which one a deployment meets depends on what uvicorn does first:

* the policy is active before uvicorn asks for uvloop: the import of uvloop
  is refused (``ImportError``), uvicorn falls back to the standard asyncio
  loop on its own, and the policy is enforced there;
* uvloop is loaded before the application activates: ``activate()`` raises
  ``RuntimeError`` and the process does not serve.

uvicorn 0.54 imports the application before it picks the loop when it serves
in one process (the command and ``uvicorn.run()``), and picks the loop first
in every worker process it starts (``--workers``, ``--reload``) and in
``uvicorn.Server(config).run()``.  Each test checks through ``/whoami``
which loop the application really runs on, and asserts what arrived in the
world.

Three arrangements end on uvloop and are asserted as limits: a log-only
policy, which refuses nothing, uvloop included; a ``scope()`` with no policy
under it; and an application without a framework that activates in its
lifespan handler, where uvicorn takes the ``RuntimeError`` for "no lifespan
support" and serves with no policy.

``test_uvicorn.py`` covers the standard loop named on the command line.
"""

from __future__ import annotations

import signal
from typing import Any

import pytest
from harness import (
    ALLOWED_ADDR,
    ALLOWED_NAME,
    ALLOWED_PORT,
    FORBIDDEN_ADDR,
    FORBIDDEN_NAME,
    LOOPBACK_ADDR,
    OTHER_PORT,
    Server,
    arrivals,
    probe_path,
    start_server,
)
from one_shot import run_to_exit

#: No ``--loop``: the default is ``auto``.
UVICORN = ["uvicorn", "probe_asgi:app", "--host=127.0.0.1", "--port={port}"]
#: The same for a command that is expected not to come up.
UVICORN_ONCE = ["uvicorn", "probe_asgi:app", "--host=127.0.0.1", "--port=0"]
FROM_PYTHON = ["python", "run_from_python.py"]

STANDARD_LOOP = "asyncio.unix_events._UnixSelectorEventLoop"
UVLOOP = "uvloop.Loop"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"

#: Logged once per process when the import of uvloop is refused.
REFUSED_TO_LOAD = "tethered: refused to load uvloop while a policy is active"
#: The ``ImportError`` that refusal raises.
NOT_LOADED = "uvloop was not loaded"
#: The ``RuntimeError`` of ``activate()`` when uvloop is already loaded.
ACTIVATE_REFUSED = "RuntimeError: tethered: activate() refused"
#: Logged once when a log-only policy or a scope finds uvloop loaded.
UVLOOP_WARNING = "tethered: uvloop is loaded in this process."

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"

#: The ways to open a TCP connection from a coroutine.
STREAM_OPS = ["open_connection", "create_connection", "sock_connect", "to_thread", "connect"]
#: Those that go through the event loop's own transports.
LOOP_STREAM_OPS = ["open_connection", "create_connection"]
#: Those that end in a call of Python's socket module, whatever the loop.
SOCKET_STREAM_OPS = ["sock_connect", "to_thread", "connect"]
#: Destinations the allow list does not cover.
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_enforcing(report: dict[str, Any], *, locked: bool) -> None:
    assert report["active"] is True, report
    assert report["locked"] is locked, report
    assert report["log_only"] is False, report
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


# ── One process: the application is imported before the loop is chosen ─


@pytest.fixture(scope="module", params=["plain", "locked", "fail_closed"])
def mode(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(mode: str) -> Server:
    """One uvicorn process, loop ``auto``; the application activates when it is imported."""
    return start_server(UVICORN, env={"TETH_ACTIVATE": mode})


class TestOneProcess:
    def test_uvloop_is_refused_and_the_server_runs_on_the_standard_loop(
        self, server: Server, mode: str
    ) -> None:
        me = server.get("/whoami").json()
        assert_enforcing(me, locked=mode == "locked")
        assert me["fail_closed"] is (mode == "fail_closed"), me
        assert me["pid"] == server.pid
        assert server.pids() == [server.pid]

    def test_the_refusal_is_logged_once_and_after_the_application_was_imported(
        self, server: Server, mode: str
    ) -> None:
        log = server.log
        assert log.count(REFUSED_TO_LOAD) == 1, log
        activated = log.index(f"probe: pid {server.pid} activated tethered ({mode})")
        assert activated < log.index(REFUSED_TO_LOAD), log
        # uvicorn catches the ImportError and says nothing; neither of the
        # messages for a uvloop that did get loaded appears.
        assert NOT_LOADED not in log, log
        assert "uvloop is loaded" not in log, log

    @pytest.mark.parametrize("op", STREAM_OPS)
    def test_the_allowed_destination_is_reached(self, server: Server, op: str) -> None:
        report = server.probe(op, ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert report["loop"] == STANDARD_LOOP, report
        assert arrivals() == {AT_ALLOWED: 1}

    @pytest.mark.parametrize("op", STREAM_OPS)
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_destination_outside_the_allow_list_is_refused(
        self, server: Server, op: str, host: str, port: int
    ) -> None:
        assert_refused(server.probe(op, host, port))
        assert arrivals() == {}

    @pytest.mark.parametrize("op", STREAM_OPS)
    def test_loopback_stays_reachable(self, server: Server, op: str) -> None:
        report = server.probe(op, LOOPBACK_ADDR, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {f"{LOOPBACK_ADDR}:{OTHER_PORT}/tcp": 1}

    def test_a_lookup_of_the_allowed_name_is_answered(self, server: Server) -> None:
        report = server.probe("getaddrinfo", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert report["addresses"] == [ALLOWED_ADDR]

    def test_a_lookup_of_a_forbidden_name_is_refused(self, server: Server) -> None:
        assert_refused(server.probe("getaddrinfo", FORBIDDEN_NAME, OTHER_PORT))
        assert arrivals() == {}

    @pytest.mark.parametrize("op", ["datagram_connected", "datagram_unconnected"])
    def test_a_datagram_reaches_the_allowed_destination(self, server: Server, op: str) -> None:
        report = server.probe(op, ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {f"{ALLOWED_ADDR}:{ALLOWED_PORT}/udp": 1}

    @pytest.mark.parametrize("op", ["datagram_connected", "datagram_unconnected"])
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_datagram_outside_the_allow_list_is_not_sent(
        self, server: Server, op: str, host: str, port: int
    ) -> None:
        assert_refused(server.probe(op, host, port))
        assert arrivals() == {}

    def test_an_uncaught_refusal_is_a_500_and_the_server_keeps_serving(
        self, server: Server
    ) -> None:
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)
        assert server.get(path).status == 500
        assert arrivals() == {}
        server.wait_log("Exception in ASGI application")
        assert server.get("/whoami").json()["pid"] == server.pid

    def test_a_python_child_launched_through_the_loop_inherits_the_policy(
        self, server: Server, mode: str
    ) -> None:
        # asyncio.create_subprocess_exec: on the standard loop it ends in
        # subprocess.Popen, which the hook sees.
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        child = report["child"]
        assert child["ppid"] == server.pid
        assert child["active"] is True, child
        assert child["locked"] is (mode == "locked"), child
        assert_refused(child)
        assert arrivals() == {}

    def test_a_tool_launched_through_the_loop_is_seen(self, server: Server) -> None:
        report = server.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        # Under the default "warn" the tool runs, unrestricted: what matters
        # here is that the launch was noticed at all.
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(r"external subprocess launch detected: subprocess\.Popen\(bash\)")


def test_under_block_a_tool_is_not_launched_through_the_loop() -> None:
    server = start_server(UVICORN, env={"TETH_ACTIVATE": "locked", "TETH_ESP": "block"})
    assert server.get("/whoami").json()["loop"] == STANDARD_LOOP
    assert_refused(server.probe("tool", FORBIDDEN_NAME, OTHER_PORT), SUBPROCESS_BLOCKED)
    assert arrivals() == {}


def test_without_tethered_the_server_runs_on_uvloop() -> None:
    # The control: this image does give uvicorn uvloop when nothing refuses it.
    server = start_server(UVICORN, env={"TETH_ACTIVATE": "none"})
    me = server.get("/whoami").json()
    assert me["loop"] == UVLOOP, me
    assert me["tethered_imported"] is False, me
    report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
    assert report["outcome"] == "reached", report
    assert arrivals() == {AT_FORBIDDEN: 1}


# ── A log-only policy: uvloop is loaded ───────────────────────────────


@pytest.fixture(scope="class")
def log_only() -> Server:
    return start_server(UVICORN, env={"TETH_ACTIVATE": "log_only"})


class TestLogOnly:
    def test_uvloop_is_loaded_and_tethered_says_what_that_means(self, log_only: Server) -> None:
        """Limit: a log-only policy refuses nothing, so uvicorn gets uvloop and runs on it."""
        me = log_only.get("/whoami").json()
        assert me["loop"] == UVLOOP, me
        assert me["active"] is True, me
        assert me["log_only"] is True, me
        log = log_only.log
        assert log.count(UVLOOP_WARNING) == 1, log
        assert "they are neither blocked nor reported, by a log-only policy" in log, log
        assert "(uvicorn: --loop asyncio)" in log, log
        assert REFUSED_TO_LOAD not in log, log

    @pytest.mark.parametrize("op", LOOP_STREAM_OPS)
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_connection_made_through_the_loop_is_not_reported(
        self, log_only: Server, op: str, host: str, port: int
    ) -> None:
        """Limit: on uvloop a log-only policy reports nothing the loop does itself."""
        report = log_only.probe(op, host, port)
        assert report["outcome"] == "reached", report
        assert sum(arrivals().values()) == 1, arrivals()
        assert "tethered: blocked" not in log_only.log_of_this_test, log_only.log_of_this_test

    def test_a_lookup_made_through_the_loop_is_not_reported(self, log_only: Server) -> None:
        """Limit: nor a name lookup."""
        report = log_only.probe("getaddrinfo", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["addresses"] == [FORBIDDEN_ADDR]
        assert "tethered: blocked" not in log_only.log_of_this_test, log_only.log_of_this_test

    @pytest.mark.parametrize(
        ("op", "host"),
        [
            ("datagram_connected", FORBIDDEN_NAME),
            # uvloop's sendto() takes an address only: it does no lookup.
            ("datagram_unconnected", FORBIDDEN_ADDR),
        ],
    )
    def test_a_datagram_sent_through_the_loop_is_not_reported(
        self, log_only: Server, op: str, host: str
    ) -> None:
        """Limit: nor a datagram."""
        report = log_only.probe(op, host, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {f"{FORBIDDEN_ADDR}:{OTHER_PORT}/udp": 1}
        assert "tethered: blocked" not in log_only.log_of_this_test, log_only.log_of_this_test

    def test_a_launch_made_through_the_loop_is_not_reported(self, log_only: Server) -> None:
        """Limit: nor a process launch; on the standard loop this one is warned about."""
        report = log_only.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        assert "external subprocess" not in log_only.log_of_this_test, log_only.log_of_this_test

    @pytest.mark.parametrize("op", SOCKET_STREAM_OPS)
    def test_a_connection_made_with_the_socket_module_is_still_reported(
        self, log_only: Server, op: str
    ) -> None:
        report = log_only.probe(op, FORBIDDEN_ADDR, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        log_only.wait_log(f"tethered: blocked connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")


def test_log_only_on_the_standard_loop_reports_what_uvloop_hides() -> None:
    # The other half of the limit above: the same policy, the loop named.
    server = start_server([*UVICORN, "--loop=asyncio"], env={"TETH_ACTIVATE": "log_only"})
    assert server.get("/whoami").json()["loop"] == STANDARD_LOOP
    assert server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)["outcome"] == "reached"
    server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")
    server.wait_log(f"tethered: blocked connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")
    assert server.probe("tool", FORBIDDEN_NAME, OTHER_PORT)["outcome"] == "reached"
    server.wait_log(r"external subprocess launch detected: subprocess\.Popen\(bash\)")
    assert UVLOOP_WARNING not in server.log


# ── uvloop asked for by name ──────────────────────────────────────────


class TestUvloopByName:
    @pytest.mark.parametrize("policy", ["plain", "locked"])
    def test_the_server_does_not_start(self, policy: str) -> None:
        done = run_to_exit([*UVICORN_ONCE, "--loop=uvloop"], env={"TETH_ACTIVATE": policy})
        assert done["returncode"] == 1, done
        output = done["output"]
        # The application was imported, the policy is active, and then
        # uvicorn's import of uvloop fails with tethered's reason.
        assert f"activated tethered ({policy})" in output, output
        assert REFUSED_TO_LOAD in output, output
        last = output.strip().splitlines()[-1]
        assert last.startswith("ImportError: tethered: uvloop was not loaded"), last
        assert "Run the application on the standard asyncio event loop" in last, last
        assert "Started server process" not in output, output
        assert arrivals() == {}

    def test_under_a_log_only_policy_it_starts_on_uvloop(self) -> None:
        """Limit: the same as with the loop left to uvicorn."""
        server = start_server([*UVICORN, "--loop=uvloop"], env={"TETH_ACTIVATE": "log_only"})
        assert server.get("/whoami").json()["loop"] == UVLOOP
        assert UVLOOP_WARNING in server.log


# ── --workers: every worker picks its loop before it imports the application ──


class TestWorkers:
    def test_no_worker_starts_and_the_supervisor_keeps_trying(self) -> None:
        """Limit: with --workers and the loop left to uvicorn the server never serves.

        Each worker process loads uvloop first and imports the application
        afterwards, so ``activate()`` raises ``RuntimeError`` and the worker
        dies.  The supervisor starts another one, again and again, and never
        exits.  Nothing is served without the policy: nothing is served.
        """
        server = start_server(
            [*UVICORN, "--workers", "2"],
            env={"TETH_ACTIVATE": "locked"},
            ready=two_workers_refused,
        )
        log = server.log
        assert ACTIVATE_REFUSED in log, log
        assert "(uvicorn: --loop asyncio, or UVICORN_LOOP=asyncio in the environment)" in log, log
        assert "activated tethered" not in log, log
        # Dead workers are replaced, and the replacements die the same way.
        server.wait_log(r"Child process \[\d+\] died")
        server.wait_log(r"(?s)(RuntimeError: tethered: activate\(\) refused.*){4}", timeout=30)
        assert server.running
        assert never_answers(server)
        assert "Application startup complete" not in server.log, server.log
        assert arrivals() == {}

    @pytest.mark.parametrize(
        "arrangement",
        [
            pytest.param((["--loop=asyncio"], {}), id="--loop=asyncio"),
            pytest.param(([], {"UVICORN_LOOP": "asyncio"}), id="UVICORN_LOOP=asyncio"),
        ],
    )
    def test_with_the_standard_loop_named_every_worker_enforces(
        self, arrangement: tuple[list[str], dict[str, str]]
    ) -> None:
        options, env = arrangement
        server = start_server(
            [*UVICORN, "--workers", "2", *options], env={"TETH_ACTIVATE": "locked", **env}
        )
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        answers = server.each_worker(path, 2)
        for pid, report in answers.items():
            assert_enforcing(report, locked=True)
            assert report["ppid"] == server.pid
            assert report["imported_in_pid"] == pid
            assert_refused(report)
        assert arrivals() == {}
        # uvloop was never asked for, so there was nothing to refuse.
        assert REFUSED_TO_LOAD not in server.log, server.log


# ── uvicorn started from Python ───────────────────────────────────────


class TestStartedFromPython:
    @pytest.mark.parametrize("how", ["run", "run-object", "serve"])
    def test_one_process_runs_on_the_standard_loop_and_enforces(self, how: str) -> None:
        server = start_server([*FROM_PYTHON, how], env={"TETH_ACTIVATE": "locked"})
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert_enforcing(report, locked=True)
        assert_refused(report)
        assert arrivals() == {}
        assert server.probe("open_connection", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}
        # Server.serve() under asyncio.run() never asks for uvloop at all.
        assert server.log.count(REFUSED_TO_LOAD) == (0 if how == "serve" else 1), server.log

    def test_server_run_loads_uvloop_first_and_the_application_does_not_activate(self) -> None:
        """Limit: ``uvicorn.Server(config).run()`` picks the loop before it imports the application.

        ``uvicorn.run()`` imports the application first; the ``Server`` class
        used directly does not.  ``activate()`` then finds uvloop loaded and
        raises, and the process ends.  ``Config(..., loop="asyncio")`` or an
        ``activate()`` before the ``Server`` is created avoids it.
        """
        done = run_to_exit(
            [*FROM_PYTHON, "server-run"], env={"TETH_ACTIVATE": "locked", "PORT": "0"}
        )
        assert done["returncode"] == 1, done
        last = done["output"].strip().splitlines()[-1]
        assert last.startswith(ACTIVATE_REFUSED), last
        assert "activated tethered" not in done["output"], done["output"]
        assert arrivals() == {}

    @pytest.mark.parametrize("launch", ["plain", "locked"])
    @pytest.mark.parametrize("application", ["none", "same"])
    def test_a_launcher_that_activates_first_keeps_uvloop_out(
        self, launch: str, application: str
    ) -> None:
        env = {
            "LAUNCH_ACTIVATE": launch,
            "TETH_ACTIVATE": launch if application == "same" else "none",
        }
        server = start_server([*FROM_PYTHON, "activate-run"], env=env)
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert_enforcing(report, locked=launch == "locked")
        assert_refused(report)
        assert arrivals() == {}
        assert server.probe("open_connection", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
        assert server.log.count(REFUSED_TO_LOAD) == 1, server.log

    def test_workers_of_a_launcher_that_activates_first_inherit_and_enforce(self) -> None:
        server = start_server(
            [*FROM_PYTHON, "activate-run-workers"],
            env={"LAUNCH_ACTIVATE": "locked", "TETH_ACTIVATE": "none"},
        )
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        first = server.each_worker(path, 2)
        for report in first.values():
            assert_enforcing(report, locked=True)
            assert report["ppid"] == server.pid
            assert_refused(report)
        assert arrivals() == {}
        # Each worker inherited the policy as it started, asked for uvloop
        # and was refused; the launcher itself never asks.
        assert server.log.count(REFUSED_TO_LOAD) == 2, server.log

        server.send_signal(signal.SIGKILL, min(first))
        (replacement,) = server.each_worker(path, 1, exclude=first).values()
        assert_enforcing(replacement, locked=True)
        assert_refused(replacement)
        assert arrivals() == {}
        assert server.log.count(REFUSED_TO_LOAD) == 3, server.log

    def test_workers_of_a_launcher_that_does_not_activate_never_start(self) -> None:
        """Limit: ``uvicorn.run(workers=2)`` with no ``loop`` argument, like the command line."""
        server = start_server(
            [*FROM_PYTHON, "run-workers"],
            env={"TETH_ACTIVATE": "locked"},
            ready=two_workers_refused,
        )
        assert never_answers(server)
        assert arrivals() == {}

    def test_the_environment_variable_of_the_command_line_does_not_reach_uvicorn_run(
        self,
    ) -> None:
        """Limit: ``UVICORN_LOOP`` belongs to the ``uvicorn`` command, not to ``uvicorn.run()``.

        tethered's message offers it next to ``--loop asyncio``.  For a server
        started from Python only the ``loop="asyncio"`` argument works.
        """
        server = start_server(
            [*FROM_PYTHON, "run-workers"],
            env={"TETH_ACTIVATE": "locked", "UVICORN_LOOP": "asyncio"},
            ready=two_workers_refused,
        )
        assert "UVICORN_LOOP=asyncio in the environment" in server.log, server.log
        assert never_answers(server)
        assert arrivals() == {}


# ── Activation that comes after the loop ──────────────────────────────


class TestActivationAfterTheLoop:
    def test_a_factory_that_activates_when_it_is_called_is_too_late(self) -> None:
        """Limit: ``--factory`` with the activation inside the factory does not start.

        uvicorn imports the module first, which activates nothing, picks
        uvloop, and calls the factory on the running loop.
        """
        done = run_to_exit(
            ["uvicorn", "--factory", "factory_app:create_app", "--host=127.0.0.1", "--port=0"],
            env={"TETH_ACTIVATE": "locked"},
        )
        assert done["returncode"] == 1, done
        assert ACTIVATE_REFUSED in done["output"], done["output"]
        assert "Application startup complete" not in done["output"], done["output"]
        assert arrivals() == {}

    def test_the_same_factory_on_the_standard_loop_enforces(self) -> None:
        server = start_server(
            [
                "uvicorn",
                "--factory",
                "factory_app:create_app",
                "--host=127.0.0.1",
                "--port={port}",
                "--loop=asyncio",
            ],
            env={"TETH_ACTIVATE": "locked"},
        )
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert_enforcing(report, locked=True)
        assert_refused(report)
        assert arrivals() == {}

    def test_reload_starts_the_application_in_a_process_that_loaded_uvloop_first(self) -> None:
        """Limit: ``--reload`` with the loop left to uvicorn never serves, like ``--workers``."""
        server = start_server(
            [*UVICORN, "--reload"],
            env={"TETH_ACTIVATE": "plain"},
            ready=lambda started: ACTIVATE_REFUSED in started.log,
        )
        assert server.running
        assert never_answers(server)
        assert arrivals() == {}

    def test_reload_on_the_standard_loop_enforces(self) -> None:
        server = start_server(
            [*UVICORN, "--reload", "--loop=asyncio"], env={"TETH_ACTIVATE": "plain"}
        )
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert_enforcing(report, locked=False)
        assert report["ppid"] == server.pid
        assert_refused(report)
        assert arrivals() == {}


# ── Activation in a lifespan handler, with no framework around it ─────

LIFESPAN = ["uvicorn", "lifespan_app:app", "--host=127.0.0.1"]
#: ``lifespan_app`` activates this at startup; importing it activates nothing.
AT_STARTUP = {"TETH_ACTIVATE": "none", "LIFESPAN_ACTIVATE": "locked"}


class TestActivationInALifespanHandler:
    def test_uvicorn_takes_the_refusal_for_an_application_without_lifespan_and_serves(
        self,
    ) -> None:
        """Limit: the server comes up on uvloop with no policy at all, and nothing says so.

        The loop is chosen before the application's startup runs, so uvloop
        is loaded and ``activate()`` raises ``RuntimeError`` in the lifespan
        handler.  uvicorn's default, ``--lifespan auto``, reads any exception
        from that handler as "this application does not support lifespan"
        and serves, without logging the exception.  The application then
        runs without the policy it asked for: the forbidden destination is
        reached by blocking code as well, and tethered's message appears
        nowhere, because ``activate()`` only raises it.  A framework that
        catches the exception and reports a failed startup (FastAPI,
        Starlette: see the ``fastapi`` suite) makes uvicorn exit instead, and
        so does ``--lifespan on``.
        """
        server = start_server([*LIFESPAN, "--port={port}"], env=AT_STARTUP)
        me = server.get("/whoami").json()
        assert me["loop"] == UVLOOP, me
        assert me["tethered_imported"] is True, me
        assert me["active"] is False, me
        log = server.log
        assert "ASGI 'lifespan' protocol appears unsupported." in log, log
        assert "Application startup complete." in log, log
        assert "tethered" not in log, log
        assert "Traceback" not in log, log

        for op in ("open_connection", "connect"):
            report = server.probe(op, FORBIDDEN_NAME, OTHER_PORT)
            assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 2}
        assert "tethered" not in server.log, server.log

    def test_with_lifespan_on_the_server_exits(self) -> None:
        done = run_to_exit([*LIFESPAN, "--port=0", "--lifespan=on"], env=AT_STARTUP)
        assert done["returncode"] == 3, done
        assert ACTIVATE_REFUSED in done["output"], done["output"]
        assert "Application startup failed. Exiting." in done["output"], done["output"]
        assert arrivals() == {}

    def test_on_the_standard_loop_the_policy_is_activated_at_startup_and_enforced(self) -> None:
        server = start_server([*LIFESPAN, "--port={port}", "--loop=asyncio"], env=AT_STARTUP)
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert_enforcing(report, locked=True)
        assert_refused(report)
        assert arrivals() == {}


# ── A scope with no policy under it ───────────────────────────────────

SCOPED = ["uvicorn", "scoped_app:app", "--host=127.0.0.1", "--port={port}"]


@pytest.fixture(scope="class")
def scoped_on_uvloop() -> Server:
    """``scoped_app``: no ``activate()`` anywhere, every request inside a ``scope()``."""
    return start_server(SCOPED, env={"TETH_ACTIVATE": "none"})


@pytest.fixture(scope="class")
def scoped_on_asyncio() -> Server:
    return start_server([*SCOPED, "--loop=asyncio"], env={"TETH_ACTIVATE": "none"})


class TestScopeWithoutAPolicy:
    def test_nothing_keeps_uvloop_out_and_the_scope_says_so(self, scoped_on_uvloop: Server) -> None:
        """Limit: uvloop is refused under an active policy only; a scope alone does not count."""
        me = scoped_on_uvloop.get("/whoami").json()
        assert me["loop"] == UVLOOP, me
        assert me["tethered_imported"] is True, me
        assert me["active"] is False, me
        log = scoped_on_uvloop.log
        assert log.count(UVLOOP_WARNING) == 1, log
        assert REFUSED_TO_LOAD not in log, log

    @pytest.mark.parametrize("op", LOOP_STREAM_OPS)
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_the_scope_does_not_restrict_what_goes_through_the_loop(
        self, scoped_on_uvloop: Server, op: str, host: str, port: int
    ) -> None:
        """Limit: a forbidden destination is reached from inside the scope, with no exception."""
        report = scoped_on_uvloop.probe(op, host, port)
        assert report["outcome"] == "reached", report
        assert sum(arrivals().values()) == 1, arrivals()

    @pytest.mark.parametrize("op", SOCKET_STREAM_OPS)
    def test_the_scope_restricts_what_uses_the_socket_module(
        self, scoped_on_uvloop: Server, op: str
    ) -> None:
        report = scoped_on_uvloop.probe(op, FORBIDDEN_ADDR, OTHER_PORT)
        assert_refused(report)
        assert "scoped_app" in report["message"], report
        assert arrivals() == {}

    @pytest.mark.parametrize("op", STREAM_OPS)
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_on_the_standard_loop_the_scope_restricts_everything(
        self, scoped_on_asyncio: Server, op: str, host: str, port: int
    ) -> None:
        report = scoped_on_asyncio.probe(op, host, port)
        assert report["loop"] == STANDARD_LOOP, report
        assert_refused(report)
        assert arrivals() == {}
