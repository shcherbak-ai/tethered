"""uvicorn 0.46.0 with uvloop installed: what a user of the older releases meets.

Up to and including 0.46.0, uvicorn picks its event loop first and imports
the application afterwards, inside the running loop, in every arrangement
(``uvicorn.run()`` imports the application first since 0.47.0).  With uvloop
installed and no word about the loop, uvloop is therefore loaded when an
application that activates at import calls ``activate()``.  ``activate()``
then raises ``RuntimeError`` and the server does not start: it does not
serve without the policy.  The tests pin that down, and then each way out:

* ``--loop asyncio`` on the command line;
* ``UVICORN_LOOP=asyncio`` in the environment, which works for the
  ``uvicorn`` command and not for ``uvicorn.run()`` called from Python;
* a launcher that activates before it calls ``uvicorn.run()``: uvloop is
  then refused and uvicorn falls back by itself;
* a log-only policy, which is activated over the loaded uvloop with a
  warning and reports nothing the loop does.

``test_gunicorn_worker.py`` and ``test_fastapi_run.py`` cover the same
release under gunicorn and under ``fastapi run``.  The uvicorn suite covers
the current release.
"""

from __future__ import annotations

import importlib.metadata
import signal
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
    start_server,
)
from one_shot import run_to_exit

UVICORN = ["uvicorn", "probe_asgi:app", "--host=127.0.0.1", "--port={port}"]
UVICORN_ONCE = ["uvicorn", "probe_asgi:app", "--host=127.0.0.1", "--port=0"]
FROM_PYTHON = ["python", "run_from_python.py"]

STANDARD_LOOP = "asyncio.unix_events._UnixSelectorEventLoop"
UVLOOP = "uvloop.Loop"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"

REFUSED_TO_LOAD = "tethered: refused to load uvloop while a policy is active"
ACTIVATE_REFUSED = "RuntimeError: tethered: activate() refused"
UVLOOP_WARNING = "tethered: uvloop is loaded in this process."
#: The remedies the RuntimeError names.
REMEDIES = (
    "(uvicorn: --loop asyncio on the command line, UVICORN_LOOP=asyncio in the environment "
    'of that command, or loop="asyncio" in uvicorn.run())'
)

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"

#: The ways to open a TCP connection from a coroutine.
STREAM_OPS = ["open_connection", "create_connection", "sock_connect", "to_thread", "connect"]
#: Destinations the allow list does not cover.
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]


def assert_refused(report: dict[str, Any]) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == EGRESS_BLOCKED, report


def assert_enforcing(report: dict[str, Any], *, locked: bool) -> None:
    assert report["active"] is True, report
    assert report["locked"] is locked, report
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


def test_the_image_has_the_release_this_suite_is_about() -> None:
    # Every expectation in this directory is about uvicorn 0.46.  If the pin
    # in requirements.txt was moved, say so here and not in sixty failures.
    assert importlib.metadata.version("uvicorn") == "0.46.0"


# ── The loop left to uvicorn: the server does not start ───────────────


class TestTheLoopLeftToUvicorn:
    @pytest.mark.parametrize("policy", ["plain", "locked", "fail_closed"])
    def test_activate_raises_and_the_server_does_not_start(self, policy: str) -> None:
        done = run_to_exit(UVICORN_ONCE, env={"TETH_ACTIVATE": policy})
        assert done["returncode"] == 1, done
        output = done["output"]
        last = output.strip().splitlines()[-1]
        assert last.startswith(ACTIVATE_REFUSED), last
        # The message says what to do about it, for this command line.
        assert REMEDIES in last, last
        assert "or call activate() before uvloop is imported" in last, last
        assert "Nothing was changed." in last, last
        assert "activated tethered" not in output, output
        assert "Started server process" not in output, output
        assert REFUSED_TO_LOAD not in output, output
        assert arrivals() == {}

    def test_uvloop_named_on_the_command_line_ends_the_same_way(self) -> None:
        # On the current release this is an ImportError: there the policy is
        # active first.  Here uvloop is loaded first.
        done = run_to_exit([*UVICORN_ONCE, "--loop=uvloop"], env={"TETH_ACTIVATE": "locked"})
        assert done["returncode"] == 1, done
        assert done["output"].strip().splitlines()[-1].startswith(ACTIVATE_REFUSED), done
        assert arrivals() == {}

    def test_with_workers_no_worker_starts_and_the_supervisor_keeps_trying(self) -> None:
        """Limit: the supervisor never exits; every worker it starts dies with the same error."""
        server = start_server(
            [*UVICORN, "--workers", "2"],
            env={"TETH_ACTIVATE": "locked"},
            ready=two_workers_refused,
        )
        assert REMEDIES in server.log, server.log
        server.wait_log(r"Child process \[\d+\] died")
        assert server.running
        assert never_answers(server)
        assert arrivals() == {}

    def test_without_tethered_the_server_runs_on_uvloop(self) -> None:
        # The control: this image does give uvicorn uvloop.
        server = start_server(UVICORN, env={"TETH_ACTIVATE": "none"})
        assert server.get("/whoami").json()["loop"] == UVLOOP
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}


# ── The two remedies of the message, on the command line ──────────────

NAMED = {
    "--loop=asyncio": (["--loop=asyncio"], {}),
    "UVICORN_LOOP=asyncio": ([], {"UVICORN_LOOP": "asyncio"}),
}


@pytest.fixture(scope="class", params=list(NAMED))
def named(request: pytest.FixtureRequest) -> Server:
    """One uvicorn process with the standard loop named, under a locked policy."""
    options, env = NAMED[request.param]
    return start_server([*UVICORN, *options], env={"TETH_ACTIVATE": "locked", **env})


class TestTheStandardLoopNamed:
    def test_the_server_starts_on_the_standard_loop_and_never_asks_for_uvloop(
        self, named: Server
    ) -> None:
        me = named.get("/whoami").json()
        assert_enforcing(me, locked=True)
        assert me["pid"] == named.pid
        assert "uvloop" not in named.log, named.log

    @pytest.mark.parametrize("op", STREAM_OPS)
    def test_the_allowed_destination_is_reached(self, named: Server, op: str) -> None:
        report = named.probe(op, ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 1}

    @pytest.mark.parametrize("op", STREAM_OPS)
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_destination_outside_the_allow_list_is_refused(
        self, named: Server, op: str, host: str, port: int
    ) -> None:
        assert_refused(named.probe(op, host, port))
        assert arrivals() == {}

    @pytest.mark.parametrize("op", ["getaddrinfo", "datagram_connected", "datagram_unconnected"])
    def test_a_lookup_and_a_datagram_are_refused(self, named: Server, op: str) -> None:
        assert_refused(named.probe(op, FORBIDDEN_NAME, OTHER_PORT))
        assert arrivals() == {}


@pytest.mark.parametrize("arrangement", list(NAMED))
def test_with_the_standard_loop_named_every_worker_enforces(arrangement: str) -> None:
    options, env = NAMED[arrangement]
    server = start_server(
        [*UVICORN, "--workers", "2", *options], env={"TETH_ACTIVATE": "locked", **env}
    )
    path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
    first = server.each_worker(path, 2)
    for pid, report in first.items():
        assert_enforcing(report, locked=True)
        assert report["imported_in_pid"] == pid
        assert_refused(report)
    assert arrivals() == {}

    server.send_signal(signal.SIGKILL, min(first))
    (replacement,) = server.each_worker(path, 1, exclude=first).values()
    assert_enforcing(replacement, locked=True)
    assert_refused(replacement)
    assert arrivals() == {}


# ── uvicorn started from Python ───────────────────────────────────────


class TestStartedFromPython:
    @pytest.mark.parametrize("environment", [{}, {"UVICORN_LOOP": "asyncio"}], ids=["", "env"])
    def test_uvicorn_run_fails_like_the_command_and_the_variable_does_not_help(
        self, environment: dict[str, str]
    ) -> None:
        """Limit: ``UVICORN_LOOP`` belongs to the ``uvicorn`` command, not to ``uvicorn.run()``.

        tethered's message offers it without saying so.  For a server that is
        started from Python the remedy is the ``loop="asyncio"`` argument, or
        activating before ``uvicorn.run()`` is called.
        """
        done = run_to_exit(
            [*FROM_PYTHON, "run"], env={"TETH_ACTIVATE": "locked", "PORT": "0", **environment}
        )
        assert done["returncode"] == 1, done
        last = done["output"].strip().splitlines()[-1]
        assert last.startswith(ACTIVATE_REFUSED), last
        assert REMEDIES in last, last
        assert arrivals() == {}

    def test_an_application_object_imported_by_the_launcher_keeps_uvloop_out(self) -> None:
        # uvicorn.run(app): the launcher has imported the application, and
        # with it the policy, before uvicorn asks for its loop.
        server = start_server([*FROM_PYTHON, "run-object"], env={"TETH_ACTIVATE": "locked"})
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert_enforcing(report, locked=True)
        assert_refused(report)
        assert arrivals() == {}
        assert server.log.count(REFUSED_TO_LOAD) == 1, server.log

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
        assert arrivals() == {AT_ALLOWED: 1}
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

        server.send_signal(signal.SIGKILL, min(first))
        (replacement,) = server.each_worker(path, 1, exclude=first).values()
        assert_enforcing(replacement, locked=True)
        assert_refused(replacement)
        assert arrivals() == {}

    def test_server_serve_under_asyncio_run_never_asks_for_uvloop(self) -> None:
        server = start_server([*FROM_PYTHON, "serve"], env={"TETH_ACTIVATE": "locked"})
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert_enforcing(report, locked=True)
        assert_refused(report)
        assert arrivals() == {}
        assert "uvloop" not in server.log, server.log


# ── A log-only policy ─────────────────────────────────────────────────


class TestLogOnly:
    def test_it_is_activated_over_the_loaded_uvloop_with_a_warning(self) -> None:
        """Limit: a log-only policy is the one ``activate()`` accepts over a loaded uvloop.

        The server runs on uvloop.  What goes through the loop is neither
        refused nor reported; a connection made with the socket module is
        still reported.
        """
        server = start_server(UVICORN, env={"TETH_ACTIVATE": "log_only"})
        me = server.get("/whoami").json()
        assert me["loop"] == UVLOOP, me
        assert me["log_only"] is True, me
        log = server.log
        assert log.count(UVLOOP_WARNING) == 1, log
        # Here the warning comes from activate() itself: uvloop was there first.
        assert log.index(UVLOOP_WARNING) < log.index("activated tethered (log_only)"), log

        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        assert "tethered: blocked" not in server.log, server.log

        report = server.probe("to_thread", FORBIDDEN_ADDR, OTHER_PORT)
        assert report["outcome"] == "reached", report
        server.wait_log(f"tethered: blocked connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")
