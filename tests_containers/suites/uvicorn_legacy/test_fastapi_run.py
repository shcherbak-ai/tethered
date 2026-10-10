"""``fastapi run`` on top of uvicorn 0.46.0.

``fastapi run`` has no option for the event loop and calls ``uvicorn.run()``
without one, so ``UVICORN_LOOP`` does not reach it either.  What decides is
whether ``fastapi run`` imports the application itself:

* with a path, or with nothing (it then finds ``main.py``), it imports the
  module to look for the ``FastAPI`` object.  The policy is active before
  uvicorn is started, uvloop is refused, the server runs on the standard
  loop and its workers inherit the policy;
* with ``--entrypoint main:app`` (or the same in ``pyproject.toml``) the
  import is left to uvicorn, and uvicorn 0.46 loads uvloop first:
  ``activate()`` raises and the server does not start.  On the current
  uvicorn the same command works in one process (the ``fastapi`` suite).

The application is ``main.py``: a ``FastAPI`` object with the ASGI probe
application mounted in it.
"""

from __future__ import annotations

import re
import signal
from typing import Any

import pytest
from harness import (
    ALLOWED_ADDR,
    ALLOWED_NAME,
    ALLOWED_PORT,
    FORBIDDEN_NAME,
    OTHER_PORT,
    Server,
    arrivals,
    probe_path,
    start_server,
)
from one_shot import run_to_exit

FASTAPI_RUN = ["fastapi", "run", "--host", "127.0.0.1", "--port", "{port}"]
FASTAPI_RUN_ONCE = ["fastapi", "run", "--host", "127.0.0.1", "--port", "0"]
ENTRYPOINT = ["--entrypoint", "main:app"]

STANDARD_LOOP = "asyncio.unix_events._UnixSelectorEventLoop"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
REFUSED_TO_LOAD = "tethered: refused to load uvloop while a policy is active"
ACTIVATE_REFUSED = "RuntimeError: tethered: activate() refused"
#: What the probe application prints once ``activate()`` has returned.
ACTIVATED = r"probe: pid \d+ activated tethered"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"


def assert_refused(report: dict[str, Any]) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == EGRESS_BLOCKED, report


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


class TestWithAPath:
    @pytest.mark.parametrize("target", [["main.py"], []], ids=["a-path", "discovered"])
    def test_one_process_runs_on_the_standard_loop_and_enforces(self, target: list[str]) -> None:
        server = start_server([*FASTAPI_RUN, *target], env={"TETH_ACTIVATE": "locked"})
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert_enforcing(report)
        assert report["pid"] == server.pid
        assert_refused(report)
        assert arrivals() == {}
        assert server.probe("open_connection", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}
        log = server.log
        assert log.count(REFUSED_TO_LOAD) == 1, log
        assert log.index("activated tethered (locked)") < log.index(REFUSED_TO_LOAD), log

    def test_the_workers_inherit_the_policy_and_enforce(self) -> None:
        server = start_server(
            [*FASTAPI_RUN, "main.py", "--workers", "2"], env={"TETH_ACTIVATE": "locked"}
        )
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        first = server.each_worker(path, 2)
        for report in first.values():
            assert_enforcing(report)
            assert report["ppid"] == server.pid
            assert_refused(report)
        assert arrivals() == {}

        server.send_signal(signal.SIGKILL, min(first))
        (replacement,) = server.each_worker(path, 1, exclude=first).values()
        assert_enforcing(replacement)
        assert_refused(replacement)
        assert arrivals() == {}


class TestWithAnEntrypoint:
    @pytest.mark.parametrize("environment", [{}, {"UVICORN_LOOP": "asyncio"}], ids=["", "env"])
    def test_the_server_does_not_start_and_the_variable_does_not_help(
        self, environment: dict[str, str]
    ) -> None:
        """Limit: ``fastapi run --entrypoint`` on uvicorn 0.46 cannot be started under a policy.

        uvicorn loads uvloop, then imports the application, and
        ``activate()`` raises.  The message names ``--loop asyncio`` and
        ``UVICORN_LOOP``; this command has neither.  What works is to give
        ``fastapi run`` the path instead, to serve with ``uvicorn main:app
        --loop asyncio``, or to uninstall uvloop.
        """
        done = run_to_exit(
            [*FASTAPI_RUN_ONCE, *ENTRYPOINT], env={"TETH_ACTIVATE": "locked", **environment}
        )
        assert done["returncode"] == 1, done
        # "fastapi run" prints the traceback with rich: framed, with source
        # lines, and wrapped at the terminal width.
        assert ACTIVATE_REFUSED in done["output"], done["output"]
        assert not re.search(ACTIVATED, done["output"]), done["output"]
        assert arrivals() == {}

    def test_with_workers_no_worker_starts(self) -> None:
        """Limit: nor with ``--workers``; the supervisor replaces dying workers without end."""
        server = start_server(
            [*FASTAPI_RUN, *ENTRYPOINT, "--workers", "2"],
            env={"TETH_ACTIVATE": "locked"},
            ready=two_workers_refused,
        )
        assert server.running
        assert never_answers(server)
        assert arrivals() == {}
