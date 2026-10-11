"""A Python program under supervisord, started by an entry point that holds the policy.

The question: a process that holds a policy starts something that knows
nothing of tethered, and that in turn starts a Python program.  Does the
program get the policy?  Here the entry point (``entrypoint.py``) activates
it and replaces itself with supervisord, Debian's package, which runs on the
distribution's own ``python3`` (no tethered there).  supervisord starts the
program (``sup_app.py``) with its own environment plus what its
configuration adds.

The policy travels in the environment (``_TETHERED_CHILD_POLICY``): the
program inherits it when supervisord passes its environment on, and every
time supervisord restarts it.  A program whose environment is wiped
(``env -i``) starts without it.

Not covered: ``supervisorctl`` and event listeners.
"""

from __future__ import annotations

import os
import signal
from pathlib import Path
from typing import Any

import pytest
from harness import (
    ALLOWED_ADDR,
    ALLOWED_NAME,
    ALLOWED_PORT,
    APPS_DIR,
    FORBIDDEN_ADDR,
    FORBIDDEN_NAME,
    OTHER_PORT,
    SUITE_DIR,
    Server,
    arrivals,
    probe_path,
    start_server,
)

EGRESS_BLOCKED = "tethered._core.EgressBlocked"
AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"

#: The program, started with the interpreter that has tethered.
APP = "/usr/local/bin/python sup_app.py"


def wiped(program: str) -> str:
    """The same command with an environment that holds only what the program needs to run."""
    keep = f"PORT={{port}} TETH_ACTIVATE={program} PYTHONPATH={APPS_DIR}:{SUITE_DIR}"
    return f"env -i {keep} PYTHONUNBUFFERED=1 {APP}"


def supervised(launcher: str, program: str, command: str = APP) -> Server:
    """Start the entry point, which activates ``launcher`` and becomes supervisord.

    ``program`` is the policy the supervised program activates itself
    (``none``: it never calls ``activate()``), ``command`` its command line.
    """
    env = {"LAUNCHER_ACTIVATE": launcher, "TETH_ACTIVATE": program}
    return start_server(["python", "entrypoint.py", command], env=env)


def assert_under_supervisord(report: dict[str, Any], server: Server) -> None:
    """The program is a child of supervisord, which is not the Python that has tethered."""
    assert report["ppid"] == server.pid
    assert report["configured"] == "yes", "the environment supervisord's configuration adds"
    command = Path(f"/proc/{server.pid}/cmdline").read_bytes().replace(b"\0", b" ").decode()
    assert "supervisord" in command, command
    interpreter = os.readlink(f"/proc/{server.pid}/exe")
    assert interpreter.startswith("/usr/bin/python3"), interpreter
    assert report["executable"].startswith("/usr/local/bin/python"), report


def assert_refused(report: dict[str, Any]) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == EGRESS_BLOCKED, report


def assert_policy(report: dict[str, Any], mode: str) -> None:
    assert report["active"] is True, report
    assert report["locked"] is (mode == "locked"), report


def restarted(server: Server, old: int) -> dict[str, Any]:
    """Kill the program and return the first report of the one supervisord starts instead."""
    server.send_signal(signal.SIGKILL, old)
    path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
    (report,) = server.each_worker(path, 1, exclude=[old]).values()
    return report


class TestThePolicyOfTheEntryPoint:
    @pytest.mark.parametrize("mode", ["plain", "locked"])
    def test_the_program_inherits_it_through_supervisord_and_so_does_its_restart(
        self, mode: str
    ) -> None:
        # The program itself never calls activate().
        server = supervised(mode, "none")
        me = server.probe("whoami")
        assert_under_supervisord(me, server)
        assert_policy(me, mode)
        # What the entry point logged when it became supervisord: not a launch
        # tethered can vouch for.
        server.wait_log(r"external subprocess launch detected: os\.exec\*\(.*supervisord")

        assert_refused(server.probe("connect", FORBIDDEN_NAME, OTHER_PORT))
        assert arrivals() == {}
        report = server.probe("connect", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 1}

        # supervisord restarts the program with the same environment.
        report = restarted(server, me["pid"])
        assert_under_supervisord(report, server)
        assert_policy(report, mode)
        assert_refused(report)
        assert arrivals() == {AT_ALLOWED: 1}

    def test_a_program_started_with_a_wiped_environment_does_not_get_it(self) -> None:
        """Limit: the policy does not reach a program whose environment was wiped on the way.

        The entry point holds a locked policy; supervisord is not a Python
        with tethered and enforces nothing; ``env -i`` drops
        ``_TETHERED_CHILD_POLICY``, and the program starts unrestricted.
        Activate in the program itself as well (the next class).
        """
        server = supervised("locked", "none", wiped("none"))
        report = server.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert report["ppid"] == server.pid
        assert report["policy_in_environ"] is False
        assert report["tethered_imported"] is False, report
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}

    def test_an_entry_point_that_blocks_external_launches_cannot_become_supervisord(self) -> None:
        # external_subprocess_policy="block": supervisord is not this
        # interpreter, so the exec is refused and the entry point ends.
        started: list[Server] = []

        def ready(server: Server) -> bool:
            started.append(server)
            return False

        with pytest.raises(AssertionError, match="exited with status 1 while starting"):
            start_server(
                ["python", "entrypoint.py", APP],
                env={"LAUNCHER_ACTIVATE": "locked", "TETH_ACTIVATE": "none", "TETH_ESP": "block"},
                ready=ready,
            )
        assert "SubprocessBlocked: Blocked by tethered: os.exec*(" in started[0].log
        assert "supervisord" in started[0].log


class TestThePolicyOfTheProgram:
    @pytest.mark.parametrize("command", [APP, wiped("locked")], ids=["inherited", "wiped"])
    def test_a_program_that_activates_itself_holds_the_policy_and_so_does_its_restart(
        self, command: str
    ) -> None:
        # No policy in the entry point: what a deployment with supervisord as
        # its first process looks like.  The program's environment does not matter.
        server = supervised("none", "locked", command)
        me = server.probe("whoami")
        assert me["ppid"] == server.pid
        assert_policy(me, "locked")
        assert_refused(server.probe("connect", FORBIDDEN_NAME, OTHER_PORT))

        report = restarted(server, me["pid"])
        assert_policy(report, "locked")
        assert_refused(report)
        assert arrivals() == {}

    def test_with_no_policy_anywhere_the_forbidden_destination_is_reached(self) -> None:
        # The control.
        server = supervised("none", "none")
        report = server.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert_under_supervisord(report, server)
        assert report["tethered_imported"] is False
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
