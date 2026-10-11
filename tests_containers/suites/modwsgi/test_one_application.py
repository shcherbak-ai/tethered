"""Apache with mod_wsgi, one application per process: every process enforces the policy.

mod_wsgi runs an application in daemon processes of its own
(``WSGIDaemonProcess``) or inside Apache's child processes (embedded mode).
In either it runs in the main interpreter of the process when its application
group is ``%{GLOBAL}``, and otherwise, which is the default, in a
subinterpreter that mod_wsgi creates when the application gets its first
request there.  ``mod_wsgi-express`` generates a configuration of the first
kind: daemon mode, the main interpreter, the script imported at process start.

With one application in a process none of that matters to tethered: the
application calls ``activate()`` when its script is imported, in whatever
interpreter that is, and the process is covered.  This module checks that for
each arrangement, in every process, and in the processes that replace them:
after a graceful restart, after ``maximum-requests`` or ``inactivity-timeout``,
and after the script was touched.

The other modules of the suite: ``test_two_applications.py`` (several
applications in one process, which is where the order of things starts to
matter), ``test_virtualenv.py`` (``python-home`` and ``python-path``),
``test_launches.py`` (what a handler launches) and ``test_uvloop.py``.  The
application is ``mw_app``: the operations and reports of the shared probe
applications, with the settings as arguments.  Not covered anywhere in the
suite: Windows, a ``mod_wsgi`` packaged by a distribution, and Apache's worker
MPM (threaded, like event).
"""

from __future__ import annotations

import os
import signal
import sys
from dataclasses import dataclass
from importlib.metadata import version
from typing import TYPE_CHECKING, Any

import pytest
from apache import (
    EVENT_ONE,
    EVENT_PROXY,
    PREFORK_TWO,
    Site,
    apache_version,
    ask,
    standing,
    start_express,
)
from expect import (
    AT_ALLOWED,
    AT_FORBIDDEN,
    NO_OP,
    POLICY_DIFFERS,
    TETHERED_LOCKED,
    enforces,
    reached,
    refused,
)
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
)

if TYPE_CHECKING:
    from pathlib import Path

#: Daemon mode: two processes of one thread each, so that overlapping requests reach both.
DAEMON = """
    WSGIRestrictEmbedded On
    WSGIDaemonProcess shop processes=2 threads=1 {options}
    WSGIScriptAlias /shop {script}
    <Location /shop>
        WSGIProcessGroup shop
        {group}
    </Location>
"""
#: Embedded mode: no daemon process group; Apache's child processes run the application.
EMBEDDED = """
    WSGIScriptAlias /shop {script}
    <Location /shop>
        {group}
    </Location>
"""
IN_MAIN_INTERPRETER = "WSGIApplicationGroup %{GLOBAL}"
#: What Apache logs for SIGUSR1, with the event MPM and with prefork.
GRACEFUL_RESTART = r"SIGUSR1 received\.  Doing graceful restart|Graceful restart requested"
#: ``allowed.test:9002``, for a script whose policy changes.
CHANGED_ALLOW = [f"{ALLOWED_NAME}:{OTHER_PORT}"]


@dataclass(frozen=True)
class Arrangement:
    """One way of running the application, and what its reports must then say."""

    directives: str = DAEMON
    #: ``WSGIApplicationGroup``; empty for mod_wsgi's default, a group per application.
    group: str = ""
    mpm: str = "event"
    mpm_settings: str = EVENT_PROXY
    #: How many processes run the application.
    processes: int = 2

    @property
    def embedded(self) -> bool:
        return self.directives is EMBEDDED

    @property
    def main_interpreter(self) -> bool:
        return self.group == IN_MAIN_INTERPRETER


ARRANGEMENTS = {
    "daemon": Arrangement(),
    "daemon-global": Arrangement(group=IN_MAIN_INTERPRETER),
    "embedded-prefork": Arrangement(EMBEDDED, mpm="prefork", mpm_settings=PREFORK_TWO),
    # The threaded MPM: one child process, see EVENT_ONE.
    "embedded-event": Arrangement(EMBEDDED, mpm_settings=EVENT_ONE, processes=1),
    "embedded-event-global": Arrangement(
        EMBEDDED, group=IN_MAIN_INTERPRETER, mpm_settings=EVENT_ONE, processes=1
    ),
    # mod_wsgi-express with its defaults: one daemon process, the main interpreter.
    "express": Arrangement(group=IN_MAIN_INTERPRETER, processes=1),
}
#: A locked policy in every arrangement; a plain one where the interpreter or the kind of
#: process differs (a subinterpreter, the main interpreter, an Apache child process).
ENFORCING = [(name, "locked") for name in ARRANGEMENTS] + [
    ("daemon", "plain"),
    ("daemon-global", "plain"),
    ("embedded-prefork", "plain"),
]


@dataclass(frozen=True)
class Running:
    """A started arrangement: the server, where the application is, the script behind it."""

    server: Server
    arrangement: Arrangement
    mount: str
    site: Site
    script: Path

    def path(self, op: str, host: str | None = None, port: int | None = None, **params: Any) -> str:
        """The path of one operation of the application."""
        return self.mount + probe_path(op, host, port, **params)

    def every_process(self, path: str, exclude: Any = ()) -> dict[int, dict[str, Any]]:
        """The report of ``path`` from every process that runs the application."""
        return self.server.each_worker(path, self.arrangement.processes, exclude=exclude)


def start(name: str, options: str = "", **settings: Any) -> Running:
    """Start the arrangement ``name``; ``settings`` are those of the WSGI script.

    ``options`` are further options of ``WSGIDaemonProcess``, in daemon mode.
    """
    arrangement = ARRANGEMENTS[name]
    site = Site()
    script = site.script("shop", **settings)
    if name == "express":
        return Running(start_express(site, script), arrangement, "", site, script)
    directives = arrangement.directives.format(
        script=script, group=arrangement.group, options=options
    )
    server = site.start(directives, mpm=arrangement.mpm, mpm_settings=arrangement.mpm_settings)
    return Running(server, arrangement, "/shop", site, script)


def touch(script: Path) -> None:
    """Give the script a later modification time, which is what mod_wsgi looks at."""
    later = script.stat().st_mtime + 10
    os.utime(script, (later, later))


def test_the_versions_under_test() -> None:
    # What Apache says it loaded is what pip built for this Python.
    running = start("daemon")
    banner = running.server.wait_log(
        r"AH00489: (Apache/\S+).* mod_wsgi/(\S+) Python/(\S+) configured"
    )
    assert banner.group(1) == apache_version()
    assert banner.group(1).startswith("Apache/2.4.")
    assert banner.group(2) == version("mod_wsgi")
    assert banner.group(3) == f"{sys.version_info.major}.{sys.version_info.minor}"


# ── Every arrangement ─────────────────────────────────────────────────


@pytest.fixture(scope="class", params=ENFORCING, ids=lambda pair: "-".join(pair))
def enforcing(request: pytest.FixtureRequest) -> tuple[str, str]:
    return request.param


@pytest.fixture(scope="class")
def policy(enforcing: tuple[str, str]) -> str:
    return enforcing[1]


@pytest.fixture(scope="class")
def running(enforcing: tuple[str, str]) -> Running:
    name, policy = enforcing
    return start(name, activate=policy)


class TestEveryProcess:
    def test_the_application_runs_as_arranged_and_holds_the_policy(
        self, running: Running, policy: str
    ) -> None:
        arrangement = running.arrangement
        answers = running.every_process(running.path("whoami"))
        assert running.server.pid not in answers
        for pid, me in answers.items():
            # Daemon processes and Apache's children are both children of Apache's parent.
            assert me["ppid"] == running.server.pid, me
            assert (me["process_group"] == "") is arrangement.embedded, me
            assert me["main_interpreter"] is arrangement.main_interpreter, me
            assert (me["group"] == "") is arrangement.main_interpreter, me
            # Each process imported the script itself: nothing came from a parent.
            assert me["imported_in_pid"] == pid, me
            assert me["at_startup"]["tethered_imported"] is False, me
            assert me["activation"] == {"outcome": "activated"}, me
            assert standing(me) == ("holder" if policy == "locked" else "unlocked"), me

    def test_every_process_reaches_the_allowed_destination(self, running: Running) -> None:
        path = running.path("connect", ALLOWED_NAME, ALLOWED_PORT)
        for report in running.every_process(path).values():
            reached(report)
            assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}", report
        assert set(arrivals()) == {AT_ALLOWED}

    def test_every_process_refuses_the_forbidden_destination(self, running: Running) -> None:
        path = running.path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in running.every_process(path).values():
            refused(report)
        assert arrivals() == {}

    def test_the_allow_list_is_enforced_rule_by_rule(self, running: Running) -> None:
        # A forbidden address, the allowed name on another port, the forbidden
        # name on the allowed port, loopback: one request each, whichever
        # process answers.
        enforces(running.server, running.mount)
        report = ask(running.server, running.mount, "urllib", ALLOWED_NAME, ALLOWED_PORT)
        reached(report)
        refused(ask(running.server, running.mount, "urllib", FORBIDDEN_NAME, OTHER_PORT))

    def test_an_uncaught_refusal_is_a_500_and_the_processes_survive(self, running: Running) -> None:
        before = running.every_process(running.path("whoami"))
        path = running.path("connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)
        assert running.server.get(path).status == 500
        assert arrivals() == {}
        running.server.wait_log(
            f"EgressBlocked: Blocked by tethered: {FORBIDDEN_NAME} is not in the allow list"
        )
        assert set(running.every_process(running.path("whoami"))) == set(before)

    def test_a_python_child_of_every_process_inherits_the_policy(
        self, running: Running, policy: str
    ) -> None:
        path = running.path("child", FORBIDDEN_NAME, OTHER_PORT)
        for pid, report in running.every_process(path).items():
            reached(report)
            child = report["child"]
            assert child["ppid"] == pid, report
            assert child["active"] is True, report
            assert child["locked"] is (policy == "locked"), report
            refused(child)
        assert arrivals() == {}


# ── Processes that are started later ──────────────────────────────────


def assert_new_processes_enforce(
    running: Running, first: dict[int, Any], policy: str = "locked"
) -> dict[int, Any]:
    """Wait for processes other than ``first`` and check the policy in each."""
    path = running.path("connect", FORBIDDEN_NAME, OTHER_PORT)
    later = running.every_process(path, exclude=first)
    for report in later.values():
        assert report["ppid"] == running.server.pid, report
        assert standing(report) == ("holder" if policy == "locked" else "unlocked"), report
        refused(report)
    assert arrivals() == {}
    path = running.path("connect", ALLOWED_NAME, ALLOWED_PORT)
    for report in running.every_process(path, exclude=first).values():
        reached(report)
    assert set(arrivals()) == {AT_ALLOWED}
    return later


class TestLaterProcesses:
    @pytest.mark.parametrize(
        ("name", "policy"),
        [
            ("daemon", "locked"),
            ("daemon", "plain"),
            ("daemon-global", "locked"),
            ("embedded-event", "locked"),
            ("express", "locked"),
        ],
    )
    def test_the_processes_of_a_graceful_restart_enforce_the_policy(
        self, name: str, policy: str
    ) -> None:
        running = start(name, activate=policy)
        first = running.every_process(running.path("whoami"))
        # What "apachectl graceful" sends to Apache's parent process.
        running.server.send_signal(signal.SIGUSR1)
        assert_new_processes_enforce(running, first, policy)
        running.server.wait_log(GRACEFUL_RESTART)

    @pytest.mark.parametrize(
        ("name", "policy"), [("daemon", "locked"), ("daemon", "plain"), ("daemon-global", "locked")]
    )
    def test_a_process_started_after_maximum_requests_enforces_the_policy(
        self, name: str, policy: str
    ) -> None:
        running = start(name, "maximum-requests=5", activate=policy)
        first = running.every_process(running.path("whoami"))
        assert_new_processes_enforce(running, first, policy)
        # mod_wsgi's own words: the new processes came from the limit, not from a crash.
        running.server.wait_log("Maximum requests reached")

    def test_a_process_started_after_the_inactivity_timeout_enforces_the_policy(self) -> None:
        running = start("daemon", "inactivity-timeout=1", activate="locked")
        first = running.every_process(running.path("whoami"))
        # Both processes, before the next request: a request would start the
        # timer of a process that has not stopped yet all over again.
        expired = "Daemon process idle inactivity timer expired"
        running.server.wait_log(f"(?s){expired}.*{expired}")
        assert_new_processes_enforce(running, first)


# ── A WSGI script that changes ────────────────────────────────────────


class TestTouchedScript:
    def test_daemon_mode_restarts_the_process_and_a_changed_policy_is_in_place(self) -> None:
        running = start("daemon", activate="locked")
        first = running.every_process(running.path("whoami"))
        touch(running.script)
        second = assert_new_processes_enforce(running, first)
        running.server.wait_log("Forcing restart of daemon process 'shop' due to modification")

        # The same with another allow list in the script: a new process, a new lock.
        running.site.script("shop", activate="locked", allow=CHANGED_ALLOW)
        touch(running.script)
        gone = {**first, **second}
        for me in running.every_process(running.path("whoami"), exclude=gone).values():
            assert standing(me) == "holder", me
        enforces(running.server, running.mount, port=OTHER_PORT, other_port=ALLOWED_PORT)

    def test_embedded_mode_reloads_the_same_locked_policy_as_a_no_op(self) -> None:
        # In embedded mode mod_wsgi imports the script again in the same
        # interpreter, which still holds the lock.
        running = start("embedded-prefork", activate="locked")
        first = running.every_process(running.path("whoami"))
        touch(running.script)
        again = running.every_process(running.path("whoami"))
        assert set(again) == set(first)
        for me in again.values():
            assert me["at_startup"]["locked"] is True, me
            assert me["activation"] == {"outcome": "activated"}, me
            assert standing(me) == "holder", me
        running.server.wait_log("Reloading WSGI script")
        running.server.wait_log(NO_OP)
        enforces(running.server, running.mount)

    def test_embedded_mode_replaces_a_plain_policy_with_the_changed_one(self) -> None:
        running = start("embedded-prefork", activate="plain")
        enforces(running.server, running.mount)
        running.site.script("shop", activate="plain", allow=CHANGED_ALLOW)
        touch(running.script)
        running.every_process(running.path("whoami"))
        running.server.wait_log("Reloading WSGI script")
        enforces(running.server, running.mount, port=OTHER_PORT, other_port=ALLOWED_PORT)

    def test_embedded_mode_cannot_replace_a_locked_policy_until_apache_restarts(self) -> None:
        """Limit: in embedded mode a changed locked policy is a 500 until the processes are new.

        The reloaded script runs in the interpreter that holds the lock and
        asks for another policy without the token: ``TetheredLocked``.  The
        script fails to import, mod_wsgi tries again at every request, and
        the application is gone until Apache's child processes are replaced.
        The old policy stays in force meanwhile: nothing arrives anywhere.
        """
        running = start("embedded-prefork", activate="locked")
        first = running.every_process(running.path("whoami"))
        running.site.script("shop", activate="locked", allow=CHANGED_ALLOW, catch=False)
        touch(running.script)

        for _ in range(4):
            path = running.path("connect", ALLOWED_NAME, OTHER_PORT)
            assert running.server.get(path).status == 500
        assert arrivals() == {}
        running.server.wait_log(f"{TETHERED_LOCKED}: tethered: activate\\(\\) blocked")
        assert POLICY_DIFFERS in running.server.log

        running.server.send_signal(signal.SIGUSR1)
        for me in running.every_process(running.path("whoami"), exclude=first).values():
            assert standing(me) == "holder", me
        enforces(running.server, running.mount, port=OTHER_PORT, other_port=ALLOWED_PORT)


# ── The modes that do not refuse ──────────────────────────────────────


class TestNotEnforcing:
    def test_without_tethered_the_forbidden_destination_is_reached(self) -> None:
        # The control: the same route, no policy.  It shows that the world's
        # counters move when something does arrive.
        running = start("daemon")
        me = ask(running.server, running.mount, "whoami")
        assert me["tethered_imported"] is False, me
        reached(ask(running.server, running.mount, "connect", FORBIDDEN_NAME, OTHER_PORT))
        assert arrivals() == {AT_FORBIDDEN: 1}

    def test_log_only_reports_the_connection_and_lets_it_through(self) -> None:
        running = start("daemon", activate="log_only")
        reached(ask(running.server, running.mount, "connect", FORBIDDEN_NAME, OTHER_PORT))
        assert arrivals() == {AT_FORBIDDEN: 1}
        running.server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")
        running.server.wait_log(f"tethered: blocked connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")
