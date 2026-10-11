"""gunicorn with its gevent workers: ``-k gevent`` and ``-k gevent_pywsgi``.

The worker monkey-patches the standard library when it starts, and three
things then differ from gunicorn's own workers (the ``gunicorn`` suite):

- **Name lookups** go through gevent's resolver.  The default one calls
  ``getaddrinfo`` in a thread pool, which tethered sees.  ``GEVENT_RESOLVER=ares``
  resolves in C and raises no audit event.
- **Process launches** go through gevent's own ``subprocess.Popen``, which
  forks and calls ``os.exec*`` from Python.  tethered sees no
  ``subprocess.Popen`` event; it sees ``os.exec`` events *inside the forked
  child*, one for each ``PATH`` directory that is tried, and whatever it logs
  there is written to the child's stderr, which is the pipe the application
  captures.
- **Refusals in the thread pool** are printed by gevent's hub with a traceback.

The application is ``gevent_app:application``: the shared WSGI probe plus
``/arrangement`` and ``/launch``.  gunicorn 26 has no eventlet worker any more
(``-k eventlet``: "Entry point ('gunicorn.workers', 'eventlet') not found"),
and gevent's dnspython resolver fails every lookup with dnspython 2.9, with
or without tethered; neither is covered.
"""

from __future__ import annotations

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

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
    dns_queries,
    probe_path,
    start_server,
)

if TYPE_CHECKING:
    from collections.abc import Callable

GUNICORN = ["gunicorn", "gevent_app:application", "--bind", "127.0.0.1:{port}"]
WORKER_MODELS = {
    "gevent": ["--worker-class", "gevent"],
    "gevent-preload": ["--worker-class", "gevent", "--preload"],
    "gevent_pywsgi": ["--worker-class", "gevent_pywsgi"],
}
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"
#: A name that is in no hosts file: only a DNS query could resolve it.
UNLISTED_NAME = f"secret-data.{FORBIDDEN_NAME}"

OPS = ["connect", "urllib"]
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]

#: tethered's warning about a launch it cannot vouch for; the group is the path that was tried.
#: A path that os.execvp joined itself is bytes and is printed as b'...'.
LAUNCH_WARNING = re.compile(
    r"tethered: external subprocess launch detected: os\.exec\*\((?:b')?([^)']+)'?\)"
)
EXEC_COMPLETED = "carried out with the locked policy added"
HUB_TRACEBACK = "failed with EgressBlocked"


def gunicorn(model: str, *options: str, workers: int = 2) -> list[str]:
    return [*GUNICORN, "--workers", str(workers), *WORKER_MODELS[model], *options]


def wait_until(condition: Callable[[], Any], what: str, timeout: float = 15.0) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        value = condition()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"not within {timeout} s: {what}")
        time.sleep(0.05)


def tried(program: str) -> list[str]:
    """The paths ``os.execvp`` tries for a bare program name: one per ``PATH`` entry, up to the hit.

    The server has the ``PATH`` of this process.  An entry that is listed
    twice is tried twice.
    """
    paths = []
    for directory in os.get_exec_path():
        candidate = os.path.join(directory, program)
        paths.append(candidate)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return paths
    raise AssertionError(f"{program} is not on PATH")


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def launch(server: Server, what: str, stderr: str = "pipe") -> dict[str, Any]:
    """Have the application launch ``what`` towards the forbidden destination."""
    return server.probe("launch", FORBIDDEN_NAME, OTHER_PORT, what=what, stderr=stderr)


def child_of(report: dict[str, Any]) -> dict[str, Any]:
    """The report a Python child printed, from what the application captured of its stdout."""
    assert report["outcome"] == "reached", report
    return json.loads(report["stdout"].strip().splitlines()[-1])


# ── Every worker class, two workers, a locked policy ──────────────────


@pytest.fixture(scope="module", params=list(WORKER_MODELS))
def model(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(model: str) -> Server:
    return start_server(gunicorn(model), env={"TETH_ACTIVATE": "locked"})


class TestWorkerModels:
    def test_every_worker_runs_on_gevent_and_holds_the_locked_policy(
        self, server: Server, model: str
    ) -> None:
        answers = server.each_worker("/arrangement", 2)
        assert server.pid not in answers
        for pid, me in answers.items():
            assert me["ppid"] == server.pid
            assert me["imported_in_pid"] == (server.pid if "preload" in model else pid)
            assert (me["active"], me["locked"]) == (True, True), me
            assert me["socket_patched"] is True, me
            assert me["popen"] == "gevent.subprocess.Popen", me
            assert me["resolver"] == "gevent.resolver.thread.Resolver", me
            assert me["greenlet"] == "Greenlet", me

    @pytest.mark.parametrize("op", OPS)
    def test_every_worker_reaches_the_allowed_destination(self, server: Server, op: str) -> None:
        for report in server.each_worker(probe_path(op, ALLOWED_NAME, ALLOWED_PORT), 2).values():
            assert report["outcome"] == "reached", report
            assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize("op", OPS)
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_every_worker_refuses_a_destination_outside_the_allow_list(
        self, server: Server, op: str, host: str, port: int
    ) -> None:
        for report in server.each_worker(probe_path(op, host, port), 2).values():
            assert_refused(report)
        assert arrivals() == {}

    def test_greenlets_that_overlap_each_get_their_own_answer(self, server: Server) -> None:
        # Forty requests at once on two workers: every greenlet looks a name
        # up and connects while others are between their lookup and their connect.
        destinations = [(ALLOWED_NAME, ALLOWED_PORT), (FORBIDDEN_NAME, ALLOWED_PORT)] * 20

        def ask(destination: tuple[str, int]) -> dict[str, Any]:
            return server.probe("connect", *destination, hold=0.05)

        with ThreadPoolExecutor(max_workers=len(destinations)) as pool:
            reports = list(pool.map(ask, destinations))
        for (host, _), report in zip(destinations, reports, strict=True):
            assert report["outcome"] == ("reached" if host == ALLOWED_NAME else "blocked"), report
        assert arrivals() == {AT_ALLOWED: 20}

    def test_an_uncaught_refusal_is_a_500_and_the_workers_survive(self, server: Server) -> None:
        before = server.each_worker("/whoami", 2)
        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)
        assert server.get(path).status == 500
        assert arrivals() == {}
        server.wait_log(f"EgressBlocked: Blocked by tethered: {FORBIDDEN_NAME} is not in the allow")
        assert set(server.each_worker("/whoami", 2)) == set(before)

    def test_a_python_child_of_every_worker_inherits_the_locked_policy(
        self, server: Server
    ) -> None:
        path = probe_path("child", FORBIDDEN_NAME, OTHER_PORT)
        for pid, report in server.each_worker(path, 2).items():
            assert report["outcome"] == "reached", report
            child = report["child"]
            assert child["ppid"] == pid
            assert (child["active"], child["locked"]) == (True, True), child
            assert_refused(child)
        assert arrivals() == {}

    # Not gevent_pywsgi: that worker does not count requests, so --max-requests replaces nothing.
    @pytest.mark.parametrize("recycling", ["gevent", "gevent-preload"])
    def test_a_worker_started_after_max_requests_enforces_the_policy(self, recycling: str) -> None:
        command = gunicorn(recycling, "--max-requests", "5")
        replaced = start_server(command, env={"TETH_ACTIVATE": "locked"})
        first = replaced.each_worker("/whoami", 2)
        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in replaced.each_worker(path, 2, exclude=first).values():
            assert report["ppid"] == replaced.pid
            assert (report["active"], report["locked"]) == (True, True), report
            assert_refused(report)
        assert arrivals() == {}
        replaced.wait_log("Autorestarting worker after current request")


# ── What gevent's hub makes of a refused lookup ───────────────────────


class TestHubTraceback:
    def test_gevent_prints_a_traceback_for_every_refused_lookup(self) -> None:
        """Limit: a refused name lookup is reported twice, by tethered and by gevent's hub.

        The lookup runs in gevent's thread pool, and the hub prints the
        traceback of everything that fails there unless the exception type
        is in its ``NOT_ERROR``.  The application still gets ``EgressBlocked``.
        """
        server = start_server(gunicorn("gevent", workers=1), env={"TETH_ACTIVATE": "locked"})
        assert_refused(server.probe("connect", FORBIDDEN_NAME, OTHER_PORT))
        assert arrivals() == {}
        server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")
        server.wait_log(rf"<built-in function getaddrinfo>\) {HUB_TRACEBACK}")
        assert server.log.count("Traceback (most recent call last)") == 1

    def test_an_application_can_tell_the_hub_that_a_refusal_is_not_its_error(self) -> None:
        # gevent_app adds tethered.EgressBlocked to the hub's NOT_ERROR.
        env = {"TETH_ACTIVATE": "locked", "GEVENT_QUIET": "1"}
        server = start_server(gunicorn("gevent", workers=1), env=env)
        assert_refused(server.probe("connect", FORBIDDEN_NAME, OTHER_PORT))
        assert arrivals() == {}
        server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")
        # One more request, so that anything the hub had to say about the first is in the log.
        assert server.probe("connect", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
        assert HUB_TRACEBACK not in server.log
        assert "Traceback" not in server.log


# ── Launches: what the application sees ───────────────────────────────


@pytest.fixture(scope="class", params=["plain", "locked"])
def policy(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="class")
def warning(policy: str) -> Server:
    """One gevent worker under the default ``external_subprocess_policy`` (warn)."""
    return start_server(gunicorn("gevent", workers=1), env={"TETH_ACTIVATE": policy})


@pytest.fixture(scope="class")
def blocking() -> Server:
    """One gevent worker, a locked policy, ``external_subprocess_policy="block"``."""
    env = {"TETH_ACTIVATE": "locked", "TETH_ESP": "block"}
    return start_server(gunicorn("gevent", workers=1), env=env)


class TestLaunchesUnderWarn:
    def test_a_child_started_with_sys_executable_inherits_and_nothing_is_added_to_its_output(
        self, warning: Server, policy: str
    ) -> None:
        report = launch(warning, "executable")
        child = child_of(report)
        assert (child["active"], child["locked"]) == (True, policy == "locked"), child
        assert_refused(child)
        assert arrivals() == {}
        assert LAUNCH_WARNING.findall(report["stderr"]) == []
        assert EXEC_COMPLETED not in report["stderr"]
        assert "external subprocess" not in warning.log_of_this_test

    def test_a_child_given_an_environment_without_the_policy_is_launched_with_it(
        self, warning: Server, policy: str
    ) -> None:
        """Under gevent this launch is an ``os.exec*`` of the same interpreter, which tethered
        carries out with the policy added, under a lock too.  (Under gunicorn's sync worker the
        same code is a ``subprocess.Popen`` event and a locked policy refuses it.)  Under a lock
        tethered says so, in the forked child: the line is in the stderr the application captures.
        """
        report = launch(warning, "clean_env")
        child = child_of(report)
        assert (child["active"], child["locked"]) == (True, policy == "locked"), child
        assert_refused(child)
        assert arrivals() == {}
        completed = [line for line in report["stderr"].splitlines() if EXEC_COMPLETED in line]
        if policy == "locked":
            assert len(completed) == 1, report["stderr"]
            # The forked child logged it, and then became the Python child.
            assert completed[0].startswith(f"LOG pid={child['pid']} tethered WARNING"), completed
        else:
            assert completed == []
        assert EXEC_COMPLETED not in warning.log_of_this_test

    def test_the_warning_about_a_child_without_site_is_in_its_captured_stderr(
        self, warning: Server
    ) -> None:
        """Limit: "python -S" is launched with a warning and holds no policy (as everywhere), and
        under gevent the warning is in the child's captured stderr, not in the server log.
        """
        report = launch(warning, "no_site")
        child = child_of(report)
        assert child["active"] is False, child
        assert child["outcome"] == "reached", child
        assert arrivals() == {AT_FORBIDDEN: 1}
        assert LAUNCH_WARNING.findall(report["stderr"]) == [child["executable"]]
        assert "external subprocess" not in warning.log_of_this_test

    def test_a_child_started_as_python3_is_warned_about_once_per_path_entry_tried(
        self, warning: Server, policy: str
    ) -> None:
        """Limit: the warning is repeated for every ``PATH`` directory ``os.execvp`` tries, in the
        child's captured stderr.  The child itself does inherit the policy.
        """
        report = launch(warning, "path_python")
        child = child_of(report)
        assert (child["active"], child["locked"]) == (True, policy == "locked"), child
        assert_refused(child)
        assert arrivals() == {}
        assert LAUNCH_WARNING.findall(report["stderr"]) == tried("python3")
        assert "external subprocess" not in warning.log_of_this_test

    def test_a_tool_is_not_restricted_and_the_warnings_are_in_its_captured_stderr(
        self, warning: Server
    ) -> None:
        """Limit: an external tool is launched (the documented default) and reaches anything; the
        warnings, one per ``PATH`` directory tried, are in the stderr the application captured.
        """
        report = launch(warning, "tool")
        assert report["outcome"] == "reached", report
        assert report["returncode"] == 0, report
        assert report["stdout"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}\n"
        assert arrivals() == {AT_FORBIDDEN: 1}
        candidates = tried("bash")
        assert LAUNCH_WARNING.findall(report["stderr"]) == candidates
        # Nothing but those warnings: bash itself wrote nothing to stderr.
        assert len(report["stderr"].splitlines()) == len(candidates), report["stderr"]
        assert "external subprocess" not in warning.log_of_this_test

    def test_with_stderr_sent_to_stdout_the_warnings_come_before_the_output_of_the_tool(
        self, warning: Server
    ) -> None:
        """Limit: ``stderr=subprocess.STDOUT`` puts tethered's warnings into the captured output
        of the tool, ahead of what the tool printed.
        """
        report = launch(warning, "tool", stderr="stdout")
        assert report["outcome"] == "reached", report
        lines = report["stdout"].splitlines()
        candidates = tried("bash")
        assert LAUNCH_WARNING.findall("\n".join(lines[:-1])) == candidates
        assert len(lines) == len(candidates) + 1, lines
        assert lines[-1] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}"
        assert arrivals() == {AT_FORBIDDEN: 1}

    def test_with_stderr_inherited_the_warnings_are_in_the_server_log(
        self, warning: Server
    ) -> None:
        worker = warning.get("/whoami").json()["pid"]
        report = launch(warning, "tool", stderr="inherit")
        assert report["outcome"] == "reached", report
        assert report["stdout"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}\n"
        assert report["stderr"] is None
        assert arrivals() == {AT_FORBIDDEN: 1}
        last = re.escape(tried("bash")[-1])
        logged = warning.wait_log(rf"LOG pid=(\d+) tethered WARNING [^\n]*os\.exec\*\(b?'?{last}")
        assert LAUNCH_WARNING.findall(warning.log_of_this_test) == tried("bash")
        # Logged by the forked child, not by the worker.
        assert int(logged.group(1)) not in (worker, warning.pid)


class TestLaunchesUnderBlock:
    def test_a_child_started_with_sys_executable_is_launched_and_inherits(
        self, blocking: Server
    ) -> None:
        report = launch(blocking, "executable")
        child = child_of(report)
        assert (child["active"], child["locked"]) == (True, True), child
        assert child["external_subprocess_policy"] == "block"
        assert_refused(child)
        assert arrivals() == {}

    def test_a_child_given_an_environment_without_the_policy_is_launched_with_it(
        self, blocking: Server
    ) -> None:
        report = launch(blocking, "clean_env")
        child = child_of(report)
        assert (child["active"], child["locked"]) == (True, True), child
        assert child["external_subprocess_policy"] == "block"
        assert_refused(child)
        assert arrivals() == {}
        assert EXEC_COMPLETED in report["stderr"]

    @pytest.mark.parametrize(
        ("what", "program"),
        [("no_site", None), ("path_python", "python3"), ("tool", "bash")],
    )
    def test_any_other_launch_is_refused_in_the_forked_child_and_raised_in_the_worker(
        self, blocking: Server, what: str, program: str | None
    ) -> None:
        """The refusal happens in the forked child; gevent pickles the exception and raises it
        from ``Popen`` in the worker, so the application gets ``SubprocessBlocked`` as usual.
        It names the first path that was tried, which need not exist.
        """
        me = blocking.get("/whoami").json()
        report = launch(blocking, what)
        assert_refused(report, SUBPROCESS_BLOCKED)
        first = me["executable"] if program is None else tried(program)[0]
        assert re.search(rf"os\.exec\*\(b?'?{re.escape(first)}'?\)", report["message"]), report
        assert arrivals() == {}
        # The forked child is gone: the master and its one worker are all there is.
        wait_until(lambda: len(blocking.pids()) == 2, "the forked child exits")

    def test_a_refused_launch_is_not_in_the_server_log_when_stderr_is_captured(
        self, blocking: Server
    ) -> None:
        """Limit: tethered logs the refusal in the forked child, whose stderr is the pipe; the
        launch fails, nothing reads the pipe, and the line is lost.  The exception is all there is.
        """
        assert_refused(launch(blocking, "tool"), SUBPROCESS_BLOCKED)
        assert_refused(blocking.probe("connect", FORBIDDEN_NAME, OTHER_PORT))
        blocking.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")
        assert "blocked external subprocess launch" not in blocking.log_of_this_test
        assert arrivals() == {}

    def test_a_refused_launch_is_in_the_server_log_when_stderr_is_inherited(
        self, blocking: Server
    ) -> None:
        assert_refused(launch(blocking, "tool", stderr="inherit"), SUBPROCESS_BLOCKED)
        first = re.escape(tried("bash")[0])
        blocking.wait_log(rf"blocked external subprocess launch: os\.exec\*\(b?'?{first}")
        assert arrivals() == {}


# ── Resolvers ─────────────────────────────────────────────────────────


def resolving_with(resolver: str, **env: str) -> Server:
    settings = {"TETH_ACTIVATE": "locked", "GEVENT_RESOLVER": resolver, **env}
    server = start_server(gunicorn("gevent", workers=1), env=settings)
    module = {"thread": "thread", "ares": "ares", "block": "blocking"}[resolver]
    assert server.get("/arrangement").json()["resolver"] == f"gevent.resolver.{module}.Resolver"
    return server


class TestResolvers:
    @pytest.mark.parametrize("resolver", ["thread", "block"])
    def test_a_lookup_through_getaddrinfo_is_refused_before_any_query_is_sent(
        self, resolver: str
    ) -> None:
        server = resolving_with(resolver)
        report = server.probe("connect", UNLISTED_NAME, OTHER_PORT)
        assert_refused(report)
        assert report["message"] == f"Blocked by tethered: {UNLISTED_NAME} is not in the allow list"
        assert dns_queries() == {}
        report = server.probe("connect", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 1}

    def test_the_blocking_resolver_leaves_the_hub_out_of_it(self) -> None:
        server = resolving_with("block")
        assert_refused(server.probe("connect", FORBIDDEN_NAME, OTHER_PORT))
        server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")
        assert "Traceback" not in server.log

    def test_a_lookup_through_c_ares_is_not_seen_and_the_name_leaves_in_a_dns_query(self) -> None:
        """Limit: with ``GEVENT_RESOLVER=ares`` name lookups raise no audit event.  The name of a
        host that no rule allows is sent to the DNS server, under a locked policy.
        """
        server = resolving_with("ares")
        report = server.probe("connect", UNLISTED_NAME, OTHER_PORT)
        # Not a refusal: the application gets the resolver's own answer (there is no such name).
        assert report["outcome"] == "error", report
        assert report["exception"] == "socket.gaierror", report
        assert dns_queries().get(f"{UNLISTED_NAME}/A") == 1, dns_queries()
        assert arrivals() == {}
        assert "tethered: blocked" not in server.log

    def test_under_c_ares_a_connection_is_still_checked_by_its_address(self) -> None:
        server = resolving_with("ares")
        report = server.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert_refused(report)
        # Refused at the connection, by address: the lookup went through unseen.
        assert report["message"] == (
            f"Blocked by tethered: {FORBIDDEN_ADDR}:{OTHER_PORT} is not in the allow list"
        )
        assert arrivals() == {}

    @pytest.mark.parametrize("op", OPS)
    def test_under_c_ares_an_allowed_hostname_is_refused(self, op: str) -> None:
        """Limit: tethered saw no lookup, so the connection is to an address it knows no name for,
        and a rule that names a host does not match.  Refused although allowed.
        """
        server = resolving_with("ares")
        report = server.probe(op, ALLOWED_NAME, ALLOWED_PORT)
        assert_refused(report)
        assert report["message"] == (
            f"Blocked by tethered: {ALLOWED_ADDR}:{ALLOWED_PORT} is not in the allow list"
        )
        assert arrivals() == {}

    def test_under_c_ares_a_rule_that_names_the_address_still_allows(self) -> None:
        server = resolving_with("ares", TETH_ALLOW=f"{ALLOWED_ADDR}:{ALLOWED_PORT}")
        report = server.probe("connect", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 1}

    def test_without_tethered_c_ares_resolves_the_allowed_name(self) -> None:
        # The control for the two limits above: the resolver works, and its queries are counted.
        server = start_server(
            gunicorn("gevent", workers=1), env={"TETH_ACTIVATE": "none", "GEVENT_RESOLVER": "ares"}
        )
        report = server.probe("connect", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 1}
