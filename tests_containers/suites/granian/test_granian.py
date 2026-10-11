"""granian, a server written in Rust: its three interfaces and every event loop it offers.

granian's main process never imports the application.  Each worker does, after
granian has created the worker's event loop: a fork of the main process up to
Python 3.13, a new interpreter from 3.14 on.

**Which loop.**  ``--loop auto`` (the default) takes rloop if it can be
imported, else uvloop, else asyncio's own.  And granian imports every loop
package it finds as soon as granian itself is imported, in the main process
and in every worker, whichever ``--loop`` was asked for.  So what a policy
meets depends on what is installed next to granian (``loop_packages.py``
arranges that per server):

* nothing (``pip install granian``): the standard event loop; enforced.
* rloop (``granian[rloop]``): a Rust event loop that makes its connections,
  lookups and launches through Python's ``socket`` and ``subprocess`` modules,
  so those are seen and enforced.  One way out is not: a datagram sent with
  ``transport.sendto(data, addr)`` on an unconnected endpoint goes out below
  Python, and no audit event is raised for it.
* uvloop (``granian[uvloop]``): ``activate()`` refuses and the server does not
  start, on uvloop and also with ``--loop asyncio`` or ``--loop rloop``,
  because uvloop is loaded all the same.  It works when the policy is in
  place before granian is imported (``launcher.py``): uvloop is then not
  loaded, and ``auto`` goes on to rloop or asyncio.

Also here: ASGI, RSGI (``probe_rsgi.py``) and WSGI, ``--workers``, workers
started later (SIGHUP, a killed worker under ``--respawn-failed-workers``).
Not here: ``--reload`` (needs the watchfiles extra), ``--workers-lifetime``
(sixty seconds at least), the embedded server, free-threaded builds.

The applications allow ``allowed.test:9001``.  Each test asserts what the
application reported and what arrived in the world.
"""

from __future__ import annotations

import signal
from typing import TYPE_CHECKING, Any

import loop_packages
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
from harness.servers import registry

if TYPE_CHECKING:
    from collections.abc import Iterator

STANDARD_LOOP = "asyncio.unix_events._UnixSelectorEventLoop"
RLOOP = "rloop.loop.RLoop"
UVLOOP = "uvloop.Loop"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"
AT_FORBIDDEN_UDP = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/udp"

#: The application of each interface, and a route that opens a TCP connection there.
INTERFACES = {
    "asgi": {"app": "probe_asgi:app", "stream": "open_connection"},
    "rsgi": {"app": "probe_rsgi:app", "stream": "open_connection"},
    "wsgi": {"app": "probe_wsgi:application", "stream": "connect"},
}
#: The ways to open a TCP connection from a coroutine.
STREAM_OPS = ["open_connection", "create_connection", "sock_connect", "to_thread", "connect"]
#: Destinations the allow list does not cover.
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]
ACTIVATE_REFUSED = "RuntimeError: tethered: activate() refused — uvloop is loaded in this process."
UVLOOP_LOADED = "tethered: uvloop is loaded in this process."
UVLOOP_NOT_LOADED = "tethered: refused to load uvloop while a policy is active"


@pytest.fixture(scope="session", autouse=True)
def _loop_packages_set_aside() -> Iterator[None]:
    """uvloop and rloop are installed for the servers that ask for them, and for no other."""
    loop_packages.set_aside()
    try:
        yield
    finally:
        loop_packages.restore()


def granian(
    interface: str = "asgi", *options: str, loop: str | None = None, app: str | None = None
) -> list[str]:
    """The command line; without ``loop`` granian chooses (``--loop auto``)."""
    command = ["granian", "--interface", interface, "--host", "127.0.0.1", "--port", "{port}"]
    if loop is not None:
        command += ["--loop", loop]
    return [*command, *options, app or INTERFACES[interface]["app"]]


def env(activate: str, *installed: str, **more: str) -> dict[str, str]:
    """The environment of a server that finds ``installed`` (of uvloop and rloop) and no other."""
    return {
        "TETH_ACTIVATE": activate,
        "PYTHONPATH": loop_packages.pythonpath(*installed),
        **more,
    }


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_enforcing(report: dict[str, Any], loop: str | None, *, locked: bool) -> None:
    assert report["active"] is True, report
    assert report["locked"] is locked, report
    assert report["loop"] == loop, report


def refused_start(argv: list[str], environment: dict[str, str]) -> Server:
    """Start a server that must not come up; returns it, stopped, for its log."""
    with pytest.raises(AssertionError, match="exited with status"):
        start_server(argv, env=environment)
    return registry.ended[-1]


# ── Which loop, and what a policy meets on it ─────────────────────────

#: (installed, --loop) -> the loop the application runs on.
ENFORCED_CHOICES = [
    pytest.param((), None, STANDARD_LOOP, id="nothing-installed-auto"),
    pytest.param((), "asyncio", STANDARD_LOOP, id="nothing-installed-asyncio"),
    pytest.param(("rloop",), None, RLOOP, id="rloop-installed-auto"),
    pytest.param(("rloop",), "rloop", RLOOP, id="rloop-installed-rloop"),
    pytest.param(("rloop",), "asyncio", STANDARD_LOOP, id="rloop-installed-asyncio"),
]
ON_UVLOOP = [
    pytest.param(("uvloop",), None, id="uvloop-installed-auto"),
    pytest.param(("uvloop",), "uvloop", id="uvloop-installed-uvloop"),
    pytest.param(("uvloop", "rloop"), "uvloop", id="both-installed-uvloop"),
]
NOT_ON_UVLOOP = [
    pytest.param(("uvloop",), "asyncio", STANDARD_LOOP, id="uvloop-installed-asyncio"),
    pytest.param(("uvloop", "rloop"), None, RLOOP, id="both-installed-auto"),
    pytest.param(("uvloop", "rloop"), "rloop", RLOOP, id="both-installed-rloop"),
    pytest.param(("uvloop", "rloop"), "asyncio", STANDARD_LOOP, id="both-installed-asyncio"),
]


class TestLoopChoice:
    @pytest.mark.parametrize(("installed", "loop", "expected"), ENFORCED_CHOICES)
    def test_the_policy_is_enforced_on_the_loop_granian_picks(
        self, installed: tuple[str, ...], loop: str | None, expected: str
    ) -> None:
        server = start_server(granian(loop=loop), env=env("locked", *installed))
        assert_enforcing(server.get("/whoami").json(), expected, locked=True)
        assert_refused(server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT))
        assert_refused(server.probe("open_connection", FORBIDDEN_ADDR, OTHER_PORT))
        assert arrivals() == {}
        report = server.probe("open_connection", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 1}

    @pytest.mark.parametrize(("installed", "loop", "expected"), ENFORCED_CHOICES)
    def test_without_tethered_the_same_loop_is_picked(
        self, installed: tuple[str, ...], loop: str | None, expected: str
    ) -> None:
        # The control: the loop is granian's choice, not something tethered moved it to.
        server = start_server(granian(loop=loop), env=env("none", *installed))
        me = server.get("/whoami").json()
        assert me["tethered_imported"] is False
        assert me["loop"] == expected

    @pytest.mark.parametrize(("installed", "loop"), ON_UVLOOP)
    def test_without_tethered_these_run_on_uvloop(
        self, installed: tuple[str, ...], loop: str | None
    ) -> None:
        server = start_server(granian(loop=loop), env=env("none", *installed))
        assert server.get("/whoami").json()["loop"] == UVLOOP

    @pytest.mark.parametrize(("installed", "loop"), ON_UVLOOP)
    @pytest.mark.parametrize("policy", ["plain", "locked"])
    def test_on_uvloop_the_server_does_not_start_under_a_policy(
        self, installed: tuple[str, ...], loop: str | None, policy: str
    ) -> None:
        # The worker has its uvloop event loop before it imports the
        # application: activate() refuses.
        server = refused_start(granian(loop=loop), env(policy, *installed))
        assert ACTIVATE_REFUSED in server.log, server.log
        assert "Started worker" not in server.log
        assert server.pids() == []

    @pytest.mark.parametrize(("installed", "loop", "expected"), NOT_ON_UVLOOP)
    def test_with_uvloop_installed_the_server_does_not_start_on_another_loop_either(
        self, installed: tuple[str, ...], loop: str | None, expected: str
    ) -> None:
        """Limit: uvloop being installed is enough for ``activate()`` to refuse under granian.

        The application would run on a loop the policy is enforced on, as the
        run without tethered shows.  But granian has imported uvloop, like
        every loop package it finds, and ``activate()`` goes by that.
        """
        control = start_server(granian(loop=loop), env=env("none", *installed))
        assert control.get("/whoami").json()["loop"] == expected
        control.stop()

        server = refused_start(granian(loop=loop), env("locked", *installed))
        assert ACTIVATE_REFUSED in server.log, server.log
        assert "Started worker" not in server.log

    def test_log_only_on_uvloop_reports_nothing_of_the_event_loop(self) -> None:
        """Limit: a log-only policy over uvloop is activated, and reports nothing the loop does."""
        server = start_server(granian(loop="uvloop"), env=env("log_only", "uvloop"))
        me = server.get("/whoami").json()
        assert me["loop"] == UVLOOP
        assert me["log_only"] is True
        server.wait_log(UVLOOP_LOADED)
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        assert "tethered: blocked" not in server.log, server.log

    def test_log_only_on_the_standard_loop_reports_although_it_warns_about_uvloop(self) -> None:
        # The other side of the limit above: uvloop is installed and loaded
        # but not in use, the warning is given all the same, and the report
        # is complete.
        server = start_server(granian(loop="asyncio"), env=env("log_only", "uvloop"))
        assert server.get("/whoami").json()["loop"] == STANDARD_LOOP
        server.wait_log(UVLOOP_LOADED)
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")
        server.wait_log(f"tethered: blocked connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")


# ── One worker on each loop a policy is enforced on ───────────────────

LOOPS = {
    "asyncio": {"installed": (), "class": STANDARD_LOOP},
    "rloop": {"installed": ("rloop",), "class": RLOOP},
}


@pytest.fixture(scope="module", params=list(LOOPS))
def loop(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module", params=["plain", "locked"])
def mode(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(loop: str, mode: str) -> Server:
    """``granian --interface asgi``: one worker, on the loop ``auto`` picks of what is installed."""
    return start_server(granian(), env=env(mode, *LOOPS[loop]["installed"]))


class TestOneWorker:
    def test_the_worker_holds_the_policy_and_the_main_process_never_imported_the_application(
        self, server: Server, loop: str, mode: str
    ) -> None:
        me = server.get("/whoami").json()
        assert_enforcing(me, LOOPS[loop]["class"], locked=mode == "locked")
        assert me["pid"] != server.pid
        assert me["ppid"] == server.pid
        assert me["imported_in_pid"] == me["pid"]
        assert server.log.count("probe: pid") == 1, server.log

    def test_the_allowed_destination_is_reached(self, server: Server) -> None:
        for op in STREAM_OPS:
            report = server.probe(op, ALLOWED_NAME, ALLOWED_PORT)
            assert report["outcome"] == "reached", report
            assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert arrivals() == {AT_ALLOWED: len(STREAM_OPS)}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_destination_outside_the_allow_list_is_refused(
        self, server: Server, host: str, port: int
    ) -> None:
        for op in STREAM_OPS:
            assert_refused(server.probe(op, host, port))
        assert arrivals() == {}

    def test_loopback_stays_reachable(self, server: Server) -> None:
        for op in STREAM_OPS:
            report = server.probe(op, LOOPBACK_ADDR, OTHER_PORT)
            assert report["outcome"] == "reached", report
        assert arrivals() == {f"{LOOPBACK_ADDR}:{OTHER_PORT}/tcp": len(STREAM_OPS)}

    def test_a_lookup_of_the_allowed_name_is_answered(self, server: Server) -> None:
        report = server.probe("getaddrinfo", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert report["addresses"] == [ALLOWED_ADDR]

    def test_a_lookup_of_a_forbidden_name_is_refused(self, server: Server) -> None:
        assert_refused(server.probe("getaddrinfo", FORBIDDEN_NAME, OTHER_PORT))
        assert arrivals() == {}

    def test_a_connected_datagram_endpoint_reaches_the_allowed_destination(
        self, server: Server
    ) -> None:
        report = server.probe("datagram_connected", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {f"{ALLOWED_ADDR}:{ALLOWED_PORT}/udp": 1}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_connected_datagram_endpoint_is_refused(
        self, server: Server, host: str, port: int
    ) -> None:
        assert_refused(server.probe("datagram_connected", host, port))
        assert arrivals() == {}

    def test_an_uncaught_refusal_is_a_500_and_the_worker_keeps_serving(
        self, server: Server
    ) -> None:
        me = server.get("/whoami").json()
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)
        assert server.get(path).status == 500
        assert arrivals() == {}
        server.wait_log("Application callable raised an exception")
        server.wait_log(f"EgressBlocked: Blocked by tethered: {FORBIDDEN_NAME} is not in the allow")
        assert server.get("/whoami").json()["pid"] == me["pid"]
        report = server.probe("open_connection", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report

    def test_a_python_child_inherits_the_policy(self, server: Server, mode: str) -> None:
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        child = report["child"]
        assert child["ppid"] == report["pid"]
        assert child["active"] is True, child
        assert child["locked"] is (mode == "locked"), child
        assert_refused(child)
        assert arrivals() == {}

    def test_a_python_child_reaches_the_allowed_destination(self, server: Server) -> None:
        child = server.probe("child", ALLOWED_NAME, ALLOWED_PORT)["child"]
        assert child["outcome"] == "reached", child
        assert arrivals() == {AT_ALLOWED: 1}

    def test_a_tool_is_launched_with_a_warning_and_is_not_restricted(self, server: Server) -> None:
        # The default external_subprocess_policy.  The tool is not Python:
        # nothing enforces the allow list inside it.
        report = server.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["stdout"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}"
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(r"external subprocess launch detected: subprocess\.Popen\(bash\)")


class TestUnconnectedDatagrams:
    """``transport.sendto(data, addr)`` on an endpoint with no remote address.

    The address is numeric throughout: rloop 0.5.0 ends the worker when it is
    handed a host name there (a panic in its UDP code, with or without
    tethered), so a name cannot be compared between the two loops.
    """

    def test_on_the_standard_loop_the_datagram_is_refused(self) -> None:
        server = start_server(granian(), env=env("locked"))
        report = server.probe("datagram_unconnected", FORBIDDEN_ADDR, OTHER_PORT)
        assert_refused(report)
        assert report["notes"] == ["delivered to the protocol's connection_lost()"]
        assert arrivals() == {}

    @pytest.mark.parametrize("policy", ["plain", "locked", "locked,fail_closed"])
    def test_on_rloop_the_datagram_is_sent(self, policy: str) -> None:
        """Limit: rloop sends an unconnected datagram below Python, and it is not seen."""
        server = start_server(granian(), env=env(policy, "rloop"))
        assert server.get("/whoami").json()["loop"] == RLOOP
        report = server.probe("datagram_unconnected", FORBIDDEN_ADDR, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["reply"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}"
        assert arrivals() == {AT_FORBIDDEN_UDP: 1}
        assert "tethered: blocked" not in server.log, server.log

    def test_on_rloop_a_log_only_policy_does_not_report_the_datagram(self) -> None:
        """Limit: the same datagram is missing from a log-only policy's report."""
        server = start_server(granian(), env=env("log_only", "rloop"))
        report = server.probe("datagram_unconnected", FORBIDDEN_ADDR, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN_UDP: 1}
        assert "tethered: blocked" not in server.log, server.log
        # A connection from the same worker is reported.
        server.probe("open_connection", FORBIDDEN_ADDR, OTHER_PORT)
        server.wait_log(f"tethered: blocked connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")


# ── What an audit hook sees of rloop, with no tethered involved ───────


@pytest.fixture(scope="class")
def traced_rloop() -> Server:
    """A worker on rloop with no tethered at all and every audit event printed."""
    return start_server(granian(loop="rloop", app="traced_asgi:app"), env=env("none", "rloop"))


class TestWhatAnAuditHookSeesOfRloop:
    """The evidence under the rloop results: which of its operations raise audit events."""

    def events(self, server: Server) -> list[list[str]]:
        lines = server.log_of_this_test.splitlines()
        return [line.split()[2:] for line in lines if line.startswith("AUDIT")]

    @pytest.mark.parametrize(
        ("op", "arrival"),
        [
            ("open_connection", AT_FORBIDDEN),
            ("create_connection", AT_FORBIDDEN),
            ("sock_connect", AT_FORBIDDEN),
            ("datagram_connected", AT_FORBIDDEN_UDP),
        ],
    )
    def test_a_connection_raises_the_lookup_and_the_connect_event(
        self, traced_rloop: Server, op: str, arrival: str
    ) -> None:
        report = traced_rloop.probe(op, FORBIDDEN_NAME, OTHER_PORT)
        assert report["loop"] == RLOOP
        assert report["tethered_imported"] is False
        assert report["outcome"] == "reached", report
        assert arrivals() == {arrival: 1}
        assert self.events(traced_rloop) == [
            ["socket.getaddrinfo", f"{FORBIDDEN_NAME}:{OTHER_PORT}"],
            ["socket.connect", f"{FORBIDDEN_ADDR}:{OTHER_PORT}"],
        ]

    def test_a_lookup_raises_its_event(self, traced_rloop: Server) -> None:
        report = traced_rloop.probe("getaddrinfo", FORBIDDEN_NAME, OTHER_PORT)
        assert report["addresses"] == [FORBIDDEN_ADDR]
        assert self.events(traced_rloop) == [
            ["socket.getaddrinfo", f"{FORBIDDEN_NAME}:{OTHER_PORT}"]
        ]

    def test_a_launch_raises_its_event(self, traced_rloop: Server) -> None:
        report = traced_rloop.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        assert ["subprocess.Popen", "bash"] in self.events(traced_rloop)

    def test_an_unconnected_datagram_raises_no_event_at_all(self, traced_rloop: Server) -> None:
        report = traced_rloop.probe("datagram_unconnected", FORBIDDEN_ADDR, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN_UDP: 1}
        assert self.events(traced_rloop) == []


# ── The other interfaces ──────────────────────────────────────────────


@pytest.fixture(scope="class", params=["rsgi", "wsgi"])
def interface(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="class")
def served(interface: str) -> Server:
    """One worker with a locked policy, serving the probe application of ``interface``."""
    return start_server(granian(interface), env=env("locked"))


class TestInterfaces:
    def test_the_worker_holds_the_locked_policy(self, served: Server, interface: str) -> None:
        me = served.get("/whoami").json()
        # RSGI handlers are coroutines on the event loop; WSGI handlers run in
        # threads that granian starts from Rust, with no event loop.
        assert_enforcing(me, STANDARD_LOOP if interface == "rsgi" else None, locked=True)
        assert (me["thread"] == "MainThread") is (interface == "rsgi")
        assert me["ppid"] == served.pid

    def test_the_allowed_destination_is_reached(self, served: Server, interface: str) -> None:
        report = served.probe(INTERFACES[interface]["stream"], ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 1}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_destination_outside_the_allow_list_is_refused(
        self, served: Server, interface: str, host: str, port: int
    ) -> None:
        assert_refused(served.probe(INTERFACES[interface]["stream"], host, port))
        assert arrivals() == {}

    def test_an_uncaught_refusal_is_a_500_and_the_worker_keeps_serving(
        self, served: Server, interface: str
    ) -> None:
        me = served.get("/whoami").json()
        op = INTERFACES[interface]["stream"]
        assert served.get(probe_path(op, FORBIDDEN_NAME, OTHER_PORT, uncaught=1)).status == 500
        assert arrivals() == {}
        served.wait_log("Application callable raised an exception")
        assert served.get("/whoami").json()["pid"] == me["pid"]

    def test_a_python_child_inherits_the_locked_policy(self, served: Server) -> None:
        report = served.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["child"]["locked"] is True, report
        assert_refused(report["child"])
        assert arrivals() == {}


# ── --workers, and workers that are started later ─────────────────────


@pytest.fixture(scope="class", params=list(INTERFACES))
def workers(request: pytest.FixtureRequest) -> Server:
    """Two workers, each of which imports the application and locks the policy."""
    return start_server(granian(request.param, "--workers", "2"), env=env("locked"))


def stream_of(server: Server) -> str:
    """The TCP route of the interface a server was started with."""
    return INTERFACES[server.argv[server.argv.index("--interface") + 1]]["stream"]


class TestWorkers:
    def test_each_worker_activates_the_policy_when_it_imports_the_application(
        self, workers: Server
    ) -> None:
        answers = workers.each_worker("/whoami", 2)
        assert workers.pid not in answers
        for pid, me in answers.items():
            assert me["locked"] is True, me
            assert me["ppid"] == workers.pid
            assert me["imported_in_pid"] == pid

    def test_every_worker_reaches_the_allowed_destination(self, workers: Server) -> None:
        path = probe_path(stream_of(workers), ALLOWED_NAME, ALLOWED_PORT)
        for report in workers.each_worker(path, 2).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_every_worker_refuses_a_destination_outside_the_allow_list(
        self, workers: Server, host: str, port: int
    ) -> None:
        for report in workers.each_worker(probe_path(stream_of(workers), host, port), 2).values():
            assert_refused(report)
        assert arrivals() == {}


class TestLaterWorkers:
    def assert_replacements_refuse(
        self, server: Server, replacements: dict[int, dict[str, Any]]
    ) -> None:
        for pid, report in replacements.items():
            assert report["ppid"] == server.pid
            assert report["imported_in_pid"] == pid
            assert report["locked"] is True, report
            assert_refused(report)
        assert arrivals() == {}

    @pytest.mark.parametrize("interface", list(INTERFACES))
    def test_workers_started_by_sighup_enforce_the_policy(self, interface: str) -> None:
        command = granian(interface, "--workers", "2", "--respawn-interval", "0.2")
        server = start_server(command, env=env("locked"))
        first = server.each_worker("/whoami", 2)
        server.send_signal(signal.SIGHUP)

        path = probe_path(INTERFACES[interface]["stream"], FORBIDDEN_NAME, OTHER_PORT)
        self.assert_replacements_refuse(server, server.each_worker(path, 2, exclude=first))
        # granian's own words for a reload.
        server.wait_log("HUP signal received, gracefully respawning workers")

        path = probe_path(INTERFACES[interface]["stream"], ALLOWED_NAME, ALLOWED_PORT)
        for report in server.each_worker(path, 2, exclude=first).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    def test_a_worker_that_replaces_a_killed_one_enforces_the_policy(self) -> None:
        command = granian("asgi", "--workers", "2", "--respawn-failed-workers")
        server = start_server(command, env=env("locked"))
        first = server.each_worker("/whoami", 2)
        server.send_signal(signal.SIGKILL, min(first))

        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        self.assert_replacements_refuse(server, server.each_worker(path, 1, exclude=first))
        server.wait_log("Unexpected exit from worker")


# ── A launcher that locks the policy before granian is imported ───────

LAUNCHES = {
    "workers-only-inherit": {},
    "application-activates-the-same-policy": {"TETH_ACTIVATE": "locked"},
    "workers-only-inherit-under-block": {"TETH_ESP": "block"},
}


@pytest.fixture(scope="class", params=list(LAUNCHES))
def launched(request: pytest.FixtureRequest) -> Server:
    """``launcher.py``: ``activate(locked=True)``, then ``Granian(..., workers=2).serve()``.

    uvloop is installed: this is the arrangement that works with it.
    """
    environment = env("none", "uvloop", **LAUNCHES[request.param])
    return start_server(["python", "launcher.py", "asgi", "auto", "2"], env=environment)


class TestLauncher:
    def test_uvloop_is_not_loaded_and_both_workers_hold_the_locked_policy(
        self, launched: Server
    ) -> None:
        answers = launched.each_worker("/whoami", 2)
        for me in answers.values():
            assert_enforcing(me, STANDARD_LOOP, locked=True)
            assert me["ppid"] == launched.pid
        assert UVLOOP_NOT_LOADED in launched.log
        activated_by_the_application = launched.log.count("probe: pid")
        assert launched.log.count("tethered: activate() no-op") == activated_by_the_application

    def test_both_workers_reach_the_allowed_destination(self, launched: Server) -> None:
        path = probe_path("open_connection", ALLOWED_NAME, ALLOWED_PORT)
        for report in launched.each_worker(path, 2).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_both_workers_refuse_a_destination_outside_the_allow_list(
        self, launched: Server, host: str, port: int
    ) -> None:
        for report in launched.each_worker(probe_path("open_connection", host, port), 2).values():
            assert_refused(report)
        assert arrivals() == {}

    def test_a_python_child_of_a_worker_inherits_the_locked_policy(self, launched: Server) -> None:
        report = launched.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["child"]["locked"] is True, report
        assert_refused(report["child"])
        assert arrivals() == {}

    @pytest.mark.parametrize("interface", ["rsgi", "wsgi"])
    def test_the_other_interfaces_inherit_the_locked_policy_too(self, interface: str) -> None:
        command = ["python", "launcher.py", interface, "auto", "2"]
        server = start_server(command, env=env("none", "uvloop"))
        path = probe_path(INTERFACES[interface]["stream"], FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2).values():
            assert report["locked"] is True, report
            assert_refused(report)
        assert arrivals() == {}
        assert "probe: pid" not in server.log, "the application activated after all"

    def test_with_rloop_installed_as_well_auto_goes_on_to_rloop(self) -> None:
        command = ["python", "launcher.py", "asgi", "auto", "2"]
        server = start_server(command, env=env("none", "uvloop", "rloop"))
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2).values():
            assert_enforcing(report, RLOOP, locked=True)
            assert_refused(report)
        assert arrivals() == {}

    def test_asking_for_uvloop_by_name_does_not_start(self) -> None:
        # granian does not fall back from a loop that was asked for by name.
        command = ["python", "launcher.py", "asgi", "uvloop", "2"]
        server = refused_start(command, env("none", "uvloop"))
        assert UVLOOP_NOT_LOADED in server.log
        assert "RuntimeError: 'uvloop' implementation not available." in server.log
        assert "Started worker" not in server.log

    def test_a_worker_that_replaces_a_killed_one_inherits_the_locked_policy(self) -> None:
        command = ["python", "launcher.py", "asgi", "auto", "2", "respawn"]
        server = start_server(command, env=env("none", "uvloop"))
        first = server.each_worker("/whoami", 2)
        server.send_signal(signal.SIGKILL, min(first))

        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        (replacement,) = server.each_worker(path, 1, exclude=first).values()
        assert_enforcing(replacement, STANDARD_LOOP, locked=True)
        assert_refused(replacement)
        assert arrivals() == {}
        assert "probe: pid" not in server.log, "the application activated after all"


# ── The modes that do not refuse ──────────────────────────────────────


class TestNotEnforcing:
    def test_without_tethered_the_forbidden_destination_is_reached(self, loop: str) -> None:
        # The control: the same route, no policy.  It shows that the world's
        # counters move when something does arrive.
        server = start_server(granian(), env=env("none", *LOOPS[loop]["installed"]))
        me = server.get("/whoami").json()
        assert me["tethered_imported"] is False
        assert me["loop"] == LOOPS[loop]["class"]
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}

    def test_log_only_reports_the_connection_and_lets_it_through(self, loop: str) -> None:
        server = start_server(granian(), env=env("log_only", *LOOPS[loop]["installed"]))
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")
        server.wait_log(f"tethered: blocked connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")
