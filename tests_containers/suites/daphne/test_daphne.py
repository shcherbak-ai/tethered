"""daphne, the Twisted-based ASGI server that Django Channels uses.

daphne is one process: no master, no workers, no reload.  It runs Twisted's
reactor on a standard asyncio event loop and the application's coroutines on
that loop, so an application has two ways out, and the suite has two halves.

**asyncio, as ASGI applications use it** (``probe_asgi``): everything is seen
and enforced, as on any standard event loop.

**Twisted's own client API, used from a handler** (``probe_twisted.py``):
Twisted makes its connections, lookups and datagrams through Python's
``socket`` module and its launches through ``os.posix_spawn``, so all of it is
seen and nothing that is refused gets out.  What differs is how a refusal
comes back, because it is raised inside the reactor and not in the caller:

* a datagram (``transport.write(data, addr)``) and ``reactor.spawnProcess``
  raise it to the caller;
* a refused connection attempt is reported to the caller as Twisted's own
  ``TimeoutError``, when the attempt's timeout is over (30 seconds unless the
  caller says otherwise);
* a refused lookup is never reported at all: ``HostnameEndpoint.connect``,
  ``Agent.request`` and ``reactor.resolve`` return a ``Deferred`` that never
  fires, because Twisted's resolver expects ``socket.gaierror`` and nothing
  else.

tethered's own warning is in the log in every case; Twisted's traceback of
the refusal is only there with ``daphne -v 2``.

The applications allow ``allowed.test:9001``.  Each test asserts what the
application reported and what arrived in the world.
"""

from __future__ import annotations

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

STANDARD_LOOP = "asyncio.unix_events._UnixSelectorEventLoop"
ASYNCIO_REACTOR = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"
TWISTED_TIMEOUT = "twisted.internet.error.TimeoutError"
#: ``probe_twisted.CONNECT_TIMEOUT``: what Twisted is given for a connection attempt.
CONNECT_TIMEOUT = 1.0

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_ALLOWED_UDP = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/udp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"
AT_FORBIDDEN_UDP = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/udp"

#: The ways to open a TCP connection from a coroutine, with asyncio.
STREAM_OPS = ["open_connection", "create_connection", "sock_connect", "to_thread", "connect"]
#: The ways to open a TCP connection with Twisted.
TWISTED_OPS = ["connect_tcp", "endpoint", "agent"]
#: Destinations the allow list does not cover.
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]
#: Those of them that are refused when the connection is made, not at the lookup.
REFUSED_AT_CONNECT = [
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]
#: The Twisted application also sends datagrams, which Twisted takes by address only.
TWISTED_ALLOW = f"{ALLOWED_NAME}:{ALLOWED_PORT},{ALLOWED_ADDR}:{ALLOWED_PORT}"


def daphne(app: str, *options: str) -> list[str]:
    return ["daphne", "-b", "127.0.0.1", "-p", "{port}", *options, app]


def twisted_env(activate: str, **more: str) -> dict[str, str]:
    return {"TETH_ACTIVATE": activate, "TETH_ALLOW": TWISTED_ALLOW, **more}


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_enforcing(report: dict[str, Any], *, locked: bool) -> None:
    assert report["active"] is True, report
    assert report["locked"] is locked, report
    assert report["loop"] == STANDARD_LOOP, report


# ── asyncio, as an ASGI application uses it ───────────────────────────


@pytest.fixture(scope="module", params=["plain", "locked"])
def mode(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(mode: str) -> Server:
    """daphne with the asyncio probe application, which activates the policy when imported."""
    return start_server(daphne("probe_asgi:app"), env={"TETH_ACTIVATE": mode})


class TestAsyncioApi:
    def test_the_only_process_runs_the_standard_loop_with_the_policy(
        self, server: Server, mode: str
    ) -> None:
        me = server.get("/whoami").json()
        assert_enforcing(me, locked=mode == "locked")
        assert me["pid"] == server.pid
        assert server.pids() == [server.pid]

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

    @pytest.mark.parametrize("op", ["datagram_connected", "datagram_unconnected"])
    def test_a_datagram_reaches_the_allowed_destination(self, server: Server, op: str) -> None:
        report = server.probe(op, ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED_UDP: 1}

    @pytest.mark.parametrize("op", ["datagram_connected", "datagram_unconnected"])
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_refused_datagram_is_not_sent(
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
        server.wait_log(
            f"Exception inside application: Blocked by tethered: {FORBIDDEN_NAME} is not in the"
        )
        assert server.get("/whoami").json()["pid"] == server.pid
        assert server.probe("open_connection", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"

    def test_a_python_child_inherits_the_policy(self, server: Server, mode: str) -> None:
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        child = report["child"]
        assert child["ppid"] == server.pid
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


# ── Twisted's own client API, with no tethered involved ───────────────


@pytest.fixture(scope="class")
def traced() -> Server:
    """daphne with the Twisted probe application, no tethered, every audit event printed."""
    return start_server(daphne("traced_twisted:app"), env={"TETH_ACTIVATE": "none"})


class TestWhatAnAuditHookSeesOfTwisted:
    """The evidence under the Twisted results: its networking raises the audit events."""

    def events(self, server: Server) -> list[list[str]]:
        lines = server.log_of_this_test.splitlines()
        return [line.split()[2:] for line in lines if line.startswith("AUDIT")]

    @pytest.mark.parametrize("op", TWISTED_OPS)
    def test_a_connection_raises_the_lookup_and_the_connect_event(
        self, traced: Server, op: str
    ) -> None:
        report = traced.probe(op, FORBIDDEN_NAME, OTHER_PORT)
        assert report["tethered_imported"] is False
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        events = self.events(traced)
        assert ["socket.connect", f"{FORBIDDEN_ADDR}:{OTHER_PORT}"] in events, events
        # reactor.connectTCP looks the name up with port 0, the endpoints with the port.
        lookups = [target for event, target in events if event == "socket.getaddrinfo"]
        assert lookups in ([f"{FORBIDDEN_NAME}:0"], [f"{FORBIDDEN_NAME}:{OTHER_PORT}"]), events

    def test_a_datagram_raises_the_sendto_event(self, traced: Server) -> None:
        report = traced.probe("udp_write", FORBIDDEN_ADDR, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN_UDP: 1}
        assert self.events(traced) == [["socket.sendto", f"{FORBIDDEN_ADDR}:{OTHER_PORT}"]]

    def test_spawn_process_raises_posix_spawn_and_not_the_subprocess_event(
        self, traced: Server
    ) -> None:
        report = traced.probe("spawn_tool", FORBIDDEN_ADDR, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        assert self.events(traced) == [["os.posix_spawn", "bash"]]


# ── Twisted's own client API under a policy ───────────────────────────


@pytest.fixture(scope="class", params=["plain", "locked"])
def twisted(request: pytest.FixtureRequest) -> Server:
    """daphne with the Twisted probe application under a policy."""
    return start_server(daphne("probe_twisted:app"), env=twisted_env(request.param))


class TestTwistedApi:
    def test_the_handlers_use_the_reactor_daphne_runs(self, twisted: Server) -> None:
        me = twisted.get("/whoami").json()
        assert me["active"] is True
        assert me["reactor"] == ASYNCIO_REACTOR
        assert me["loop"] == STANDARD_LOOP

    @pytest.mark.parametrize("op", TWISTED_OPS)
    def test_the_allowed_destination_is_reached(self, twisted: Server, op: str) -> None:
        report = twisted.probe(op, ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert arrivals() == {AT_ALLOWED: 1}

    def test_a_datagram_reaches_the_allowed_address(self, twisted: Server) -> None:
        report = twisted.probe("udp_write", ALLOWED_ADDR, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED_UDP: 1}

    def test_a_refused_datagram_is_raised_to_the_caller(self, twisted: Server) -> None:
        report = twisted.probe("udp_write", FORBIDDEN_ADDR, OTHER_PORT)
        assert_refused(report)
        assert report["seconds"] < CONNECT_TIMEOUT
        assert arrivals() == {}

    @pytest.mark.parametrize("op", TWISTED_OPS)
    @pytest.mark.parametrize(("host", "port"), REFUSED_AT_CONNECT)
    def test_a_refused_connection_is_not_made_and_comes_back_as_a_timeout(
        self, twisted: Server, op: str, host: str, port: int
    ) -> None:
        """Limit: Twisted reports a refused connection attempt as its own ``TimeoutError``.

        The refusal is raised in the reactor's call, which the caller's
        ``Deferred`` knows nothing of; the attempt then runs into its timeout.
        """
        report = twisted.probe(op, host, port)
        assert report["outcome"] == "error", report
        assert report["exception"] == TWISTED_TIMEOUT, report
        assert report["seconds"] >= CONNECT_TIMEOUT * 0.9, report
        assert arrivals() == {}
        address = FORBIDDEN_ADDR if host == FORBIDDEN_ADDR else ALLOWED_ADDR
        twisted.wait_log(rf"tethered: blocked connect to .*{address}")

    def test_connect_tcp_reports_a_refused_lookup_as_a_timeout_too(self, twisted: Server) -> None:
        """Limit: ``reactor.connectTCP`` to a forbidden name ends in Twisted's ``TimeoutError``."""
        report = twisted.probe("connect_tcp", FORBIDDEN_NAME, OTHER_PORT)
        assert report["exception"] == TWISTED_TIMEOUT, report
        assert report["seconds"] >= CONNECT_TIMEOUT * 0.9, report
        assert arrivals() == {}
        twisted.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")

    @pytest.mark.parametrize("op", ["endpoint", "agent", "resolve"])
    def test_a_refused_lookup_is_never_reported_to_the_caller(
        self, twisted: Server, op: str
    ) -> None:
        """Limit: after a refused lookup the ``Deferred`` of these three never fires.

        The handler waits two and a half times the connection timeout Twisted
        was given and then gives up itself (``asyncio.wait_for``): what it
        reports is its own timeout, not anything Twisted said.
        """
        patience = 2.5 * CONNECT_TIMEOUT
        report = twisted.probe(op, FORBIDDEN_NAME, OTHER_PORT, patience=patience)
        assert report["outcome"] == "error", report
        assert report["exception"] == "builtins.TimeoutError", report
        assert report["seconds"] >= patience * 0.9, report
        assert arrivals() == {}
        twisted.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")
        # The server is not stuck: only that caller was.
        assert twisted.probe("connect_tcp", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"

    def test_a_tool_is_launched_with_a_warning_and_is_not_restricted(self, twisted: Server) -> None:
        report = twisted.probe("spawn_tool", FORBIDDEN_ADDR, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["stdout"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}"
        assert arrivals() == {AT_FORBIDDEN: 1}
        twisted.wait_log(r"external subprocess launch detected: os\.posix_spawn\(bash\)")

    def test_a_python_child_that_inherits_the_environment_inherits_the_policy(
        self, twisted: Server
    ) -> None:
        # spawnProcess(..., env=None): the child gets this process's environment.
        report = twisted.probe("spawn_child", FORBIDDEN_ADDR, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["child"]["active"] is True, report
        assert report["child"]["locked"] is report["locked"], report
        assert_refused(report["child"])
        assert arrivals() == {}


class TestTwistedSpawnProcessWithItsDefaultEnvironment:
    """``reactor.spawnProcess`` gives the child an empty environment unless told otherwise."""

    def test_under_a_locked_policy_the_child_is_not_launched(self) -> None:
        server = start_server(daphne("probe_twisted:app"), env=twisted_env("locked"))
        report = server.probe("spawn_child", FORBIDDEN_ADDR, OTHER_PORT, env="empty")
        assert_refused(report, SUBPROCESS_BLOCKED)
        assert "env strips _TETHERED_CHILD_POLICY" in report["message"]
        assert arrivals() == {}

    def test_under_a_plain_policy_the_child_runs_without_the_policy(self) -> None:
        """Limit: without a lock the child is launched, warned about, and holds no policy.

        The policy variable cannot be added to the environment of an
        ``os.posix_spawn``, as it is for ``subprocess``.
        """
        server = start_server(daphne("probe_twisted:app"), env=twisted_env("plain"))
        report = server.probe("spawn_child", FORBIDDEN_ADDR, OTHER_PORT, env="empty")
        assert report["outcome"] == "reached", report
        assert report["child"]["active"] is False, report
        assert report["child"]["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(
            r"external subprocess launch detected: os\.posix_spawn\(\S*python\S*\) — "
            "its environment lacks _TETHERED_CHILD_POLICY and cannot be rewritten"
        )

    def test_under_block_the_child_is_not_launched_without_a_lock_either(self) -> None:
        server = start_server(
            daphne("probe_twisted:app"), env=twisted_env("plain", TETH_ESP="block")
        )
        report = server.probe("spawn_child", FORBIDDEN_ADDR, OTHER_PORT, env="empty")
        assert_refused(report, SUBPROCESS_BLOCKED)
        assert arrivals() == {}
        # A tool is not launched either, and the refusal is raised to the caller.
        assert_refused(server.probe("spawn_tool", FORBIDDEN_ADDR, OTHER_PORT), SUBPROCESS_BLOCKED)
        assert arrivals() == {}
        server.wait_log(r"blocked external subprocess launch: os\.posix_spawn\(bash\)")
        # A child that inherits the environment is launched, and inherits the policy.
        report = server.probe("spawn_child", FORBIDDEN_ADDR, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert_refused(report["child"])
        assert arrivals() == {}


class TestWhereTheRefusalIsLogged:
    def test_at_the_default_verbosity_only_tethered_says_what_happened(self) -> None:
        server = start_server(daphne("probe_twisted:app"), env=twisted_env("locked"))
        report = server.probe("connect_tcp", FORBIDDEN_ADDR, OTHER_PORT)
        assert report["exception"] == TWISTED_TIMEOUT, report
        server.wait_log(f"tethered: blocked connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")
        server.stop()
        assert "EgressBlocked" not in server.log, server.log

    def test_with_verbosity_2_twisted_logs_the_refusal_with_its_traceback(self) -> None:
        command = daphne("probe_twisted:app", "-v", "2")
        server = start_server(command, env=twisted_env("locked"))
        report = server.probe("connect_tcp", FORBIDDEN_ADDR, OTHER_PORT)
        assert report["exception"] == TWISTED_TIMEOUT, report
        assert arrivals() == {}
        server.wait_log("while handling timed call")
        server.wait_log(
            f"EgressBlocked: Blocked by tethered: {FORBIDDEN_ADDR}:{OTHER_PORT} is not in the"
        )


# ── A launcher that locks the policy and then imports daphne ──────────


class TestLauncher:
    @pytest.mark.parametrize("app", ["probe_asgi:app", "probe_twisted:app"])
    @pytest.mark.parametrize("activate", ["none", "locked"])
    def test_daphne_starts_under_a_policy_that_is_already_locked(
        self, app: str, activate: str
    ) -> None:
        server = start_server(["python", "launcher.py", app], env={"TETH_ACTIVATE": activate})
        me = server.get("/whoami").json()
        assert_enforcing(me, locked=True)
        assert me["pid"] == server.pid
        # The application's activation of the same policy changes nothing.
        assert server.log.count("tethered: activate() no-op") == (1 if activate == "locked" else 0)

        op = "open_connection" if app == "probe_asgi:app" else "udp_write"
        assert_refused(server.probe(op, FORBIDDEN_ADDR, OTHER_PORT))
        assert arrivals() == {}
        op = "open_connection" if app == "probe_asgi:app" else "connect_tcp"
        assert server.probe(op, ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}


# ── The modes that do not refuse ──────────────────────────────────────


class TestNotEnforcing:
    def test_without_tethered_the_forbidden_destination_is_reached(self) -> None:
        # The control: the same route, no policy.  It shows that the world's
        # counters move when something does arrive.
        server = start_server(daphne("probe_asgi:app"), env={"TETH_ACTIVATE": "none"})
        assert server.get("/whoami").json()["tethered_imported"] is False
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}

    def test_log_only_reports_the_connection_and_lets_it_through(self) -> None:
        server = start_server(daphne("probe_asgi:app"), env={"TETH_ACTIVATE": "log_only"})
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")
        server.wait_log(f"tethered: blocked connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")

    @pytest.mark.parametrize("op", TWISTED_OPS)
    def test_log_only_reports_what_twisted_does_and_lets_it_through(self, op: str) -> None:
        server = start_server(daphne("probe_twisted:app"), env=twisted_env("log_only"))
        report = server.probe(op, FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["seconds"] < CONNECT_TIMEOUT
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")
        server.wait_log(f"tethered: blocked connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")
