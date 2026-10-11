"""hypercorn with each of its worker classes: asyncio (the default), trio and uvloop.

hypercorn's master never imports the application (except under ``--reload``):
it starts every worker, the only one of the default command line too, as a
new Python process, and the worker imports the application and with it the
policy.  What the three worker classes come to:

* ``asyncio``: the standard event loop; everything is seen and enforced.
* ``trio``: not asyncio at all, but trio does its networking through Python's
  ``socket`` module and its launches through ``subprocess``, so everything is
  seen and enforced.  ``probe_trio.py`` is the probe application for it.  One
  limit: trio cannot be imported once a locked policy is in place
  (``TestImportingTrioUnderAPolicy``), so the policy has to be activated by
  the application, which the worker imports after trio.
* ``uvloop``: the worker imports uvloop before it imports the application, so
  ``activate()`` refuses and the server does not start.  When the master holds
  the policy the worker cannot import uvloop and does not start either.  Only
  a ``log_only`` policy runs there, and sees nothing of the event loop.

Also here: ``--workers``, workers that are started later (``--max-requests``,
SIGHUP, ``--reload``), a configuration file that locks the policy in the
master, ``serve()`` in a script, and a WSGI application in hypercorn's
threads.  Not here: HTTP/2, HTTP/3 and WebSockets (the policy is about what
the application sends out, not about how a request came in), and a worker
that is killed (hypercorn replaces a worker that exits with status 0 and
shuts down when one dies any other way).

The applications allow ``allowed.test:9001``.  Each test asserts what the
application reported and what arrived in the world.
"""

from __future__ import annotations

import os
import signal
from typing import Any

import pytest
from harness import (
    ALLOWED_ADDR,
    ALLOWED_NAME,
    ALLOWED_PORT,
    APPS_DIR,
    FORBIDDEN_ADDR,
    FORBIDDEN_NAME,
    LOOPBACK_ADDR,
    OTHER_PORT,
    Server,
    arrivals,
    probe_path,
    run_python,
    start_server,
)
from harness.servers import registry

STANDARD_LOOP = "asyncio.unix_events._UnixSelectorEventLoop"
UVLOOP = "uvloop.Loop"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"
AT_FORBIDDEN_UDP = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/udp"

#: The worker classes on which a policy is enforced, with the application for each.
ENFORCING = {
    "asyncio": {"app": "probe_asgi:app", "loop": STANDARD_LOOP, "stream": "open_connection"},
    "trio": {"app": "probe_trio:app", "loop": "trio", "stream": "open_tcp_stream"},
}
#: The ways to open a TCP connection from a coroutine, per worker class.
STREAM_OPS = {
    "asyncio": ["open_connection", "create_connection", "sock_connect", "to_thread", "connect"],
    "trio": ["open_tcp_stream", "socket_connect", "to_thread", "connect"],
}
#: Destinations the allow list does not cover.
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]
ACTIVATE_REFUSED = "RuntimeError: tethered: activate() refused — uvloop is loaded in this process."
IMPORT_REFUSED = "ImportError: tethered: uvloop was not loaded — a policy is active"


def hypercorn(worker: str, *options: str, app: str | None = None) -> list[str]:
    """The command line for one worker class; the application defaults to its probe."""
    application = app or ENFORCING.get(worker, ENFORCING["asyncio"])["app"]
    return ["hypercorn", "--bind", "127.0.0.1:{port}", "-k", worker, *options, application]


def refusal_of(report: dict[str, Any]) -> dict[str, Any]:
    """The refusal itself: trio hands some of them over inside an exception group."""
    return report.get("refusal") or report


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert refusal_of(report)["exception"] == exception, report


def assert_enforcing(report: dict[str, Any], worker: str, *, locked: bool) -> None:
    assert report["active"] is True, report
    assert report["locked"] is locked, report
    assert report["loop"] == ENFORCING[worker]["loop"], report


def refused_start(argv: list[str], env: dict[str, str]) -> Server:
    """Start a server that must not come up; returns it, stopped, for its log."""
    with pytest.raises(AssertionError, match="exited with status"):
        start_server(argv, env=env)
    return registry.ended[-1]


# ── One worker, as the command line of the quick start gives it ───────


@pytest.fixture(scope="module", params=list(ENFORCING))
def worker(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module", params=["plain", "locked"])
def mode(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(worker: str, mode: str) -> Server:
    """hypercorn with one worker, whose application activates the policy when it is imported."""
    return start_server(hypercorn(worker), env={"TETH_ACTIVATE": mode})


class TestOneWorker:
    def test_the_worker_holds_the_policy_and_the_master_never_imported_the_application(
        self, server: Server, worker: str, mode: str
    ) -> None:
        me = server.get("/whoami").json()
        assert_enforcing(me, worker, locked=mode == "locked")
        # The master, the worker, and multiprocessing's resource tracker beside them.
        assert me["pid"] != server.pid
        assert {server.pid, me["pid"]} <= set(server.pids())
        assert me["ppid"] == server.pid
        assert me["imported_in_pid"] == me["pid"]
        assert server.log.count("probe: pid") == 1, server.log

    def test_the_allowed_destination_is_reached(self, server: Server, worker: str) -> None:
        for op in STREAM_OPS[worker]:
            report = server.probe(op, ALLOWED_NAME, ALLOWED_PORT)
            assert report["outcome"] == "reached", report
            assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert arrivals() == {AT_ALLOWED: len(STREAM_OPS[worker])}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_destination_outside_the_allow_list_is_refused(
        self, server: Server, worker: str, host: str, port: int
    ) -> None:
        for op in STREAM_OPS[worker]:
            assert_refused(server.probe(op, host, port))
        assert arrivals() == {}

    def test_loopback_stays_reachable(self, server: Server, worker: str) -> None:
        for op in STREAM_OPS[worker]:
            report = server.probe(op, LOOPBACK_ADDR, OTHER_PORT)
            assert report["outcome"] == "reached", report
        assert arrivals() == {f"{LOOPBACK_ADDR}:{OTHER_PORT}/tcp": len(STREAM_OPS[worker])}

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
    def test_a_refused_datagram_is_not_sent(
        self, server: Server, op: str, host: str, port: int
    ) -> None:
        assert_refused(server.probe(op, host, port))
        assert arrivals() == {}

    def test_an_uncaught_refusal_is_a_500_and_the_worker_keeps_serving(
        self, server: Server, worker: str
    ) -> None:
        me = server.get("/whoami").json()
        path = probe_path(ENFORCING[worker]["stream"], FORBIDDEN_NAME, OTHER_PORT, uncaught=1)
        assert server.get(path).status == 500
        assert arrivals() == {}
        server.wait_log("Error in ASGI Framework")
        server.wait_log(f"EgressBlocked: Blocked by tethered: {FORBIDDEN_NAME} is not in the allow")
        assert server.get("/whoami").json()["pid"] == me["pid"]
        report = server.probe(ENFORCING[worker]["stream"], ALLOWED_NAME, ALLOWED_PORT)
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


# ── trio in particular ────────────────────────────────────────────────


@pytest.fixture(scope="class")
def traced_trio() -> Server:
    """The trio worker with no tethered at all and every audit event printed."""
    return start_server(hypercorn("trio", app="traced_trio:app"), env={"TETH_ACTIVATE": "none"})


class TestWhatAnAuditHookSeesOfTrio:
    """The evidence under the trio results: trio's networking raises the audit events."""

    @pytest.mark.parametrize(
        ("op", "events", "arrival"),
        [
            ("open_tcp_stream", ["socket.getaddrinfo", "socket.connect"], AT_FORBIDDEN),
            ("socket_connect", ["socket.getaddrinfo", "socket.connect"], AT_FORBIDDEN),
            ("datagram_connected", ["socket.getaddrinfo", "socket.connect"], AT_FORBIDDEN_UDP),
            ("datagram_unconnected", ["socket.getaddrinfo", "socket.sendto"], AT_FORBIDDEN_UDP),
        ],
    )
    def test_every_way_out_raises_its_events(
        self, traced_trio: Server, op: str, events: list[str], arrival: str
    ) -> None:
        report = traced_trio.probe(op, FORBIDDEN_NAME, OTHER_PORT)
        assert report["loop"] == "trio"
        assert report["tethered_imported"] is False
        assert report["outcome"] == "reached", report
        assert arrivals() == {arrival: 1}
        seen = [line.split()[2:] for line in traced_trio.log_of_this_test.splitlines()]
        targets = {
            "socket.getaddrinfo": f"{FORBIDDEN_NAME}:{OTHER_PORT}",
            "socket.connect": f"{FORBIDDEN_ADDR}:{OTHER_PORT}",
            "socket.sendto": f"{FORBIDDEN_ADDR}:{OTHER_PORT}",
        }
        for event in events:
            assert [event, targets[event]] in seen, traced_trio.log_of_this_test

    def test_a_lookup_raises_its_event(self, traced_trio: Server) -> None:
        report = traced_trio.probe("getaddrinfo", FORBIDDEN_NAME, OTHER_PORT)
        assert report["addresses"] == [FORBIDDEN_ADDR]
        traced_trio.wait_log(rf"AUDIT pid=\d+ socket\.getaddrinfo {FORBIDDEN_NAME}:{OTHER_PORT}")

    def test_run_process_raises_the_launch_event(self, traced_trio: Server) -> None:
        report = traced_trio.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        traced_trio.wait_log(r"AUDIT pid=\d+ subprocess\.Popen bash")


class TestTrio:
    def test_open_tcp_stream_delivers_a_refused_connection_in_an_exception_group(self) -> None:
        # A refusal at the lookup is raised as it is.  One at the connection
        # (an address, or a port the rule does not cover) comes out of the
        # nursery in which trio tries the addresses: `except EgressBlocked`
        # does not match it, `except* EgressBlocked` does.
        server = start_server(hypercorn("trio"), env={"TETH_ACTIVATE": "locked"})
        at_lookup = server.probe("open_tcp_stream", FORBIDDEN_NAME, OTHER_PORT)
        assert at_lookup["exception"] == EGRESS_BLOCKED, at_lookup
        for host in (FORBIDDEN_ADDR, ALLOWED_NAME):
            report = server.probe("open_tcp_stream", host, OTHER_PORT)
            assert report["outcome"] == "blocked", report
            assert report["exception"] == "builtins.ExceptionGroup", report
            assert report["refusal"]["exception"] == EGRESS_BLOCKED, report
        assert arrivals() == {}

    def test_under_block_run_process_does_not_launch_a_tool(self) -> None:
        env = {"TETH_ACTIVATE": "locked", "TETH_ESP": "block"}
        server = start_server(hypercorn("trio"), env=env)
        assert_refused(server.probe("tool", FORBIDDEN_NAME, OTHER_PORT), SUBPROCESS_BLOCKED)
        assert arrivals() == {}
        server.wait_log(r"blocked external subprocess launch: subprocess\.Popen\(bash\)")
        # A Python child is still launched, and inherits.
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["child"]["locked"] is True, report
        assert_refused(report["child"])
        assert arrivals() == {}

    def test_a_child_given_an_environment_without_the_policy_gets_the_lock_all_the_same(
        self,
    ) -> None:
        # The lock adds the variable to the child's environment (it used to
        # refuse the launch).
        server = start_server(hypercorn("trio"), env={"TETH_ACTIVATE": "locked"})
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT, how="clean_env")
        assert report["outcome"] == "reached", report
        assert report["child"]["locked"] is True, report
        assert_refused(report["child"])
        assert arrivals() == {}


#: What ``import trio`` does on Linux: ``ctypes.util.find_library("pthread")`` runs
#: ``/sbin/ldconfig -p`` with an environment of its own (``LC_ALL`` and ``LANG`` only).
IMPORT_TRIO = """
import json
try:
    import trio
    report = {"imported": trio.__version__}
except Exception as exc:
    report = {"exception": f"{type(exc).__module__}.{type(exc).__qualname__}", "message": str(exc)}
print(json.dumps(report))
"""


class TestImportingTrioUnderAPolicy:
    """Importing trio launches ``ldconfig``, with an environment of its own.

    A locked policy used to refuse that launch (the environment lacks the
    policy variable), so trio could only be imported before the lock: with
    the policy locked in hypercorn's master, or inherited by a child
    process, ``import trio`` raised ``SubprocessBlocked``.  The launch is now
    given the variable, and is judged like any other external launch.
    """

    def test_under_a_plain_policy_the_import_is_warned_about(self) -> None:
        done = run_python(IMPORT_TRIO, activate="plain")
        assert "imported" in done.json(), done.stderr
        assert "external subprocess launch detected: subprocess.Popen(/sbin/ldconfig)" in (
            done.stderr
        )

    @pytest.mark.parametrize("esp", ["warn", "allow"])
    def test_under_a_locked_policy_the_import_works(self, esp: str) -> None:
        done = run_python(IMPORT_TRIO, activate="locked", esp=esp)
        assert "imported" in done.json(), done.stderr
        assert "strips" not in done.stderr, done.stderr
        warned = "external subprocess launch detected: subprocess.Popen(/sbin/ldconfig)"
        assert (warned in done.stderr) is (esp == "warn"), done.stderr

    @pytest.mark.parametrize("activate", ["plain", "locked"])
    def test_under_block_the_import_fails(self, activate: str) -> None:
        """Limit: ``external_subprocess_policy="block"`` refuses ldconfig like any external tool.

        Import trio before ``activate()`` where external launches are blocked.
        """
        done = run_python(IMPORT_TRIO, activate=activate, esp="block")
        report = done.json()
        assert report.get("exception") == SUBPROCESS_BLOCKED, report
        assert "subprocess.Popen(/sbin/ldconfig)" in report["message"], report
        assert "strips" not in report["message"], report

    def test_hypercorn_starts_its_trio_worker_when_the_master_locked_the_policy(self) -> None:
        command = hypercorn("trio", "-c", "file:locking_conf.py")
        server = start_server(command, env={"TETH_ACTIVATE": "none"})
        me = server.get("/whoami").json()
        assert me["locked"] is True, me
        assert_refused(server.probe("connect", FORBIDDEN_NAME, OTHER_PORT))
        assert arrivals() == {}


# ── The uvloop worker ─────────────────────────────────────────────────


class TestUvloopWorker:
    def test_without_tethered_the_worker_runs_on_uvloop_and_an_audit_hook_sees_nothing(
        self,
    ) -> None:
        # The control, and the reason for everything else in this class.
        command = hypercorn("uvloop", app="traced_asgi:app")
        server = start_server(command, env={"TETH_ACTIVATE": "none"})
        assert server.get("/whoami").json()["loop"] == UVLOOP
        for op in ("open_connection", "create_connection", "datagram_connected", "tool"):
            report = server.probe(op, FORBIDDEN_NAME, OTHER_PORT)
            assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 3, AT_FORBIDDEN_UDP: 1}
        assert "AUDIT" not in server.log, server.log
        # The hook is there: blocking code in the same worker is seen.
        server.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        server.wait_log(rf"AUDIT pid=\d+ socket\.connect {FORBIDDEN_ADDR}:{OTHER_PORT}")

    @pytest.mark.parametrize("policy", ["plain", "locked", "locked,fail_closed"])
    def test_the_server_does_not_start_when_the_application_activates_a_policy(
        self, policy: str
    ) -> None:
        # The worker imports uvloop, then the application: activate() refuses.
        server = refused_start(hypercorn("uvloop"), {"TETH_ACTIVATE": policy})
        assert ACTIVATE_REFUSED in server.log, server.log
        assert "Running on" not in server.log
        assert server.pids() == []

    def test_the_server_does_not_start_when_the_master_holds_the_policy(self) -> None:
        # The worker inherits the policy at startup and cannot import uvloop.
        # hypercorn does not fall back to another loop: "-k uvloop" asked for this one.
        command = hypercorn("uvloop", "-c", "file:locking_conf.py")
        server = refused_start(command, {"TETH_ACTIVATE": "none"})
        assert "tethered: refused to load uvloop while a policy is active" in server.log
        assert IMPORT_REFUSED in server.log, server.log
        assert "Exception: uvloop is not installed" in server.log
        assert "Running on" not in server.log

    def test_log_only_runs_on_uvloop_and_reports_nothing_of_the_event_loop(self) -> None:
        """Limit: a log-only policy over uvloop is activated, and reports nothing the loop does."""
        server = start_server(hypercorn("uvloop"), env={"TETH_ACTIVATE": "log_only"})
        me = server.get("/whoami").json()
        assert me["loop"] == UVLOOP
        assert me["active"] is True
        assert me["log_only"] is True
        server.wait_log("tethered: uvloop is loaded in this process")
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        assert "tethered: blocked" not in server.log, server.log
        # Blocking code in the same worker is reported, as on any loop.
        server.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")


# ── --workers, and workers that are started later ─────────────────────


@pytest.fixture(scope="class")
def workers(worker: str) -> Server:
    """Two workers, each of which imports the application and locks the policy."""
    return start_server(hypercorn(worker, "--workers", "2"), env={"TETH_ACTIVATE": "locked"})


class TestWorkers:
    def test_each_worker_activates_the_policy_when_it_imports_the_application(
        self, workers: Server, worker: str
    ) -> None:
        answers = workers.each_worker("/whoami", 2)
        assert workers.pid not in answers
        for pid, me in answers.items():
            assert_enforcing(me, worker, locked=True)
            assert me["ppid"] == workers.pid
            assert me["imported_in_pid"] == pid

    def test_every_worker_reaches_the_allowed_destination(
        self, workers: Server, worker: str
    ) -> None:
        path = probe_path(ENFORCING[worker]["stream"], ALLOWED_NAME, ALLOWED_PORT)
        for report in workers.each_worker(path, 2).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_every_worker_refuses_a_destination_outside_the_allow_list(
        self, workers: Server, worker: str, host: str, port: int
    ) -> None:
        path = probe_path(ENFORCING[worker]["stream"], host, port)
        for report in workers.each_worker(path, 2).values():
            assert_refused(report)
        assert arrivals() == {}


class TestLaterWorkers:
    def assert_replacements_enforce(self, server: Server, worker: str, first: dict) -> None:
        path = probe_path(ENFORCING[worker]["stream"], FORBIDDEN_NAME, OTHER_PORT)
        replacements = server.each_worker(path, 2, exclude=first)
        for pid, report in replacements.items():
            assert report["ppid"] == server.pid
            assert report["imported_in_pid"] == pid
            assert_enforcing(report, worker, locked=True)
            assert_refused(report)
        assert arrivals() == {}
        path = probe_path(ENFORCING[worker]["stream"], ALLOWED_NAME, ALLOWED_PORT)
        for report in server.each_worker(path, 2, exclude=first).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    def test_workers_started_after_max_requests_enforce_the_policy(self, worker: str) -> None:
        command = hypercorn(worker, "--workers", "2", "--max-requests", "5")
        server = start_server(command, env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)
        self.assert_replacements_enforce(server, worker, first)

    def test_workers_started_by_sighup_enforce_the_policy(self, worker: str) -> None:
        server = start_server(hypercorn(worker, "--workers", "2"), env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)
        server.send_signal(signal.SIGHUP)
        self.assert_replacements_enforce(server, worker, first)

    def test_workers_started_by_the_reloader_enforce_the_policy(self) -> None:
        # Under --reload the master imports the application too, to know
        # which files to watch: it holds the policy, the workers inherit it
        # at startup, and their own activation of the same policy is a no-op.
        command = hypercorn("asyncio", "--workers", "2", "--reload")
        server = start_server(command, env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)
        assert f"probe: pid {server.pid} activated tethered" in server.log
        assert server.log.count("tethered: activate() no-op") == 2, server.log

        os.utime(APPS_DIR / "probe_asgi.py")
        self.assert_replacements_enforce(server, "asyncio", first)
        assert server.log.count("tethered: activate() no-op") == 4, server.log


# ── A configuration file that locks the policy in the master ──────────

CONFIGURED = {
    "workers-only-inherit": {"TETH_ACTIVATE": "none"},
    "application-activates-the-same-policy": {"TETH_ACTIVATE": "locked"},
    "workers-only-inherit-under-block": {"TETH_ACTIVATE": "none", "TETH_ESP": "block"},
}


@pytest.fixture(scope="class", params=list(CONFIGURED))
def configured(request: pytest.FixtureRequest) -> Server:
    """``-c file:locking_conf.py``: the master locks the policy, then starts two asyncio workers."""
    command = hypercorn("asyncio", "--workers", "2", "-c", "file:locking_conf.py")
    return start_server(command, env=CONFIGURED[request.param])


class TestConfigurationFileLocks:
    def test_both_workers_hold_the_locked_policy(self, configured: Server) -> None:
        answers = configured.each_worker("/whoami", 2)
        for me in answers.values():
            assert_enforcing(me, "asyncio", locked=True)
            assert me["ppid"] == configured.pid
        activated_by_the_application = configured.log.count("probe: pid")
        assert configured.log.count("tethered: activate() no-op") == activated_by_the_application

    def test_both_workers_reach_the_allowed_destination(self, configured: Server) -> None:
        path = probe_path("open_connection", ALLOWED_NAME, ALLOWED_PORT)
        for report in configured.each_worker(path, 2).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_both_workers_refuse_a_destination_outside_the_allow_list(
        self, configured: Server, host: str, port: int
    ) -> None:
        path = probe_path("open_connection", host, port)
        for report in configured.each_worker(path, 2).values():
            assert_refused(report)
        assert arrivals() == {}

    def test_a_python_child_of_a_worker_inherits_the_locked_policy(
        self, configured: Server
    ) -> None:
        report = configured.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["child"]["locked"] is True, report
        assert_refused(report["child"])
        assert arrivals() == {}

    def test_a_worker_that_replaces_one_that_reached_max_requests_inherits_the_policy(
        self,
    ) -> None:
        command = hypercorn(
            "asyncio", "--workers", "2", "--max-requests", "5", "-c", "file:locking_conf.py"
        )
        server = start_server(command, env={"TETH_ACTIVATE": "none"})
        first = server.each_worker("/whoami", 2)
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2, exclude=first).values():
            assert_enforcing(report, "asyncio", locked=True)
            assert_refused(report)
        assert arrivals() == {}
        assert "probe: pid" not in server.log, "the application activated after all"


# ── serve() in a script ───────────────────────────────────────────────


class TestServeInAScript:
    def test_the_only_process_holds_the_policy(self, worker: str, mode: str) -> None:
        server = start_server(["python", "serve_script.py", worker], env={"TETH_ACTIVATE": mode})
        me = server.get("/whoami").json()
        assert_enforcing(me, worker, locked=mode == "locked")
        assert me["pid"] == server.pid
        assert server.pids() == [server.pid]

        op = ENFORCING[worker]["stream"]
        assert_refused(server.probe(op, FORBIDDEN_NAME, OTHER_PORT))
        assert_refused(server.probe(op, FORBIDDEN_ADDR, OTHER_PORT))
        assert arrivals() == {}
        assert server.probe(op, ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}


# ── A WSGI application, which hypercorn runs in threads ───────────────


class TestWsgiApplication:
    def test_a_handler_in_a_worker_thread_is_held_to_the_policy(self) -> None:
        command = hypercorn("asyncio", app="probe_wsgi:application")
        server = start_server(command, env={"TETH_ACTIVATE": "locked"})
        me = server.get("/whoami").json()
        assert me["locked"] is True
        assert me["thread"] != "MainThread"
        for op in ("connect", "urllib"):
            assert_refused(server.probe(op, FORBIDDEN_NAME, OTHER_PORT))
            assert_refused(server.probe(op, FORBIDDEN_ADDR, OTHER_PORT))
        assert arrivals() == {}
        assert server.probe("urllib", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}


# ── The modes that do not refuse ──────────────────────────────────────


class TestNotEnforcing:
    def test_without_tethered_the_forbidden_destination_is_reached(self, worker: str) -> None:
        # The control: the same route, no policy.  It shows that the world's
        # counters move when something does arrive.
        server = start_server(hypercorn(worker), env={"TETH_ACTIVATE": "none"})
        assert server.get("/whoami").json()["tethered_imported"] is False
        report = server.probe(ENFORCING[worker]["stream"], FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}

    def test_log_only_reports_the_connection_and_lets_it_through(self, worker: str) -> None:
        server = start_server(hypercorn(worker), env={"TETH_ACTIVATE": "log_only"})
        report = server.probe(ENFORCING[worker]["stream"], FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")
        server.wait_log(f"tethered: blocked connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")
