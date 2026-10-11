"""aiohttp as a server: on its own, and under gunicorn with aiohttp's two worker classes.

* ``web.run_app`` in a script, and aiohttp's command line
  (``python -m aiohttp.web``): one process on the standard asyncio event
  loop.  Everything is seen and enforced, ``aiohttp.ClientSession`` included.
* gunicorn with ``aiohttp.GunicornWebWorker``: each worker has a standard
  event loop of its own; enforced with and without ``--preload``, in every
  worker and in workers that are started later (``--max-requests``, SIGHUP, a
  killed worker).
* gunicorn with ``aiohttp.GunicornUVLoopWebWorker``: the worker imports uvloop
  when it starts.  Without ``--preload`` that is before it imports the
  application, so ``activate()`` refuses; with ``--preload`` the policy came
  with the fork, so the import of uvloop is refused.  Either way the worker
  fails to boot and gunicorn stops ("Worker failed to boot.").  Only a
  ``log_only`` policy runs there, and reports nothing of the event loop.
* ``aiohttp.ClientSession`` with aiodns installed
  (``pip install aiohttp[speedups]``; ``resolver_packages.py`` arranges it per
  server): the client resolves names with c-ares, below Python, and no audit
  event is raised for a lookup.  Connections are still seen and refused.  But
  a rule that names a host no longer lets the client through, because the
  address it connects to was never tied to that name; and a lookup of any
  name at all reaches the name server.  ``TestClientSessionWithAiodns``.

The application (``probe_aiohttp.py``) allows ``allowed.test:9001``.  Each
test asserts what the application reported and what arrived in the world.
"""

from __future__ import annotations

import signal
from typing import TYPE_CHECKING, Any

import pytest
import resolver_packages
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
    dns_queries,
    probe_path,
    start_server,
)
from harness.servers import registry

if TYPE_CHECKING:
    from collections.abc import Iterator

STANDARD_LOOP = "asyncio.unix_events._UnixSelectorEventLoop"
UVLOOP = "uvloop.Loop"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"

#: The ways to open a TCP connection from a handler; ``client`` is ``aiohttp.ClientSession``.
STREAM_OPS = [
    "client",
    "open_connection",
    "create_connection",
    "sock_connect",
    "to_thread",
    "connect",
]
#: Destinations the allow list does not cover.
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]
#: aiohttp serving by itself: ``web.run_app`` in a script, and its command line.
STANDALONE = {
    "run_app": ["python", "probe_aiohttp.py"],
    "command-line": [
        "python",
        "-m",
        "aiohttp.web",
        "-H",
        "127.0.0.1",
        "-P",
        "{port}",
        "probe_aiohttp:init",
    ],
}
PRELOAD = {"import-in-the-worker": [], "preload": ["--preload"]}
ACTIVATE_REFUSED = "RuntimeError: tethered: activate() refused — uvloop is loaded in this process."
IMPORT_REFUSED = "ImportError: tethered: uvloop was not loaded — a policy is active"
UVLOOP_LOADED = "tethered: uvloop is loaded in this process."
#: A name that is in no allow list and in no hosts file: only the name server can be asked.
UNKNOWN_NAME = "nowhere.test"


@pytest.fixture(scope="session", autouse=True)
def _aiodns_set_aside() -> Iterator[None]:
    """aiodns is installed for the servers that ask for it, and for no other."""
    resolver_packages.set_aside()
    try:
        yield
    finally:
        resolver_packages.restore()


def gunicorn(worker: str, *options: str, workers: int = 2, app: str = "probe_aiohttp:app") -> list:
    """gunicorn with one of aiohttp's worker classes."""
    command = ["gunicorn", app, "--bind", "127.0.0.1:{port}", "--workers", str(workers)]
    return [*command, "--worker-class", f"aiohttp.{worker}", *options]


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_enforcing(report: dict[str, Any], *, locked: bool) -> None:
    assert report["active"] is True, report
    assert report["locked"] is locked, report
    assert report["loop"] == STANDARD_LOOP, report


def refused_start(argv: list[str], env: dict[str, str]) -> Server:
    """Start a server that must not come up; returns it, stopped, for its log."""
    with pytest.raises(AssertionError, match="exited with status"):
        start_server(argv, env=env)
    return registry.ended[-1]


# ── aiohttp serving by itself: one process ────────────────────────────


@pytest.fixture(scope="module", params=list(STANDALONE))
def launch(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module", params=["plain", "locked"])
def mode(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(launch: str, mode: str) -> Server:
    """aiohttp's own server; the application activates the policy when it is imported."""
    return start_server(STANDALONE[launch], env={"TETH_ACTIVATE": mode})


class TestOneProcess:
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
        assert arrivals() == {f"{ALLOWED_ADDR}:{ALLOWED_PORT}/udp": 1}

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
        path = probe_path("client", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)
        assert server.get(path).status == 500
        assert arrivals() == {}
        server.wait_log("Error handling request")
        server.wait_log(f"EgressBlocked: Blocked by tethered: {FORBIDDEN_NAME} is not in the allow")
        assert server.get("/whoami").json()["pid"] == server.pid
        assert server.probe("client", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"

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

    def test_under_block_a_tool_is_not_launched(self, launch: str) -> None:
        blocking = start_server(
            STANDALONE[launch], env={"TETH_ACTIVATE": "locked", "TETH_ESP": "block"}
        )
        assert_refused(blocking.probe("tool", FORBIDDEN_NAME, OTHER_PORT), SUBPROCESS_BLOCKED)
        assert arrivals() == {}
        blocking.wait_log(r"blocked external subprocess launch: subprocess\.Popen\(bash\)")


# ── gunicorn with aiohttp.GunicornWebWorker ───────────────────────────


@pytest.fixture(scope="class", params=list(PRELOAD))
def preload(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="class")
def workers(preload: str) -> Server:
    """Two aiohttp workers under gunicorn, a locked policy."""
    command = gunicorn("GunicornWebWorker", *PRELOAD[preload])
    return start_server(command, env={"TETH_ACTIVATE": "locked"})


class TestGunicornWorker:
    def test_every_worker_holds_the_locked_policy_on_a_standard_loop(
        self, workers: Server, preload: str
    ) -> None:
        answers = workers.each_worker("/whoami", 2)
        assert workers.pid not in answers
        for pid, me in answers.items():
            assert_enforcing(me, locked=True)
            assert me["ppid"] == workers.pid
            # Where the application was imported, and so where activate() ran.
            assert me["imported_in_pid"] == (workers.pid if preload == "preload" else pid)

    @pytest.mark.parametrize("op", ["client", "open_connection"])
    def test_every_worker_reaches_the_allowed_destination(self, workers: Server, op: str) -> None:
        for report in workers.each_worker(probe_path(op, ALLOWED_NAME, ALLOWED_PORT), 2).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize("op", ["client", "open_connection"])
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_every_worker_refuses_a_destination_outside_the_allow_list(
        self, workers: Server, op: str, host: str, port: int
    ) -> None:
        for report in workers.each_worker(probe_path(op, host, port), 2).values():
            assert_refused(report)
        assert arrivals() == {}

    def test_an_uncaught_refusal_is_a_500_and_the_workers_survive(self, workers: Server) -> None:
        before = workers.each_worker("/whoami", 2)
        path = probe_path("client", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)
        assert workers.get(path).status == 500
        assert arrivals() == {}
        workers.wait_log(
            f"EgressBlocked: Blocked by tethered: {FORBIDDEN_NAME} is not in the allow"
        )
        assert set(workers.each_worker("/whoami", 2)) == set(before)

    def test_a_python_child_of_every_worker_inherits_the_locked_policy(
        self, workers: Server
    ) -> None:
        path = probe_path("child", FORBIDDEN_NAME, OTHER_PORT)
        for pid, report in workers.each_worker(path, 2).items():
            assert report["outcome"] == "reached", report
            child = report["child"]
            assert child["ppid"] == pid
            assert child["locked"] is True, child
            assert_refused(child)
        assert arrivals() == {}


class TestLaterGunicornWorkers:
    def assert_replacements_enforce(
        self, server: Server, first: dict[int, Any], count: int = 2
    ) -> None:
        path = probe_path("client", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, count, exclude=first).values():
            assert report["ppid"] == server.pid
            assert_enforcing(report, locked=True)
            assert_refused(report)
        assert arrivals() == {}
        path = probe_path("client", ALLOWED_NAME, ALLOWED_PORT)
        for report in server.each_worker(path, count, exclude=first).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    def test_workers_started_after_max_requests_enforce_the_policy(self, preload: str) -> None:
        command = gunicorn("GunicornWebWorker", *PRELOAD[preload], "--max-requests", "5")
        server = start_server(command, env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)
        self.assert_replacements_enforce(server, first)
        # aiohttp's own words: the new workers came from --max-requests, not from a crash.
        server.wait_log("Max requests, shutting down")

    def test_workers_started_by_a_reload_enforce_the_policy(self, preload: str) -> None:
        command = gunicorn("GunicornWebWorker", *PRELOAD[preload])
        server = start_server(command, env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)
        server.send_signal(signal.SIGHUP)
        self.assert_replacements_enforce(server, first)
        server.wait_log("Hang up: Master")

    def test_a_worker_that_replaces_a_killed_one_enforces_the_policy(self, preload: str) -> None:
        command = gunicorn("GunicornWebWorker", *PRELOAD[preload])
        server = start_server(command, env={"TETH_ACTIVATE": "locked"})
        first = server.each_worker("/whoami", 2)
        server.send_signal(signal.SIGKILL, min(first))
        self.assert_replacements_enforce(server, first, count=1)


# ── gunicorn with aiohttp.GunicornUVLoopWebWorker ─────────────────────


class TestGunicornUvloopWorker:
    def test_without_tethered_the_workers_run_on_uvloop_and_an_audit_hook_sees_no_lookup(
        self,
    ) -> None:
        # The control, and the reason for the rest of this class.
        command = gunicorn("GunicornUVLoopWebWorker", workers=1, app="traced_aiohttp:app")
        server = start_server(command, env={"TETH_ACTIVATE": "none"})
        assert server.get("/whoami").json()["loop"] == UVLOOP
        for op in ("open_connection", "create_connection", "getaddrinfo"):
            assert server.probe(op, FORBIDDEN_NAME, OTHER_PORT)["outcome"] == "reached"
        assert arrivals() == {AT_FORBIDDEN: 2}
        assert "AUDIT" not in server.log, server.log
        # aiohttp's client connects a Python socket itself, after a lookup
        # that went through uvloop: the address is seen, the name is not.
        report = server.probe("client", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        server.wait_log(rf"AUDIT pid=\d+ socket\.connect {FORBIDDEN_ADDR}:{OTHER_PORT}")
        assert "socket.getaddrinfo" not in server.log, server.log

    @pytest.mark.parametrize("policy", ["plain", "locked"])
    def test_without_preload_the_workers_fail_to_boot_at_activate(self, policy: str) -> None:
        # The worker imports uvloop, then the application: activate() refuses.
        server = refused_start(gunicorn("GunicornUVLoopWebWorker"), {"TETH_ACTIVATE": policy})
        assert ACTIVATE_REFUSED in server.log, server.log
        assert "Worker failed to boot." in server.log
        assert server.pids() == []

    @pytest.mark.parametrize("policy", ["plain", "locked"])
    def test_with_preload_the_workers_fail_to_boot_at_the_import_of_uvloop(
        self, policy: str
    ) -> None:
        # The master imported the application, and with it the policy, before
        # the fork: the worker's import of uvloop is refused.
        command = gunicorn("GunicornUVLoopWebWorker", "--preload")
        server = refused_start(command, {"TETH_ACTIVATE": policy})
        assert IMPORT_REFUSED in server.log, server.log
        assert "tethered: refused to load uvloop while a policy is active" in server.log
        assert "Worker failed to boot." in server.log
        assert server.pids() == []

    def test_log_only_runs_on_uvloop_and_reports_nothing_of_the_event_loop(self) -> None:
        """Limit: a log-only policy over uvloop is activated, and reports nothing the loop does."""
        command = gunicorn("GunicornUVLoopWebWorker", workers=1)
        server = start_server(command, env={"TETH_ACTIVATE": "log_only"})
        me = server.get("/whoami").json()
        assert me["loop"] == UVLOOP
        assert me["log_only"] is True
        server.wait_log(UVLOOP_LOADED)
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        assert "tethered: would block" not in server.log, server.log


# ── aiohttp's client with aiodns installed ────────────────────────────


def with_aiodns(activate: str, **more: str) -> dict[str, str]:
    """The environment of a server that finds aiodns installed."""
    return {
        "TETH_ACTIVATE": activate,
        "PYTHONPATH": resolver_packages.pythonpath(aiodns=True),
        **more,
    }


class TestClientSessionWithAiodns:
    """``pip install aiohttp[speedups]``: the client's lookups go through c-ares."""

    def test_without_tethered_an_audit_hook_sees_the_connection_and_no_lookup(self) -> None:
        # The evidence under the limits below.
        command = ["python", "traced_aiohttp.py"]
        server = start_server(command, env=with_aiodns("none"))
        report = server.probe("client", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(rf"AUDIT pid=\d+ socket\.connect {FORBIDDEN_ADDR}:{OTHER_PORT}")
        assert "socket.getaddrinfo forbidden" not in server.log, server.log
        # Without aiodns the same client raises the lookup event (the control of the control).
        plain = start_server(command, env={"TETH_ACTIVATE": "none"})
        plain.probe("client", FORBIDDEN_NAME, OTHER_PORT)
        plain.wait_log(rf"AUDIT pid=\d+ socket\.getaddrinfo {FORBIDDEN_NAME}:{OTHER_PORT}")

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_destination_outside_the_allow_list_is_still_refused(
        self, host: str, port: int
    ) -> None:
        # Every refusal now comes at the connection, by address.
        server = start_server(STANDALONE["run_app"], env=with_aiodns("locked"))
        report = server.probe("client", host, port)
        assert_refused(report)
        address = ALLOWED_ADDR if host == ALLOWED_NAME else FORBIDDEN_ADDR
        assert (
            report["message"] == f"Blocked by tethered: {address}:{port} is not in the allow list"
        )
        assert arrivals() == {}

    @pytest.mark.parametrize("policy", ["plain", "locked"])
    def test_the_allowed_name_is_refused_too(self, policy: str) -> None:
        """Limit: with aiodns a rule that names a host does not let aiohttp's client through.

        tethered learns which name an address belongs to from the lookup's
        audit event, and c-ares raises none: the connection is judged as one
        to a bare address, which the rule ``allowed.test:9001`` does not cover.
        """
        server = start_server(STANDALONE["run_app"], env=with_aiodns(policy))
        report = server.probe("client", ALLOWED_NAME, ALLOWED_PORT)
        assert_refused(report)
        assert report["message"] == (
            f"Blocked by tethered: {ALLOWED_ADDR}:{ALLOWED_PORT} is not in the allow list"
        )
        assert arrivals() == {}
        # asyncio's own lookup, in the same process, ties the name to the
        # address; from then on the client's connection is allowed.
        assert server.probe("getaddrinfo", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
        assert server.probe("client", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}

    def test_a_rule_for_the_address_lets_the_client_through(self) -> None:
        allow = f"{ALLOWED_NAME}:{ALLOWED_PORT},{ALLOWED_ADDR}:{ALLOWED_PORT}"
        server = start_server(STANDALONE["run_app"], env=with_aiodns("locked", TETH_ALLOW=allow))
        report = server.probe("client", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 1}

    @pytest.mark.parametrize("policy", ["locked", "locked,fail_closed", "log_only"])
    def test_a_lookup_of_any_name_reaches_the_name_server(self, policy: str) -> None:
        """Limit: c-ares asks the name server itself; the lookup is neither refused nor reported."""
        server = start_server(STANDALONE["run_app"], env=with_aiodns(policy))
        report = server.probe("client", UNKNOWN_NAME, ALLOWED_PORT)
        assert report["outcome"] == "error", report
        assert report["exception"] == "aiohttp.client_exceptions.ClientConnectorDNSError", report
        assert dns_queries().get(f"{UNKNOWN_NAME}/A", 0) >= 1, dns_queries()
        assert "tethered: blocked" not in server.log, server.log

    def test_without_aiodns_that_lookup_is_refused_and_asks_nobody(self) -> None:
        # The control for the limit above: the image's default arrangement.
        server = start_server(STANDALONE["run_app"], env={"TETH_ACTIVATE": "locked"})
        assert_refused(server.probe("client", UNKNOWN_NAME, ALLOWED_PORT))
        assert dns_queries() == {}
        server.wait_log(f"tethered: blocked getaddrinfo for {UNKNOWN_NAME}")


# ── The modes that do not refuse ──────────────────────────────────────


class TestNotEnforcing:
    def test_without_tethered_the_forbidden_destination_is_reached(self, launch: str) -> None:
        # The control: the same route, no policy.  It shows that the world's
        # counters move when something does arrive.
        server = start_server(STANDALONE[launch], env={"TETH_ACTIVATE": "none"})
        assert server.get("/whoami").json()["tethered_imported"] is False
        report = server.probe("client", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}

    def test_log_only_reports_the_connection_and_lets_it_through(self, launch: str) -> None:
        server = start_server(STANDALONE[launch], env={"TETH_ACTIVATE": "log_only"})
        report = server.probe("client", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(f"tethered: would block getaddrinfo for {FORBIDDEN_NAME}")
        server.wait_log(f"tethered: would block connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")
