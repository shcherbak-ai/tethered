"""sanic with its own server: the worker manager (the default) and ``--single-process``.

By default sanic's main process starts every worker as a new Python process;
with ``--single-process`` there is only the one.  Either way sanic serves on
uvloop when uvloop can be imported, and ``pip install sanic`` installs it.
``import sanic`` itself imports uvloop (``sanic/compat.py``), so everything
turns on what comes first:

* **The ``sanic`` command, as installed.**  The command has imported sanic,
  and with it uvloop, before it imports the application.  ``activate()``
  refuses and the server does not start, whatever the application module does
  first, and also when sanic is told not to serve on uvloop
  (``SANIC_USE_UVLOOP=false``): uvloop is loaded all the same.
* **A script that activates the policy before it imports sanic**
  (``serve_script.py``).  uvloop is not loaded, sanic says that it is not
  installed and serves on the standard event loop, and the policy is enforced:
  in the main process, in the workers, which inherit it, and in workers that
  are started later.
* **A script that imports sanic first.**  ``activate()`` refuses.
* **sanic without uvloop** (``pip uninstall uvloop``; ``loop_packages.py``
  arranges it per server).  The command works as it is, and the policy is
  enforced.  This is where the suite covers every operation.

Also here: ``--workers``, workers replaced through sanic's own
``app.m.restart()`` and by ``--auto-reload``.  Not here: a killed worker (the
worker manager does not replace it), the inspector, HTTP/3, ASGI mode (sanic
under another server is that server's suite).

Three helpers are there because of how sanic 25.12.1 takes a SIGTERM, which
every test ends with:

* ``settled()``.  sanic does not stop when it is signalled before its main
  process has seen every worker's startup acknowledgement: it loops in
  ``WorkerManager.wait_for_ack``.  Reproduced three times out of three with an
  application that never imports tethered.  The servers here are given a
  second after their first answer before the test goes on.
* ``wait_until_retired()``.  A restart starts the new workers before it stops
  the old ones, and a SIGTERM in between left the main process and the old
  workers running.  Seen once, under a locked policy; not tried without one.
* ``stop()``.  The SIGTERM handler writes the workers' state through the
  manager connection that the main loop reads it through ten times a second.
  When the signal lands inside such a read, the main process fails in
  ``WorkerManager._sync_states`` and ends with status 1 after its workers have
  stopped.  Seen once in several hundred stops, under a locked policy; the
  cause is read from sanic's source, not reproduced.  ``stop()`` accepts that
  one ending, recognised by its traceback, and no other.

The application allows ``allowed.test:9001``.  Each test asserts what the
application reported and what arrived in the world.
"""

from __future__ import annotations

import functools
import os
import time
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
    SUITE_DIR,
    Server,
    arrivals,
    probe_path,
    start_server,
)
from harness.servers import registry

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

STANDARD_LOOP = "asyncio.unix_events._UnixSelectorEventLoop"
UVLOOP = "uvloop.Loop"
EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"

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
#: sanic's two process layouts, as options of the command and of ``serve_script.py``.
LAYOUTS = {"worker-manager": ([], []), "single-process": (["--single-process"], ["single"])}
ACTIVATE_REFUSED = "tethered: activate() refused — uvloop is loaded"
UVLOOP_LOADED = "tethered: uvloop is loaded in this process."
UVLOOP_NOT_LOADED = "tethered: refused to load uvloop while a policy is active"
#: What sanic says when it cannot import uvloop, whoever kept it from doing so.
SANIC_FALLS_BACK = "You are trying to use uvloop, but uvloop is not installed in your system"


@pytest.fixture(scope="session", autouse=True)
def _uvloop_set_aside() -> Iterator[None]:
    """uvloop is installed for the servers that ask for it, and for no other."""
    loop_packages.set_aside()
    try:
        yield
    finally:
        loop_packages.restore()


def settled(seconds: float = 1.0) -> Callable[[Server], bool]:
    """Ready when the server has been answering for ``seconds`` (see the module docstring)."""
    first: float | None = None

    def ready(server: Server) -> bool:
        nonlocal first
        if server.get("/whoami", timeout=5.0).status >= 500:
            return False
        first = first or time.monotonic()
        return time.monotonic() - first >= seconds

    return ready


def command(layout: str = "worker-manager", *options: str) -> list[str]:
    """The ``sanic`` command line for one process layout."""
    cli = ["sanic", "probe_sanic:app", "--host", "127.0.0.1", "--port", "{port}"]
    return [*cli, *LAYOUTS[layout][0], *options]


def script(layout: str = "worker-manager", *options: str) -> list[str]:
    """``serve_script.py`` for one process layout."""
    return ["python", "serve_script.py", *LAYOUTS[layout][1], *options]


def env(activate: str, *, uvloop: bool, **more: str) -> dict[str, str]:
    """The environment of a server that finds uvloop installed, or does not."""
    installed = ("uvloop",) if uvloop else ()
    return {
        "TETH_ACTIVATE": activate,
        "PYTHONPATH": loop_packages.pythonpath(*installed),
        **more,
    }


def stop(server: Server) -> None:
    """Stop sanic, telling its own shutdown race from an unclean stop (module docstring)."""
    try:
        server.stop()
    except AssertionError as problem:
        raced = (
            str(problem).endswith(": exit status 1")
            and "WorkerManager._sync_states" in server.log
            and "AttributeError: 'NoneType' object has no attribute 'get'" in server.log
        )
        if not raced:
            raise


def start(argv: list[str], environment: dict[str, str]) -> Server:
    """Start sanic, let its main process finish its own startup, and have it stopped by ``stop``."""
    server = start_server(argv, env=environment, ready=settled())
    # start_server has registered Server.stop with the fixture or the test that
    # is running.  This is registered after it and so runs before it; the
    # harness then finds the server stopped.
    owner = registry.fixture_requests[-1] if registry.fixture_requests else registry.item
    owner.addfinalizer(functools.partial(stop, server))
    return server


def wait_until_retired(server: Server, replaced: dict[int, Any], timeout: float = 30.0) -> None:
    """Wait until sanic has stopped the workers it replaced.

    A restart starts the new workers first and stops the old ones afterwards.
    That the old ones go is part of what is tested.  It is also needed before
    the server is stopped: sanic 25.12.1 does not stop when SIGTERM arrives in
    between (seen once, under a locked policy: the main process and the old
    workers stayed, the workers spinning on their closed listening socket).
    """
    deadline = time.monotonic() + timeout
    while left := sorted(set(replaced) & set(server.pids())):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{server.name}: the replaced workers are still there: {left}")
        time.sleep(0.05)


def refused_start(argv: list[str], environment: dict[str, str]) -> Server:
    """Start a server that must not come up; returns it, stopped, for its log."""
    with pytest.raises(AssertionError, match="exited with status"):
        start_server(argv, env=environment)
    return registry.ended[-1]


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_enforcing(report: dict[str, Any], *, locked: bool) -> None:
    assert report["active"] is True, report
    assert report["locked"] is locked, report
    assert report["loop"] == STANDARD_LOOP, report


# ── The sanic command with uvloop installed, as "pip install sanic" leaves it ──


class TestTheCommandAsInstalled:
    @pytest.mark.parametrize("layout", list(LAYOUTS))
    def test_without_tethered_sanic_serves_on_uvloop(self, layout: str) -> None:
        # The control, and the reason for the rest of this class.
        server = start(command(layout), env("none", uvloop=True))
        me = server.get("/whoami").json()
        assert me["loop"] == UVLOOP
        assert (me["pid"] == server.pid) is (layout == "single-process")

    @pytest.mark.parametrize("layout", list(LAYOUTS))
    @pytest.mark.parametrize("policy", ["plain", "locked"])
    def test_the_server_does_not_start_under_a_policy(self, layout: str, policy: str) -> None:
        # The command imported sanic, and with it uvloop, before the
        # application: activate() refuses, whatever the application does first.
        for order in ("activate_first", "sanic_first"):
            environment = env(policy, uvloop=True, TETH_ORDER=order)
            server = refused_start(command(layout), environment)
            assert ACTIVATE_REFUSED in server.log, server.log
            assert "Worker ready" not in server.log
            assert server.pids() == []

    @pytest.mark.parametrize("layout", list(LAYOUTS))
    def test_telling_sanic_not_to_use_uvloop_does_not_help(self, layout: str) -> None:
        """Limit: with ``SANIC_USE_UVLOOP=false`` sanic serves on the standard loop, refused too.

        The run without tethered shows the loop the policy would be enforced
        on.  But ``import sanic`` has loaded uvloop, and ``activate()`` goes
        by that.
        """
        setting = {"SANIC_USE_UVLOOP": "false"}
        control = start(command(layout), env("none", uvloop=True, **setting))
        assert control.get("/whoami").json()["loop"] == STANDARD_LOOP
        stop(control)

        server = refused_start(command(layout), env("locked", uvloop=True, **setting))
        assert ACTIVATE_REFUSED in server.log, server.log
        assert "Worker ready" not in server.log

    def test_log_only_serves_on_uvloop_and_reports_nothing_of_the_event_loop(self) -> None:
        """Limit: a log-only policy over uvloop is activated, and reports nothing the loop does."""
        server = start(command("single-process"), env("log_only", uvloop=True))
        me = server.get("/whoami").json()
        assert me["loop"] == UVLOOP
        assert me["log_only"] is True
        server.wait_log(UVLOOP_LOADED)
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        assert "tethered: would block" not in server.log, server.log


# ── A script, with uvloop installed: what comes first decides ─────────


class TestAScriptThatActivatesBeforeItImportsSanic:
    @pytest.mark.parametrize("layout", list(LAYOUTS))
    @pytest.mark.parametrize("policy", ["plain", "locked"])
    def test_uvloop_is_not_loaded_and_the_policy_is_enforced(
        self, layout: str, policy: str
    ) -> None:
        server = start(script(layout), env(policy, uvloop=True, TETH_ORDER="activate_first"))
        me = server.get("/whoami").json()
        assert_enforcing(me, locked=policy == "locked")
        assert UVLOOP_NOT_LOADED in server.log
        # sanic takes the failed import for a missing package, says so, and goes on.
        assert SANIC_FALLS_BACK in server.log

        if layout == "single-process":
            assert me["pid"] == server.pid
            assert server.pids() == [server.pid]
        else:
            # The main process imported the application and holds the policy;
            # the worker is a new interpreter that inherited it at startup.
            assert me["ppid"] == server.pid
            assert f"probe: pid {server.pid} activated tethered" in server.log

        for op in STREAM_OPS:
            assert_refused(server.probe(op, FORBIDDEN_NAME, OTHER_PORT))
            assert_refused(server.probe(op, FORBIDDEN_ADDR, OTHER_PORT))
        assert arrivals() == {}
        report = server.probe("open_connection", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 1}

    def test_every_worker_and_every_later_worker_inherits_the_locked_policy(self) -> None:
        environment = env("locked", uvloop=True, TETH_ORDER="activate_first")
        server = start(script("worker-manager", "workers=2"), environment)
        first = server.each_worker("/whoami", 2)
        for me in first.values():
            assert_enforcing(me, locked=True)
            assert me["ppid"] == server.pid

        assert server.get("/restart").status == 200
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2, exclude=first).values():
            assert_enforcing(report, locked=True)
            assert_refused(report)
        assert arrivals() == {}
        # Each worker asked for the policy it had already inherited.
        assert "tethered: activate() no-op" in server.log
        wait_until_retired(server, first)

    def test_under_block_the_main_process_still_starts_its_workers(self) -> None:
        environment = env("locked", uvloop=True, TETH_ORDER="activate_first", TETH_ESP="block")
        server = start(script("worker-manager", "workers=2"), environment)
        path = probe_path("tool", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2).values():
            assert report["external_subprocess_policy"] == "block"
            assert_refused(report, SUBPROCESS_BLOCKED)
        assert arrivals() == {}


class TestAScriptThatImportsSanicFirst:
    @pytest.mark.parametrize("layout", list(LAYOUTS))
    @pytest.mark.parametrize("policy", ["plain", "locked"])
    def test_the_script_fails_at_activate(self, layout: str, policy: str) -> None:
        environment = env(policy, uvloop=True, TETH_ORDER="sanic_first")
        server = refused_start(script(layout), environment)
        assert ACTIVATE_REFUSED in server.log, server.log
        assert "Worker ready" not in server.log
        assert server.pids() == []


# ── sanic without uvloop: the command works, and everything is enforced ──


@pytest.fixture(scope="module", params=list(LAYOUTS))
def layout(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module", params=["plain", "locked"])
def mode(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(layout: str, mode: str) -> Server:
    """The ``sanic`` command, uvloop not installed; the application activates when imported."""
    return start(command(layout), env(mode, uvloop=False))


class TestWithoutUvloop:
    def test_sanic_serves_on_the_standard_loop_with_the_policy(
        self, server: Server, layout: str, mode: str
    ) -> None:
        me = server.get("/whoami").json()
        assert_enforcing(me, locked=mode == "locked")
        if layout == "single-process":
            assert me["pid"] == server.pid
            assert server.pids() == [server.pid]
        else:
            # The main process imports the application too, and each worker again.
            assert me["ppid"] == server.pid
            assert me["imported_in_pid"] == me["pid"]
            assert f"probe: pid {server.pid} activated tethered" in server.log

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

    def test_an_uncaught_refusal_is_a_500_and_the_worker_keeps_serving(
        self, server: Server
    ) -> None:
        me = server.get("/whoami").json()
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)
        assert server.get(path).status == 500
        assert arrivals() == {}
        server.wait_log(f"EgressBlocked: Blocked by tethered: {FORBIDDEN_NAME}")
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


# ── --workers, and workers that are started later ─────────────────────


@pytest.fixture(scope="class")
def workers() -> Server:
    """Two workers, uvloop not installed, a locked policy."""
    return start(command("worker-manager", "--workers", "2"), env("locked", uvloop=False))


class TestWorkers:
    def test_each_worker_holds_the_locked_policy(self, workers: Server) -> None:
        answers = workers.each_worker("/whoami", 2)
        assert workers.pid not in answers
        for pid, me in answers.items():
            assert_enforcing(me, locked=True)
            assert me["ppid"] == workers.pid
            assert me["imported_in_pid"] == pid

    def test_every_worker_reaches_the_allowed_destination(self, workers: Server) -> None:
        path = probe_path("open_connection", ALLOWED_NAME, ALLOWED_PORT)
        for report in workers.each_worker(path, 2).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_every_worker_refuses_a_destination_outside_the_allow_list(
        self, workers: Server, host: str, port: int
    ) -> None:
        for report in workers.each_worker(probe_path("open_connection", host, port), 2).values():
            assert_refused(report)
        assert arrivals() == {}


class TestLaterWorkers:
    def assert_replacements_enforce(self, server: Server, first: dict[int, Any]) -> None:
        path = probe_path("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        for pid, report in server.each_worker(path, 2, exclude=first).items():
            assert report["ppid"] == server.pid
            assert report["imported_in_pid"] == pid
            assert_enforcing(report, locked=True)
            assert_refused(report)
        assert arrivals() == {}
        path = probe_path("open_connection", ALLOWED_NAME, ALLOWED_PORT)
        for report in server.each_worker(path, 2, exclude=first).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}
        wait_until_retired(server, first)

    def test_workers_started_by_a_restart_enforce_the_policy(self) -> None:
        server = start(command("worker-manager", "--workers", "2"), env("locked", uvloop=False))
        first = server.each_worker("/whoami", 2)
        assert server.get("/restart").status == 200
        self.assert_replacements_enforce(server, first)

    def test_workers_started_by_the_reloader_enforce_the_policy(self) -> None:
        argv = command("worker-manager", "--workers", "2", "--auto-reload")
        server = start(argv, env("locked", uvloop=False))
        first = server.each_worker("/whoami", 2)
        os.utime(SUITE_DIR / "probe_sanic.py")
        self.assert_replacements_enforce(server, first)


# ── The modes that do not refuse ──────────────────────────────────────


class TestNotEnforcing:
    def test_without_tethered_the_forbidden_destination_is_reached(self, layout: str) -> None:
        # The control: the same route, no policy.  It shows that the world's
        # counters move when something does arrive.
        server = start(command(layout), env("none", uvloop=False))
        me = server.get("/whoami").json()
        assert me["tethered_imported"] is False
        assert me["loop"] == STANDARD_LOOP
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}

    def test_log_only_reports_the_connection_and_lets_it_through(self, layout: str) -> None:
        server = start(command(layout), env("log_only", uvloop=False))
        report = server.probe("open_connection", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(f"tethered: would block getaddrinfo for {FORBIDDEN_NAME}")
        server.wait_log(f"tethered: would block connect to {FORBIDDEN_ADDR}:{OTHER_PORT}")
