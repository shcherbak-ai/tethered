"""Flask, with the policy activated in the application factory.

``flask_app:create_app`` calls ``tethered.activate()`` and then builds the
application; its views make their outbound requests with ``requests``.  The
factory runs wherever the application is built: in every gunicorn worker (in
the master under ``--preload``), in a ``flask`` command, and in both
processes of the development server when its reloader is on, which
re-executes ``flask run`` as a child process.

Each test asserts what the view reported and what arrived in the world.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from typing import TYPE_CHECKING, Any

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

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

APPLICATION = "flask_app:create_app"
GUNICORN = ["gunicorn", f"{APPLICATION}()", "--bind", "127.0.0.1:{port}", "--workers", "2"]
SERVERS = {"gunicorn": GUNICORN, "gunicorn-preload": [*GUNICORN, "--preload"]}
FLASK = ["flask", "--app", APPLICATION]
FLASK_RUN = [*FLASK, "run", "--host", "127.0.0.1", "--port", "{port}"]

EGRESS_BLOCKED = "tethered._core.EgressBlocked"
AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"

OPS = ["fetch", "connect"]
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]
TO_FORBIDDEN = probe_path("fetch", FORBIDDEN_NAME, OTHER_PORT)
TO_ALLOWED = probe_path("fetch", ALLOWED_NAME, ALLOWED_PORT)
ACTIVATE_NO_OP = (
    r"tethered: activate\(\) no-op — the requested policy is identical to the active locked policy"
)


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_locked(report: dict[str, Any]) -> None:
    assert (report["active"], report["locked"]) == (True, True), report


def wait_until(condition: Callable[[], Any], what: str, timeout: float = 20.0) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        value = condition()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"not within {timeout} s: {what}")
        time.sleep(0.05)


def run_command(argv: list[str], **env: str) -> dict[str, Any]:
    """Run a command line of the application to its end; the JSON it printed last."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if key != "_TETHERED_CHILD_POLICY" and not key.startswith("PYTEST_")
    }
    environment.update(PYTHONPATH=os.pathsep.join([str(APPS_DIR), str(SUITE_DIR)]), **env)
    done = subprocess.run(
        argv,
        env=environment,
        cwd=SUITE_DIR,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    said = f"exit status {done.returncode}\n{done.stdout}\n--- stderr ---\n{done.stderr}"
    assert done.returncode == 0, said
    try:
        return json.loads(done.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        raise AssertionError(f"no JSON on the last line of stdout: {said}") from None


# ── Under gunicorn ────────────────────────────────────────────────────


@pytest.fixture(scope="module", params=list(SERVERS))
def arrangement(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(arrangement: str) -> Server:
    return start_server(SERVERS[arrangement], env={"TETH_ACTIVATE": "locked"})


class TestUnderGunicorn:
    def test_the_factory_gave_every_worker_the_locked_policy(
        self, server: Server, arrangement: str
    ) -> None:
        answers = server.each_worker("/whoami", 2)
        for pid, me in answers.items():
            assert_locked(me)
            assert me["ppid"] == server.pid
            # Where the factory ran: in the master under --preload, else in each worker.
            assert me["imported_in_pid"] == (server.pid if "preload" in arrangement else pid)

    @pytest.mark.parametrize("op", OPS)
    def test_a_view_reaches_the_allowed_destination(self, server: Server, op: str) -> None:
        for report in server.each_worker(probe_path(op, ALLOWED_NAME, ALLOWED_PORT), 2).values():
            assert report["outcome"] == "reached", report
            assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize("op", OPS)
    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_a_view_is_refused_a_destination_outside_the_allow_list(
        self, server: Server, op: str, host: str, port: int
    ) -> None:
        # requests does not wrap the refusal: the view gets EgressBlocked itself.
        for report in server.each_worker(probe_path(op, host, port), 2).values():
            assert_refused(report)
        assert arrivals() == {}

    @pytest.mark.parametrize(
        ("host", "port", "attempt"),
        [
            pytest.param(FORBIDDEN_NAME, OTHER_PORT, "getaddrinfo for forbidden.test", id="lookup"),
            pytest.param(
                FORBIDDEN_ADDR,
                OTHER_PORT,
                f"connect to {FORBIDDEN_ADDR}:{OTHER_PORT}",
                id="connect",
            ),
        ],
    )
    def test_a_refusal_is_not_retried_by_an_adapter_that_retries(
        self, server: Server, host: str, port: int, attempt: str
    ) -> None:
        report = server.probe("fetch", host, port, retries=3)
        assert_refused(report)
        assert arrivals() == {}
        # One attempt, although the adapter retries connection errors three times.
        server.wait_log(f"tethered: blocked {attempt}")
        assert server.log_of_this_test.count("tethered: blocked ") == 1

    def test_an_uncaught_refusal_is_a_500_and_the_workers_survive(self, server: Server) -> None:
        before = server.each_worker("/whoami", 2)
        assert server.get(TO_FORBIDDEN + "&uncaught=1").status == 500
        assert arrivals() == {}
        server.wait_log(f"EgressBlocked: Blocked by tethered: {FORBIDDEN_NAME} is not in the allow")
        assert set(server.each_worker("/whoami", 2)) == set(before)

    def test_a_python_child_of_a_view_inherits_the_locked_policy(self, server: Server) -> None:
        path = probe_path("child", FORBIDDEN_NAME, OTHER_PORT)
        for pid, report in server.each_worker(path, 2).items():
            assert report["outcome"] == "reached", report
            assert report["child"]["ppid"] == pid
            assert_locked(report["child"])
            assert_refused(report["child"])
        assert arrivals() == {}


class TestErrorHandler:
    """``@app.errorhandler(tethered.EgressBlocked)``: one place that answers every refusal."""

    @pytest.fixture(scope="class")
    def handling(self) -> Server:
        return start_server(GUNICORN, env={"TETH_ACTIVATE": "locked", "TETH_HANDLER": "1"})

    def test_a_refused_lookup_reaches_the_handler(self, handling: Server) -> None:
        reply = handling.get(TO_FORBIDDEN + "&uncaught=1")
        assert reply.status == 503
        assert reply.json() == {"error": "egress blocked", "host": FORBIDDEN_NAME, "port": None}
        assert arrivals() == {}
        handling.wait_log(f"Egress blocked: {FORBIDDEN_NAME}:None")

    def test_a_refused_connection_reaches_the_handler(self, handling: Server) -> None:
        reply = handling.get(probe_path("fetch", FORBIDDEN_ADDR, OTHER_PORT, uncaught=1))
        assert reply.status == 503
        assert reply.json() == {
            "error": "egress blocked",
            "host": FORBIDDEN_ADDR,
            "port": OTHER_PORT,
        }
        assert arrivals() == {}

    def test_an_allowed_request_is_answered_as_before(self, handling: Server) -> None:
        reply = handling.get(TO_ALLOWED + "&uncaught=1")
        assert reply.status == 200
        assert reply.json()["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}


# ── A command of the application ──────────────────────────────────────


class TestCommandLine:
    def test_a_flask_command_runs_under_the_policy_of_the_factory(self) -> None:
        command = [*FLASK, "fetch", FORBIDDEN_NAME, str(OTHER_PORT)]
        report = run_command(command, TETH_ACTIVATE="locked")
        assert_locked(report)
        assert_refused(report)
        assert arrivals() == {}

        command = [*FLASK, "fetch", ALLOWED_NAME, str(ALLOWED_PORT)]
        report = run_command(command, TETH_ACTIVATE="locked")
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 1}

    def test_without_tethered_the_command_reaches_the_forbidden_destination(self) -> None:
        # The control: the same command, no policy.
        command = [*FLASK, "fetch", FORBIDDEN_NAME, str(OTHER_PORT)]
        report = run_command(command, TETH_ACTIVATE="none")
        assert report["tethered_imported"] is False, report
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}


# ── The development server ────────────────────────────────────────────


class TestDevelopmentServer:
    def test_without_the_reloader_the_one_process_enforces(self) -> None:
        server = start_server([*FLASK_RUN, "--no-reload"], env={"TETH_ACTIVATE": "locked"})
        me = server.get("/whoami").json()
        assert me["pid"] == server.pid
        assert_locked(me)
        assert_refused(server.probe("fetch", FORBIDDEN_NAME, OTHER_PORT))
        assert arrivals() == {}
        assert server.probe("fetch", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}

    @pytest.mark.parametrize("esp", ["warn", "block"])
    def test_the_process_the_reloader_starts_inherits_the_lock_and_serves_under_it(
        self, esp: str
    ) -> None:
        """The reloader's process builds the application, and so activates, and then starts
        ``flask run`` again as a child: a launch of ``sys.executable``, which carries the
        policy and is not refused under ``"block"`` either.  The child holds the locked policy
        before it builds the application itself.
        """
        env = {"TETH_ACTIVATE": "locked", "TETH_ESP": esp}
        server = start_server([*FLASK_RUN, "--reload"], env=env)
        me = server.get("/whoami").json()
        assert me["ppid"] == server.pid
        assert me["imported_in_pid"] == me["pid"]
        assert_locked(me)
        assert me["external_subprocess_policy"] == esp
        server.wait_log(rf"LOG pid={me['pid']} tethered INFO {ACTIVATE_NO_OP}")
        assert "external subprocess" not in server.log
        assert_refused(server.probe("fetch", FORBIDDEN_NAME, OTHER_PORT))
        assert arrivals() == {}
        assert server.probe("fetch", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}

    def test_the_process_started_after_a_source_file_changed_enforces(self, tmp_path: Path) -> None:
        # The application is served from a copy, so that the test can touch its source.
        source = tmp_path / "flask_app.py"
        source.write_text((SUITE_DIR / "flask_app.py").read_text(encoding="utf-8"))
        env = {
            "TETH_ACTIVATE": "locked",
            "PYTHONPATH": os.pathsep.join([str(APPS_DIR), str(tmp_path)]),
        }
        server = start_server([*FLASK_RUN, "--reload"], env=env, cwd=tmp_path)
        first = server.get("/whoami").json()["pid"]
        assert first != server.pid

        def touched_and_noticed() -> bool:
            # The reloader notes a file's time on its first pass and compares afterwards.
            source.touch()
            return "Detected change in" in server.log_of_this_test

        wait_until(touched_and_noticed, "the reloader notices the touched source file")
        (report,) = server.each_worker(TO_FORBIDDEN, 1, exclude={first}).values()
        assert report["ppid"] == server.pid
        assert_locked(report)
        assert_refused(report)
        assert arrivals() == {}
