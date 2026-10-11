"""Django, with the policy activated in ``settings.py``.

The settings module is what every entry point of a Django project imports
first, so that is where the project in this directory (``djsite``, ``djapp``)
calls ``tethered.activate()``.  The tests follow it through the entry points:

- the WSGI application under gunicorn, with and without ``--preload``;
- a management command (``python manage.py fetch``);
- ``runserver``, whose autoreloader runs the server in a child process that
  it starts again whenever a source file changes;
- the middleware of ``docs/COOKBOOK.md``, as printed there.

The views make their outbound requests with ``requests``.  Django 6 needs
Python 3.12, so on Python 3.11 the suite runs on the 5.2 long-term series.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
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

GUNICORN = ["gunicorn", "djsite.wsgi:application", "--bind", "127.0.0.1:{port}", "--workers", "2"]
SERVERS = {"gunicorn": GUNICORN, "gunicorn-preload": [*GUNICORN, "--preload"]}
MANAGE = [sys.executable, "manage.py"]
RUNSERVER = [*MANAGE, "runserver", "127.0.0.1:{port}"]

EGRESS_BLOCKED = "tethered._core.EgressBlocked"
AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"
DEFAULT_RULE = f"{ALLOWED_NAME}:{ALLOWED_PORT}"
OTHER_RULE = f"{FORBIDDEN_NAME}:{OTHER_PORT}"

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
LOCKED_AND_DIFFERENT = (
    r"TetheredLocked: tethered: activate\(\) blocked — a locked policy is active and the "
    r"requested policy differs from it"
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


def manage(*arguments: str, **env: str) -> subprocess.CompletedProcess[str]:
    """Run ``python manage.py <arguments>`` in the project directory, to its end."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if key != "_TETHERED_CHILD_POLICY" and not key.startswith("PYTEST_")
    }
    environment.update(PYTHONPATH=os.pathsep.join([str(APPS_DIR), str(SUITE_DIR)]), **env)
    return subprocess.run(
        [*MANAGE, *arguments],
        env=environment,
        cwd=SUITE_DIR,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def report_of(done: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    """The JSON a management command printed on its last line."""
    said = f"exit status {done.returncode}\n{done.stdout}\n--- stderr ---\n{done.stderr}"
    assert done.returncode == 0, said
    try:
        return json.loads(done.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        raise AssertionError(f"no JSON on the last line of stdout: {said}") from None


def allow_file(tmp_path: Path, *rules: str) -> Path:
    path = tmp_path / "allow.txt"
    path.write_text("\n".join(rules) + "\n", encoding="utf-8")
    return path


# ── The WSGI application under gunicorn ───────────────────────────────


@pytest.fixture(scope="module", params=list(SERVERS))
def arrangement(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(arrangement: str) -> Server:
    return start_server(SERVERS[arrangement], env={"TETH_ACTIVATE": "locked"})


class TestUnderGunicorn:
    def test_the_settings_gave_every_worker_the_locked_policy(
        self, server: Server, arrangement: str
    ) -> None:
        for pid, me in server.each_worker("/whoami", 2).items():
            assert_locked(me)
            assert me["ppid"] == server.pid
            # Where the settings were imported: in the master under --preload.
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
        for report in server.each_worker(probe_path(op, host, port), 2).values():
            assert_refused(report)
        assert arrivals() == {}

    def test_an_uncaught_refusal_is_a_500_and_the_workers_survive(self, server: Server) -> None:
        before = server.each_worker("/whoami", 2)
        assert server.get(TO_FORBIDDEN + "&uncaught=1").status == 500
        assert arrivals() == {}
        # Django's own report of the failed request, with the traceback.
        server.wait_log("django.request ERROR Internal Server Error: /fetch")
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


# ── The middleware of the cookbook ────────────────────────────────────


class TestCookbookMiddleware:
    def test_the_middleware_as_printed_does_not_see_the_refusal_of_a_view(self) -> None:
        """Limit: the recipe wraps ``get_response()`` in ``try`` / ``except``, and Django has
        turned the view's exception into a 500 response before that call returns.  The
        connection is refused all the same; the request ends as a 500, not the recipe's 503.
        """
        env = {"TETH_ACTIVATE": "locked", "TETH_MIDDLEWARE": "printed"}
        server = start_server(GUNICORN, env=env)
        reply = server.get(TO_FORBIDDEN + "&uncaught=1")
        assert reply.status == 500
        assert "Service unavailable" not in reply.text
        assert arrivals() == {}
        server.wait_log("django.request ERROR Internal Server Error: /fetch")
        assert "Egress blocked:" not in server.log
        # The middleware is in the request path: an allowed request passes through it.
        assert server.get(TO_ALLOWED + "&uncaught=1").json()["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}

    def test_a_middleware_with_process_exception_answers_the_refusal_with_a_503(self) -> None:
        env = {"TETH_ACTIVATE": "locked", "TETH_MIDDLEWARE": "process_exception"}
        server = start_server(GUNICORN, env=env)
        reply = server.get(TO_FORBIDDEN + "&uncaught=1")
        assert (reply.status, reply.text) == (503, "Service unavailable")
        assert arrivals() == {}
        server.wait_log(f"Egress blocked: {FORBIDDEN_NAME}:None \\(resolved_from=None\\)")

        # Refused at the connection, by a port rule: the exception names the address.
        reply = server.get(probe_path("fetch", ALLOWED_NAME, OTHER_PORT, uncaught=1))
        assert (reply.status, reply.text) == (503, "Service unavailable")
        assert arrivals() == {}
        server.wait_log(
            f"Egress blocked: {ALLOWED_ADDR}:{OTHER_PORT} \\(resolved_from={ALLOWED_NAME}\\)"
        )

        assert server.get(TO_ALLOWED + "&uncaught=1").json()["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}


# ── A management command ──────────────────────────────────────────────


class TestManagementCommand:
    def test_a_command_runs_under_the_policy_of_the_settings(self) -> None:
        report = report_of(manage("fetch", FORBIDDEN_NAME, str(OTHER_PORT), TETH_ACTIVATE="locked"))
        assert_locked(report)
        assert_refused(report)
        assert arrivals() == {}

        report = report_of(manage("fetch", ALLOWED_NAME, str(ALLOWED_PORT), TETH_ACTIVATE="locked"))
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 1}

    def test_the_system_check_runs_under_a_locked_policy(self) -> None:
        done = manage("check", TETH_ACTIVATE="locked")
        assert done.returncode == 0, done.stderr
        assert "System check identified no issues" in done.stdout
        assert arrivals() == {}

    def test_without_tethered_the_command_reaches_the_forbidden_destination(self) -> None:
        # The control: the same command, no policy.
        report = report_of(manage("fetch", FORBIDDEN_NAME, str(OTHER_PORT), TETH_ACTIVATE="none"))
        assert report["tethered_imported"] is False, report
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}


# ── runserver and its autoreloader ────────────────────────────────────


def touch_until_reloading(server: Server) -> None:
    """Touch a source file of the project until the autoreloader says it noticed."""
    source = SUITE_DIR / "djapp" / "views.py"

    def touched_and_noticed() -> bool:
        # The reloader notes a file's time on its first pass and compares afterwards.
        source.touch()
        return "views.py changed, reloading" in server.log_of_this_test

    wait_until(touched_and_noticed, "the autoreloader notices the touched source file")


class TestRunserver:
    def test_without_the_autoreloader_the_one_process_enforces(self) -> None:
        server = start_server([*RUNSERVER, "--noreload"], env={"TETH_ACTIVATE": "locked"})
        me = server.get("/whoami").json()
        assert me["pid"] == server.pid
        assert_locked(me)
        assert_refused(server.probe("fetch", FORBIDDEN_NAME, OTHER_PORT))
        assert arrivals() == {}
        assert server.probe("fetch", ALLOWED_NAME, ALLOWED_PORT)["outcome"] == "reached"
        assert arrivals() == {AT_ALLOWED: 1}

    @pytest.mark.parametrize("esp", ["warn", "block"])
    def test_the_process_the_autoreloader_starts_inherits_the_lock_and_serves_under_it(
        self, esp: str
    ) -> None:
        """``manage.py runserver`` imports the settings, and so activates, and then starts
        itself again as a child that serves: a launch of ``sys.executable`` that carries the
        policy, not refused under ``"block"`` either.  The child holds the locked policy when
        it imports the settings itself.
        """
        server = start_server(RUNSERVER, env={"TETH_ACTIVATE": "locked", "TETH_ESP": esp})
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

    def test_the_process_started_after_a_source_file_changed_enforces(self) -> None:
        server = start_server(RUNSERVER, env={"TETH_ACTIVATE": "locked"})
        first = server.get("/whoami").json()["pid"]
        assert first != server.pid
        touch_until_reloading(server)
        (report,) = server.each_worker(TO_FORBIDDEN, 1, exclude={first}).values()
        assert report["ppid"] == server.pid
        assert_locked(report)
        assert_refused(report)
        assert arrivals() == {}

    def test_an_unlocked_policy_changes_when_the_autoreloader_restarts(
        self, tmp_path: Path
    ) -> None:
        rules = allow_file(tmp_path, DEFAULT_RULE)
        env = {"TETH_ACTIVATE": "plain", "TETH_ALLOW_FILE": str(rules)}
        server = start_server(RUNSERVER, env=env)
        first = server.probe("fetch", FORBIDDEN_NAME, OTHER_PORT)
        assert_refused(first)
        assert arrivals() == {}

        allow_file(tmp_path, DEFAULT_RULE, OTHER_RULE)
        touch_until_reloading(server)
        (report,) = server.each_worker(TO_FORBIDDEN, 1, exclude={first["pid"]}).values()
        assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_FORBIDDEN}

    def test_a_changed_locked_policy_ends_runserver_when_the_autoreloader_restarts(
        self, tmp_path: Path
    ) -> None:
        """Limit: the autoreloader's own process holds the locked policy and hands it to every
        child it starts.  When the settings now ask for another allow list, the child's
        ``activate()`` raises ``TetheredLocked``, the child cannot import its settings, and
        ``runserver`` exits.  Start it again to change a locked policy.
        """
        rules = allow_file(tmp_path, DEFAULT_RULE)
        env = {"TETH_ACTIVATE": "locked", "TETH_ALLOW_FILE": str(rules)}
        server = start_server(RUNSERVER, env=env)
        assert_refused(server.probe("fetch", FORBIDDEN_NAME, OTHER_PORT))

        allow_file(tmp_path, DEFAULT_RULE, OTHER_RULE)
        touch_until_reloading(server)
        server.wait_log(LOCKED_AND_DIFFERENT)
        wait_until(lambda: not server.running, "runserver exits")
        wait_until(lambda: not server.pids(), "nothing of runserver is left")
        assert arrivals() == {}
        assert server.stop(check=False) == 1
