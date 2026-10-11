"""The standard library's worker pools, owned by a process that holds the policy.

``multiprocessing.Pool`` and ``concurrent.futures.ProcessPoolExecutor`` with
the fork, spawn and forkserver start methods, and
``concurrent.futures.InterpreterPoolExecutor`` on Python 3.14 and later.  How
a worker gets the policy differs with each: a forked worker is a copy of a
process that holds it, a spawned one finds it in its environment when it
starts, a forkserver worker is a copy of the fork server, which found it in
its environment, and a worker interpreter joins the lock of its process (or
activates the policy it finds in the environment, when nothing is locked).

The owner is ``pool_server.py``: an HTTP front end that activates the policy,
creates the pool and runs one task per request (``pool_tasks.probe``).  Each
test asserts what the worker reported and what arrived in the world, and
checks in ``/proc`` that the workers were started the way the test asked for.

The unit tests (``tests/test_subprocess.py``, ``tests/test_exceptions.py``,
``tests/test_subinterpreters.py``) cover much of this from inside one pytest
process; this is the installed package, in a clean container.  Not covered:
``multiprocessing.Process`` on its own, managers, and thread pools (the same
process and interpreter as their owner).
"""

from __future__ import annotations

import sys
from pathlib import Path
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

EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"
TETHERED_LOCKED = "tethered._core.TetheredLocked"
REFUSED_NAME = f"Blocked by tethered: {FORBIDDEN_NAME} is not in the allow list"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"

KINDS = ["mp-pool", "process-pool"]
METHODS = ["fork", "spawn", "forkserver"]
#: What a process is started with when no context is named.
DEFAULT_METHOD = "forkserver" if sys.version_info >= (3, 14) else "fork"
#: Destinations the allow list does not cover.
REFUSED = [
    pytest.param(FORBIDDEN_NAME, OTHER_PORT, id="forbidden-name"),
    pytest.param(FORBIDDEN_ADDR, OTHER_PORT, id="forbidden-address"),
    pytest.param(FORBIDDEN_NAME, ALLOWED_PORT, id="forbidden-name-on-the-allowed-port"),
    pytest.param(ALLOWED_NAME, OTHER_PORT, id="allowed-name-on-another-port"),
]

interpreter_pools = pytest.mark.skipif(
    sys.version_info < (3, 14), reason="InterpreterPoolExecutor is new in Python 3.14"
)


def owner(
    kind: str,
    method: str = "default",
    *,
    mode: str = "locked",
    where: str = "main",
    recycle: int = 0,
    workers: int = 2,
    esp: str | None = None,
) -> Server:
    """Start ``pool_server.py``: the process that holds the policy and owns the pool."""
    env = {
        "TETH_ACTIVATE": mode,
        "TETH_WHERE": where,
        "POOL_RECYCLE": str(recycle),
        "POOL_WORKERS": str(workers),
        **({"TETH_ESP": esp} if esp else {}),
    }
    return start_server(["python", "pool_server.py", kind, method], env=env, ready="/owner")


def command_line(pid: int) -> str:
    return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode().strip()


def parent_of(pid: int) -> int:
    # "pid (comm) state ppid ...": comm may contain spaces and brackets.
    return int(Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[1])


def assert_started_by(
    method: str, report: dict[str, Any], server: Server, *, alive: bool = True
) -> None:
    """The worker that wrote ``report`` was started the way ``method`` says.

    From the report, where it was started from and where the task module was
    imported; and, for a worker that is still ``alive``, its command line.
    """
    pid = report["pid"]
    if method == "fork":
        # A copy of the owner: the same modules, the same command line.
        assert report["ppid"] == server.pid
        assert report["imported_in_pid"] == server.pid
        expected = command_line(server.pid)
    elif method == "spawn":
        # A new interpreter that the owner started.
        assert report["ppid"] == server.pid
        assert report["imported_in_pid"] == pid
        expected = "from multiprocessing.spawn import spawn_main"
    else:
        # A copy of the fork server, which the owner started.  From Python 3.13
        # the fork server has imported the owner's main module, and so the task
        # module; on 3.11 and 3.12 the worker imports them itself.
        assert report["ppid"] != server.pid
        assert report["imported_in_pid"] in (report["ppid"], pid)
        assert parent_of(report["ppid"]) == server.pid
        expected = "from multiprocessing.forkserver import main"
        assert expected in command_line(report["ppid"])
    if alive:
        assert expected in command_line(pid)


def assert_refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def assert_policy(report: dict[str, Any], mode: str) -> None:
    assert report["active"] is True, report
    assert report["locked"] is (mode == "locked"), report


# ── Process pools: every kind, every start method, a plain and a locked policy ──


@pytest.fixture(scope="module", params=KINDS)
def kind(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module", params=METHODS)
def method(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module", params=["plain", "locked"])
def mode(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="module")
def server(kind: str, method: str, mode: str) -> Server:
    """An owner that activates the policy in ``main()`` and then creates a pool of two."""
    return owner(kind, method, mode=mode)


class TestProcessPools:
    def test_every_worker_was_started_as_asked_and_holds_the_policy(
        self, server: Server, method: str, mode: str
    ) -> None:
        me = server.get("/owner").json()
        assert me["pid"] == server.pid
        assert_policy(me, mode)
        answers = server.each_worker("/whoami", 2)
        assert server.pid not in answers
        for report in answers.values():
            assert_started_by(method, report, server)
            assert_policy(report, mode)

    def test_every_worker_reaches_the_allowed_destination(self, server: Server) -> None:
        path = probe_path("connect", ALLOWED_NAME, ALLOWED_PORT)
        for report in server.each_worker(path, 2).values():
            assert report["outcome"] == "reached", report
            assert report["reply"] == f"reached {ALLOWED_ADDR}:{ALLOWED_PORT}"
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize(("host", "port"), REFUSED)
    def test_every_worker_refuses_a_destination_outside_the_allow_list(
        self, server: Server, host: str, port: int
    ) -> None:
        for report in server.each_worker(probe_path("connect", host, port), 2).values():
            assert_refused(report)
        assert arrivals() == {}

    def test_an_uncaught_refusal_reaches_the_owner_as_egress_blocked(self, server: Server) -> None:
        before = server.each_worker("/whoami", 2)
        task = server.probe("connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)["task"]
        assert arrivals() == {}
        # The pool pickles the exception in the worker and raises it where the
        # result is asked for: `except tethered.EgressBlocked` works there.
        assert task["exception"] == EGRESS_BLOCKED, task
        assert task["message"] == REFUSED_NAME
        assert task["host"] == FORBIDDEN_NAME
        # The pool is not broken by it and keeps its workers.
        assert set(server.each_worker("/whoami", 2)) == set(before)

    def test_a_python_child_of_a_worker_inherits_the_policy(
        self, server: Server, mode: str
    ) -> None:
        path = probe_path("child", FORBIDDEN_NAME, OTHER_PORT)
        for pid, report in server.each_worker(path, 2).items():
            assert report["outcome"] == "reached", report
            child = report["child"]
            assert child["ppid"] == pid
            assert_policy(child, mode)
            assert_refused(child)
        assert arrivals() == {}

    def test_a_tool_launched_by_a_worker_is_warned_about_and_is_not_restricted(
        self, server: Server
    ) -> None:
        report = server.probe("tool", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert report["stdout"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}"
        assert arrivals() == {AT_FORBIDDEN: 1}
        server.wait_log(r"external subprocess launch detected: subprocess\.Popen\(bash\)")


# ── Workers that are started later ────────────────────────────────────

#: ProcessPoolExecutor refuses max_tasks_per_child with the fork start method.
RECYCLING = [
    ("mp-pool", "fork"),
    ("mp-pool", "spawn"),
    ("mp-pool", "forkserver"),
    ("process-pool", "spawn"),
    ("process-pool", "forkserver"),
]


class TestLaterWorkers:
    @pytest.mark.parametrize(("kind", "method"), RECYCLING)
    @pytest.mark.parametrize("mode", ["plain", "locked"])
    def test_a_worker_that_replaces_a_recycled_one_enforces_the_policy(
        self, kind: str, method: str, mode: str
    ) -> None:
        server = owner(kind, method, mode=mode, recycle=3)
        first = server.each_worker("/whoami", 2)

        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2, exclude=first).values():
            # (A replacement may itself have been replaced by now.)
            assert_started_by(method, report, server, alive=False)
            assert_policy(report, mode)
            assert_refused(report)
        assert arrivals() == {}

        path = probe_path("connect", ALLOWED_NAME, ALLOWED_PORT)
        for report in server.each_worker(path, 2, exclude=first).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}

    @pytest.mark.parametrize("method", METHODS)
    def test_a_worker_that_replaces_a_dead_one_enforces_the_policy(self, method: str) -> None:
        # multiprocessing.Pool starts another worker when one dies.  (A
        # ProcessPoolExecutor is broken from then on, with or without tethered.)
        server = owner("mp-pool", method)
        first = server.each_worker("/whoami", 2)
        # A worker is killed in the middle of a task, as by the OOM killer: the
        # task is lost, and the owner is not kept waiting for it here.
        lost = server.probe("die", wait=0)["task"]
        assert lost["exception"] == "multiprocessing.context.TimeoutError", lost

        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 1, exclude=first).values():
            assert_started_by(method, report, server)
            assert_policy(report, "locked")
            assert_refused(report)
        assert arrivals() == {}


# ── Other arrangements of the owner ───────────────────────────────────


class TestTheOwner:
    @pytest.mark.parametrize("kind", KINDS)
    def test_a_pool_with_no_context_uses_the_default_start_method(self, kind: str) -> None:
        # fork up to Python 3.13, forkserver from 3.14.
        server = owner(kind)
        assert server.get("/owner").json()["default_start_method"] == DEFAULT_METHOD
        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2).values():
            assert_started_by(DEFAULT_METHOD, report, server)
            assert_policy(report, "locked")
            assert_refused(report)
        assert arrivals() == {}

    @pytest.mark.parametrize("method", ["spawn", "forkserver"])
    @pytest.mark.parametrize("mode", ["plain", "locked"])
    def test_activate_at_the_top_of_the_main_module_runs_again_in_the_workers(
        self, method: str, mode: str
    ) -> None:
        # Outside the __main__ guard: a spawned worker, and the fork server, run
        # the main module again and call activate() with the policy they inherited.
        server = owner("process-pool", method, mode=mode, where="module")
        answers = server.each_worker(probe_path("connect", FORBIDDEN_NAME, OTHER_PORT), 2)
        for report in answers.values():
            assert_started_by(method, report, server)
            assert_policy(report, mode)
            assert_refused(report)
        assert arrivals() == {}
        path = probe_path("connect", ALLOWED_NAME, ALLOWED_PORT)
        for report in server.each_worker(path, 2).values():
            assert report["outcome"] == "reached", report
        assert set(arrivals()) == {AT_ALLOWED}
        if mode == "locked":
            # What the second activate() of a worker says: nothing changed.
            server.wait_log("no-op — the requested policy is identical to the active locked")

    @pytest.mark.parametrize("method", METHODS)
    def test_a_worker_can_neither_release_nor_replace_a_locked_policy(self, method: str) -> None:
        server = owner("mp-pool", method)
        for op in ("deactivate", "widen"):
            report = server.probe(op)
            assert report["exception"] == TETHERED_LOCKED, report
            assert_policy(report, "locked")
        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for report in server.each_worker(path, 2).values():
            assert_refused(report)
        assert arrivals() == {}

    @pytest.mark.parametrize("kind", KINDS)
    @pytest.mark.parametrize("method", METHODS)
    def test_the_pool_starts_under_external_subprocess_policy_block(
        self, kind: str, method: str
    ) -> None:
        # Starting a worker, a fork server or multiprocessing's resource tracker
        # is a launch of this interpreter: not an external one.
        server = owner(kind, method, esp="block")
        for report in server.each_worker("/whoami", 2).values():
            assert_started_by(method, report, server)
            assert_policy(report, "locked")
            assert report["external_subprocess_policy"] == "block"
        assert "blocked external subprocess launch" not in server.log

        assert_refused(server.probe("tool", FORBIDDEN_NAME, OTHER_PORT), SUBPROCESS_BLOCKED)
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert_refused(report["child"])
        assert arrivals() == {}


# ── A pool that is older than the policy ──────────────────────────────


class TestPoolsOlderThanThePolicy:
    @pytest.mark.parametrize("method", ["fork", "spawn"])
    def test_workers_from_before_activate_hold_no_policy_and_their_replacements_do(
        self, method: str
    ) -> None:
        """Limit: a worker process that was started before ``activate()`` is not restricted.

        The policy reaches a process when it starts.  Once the old workers
        are replaced (here after three tasks each), the new ones enforce it.
        """
        server = owner("mp-pool", method, where="after_warmup", recycle=3)
        assert_policy(server.get("/owner").json(), "locked")
        first = [int(pid) for pid in server.wait_log(r"workers \[(.*)\]").group(1).split(", ")]

        report = server.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert report["pid"] in first
        assert report["active"] is False, report
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}

        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        for later in server.each_worker(path, 2, exclude=first).values():
            assert_policy(later, "locked")
            assert_refused(later)

    @pytest.mark.parametrize("kind", KINDS)
    def test_a_fork_server_from_before_activate_keeps_producing_unrestricted_workers(
        self, kind: str
    ) -> None:
        """Limit: workers of a fork server that is older than the policy are never restricted.

        A forkserver worker is a copy of the fork server, not of the owner and
        not a new interpreter: it gets neither the owner's policy nor the
        environment variable.  When the fork server was started before
        ``activate()`` (here by a pool that was used first), every later
        worker is unrestricted too, although it starts under a locked policy.
        forkserver is the default start method from Python 3.14.
        """
        server = owner(kind, "forkserver", where="after_warmup", recycle=3)
        assert_policy(server.get("/owner").json(), "locked")
        first = [int(pid) for pid in server.wait_log(r"workers \[(.*)\]").group(1).split(", ")]

        path = probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
        later = server.each_worker(path, 2, exclude=first)
        for report in later.values():
            assert_started_by("forkserver", report, server, alive=False)
            assert report["active"] is False, report
            assert report["outcome"] == "reached", report
        assert arrivals()[AT_FORBIDDEN] >= len(later)


# ── Worker interpreters (Python 3.14+) ────────────────────────────────


def interpreters(mode: str = "locked", where: str = "main") -> Server:
    return owner("interpreter-pool", mode=mode, where=where, workers=1)


def assert_a_worker_interpreter(report: dict[str, Any], server: Server) -> None:
    assert report["pid"] == server.pid
    assert report["interpreter"] not in (None, 0), report


@interpreter_pools
class TestInterpreterPool:
    def test_a_worker_started_under_a_lock_joins_it(self) -> None:
        server = interpreters()
        me = server.probe("whoami")
        assert_a_worker_interpreter(me, server)
        assert_policy(me, "locked")

        report = server.probe("connect", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        report = server.probe("connect", LOOPBACK_ADDR, OTHER_PORT)
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_ALLOWED: 1, f"{LOOPBACK_ADDR}:{OTHER_PORT}/tcp": 1}

        for host, port in [(FORBIDDEN_NAME, OTHER_PORT), (FORBIDDEN_ADDR, OTHER_PORT)]:
            assert_refused(server.probe("connect", host, port))
        task = server.probe("connect", FORBIDDEN_NAME, OTHER_PORT, uncaught=1)["task"]
        assert task["exception"] == EGRESS_BLOCKED, task
        assert task["message"] == REFUSED_NAME
        assert task["cause"] == "ExecutionFailed"

        # It has no token: it can neither release nor replace the policy.
        for op in ("deactivate", "widen"):
            report = server.probe(op)
            assert report["exception"] == TETHERED_LOCKED, report
            assert_policy(report, "locked")

        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert_policy(report["child"], "locked")
        assert_refused(report["child"])
        assert len(arrivals()) == 2, "nothing but the two allowed connections"

    def test_a_worker_from_before_the_lock_gets_no_network_at_all(self) -> None:
        """Limit: a worker interpreter that existed before the lock is refused everything.

        It cannot join the lock afterwards, so the guardian refuses it every
        guarded operation: the allowed destination and loopback too, and
        launches.  Create the pool after ``activate(locked=True)``.
        """
        server = interpreters(where="after_warmup")
        assert_policy(server.get("/owner").json(), "locked")
        me = server.probe("whoami")
        assert_a_worker_interpreter(me, server)
        assert me["active"] is False, me

        # tethered is not imported in that interpreter, so the refusal is a
        # plain RuntimeError there; it says what the matter is.
        for host, port in [
            (ALLOWED_NAME, ALLOWED_PORT),
            (LOOPBACK_ADDR, OTHER_PORT),
            (FORBIDDEN_NAME, OTHER_PORT),
        ]:
            report = server.probe("connect", host, port)
            assert report["exception"] == "builtins.RuntimeError", report
            assert report["message"] == (
                f"Blocked by tethered: {host} (a locked tethered policy is active in another "
                "interpreter of this process, so this interpreter gets no network access)"
            )
        report = server.probe("child", FORBIDDEN_NAME, OTHER_PORT)
        assert report["exception"] == "builtins.RuntimeError", report
        assert "so this interpreter cannot launch processes" in report["message"]
        assert arrivals() == {}

        # Once tethered is imported there, the same refusal is an EgressBlocked.
        report = server.probe("deactivate")
        assert report["exception"] == TETHERED_LOCKED, report
        assert "this interpreter is outside that lock" in report["message"]
        assert_refused(server.probe("connect", ALLOWED_NAME, ALLOWED_PORT))
        assert arrivals() == {}

    def test_a_worker_started_under_a_plain_policy_activates_it(self) -> None:
        # Nothing is locked: the new interpreter finds the policy in the
        # environment of its process and activates it for itself.
        server = interpreters("plain")
        me = server.probe("whoami")
        assert_a_worker_interpreter(me, server)
        assert_policy(me, "plain")
        report = server.probe("connect", ALLOWED_NAME, ALLOWED_PORT)
        assert report["outcome"] == "reached", report
        assert_refused(server.probe("connect", FORBIDDEN_NAME, OTHER_PORT))
        assert arrivals() == {AT_ALLOWED: 1}

    def test_a_worker_from_before_a_plain_policy_holds_none(self) -> None:
        """Limit: a worker interpreter that existed before a plain ``activate()`` is unrestricted.

        An unlocked policy lives in the interpreter that activated it.  An
        interpreter that was already running is not told, and connects where
        it likes.  (Under a lock it would be refused everything instead.)
        """
        server = interpreters("plain", where="after_warmup")
        assert_policy(server.get("/owner").json(), "plain")
        report = server.probe("connect", FORBIDDEN_NAME, OTHER_PORT)
        assert_a_worker_interpreter(report, server)
        assert report["active"] is False, report
        assert report["outcome"] == "reached", report
        assert arrivals() == {AT_FORBIDDEN: 1}
