"""Apache with mod_wsgi: what a request handler launches under a locked policy.

A launch is judged in the interpreter that makes it, and under mod_wsgi a
process can have three kinds.  The server of these tests has one of each in
a daemon process, imported when the process starts, in this order:

    /early   never imports tethered; exists before the lock: outside it
    /shop    takes the lock: the holder
    /blog    never imports tethered; created under the lock: joined

The holder and a joined interpreter launch by the same rules, the ones the
other servers' suites show for a worker process.  An interpreter outside the
lock launches nothing.

``sys.executable`` under mod_wsgi is the Python that mod_wsgi was built for,
not Apache, so "a Python child" is recognised here as anywhere else.

The last class is ``os.fork()`` followed by ``os.exec*``, which only the main
interpreter can do: in a subinterpreter the forked child is ended by CPython
("Fatal Python error: ... not main interpreter"), with or without tethered.
"""

from __future__ import annotations

from typing import Any

import pytest
from apache import Site, ask, standing
from expect import (
    AT_FORBIDDEN,
    NO_LAUNCHES,
    RUNTIME_ERROR,
    SUBPROCESS_BLOCKED,
    reached,
    refused,
)
from harness import FORBIDDEN_ADDR, FORBIDDEN_NAME, OTHER_PORT, Server, arrivals

THREE_KINDS = """
    WSGIRestrictEmbedded On
    WSGIDaemonProcess apps processes=1 threads=2
    WSGIScriptAlias /early {early} process-group=apps application-group=early
    WSGIScriptAlias /shop {shop} process-group=apps application-group=shop
    WSGIScriptAlias /blog {blog} process-group=apps application-group=blog
"""
#: The interpreters that have the locked policy.
UNDER_THE_POLICY = ["/shop", "/blog"]


def three_kinds(esp: str | None = None) -> Server:
    site = Site()
    scripts = {
        "early": site.script("early"),
        "shop": site.script("shop", activate="locked", esp=esp),
        "blog": site.script("blog"),
    }
    server = site.start(THREE_KINDS.format(**scripts))
    assert standing(ask(server, "/early", "whoami")) == "none"
    assert standing(ask(server, "/shop", "whoami")) == "holder"
    assert standing(ask(server, "/blog", "whoami")) == "joined"
    return server


@pytest.fixture(scope="module")
def warning() -> Server:
    """The default ``external_subprocess_policy`` (warn)."""
    return three_kinds()


@pytest.fixture(scope="module")
def blocking() -> Server:
    """``external_subprocess_policy="block"``."""
    return three_kinds(esp="block")


def launch(server: Server, mount: str, how: str | None = None) -> dict[str, Any]:
    """Have the application launch a Python child (``how``) or, without it, a tool."""
    if how is None:
        return ask(server, mount, "tool", FORBIDDEN_NAME, OTHER_PORT)
    return ask(server, mount, "child", FORBIDDEN_NAME, OTHER_PORT, how=how)


@pytest.mark.parametrize("mount", UNDER_THE_POLICY)
class TestTheHolderAndAJoinedInterpreter:
    def test_a_child_started_with_sys_executable_inherits_the_lock(
        self, warning: Server, mount: str
    ) -> None:
        report = launch(warning, mount, "executable")
        reached(report)
        assert report["child"]["locked"] is True, report
        refused(report["child"])
        assert arrivals() == {}
        assert "external subprocess" not in warning.log_of_this_test

    def test_a_child_started_as_python3_is_warned_about_and_inherits_all_the_same(
        self, warning: Server, mount: str
    ) -> None:
        report = launch(warning, mount, "path_python")
        reached(report)
        assert report["child"]["locked"] is True, report
        refused(report["child"])
        assert arrivals() == {}
        warning.wait_log(r"external subprocess launch detected: subprocess\.Popen\(python3\)")

    def test_a_child_given_an_environment_without_the_policy_is_not_launched(
        self, warning: Server, mount: str
    ) -> None:
        report = launch(warning, mount, "clean_env")
        refused(report, SUBPROCESS_BLOCKED)
        assert "env strips _TETHERED_CHILD_POLICY" in report["message"], report
        assert arrivals() == {}

    def test_a_child_started_without_site_is_warned_about_and_holds_no_policy(
        self, warning: Server, mount: str
    ) -> None:
        # "python -S" does not run the bootstrap: a documented limit, which
        # external_subprocess_policy="block" closes (below).
        report = launch(warning, mount, "no_site")
        reached(report)
        assert report["child"]["active"] is False, report
        reached(report["child"])
        assert arrivals() == {AT_FORBIDDEN: 1}
        warning.wait_log("external subprocess launch detected")

    def test_a_tool_is_warned_about_and_is_not_restricted(
        self, warning: Server, mount: str
    ) -> None:
        report = launch(warning, mount)
        reached(report)
        assert report["stdout"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}", report
        assert arrivals() == {AT_FORBIDDEN: 1}
        warning.wait_log(r"external subprocess launch detected: subprocess\.Popen\(bash\)")

    def test_under_block_a_child_started_with_sys_executable_is_launched_and_inherits(
        self, blocking: Server, mount: str
    ) -> None:
        report = launch(blocking, mount, "executable")
        reached(report)
        assert report["child"]["locked"] is True, report
        assert report["child"]["external_subprocess_policy"] == "block", report
        refused(report["child"])
        assert arrivals() == {}

    @pytest.mark.parametrize("how", ["path_python", "no_site", "clean_env", None])
    def test_under_block_nothing_else_is_launched(
        self, blocking: Server, mount: str, how: str | None
    ) -> None:
        refused(launch(blocking, mount, how), SUBPROCESS_BLOCKED)
        assert arrivals() == {}


class TestAnInterpreterOutsideTheLock:
    @pytest.mark.parametrize("how", ["executable", "path_python", "no_site", "clean_env", None])
    def test_nothing_is_launched(self, warning: Server, how: str | None) -> None:
        # Not even the child that would inherit the lock.  The interpreter
        # never imported tethered, so the refusal is a RuntimeError.
        report = launch(warning, "/early", how)
        assert report["outcome"] == "error", report
        assert report["exception"] == RUNTIME_ERROR, report
        assert report["message"] == f"Blocked by tethered: subprocess.Popen {NO_LAUNCHES}", report
        assert arrivals() == {}


# ── os.fork() and os.exec*, in the main interpreter ───────────────────

IN_THE_MAIN_INTERPRETER = """
    WSGIRestrictEmbedded On
    WSGIDaemonProcess shop processes=1 threads=2
    WSGIScriptAlias /shop {shop}
    <Location /shop>
        WSGIProcessGroup shop
        WSGIApplicationGroup %{{GLOBAL}}
    </Location>
"""


class TestForkAndExec:
    @pytest.mark.parametrize("policy", ["plain", "locked"])
    def test_an_exec_of_python_with_a_bare_environment_is_given_the_policy(
        self, policy: str
    ) -> None:
        # The handler forks and the child calls os.execve(sys.executable, ...)
        # with an environment that has PATH and nothing else.  tethered carries
        # the exec out with the policy variable added, under a lock as well.
        site = Site()
        shop = site.script("shop", activate=policy)
        server = site.start(IN_THE_MAIN_INTERPRETER.format(shop=shop))
        report = ask(server, "/shop", "fork_exec", FORBIDDEN_NAME, OTHER_PORT)
        assert report["main_interpreter"] is True, report
        reached(report)
        child = report["child"]
        assert child["ppid"] == report["pid"], report
        assert child["active"] is True, report
        assert child["locked"] is (policy == "locked"), report
        assert child["policy_in_environ"] is True, report
        refused(child)
        assert arrivals() == {}
        if policy == "locked":
            server.wait_log(
                r"os\.exec\*\(\S+\) was given an environment without _TETHERED_CHILD_POLICY; "
                "carried out with the locked policy added"
            )

    def test_the_same_environment_given_to_subprocess_is_refused_under_a_lock(self) -> None:
        # Only an exec is completed.  subprocess with that environment is
        # refused under a lock, here as in the subinterpreters above.
        site = Site()
        shop = site.script("shop", activate="locked")
        server = site.start(IN_THE_MAIN_INTERPRETER.format(shop=shop))
        report = ask(server, "/shop", "child", FORBIDDEN_NAME, OTHER_PORT, how="clean_env")
        refused(report, SUBPROCESS_BLOCKED)
        assert "env strips _TETHERED_CHILD_POLICY" in report["message"], report
        assert arrivals() == {}
