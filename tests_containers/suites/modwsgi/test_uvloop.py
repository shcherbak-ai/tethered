"""Apache with mod_wsgi and uvloop: what an application can do with it next to a policy.

mod_wsgi serves WSGI: there is no event loop in the server and nothing loads
uvloop on its own.  uvloop comes into it only when an application runs async
code of its own inside a request, on a loop it creates.  Nothing that goes
through a uvloop event loop raises an audit event, so tethered sees none of
it.  That is why tethered keeps uvloop from being imported while a policy is
active, and refuses to activate once it is loaded.

Both checks are made in the interpreter that holds the policy, and they hold
in every arrangement of this suite's other modules: the holder of a lock, an
interpreter that joined it, an unlocked policy.  The limit is the
interpreter outside a lock.  It has no policy of its own for the import to
be refused by, the C extension that refuses its sockets sees no socket, and
so the one interpreter that is "refused all network" reaches everything
through uvloop.

uvloop can be loaded into one interpreter of a process only (its extension
module says so itself), which is enough for each case here.
"""

from __future__ import annotations

from typing import Any

import pytest
from apache import Site, ask, standing
from expect import AT_FORBIDDEN, RUNTIME_ERROR, has_no_network, is_unrestricted, reached
from harness import FORBIDDEN_ADDR, FORBIDDEN_NAME, OTHER_PORT, Server, arrivals

IMPORT_ERROR = "builtins.ImportError"
NOT_LOADED = "tethered: uvloop was not loaded — a policy is active"
REFUSED_TO_LOAD = "tethered: refused to load uvloop while a policy is active"
ACTIVATE_REFUSED = "tethered: activate() refused — uvloop is loaded in this process."

#: One daemon process, the shop and the blog each in a group of its own, imported in
#: the order of the lines when the process starts.
TWO_GROUPS = """
    WSGIRestrictEmbedded On
    WSGIDaemonProcess apps processes=1 threads=2
    WSGIScriptAlias /{first} {first_script} process-group=apps application-group={first}
    WSGIScriptAlias /{second} {second_script} process-group=apps application-group={second}
"""


def start(first: tuple[str, dict[str, Any]], second: tuple[str, dict[str, Any]]) -> Server:
    """Start two applications, ``(name, settings)`` each, imported in this order."""
    site = Site()
    return site.start(
        TWO_GROUPS.format(
            first=first[0],
            first_script=site.script(first[0], **first[1]),
            second=second[0],
            second_script=site.script(second[0], **second[1]),
        )
    )


def uvloop_connection(server: Server, mount: str) -> dict[str, Any]:
    """Have the application connect to the forbidden destination on a uvloop event loop."""
    return ask(server, mount, "uvloop", FORBIDDEN_NAME, OTHER_PORT)


def assert_import_refused(server: Server, mount: str) -> None:
    report = uvloop_connection(server, mount)
    assert report["outcome"] == "error", report
    assert report["exception"] == IMPORT_ERROR, report
    assert report["message"].startswith(NOT_LOADED), report
    assert arrivals() == {}
    server.wait_log(REFUSED_TO_LOAD)


def test_without_a_policy_a_uvloop_connection_is_made() -> None:
    # The control: uvloop loads in a mod_wsgi subinterpreter, the connection
    # arrives, and the counter moves.
    server = start(("shop", {}), ("blog", {}))
    report = uvloop_connection(server, "/shop")
    assert report["main_interpreter"] is False, report
    reached(report)
    assert report["loop"] == "uvloop.Loop", report
    assert report["reply"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}", report
    assert arrivals() == {AT_FORBIDDEN: 1}

    # One interpreter per process: this refusal is uvloop's own.
    second = uvloop_connection(server, "/blog")
    assert second["exception"] == IMPORT_ERROR, second
    assert "can only be loaded into one interpreter per process" in second["message"], second


@pytest.mark.parametrize("policy", ["plain", "locked"])
def test_under_a_policy_uvloop_is_not_loaded(policy: str) -> None:
    # The shop activates; the blog never imports tethered and is created
    # afterwards, so it starts with the shop's policy (joined, under a lock).
    server = start(("shop", {"activate": policy}), ("blog", {}))
    blog = ask(server, "/blog", "whoami")
    assert standing(blog) == ("joined" if policy == "locked" else "unlocked"), blog
    assert_import_refused(server, "/shop")
    assert_import_refused(server, "/blog")
    assert server.log.count(REFUSED_TO_LOAD) == 2  # once in each interpreter


@pytest.mark.parametrize("policy", ["plain", "locked"])
def test_activate_is_refused_in_an_interpreter_that_has_loaded_uvloop(policy: str) -> None:
    # The script imports uvloop and then activates.  The application has no
    # policy then, and says so at once: here the script catches the error,
    # and in an application that does not, every request is a 500.
    server = start(("shop", {"activate": policy, "import_first": ["uvloop"]}), ("blog", {}))
    shop = ask(server, "/shop", "whoami")
    assert shop["activation"]["outcome"] == "raised", shop
    assert shop["activation"]["exception"] == RUNTIME_ERROR, shop
    assert shop["activation"]["message"].startswith(ACTIVATE_REFUSED), shop
    assert standing(shop) == "none", shop
    is_unrestricted(server, "/shop")


def test_a_log_only_policy_is_activated_over_a_loaded_uvloop_with_a_warning() -> None:
    settings = {"activate": "log_only", "import_first": ["uvloop"]}
    server = start(("shop", settings), ("blog", {}))
    shop = ask(server, "/shop", "whoami")
    assert shop["activation"] == {"outcome": "activated"}, shop
    assert shop["log_only"] is True, shop
    server.wait_log("tethered: uvloop is loaded in this process")
    reached(uvloop_connection(server, "/shop"))
    assert arrivals() == {AT_FORBIDDEN: 1}


@pytest.mark.parametrize(
    "early",
    [
        pytest.param({}, id="uvloop-imported-in-a-request"),
        pytest.param({"import_first": ["uvloop"]}, id="uvloop-imported-before-the-lock"),
    ],
)
def test_an_interpreter_outside_the_lock_reaches_anything_through_uvloop(
    early: dict[str, Any],
) -> None:
    """Limit: a locked policy does not stop a uvloop connection made outside the lock.

    The early application is imported before the shop takes the lock, so its
    interpreter is outside it.  Its sockets are refused: no network at all.
    But it can import uvloop, before the lock or after, because it has no
    policy of its own and the lock does not refuse imports, and a connection
    on a uvloop event loop then arrives at the forbidden destination with no
    exception and no log line.  That uvloop is loaded in another interpreter
    does not keep the shop from activating either: ``activate()`` looks at
    its own interpreter.
    """
    server = start(("early", early), ("shop", {"activate": "locked"}))
    assert standing(ask(server, "/shop", "whoami")) == "holder"
    assert ask(server, "/early", "whoami")["tethered_imported"] is False
    has_no_network(server, "/early", RUNTIME_ERROR)

    report = uvloop_connection(server, "/early")
    reached(report)
    assert report["loop"] == "uvloop.Loop", report
    assert report["reply"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}", report
    assert arrivals() == {AT_FORBIDDEN: 1}
    # Neither the refusals above nor the connection left a line in the log.
    assert "tethered: blocked" not in server.log
