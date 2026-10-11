"""What the tests of this suite assert again and again, each said once.

Every check asks the application (the report) and the world (the counters):
"blocked" is a counter that did not move, "reached" one that did.  A check
sets the counters to zero first, so that it can say exactly what arrived
because of it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from apache import ask
from harness import (
    ALLOWED_ADDR,
    ALLOWED_NAME,
    ALLOWED_PORT,
    FORBIDDEN_ADDR,
    FORBIDDEN_NAME,
    LOOPBACK_ADDR,
    OTHER_PORT,
    arrivals,
    reset_arrivals,
)

if TYPE_CHECKING:
    from harness import Server

EGRESS_BLOCKED = "tethered._core.EgressBlocked"
SUBPROCESS_BLOCKED = "tethered._core.SubprocessBlocked"
TETHERED_LOCKED = "tethered._core.TetheredLocked"
#: What the C extension raises in an interpreter that has not imported tethered.
RUNTIME_ERROR = "builtins.RuntimeError"

AT_ALLOWED = f"{ALLOWED_ADDR}:{ALLOWED_PORT}/tcp"
AT_ALLOWED_OTHER_PORT = f"{ALLOWED_ADDR}:{OTHER_PORT}/tcp"
AT_FORBIDDEN = f"{FORBIDDEN_ADDR}:{OTHER_PORT}/tcp"
AT_LOOPBACK = f"{LOOPBACK_ADDR}:{ALLOWED_PORT}/tcp"

#: activate() / deactivate() in an interpreter that neither took the lock nor joined it.
OUTSIDE_THE_LOCK = (
    "a policy is locked by another interpreter of this process, and this interpreter is "
    "outside that lock: it existed before the lock was taken, or did not join it when it "
    "started."
)
#: A connection, lookup or launch in such an interpreter.
LOCKED_ELSEWHERE = "a locked tethered policy is active in another interpreter of this process"
NO_NETWORK = f"({LOCKED_ELSEWHERE}, so this interpreter gets no network access)"
NO_LAUNCHES = f"({LOCKED_ELSEWHERE}, so this interpreter cannot launch processes)"
#: activate() with other arguments under a lock, without the token.
POLICY_DIFFERS = "a locked policy is active and the requested policy differs from it"
#: What an identical activate() logs under a lock.
NO_OP = "activate\\(\\) no-op"


def refused(report: dict[str, Any], exception: str = EGRESS_BLOCKED) -> None:
    """The operation of ``report`` was refused by tethered with ``exception``."""
    assert report["outcome"] == "blocked", report
    assert report["exception"] == exception, report


def reached(report: dict[str, Any]) -> None:
    """The operation of ``report`` was carried out."""
    assert report["outcome"] == "reached", report


def enforces(
    server: Server, mount: str, port: int = ALLOWED_PORT, other_port: int = OTHER_PORT
) -> None:
    """The application at ``mount`` reaches ``allowed.test:<port>`` and loopback, nothing else.

    ``other_port`` is a port of the allowed name that the policy does not cover.
    """
    reset_arrivals()
    report = ask(server, mount, "connect", ALLOWED_NAME, port)
    reached(report)
    assert report["reply"] == f"reached {ALLOWED_ADDR}:{port}", report
    reached(ask(server, mount, "connect", LOOPBACK_ADDR, ALLOWED_PORT))
    for host, forbidden_port in (
        (FORBIDDEN_NAME, OTHER_PORT),
        (FORBIDDEN_ADDR, OTHER_PORT),
        (FORBIDDEN_NAME, port),
        (ALLOWED_NAME, other_port),
    ):
        report = ask(server, mount, "connect", host, forbidden_port)
        refused(report)
        assert "is not in the allow list" in report["message"], report
    assert arrivals() == {f"{ALLOWED_ADDR}:{port}/tcp": 1, AT_LOOPBACK: 1}


def has_no_network(server: Server, mount: str, exception: str = EGRESS_BLOCKED) -> None:
    """The application at ``mount`` reaches nothing: not the allowed host, not loopback.

    That is an interpreter outside the lock of its process.  The C extension
    refuses it without consulting any allow list, with the interpreter's own
    ``EgressBlocked`` if tethered is imported there and ``RuntimeError`` if not.
    """
    reset_arrivals()
    for host, port in (
        (ALLOWED_NAME, ALLOWED_PORT),
        (LOOPBACK_ADDR, ALLOWED_PORT),
        (FORBIDDEN_NAME, OTHER_PORT),
    ):
        report = ask(server, mount, "connect", host, port)
        assert report["outcome"] != "reached", report
        assert report["exception"] == exception, report
        assert report["message"] == f"Blocked by tethered: {host} {NO_NETWORK}", report
    assert arrivals() == {}


def is_unrestricted(server: Server, mount: str) -> None:
    """The application at ``mount`` reaches the forbidden destination."""
    reset_arrivals()
    report = ask(server, mount, "connect", FORBIDDEN_NAME, OTHER_PORT)
    reached(report)
    assert report["reply"] == f"reached {FORBIDDEN_ADDR}:{OTHER_PORT}", report
    assert arrivals() == {AT_FORBIDDEN: 1}
