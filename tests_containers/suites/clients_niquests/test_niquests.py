"""Does tethered see niquests?

niquests runs on urllib3-future, whose distribution installs a package named
``urllib3`` over the one requests and botocore use.  It therefore has an image
of its own; everything else about client libraries is in the ``clients``
suite, and the rows measured here belong to the same table.

Two arrangements: niquests as it comes, which asks the operating system's
resolver, and niquests with one of urllib3-future's own resolvers (DNS over
UDP), which looks names up itself.  Each is measured like a row of the clients
suite: two attempts without tethered as a control (by name and by address,
with an audit hook that records the ``socket.*`` events), then the forbidden
name, the forbidden address, the allowed name and the allowed name on another
port under ``allow=["allowed.test:9001"]``, plain and locked.  The world's
counters and its DNS responder are the ground truth.

Not covered: DNS over HTTPS, TLS or QUIC, and HTTP/2 and HTTP/3 (the
destinations speak HTTP/1.1 without TLS).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from harness import (
    ALLOWED_ADDR,
    ALLOWED_NAME,
    ALLOWED_PORT,
    FORBIDDEN_ADDR,
    FORBIDDEN_NAME,
    arrivals,
    dns_queries,
    reset_arrivals,
    run_python,
)

SOURCE = "import niquests_case\n\nniquests_case.main()\n"
SYSTEM = "system"
#: urllib3-future's DNS-over-UDP resolver, pointed at the world's responder.
OWN = "dou://127.0.0.1"

ADDRESSES = {ALLOWED_NAME: ALLOWED_ADDR, FORBIDDEN_NAME: FORBIDDEN_ADDR}
CONTROL = {"control_name": (ALLOWED_NAME, 9002), "control_address": (FORBIDDEN_ADDR, 9001)}
POLICY = {
    "forbidden_name": (FORBIDDEN_NAME, 9002),
    "forbidden_address": (FORBIDDEN_ADDR, 9003),
    "allowed": (ALLOWED_NAME, ALLOWED_PORT),
    "other_port": (ALLOWED_NAME, 9003),
}


@dataclass(frozen=True)
class Measured:
    """The attempts of one arrangement, each made in a process of its own."""

    reports: dict[str, dict[str, Any]]
    arrived: list[str]
    #: Whether the DNS responder was asked about the forbidden name.
    forbidden_name_queried: bool

    def events(self, case: str) -> list[str]:
        return self.reports[case]["events"]


def attempts(resolver: str, cases: dict[str, tuple[str, int]], activate: str) -> Measured:
    """Run one process per case and read the world's counters after each."""
    reports, arrived, queried = {}, [], False
    for case, (host, port) in cases.items():
        reset_arrivals()
        done = run_python(SOURCE, activate=activate, args=[resolver, host, str(port)])
        reports[case] = done.json()
        counted = arrivals()
        expected = f"{ADDRESSES.get(host, host)}:{port}/tcp"
        assert set(counted) <= {expected}, f"{case}: something arrived elsewhere: {counted}"
        if counted:
            arrived.append(case)
        queried = queried or any(key.startswith(f"{FORBIDDEN_NAME}/") for key in dns_queries())
    return Measured(reports, arrived, queried)


def test_niquests_runs_on_urllib3_future() -> None:
    # The reason for this image: the package named urllib3 here is urllib3-future's.
    source = "import json, urllib3, urllib3_future\n"
    source += "print(json.dumps([urllib3.__version__, urllib3_future.__version__]))\n"
    shadowing, future = run_python(source, activate="none").json()
    assert shadowing == future


class TestTheSystemResolver:
    """niquests as it comes."""

    def test_without_tethered_niquests_raises_lookup_and_connect_events(self) -> None:
        control = attempts(SYSTEM, CONTROL, "none")
        assert control.arrived == ["control_name", "control_address"], control.reports
        events = control.events("control_name")
        assert f"getaddrinfo({ALLOWED_NAME})" in events, events
        assert f"connect({ALLOWED_ADDR}:9002)" in events, events
        assert f"connect({FORBIDDEN_ADDR}:9001)" in control.events("control_address")

    @pytest.mark.parametrize("activate", ["plain", "locked"])
    def test_tethered_sees_niquests(self, activate: str) -> None:
        """The forbidden name, address and port are refused and the allowed host is reached."""
        measured = attempts(SYSTEM, POLICY, activate)
        assert measured.arrived == ["allowed"], measured.reports
        assert not measured.forbidden_name_queried
        refusal = measured.reports["forbidden_name"]
        assert refusal["surface"] == "raised", refusal
        assert (
            refusal["message"] == f"Blocked by tethered: {FORBIDDEN_NAME} is not in the allow list"
        )
        for case in ("forbidden_address", "other_port"):
            assert measured.reports[case]["outcome"] == "blocked", measured.reports[case]


class TestAResolverOfItsOwn:
    """niquests with ``Session(resolver="dou://...")``: urllib3-future makes the DNS queries."""

    def test_without_tethered_no_lookup_event_is_raised_for_the_name(self) -> None:
        control = attempts(OWN, CONTROL, "none")
        assert control.arrived == ["control_name", "control_address"], control.reports
        events = control.events("control_name")
        assert f"connect({ALLOWED_ADDR}:9002)" in events
        assert f"getaddrinfo({ALLOWED_NAME})" not in events, events
        # Its queries go out through Python's sockets, to the name server.
        assert "connect(127.0.0.1:53)" in events or "sendto(127.0.0.1:53)" in events, events

    @pytest.mark.parametrize("activate", ["plain", "locked"])
    def test_limit_the_allowed_host_is_refused(self, activate: str) -> None:
        """Limit: tethered sees a connection to an address it has no name for, and refuses it.

        The forbidden destinations are refused too, by their address, after the
        forbidden name has been asked for in DNS.
        """
        measured = attempts(OWN, POLICY, activate)
        assert measured.arrived == [], measured.reports
        assert measured.forbidden_name_queried
        refusal = measured.reports["allowed"]
        assert refusal["outcome"] == "blocked", refusal
        assert f"{ALLOWED_ADDR}:{ALLOWED_PORT} is not in the allow list" in refusal["message"]
