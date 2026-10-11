"""Measure one client library: what it raises without tethered, what arrives under a policy.

This runs in the pytest process.  A measurement is six ``harness.run_python``
scripts (``client_case.py``), each making one attempt in a process of its own,
so that nothing a library keeps (a pool, a cache, a failed connection) carries
over from one attempt to the next:

* two controls with no tethered at all, one by name and one by raw address.
  Both must arrive, or "nothing arrived" under the policy would say nothing
  about tethered.  An audit hook in these processes records the ``socket.*``
  events the library raises, which is why tethered does or does not see it;
* four attempts under the policy ``allow=["allowed.test:9001"]``: the forbidden
  name, the forbidden address, the allowed name, and the allowed name on a
  port the rule does not cover.

Every attempt has a destination of its own (an address and port no other
attempt uses), so the world's counters say which of them arrived, and the six
processes run at the same time.  ``forbidden.test`` is looked up only by the
attempt under the policy: a DNS query for it means the name left the process.
"""

from __future__ import annotations

import itertools
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

import catalog
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

#: The script ``run_python`` starts: ``client_case.py`` does the work.
SOURCE = "import client_case\n\nclient_case.main()\n"

#: The attempts made without tethered.
CONTROL = {
    "control_name": (ALLOWED_NAME, 9002),
    "control_address": (FORBIDDEN_ADDR, 9001),
}
#: The attempts made under the policy.
POLICY = {
    "forbidden_name": (FORBIDDEN_NAME, 9002),
    "forbidden_address": (FORBIDDEN_ADDR, 9003),
    "allowed": (ALLOWED_NAME, ALLOWED_PORT),
    # The allowed name on a port the rule does not cover.
    "other_port": (ALLOWED_NAME, 9003),
}
PYTHON = f"{sys.version_info.major}.{sys.version_info.minor}"

_ADDRESSES = {FORBIDDEN_NAME: FORBIDDEN_ADDR, ALLOWED_NAME: ALLOWED_ADDR}
_tags = itertools.count(1)


def counter_key(host: str, port: int, proto: str = "tcp") -> str:
    """The world's counter for one destination: ``10.77.0.20:9002/tcp``."""
    return f"{_ADDRESSES.get(host, host)}:{port}/{proto}"


@dataclass(frozen=True)
class Attempt:
    """One process: a destination, and the policy it is tried under (``none`` for a control)."""

    host: str
    port: int
    activate: str


@dataclass(frozen=True)
class Batch:
    """Attempts of one variant that were made at the same time, and what the world saw."""

    attempts: dict[str, Attempt]
    reports: dict[str, dict[str, Any]]
    #: What each process wrote to stderr: tethered's log lines among it.
    stderr: dict[str, str]
    arrivals: dict[str, int]
    dns: dict[str, int]
    proto: str = "tcp"

    def arrived(self, case: str) -> bool:
        """Whether the world counted an arrival at the destination of one attempt."""
        attempt = self.attempts[case]
        return self.arrivals.get(counter_key(attempt.host, attempt.port, self.proto), 0) > 0

    def queried(self, name: str) -> bool:
        """Whether the world's DNS responder was asked about ``name`` (any record type)."""
        return any(key.startswith(f"{name}/") for key in self.dns)

    def stray(self) -> list[str]:
        """Arrivals at anything that is not the destination of an attempt."""
        expected = {counter_key(a.host, a.port, self.proto) for a in self.attempts.values()}
        return sorted(set(self.arrivals) - expected)


def _launched(tag: str) -> bool:
    """Whether a process with ``tag`` among its arguments exists."""
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                with open(f"/proc/{entry}/cmdline", "rb") as handle:
                    if tag.encode() in handle.read().split(b"\0"):
                        return True
            except OSError:
                continue
    return False


def run_batch(
    variant: catalog.Variant, attempts: dict[str, Attempt], env: dict[str, str] | None = None
) -> Batch:
    """Run one process per attempt, all at once, and read the world's counters afterwards."""
    reset_arrivals()
    with ThreadPoolExecutor(max_workers=len(attempts)) as pool:
        running = {}
        for case, attempt in attempts.items():
            settings = {**variant.env, **(env or {})}
            policy = attempt.activate
            if (variant.patch or variant.import_first) and policy != "none":
                # Something happens before the policy is activated: client_case does both.
                settings["CLIENT_ACTIVATE_LATER"] = policy
                policy = "none"
            tag = f"clients-launch-{next(_tags)}"
            arguments = [variant.id, attempt.host, str(attempt.port), tag]
            running[case] = pool.submit(
                run_python, SOURCE, activate=policy, env=settings, args=arguments, timeout=60.0
            )
            # run_python numbers its script files with a counter that is not
            # made for threads: the next call is made when this one has
            # written its script and started its process.
            deadline = time.monotonic() + 60.0
            while not _launched(tag) and not running[case].done():
                if time.monotonic() > deadline:
                    raise AssertionError(f"{variant.id}: the process for {case} did not start")
                time.sleep(0.002)
        done = {case: future.result() for case, future in running.items()}
    reports = {case: completed.json() for case, completed in done.items()}
    stderr = {case: completed.stderr for case, completed in done.items()}
    return Batch(attempts, reports, stderr, arrivals(), dns_queries(), variant.proto)


def under(activate: str) -> dict[str, Attempt]:
    """The four attempts of ``POLICY`` under one policy."""
    return {case: Attempt(host, port, activate) for case, (host, port) in POLICY.items()}


def controls() -> dict[str, Attempt]:
    """The two attempts of ``CONTROL``, without tethered."""
    return {case: Attempt(host, port, "none") for case, (host, port) in CONTROL.items()}


@dataclass(frozen=True)
class Row:
    """What was measured for one variant: a row of the compatibility table."""

    variant: catalog.Variant
    batch: Batch
    measured: catalog.Expect
    #: Everything that makes the row doubtful; a test fails when there is any.
    problems: list[str] = field(default_factory=list)

    @property
    def control(self) -> dict[str, Any]:
        """The report of the control that went by name."""
        return self.batch.reports["control_name"]

    @property
    def versions(self) -> dict[str, str]:
        """The versions of the variant's distributions, as installed."""
        return self.control["versions"]

    @property
    def notes(self) -> dict[str, Any]:
        """What the client function reported about its arrangement."""
        return self.control["notes"]

    @property
    def events(self) -> list[str]:
        """The ``socket.*`` events the library raised, without tethered, going by name."""
        return self.control["events"]

    @property
    def extensions(self) -> list[str]:
        """Extension modules from outside the standard library that the attempt loaded."""
        return sorted(set(self.control["extensions"]))

    @property
    def dlopen(self) -> list[str]:
        """What the attempt opened through ``ctypes``."""
        return sorted(set(self.control["dlopen"]) - {"None"})


def _raised(report: dict[str, Any], prefixes: tuple[str, ...], targets: set[str]) -> bool:
    return any(
        event.startswith(prefix) and event.endswith(f"({target})")
        for event in report["events"]
        for prefix in prefixes
        for target in targets
    )


def lookup_event(report: dict[str, Any]) -> bool:
    """Whether the process raised a lookup event for the name it was given."""
    return _raised(report, ("getaddrinfo(", "gethostbyname("), {report["host"]})


def connect_event(report: dict[str, Any]) -> bool:
    """Whether the process raised a connect or sendto event for its destination.

    The event carries the address, or the name when the library hands the name
    to ``socket.connect`` (httplib2 does).
    """
    host, port = report["host"], report["port"]
    targets = {f"{_ADDRESSES.get(host, host)}:{port}", f"{host}:{port}"}
    return _raised(report, ("connect(", "sendto("), targets)


def surface(report: dict[str, Any]) -> str:
    """How a refusal by tethered reached the caller of the library."""
    if report["outcome"] == "completed":
        return "no exception"
    return report["surface"] or "hidden"


def measured_under(batch: Batch, control: dict[str, bool]) -> catalog.Expect:
    """The row that the four attempts under a policy amount to."""
    forbidden_name = "ARRIVED" if batch.arrived("forbidden_name") else "blocked"
    return catalog.Expect(
        lookup_event=control["lookup"],
        connect_event=control["connect"],
        forbidden_name=forbidden_name,
        name_leaked=batch.queried(FORBIDDEN_NAME),
        forbidden_address="ARRIVED" if batch.arrived("forbidden_address") else "blocked",
        allowed="arrived" if batch.arrived("allowed") else "REFUSED",
        other_port="ARRIVED" if batch.arrived("other_port") else "blocked",
        surface=surface(batch.reports["forbidden_name"]) if forbidden_name == "blocked" else "-",
    )


def describe(variant: catalog.Variant, batch: Batch) -> Row:
    """Turn the six attempts into the measured row, and note everything that makes it doubtful."""
    problems = []
    for case in CONTROL:
        if not batch.arrived(case):
            said = batch.reports[case]
            problems.append(
                f"{case} did not arrive without tethered: "
                f"{said.get('exception')}: {said.get('message')}"
            )
    by_name, by_address = batch.reports["control_name"], batch.reports["control_address"]
    connects = {"by name": connect_event(by_name), "by address": connect_event(by_address)}
    if len(set(connects.values())) > 1:
        problems.append(f"the connect event was not raised for both controls: {connects}")
    if batch.stray():
        problems.append(f"something arrived elsewhere: {batch.stray()}")
    control = {"lookup": lookup_event(by_name), "connect": connects["by name"]}
    return Row(variant, batch, measured_under(batch, control), problems)


_rows: dict[str, Row] = {}
#: What a test found for a variant under a locked policy, for the table.
under_lock: dict[str, str] = {}


def measure(variant: catalog.Variant) -> Row:
    """The row of one variant, measured once per session."""
    if variant.id not in _rows:
        batch = run_batch(variant, {**controls(), **under("plain")})
        _rows[variant.id] = describe(variant, batch)
    return _rows[variant.id]


def measured_rows() -> list[Row]:
    """Every row measured so far, in the order of the catalog."""
    return [_rows[name] for name in catalog.TABLE if name in _rows]
