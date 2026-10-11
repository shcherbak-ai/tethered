"""Which client libraries does tethered see?

tethered enforces at Python's audit events.  A library that looks names up and
connects through Python's ``socket`` module is seen; one that does both inside
a C library of its own raises no event and is neither blocked nor reported;
one that resolves names itself and connects through Python gets an allowed
host refused, because tethered sees a connection to an address it has no name
for.

Every library in ``catalog.TABLE`` is measured under the policy
``allow=["allowed.test:9001"]`` and, as a control, with no tethered at all
(``measure.py``), and the result is compared with the row the catalog records.
The world's counters and its DNS responder are the ground truth.  A row that
is not "enforced" is a limit: it is asserted as what happens today.

Covered besides the table: every row again under a locked policy, the
libraries that call ``ctypes.util.find_library`` when they are imported
included (a locked policy used to refuse the launch that makes); a
fail-closed policy; what a log-only policy reports; what makes a refused
allowed host reachable; what a library does when its C module cannot be
imported; how Twisted delivers a refusal; and a DNS query sent straight to a
forbidden name server.

Not covered: TLS, proxies, connection reuse, Windows and macOS, and what the
libraries do on uvloop (tethered does not let uvloop be loaded under a policy;
the event-loop suites cover that).
"""

from __future__ import annotations

import socket
from dataclasses import asdict

import catalog
import measure
import pytest
from harness import (
    ALLOWED_ADDR,
    ALLOWED_NAME,
    FORBIDDEN_ADDR,
    FORBIDDEN_NAME,
    dns_queries,
    run_python,
)
from measure import Attempt

ALL_FOUR = ["forbidden_name", "forbidden_address", "allowed", "other_port"]
#: One row of every kind, for the questions that do not need the whole table.
REPRESENTATIVES = [
    "requests",
    "gevent",
    "psycopg2",
    "psycopg-binary-sync",
    "aiohttp-aiodns-imported-first",
]
#: The warning for the launch ``ctypes.util.find_library`` makes on Linux.
LDCONFIG_WARNING = "external subprocess launch detected: subprocess.Popen(/sbin/ldconfig)"


def rows(verdict: str) -> list[object]:
    return [
        pytest.param(variant, id=variant.id)
        for variant in catalog.TABLE.values()
        if variant.expect.verdict == verdict
    ]


def check(variant: catalog.Variant) -> measure.Row:
    """Measure the variant and compare every column with the recorded row."""
    if measure.PYTHON in variant.missing_on:
        pytest.skip(variant.missing_on[measure.PYTHON])
    row = measure.measure(variant)
    assert not row.problems, (row.problems, row.batch.reports)
    recorded, measured = asdict(variant.expect), asdict(row.measured)
    differences = {
        column: f"recorded {recorded[column]!r}, measured {measured[column]!r}"
        for column in recorded
        if recorded[column] != measured[column]
    }
    assert not differences, (differences, row.batch.reports)
    return row


def arrived(batch: measure.Batch) -> list[str]:
    return [case for case in batch.attempts if batch.arrived(case)]


def test_the_names_exist_only_in_dns() -> None:
    # What conftest.py arranges: a lookup is a query the world's responder counts.
    found = socket.getaddrinfo(ALLOWED_NAME, 9001, type=socket.SOCK_STREAM)
    assert {info[4][0] for info in found} == {ALLOWED_ADDR}
    assert f"{ALLOWED_NAME}/A" in dns_queries()


# ── The table ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("variant", rows(catalog.ENFORCED))
def test_tethered_sees_the_client(variant: catalog.Variant) -> None:
    """The forbidden name, address and port are refused and the allowed host is reached."""
    check(variant)


@pytest.mark.parametrize("variant", rows(catalog.NOT_SEEN))
def test_limit_the_client_is_not_seen(variant: catalog.Variant) -> None:
    """Limit: the library resolves and connects in C, raises no audit event, and reaches all."""
    check(variant)


@pytest.mark.parametrize("variant", rows(catalog.PARTLY))
def test_limit_the_client_is_partly_seen(variant: catalog.Variant) -> None:
    """Limit: the lookup is Python's and is checked; the connection is made in C and is not."""
    check(variant)


@pytest.mark.parametrize("variant", rows(catalog.ALLOWED_REFUSED))
def test_limit_the_allowed_host_is_refused(variant: catalog.Variant) -> None:
    """Limit: the library resolves names itself, so the allowed host is refused as well."""
    row = check(variant)
    # tethered was asked about an address, not about a name.
    refusal = row.batch.reports["allowed"]
    assert f"{ALLOWED_ADDR}:9001 is not in the allow list" in refusal["message"], refusal


def test_limit_a_refusal_reaches_a_twisted_caller_as_a_timeout() -> None:
    """Limit: Twisted fails a connection attempt on ``OSError`` only; a refusal leaves it waiting.

    ``EgressBlocked`` is logged by the reactor ("while handling timed call")
    and the caller gets ``TimeoutError`` when its own connection timeout ends,
    30 seconds by default.
    """
    row = check(catalog.TABLE["twisted-connecttcp"])
    for case in ("forbidden_name", "forbidden_address", "other_port"):
        said = row.batch.reports[case]
        assert said["exception"] == "twisted.internet.error.TimeoutError", said
        assert said["seconds"] >= 1.0, said
    assert "EgressBlocked: Blocked by tethered" in row.batch.stderr["forbidden_address"]


def test_limit_a_twisted_agent_request_for_a_refused_name_never_finishes() -> None:
    """Limit: ``HostnameEndpoint`` has no timeout for a lookup that raises something unexpected.

    Twisted's resolver thread expects ``gaierror`` from ``getaddrinfo``.
    ``EgressBlocked`` ends the lookup without a result, and the request's
    Deferred never fires: no connection, no error, no timeout.
    """
    row = check(catalog.TABLE["twisted-agent"])
    said = row.batch.reports["forbidden_name"]
    assert said["exception"] == "clients_runtimes.NeverFinished", said
    assert "tethered: blocked getaddrinfo for forbidden.test" in row.batch.stderr["forbidden_name"]
    # A refused address ends in the connection timeout, as with connectTCP.
    refused = row.batch.reports["forbidden_address"]
    assert refused["exception"] == "twisted.internet.error.TimeoutError", refused


# ── Other policies ────────────────────────────────────────────────────


def same_row_under(variant: catalog.Variant, activate: str) -> None:
    """The four attempts under another policy must amount to the plain policy's row."""
    row = check(variant)
    batch = measure.run_batch(variant, measure.under(activate))
    control = {"lookup": row.measured.lookup_event, "connect": row.measured.connect_event}
    assert measure.measured_under(batch, control) == row.measured, batch.reports
    assert not batch.stray()
    if activate == "locked":
        measure.under_lock[variant.id] = "the same"


def locked_rows(*, find_library: bool) -> list[object]:
    return [
        pytest.param(variant, id=variant.id)
        for variant in catalog.TABLE.values()
        if bool(variant.calls_find_library_in) is find_library
    ]


@pytest.mark.parametrize("variant", locked_rows(find_library=False))
def test_a_locked_policy_sees_what_a_plain_one_sees(variant: catalog.Variant) -> None:
    """A locked policy changes no row: what a plain policy does not see, it does not see either."""
    same_row_under(variant, "locked")


@pytest.mark.parametrize("variant", locked_rows(find_library=True))
def test_a_library_that_calls_find_library_is_usable_under_a_locked_policy(
    variant: catalog.Variant,
) -> None:
    """The row is the plain policy's, although importing the library launches ``ldconfig``.

    On Linux ``ctypes.util.find_library`` launches ``/sbin/ldconfig`` with an
    environment of its own, which lacks the policy variable.  A locked policy
    used to refuse that launch, so the library, or one it imports, could not
    be imported and nothing worked, the allowed host included.  The launch
    is now given the variable instead.
    """
    if measure.PYTHON in variant.missing_on:
        pytest.skip(variant.missing_on[measure.PYTHON])
    same_row_under(variant, "locked")


def test_httpx_is_usable_under_a_locked_policy_where_trio_is_not_installed() -> None:
    # httpx does not use trio here; httpcore merely imports it when it is installed.
    same_row_under(catalog.HTTPX_WITHOUT_TRIO, "locked")


def test_httpx_is_usable_under_a_locked_policy_when_httpcore_was_imported_before() -> None:
    # The lookup of libpthread was made before there was a lock.
    same_row_under(catalog.HTTPCORE_IMPORTED_FIRST, "locked")


@pytest.mark.parametrize("name", REPRESENTATIVES)
def test_a_fail_closed_policy_sees_what_a_plain_one_sees(name: str) -> None:
    """A fail-closed policy changes no row either: it is about errors in tethered's own check."""
    same_row_under(catalog.TABLE[name], "fail_closed")


FIND_LIBRARY = """
import ctypes.util, json

try:
    report = {"found": ctypes.util.find_library("c")}
except Exception as exc:
    report = {"exception": type(exc).__name__, "message": str(exc)}
print(json.dumps(report))
"""


@pytest.mark.parametrize("activate", ["plain", "locked"])
def test_ctypes_find_library_works_under_a_policy_with_a_warning(activate: str) -> None:
    """``ldconfig`` is an external program, launched with an environment of its own."""
    assert run_python(FIND_LIBRARY, activate="none").json() == {"found": "libc.so.6"}
    done = run_python(FIND_LIBRARY, activate=activate)
    assert done.json() == {"found": "libc.so.6"}
    assert LDCONFIG_WARNING in done.stderr
    assert "strips" not in done.stderr, done.stderr
    # Allowed external launches are not mentioned at all.
    done = run_python(FIND_LIBRARY, activate=activate, esp="allow")
    assert done.json() == {"found": "libc.so.6"}
    assert "ldconfig" not in done.stderr, done.stderr


def test_limit_ctypes_find_library_is_refused_when_external_launches_are_blocked() -> None:
    """Limit: ``external_subprocess_policy="block"`` refuses the launch of ``/sbin/ldconfig``."""
    refused = run_python(FIND_LIBRARY, esp="block").json()
    assert refused["exception"] == "SubprocessBlocked", refused
    assert "subprocess.Popen(/sbin/ldconfig)" in refused["message"]


def test_a_log_only_policy_reports_the_client_it_sees() -> None:
    batch = measure.run_batch(catalog.TABLE["requests"], measure.under("log_only"))
    assert arrived(batch) == ALL_FOUR
    assert f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}" in batch.stderr["forbidden_name"]
    assert (
        f"tethered: blocked connect to {FORBIDDEN_ADDR}:9003" in batch.stderr["forbidden_address"]
    )
    assert f"tethered: blocked connect to {ALLOWED_NAME}:9003" in batch.stderr["other_port"]
    assert "tethered: blocked" not in batch.stderr["allowed"]


def test_limit_a_log_only_policy_reports_nothing_for_a_client_it_does_not_see() -> None:
    """Limit: what a C library connects to is not blocked and not reported either."""
    batch = measure.run_batch(catalog.TABLE["psycopg2"], measure.under("log_only"))
    assert arrived(batch) == ALL_FOUR
    for case in ALL_FOUR:
        assert "tethered: activated" in batch.stderr[case]
        assert "tethered: blocked" not in batch.stderr[case]


def test_limit_a_log_only_policy_reports_the_allowed_host_of_a_client_that_resolves_itself() -> (
    None
):
    """Limit: the allowed host is reported as blocked, by its address, and so is every other."""
    batch = measure.run_batch(catalog.TABLE["aiohttp-aiodns"], measure.under("log_only"))
    assert arrived(batch) == ALL_FOUR
    assert f"tethered: blocked connect to {ALLOWED_ADDR}:9001" in batch.stderr["allowed"]
    # The forbidden name is reported by its address too: tethered never saw the name.
    assert f"tethered: blocked connect to {FORBIDDEN_ADDR}:9002" in batch.stderr["forbidden_name"]
    assert FORBIDDEN_NAME not in batch.stderr["forbidden_name"]


PYCARES_UNDER_A_POLICY = """
import json

report = {}
for name in ("pycares", "aiodns"):
    try:
        __import__(name)
        report[name] = "loaded"
    except ImportError as exc:
        report[name] = str(exc)
import aiohttp.resolver

report["aiohttp"] = aiohttp.resolver.DefaultResolver.__name__
print(json.dumps(report))
"""


@pytest.mark.parametrize("activate", ["plain", "locked", "fail_closed"])
def test_pycares_is_not_loaded_under_a_policy_and_aiohttp_falls_back(activate: str) -> None:
    """tethered refuses the import; aiodns then counts as not installed for aiohttp.

    c-ares resolves in C, where tethered sees neither the lookup nor which
    host an address belongs to, so with it every host allowed by name was
    refused.  Code that asks for pycares or aiodns by name gets the reason.
    """
    report = run_python(PYCARES_UNDER_A_POLICY, activate=activate).json()
    assert report["pycares"].startswith("tethered: pycares was not loaded"), report
    assert report["aiodns"].startswith("tethered: pycares was not loaded"), report
    assert report["aiohttp"] == "ThreadedResolver", report


@pytest.mark.parametrize("activate", ["none", "log_only"])
def test_pycares_is_loaded_where_nothing_is_refused(activate: str) -> None:
    report = run_python(PYCARES_UNDER_A_POLICY, activate=activate).json()
    assert report == {"pycares": "loaded", "aiodns": "loaded", "aiohttp": "AsyncResolver"}


def test_a_refused_address_without_a_name_is_explained_once() -> None:
    """The first refusal by address says where the name went; the others do not repeat it."""
    variant = catalog.TABLE["aiohttp-aiodns-imported-first"]
    batch = measure.run_batch(variant, measure.under("plain"))
    for case in ALL_FOUR:
        hints = batch.stderr[case].count("tethered: no hostname is known for the refused address")
        assert hints == 1, batch.stderr[case]
    assert "aiohttp.ThreadedResolver()" in batch.stderr["allowed"]


# ── What makes it work ────────────────────────────────────────────────


@pytest.mark.parametrize("variant", rows(catalog.ALLOWED_REFUSED))
def test_a_lookup_through_the_socket_module_makes_the_allowed_host_reachable(
    variant: catalog.Variant,
) -> None:
    """The application calls ``_socket.getaddrinfo(host, port)`` before it uses the library.

    tethered then knows which name the address belongs to.  The same call for
    the forbidden name is refused before the library's own resolver runs, so
    that name does not reach DNS any more either.
    """
    if measure.PYTHON in variant.missing_on:
        pytest.skip(variant.missing_on[measure.PYTHON])
    lookup = {"CLIENT_LOOKUP_FIRST": "getaddrinfo"}
    batch = measure.run_batch(variant, measure.under("plain"), env=lookup)
    assert arrived(batch) == ["allowed"], batch.reports
    assert not batch.queried(FORBIDDEN_NAME)
    refusal = batch.reports["forbidden_name"]
    assert refusal["outcome"] == "blocked", refusal
    assert f"{FORBIDDEN_NAME} is not in the allow list" in refusal["message"]


def test_knowing_the_allowed_name_is_enough_to_match_its_address() -> None:
    """``gethostbyname`` gives tethered the name and no address, and the host is reached.

    tethered records such a name as a candidate only.  When the library then
    connects to an address tethered has no name for, tethered resolves its
    candidates itself and finds the address among the answers.  The name does
    not have to come from a lookup of the application: an exact host name of
    the allow list would do as a candidate just as well.
    """
    variant = catalog.TABLE["aiohttp-aiodns-imported-first"]
    lookup = {"CLIENT_LOOKUP_FIRST": "gethostbyname"}
    batch = measure.run_batch(variant, measure.under("plain"), env=lookup)
    assert arrived(batch) == ["allowed"], batch.reports
    assert batch.reports["other_port"]["message"].endswith(
        f"{ALLOWED_ADDR}:9003 (resolved from {ALLOWED_NAME}) is not in the allow list"
    )


def test_an_address_rule_makes_the_allowed_host_reachable() -> None:
    # The rule names the address: no name is needed to allow the connection.
    variant = catalog.TABLE["aiohttp-aiodns-imported-first"]
    rule = {"TETH_ALLOW": f"{ALLOWED_ADDR}:9001"}
    batch = measure.run_batch(variant, measure.under("plain"), env=rule)
    assert arrived(batch) == ["allowed"], batch.reports
    # The library's own resolver still asks for the forbidden name.
    assert batch.queried(FORBIDDEN_NAME)


@pytest.mark.parametrize("variant", [pytest.param(v, id=v.id) for v in catalog.FALLBACKS.values()])
def test_a_library_falls_back_to_python_sockets_without_its_c_module(
    variant: catalog.Variant,
) -> None:
    """With the module unimportable the library uses Python's sockets, and is seen.

    That is what an ``ImportError`` for the module under a policy would give:
    aiohttp takes its threaded resolver, mysql-connector-python its pure
    implementation, and botocore goes on without awscrt.
    """
    row = check(variant)
    assert not set(row.extensions) & set(variant.without), row.extensions


# ── A DNS query sent straight to a name server ────────────────────────

NAME_SERVER = {
    "control": Attempt(FORBIDDEN_ADDR, 9001, "none"),
    "policy": Attempt(FORBIDDEN_ADDR, 9002, "plain"),
}


def test_a_dns_query_by_dnspython_to_a_forbidden_name_server_is_refused() -> None:
    batch = measure.run_batch(catalog.DNS_SERVER_VARIANTS["dnspython-query-server"], NAME_SERVER)
    assert arrived(batch) == ["control"], batch.reports
    assert measure.connect_event(batch.reports["control"])
    refusal = batch.reports["policy"]
    assert refusal["outcome"] == "blocked", refusal
    assert f"{FORBIDDEN_ADDR}:9002 is not in the allow list" in refusal["message"]


def test_limit_a_dns_query_by_c_ares_to_a_forbidden_name_server_is_not_seen() -> None:
    """Limit: c-ares sends its queries in C: a datagram reaches the forbidden address."""
    batch = measure.run_batch(catalog.DNS_SERVER_VARIANTS["pycares-query-server"], NAME_SERVER)
    assert arrived(batch) == ["control", "policy"], batch.reports
    assert not measure.connect_event(batch.reports["control"])
    assert batch.reports["policy"]["surface"] is None
