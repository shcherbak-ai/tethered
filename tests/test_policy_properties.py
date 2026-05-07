"""Property-based tests for AllowPolicy using Hypothesis.

These tests complement the example-based tests in ``test_policy.py`` by
exploring the input space at random and checking invariants that should
hold across the entire space — pattern-matching corner cases (CIDR
boundaries, port handling, wildcard suffix bounds, monotonicity) where
hand-written examples are most likely to miss something.

All tests are pure: they construct ``AllowPolicy`` and call ``is_allowed``.
No audit hooks, no network, no filesystem.
"""

from __future__ import annotations

import ipaddress

from hypothesis import assume, given
from hypothesis import strategies as st

from tethered._policy import AllowPolicy, _could_be_ip, _normalize_host

# Constrained alphabets keep generated hostnames short, ASCII-only, and
# unable to look like IPs or localhost — so localhost detection doesn't
# interfere with the policy under test, and ``_could_be_ip`` reliably
# returns False for these synthetic hostnames.
_label = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=8)
_hostname = st.lists(_label, min_size=1, max_size=4).map(".".join)
_port = st.integers(min_value=0, max_value=65535)


class TestNormalizeHostInvariants:
    @given(st.text(min_size=1, max_size=253))
    def test_strips_outer_whitespace(self, host):
        result = _normalize_host(host)
        assert result == result.strip()

    @given(st.text(min_size=1, max_size=253))
    def test_ascii_output_is_lowercase(self, host):
        result = _normalize_host(host)
        if result.isascii():
            assert result == result.lower()


class TestCouldBeIpSound:
    """Soundness: every value ``ipaddress.ip_address`` accepts must pass the prefilter.

    ``is_allowed`` uses ``_could_be_ip`` to decide whether to take the IP path
    or the hostname path. If a real IP slipped through as False, it would be
    matched against hostname rules instead of CIDR/network rules.
    """

    @given(st.ip_addresses())
    def test_every_valid_ip_passes_prefilter(self, ip):
        assert _could_be_ip(str(ip)) is True


class TestCidrMembership:
    """A CIDR rule allows exactly the IPs that ``ipaddress`` says are in the network."""

    @given(
        net_addr=st.ip_addresses(v=4),
        prefix=st.integers(min_value=0, max_value=32),
        query=st.ip_addresses(v=4),
    )
    def test_ipv4_cidr_membership_round_trip(self, net_addr, prefix, query):
        network = ipaddress.ip_network(f"{net_addr}/{prefix}", strict=False)
        policy = AllowPolicy([str(network)], allow_localhost=False)
        assert policy.is_allowed(str(query)) is (query in network)

    @given(
        net_addr=st.ip_addresses(v=6),
        prefix=st.integers(min_value=0, max_value=128),
        query=st.ip_addresses(v=6),
    )
    def test_ipv6_cidr_membership_round_trip(self, net_addr, prefix, query):
        network = ipaddress.ip_network(f"{net_addr}/{prefix}", strict=False)
        policy = AllowPolicy([str(network)], allow_localhost=False)
        assert policy.is_allowed(str(query)) is (query in network)


class TestPortRestriction:
    @given(rule_port=_port, query_port=_port)
    def test_port_must_match_for_restricted_rule(self, rule_port, query_port):
        policy = AllowPolicy([f"api.example.com:{rule_port}"], allow_localhost=False)
        assert policy.is_allowed("api.example.com", query_port) is (rule_port == query_port)

    @given(query_port=_port)
    def test_unrestricted_rule_accepts_any_port(self, query_port):
        policy = AllowPolicy(["api.example.com"], allow_localhost=False)
        assert policy.is_allowed("api.example.com", query_port) is True

    @given(rule_port=_port)
    def test_port_rule_allows_no_port_query(self, rule_port):
        # Documented behavior: port rule + no port specified -> allow.
        policy = AllowPolicy([f"api.example.com:{rule_port}"], allow_localhost=False)
        assert policy.is_allowed("api.example.com") is True


class TestMonotonicity:
    """Adding a rule to a policy can only widen the allowed set, never narrow it.

    This is the "scopes can only narrow, never widen" invariant in reverse —
    the global policy itself must be monotonic in its rule set.
    """

    @given(rule_a=_hostname, rule_b=_hostname, host=_hostname, port=_port)
    def test_adding_rule_preserves_allowed_hosts(self, rule_a, rule_b, host, port):
        narrow = AllowPolicy([rule_a], allow_localhost=False)
        wide = AllowPolicy([rule_a, rule_b], allow_localhost=False)
        if narrow.is_allowed(host, port):
            assert wide.is_allowed(host, port)


class TestWildcardSuffix:
    """``*.stripe.com`` matches exactly the hosts ending in ``.stripe.com``."""

    @given(prefix_labels=st.lists(_label, min_size=1, max_size=4))
    def test_wildcard_matches_any_prefix(self, prefix_labels):
        host = ".".join(prefix_labels) + ".stripe.com"
        policy = AllowPolicy(["*.stripe.com"], allow_localhost=False)
        assert policy.is_allowed(host) is True

    @given(host=_hostname)
    def test_wildcard_rejects_non_suffix(self, host):
        assume(not host.endswith(".stripe.com"))
        policy = AllowPolicy(["*.stripe.com"], allow_localhost=False)
        assert policy.is_allowed(host) is False
