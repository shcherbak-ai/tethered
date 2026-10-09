"""Property-based tests for AllowPolicy using Hypothesis.

These tests complement the example-based tests in ``test_policy.py`` by
exploring the input space at random and checking invariants that should
hold across the entire space — pattern-matching corner cases (CIDR
boundaries, port handling, wildcard suffix bounds, monotonicity) where
hand-written examples are most likely to miss something.

All tests are pure: they construct ``AllowPolicy``, call ``is_allowed`` and
serialize the policy.  No audit hooks, no network, no filesystem.
"""

from __future__ import annotations

import collections
import ipaddress

from hypothesis import assume, given
from hypothesis import strategies as st

from tethered._core import _serialize_allow_list
from tethered._policy import AllowPolicy, _could_be_ip, _NetworkRule, _normalize_host

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

    @given(
        net_addr=st.ip_addresses(v=4),
        prefix=st.integers(min_value=0, max_value=32),
        query=st.ip_addresses(v=4),
    )
    def test_ipv4_mapped_query_matches_like_its_ipv4_address(self, net_addr, prefix, query):
        network = ipaddress.ip_network(f"{net_addr}/{prefix}", strict=False)
        policy = AllowPolicy([str(network)], allow_localhost=False)
        assert policy.is_allowed(f"::ffff:{query}") is (query in network)

    @given(
        net_addr=st.ip_addresses(),
        prefix_fraction=st.floats(min_value=0, max_value=1),
        query=st.ip_addresses(),
    )
    def test_any_port_rule_lookup_agrees_with_ipaddress(self, net_addr, prefix_fraction, query):
        """Mixed families included: an address is never inside a network of the other family."""
        prefix = round(prefix_fraction * net_addr.max_prefixlen)
        network = ipaddress.ip_network(f"{net_addr}/{prefix}", strict=False)
        policy = AllowPolicy([str(network)], allow_localhost=False)
        assert policy._has_any_port_rule(str(query)) is (query in network)


class TestNetworkRuleRepresentation:
    """A network rule keeps integers; ``network`` rebuilds the ``ipaddress`` object."""

    @given(
        net_addr=st.ip_addresses(),
        prefix_fraction=st.floats(min_value=0, max_value=1),
        port=st.none() | st.integers(min_value=0, max_value=65535),
    )
    def test_network_survives_the_integer_representation(self, net_addr, prefix_fraction, port):
        prefix = round(prefix_fraction * net_addr.max_prefixlen)
        network = ipaddress.ip_network(f"{net_addr}/{prefix}", strict=False)

        rule = _NetworkRule.from_network(network, port)

        assert rule.network == network
        assert rule == (
            network.version,
            int(network.network_address),
            int(network.netmask),
            network.prefixlen,
            port,
        )

    @given(
        rule_addr=st.ip_addresses(),
        rule_fraction=st.floats(min_value=0, max_value=1),
        # None reuses the rule's address, so that nested blocks come up often.
        scope_addr=st.none() | st.ip_addresses(),
        scope_fraction=st.floats(min_value=0, max_value=1),
        rule_port=st.none() | st.sampled_from([80, 443]),
        scope_port=st.none() | st.sampled_from([80, 443]),
    )
    def test_cidr_overlap_agrees_with_ipaddress(
        self, rule_addr, rule_fraction, scope_addr, scope_fraction, rule_port, scope_port
    ):
        """The scope-overlap check compares integers; ``ipaddress.overlaps`` is the reference."""
        scope_addr = rule_addr if scope_addr is None else scope_addr
        rule_net = ipaddress.ip_network(
            f"{rule_addr}/{round(rule_fraction * rule_addr.max_prefixlen)}", strict=False
        )
        scope_net = ipaddress.ip_network(
            f"{scope_addr}/{round(scope_fraction * scope_addr.max_prefixlen)}", strict=False
        )
        rule_text = f"[{rule_net.network_address}]/{rule_net.prefixlen}"
        if rule_port is not None:
            rule_text += f":{rule_port}"
        policy = AllowPolicy([rule_text])

        ports_disjoint = None not in (rule_port, scope_port) and rule_port != scope_port
        if not scope_net.overlaps(rule_net) or ports_disjoint:
            expected = "none"
        elif scope_net.prefixlen >= rule_net.prefixlen and scope_port == rule_port:
            expected = "full"
        else:
            expected = "partial"
        assert policy._check_cidr_overlap(scope_net, scope_port) == expected


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


def _is_accepted(rule: str) -> bool:
    try:
        AllowPolicy([rule])
    except ValueError:
        return False
    return True


def _bracketed(addr, prefix, port):
    text = f"[{addr}]"
    if prefix is not None:
        text += f"/{prefix}"
    if port is not None:
        text += f":{port}"
    return text


def _decorate(core, port, dots, upper, pad):
    text = core + "." * dots
    if port is not None:
        text = f"{text}:{port}"
    if upper:
        text = text.upper()
    return f"{pad}{text}{pad}"


_pattern_label = st.one_of(_label, st.sampled_from(["*", "?", "a*", "*b", "[ab]", "[!a]", "[0-9]"]))
_address_and_prefix = st.ip_addresses().flatmap(
    lambda addr: st.tuples(st.just(addr), st.one_of(st.none(), st.integers(0, addr.max_prefixlen)))
)
_rule_core = st.one_of(
    # Hostname patterns, including ones that start with an fnmatch character set.
    st.lists(_pattern_label, min_size=1, max_size=4).map(".".join),
    # Unbracketed addresses and CIDR ranges.
    _address_and_prefix.map(lambda ap: str(ap[0]) if ap[1] is None else f"{ap[0]}/{ap[1]}"),
    # Bracketed addresses and CIDR ranges, with and without a port.
    st.builds(lambda ap, port: _bracketed(*ap, port), _address_and_prefix, st.none() | _port),
)
# Well-formed rules in every spelling the parser normalizes (port, FQDN dots,
# case, padding), plus short strings over the syntax characters: whatever the
# parser accepts — however odd — has to survive the trip to a child process.
_accepted_rule = st.one_of(
    st.builds(
        _decorate,
        _rule_core,
        st.none() | _port,
        st.integers(0, 2),
        st.booleans(),
        st.sampled_from(["", " "]),
    ),
    st.text(alphabet="ab19.*?[]!:/-% ", min_size=1, max_size=10),
).filter(_is_accepted)


def _rules(policy):
    return (
        policy._exact_hosts_any_port,
        policy._exact_hosts,
        policy._exact_hosts_with_port,
        collections.Counter(policy._host_rules),
        collections.Counter(policy._network_rules),
    )


class TestSerializationRoundTrip:
    """A child process rebuilds its policy from the parent's serialized allow list.

    The rebuilt policy has to hold the same rules, and serializing it again
    has to give the identical list: locked mode compares the two lists, and
    a rule the parent accepted but the child rejects (or reads differently)
    would leave the child with a different policy than its parent.
    """

    @given(rules=st.lists(_accepted_rule, max_size=5))
    def test_serialized_rules_rebuild_the_same_policy(self, rules):
        policy = AllowPolicy(rules, allow_localhost=False)
        serialized = _serialize_allow_list(policy)

        rebuilt = AllowPolicy(serialized, allow_localhost=False)

        assert _rules(rebuilt) == _rules(policy)
        assert _serialize_allow_list(rebuilt) == serialized
