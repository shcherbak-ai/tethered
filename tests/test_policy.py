"""Unit tests for AllowPolicy pattern matching."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from tethered import _policy
from tethered._core import _serialize_allow_list
from tethered._policy import (
    AllowPolicy,
    _could_be_ip,
    _has_port_suffix,
    _is_ip_like,
    _is_localhost,
    _NetworkRule,
    _normalize_host,
)


class TestHasPortSuffix:
    def test_hostname_with_port(self):
        assert _has_port_suffix("api.stripe.com:443") is True

    def test_hostname_without_port(self):
        assert _has_port_suffix("api.stripe.com") is False

    def test_ipv6_no_port(self):
        assert _has_port_suffix("::1") is False

    def test_ipv6_full_no_port(self):
        assert _has_port_suffix("2001:db8::1") is False

    def test_ipv4_with_port(self):
        assert _has_port_suffix("192.0.2.1:8080") is True

    def test_wildcard_with_port(self):
        assert _has_port_suffix("*.stripe.com:443") is True

    def test_cidr_no_port(self):
        assert _has_port_suffix("192.0.2.0/24") is False

    def test_non_digit_after_colon(self):
        assert _has_port_suffix("host:abc") is False


class TestCouldBeIp:
    def test_hostname_not_mistaken_for_ipv6(self):
        assert _could_be_ip("api.stripe.com") is False

    def test_ipv4_candidate(self):
        assert _could_be_ip("192.0.2.1") is True

    def test_ipv6_candidate(self):
        assert _could_be_ip("fe80::1") is True

    def test_ipv6_loopback_short(self):
        assert _could_be_ip("::1") is True

    def test_ipv6_any(self):
        assert _could_be_ip("::") is True

    def test_hex_hostname_without_colon(self):
        """Hostname starting with hex letter but no colon is not an IP."""
        assert _could_be_ip("abc.example.com") is False

    def test_underscore_prefix_not_ip(self):
        assert _could_be_ip("_internal-host") is False


class TestNormalizeHost:
    def test_lowercase(self):
        assert _normalize_host("API.Stripe.COM") == "api.stripe.com"

    def test_trailing_dot(self):
        assert _normalize_host("api.stripe.com.") == "api.stripe.com"

    def test_ipv6_scope_id(self):
        assert _normalize_host("fe80::1%eth0") == "fe80::1"

    def test_whitespace(self):
        assert _normalize_host("  api.stripe.com  ") == "api.stripe.com"

    def test_trailing_dot_non_hex_hostname(self):
        assert _normalize_host("stripe.com.") == "stripe.com"

    def test_ip_not_stripped_of_dot(self):
        assert _normalize_host("192.0.2.1") == "192.0.2.1"

    def test_ip_with_trailing_dot_preserved(self):
        assert _normalize_host("192.0.2.1.") == "192.0.2.1."

    def test_multiple_trailing_dots_strips_one(self):
        """Only one trailing dot should be stripped (not all)."""
        assert _normalize_host("api.stripe.com..") == "api.stripe.com."

    def test_single_trailing_dot_in_rule_and_host_consistent(self):
        """Rule normalization and host normalization should agree for single dot."""
        policy = AllowPolicy(["api.stripe.com."])
        assert policy.is_allowed("api.stripe.com.") is True
        assert policy.is_allowed("api.stripe.com") is True

    def test_ip_like_invalid_hostname_keeps_trailing_dot(self):
        assert _normalize_host("1example.com.") == "1example.com"


class TestIsIpLike:
    def test_invalid_ip_like_hostname(self):
        assert _is_ip_like("1example.com") is False


class TestIsLocalhost:
    def test_localhost_string(self):
        assert _is_localhost("localhost") is True

    def test_ipv4_loopback(self):
        assert _is_localhost("127.0.0.1") is True

    def test_ipv6_loopback(self):
        assert _is_localhost("::1") is True

    def test_ipv4_loopback_other(self):
        assert _is_localhost("127.0.0.2") is True

    def test_inaddr_any_v4(self):
        assert _is_localhost("0.0.0.0") is True

    def test_inaddr_any_v6(self):
        assert _is_localhost("::") is True

    def test_ipv4_mapped_ipv6_loopback(self):
        assert _is_localhost("::ffff:127.0.0.1") is True

    def test_ipv4_mapped_ipv6_non_loopback(self):
        assert _is_localhost("::ffff:198.51.100.1") is False

    def test_public_ip(self):
        assert _is_localhost("198.51.100.1") is False

    def test_hostname(self):
        assert _is_localhost("example.com") is False

    def test_invalid_ip_like_hostname(self):
        assert _is_localhost("1example.com") is False

    def test_malformed_ip_like_localhost_prefix(self):
        """Starts with 127. but is not a valid IP — exercises ValueError path."""
        assert _is_localhost("127.0.0.bad") is False

    def test_full_loopback_range(self):
        """All of 127.0.0.0/8 should be loopback."""
        assert _is_localhost("127.255.255.255") is True
        assert _is_localhost("127.0.0.100") is True


class TestAllowPolicyHostname:
    def test_exact_match(self):
        policy = AllowPolicy(["api.stripe.com"])
        assert policy.is_allowed("api.stripe.com") is True
        assert policy.is_allowed("evil.test") is False

    def test_case_insensitive(self):
        policy = AllowPolicy(["API.Stripe.COM"])
        assert policy.is_allowed("api.stripe.com") is True

    def test_wildcard_subdomain(self):
        policy = AllowPolicy(["*.stripe.com"])
        assert policy.is_allowed("api.stripe.com") is True
        assert policy.is_allowed("dashboard.stripe.com") is True
        # Bare domain does NOT match *.domain
        assert policy.is_allowed("stripe.com") is False

    def test_wildcard_does_not_match_unrelated(self):
        policy = AllowPolicy(["*.stripe.com"])
        assert policy.is_allowed("evil.test") is False
        assert policy.is_allowed("api.stripe.com.evil.test") is False

    def test_multiple_rules(self):
        policy = AllowPolicy(["api.stripe.com", "*.twilio.com"])
        assert policy.is_allowed("api.stripe.com") is True
        assert policy.is_allowed("api.twilio.com") is True
        assert policy.is_allowed("evil.test") is False

    def test_wildcard_crosses_label_boundaries(self):
        """fnmatch * matches across dots, unlike TLS cert wildcards."""
        policy = AllowPolicy(["*.stripe.com"])
        assert policy.is_allowed("a.b.stripe.com") is True
        assert policy.is_allowed("a.b.c.stripe.com") is True


class TestAllowPolicyPort:
    def test_hostname_with_port(self):
        policy = AllowPolicy(["api.stripe.com:443"])
        assert policy.is_allowed("api.stripe.com", 443) is True
        assert policy.is_allowed("api.stripe.com", 80) is False

    def test_hostname_without_port_allows_any(self):
        policy = AllowPolicy(["api.stripe.com"])
        assert policy.is_allowed("api.stripe.com", 443) is True
        assert policy.is_allowed("api.stripe.com", 80) is True

    def test_port_rule_no_port_provided(self):
        # Rule has port but caller doesn't specify -> allow (port is None)
        policy = AllowPolicy(["api.stripe.com:443"])
        assert policy.is_allowed("api.stripe.com") is True

    def test_wildcard_with_port(self):
        policy = AllowPolicy(["*.stripe.com:443"])
        assert policy.is_allowed("api.stripe.com", 443) is True
        assert policy.is_allowed("api.stripe.com", 80) is False


class TestAllowPolicyIP:
    def test_literal_ipv4(self):
        policy = AllowPolicy(["192.0.2.1"])
        assert policy.is_allowed("192.0.2.1") is True
        assert policy.is_allowed("203.0.113.1") is False

    def test_cidr_range(self):
        policy = AllowPolicy(["192.0.2.0/24"])
        assert policy.is_allowed("192.0.2.1") is True
        assert policy.is_allowed("192.0.2.255") is True
        assert policy.is_allowed("203.0.113.1") is False

    def test_cidr_with_port(self):
        policy = AllowPolicy(["192.0.2.0/24:5432"])
        assert policy.is_allowed("192.0.2.1", 5432) is True
        assert policy.is_allowed("192.0.2.1", 80) is False

    def test_ipv6_literal(self):
        policy = AllowPolicy(["2001:db8::1"])
        assert policy.is_allowed("2001:db8::1") is True
        assert policy.is_allowed("2001:db8::2") is False


class TestAllowPolicyLocalhost:
    def test_localhost_allowed_by_default(self):
        policy = AllowPolicy(["api.stripe.com"])
        assert policy.is_allowed("127.0.0.1") is True
        assert policy.is_allowed("localhost") is True
        assert policy.is_allowed("::1") is True

    def test_localhost_can_be_disabled(self):
        policy = AllowPolicy(["api.stripe.com"], allow_localhost=False)
        assert policy.is_allowed("127.0.0.1") is False
        assert policy.is_allowed("localhost") is False
        assert policy.is_allowed("::1") is False


class TestAllowPolicyIPv4MappedIPv6:
    def test_ipv4_mapped_matches_ipv4_cidr(self):
        policy = AllowPolicy(["192.0.2.0/24"])
        assert policy.is_allowed("::ffff:192.0.2.1") is True

    def test_ipv4_mapped_matches_ipv4_literal(self):
        policy = AllowPolicy(["198.51.100.1"])
        assert policy.is_allowed("::ffff:198.51.100.1") is True

    def test_ipv4_mapped_matches_wildcard_ip_pattern(self):
        policy = AllowPolicy(["192.0.2.*"])
        assert policy.is_allowed("::ffff:192.0.2.1") is True
        assert policy.is_allowed("::ffff:198.51.100.1") is False

    def test_ipv4_mapped_no_match(self):
        policy = AllowPolicy(["192.0.2.0/24"])
        assert policy.is_allowed("::ffff:198.51.100.1") is False

    def test_ipv4_mapped_loopback_always_allowed(self):
        policy = AllowPolicy([])
        assert policy.is_allowed("::ffff:127.0.0.1") is True


class TestAllowPolicyTrailingDot:
    def test_trailing_dot_matches_rule(self):
        policy = AllowPolicy(["api.stripe.com"])
        assert policy.is_allowed("api.stripe.com.") is True

    def test_trailing_dot_matches_wildcard(self):
        policy = AllowPolicy(["*.stripe.com"])
        assert policy.is_allowed("api.stripe.com.") is True

    def test_trailing_dot_in_rule(self):
        policy = AllowPolicy(["api.stripe.com."])
        assert policy.is_allowed("api.stripe.com") is True

    def test_trailing_dot_in_wildcard_rule(self):
        policy = AllowPolicy(["*.example.com."], allow_localhost=False)
        assert policy.is_allowed("api.example.com") is True
        assert policy.is_allowed("api.example.com.") is True
        assert policy.is_allowed("example.org") is False

    def test_trailing_dot_before_port_in_exact_rule(self):
        """The FQDN dot belongs to the host part: ``host.:port``, not ``host:port.``."""
        policy = AllowPolicy(["api.example.com.:443"], allow_localhost=False)
        assert policy.is_allowed("api.example.com", 443) is True
        assert policy.is_allowed("api.example.com.", 443) is True
        assert policy.is_allowed("api.example.com", 80) is False

    def test_trailing_dot_before_port_in_wildcard_rule(self):
        policy = AllowPolicy(["*.example.com.:443"], allow_localhost=False)
        assert policy.is_allowed("api.example.com", 443) is True
        assert policy.is_allowed("api.example.com.", 443) is True
        assert policy.is_allowed("api.example.com", 80) is False
        assert policy.is_allowed("api.example.org", 443) is False

    def test_trailing_dot_before_port_in_ip_rule(self):
        policy = AllowPolicy(["192.0.2.1.:443"], allow_localhost=False)
        assert policy.is_allowed("192.0.2.1", 443) is True
        assert policy.is_allowed("192.0.2.1", 80) is False

    def test_trailing_dot_rules_equal_their_dotless_form(self):
        dotted = AllowPolicy(
            ["api.example.com.", "api.example.com.:443", "*.example.com.", "*.example.com.:443"]
        )
        plain = AllowPolicy(
            ["api.example.com", "api.example.com:443", "*.example.com", "*.example.com:443"]
        )
        assert dotted._exact_hosts_any_port == plain._exact_hosts_any_port
        assert dotted._exact_hosts == plain._exact_hosts
        assert dotted._host_rules == plain._host_rules

    def test_trailing_dot_rules_serialize_without_the_dot(self):
        """A child process rebuilds the same policy from the serialized allow list."""
        policy = AllowPolicy(["api.example.com.:443", "*.example.com.:443", "db.example.com."])
        serialized = _serialize_allow_list(policy)
        assert serialized == ["*.example.com:443", "api.example.com:443", "db.example.com"]
        assert _serialize_allow_list(AllowPolicy(serialized)) == serialized

    def test_double_trailing_dot_before_port_round_trips_through_serialization(self):
        """One dot is stripped; the one that stays survives the trip to a child process."""
        policy = AllowPolicy(["api.example.com..:443"], allow_localhost=False)
        assert policy.is_allowed("api.example.com..", 443) is True
        assert policy.is_allowed("api.example.com", 443) is False

        serialized = _serialize_allow_list(policy)
        assert serialized == ["api.example.com..:443"]
        assert AllowPolicy(serialized, allow_localhost=False)._exact_hosts == policy._exact_hosts

    @pytest.mark.parametrize("rule", ["api.example.com:443.", "*.example.com:443."])
    def test_dot_after_port_raises(self, rule):
        """``443.`` is not a port; only the host part may carry the FQDN dot."""
        with pytest.raises(ValueError, match="not a valid HOST:PORT rule"):
            AllowPolicy([rule])

    def test_dot_after_bracketed_ip_raises(self):
        with pytest.raises(ValueError, match=r"unexpected text '\.' after '\]'"):
            AllowPolicy(["[2001:db8::1]."])
        with pytest.raises(ValueError, match=r"invalid port '443\.'"):
            AllowPolicy(["[2001:db8::1]:443."])

    def test_host_of_only_a_dot_before_port_raises(self):
        with pytest.raises(ValueError, match="has no host"):
            AllowPolicy([".:443"])


class TestAllowPolicyScopeId:
    def test_ipv6_scope_id_stripped(self):
        policy = AllowPolicy(["fe80::1"])
        assert policy.is_allowed("fe80::1%eth0") is True


class TestAllowPolicyINADDR_ANY:
    def test_0000_allowed_as_localhost(self):
        policy = AllowPolicy(["api.stripe.com"])
        assert policy.is_allowed("0.0.0.0") is True

    def test_ipv6_any_allowed_as_localhost(self):
        policy = AllowPolicy(["api.stripe.com"])
        assert policy.is_allowed("::") is True

    def test_0000_blocked_when_localhost_disabled(self):
        policy = AllowPolicy(["api.stripe.com"], allow_localhost=False)
        assert policy.is_allowed("0.0.0.0") is False


class TestAllowPolicyBracketNotation:
    def test_bracketed_ipv6(self):
        policy = AllowPolicy(["[::1]"])
        assert policy.is_allowed("::1") is True

    def test_bracketed_ipv6_with_port(self):
        policy = AllowPolicy(["[2001:db8::1]:443"])
        assert policy.is_allowed("2001:db8::1", 443) is True
        assert policy.is_allowed("2001:db8::1", 80) is False

    def test_bracketed_ipv6_without_port_allows_any(self):
        policy = AllowPolicy(["[2001:db8::1]"])
        assert policy.is_allowed("2001:db8::1", 443) is True
        assert policy.is_allowed("2001:db8::1", 80) is True

    def test_bracketed_ipv6_network(self):
        policy = AllowPolicy(["[2001:db8::]/32"])
        assert policy.is_allowed("2001:db8::1") is True
        assert policy.is_allowed("2001:db9::1") is False

    def test_bracketed_ipv6_network_with_port(self):
        policy = AllowPolicy(["[2001:db8::]/32:443"])
        assert policy.is_allowed("2001:db8::1", 443) is True
        assert policy.is_allowed("2001:db8::1", 80) is False

    def test_bracketed_ipv4(self):
        policy = AllowPolicy(["[192.0.2.1]"], allow_localhost=False)
        assert policy.is_allowed("192.0.2.1", 80) is True
        assert policy.is_allowed("192.0.2.2", 80) is False

    def test_bracketed_ipv4_with_port(self):
        policy = AllowPolicy(["[192.0.2.1]:443"], allow_localhost=False)
        assert policy.is_allowed("192.0.2.1", 443) is True
        assert policy.is_allowed("192.0.2.1", 80) is False

    def test_bracketed_ipv4_network_with_port(self):
        policy = AllowPolicy(["[10.0.0.0]/8:5432"], allow_localhost=False)
        assert policy.is_allowed("10.1.2.3", 5432) is True
        assert policy.is_allowed("10.1.2.3", 80) is False
        assert policy.is_allowed("11.1.2.3", 5432) is False

    def test_bracketed_non_ip_is_a_character_set(self):
        """Brackets that hold no IP address are fnmatch syntax, not a hostname."""
        policy = AllowPolicy(["[not-an-ip]"], allow_localhost=False)
        assert policy.is_allowed("not-an-ip") is False
        assert policy.is_allowed("n") is True

    @pytest.mark.parametrize(
        "rule",
        [
            "[2001:db8::1]:abc",
            "[2001:db8::1]:-1",
            "[2001:db8::1]:",
            "[2001:db8::1]:44x",
            "[2001:db8::1]:\u0664\u0664\u0663",
            "[2001:db8::]/32:abc",
            "[2001:db8::]/32:-1",
            "[2001:db8::]/32:",
            "[192.0.2.1]:http",
        ],
    )
    def test_bracketed_invalid_port_raises(self, rule):
        """A malformed port must not widen the rule to every port."""
        with pytest.raises(ValueError, match="invalid port"):
            AllowPolicy([rule])

    @pytest.mark.parametrize("rule", ["[2001:db8::1]:65536", "[2001:db8::]/32:70000"])
    def test_bracketed_out_of_range_port_raises(self, rule):
        with pytest.raises(ValueError, match="out of valid range"):
            AllowPolicy([rule])

    @pytest.mark.parametrize(
        "rule",
        [
            "[2001:db8::1]garbage",
            "[2001:db8::1]443",
            "[2001:db8::1].example.com",
            "[2001:db8::1]x:443",
            "[192.0.2.1]garbage",
        ],
    )
    def test_bracketed_trailing_text_raises(self, rule):
        with pytest.raises(ValueError, match=r"unexpected text .* after '\]'"):
            AllowPolicy([rule])

    @pytest.mark.parametrize(
        "rule",
        [
            "[2001:db8::]/",
            "[2001:db8::]/129",
            "[2001:db8::]/abc",
            "[2001:db8::]/32/48",
            "[2001:db8::]/:443",
            "[192.0.2.0]/33",
        ],
    )
    def test_bracketed_invalid_prefix_raises(self, rule):
        with pytest.raises(ValueError, match="invalid network prefix"):
            AllowPolicy([rule])

    @pytest.mark.parametrize("rule", ["[2001:db8::/32]", "[2001:db8::1", "[2001:db8::*]:443"])
    def test_bracketed_malformed_ip_raises(self, rule):
        """Not a bracketed IP and, because of the colons, not a hostname pattern either."""
        with pytest.raises(ValueError, match="not a valid HOST:PORT rule"):
            AllowPolicy([rule])


class TestAllowPolicyLeadingCharacterSet:
    """A rule may start with an fnmatch ``[seq]`` set; it is not a bracketed IP."""

    def test_leading_set_with_port(self):
        policy = AllowPolicy(["[ab].example.com:443"], allow_localhost=False)
        assert policy.is_allowed("a.example.com", 443) is True
        assert policy.is_allowed("b.example.com", 443) is True
        assert policy.is_allowed("c.example.com", 443) is False
        assert policy.is_allowed("a.example.com", 80) is False
        # The pre-fix parse: exact hostname "ab" on any port.
        assert policy.is_allowed("ab", 443) is False

    def test_leading_set_without_port(self):
        policy = AllowPolicy(["[ab].example.com"], allow_localhost=False)
        assert policy.is_allowed("a.example.com", 80) is True
        assert policy.is_allowed("ab.example.com", 80) is False

    def test_leading_negated_set(self):
        policy = AllowPolicy(["[!a].example.com:443"], allow_localhost=False)
        assert policy.is_allowed("b.example.com", 443) is True
        assert policy.is_allowed("a.example.com", 443) is False

    def test_leading_digit_set_is_not_an_ip(self):
        policy = AllowPolicy(["[12].example.com"], allow_localhost=False)
        assert policy.is_allowed("1.example.com") is True
        assert policy.is_allowed("3.example.com") is False

    def test_leading_set_out_of_range_port_raises(self):
        with pytest.raises(ValueError, match="out of valid range"):
            AllowPolicy(["[ab].example.com:99999"])

    def test_bracketed_star_is_not_match_all(self):
        """``[*]`` used to be unwrapped to ``*`` behind the match-all guard's back."""
        policy = AllowPolicy(["[*]"], allow_localhost=False)
        assert policy.is_allowed("evil.example", 443) is False
        assert policy.is_allowed("8.8.8.8", 53) is False

    def test_leading_set_round_trips_through_serialization(self):
        policy = AllowPolicy(["[ab].example.com:443"])
        serialized = _serialize_allow_list(policy)
        assert serialized == ["[ab].example.com:443"]
        assert AllowPolicy(serialized)._host_rules == policy._host_rules


class TestAllowPolicyIPWildcard:
    def test_ip_wildcard_pattern(self):
        policy = AllowPolicy(["192.0.2.*"])
        assert policy.is_allowed("192.0.2.1") is True
        assert policy.is_allowed("203.0.113.1") is False

    def test_ip_wildcard_pattern_with_port_match(self):
        policy = AllowPolicy(["192.0.2.*:443"])
        assert policy.is_allowed("192.0.2.1", 443) is True

    def test_ip_wildcard_pattern_with_port_mismatch(self):
        policy = AllowPolicy(["192.0.2.*:443"])
        assert policy.is_allowed("192.0.2.1", 80) is False


class TestAllowPolicyEdgeCases:
    def test_url_rejected(self):
        """URLs are rejected with a helpful error message."""
        with pytest.raises(ValueError, match="looks like a URL"):
            AllowPolicy(["https://api.stripe.com:443"])

    def test_http_url_rejected(self):
        with pytest.raises(ValueError, match="looks like a URL"):
            AllowPolicy(["http://api.stripe.com"])

    def test_empty_allow_list(self):
        policy = AllowPolicy([])
        assert policy.is_allowed("evil.test") is False
        # Localhost still allowed
        assert policy.is_allowed("127.0.0.1") is True

    def test_whitespace_in_rule(self):
        policy = AllowPolicy(["  api.stripe.com  "])
        assert policy.is_allowed("api.stripe.com") is True

    def test_empty_string_rule(self):
        with pytest.raises(ValueError, match="empty or whitespace"):
            AllowPolicy([""])

    def test_whitespace_only_rule(self):
        with pytest.raises(ValueError, match="empty or whitespace"):
            AllowPolicy(["  "])

    def test_garbage_rule(self):
        # Non-parseable rules become harmless dead hostname patterns
        policy = AllowPolicy(["not a valid rule!@#$"])
        assert policy.is_allowed("evil.test") is False

    def test_invalid_ip_like_hostname_falls_back_to_hostname_matching(self):
        policy = AllowPolicy(["1example.com"])
        assert policy.is_allowed("1example.com") is True


class TestAllowPolicyPortValidation:
    """Test that out-of-range ports are rejected."""

    def test_port_too_high_raises(self):
        with pytest.raises(ValueError, match="out of valid range"):
            AllowPolicy(["host:99999"])

    def test_port_too_high_cidr_raises(self):
        with pytest.raises(ValueError, match="out of valid range"):
            AllowPolicy(["192.0.2.0/24:70000"])

    def test_port_too_high_bracketed_ipv6_raises(self):
        with pytest.raises(ValueError, match="out of valid range"):
            AllowPolicy(["[2001:db8::1]:99999"])

    def test_port_zero_valid(self):
        policy = AllowPolicy(["host:0"])
        assert policy.is_allowed("host", 0) is True

    def test_port_65535_valid(self):
        policy = AllowPolicy(["host:65535"])
        assert policy.is_allowed("host", 65535) is True


class TestAllowPolicyWildcardWarnings:
    """Test that overly-broad patterns emit warnings."""

    def test_bare_star_raises(self):
        with pytest.raises(ValueError, match="matches ALL destinations"):
            AllowPolicy(["*"])

    def test_star_dot_star_raises(self):
        with pytest.raises(ValueError, match="matches ALL destinations"):
            AllowPolicy(["*.*"])

    def test_star_dot_star_dot_star_raises(self):
        with pytest.raises(ValueError, match="matches ALL destinations"):
            AllowPolicy(["*.*.*"])

    def test_star_dot_raises(self):
        with pytest.raises(ValueError, match="matches ALL destinations"):
            AllowPolicy(["*."])

    def test_star_with_port_raises(self):
        with pytest.raises(ValueError, match="matches ALL destinations"):
            AllowPolicy(["*:443"])

    def test_mixed_star_question_raises(self):
        with pytest.raises(ValueError, match="matches ALL destinations"):
            AllowPolicy(["*?*"])

    def test_question_star_raises(self):
        with pytest.raises(ValueError, match="matches ALL destinations"):
            AllowPolicy(["?*"])

    def test_star_question_raises(self):
        with pytest.raises(ValueError, match="matches ALL destinations"):
            AllowPolicy(["*?"])

    def test_mixed_star_question_with_port_raises(self):
        with pytest.raises(ValueError, match="matches ALL destinations"):
            AllowPolicy(["*?*:443"])

    def test_star_with_literal_accepted(self):
        """*a* has a literal character — accepted."""
        AllowPolicy(["*a*"])

    def test_normal_wildcard_no_error(self):
        AllowPolicy(["*.stripe.com"])

    def test_question_mark_pattern_accepted(self):
        """? is a single-char match, not 'match all' — must be accepted."""
        AllowPolicy(["???.??"])

    def test_question_mark_with_port_accepted(self):
        """?:443 matches single-char hostnames on port 443 — must be accepted."""
        AllowPolicy(["?:443"])

    def test_question_mark_prefix_accepted(self):
        """?.stripe.com matches single-char subdomains — must be accepted."""
        AllowPolicy(["?.stripe.com"])

    @pytest.mark.parametrize(
        "rule",
        [
            "*[!/]",
            "*[a-z0-9]",
            "[!/]*",
            "*[!/]:443",
            "*.[a-z]*",
            "[a-z]*[0-9]",
            "*[]a]",
            "*[!]a]",
            "[ab].*",
        ],
    )
    def test_character_set_is_not_a_literal(self, rule):
        """A ``[...]`` set matches like a wildcard, so it cannot anchor a ``*`` pattern."""
        with pytest.raises(ValueError, match="matches ALL destinations"):
            AllowPolicy([rule])

    @pytest.mark.parametrize(
        "rule",
        ["x[ab].example.com", "[ab]*.example.com", "*[ab]c", "*.example.com", "*[ab", "*]"],
    )
    def test_character_set_next_to_a_literal_accepted(self, rule):
        AllowPolicy([rule])

    @pytest.mark.parametrize("rule", ["[!/]", "[a-z][a-z]", "[a-z]?.[0-9]", "[*]"])
    def test_character_sets_without_star_are_bounded(self, rule):
        """Like ``?``, a set matches exactly one character — bounded, so accepted."""
        AllowPolicy([rule])


@pytest.fixture
def address_wildcard_warnings(monkeypatch, caplog):
    """Start with no rule warned about yet; return the address-shaped warnings logged."""
    monkeypatch.setattr(_policy, "_ADDRESS_WILDCARD_WARNED", set())
    caplog.set_level(logging.WARNING, logger="tethered")

    def warnings() -> list[str]:
        return [r.getMessage() for r in caplog.records if "CIDR notation" in r.getMessage()]

    return warnings


class TestAddressShapedWildcard:
    """``10.*`` is an fnmatch pattern over text, not an address range."""

    def test_matching_is_unchanged(self):
        policy = AllowPolicy(["10.*"], allow_localhost=False)
        assert policy.is_allowed("10.1.2.3") is True
        assert policy.is_allowed("11.1.2.3") is False
        # The documented fnmatch semantics: a hostname that fits the text matches too.
        assert policy.is_allowed("10.attacker.example") is True

    @pytest.mark.parametrize(
        "rule",
        ["10.*", "192.0.2.*", "192.0.2.*:443", "10.?.0.1", "1*", "*.1", "10.[0-9].*", "10.[!0].1"],
    )
    def test_warns_and_points_to_cidr(self, rule, address_wildcard_warnings):
        AllowPolicy([rule])
        (message,) = address_wildcard_warnings()
        assert repr(rule) in message
        assert "also allows every hostname" in message
        assert "CIDR notation" in message

    @pytest.mark.parametrize(
        "rule",
        [
            "*.example.com",
            "api1.example.com",
            "10.example.*",
            "1example.*",
            "???.??",
            "10.0.0.0/8",
            "192.0.2.1",
            "10.0.0.256",
            "10.*[",
        ],
    )
    def test_no_warning_for_other_rules(self, rule, address_wildcard_warnings):
        AllowPolicy([rule])
        assert address_wildcard_warnings() == []

    def test_warns_once_per_rule_string(self, address_wildcard_warnings):
        """``scope()`` builds a policy on every use; the log must not repeat per call."""
        for _ in range(3):
            AllowPolicy(["10.*", "api.example.com"])
        assert len(address_wildcard_warnings()) == 1

        AllowPolicy(["10.*", "172.16.*"])
        assert len(address_wildcard_warnings()) == 2

    def test_warned_set_is_bounded(self, monkeypatch, address_wildcard_warnings):
        monkeypatch.setattr(_policy, "_ADDRESS_WILDCARD_WARNED_MAX", 2)
        AllowPolicy(["10.*", "11.*", "12.*", "13.*"])
        assert len(address_wildcard_warnings()) == 2
        assert {"10.*", "11.*"} == _policy._ADDRESS_WILDCARD_WARNED


class TestAllowPolicyEmptyRuleRaises:
    """Test that empty/whitespace rules raise ValueError."""

    def test_empty_rule_raises(self):
        with pytest.raises(ValueError, match="empty or whitespace"):
            AllowPolicy(["", "valid.com"])

    def test_whitespace_rule_raises(self):
        with pytest.raises(ValueError, match="empty or whitespace"):
            AllowPolicy(["  "])

    def test_valid_rule_no_error(self):
        AllowPolicy(["valid.com"])


class TestNormalizationConsistency:
    """Test that rule normalization and host normalization are consistent."""

    def test_single_trailing_dot_consistency(self):
        """Single trailing dot in rule and host should match."""
        policy = AllowPolicy(["api.stripe.com."])
        assert policy.is_allowed("api.stripe.com.") is True
        assert policy.is_allowed("api.stripe.com") is True

    def test_double_trailing_dot_rule(self):
        """Double trailing dot: rule strips one, host strips one -> still one dot difference."""
        # Rule "host.." strips one -> "host."
        # Host "host.." strips one -> "host."
        # They should match each other
        policy = AllowPolicy(["api.stripe.com.."])
        assert policy.is_allowed("api.stripe.com..") is True

    def test_double_trailing_dot_rule_round_trips_through_serialization(self):
        """The serialized form re-parses to the same rule instead of losing the second dot."""
        policy = AllowPolicy(["api.stripe.com..", "*.example.com.."], allow_localhost=False)
        serialized = _serialize_allow_list(policy)
        assert serialized == ["*.example.com..", "api.stripe.com.."]

        rebuilt = AllowPolicy(serialized, allow_localhost=False)
        assert rebuilt._exact_hosts_any_port == policy._exact_hosts_any_port
        assert rebuilt._host_rules == policy._host_rules
        assert rebuilt.is_allowed("api.stripe.com") is False

    def test_whitespace_before_trailing_dot_is_stripped(self):
        """``"host ."`` must not keep a trailing space that a re-parse would strip."""
        policy = AllowPolicy(["api.stripe.com ."], allow_localhost=False)
        assert policy.is_allowed("api.stripe.com") is True
        assert _serialize_allow_list(policy) == ["api.stripe.com"]


class TestHostnameNormalizationEdgeCases:
    """Adversarial hostname normalization inputs."""

    def test_null_byte_in_hostname(self):
        """Null bytes should be rejected as malformed hostnames."""
        policy = AllowPolicy(["*.allowed.com"])
        assert policy.is_allowed("evil.test\x00.allowed.com") is False

    def test_newline_in_hostname(self):
        """Newlines should be rejected as malformed hostnames."""
        policy = AllowPolicy(["*.allowed.com"])
        assert policy.is_allowed("evil.test\n.allowed.com") is False

    def test_tab_in_hostname(self):
        """Tabs should be rejected as malformed hostnames."""
        policy = AllowPolicy(["*.allowed.com"])
        assert policy.is_allowed("evil.test\t.allowed.com") is False

    def test_nbsp_in_hostname(self):
        """Non-breaking space (U+00A0) should be rejected."""
        policy = AllowPolicy(["*.allowed.com"])
        assert policy.is_allowed("evil.test\xa0.allowed.com") is False

    def test_zero_width_space_in_hostname(self):
        """Zero-width space (U+200B) should be rejected."""
        policy = AllowPolicy(["*.allowed.com"])
        assert policy.is_allowed("evil.test\u200b.allowed.com") is False

    def test_idn_hostname_allowed(self):
        """Internationalized domain names with visible Unicode should work."""
        policy = AllowPolicy(["münchen.de"])
        assert policy.is_allowed("münchen.de") is True

    def test_idn_wildcard_allowed(self):
        """Wildcard rules should match IDN hostnames."""
        policy = AllowPolicy(["*.例え.jp"])
        assert policy.is_allowed("sub.例え.jp") is True

    def test_very_long_hostname(self):
        """Very long hostname should not crash (may be slow but not error)."""
        policy = AllowPolicy(["*.allowed.com"])
        long_host = "a" * 10000 + ".allowed.com"
        # Should match but just verifying no crash
        assert isinstance(policy.is_allowed(long_host), bool)

    def test_leading_dot_hostname(self):
        policy = AllowPolicy(["*.stripe.com"])
        assert policy.is_allowed(".stripe.com") is True  # fnmatch: * matches ""

    def test_fnmatch_question_mark(self):
        """'?' in patterns matches a single character."""
        policy = AllowPolicy(["api?.stripe.com"])
        assert policy.is_allowed("api1.stripe.com") is True
        assert policy.is_allowed("api.stripe.com") is False  # ? requires exactly one char

    def test_fnmatch_bracket_syntax(self):
        """'[seq]' in patterns matches character sets."""
        policy = AllowPolicy(["api[12].stripe.com"])
        assert policy.is_allowed("api1.stripe.com") is True
        assert policy.is_allowed("api2.stripe.com") is True
        assert policy.is_allowed("api3.stripe.com") is False

    def test_duplicate_rules(self):
        """Duplicate rules should not cause issues."""
        policy = AllowPolicy(["api.stripe.com", "api.stripe.com", "*.stripe.com"])
        assert policy.is_allowed("api.stripe.com") is True
        assert policy.is_allowed("evil.test") is False


class TestCIDREdgeCases:
    """Test CIDR matching edge cases."""

    def test_strict_false_normalizes_host_bits(self):
        """ipaddress.ip_network with strict=False silently normalizes host bits."""
        # "192.0.2.1/24" becomes "192.0.2.0/24"
        policy = AllowPolicy(["192.0.2.1/24"])
        assert policy.is_allowed("192.0.2.0") is True
        assert policy.is_allowed("192.0.2.255") is True

    def test_single_ip_as_cidr(self):
        """/32 CIDR should match exactly one IP."""
        policy = AllowPolicy(["192.0.2.1/32"])
        assert policy.is_allowed("192.0.2.1") is True
        assert policy.is_allowed("192.0.2.2") is False

    def test_cross_family_no_crash(self):
        """IPv4 address checked against IPv6 CIDR should not crash."""
        policy = AllowPolicy(["[2001:db8::]/32"])
        # This should return False, not raise TypeError
        assert policy.is_allowed("192.0.2.1") is False

    def test_cross_family_typeerror_caught(self):
        """Non-standard network objects are safely skipped by isinstance guard."""
        policy = AllowPolicy(["10.0.0.0/8"])
        # Replace the network with a mock that raises TypeError on __contains__
        mock_network = MagicMock()
        mock_network.__contains__ = MagicMock(side_effect=TypeError("cross-family"))

        object.__setattr__(
            policy,
            "_network_rules",
            (_NetworkRule(network=mock_network, port=None),),
        )
        assert policy.is_allowed("192.0.2.1") is False


class TestScopeIdStripping:
    """Scope ID stripping should only apply to IPv6 addresses."""

    def test_percent_in_non_ipv6_hostname_preserved(self):
        """Hostnames with % but no colons should not be truncated."""
        policy = AllowPolicy(["internal-service%env"])
        assert policy.is_allowed("internal-service%env") is True

    def test_percent_in_non_ipv6_hostname_not_false_match(self):
        """Hostname with % should not match a truncated version."""
        policy = AllowPolicy(["internal-service"])
        assert policy.is_allowed("internal-service%evil-data") is False

    def test_ipv6_scope_id_still_stripped(self):
        """IPv6 scope IDs should still be stripped correctly."""
        policy = AllowPolicy(["fe80::1"])
        assert policy.is_allowed("fe80::1%eth0") is True


class TestUnicodeNormalization:
    """NFC normalization and fullwidth dot handling."""

    def test_nfc_nfd_equivalence(self):
        """NFC and NFD forms of the same hostname should match."""
        # NFC form: é as single codepoint U+00E9
        policy = AllowPolicy(["caf\u00e9.com"])
        # NFD form: e + combining acute accent (U+0065 U+0301)
        assert policy.is_allowed("caf\u0065\u0301.com") is True

    def test_nfc_nfd_wildcard(self):
        """Wildcard rules should match both NFC and NFD forms."""
        policy = AllowPolicy(["*.caf\u00e9.com"])
        assert policy.is_allowed("sub.caf\u0065\u0301.com") is True

    def test_fullwidth_dot_normalized(self):
        """Fullwidth full stop (U+FF0E) should be normalized to ASCII dot."""
        policy = AllowPolicy(["evil.test"])
        assert policy.is_allowed("evil\uff0etest") is True

    def test_ideographic_full_stop_normalized(self):
        """Ideographic full stop (U+3002) should be normalized to ASCII dot."""
        policy = AllowPolicy(["evil.test"])
        assert policy.is_allowed("evil\u3002test") is True

    def test_fullwidth_dot_in_rule_normalized(self):
        """Fullwidth dots in rules should also be normalized."""
        policy = AllowPolicy(["evil\uff0etest"])
        assert policy.is_allowed("evil.test") is True


class TestPortParsingNonAsciiDigits:
    """Non-ASCII digits are not port numbers; the rule is rejected, not kept as a dead rule."""

    def test_superscript_digit_not_port(self):
        """Superscript ² (U+00B2) should not be parsed as port digit."""
        with pytest.raises(ValueError, match="not a valid HOST:PORT rule"):
            AllowPolicy(["host:\u00b2"])

    def test_arabic_indic_digit_not_port(self):
        """Arabic-Indic digits should not be parsed as port."""
        with pytest.raises(ValueError, match="not a valid HOST:PORT rule"):
            AllowPolicy(["host:\u0660\u0661\u0662"])


class TestMalformedPortRejected:
    """A hostname rule that still contains ``:`` after parsing can never match a hostname."""

    @pytest.mark.parametrize(
        "rule",
        [
            "host.example:abc",
            "host.example:-1",
            "host.example:",
            "host.example: 443",
            "host.example:443:80",
            "*.example.com:https",
            "[ab].example.com:abc",
        ],
    )
    def test_malformed_port_raises(self, rule):
        with pytest.raises(ValueError, match="not a valid HOST:PORT rule"):
            AllowPolicy([rule])

    @pytest.mark.parametrize("rule", ["2001:db8::zz", "2001:db8::1/200", "fe80::*", "2001:db8:*"])
    def test_malformed_ipv6_raises(self, rule):
        """Mistyped IPv6 addresses/CIDRs and wildcards over IPv6 text are rejected."""
        with pytest.raises(ValueError, match="CIDR notation"):
            AllowPolicy([rule])

    @pytest.mark.parametrize("rule", [":443", ".", " . "])
    def test_rule_without_host_raises(self, rule):
        """An empty host would serialize to a rule the child process rejects."""
        with pytest.raises(ValueError, match="has no host"):
            AllowPolicy([rule])

    def test_unbracketed_ipv6_forms_unchanged(self):
        policy = AllowPolicy(["2001:db8::1", "2001:db9::/32", "::ffff:192.0.2.1"])
        assert policy.is_allowed("2001:db8::1", 443) is True
        assert policy.is_allowed("2001:db8::2", 443) is False
        assert policy.is_allowed("2001:db9::5", 80) is True
        assert policy.is_allowed("192.0.2.2", 80) is False
        assert policy.is_allowed("::ffff:192.0.2.1", 80) is True

    def test_ipv4_and_cidr_ports_unchanged(self):
        policy = AllowPolicy(["192.0.2.1:8080", "10.0.0.0/8:5432"], allow_localhost=False)
        assert policy.is_allowed("192.0.2.1", 8080) is True
        assert policy.is_allowed("192.0.2.1", 80) is False
        assert policy.is_allowed("10.9.9.9", 5432) is True
        assert policy.is_allowed("10.9.9.9", 80) is False


class TestIPv4MappedLocalhostUnspecified:
    """::ffff:0.0.0.0 should be treated as localhost."""

    def test_ipv4_mapped_unspecified(self):
        policy = AllowPolicy(["api.stripe.com"])
        assert policy.is_allowed("::ffff:0.0.0.0") is True

    def test_ipv4_mapped_unspecified_blocked_when_disabled(self):
        policy = AllowPolicy(["api.stripe.com"], allow_localhost=False)
        assert policy.is_allowed("::ffff:0.0.0.0") is False
