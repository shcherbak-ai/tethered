"""Unit tests for AllowPolicy pattern matching."""

from __future__ import annotations

import pytest

from tethered._policy import (
    AllowPolicy,
    _could_be_ip,
    _has_port_suffix,
    _is_ip_like,
    _is_localhost,
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
        assert policy.is_allowed("evil.com") is False

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
        assert policy.is_allowed("evil.com") is False
        assert policy.is_allowed("api.stripe.com.evil.com") is False

    def test_multiple_rules(self):
        policy = AllowPolicy(["api.stripe.com", "*.twilio.com"])
        assert policy.is_allowed("api.stripe.com") is True
        assert policy.is_allowed("api.twilio.com") is True
        assert policy.is_allowed("evil.com") is False

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

    def test_bracketed_invalid_becomes_host_rule(self):
        policy = AllowPolicy(["[not-an-ip]"])
        assert policy.is_allowed("not-an-ip") is True
        assert policy.is_allowed("other") is False


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
    def test_empty_allow_list(self):
        policy = AllowPolicy([])
        assert policy.is_allowed("evil.com") is False
        # Localhost still allowed
        assert policy.is_allowed("127.0.0.1") is True

    def test_whitespace_in_rule(self):
        policy = AllowPolicy(["  api.stripe.com  "])
        assert policy.is_allowed("api.stripe.com") is True

    def test_empty_string_rule(self):
        # Empty/whitespace rules should not crash or match anything
        policy = AllowPolicy(["", "  "])
        assert policy.is_allowed("evil.com") is False

    def test_garbage_rule(self):
        # Non-parseable rules become harmless dead hostname patterns
        policy = AllowPolicy(["not a valid rule!@#$"])
        assert policy.is_allowed("evil.com") is False

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

    def test_bare_star_warns(self, caplog):
        AllowPolicy(["*"])
        assert "matches ALL destinations" in caplog.text

    def test_normal_wildcard_no_warning(self, caplog):
        AllowPolicy(["*.stripe.com"])
        assert "matches ALL destinations" not in caplog.text


class TestAllowPolicyEmptyRuleWarnings:
    """Test that empty/whitespace rules emit warnings."""

    def test_empty_rule_warns(self, caplog):
        AllowPolicy(["", "  ", "valid.com"])
        assert "ignoring empty allow rule" in caplog.text

    def test_valid_rule_no_warning(self, caplog):
        AllowPolicy(["valid.com"])
        assert "ignoring empty" not in caplog.text


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


class TestHostnameNormalizationEdgeCases:
    """Adversarial hostname normalization inputs."""

    def test_null_byte_in_hostname(self):
        """Null bytes should be rejected as malformed hostnames."""
        policy = AllowPolicy(["*.allowed.com"])
        assert policy.is_allowed("evil.com\x00.allowed.com") is False

    def test_newline_in_hostname(self):
        """Newlines should be rejected as malformed hostnames."""
        policy = AllowPolicy(["*.allowed.com"])
        assert policy.is_allowed("evil.com\n.allowed.com") is False

    def test_tab_in_hostname(self):
        """Tabs should be rejected as malformed hostnames."""
        policy = AllowPolicy(["*.allowed.com"])
        assert policy.is_allowed("evil.com\t.allowed.com") is False

    def test_nbsp_in_hostname(self):
        """Non-breaking space (U+00A0) should be rejected."""
        policy = AllowPolicy(["*.allowed.com"])
        assert policy.is_allowed("evil.com\xa0.allowed.com") is False

    def test_zero_width_space_in_hostname(self):
        """Zero-width space (U+200B) should be rejected."""
        policy = AllowPolicy(["*.allowed.com"])
        assert policy.is_allowed("evil.com\u200b.allowed.com") is False

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
        assert policy.is_allowed("evil.com") is False


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
        from unittest.mock import MagicMock

        policy = AllowPolicy(["10.0.0.0/8"])
        # Replace the network with a mock that raises TypeError on __contains__
        mock_network = MagicMock()
        mock_network.__contains__ = MagicMock(side_effect=TypeError("cross-family"))
        from tethered._policy import _NetworkRule

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
        policy = AllowPolicy(["evil.com"])
        assert policy.is_allowed("evil\uff0ecom") is True

    def test_ideographic_full_stop_normalized(self):
        """Ideographic full stop (U+3002) should be normalized to ASCII dot."""
        policy = AllowPolicy(["evil.com"])
        assert policy.is_allowed("evil\u3002com") is True

    def test_fullwidth_dot_in_rule_normalized(self):
        """Fullwidth dots in rules should also be normalized."""
        policy = AllowPolicy(["evil\uff0ecom"])
        assert policy.is_allowed("evil.com") is True


class TestPortParsingNonAsciiDigits:
    """Non-ASCII digits should not be treated as port numbers."""

    def test_superscript_digit_not_port(self):
        """Superscript ² (U+00B2) should not be parsed as port digit."""
        # Should not crash and should treat as a hostname pattern
        policy = AllowPolicy(["host:\u00b2"])
        # The rule "host:²" should be treated as a hostname, not host:port
        assert policy.is_allowed("host:\u00b2") is True

    def test_arabic_indic_digit_not_port(self):
        """Arabic-Indic digits should not be parsed as port."""
        policy = AllowPolicy(["host:\u0660\u0661\u0662"])
        assert policy.is_allowed("host:\u0660\u0661\u0662") is True


class TestIPv4MappedLocalhostUnspecified:
    """::ffff:0.0.0.0 should be treated as localhost."""

    def test_ipv4_mapped_unspecified(self):
        policy = AllowPolicy(["api.stripe.com"])
        assert policy.is_allowed("::ffff:0.0.0.0") is True

    def test_ipv4_mapped_unspecified_blocked_when_disabled(self):
        policy = AllowPolicy(["api.stripe.com"], allow_localhost=False)
        assert policy.is_allowed("::ffff:0.0.0.0") is False
