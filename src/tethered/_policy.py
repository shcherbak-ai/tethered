"""Pattern parsing and matching for tethered allow rules."""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
import unicodedata
from dataclasses import dataclass

logger = logging.getLogger("tethered")


@dataclass(frozen=True, slots=True)
class _HostRule:
    """A parsed allow rule for hostname matching."""

    pattern: str  # lowercase, e.g. "*.stripe.com" or "api.example.com"
    port: int | None  # None means any port


@dataclass(frozen=True, slots=True)
class _NetworkRule:
    """A parsed allow rule for CIDR matching."""

    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    port: int | None


def _could_be_ip(host: str) -> bool:
    """Fast heuristic: could ``host`` be an IP address?

    IPv4 starts with a digit. IPv6 contains ``:`` and starts with a hex
    digit or ``:``.
    """
    if not host:
        return False
    c = host[0]
    if c.isdigit() or c == ":":
        return True
    return ":" in host and c in "abcdefABCDEF"


def _validate_port(port: int) -> int:
    """Validate that a port number is in the valid range 0-65535."""
    if not 0 <= port <= 65535:
        msg = f"Port {port} is out of valid range 0-65535"
        raise ValueError(msg)
    return port


class AllowPolicy:
    """Immutable policy object built from an allow list.

    Thread-safe to read from multiple threads after construction.
    """

    __slots__ = (
        "_allow_localhost",
        "_exact_hosts",
        "_exact_hosts_any_port",
        "_exact_hosts_with_port",
        "_host_rules",
        "_network_rules",
    )

    def __init__(self, allow: list[str], *, allow_localhost: bool = True) -> None:
        self._allow_localhost = allow_localhost

        host_rules: list[_HostRule] = []
        network_rules: list[_NetworkRule] = []

        for raw in allow:
            rule = raw.strip().lower()
            if not rule.isascii():
                rule = unicodedata.normalize("NFC", rule)
                rule = rule.translate(_FULLWIDTH_DOT_TABLE)

            # Reject empty/whitespace-only rules
            if not rule:
                msg = f"allow rule {raw!r} is empty or whitespace-only"
                raise ValueError(msg)

            # Reject URLs — a common mistake (should be hostname, not URL)
            if "://" in rule:
                msg = (
                    f"allow rule {raw!r} looks like a URL. "
                    f"Use a hostname pattern instead (e.g. 'api.stripe.com:443', "
                    f"not 'https://api.stripe.com:443')."
                )
                raise ValueError(msg)

            # Strip exactly one trailing dot from FQDNs (not IPs, not CIDRs)
            if rule.endswith(".") and not rule.endswith("/"):
                rule = rule[:-1]

            port: int | None = None

            # Handle bracketed IPv6: [::1]:443, [2001:db8::1], [2001:db8::]/32
            if rule.startswith("["):
                bracket_end = rule.find("]")
                if bracket_end != -1:
                    ipv6_part = rule[1:bracket_end]
                    remainder = rule[bracket_end + 1 :]
                    # CIDR suffix: [2001:db8::]/32 or [2001:db8::]/32:443
                    if remainder.startswith("/"):
                        cidr_and_rest = remainder[1:]
                        if ":" in cidr_and_rest:
                            cidr_str, port_str = cidr_and_rest.rsplit(":", 1)
                            if port_str.isascii() and port_str.isdigit():
                                port = _validate_port(int(port_str))
                            ipv6_part += "/" + cidr_str
                        else:
                            ipv6_part += "/" + cidr_and_rest
                    elif (
                        remainder.startswith(":")
                        and remainder[1:].isascii()
                        and remainder[1:].isdigit()
                    ):
                        port = _validate_port(int(remainder[1:]))
                    try:
                        network = ipaddress.ip_network(ipv6_part, strict=False)
                        network_rules.append(_NetworkRule(network=network, port=port))
                    except ValueError:
                        host_rules.append(_HostRule(pattern=ipv6_part, port=port))
                    continue

            if _has_port_suffix(rule):
                rule_part, port_str = rule.rsplit(":", 1)
                port = _validate_port(int(port_str))
                rule = rule_part

            # Try to parse as CIDR network or IP address
            try:
                network = ipaddress.ip_network(rule, strict=False)
                network_rules.append(_NetworkRule(network=network, port=port))
                continue
            except ValueError:
                pass

            # Reject overly broad wildcards — the host portion (without port)
            # must contain at least one literal character that isn't a wildcard
            # or dot. Patterns like *, *.*, *?*, ?* match all destinations.
            # Patterns with only ? (like ???.??) are allowed because ? matches
            # exactly one character — they are bounded, not open-ended.
            if "*" in rule:
                host_part_for_check = rule.split(":")[0] if ":" in rule else rule
                if all(c in "*?." for c in host_part_for_check):
                    msg = (
                        f"allow rule {raw!r} matches ALL destinations, "
                        f"which disables egress control entirely. "
                        f"Use specific hostname patterns instead "
                        f"(e.g. '*.stripe.com:443')."
                    )
                    raise ValueError(msg)

            # It's a hostname pattern
            host_rules.append(_HostRule(pattern=rule, port=port))

        # Split exact-match hostname rules from wildcard rules for O(1) lookup.
        exact_any_port: set[str] = set()
        exact_with_port: set[tuple[str, int]] = set()
        exact_hosts_with_port: set[str] = set()
        wildcard_rules: list[_HostRule] = []
        for rule_obj in host_rules:
            if "*" in rule_obj.pattern or "?" in rule_obj.pattern or "[" in rule_obj.pattern:
                wildcard_rules.append(rule_obj)
            elif rule_obj.port is None:
                exact_any_port.add(rule_obj.pattern)
            else:
                exact_with_port.add((rule_obj.pattern, rule_obj.port))
                exact_hosts_with_port.add(rule_obj.pattern)

        self._exact_hosts_any_port: frozenset[str] = frozenset(exact_any_port)
        self._exact_hosts: frozenset[tuple[str, int]] = frozenset(exact_with_port)
        self._exact_hosts_with_port: frozenset[str] = frozenset(exact_hosts_with_port)
        self._host_rules: tuple[_HostRule, ...] = tuple(wildcard_rules)
        self._network_rules: tuple[_NetworkRule, ...] = tuple(network_rules)

    def _has_any_port_rule(self, host: str) -> bool:
        """Check if a host has a port-unrestricted rule (exact or wildcard or CIDR)."""
        host_lower = _normalize_host(host)
        if host_lower in self._exact_hosts_any_port:
            return True
        for rule in self._host_rules:
            if rule.port is None and fnmatch.fnmatchcase(host_lower, rule.pattern):
                return True
        if _could_be_ip(host_lower):
            try:
                ip = ipaddress.ip_address(host_lower)
                for rule in self._network_rules:
                    if rule.port is None and ip in rule.network:
                        return True
            except ValueError:
                pass
        return False

    def is_allowed(self, host: str, port: int | None = None, *, _normalized: bool = False) -> bool:
        """Check if a host:port combination is allowed."""
        host_lower = host if _normalized else _normalize_host(host)

        if _has_invalid_hostname_chars(host_lower):
            return False

        if self._allow_localhost and _is_localhost(host_lower):
            return True

        if _could_be_ip(host_lower):
            try:
                ip = ipaddress.ip_address(host_lower)
                return self._check_ip(ip, port)
            except ValueError:
                pass

        return self._check_hostname(host_lower, port)

    def _check_hostname(self, hostname: str, port: int | None) -> bool:
        """Match hostname against host rules."""
        # O(1) exact-match check first
        if hostname in self._exact_hosts_any_port:
            return True
        if port is not None and (hostname, port) in self._exact_hosts:
            return True
        # Port rule with no port provided: allow (same as rule.port is not None and port is None)
        if port is None and hostname in self._exact_hosts_with_port:
            return True
        # Fall through to wildcard rules
        for rule in self._host_rules:
            if rule.port is not None and port is not None and rule.port != port:
                continue
            if fnmatch.fnmatchcase(hostname, rule.pattern):
                return True
        return False

    def _check_ip(
        self,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
        port: int | None,
    ) -> bool:
        """Match IP against network rules and literal IP host rules."""
        ipv4_mapped: ipaddress.IPv4Address | None = None
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ipv4_mapped = ip.ipv4_mapped

        # Check CIDR network rules (isinstance guard avoids cross-family TypeError)
        for rule in self._network_rules:
            if rule.port is not None and port is not None and rule.port != port:
                continue
            if isinstance(rule.network, ipaddress.IPv4Network):
                if isinstance(ip, ipaddress.IPv4Address) and ip in rule.network:
                    return True
                if ipv4_mapped is not None and ipv4_mapped in rule.network:
                    return True
            elif isinstance(ip, ipaddress.IPv6Address) and ip in rule.network:
                return True

        # Check wildcard host rules (e.g. "192.0.2.*")
        ip_str = str(ip)
        mapped_str = str(ipv4_mapped) if ipv4_mapped is not None else None
        for rule in self._host_rules:
            if rule.port is not None and port is not None and rule.port != port:
                continue
            if fnmatch.fnmatchcase(ip_str, rule.pattern):
                return True
            if mapped_str is not None and fnmatch.fnmatchcase(mapped_str, rule.pattern):
                return True

        return False

    def _check_wildcard_overlap(self, pattern: str, port: int | None) -> str:
        """Check how a wildcard scope rule overlaps with this policy.

        Returns:
            "none" — no connection can satisfy both (dead rule or disjoint ports).
            "partial" — some overlap but the scope is broader (on hostnames, port, or both).
            "full" — an identical rule exists in this policy (same pattern, same port).
        """

        def _ports_overlap(global_port: int | None) -> bool:
            if port is None or global_port is None:
                return True
            return port == global_port

        # Best result across all global rules: full > partial > none
        best = "none"

        # Check global wildcard rules — only identical pattern+port is "full"
        for rule in self._host_rules:
            if rule.pattern == pattern and rule.port == port:
                return "full"
            if rule.pattern == pattern and _ports_overlap(rule.port):
                best = "partial"

        # Check exact hostnames — a wildcard matching an exact host is always
        # "partial" at best because the wildcard covers more hosts
        for hostname in self._exact_hosts_any_port:
            if fnmatch.fnmatchcase(hostname, pattern) and _ports_overlap(None):
                best = "partial"
                break
        for hostname, rule_port in self._exact_hosts:
            if fnmatch.fnmatchcase(hostname, pattern) and _ports_overlap(rule_port):
                best = "partial"
                break

        # Check overlap with global wildcards via suffix heuristic
        if best == "none":
            for rule in self._host_rules:
                scope_suffix = pattern.lstrip("*?")
                rule_suffix = rule.pattern.lstrip("*?")
                if (
                    scope_suffix
                    and rule_suffix
                    and (scope_suffix.endswith(rule_suffix) or rule_suffix.endswith(scope_suffix))
                    and _ports_overlap(rule.port)
                ):
                    best = "partial"
                    break

        return best

    def _check_cidr_overlap(
        self,
        network: ipaddress.IPv4Network | ipaddress.IPv6Network,
        port: int | None,
    ) -> str:
        """Check how a CIDR scope rule overlaps with this policy.

        Returns:
            "none" — no network rule in this policy overlaps.
            "partial" — overlaps but the scope CIDR is broader.
            "full" — an identical or narrower CIDR exists in this policy.
        """
        best = "none"
        for rule in self._network_rules:
            if not network.overlaps(rule.network):
                continue
            # Networks overlap — check port compatibility
            if port is not None and rule.port is not None and port != rule.port:
                continue  # disjoint ports on this rule — try the next one
            ports_match = port == rule.port
            network_narrower = network.prefixlen >= rule.network.prefixlen
            if network_narrower and ports_match:
                return "full"
            best = "partial"
        return best


_FULLWIDTH_DOT_TABLE = str.maketrans(
    {
        "\uff0e": ".",  # Fullwidth full stop
        "\u3002": ".",  # Ideographic full stop
        "\uff61": ".",  # Halfwidth ideographic full stop
    }
)


def _normalize_host(host: str) -> str:
    """Normalize a hostname or IP for consistent matching."""
    h = host.lower().strip()
    # Fast path: skip Unicode normalization for pure-ASCII hostnames
    # (the vast majority in practice). isascii() is O(1) in CPython.
    if not h.isascii():
        # Unicode NFC normalization — ensures equivalent codepoint sequences
        # (e.g. "café" NFC vs NFD) compare equal.
        h = unicodedata.normalize("NFC", h)
        # Normalize fullwidth/ideographic dots to ASCII dots — some IDNA
        # implementations treat these as label separators.
        h = h.translate(_FULLWIDTH_DOT_TABLE)
    # Strip exactly one trailing dot from FQDNs (e.g. "api.stripe.com." -> "api.stripe.com")
    if h.endswith(".") and not _is_ip_like(h):
        h = h[:-1]
    # Strip IPv6 scope ID (e.g. "fe80::1%eth0" -> "fe80::1")
    # Only strip when host contains ":" (IPv6 indicator) to avoid
    # truncating non-IPv6 hostnames that happen to contain "%".
    if "%" in h and ":" in h:
        h = h.split("%")[0]
    return h


# Control chars (\x00-\x1f), space (\x20), and DEL (\x7f).
_INVALID_ASCII_HOST_RE = re.compile(r"[\x00-\x20\x7f]")


def _has_invalid_hostname_chars(host: str) -> bool:
    """Reject malformed hosts with control characters, whitespace, or invisible Unicode."""
    if host.isascii():
        return _INVALID_ASCII_HOST_RE.search(host) is not None
    for ch in host:
        if ch.isspace() or ord(ch) < 32 or ord(ch) == 127:
            return True
        if ord(ch) > 127 and unicodedata.category(ch) in ("Cf", "Cc", "Cs", "Co", "Cn"):
            return True
    return False


def _is_ip_like(host: str) -> bool:
    """Quick check if host looks like an IP (for normalize, not authoritative)."""
    stripped = host.rstrip(".")
    if not _could_be_ip(stripped):
        return False
    try:
        ipaddress.ip_address(stripped)
        return True
    except ValueError:
        return False


def _has_port_suffix(rule: str) -> bool:
    """Check if rule ends with :PORT (not part of IPv6 or CIDR)."""
    if ":" not in rule:
        return False
    last_colon = rule.rfind(":")
    after = rule[last_colon + 1 :]
    if not after.isascii() or not after.isdigit():
        return False
    before = rule[:last_colon]
    # Multiple colons means IPv6 -- no port suffix
    return ":" not in before


def _is_localhost(host: str) -> bool:
    """Check if host is a localhost/loopback address.

    Note: ``0.0.0.0`` and ``::`` (INADDR_ANY / IN6ADDR_ANY) are treated as
    localhost because ``connect()`` to these addresses reaches the local
    machine on Linux and Windows.  This is a deliberate convenience for the
    common bind-address case, but these are *not* true loopback addresses.
    """
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "::"):  # nosec B104
        return True
    if not _could_be_ip(host):
        return False
    # Fast reject for non-localhost IPv4: all loopback is 127.0.0.0/8 and the
    # only unspecified address is 0.0.0.0 (already in the set above).  IPv6
    # always contains ":" and bypasses this check.
    c = host[0]
    if c.isdigit() and ":" not in host and not (host.startswith("127.") or host.startswith("0.")):
        return False
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_unspecified:
            return True
        # IPv4-mapped IPv6 loopback/unspecified (::ffff:127.0.0.1, ::ffff:0.0.0.0)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return ip.ipv4_mapped.is_loopback or ip.ipv4_mapped.is_unspecified
        return False
    except ValueError:
        return False
