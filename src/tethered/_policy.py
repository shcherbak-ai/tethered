"""Pattern parsing and matching for tethered allow rules."""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
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

    IPv4 starts with a digit, IPv6 with a hex digit (0-9, a-f) or ``:``.
    A leading non-hex letter rules it out immediately.
    """
    if not host:
        return False
    c = host[0]
    return not c.isalpha() or c in "abcdefABCDEF"


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
        "_host_rules",
        "_network_rules",
    )

    def __init__(self, allow: list[str], *, allow_localhost: bool = True) -> None:
        self._allow_localhost = allow_localhost

        host_rules: list[_HostRule] = []
        network_rules: list[_NetworkRule] = []

        for raw in allow:
            rule = raw.strip().lower()

            # Warn on empty/whitespace-only rules
            if not rule:
                logger.warning("tethered: ignoring empty allow rule: %r", raw)
                continue

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
                            if port_str.isdigit():
                                port = _validate_port(int(port_str))
                            ipv6_part += "/" + cidr_str
                        else:
                            ipv6_part += "/" + cidr_and_rest
                    elif remainder.startswith(":") and remainder[1:].isdigit():
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

            # Warn on overly-broad patterns
            if rule == "*":
                logger.warning("tethered: rule %r matches ALL destinations — intended?", raw)

            # It's a hostname pattern
            host_rules.append(_HostRule(pattern=rule, port=port))

        # Split exact-match hostname rules from wildcard rules for O(1) lookup.
        exact_any_port: set[str] = set()
        exact_with_port: set[tuple[str, int]] = set()
        wildcard_rules: list[_HostRule] = []
        for rule_obj in host_rules:
            if "*" in rule_obj.pattern or "?" in rule_obj.pattern or "[" in rule_obj.pattern:
                wildcard_rules.append(rule_obj)
            elif rule_obj.port is None:
                exact_any_port.add(rule_obj.pattern)
            else:
                exact_with_port.add((rule_obj.pattern, rule_obj.port))

        self._exact_hosts_any_port: frozenset[str] = frozenset(exact_any_port)
        self._exact_hosts: frozenset[tuple[str, int]] = frozenset(exact_with_port)
        self._host_rules: tuple[_HostRule, ...] = tuple(wildcard_rules)
        self._network_rules: tuple[_NetworkRule, ...] = tuple(network_rules)

    def is_allowed(self, host: str, port: int | None = None, *, _normalized: bool = False) -> bool:
        """Check if a host:port combination is allowed."""
        host_lower = host if _normalized else _normalize_host(host)

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
        if port is None and self._exact_hosts:
            for h, _p in self._exact_hosts:
                if h == hostname:
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


def _normalize_host(host: str) -> str:
    """Normalize a hostname or IP for consistent matching."""
    h = host.lower().strip()
    # Strip exactly one trailing dot from FQDNs (e.g. "api.stripe.com." -> "api.stripe.com")
    if h.endswith(".") and not _is_ip_like(h):
        h = h[:-1]
    # Strip IPv6 scope ID (e.g. "fe80::1%eth0" -> "fe80::1")
    if "%" in h:
        h = h.split("%")[0]
    return h


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
    if not after.isdigit():
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
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return True
        # IPv4-mapped IPv6 loopback (::ffff:127.0.0.1)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return ip.ipv4_mapped.is_loopback
        return False
    except ValueError:
        return False
