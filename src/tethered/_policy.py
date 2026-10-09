"""Pattern parsing and matching for tethered allow rules."""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
import unicodedata
from typing import NamedTuple

logger = logging.getLogger("tethered")

# Rules are tuples of primitives so that a policy is immutable all the way
# down.  The locked-mode guardian verifies the *identity* of each AllowPolicy
# slot, which says nothing about objects reachable through it: a frozen
# dataclass can still be rewritten with ``object.__setattr__``, and so can the
# attributes of an ``ipaddress`` network.  A tuple of ints and strings cannot.


class _HostRule(NamedTuple):
    """A parsed allow rule for hostname matching."""

    pattern: str  # lowercase, e.g. "*.stripe.com" or "api.example.com"
    port: int | None  # None means any port


class _NetworkRule(NamedTuple):
    """A parsed allow rule for CIDR matching, held as integers."""

    version: int  # 4 or 6
    net: int  # network address
    mask: int  # netmask
    prefixlen: int
    port: int | None  # None means any port

    @classmethod
    def from_network(
        cls,
        network: ipaddress.IPv4Network | ipaddress.IPv6Network,
        port: int | None,
    ) -> _NetworkRule:
        return cls(
            network.version,
            int(network.network_address),
            int(network.netmask),
            network.prefixlen,
            port,
        )

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        """The network as an ``ipaddress`` object, rebuilt on every access.

        For serialization, tests and the scope-overlap check of a scope's own
        range rule — matching works on the integer fields and never comes
        through here.
        """
        if self.version == 4:
            return ipaddress.IPv4Network((self.net, self.prefixlen))
        return ipaddress.IPv6Network((self.net, self.prefixlen))


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

    Every slot holds a ``bool``, ``frozenset`` or ``tuple`` whose contents
    are strings, integers and tuples of those — nothing with an attribute
    that could be reassigned after the fact.
    """

    __slots__ = (
        "_allow_localhost",
        "_exact_hosts",
        "_exact_hosts_any_port",
        "_exact_hosts_with_port",
        "_host_rule_fields",
        "_host_rules",
        "_network_rule_fields",
        "_network_rules",
        "_parsed_rules",
    )

    def __init__(self, allow: list[str], *, allow_localhost: bool = True) -> None:
        self._allow_localhost = allow_localhost

        # One parsed rule per allow-list entry, in the order given.
        parsed_rules: list[_HostRule | _NetworkRule] = []

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

            port: int | None = None

            # Bracketed IP: [::1], [2001:db8::1]:443, [2001:db8::]/32[:443].
            # Brackets that do not hold an IP address are an fnmatch character
            # set ("[ab].example.com:443") and take the hostname path below.
            if rule.startswith("["):
                bracketed = _parse_bracketed_ip(rule, raw)
                if bracketed is not None:
                    parsed_rules.append(_NetworkRule.from_network(*bracketed))
                    continue

            if _has_port_suffix(rule):
                rule_part, port_str = rule.rsplit(":", 1)
                port = _validate_port(int(port_str))
                rule = rule_part

            # Strip exactly one trailing dot (FQDN form) from the host part.
            # This runs after the port split so that "api.example.com.:443"
            # normalizes the same way "api.example.com." does.  The rstrip
            # keeps the result free of outer whitespace, like the initial
            # strip() does, so a serialized rule re-parses unchanged.
            if rule.endswith("."):
                rule = rule[:-1].rstrip()

            if not rule:
                msg = f"allow rule {raw!r} has no host. Use 'HOST' or 'HOST:PORT'."
                raise ValueError(msg)

            # Try to parse as CIDR network or IP address
            try:
                network = ipaddress.ip_network(rule, strict=False)
                parsed_rules.append(_NetworkRule.from_network(network, port))
                continue
            except ValueError:
                pass

            # A hostname never contains ":".  What is left here is a malformed
            # port ("host:abc", "host:-1", "host:"), a mistyped IPv6 address
            # or CIDR, or a wildcard over the *text* of IPv6 addresses.  The
            # first two would be rules that can never match; the last one
            # depends on how str() formats an address and is what CIDR rules
            # are for.  Reject them all instead of keeping such a rule.
            if ":" in rule:
                msg = (
                    f"allow rule {raw!r} is not a valid HOST:PORT rule, IP address or "
                    f"CIDR range. A port must be a number in the range 0-65535 "
                    f"(e.g. 'api.stripe.com:443'). Write an IPv6 address with a port or "
                    f"prefix as '[ADDR]:PORT', '[ADDR]/PREFIX' or '[ADDR]/PREFIX:PORT' "
                    f"(e.g. '[2001:db8::1]:443'), and an IPv6 range in CIDR notation "
                    f"(e.g. '2001:db8::/32')."
                )
                raise ValueError(msg)

            # An fnmatch character set ("[seq]", "[!seq]") matches like a
            # wildcard, so stand "?" in for each one when judging what the
            # pattern is made of.
            shape = _CHAR_SET_RE.sub("?", rule) if "[" in rule else rule

            # Reject overly broad wildcards — the host portion (without port)
            # must contain at least one literal character that isn't a wildcard
            # or dot. Patterns like *, *.*, *?*, ?*, *[!/] match all destinations.
            # Patterns with only ? or character sets (like ???.??) are allowed
            # because each matches exactly one character — they are bounded,
            # not open-ended.
            if "*" in shape and all(c in "*?." for c in shape):
                msg = (
                    f"allow rule {raw!r} matches ALL destinations, "
                    f"which disables egress control entirely. "
                    f"Use specific hostname patterns instead "
                    f"(e.g. '*.stripe.com:443')."
                )
                raise ValueError(msg)

            # An address-shaped wildcard ("10.*", "192.0.2.*") is still an
            # fnmatch pattern over text: it also allows "10.attacker.example".
            if ("*" in shape or "?" in shape) and _ADDRESS_SHAPED_RE.fullmatch(shape):
                _warn_address_shaped_wildcard(raw)

            # It's a hostname pattern
            parsed_rules.append(_HostRule(pattern=rule, port=port))

        # Split exact-match hostname rules from wildcard rules for O(1) lookup.
        exact_any_port: set[str] = set()
        exact_with_port: set[tuple[str, int]] = set()
        exact_hosts_with_port: set[str] = set()
        wildcard_rules: list[_HostRule] = []
        network_rules: list[_NetworkRule] = []
        for rule_obj in parsed_rules:
            if isinstance(rule_obj, _NetworkRule):
                network_rules.append(rule_obj)
                continue
            pattern, rule_port = rule_obj
            if _is_wildcard_pattern(pattern):
                wildcard_rules.append(rule_obj)
            elif rule_port is None:
                exact_any_port.add(pattern)
            else:
                exact_with_port.add((pattern, rule_port))
                exact_hosts_with_port.add(pattern)

        self._exact_hosts_any_port: frozenset[str] = frozenset(exact_any_port)
        self._exact_hosts: frozenset[tuple[str, int]] = frozenset(exact_with_port)
        self._exact_hosts_with_port: frozenset[str] = frozenset(exact_hosts_with_port)
        self._host_rules: tuple[_HostRule, ...] = tuple(wildcard_rules)
        self._network_rules: tuple[_NetworkRule, ...] = tuple(network_rules)
        # Every rule again, as parsed and in allow-list order.  Matching never
        # reads this: it lets the scope-overlap check pair each rule with the
        # text the user wrote without parsing that text a second time.
        self._parsed_rules: tuple[_HostRule | _NetworkRule, ...] = tuple(parsed_rules)
        # Plain-tuple copies of the rule fields, which is what the matching
        # methods read.  Unpacking an exact tuple looks nothing up on the rule
        # classes, so whatever is patched onto _HostRule or _NetworkRule (a
        # field, ``network``, ``__iter__``) cannot change a decision.  CPython
        # also unpacks exact tuples faster than instances of a tuple subclass.
        self._host_rule_fields: tuple[tuple[str, int | None], ...] = tuple(
            (r.pattern, r.port) for r in wildcard_rules
        )
        self._network_rule_fields: tuple[tuple[int, int, int, int | None], ...] = tuple(
            (r.version, r.net, r.mask, r.port) for r in network_rules
        )

    def _has_any_port_rule(self, host: str, *, _normalized: bool = False) -> bool:
        """Check if a host has a port-unrestricted rule (exact or wildcard or CIDR)."""
        host_lower = host if _normalized else _normalize_host(host)
        if host_lower in self._exact_hosts_any_port:
            return True
        for pattern, rule_port in self._host_rule_fields:
            if rule_port is None and fnmatch.fnmatchcase(host_lower, pattern):
                return True
        if _could_be_ip(host_lower):
            try:
                ip = ipaddress.ip_address(host_lower)
                ip_version = ip.version
                ip_int = int(ip)
                for version, net, mask, rule_port in self._network_rule_fields:
                    if rule_port is None and version == ip_version and ip_int & mask == net:
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
        for pattern, rule_port in self._host_rule_fields:
            if rule_port is not None and port is not None and rule_port != port:
                continue
            if fnmatch.fnmatchcase(hostname, pattern):
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

        # Check CIDR network rules.  An address is inside a network of its own
        # family when its masked integer equals the network address — the test
        # ``ipaddress`` itself applies.  An IPv4-mapped IPv6 address is checked
        # against IPv4 networks as well, through the IPv4 address it embeds.
        ip_version = ip.version
        ip_int = int(ip)
        mapped_int = int(ipv4_mapped) if ipv4_mapped is not None else None
        for version, net, mask, rule_port in self._network_rule_fields:
            if rule_port is not None and port is not None and rule_port != port:
                continue
            if version == ip_version:
                if ip_int & mask == net:
                    return True
            elif mapped_int is not None and mapped_int & mask == net:
                return True

        # Check wildcard host rules (e.g. "192.0.2.*")
        ip_str = str(ip)
        mapped_str = str(ipv4_mapped) if ipv4_mapped is not None else None
        for pattern, rule_port in self._host_rule_fields:
            if rule_port is not None and port is not None and rule_port != port:
                continue
            if fnmatch.fnmatchcase(ip_str, pattern):
                return True
            if mapped_str is not None and fnmatch.fnmatchcase(mapped_str, pattern):
                return True

        return False

    def _check_rule_overlap(self, rule: _HostRule | _NetworkRule) -> str:
        """Check how one rule of a scope overlaps with this policy.

        ``rule`` is an entry of the scope policy's ``_parsed_rules``, so it is
        judged as ``AllowPolicy`` parsed it — the rule text is not read again.

        Returns:
            "none" — no connection can satisfy both the rule and this policy.
            "partial" — some overlap, but the rule is broader than this policy.
            "full" — this policy allows everything the rule allows.
        """
        if isinstance(rule, _NetworkRule):
            version, net, mask, prefixlen, port = rule
            # A network rule of this policy that contains the scope rule's
            # network, on that rule's port or on any port, covers it.
            for rule_version, rule_net, rule_mask, rule_port in self._network_rule_fields:
                if (
                    rule_version == version
                    and rule_mask <= mask
                    and net & rule_mask == rule_net
                    and (rule_port is None or rule_port == port)
                ):
                    return "full"
            if prefixlen < (32 if version == 4 else 128):
                # A range that no single rule covers: partial or no overlap.
                return self._check_cidr_overlap(rule.network, port)
            # A single address is one destination, like an exact hostname.  A
            # wildcard over address text ("192.0.2.*"), the localhost allowance
            # or the IPv4 address inside an IPv4-mapped one can still allow it.
            host = str(ipaddress.IPv4Address(net) if version == 4 else ipaddress.IPv6Address(net))
        else:
            host, port = rule
            if host in self._exact_hosts_any_port or (host, port) in self._exact_hosts:
                return "full"  # an exact host listed as it is, on that port or on any port
            if _is_wildcard_pattern(host):
                return self._check_wildcard_overlap(host, port)

        # One destination, in the normalized form that matching compares.
        if port is not None:
            return "full" if self.is_allowed(host, port, _normalized=True) else "none"
        if self._has_any_port_rule(host, _normalized=True) or (
            self._allow_localhost and _is_localhost(host)
        ):
            return "full"
        # Allowed without a port but by no any-port rule: on some ports only.
        return "partial" if self.is_allowed(host, _normalized=True) else "none"

    def _check_wildcard_overlap(self, pattern: str, port: int | None) -> str:
        """Check how a wildcard scope rule overlaps with this policy.

        Returns:
            "none" — no connection can satisfy both (dead rule or disjoint ports).
            "partial" — some overlap but the scope is broader (on hostnames, port, or both).
            "full" — a wildcard rule of this policy is sure to cover the scope rule:
                the same pattern, or "*" + text that the scope pattern ends with,
                on the same port or on any port.
        """

        def _ports_overlap(global_port: int | None) -> bool:
            if port is None or global_port is None:
                return True
            return port == global_port

        # Best result across all global rules: full > partial > none
        best = "none"

        # Check global wildcard rules for one that matches every hostname of
        # the scope rule: the same pattern, or "*" + text that the scope
        # pattern ends with.  That is "full" on the scope rule's port or on
        # any port, and "partial" when only the scope rule is open to all ports
        for rule_pattern, rule_port in self._host_rule_fields:
            if rule_pattern == pattern or (
                pattern.endswith(rule_pattern[1:]) and _is_suffix_wildcard(rule_pattern)
            ):
                if rule_port is None or rule_port == port:
                    return "full"
                if _ports_overlap(rule_port):
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
        version = network.version
        net = int(network.network_address)
        mask = int(network.netmask)
        for rule in self._network_rules:
            # Two CIDR blocks of one family overlap exactly when they agree on
            # every bit of the shorter prefix — the bits both netmasks keep.
            # (Integers again: rebuilding rule.network for every rule on every
            # scope() would cost far more than this comparison.)
            if rule.version != version or (net ^ rule.net) & mask & rule.mask:
                continue
            # Networks overlap — check port compatibility
            if port is not None and rule.port is not None and port != rule.port:
                continue  # disjoint ports on this rule — try the next one
            ports_match = port == rule.port
            network_narrower = network.prefixlen >= rule.prefixlen
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
        # Re-strip: the dot can hide whitespace the initial strip() could not
        # reach ("host\r." -> "host\r").
        h = h[:-1].rstrip()
    # Strip IPv6 scope ID (e.g. "fe80::1%eth0" -> "fe80::1")
    # Only strip when host contains ":" (IPv6 indicator) to avoid
    # truncating non-IPv6 hostnames that happen to contain "%".
    if "%" in h and ":" in h:
        # Re-strip: splitting on the scope-ID separator can leave trailing
        # whitespace that the initial strip() (run before the split) missed.
        h = h.split("%")[0].strip()
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


def _is_wildcard_pattern(pattern: str) -> bool:
    """Return True for a hostname pattern that ``fnmatch`` has to match.

    "*", "?" or a character set ("[seq]"); anything else is an exact hostname
    and is looked up in a set.
    """
    return "*" in pattern or "?" in pattern or "[" in pattern


def _is_suffix_wildcard(pattern: str) -> bool:
    """Return True for "*" followed by literal text, such as "*.example.com".

    Such a pattern matches exactly the hostnames that end with the text, and
    with them every hostname of a pattern that ends with the text itself: the
    text holds no "[" or "]", so there it cannot be the inside of a character
    set and is literal too.
    """
    text = pattern[1:]
    return pattern.startswith("*") and not _is_wildcard_pattern(text) and "]" not in text


# An fnmatch character set: "[seq]" or "[!seq]", where a "]" directly after
# the opening bracket (or after "!") is a member rather than the end.  For
# malformed input ("[]", "[!]") this errs toward calling literal text a set,
# which only makes the checks built on it stricter.
_CHAR_SET_RE = re.compile(r"\[!?\]?[^\]]*\]")

# A wildcard pattern (character sets already replaced by "?") made only of
# digits, dots and wildcards — it reads like an IP address range.
_ADDRESS_SHAPED_RE = re.compile(r"[.*?]*[0-9][0-9.*?]*")

# Address-shaped wildcard rules already warned about.  ``scope()`` builds an
# ``AllowPolicy`` on every use, so each distinct rule is reported once per
# process; the cap bounds the set when rule strings are generated dynamically.
_ADDRESS_WILDCARD_WARNED: set[str] = set()
_ADDRESS_WILDCARD_WARNED_MAX = 256


def _warn_address_shaped_wildcard(raw: str) -> None:
    """Warn, once per rule string, that an address-shaped wildcard is not a range."""
    if raw in _ADDRESS_WILDCARD_WARNED:
        return
    if len(_ADDRESS_WILDCARD_WARNED) >= _ADDRESS_WILDCARD_WARNED_MAX:
        return
    _ADDRESS_WILDCARD_WARNED.add(raw)
    logger.warning(
        "tethered: allow rule %r looks like an IP address range but is a wildcard "
        "pattern matched as text — it also allows every hostname that fits the "
        "pattern (the way '10.*' allows '10.attacker.example'). Use CIDR notation "
        "(e.g. '10.0.0.0/8') to allow an address range.",
        raw,
    )


def _parse_bracketed_ip(
    rule: str, raw: str
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, int | None] | None:
    """Parse ``[ADDR]``, ``[ADDR]:PORT``, ``[ADDR]/PREFIX`` or ``[ADDR]/PREFIX:PORT``.

    Returns ``None`` when the text inside the brackets is not an IP address:
    the rule is then an ordinary hostname pattern that starts with an
    ``fnmatch`` character set.  Once the brackets do hold an IP address the
    whole rule has to be well-formed — trailing text and malformed ports
    raise ``ValueError`` instead of being dropped, because dropping a port
    silently widens the rule to every port.
    """
    bracket_end = rule.find("]")
    if bracket_end == -1:
        return None
    addr = rule[1:bracket_end]
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        return None

    # What follows the bracket is "", "/PREFIX", ":PORT" or "/PREFIX:PORT".
    remainder = rule[bracket_end + 1 :]
    prefix, colon, port_str = remainder.partition(":")
    if prefix and not prefix.startswith("/"):
        msg = (
            f"allow rule {raw!r} has unexpected text {remainder!r} after ']'. "
            f"Use '[ADDR]', '[ADDR]:PORT', '[ADDR]/PREFIX' or '[ADDR]/PREFIX:PORT' "
            f"(e.g. '[2001:db8::1]:443')."
        )
        raise ValueError(msg)

    port: int | None = None
    if colon:
        if not (port_str.isascii() and port_str.isdigit()):
            msg = (
                f"allow rule {raw!r} has an invalid port {port_str!r}. "
                f"A port must be a number in the range 0-65535 (e.g. '[2001:db8::1]:443')."
            )
            raise ValueError(msg)
        port = _validate_port(int(port_str))

    try:
        network = ipaddress.ip_network(addr + prefix, strict=False)
    except ValueError:
        msg = (
            f"allow rule {raw!r} has an invalid network prefix {prefix[1:]!r} "
            f"(e.g. '[2001:db8::]/32')."
        )
        raise ValueError(msg) from None
    return network, port


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
