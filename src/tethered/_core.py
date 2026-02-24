"""Audit hook, state management, and public activate/deactivate API."""

from __future__ import annotations

import collections
import contextvars
import ipaddress
import logging
import socket
import sys
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from tethered._policy import AllowPolicy, _could_be_ip, _normalize_host

logger = logging.getLogger("tethered")

# Maximum number of IP -> hostname entries to retain.
_IP_MAP_MAX_SIZE = 4096


class EgressBlocked(RuntimeError):
    """Raised when a network connection is blocked by tethered policy."""

    def __init__(
        self,
        host: str,
        port: int | None,
        *,
        resolved_from: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.resolved_from = resolved_from

        msg = f"Blocked by tethered: {host}"
        if port is not None:
            msg += f":{port}"
        if resolved_from and resolved_from != host:
            msg += f" (resolved from {resolved_from})"
        msg += " is not in the allow list"
        super().__init__(msg)


class TetheredLocked(RuntimeError):
    """Raised when deactivate() is called in locked mode."""

    def __init__(self) -> None:
        super().__init__(
            "tethered: deactivate() blocked — policy is locked. "
            "Pass the same lock_token to deactivate() to unlock."
        )


# ── Immutable config bundle ───────────────────────────────────────
# All per-activation state is bundled into a single frozen object that is
# swapped atomically.  This eliminates the class of TOCTOU bugs where
# _policy, _log_only, and _on_blocked could be read at different times
# and see inconsistent state.  Safe on free-threaded Python (PEP 703).


@dataclass(frozen=True, slots=True)
class _Config:
    """Immutable configuration bundle swapped atomically on activate/deactivate."""

    policy: AllowPolicy
    log_only: bool = False
    fail_closed: bool = False
    on_blocked: Callable[[str, int | None], None] | None = field(default=None, repr=False)
    locked: bool = False
    lock_token: object | None = field(default=None, repr=False)


# ── Module-level state ──────────────────────────────────────────────
# The audit hook is installed once. activate()/deactivate() swap the config.

_state_lock = threading.Lock()
_config: _Config | None = None

# IP -> hostname mapping from intercepted getaddrinfo calls.
# OrderedDict for LRU eviction: move_to_end() on access, popitem(last=False) to evict.
_ip_to_hostname: collections.OrderedDict[str, str] = collections.OrderedDict()
_ip_map_lock = threading.Lock()

# Per-context reentrancy guard (faster than threading.local, async-safe)
_in_hook: contextvars.ContextVar[bool] = contextvars.ContextVar("tethered_in_hook", default=False)

# Hook installed flag
_hook_installed: bool = False

# Events that trigger connection enforcement
_CONNECT_EVENTS = frozenset(
    (
        "socket.connect",  # also raised by connect_ex() in CPython
        "socket.sendto",
        "socket.sendmsg",
    )
)

# DNS resolution events to intercept (gethostbyname family)
_DNS_EVENTS = frozenset(
    (
        "socket.gethostbyname",
        "socket.gethostbyaddr",
    )
)


def _is_ip(host: str) -> bool:
    """Check if a string is an IP address."""
    if not _could_be_ip(host):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _extract_host_port(address: Any) -> tuple[str, int | None] | None:
    """Extract (host, port) from a socket address.

    Returns None for address types we don't handle (AF_UNIX paths, etc.).

    Handles:
        AF_INET:  (host, port)
        AF_INET6: (host, port, flowinfo, scope_id)
    """
    if isinstance(address, tuple) and len(address) >= 2:
        host = address[0]
        port = address[1]
        if isinstance(host, str) and isinstance(port, int):
            return (host, port)
    return None


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    """The single audit hook installed by tethered."""
    cfg = _config
    if cfg is None:
        return

    # Fast exit for non-socket events (open, import, exec, compile, etc.)
    if event[:7] != "socket.":
        return

    if event == "socket.getaddrinfo":
        _handle_getaddrinfo(cfg, args)
    elif event in _CONNECT_EVENTS:
        _handle_connect(cfg, event, args)
    elif event in _DNS_EVENTS:
        _handle_dns_lookup(cfg, event, args)


def _handle_dns_lookup(cfg: _Config, event: str, args: tuple[Any, ...]) -> None:
    """Intercept gethostbyname/gethostbyaddr to enforce policy.

    These DNS resolution functions fire different audit events than getaddrinfo,
    so they must be intercepted separately to prevent DNS-based exfiltration.

    Audit event args for gethostbyname: (host,)
    Audit event args for gethostbyaddr: (host,)
    """
    host = args[0]
    if not isinstance(host, str) or not host:
        return

    if _is_ip(host):
        return

    host_lower = _normalize_host(host)

    try:
        allowed = cfg.policy.is_allowed(host_lower, _normalized=True)
    except Exception:
        if cfg.fail_closed:
            logger.error(
                "tethered: error checking policy for %s(%s), failing closed",
                event,
                host,
                exc_info=True,
            )
            raise EgressBlocked(host_lower, None) from None
        logger.warning(
            "tethered: error checking policy for %s(%s), failing open",
            event,
            host,
            exc_info=True,
        )
        return

    if not allowed:
        logger.warning("tethered: blocked %s for %s", event, host_lower)

        if cfg.on_blocked is not None:
            try:
                cfg.on_blocked(host_lower, None)
            except Exception:
                logger.debug(
                    "tethered: on_blocked callback raised for %s",
                    host_lower,
                    exc_info=True,
                )

        if not cfg.log_only:
            raise EgressBlocked(host_lower, None)


def _handle_getaddrinfo(cfg: _Config, args: tuple[Any, ...]) -> None:
    """Intercept getaddrinfo to enforce policy and build IP -> hostname mapping.

    Audit event args: (host, port, family, type, protocol)

    Two responsibilities:
    1. Block DNS resolution for disallowed hostnames (prevents DNS exfiltration).
    2. Resolve allowed hostnames and store IP -> hostname mappings for later
       use in _handle_connect.
    """
    host = args[0]
    if not isinstance(host, str) or not host:
        return

    if _is_ip(host):
        return

    # Reentrancy guard: our own resolution call triggers this hook again
    if _in_hook.get():
        return

    host_lower = _normalize_host(host)

    # Enforce policy at the DNS level
    try:
        allowed = cfg.policy.is_allowed(host_lower, _normalized=True)
    except Exception:
        if cfg.fail_closed:
            logger.error(
                "tethered: error checking policy for getaddrinfo(%s), failing closed",
                host,
                exc_info=True,
            )
            raise EgressBlocked(host_lower, None) from None
        logger.warning(
            "tethered: error checking policy for getaddrinfo(%s), failing open",
            host,
            exc_info=True,
        )
        return

    if not allowed:
        logger.warning("tethered: blocked getaddrinfo for %s", host_lower)

        if cfg.on_blocked is not None:
            try:
                cfg.on_blocked(host_lower, None)
            except Exception:
                logger.debug(
                    "tethered: on_blocked callback raised for %s",
                    host_lower,
                    exc_info=True,
                )

        if not cfg.log_only:
            raise EgressBlocked(host_lower, None)
        return

    # Resolve and store IP -> hostname mapping for allowed hosts.
    # This causes a second DNS resolution (the caller's original getaddrinfo
    # will also resolve). The duplicate is intentional: we need the results
    # now to populate the IP map before the subsequent connect() call.
    _token = _in_hook.set(True)
    try:
        results = socket.getaddrinfo(host, args[1])
        with _ip_map_lock:
            for _family, _socktype, _proto, _canonname, sockaddr in results:
                ip = str(sockaddr[0])  # always str; cast for pyright
                # LRU eviction: remove oldest entry when at capacity
                if len(_ip_to_hostname) >= _IP_MAP_MAX_SIZE:
                    _ip_to_hostname.popitem(last=False)
                _ip_to_hostname[ip] = host_lower
    except OSError:
        pass
    finally:
        _in_hook.reset(_token)


def _handle_connect(cfg: _Config, event: str, args: tuple[Any, ...]) -> None:
    """Enforce allow policy on connect/connect_ex/sendto/sendmsg.

    Audit event args: (socket_obj, address)
    """
    if _in_hook.get():
        return

    address = args[1]
    parsed = _extract_host_port(address)
    if parsed is None:
        # AF_UNIX or unparseable -- allow
        return

    host, port = parsed

    # Look up original hostname if this is an IP
    resolved_from: str | None = None
    check_host = _normalize_host(host)

    if _is_ip(host):
        with _ip_map_lock:
            resolved_from = _ip_to_hostname.get(host)
            # LRU: move to end on access so recently-used entries survive eviction
            if resolved_from is not None:
                _ip_to_hostname.move_to_end(host)
        if resolved_from is not None:
            check_host = resolved_from

    try:
        allowed = cfg.policy.is_allowed(check_host, port, _normalized=True)
        # If hostname didn't match but we have the raw IP, try that too
        if not allowed and resolved_from is not None:
            allowed = cfg.policy.is_allowed(host, port, _normalized=True)
    except Exception:
        if cfg.fail_closed:
            logger.error(
                "tethered: error checking policy for %s:%s, failing closed",
                host,
                port,
                exc_info=True,
            )
            raise EgressBlocked(host, port, resolved_from=resolved_from) from None
        # Fail-open: a bug in tethered should not break the host app
        logger.warning(
            "tethered: error checking policy for %s:%s, failing open",
            host,
            port,
            exc_info=True,
        )
        return

    if not allowed:
        display = resolved_from if resolved_from and resolved_from != host else host
        logger.warning(
            "tethered: blocked %s to %s:%s%s",
            event.split(".")[-1],
            display,
            port,
            f" (IP: {host})" if resolved_from and resolved_from != host else "",
        )

        if cfg.on_blocked is not None:
            try:
                cfg.on_blocked(check_host, port)
            except Exception:
                logger.debug(
                    "tethered: on_blocked callback raised for %s:%s",
                    check_host,
                    port,
                    exc_info=True,
                )

        if not cfg.log_only:
            raise EgressBlocked(host, port, resolved_from=resolved_from)


def _install_hook() -> None:
    """Install the audit hook exactly once."""
    global _hook_installed
    with _state_lock:
        if _hook_installed:
            return
        sys.addaudithook(_audit_hook)
        _hook_installed = True


def activate(
    *,
    allow: list[str],
    log_only: bool = False,
    fail_closed: bool = False,
    allow_localhost: bool = True,
    on_blocked: Callable[[str, int | None], None] | None = None,
    locked: bool = False,
    lock_token: object | None = None,
) -> None:
    """Activate tethered egress control.

    Args:
        allow: List of allowed destinations. Supports:
            - Exact hostnames: ``"api.stripe.com"``
            - Wildcard subdomains: ``"*.stripe.com"``
            - Hostname with port: ``"api.stripe.com:443"``
            - IP addresses: ``"1.2.3.4"``
            - CIDR ranges: ``"10.0.0.0/8"``
        log_only: If True, log blocked connections but don't raise.
        fail_closed: If True, block connections when the policy check itself
            raises an unexpected error (instead of the default fail-open).
        allow_localhost: If True (default), always allow loopback addresses.
        on_blocked: Optional callback ``(host, port) -> None`` invoked on
            blocked connections. Called even in log_only mode.
        locked: If True, ``deactivate()`` will refuse to disable enforcement
            unless the correct ``lock_token`` is provided. Prevents
            in-process adversaries from trivially disabling tethered.
        lock_token: An opaque object that must be passed to ``deactivate()``
            to unlock a locked policy. Only meaningful when ``locked=True``.
    """
    global _config

    policy = AllowPolicy(allow, allow_localhost=allow_localhost)
    cfg = _Config(
        policy=policy,
        log_only=log_only,
        fail_closed=fail_closed,
        on_blocked=on_blocked,
        locked=locked,
        lock_token=lock_token,
    )

    with _state_lock:
        _config = cfg

    with _ip_map_lock:
        _ip_to_hostname.clear()

    _install_hook()
    logger.info("tethered: activated with %d rules (log_only=%s)", len(allow), log_only)


def deactivate(*, lock_token: object | None = None) -> None:
    """Deactivate tethered egress control.

    The audit hook remains installed (cannot be removed) but becomes a no-op.

    Args:
        lock_token: If the policy was activated with ``locked=True``, the
            same ``lock_token`` must be provided here. Otherwise
            ``TetheredLocked`` is raised.
    """
    global _config

    with _state_lock:
        cfg = _config
        if (
            cfg is not None
            and cfg.locked
            and (lock_token is None or lock_token is not cfg.lock_token)
        ):
            raise TetheredLocked
        _config = None

    with _ip_map_lock:
        _ip_to_hostname.clear()

    logger.info("tethered: deactivated")


def _reset_state() -> None:
    """Reset all internal state. For testing only."""
    global _config

    with _state_lock:
        _config = None

    with _ip_map_lock:
        _ip_to_hostname.clear()
