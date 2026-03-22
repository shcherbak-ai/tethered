"""Audit hook, state management, and public activate/deactivate/scope API."""

from __future__ import annotations

import _socket as _csocket  # C-level socket; immune to gevent/eventlet monkey-patching
import collections
import contextvars
import functools
import inspect
import ipaddress
import logging
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


@dataclass(frozen=True, slots=True)
class _ScopeConfig:
    """Immutable configuration for a single scope() context."""

    policy: AllowPolicy
    log_only: bool = False
    fail_closed: bool = False
    on_blocked: Callable[[str, int | None], None] | None = field(default=None, repr=False)
    label: str = ""


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

# Per-context scope stack (tuple for immutability; typical depth 0-3)
_scopes: contextvars.ContextVar[tuple[_ScopeConfig, ...]] = contextvars.ContextVar(
    "tethered_scopes", default=()
)


def _validate_allow(allow: object) -> None:
    """Validate the ``allow`` parameter for activate() and scope()."""
    if not isinstance(allow, list):
        msg = f"allow must be a list of strings, got {type(allow).__name__}"
        raise TypeError(msg)
    for i, item in enumerate(allow):
        if not isinstance(item, str):
            msg = f"allow[{i}] must be a string, got {type(item).__name__}: {item!r}"
            raise TypeError(msg)


def _validate_callback(on_blocked: object, param_name: str = "on_blocked") -> None:
    """Validate that a callback parameter is callable or None."""
    if on_blocked is not None and not callable(on_blocked):
        msg = f"{param_name} must be callable or None, got {type(on_blocked).__name__}"
        raise TypeError(msg)


def _validate_bool(value: object, param_name: str) -> None:
    """Validate that a parameter is strictly bool, not a truthy/falsy stand-in."""
    if not isinstance(value, bool):
        msg = f"{param_name} must be a bool, got {type(value).__name__}: {value!r}"
        raise TypeError(msg)


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

# DNS resolution events to intercept outside getaddrinfo
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
    # Fast exit for non-socket events (open, import, exec, compile, etc.)
    # Check this FIRST to avoid ContextVar lookup on the vast majority of
    # audit events (imports, file opens, compile, exec, …).
    if not event.startswith("socket."):
        return

    cfg = _config
    scope_stack = _scopes.get()

    if cfg is None and not scope_stack:
        return

    if event == "socket.getaddrinfo":
        _handle_getaddrinfo(cfg, scope_stack, args)
    elif event in _CONNECT_EVENTS:
        _handle_connect(cfg, scope_stack, event, args)
    elif event in _DNS_EVENTS:
        _handle_dns_lookup(cfg, scope_stack, event, args)


def _check_scopes(
    scope_stack: tuple[_ScopeConfig, ...],
    host: str,
    port: int | None,
    *,
    _normalized: bool = False,
) -> _ScopeConfig | None:
    """Check host:port against all active scopes.

    Returns the first _ScopeConfig that blocks, or None if all allow.
    """
    for sc in scope_stack:
        try:
            if not sc.policy.is_allowed(host, port, _normalized=_normalized):
                return sc
        except Exception:
            if sc.fail_closed:
                return sc
            logger.warning(
                "tethered: error checking %s for %s:%s, failing open",
                sc.label,
                host,
                port,
                exc_info=True,
            )
    return None


def _enforce_scope_block(
    sc: _ScopeConfig,
    host: str,
    port: int | None,
    event_desc: str,
    *,
    global_allowed: bool = False,
    resolved_from: str | None = None,
) -> None:
    """Log and optionally raise for a scope-level block."""
    extra = " (allowed by global policy)" if global_allowed else ""
    logger.warning("tethered: %s blocked %s for %s%s", sc.label, event_desc, host, extra)

    if sc.on_blocked is not None:
        try:
            sc.on_blocked(host, port)
        except Exception:
            logger.debug(
                "tethered: on_blocked callback raised for %s:%s",
                host,
                port,
                exc_info=True,
            )

    if not sc.log_only:
        raise EgressBlocked(host, port, resolved_from=resolved_from)


def _handle_dns_lookup(
    cfg: _Config | None,
    scope_stack: tuple[_ScopeConfig, ...],
    event: str,
    args: tuple[Any, ...],
) -> None:
    """Intercept gethostbyname/gethostbyaddr to enforce policy.

    These DNS resolution functions fire different audit events than getaddrinfo,
    so they must be intercepted separately to prevent DNS-based exfiltration.

    Audit event args for gethostbyname: (host,)
    Audit event args for gethostbyaddr: (host,)
    """
    host = args[0]
    if not isinstance(host, str) or not host:
        return

    host_lower = _normalize_host(host)

    if event != "socket.gethostbyaddr" and _is_ip(host_lower):
        return

    # ── Global policy check ──
    global_allowed = True
    if cfg is not None:
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
            allowed = True  # fail-open: treat as allowed, continue to scope checks

        if not allowed:
            global_allowed = False
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

    # ── Scope checks ──
    blocking_scope = _check_scopes(scope_stack, host_lower, None, _normalized=True)
    if blocking_scope is not None:
        _enforce_scope_block(
            blocking_scope,
            host_lower,
            None,
            event,
            global_allowed=global_allowed,
        )


def _handle_getaddrinfo(
    cfg: _Config | None,
    scope_stack: tuple[_ScopeConfig, ...],
    args: tuple[Any, ...],
) -> None:
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

    # ── Global policy check ──
    global_allowed = True
    if cfg is not None:
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
            allowed = True  # fail-open: treat as allowed, continue to scope checks

        if not allowed:
            global_allowed = False
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

    # ── Scope checks (before IP map population) ──
    blocking_scope = _check_scopes(scope_stack, host_lower, None, _normalized=True)
    if blocking_scope is not None:
        _enforce_scope_block(
            blocking_scope,
            host_lower,
            None,
            "getaddrinfo",
            global_allowed=global_allowed,
        )
        # If _enforce_scope_block raised (log_only=False), we never reach here.
        # For log_only scopes, fall through to populate the IP map — without it,
        # connect-time enforcement can't map the resolved IP back to this hostname,
        # causing the *global* policy to hard-block a connection that the scope
        # only intended to log.

    # Resolve and store IP -> hostname mapping for allowed hosts.
    # Uses _csocket (CPython's C-level _socket module) instead of socket to
    # avoid gevent/eventlet monkey-patched getaddrinfo, which spawns real OS
    # threads for DNS and can cause thread/memory explosion under load.
    _token = _in_hook.set(True)
    try:
        port = args[1] if len(args) >= 2 else None
        family = args[2] if len(args) >= 3 and isinstance(args[2], int) else 0
        socktype = args[3] if len(args) >= 4 and isinstance(args[3], int) else 0
        proto = args[4] if len(args) >= 5 and isinstance(args[4], int) else 0
        flags = args[5] if len(args) >= 6 and isinstance(args[5], int) else 0
        results = _csocket.getaddrinfo(host, port, family, socktype, proto, flags)
        with _ip_map_lock:
            for _family, _socktype, _proto, _canonname, sockaddr in results:
                ip = str(sockaddr[0])  # always str; cast for pyright
                if ip in _ip_to_hostname:
                    _ip_to_hostname[ip] = host_lower
                    _ip_to_hostname.move_to_end(ip)
                    continue
                # LRU eviction: remove oldest entry when at capacity
                if len(_ip_to_hostname) >= _IP_MAP_MAX_SIZE:
                    _ip_to_hostname.popitem(last=False)
                _ip_to_hostname[ip] = host_lower
    except Exception:
        # Best-effort: gevent/eventlet monkey-patched resolvers can raise
        # RuntimeError or other non-OSError exceptions (e.g. thread pool
        # exhaustion).  The IP map is optional — connect enforcement still
        # works via hostname matching at the DNS level.
        logger.debug(
            "tethered: IP map resolution failed for %s (best-effort, non-fatal)",
            host,
            exc_info=True,
        )
    finally:
        _in_hook.reset(_token)


def _handle_connect(
    cfg: _Config | None,
    scope_stack: tuple[_ScopeConfig, ...],
    event: str,
    args: tuple[Any, ...],
) -> None:
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

    # ── Global policy check ──
    global_allowed = True
    if cfg is not None:
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
            allowed = True  # fail-open: treat as allowed, continue to scope checks

        if not allowed:
            global_allowed = False
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

    # ── Scope checks ──
    # Check resolved hostname first; if blocked, try raw IP as fallback
    # (mirrors global policy: allow if EITHER hostname or IP matches)
    blocking_scope = _check_scopes(scope_stack, check_host, port, _normalized=True)
    if blocking_scope is not None and resolved_from is not None:
        ip_blocking = _check_scopes(scope_stack, host, port, _normalized=True)
        if ip_blocking is None:
            blocking_scope = None
    if blocking_scope is not None:
        event_desc = f"{event.split('.')[-1]} to {check_host}:{port}"
        _enforce_scope_block(
            blocking_scope,
            check_host,
            port,
            event_desc,
            global_allowed=global_allowed,
            resolved_from=resolved_from,
        )


def _install_hook() -> None:
    """Install the audit hook exactly once."""
    global _hook_installed
    with _state_lock:
        if _hook_installed:
            return
        sys.addaudithook(_audit_hook)
        _hook_installed = True


# ── Context-local scope ───────────────────────────────────────────


class scope:
    """Context-local egress restriction.

    Use as a context manager or function/method decorator to restrict
    network egress within a specific code path.  Scopes are purely
    restrictive: they can only narrow the set of allowed destinations,
    never widen it.

    When combined with ``activate()``, the effective policy is the
    **intersection** — a connection must be allowed by both the global
    policy and every active scope.

    Args:
        allow: List of allowed destinations (same syntax as ``activate()``).
        allow_localhost: If True (default), always allow loopback addresses.
        log_only: If True, log blocked connections but don't raise.
        fail_closed: If True, block on unexpected policy errors.
        on_blocked: Optional callback ``(host, port) -> None`` on blocked
            connections.
    """

    __slots__ = ("_scope_cfg", "_token")

    def __init__(
        self,
        *,
        allow: list[str],
        allow_localhost: bool = True,
        log_only: bool = False,
        fail_closed: bool = False,
        on_blocked: Callable[[str, int | None], None] | None = None,
    ) -> None:
        _validate_allow(allow)
        _validate_bool(allow_localhost, "allow_localhost")
        _validate_bool(log_only, "log_only")
        _validate_bool(fail_closed, "fail_closed")
        _validate_callback(on_blocked)
        label = "scope({})".format(
            ", ".join(allow[:3]) + ("..." if len(allow) > 3 else ""),
        )
        policy = AllowPolicy(allow, allow_localhost=allow_localhost)
        self._scope_cfg = _ScopeConfig(
            policy=policy,
            log_only=log_only,
            fail_closed=fail_closed,
            on_blocked=on_blocked,
            label=label,
        )
        self._token: contextvars.Token[tuple[_ScopeConfig, ...]] | None = None

        # Warn about dead or overly broad rules when a global policy is active
        cfg = _config
        if cfg is not None:
            self._warn_scope_overlap(cfg.policy, allow, label)

    @staticmethod
    def _warn_scope_overlap(
        global_policy: AllowPolicy,
        allow: list[str],
        label: str,
    ) -> None:
        """Warn about scope rules that have no or partial overlap with the global policy."""
        for rule in allow:
            rule_stripped = rule.strip().lower()
            # Parse port from the rule
            port_part: int | None = None
            host_part = rule_stripped

            # Handle bracketed IPv6: [2001:db8::1]:443 or [2001:db8::]/32:443
            if rule_stripped.startswith("["):
                bracket_end = rule_stripped.find("]")
                if bracket_end != -1:
                    inner = rule_stripped[1:bracket_end]
                    remainder = rule_stripped[bracket_end + 1 :]
                    # CIDR suffix: [2001:db8::]/32 or [2001:db8::]/32:443
                    if remainder.startswith("/"):
                        cidr_and_rest = remainder[1:]
                        if ":" in cidr_and_rest:
                            cidr_str, port_str = cidr_and_rest.rsplit(":", 1)
                            if port_str.isascii() and port_str.isdigit():
                                port_part = int(port_str)
                            host_part = inner + "/" + cidr_str
                        else:
                            host_part = inner + "/" + cidr_and_rest
                    else:
                        if ":" in remainder and remainder.split(":")[-1].isdigit():
                            port_part = int(remainder.split(":")[-1])
                        host_part = inner
            elif ":" in rule_stripped:
                parts = rule_stripped.rsplit(":", 1)
                if parts[1].isascii() and parts[1].isdigit():
                    host_part = parts[0]
                    port_part = int(parts[1])

            # Wildcard hostname rules
            if "*" in host_part or "?" in host_part:
                overlap = global_policy._check_wildcard_overlap(host_part, port_part)
                if overlap == "none":
                    logger.warning(
                        "tethered: %s rule %r has no overlap with global policy"
                        " — it will never match",
                        label,
                        rule,
                    )
                elif overlap == "partial":
                    logger.warning(
                        "tethered: %s rule %r is broader than the global policy"
                        " — only a subset will be reachable",
                        label,
                        rule,
                    )
                continue

            # CIDR rules
            if "/" in host_part:
                try:
                    network = ipaddress.ip_network(host_part, strict=False)
                    overlap = global_policy._check_cidr_overlap(network, port_part)
                    if overlap == "none":
                        logger.warning(
                            "tethered: %s rule %r has no overlap with global policy"
                            " — it will never match",
                            label,
                            rule,
                        )
                    elif overlap == "partial":
                        logger.warning(
                            "tethered: %s rule %r is broader than the global policy"
                            " — only a subset will be reachable",
                            label,
                            rule,
                        )
                except ValueError:
                    pass
                continue

            # Exact hostname/IP rules
            if port_part is not None:
                if global_policy.is_allowed(host_part, port_part):
                    continue
                logger.warning(
                    "tethered: %s rule %r has no overlap with global policy — it will never match",
                    label,
                    rule,
                )
            elif global_policy._has_any_port_rule(host_part):
                # Global has an any-port rule for this host — full match
                continue
            elif global_policy.is_allowed(host_part, None):
                # Host exists but only on specific ports — scope is broader
                logger.warning(
                    "tethered: %s rule %r is broader than the global policy"
                    " — only a subset will be reachable",
                    label,
                    rule,
                )
            else:
                logger.warning(
                    "tethered: %s rule %r has no overlap with global policy — it will never match",
                    label,
                    rule,
                )

    def __enter__(self) -> scope:
        if self._token is not None:
            msg = "tethered.scope: this instance is already entered; create a new scope() instance"
            raise RuntimeError(msg)
        _install_hook()
        current = _scopes.get()
        self._token = _scopes.set((*current, self._scope_cfg))
        logger.debug("tethered: entered %s", self._scope_cfg.label)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        assert self._token is not None  # nosec B101
        _scopes.reset(self._token)
        self._token = None
        logger.debug("tethered: exited %s", self._scope_cfg.label)

    def __call__(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Use as a decorator on sync or async functions."""
        if inspect.isgeneratorfunction(fn) or inspect.isasyncgenfunction(fn):
            msg = (
                "tethered.scope cannot decorate generator or async generator functions "
                "because the scope would exit after the first yield. "
                "Use 'with tethered.scope(allow=[...]):' inside the function body instead."
            )
            raise TypeError(msg)

        scope_cfg = self._scope_cfg

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                _install_hook()
                current = _scopes.get()
                token = _scopes.set((*current, scope_cfg))
                logger.debug("tethered: entered %s", scope_cfg.label)
                try:
                    return await fn(*args, **kwargs)
                finally:
                    _scopes.reset(token)
                    logger.debug("tethered: exited %s", scope_cfg.label)

            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            _install_hook()
            current = _scopes.get()
            token = _scopes.set((*current, scope_cfg))
            logger.debug("tethered: entered %s", scope_cfg.label)
            try:
                return fn(*args, **kwargs)
            finally:
                _scopes.reset(token)
                logger.debug("tethered: exited %s", scope_cfg.label)

        return sync_wrapper


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
            unless the correct ``lock_token`` is provided. Raises the bar
            for accidental or casual in-process disabling of tethered.
        lock_token: An opaque object required when ``locked=True`` and used
            to authenticate when replacing an existing locked policy.
            Compared by identity (``is``), not equality.

    Raises:
        ValueError: If ``locked=True`` is used without ``lock_token``.
        TetheredLocked: If a locked policy is active and the correct
            ``lock_token`` is not provided.
    """
    global _config

    _validate_allow(allow)
    _validate_bool(log_only, "log_only")
    _validate_bool(fail_closed, "fail_closed")
    _validate_bool(allow_localhost, "allow_localhost")
    _validate_bool(locked, "locked")
    _validate_callback(on_blocked)

    if locked and lock_token is None:
        msg = "tethered: lock_token is required when locked=True"
        raise ValueError(msg)

    policy = AllowPolicy(allow, allow_localhost=allow_localhost)
    cfg = _Config(
        policy=policy,
        log_only=log_only,
        fail_closed=fail_closed,
        on_blocked=on_blocked,
        locked=locked,
        lock_token=lock_token if locked else None,
    )

    with _state_lock:
        old = _config
        if (
            old is not None
            and old.locked
            and (lock_token is None or lock_token is not old.lock_token)
        ):
            raise TetheredLocked
        with _ip_map_lock:
            _config = cfg
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
        with _ip_map_lock:
            _config = None
            _ip_to_hostname.clear()

    logger.info("tethered: deactivated")
