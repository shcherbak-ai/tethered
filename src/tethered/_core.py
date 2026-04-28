"""Audit hook, state management, and public activate/deactivate/scope API."""

from __future__ import annotations

import _socket as _csocket  # C-level socket; immune to gevent/eventlet monkey-patching
import collections
import contextvars
import functools
import inspect
import ipaddress
import json
import logging
import os
import sys
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from tethered._policy import AllowPolicy, _could_be_ip, _normalize_host

try:
    from tethered import _guardian as _c_guardian
except ImportError:  # pragma: no cover
    _c_guardian = None  # ty: ignore[invalid-assignment]

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
        scope_label: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.resolved_from = resolved_from
        # Human-readable label of the scope that blocked the call (e.g.
        # ``"scope(api.mylib.com:443)"``), or ``None`` when the block came
        # from the global policy.  Useful for libraries that wrap
        # ``EgressBlocked`` in their own exception type and want to
        # disambiguate which scope produced the block.
        self.scope_label = scope_label

        msg = f"Blocked by tethered: {host}"
        if port is not None:
            msg += f":{port}"
        if resolved_from and resolved_from != host:
            msg += f" (resolved from {resolved_from})"
        msg += " is not in the allow list"
        if scope_label:
            msg += f" (blocked by {scope_label})"
        super().__init__(msg)


class TetheredLocked(RuntimeError):
    """Raised when deactivate() is called in locked mode."""

    def __init__(self) -> None:
        super().__init__(
            "tethered: deactivate() blocked — policy is locked. "
            "Pass the same lock_token to deactivate() to unlock."
        )


class SubprocessBlocked(RuntimeError):
    """Raised when a subprocess launch is blocked by tethered policy."""

    def __init__(self, event: str, description: str) -> None:
        self.event = event
        self.description = description
        super().__init__(
            f"Blocked by tethered: {description} — refused by tethered policy "
            f"(external_subprocess_policy or locked-mode tamper check)"
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
    external_subprocess_policy: str = "warn"
    # Canonical JSON-serialized at-rest env payload, written to
    # ``os.environ[_TETHERED_CHILD_POLICY]`` at activate() time.  Format:
    # ``{"global": {<global fields>}, "scopes": []}``.  Per-launch payloads
    # injected by the subprocess audit hook share the same shape with a
    # populated ``scopes`` list.  Integrity-snapshotted via _Config.__slots__.
    _serialized_payload: str = field(default="", repr=False)
    # Canonical inner ``global`` dict — the integrity-anchored half of the
    # env payload.  Locked mode compares ``parsed["global"]`` of the launch
    # env against this dict.  The ``scopes`` half is not byte-checked because
    # scopes can only narrow within the parent's global ceiling.
    _global_payload_dict: dict[str, Any] = field(default_factory=dict, repr=False)
    # Absolute path of the tethered.pth file that performs auto-activation in
    # spawn-mode children.  Cached at activate() time so the locked-mode FS
    # hook can refuse Python-level deletion or overwrite of this exact path.
    _pth_path: str = field(default="", repr=False)
    # Captured ``socket.gethostname()`` (normalized) at activate() time.
    # Used to short-circuit the policy check in ``_handle_dns_lookup`` and
    # ``_handle_getaddrinfo`` for self-introspection lookups: ``getfqdn()``,
    # ``gethostbyaddr(gethostname())``, ``gethostbyname(gethostname())``,
    # and ``getaddrinfo(gethostname(), ...)``.  Those calls consult the
    # local resolver / ``/etc/hosts`` / NSS to retrieve the canonical
    # name string — no network connection is made.  Affects any caller
    # that introspects its own machine identity: ``smtplib`` HELO/EHLO,
    # ``email.utils.make_msgid``, the stdlib ``logging.handlers.SMTPHandler``
    # and its downstream users (e.g. Django's ``AdminEmailHandler``),
    # ``paramiko``/``fabric`` host-identification paths, custom
    # health-check / observability code, etc.  Captured at activate-time
    # from OS-controlled state, so an in-process attacker can't influence
    # it before activate runs.  Empty string when ``gethostname()`` returns
    # nothing or raises — the comparison then never matches.
    # Integrity-snapshotted via ``_Config.__slots__``.  Connect-time policy
    # is unchanged — this only exempts the DNS-lookup audit-hook path.
    _local_hostname: str = field(default="", repr=False)


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
_guardian_token_id: int = 0  # stored for test fixture cleanup

# IP -> hostname mapping from intercepted getaddrinfo calls.
# OrderedDict for LRU eviction: move_to_end() on access, popitem(last=False) to evict.
_ip_to_hostname: collections.OrderedDict[str, str] = collections.OrderedDict()
_ip_map_lock = threading.Lock()

# Recently-allowed hostnames (passed the global policy check in
# ``_handle_getaddrinfo``).  Used by ``_fallback_resolve`` to repair the
# IP -> hostname map on a connect-time miss caused by DNS divergence —
# tethered's audit-time getaddrinfo and CPython's original getaddrinfo
# are independent queries; under load-balanced services with short TTLs
# (Microsoft Entra ID, M365, large CDNs) and gevent threadpool latency,
# they can return different IP sets, leaving the connect-time IP unmapped.
# OrderedDict for LRU semantics; values unused (set-like).  Bounded so
# the fallback search stays cheap.  Guarded by ``_ip_map_lock``.
_ALLOWED_HOSTNAMES_MAX_SIZE = 512
_allowed_hostnames: collections.OrderedDict[str, None] = collections.OrderedDict()

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


def _validate_optional_str(value: object, param_name: str) -> None:
    """Validate that a parameter is either a ``str`` or ``None``."""
    if value is not None and not isinstance(value, str):
        msg = f"{param_name} must be a str or None, got {type(value).__name__}"
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

# Process-launch audit events (CPython audit event table)
_SUBPROCESS_EVENTS = frozenset(
    (
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.spawn",
        "os.startfile",
    )
)

_EXTERNAL_SUBPROCESS_POLICIES = frozenset(("allow", "warn", "block"))

# Locked-mode FS-tamper detection.  Refuses Python-level deletion, rename,
# overwrite, or chmod of tethered.pth (the auto-propagation hook).  No-op
# when locked mode is off.  ``os.unlink`` is intentionally absent — CPython
# aliases it to ``os.remove`` and fires the ``os.remove`` audit event, never
# ``os.unlink``.  The ``os.chmod`` entry catches a permission-strip attack:
# ``os.chmod(path, 0)`` makes the file unreadable, so site.py silently skips
# it on POSIX → no auto-activation in the next interpreter.
#
# ``os.link`` and ``os.symlink`` are intentionally absent: both syscalls
# fail with ``EEXIST`` when the destination already exists, and the
# ``.pth`` is created during ``pip install`` and present at the moment
# this hook starts watching.  To use either against the live ``.pth`` an
# attacker must first delete or rename it — both of which ARE in this set
# and get refused.  Adding ``os.link`` / ``os.symlink`` would catch nothing
# extra in the locked-mode threat model.
_PTH_FS_EVENTS = frozenset(("os.remove", "os.rename", "open", "os.chmod"))


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
    # socket.* is the hot path — handle and return early.
    if event.startswith("socket."):
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
        return

    # Subprocess launches: parent-side enforcement (warn/block), locked-mode
    # payload-integrity check, and per-launch scope-env injection.  Routed
    # whenever there is anything to enforce — global config OR an active
    # scope chain.  Scope-only firing (cfg is None) is what makes scope
    # propagation work for libraries doing self-defense without app-level
    # activate().
    if event in _SUBPROCESS_EVENTS:
        cfg = _config
        scope_stack = _scopes.get()
        if cfg is None and not scope_stack:
            return
        _handle_subprocess(cfg, event, args, scope_stack)
        return

    # Locked-mode-only tamper detection on FS access to tethered.pth.
    # ``open`` fires constantly during normal program operation, so
    # short-circuit on cfg.locked before doing any per-event work.
    cfg = _config
    if cfg is None or not cfg.locked:
        return
    if event in _PTH_FS_EVENTS:
        _handle_pth_fs_op(cfg, event, args)


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
        raise EgressBlocked(host, port, resolved_from=resolved_from, scope_label=sc.label)


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

    # Self-introspection short-circuit: ``socket.getfqdn()``,
    # ``gethostbyaddr(gethostname())``, and similar paths consult the
    # local resolver / ``/etc/hosts`` / NSS to retrieve the canonical
    # host name string — no network connection is made.  Blocking these
    # cascades through any caller that introspects machine identity:
    # ``smtplib`` HELO/EHLO, ``email.utils.make_msgid``, the stdlib
    # ``logging.handlers.SMTPHandler`` (and its downstream users like
    # Django's ``AdminEmailHandler``), ``paramiko``/``fabric``,
    # health-check code, etc.  The captured ``_local_hostname`` is
    # OS-controlled (set by the kernel / container runtime), frozen at
    # activate-time, and snapshotted in locked mode — so this exemption
    # can't be abused by an in-process attacker to widen egress.
    # Connect-time policy is unchanged; this only affects the DNS-lookup
    # audit-hook path.
    if cfg is not None and cfg._local_hostname and host_lower == cfg._local_hostname:
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

    # Self-introspection short-circuit: see ``_handle_dns_lookup`` for
    # rationale.  Apps may also do ``getaddrinfo(gethostname(), ...)``
    # (e.g. for binding to a self-named address).  Connect-time policy
    # on whatever IP that resolves to is unchanged.
    if cfg is not None and cfg._local_hostname and host_lower == cfg._local_hostname:
        return

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

    # Record the hostname for the connect-time fallback-resolve path.
    # Done AFTER the global policy check passes (so we don't invite arbitrary
    # hostnames into the candidate set) and BEFORE the scope check (so
    # log-only scopes still benefit, mirroring how _ip_to_hostname is
    # populated below).
    with _ip_map_lock:
        if host_lower in _allowed_hostnames:
            _allowed_hostnames.move_to_end(host_lower)
        else:
            if len(_allowed_hostnames) >= _ALLOWED_HOSTNAMES_MAX_SIZE:
                _allowed_hostnames.popitem(last=False)
            _allowed_hostnames[host_lower] = None

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
    # When the C guardian is active, _c_guardian.resolve() manages a C-internal
    # resolving_depth counter that the guardian audit hook trusts.  This prevents
    # _in_hook.set(True) from being used to bypass enforcement in locked mode.
    # Falls back to _csocket (CPython's C-level _socket module) when the guardian
    # is not active, to avoid gevent/eventlet monkey-patched getaddrinfo.
    _token = _in_hook.set(True)
    try:
        port = args[1] if len(args) >= 2 else None
        family = args[2] if len(args) >= 3 and isinstance(args[2], int) else 0
        socktype = args[3] if len(args) >= 4 and isinstance(args[3], int) else 0
        proto = args[4] if len(args) >= 5 and isinstance(args[4], int) else 0
        flags = args[5] if len(args) >= 6 and isinstance(args[5], int) else 0
        if _c_guardian is not None and _c_guardian.is_active():
            results = _c_guardian.resolve(host, port, family, socktype, proto, flags)
        else:
            results = _csocket.getaddrinfo(host, port, family, socktype, proto, flags)
        with _ip_map_lock:
            for _family, _socktype, _proto, _canonname, sockaddr in results:
                ip = str(sockaddr[0])  # always str; cast for the type checker
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


# Maximum hostnames to re-resolve on a single connect-time IP-map miss.
# Bounds worst-case work to a small constant (each iteration is one
# OS-cached DNS lookup) and limits the surface area for any DNS-based
# amplification a malicious caller could create by feeding many fake
# unmapped IPs through socket.connect.
_FALLBACK_RESOLVE_MAX_CANDIDATES = 30


def _fallback_resolve(target_ip: str, port: int | None) -> str | None:
    """Re-resolve recently-allowed hostnames to find one that maps to ``target_ip``.

    Called from :func:`_handle_connect` when an IP isn't in
    :data:`_ip_to_hostname`.  Mitigates DNS divergence between tethered's
    audit-time ``getaddrinfo`` (used to populate the IP map) and CPython's
    own ``getaddrinfo`` (whose results are returned to the application).
    Under load-balanced services with short TTLs (Microsoft Entra ID,
    M365, large CDNs) and gevent threadpool latency, the two queries can
    return different IP sets, leaving the connect-time IP unmapped.

    Returns the matching hostname (and enriches :data:`_ip_to_hostname`
    so future connects to the same IP take the fast path) on hit; returns
    ``None`` on miss.  Per-hostname resolve failures are swallowed and
    the search continues — sustained DNS failure for every candidate
    yields ``None``, leaving the calling :func:`_handle_connect` to block
    on the original miss.

    In locked mode the resolve goes through :func:`_c_guardian.resolve`,
    whose caller verification accepts ``_fallback_resolve``'s ``__code__``
    as a second authorized caller alongside :func:`_handle_getaddrinfo`.
    Outside locked mode the resolve goes through :data:`_csocket.getaddrinfo`
    directly (immune to gevent/eventlet monkey-patching).
    """
    # Snapshot recent-first under the lock (LRU order: newest is rightmost).
    with _ip_map_lock:
        candidates = list(reversed(_allowed_hostnames))[:_FALLBACK_RESOLVE_MAX_CANDIDATES]

    if not candidates:
        return None

    _token = _in_hook.set(True)
    try:
        for hostname in candidates:
            try:
                if _c_guardian is not None and _c_guardian.is_active():
                    results = _c_guardian.resolve(hostname, port, 0, 0, 0, 0)
                else:
                    results = _csocket.getaddrinfo(hostname, port, 0, 0, 0, 0)
            except Exception:
                # Per-hostname failures (NXDOMAIN, timeout, gevent threadpool
                # exhaustion, etc.) must not abort the whole search.
                logger.debug(
                    "tethered: fallback resolve of %s failed (continuing)",
                    hostname,
                    exc_info=True,
                )
                continue

            matched = False
            with _ip_map_lock:
                for _fam, _stype, _proto, _canon, sockaddr in results:
                    ip = str(sockaddr[0])
                    if ip in _ip_to_hostname:
                        _ip_to_hostname[ip] = hostname
                        _ip_to_hostname.move_to_end(ip)
                    else:
                        if len(_ip_to_hostname) >= _IP_MAP_MAX_SIZE:
                            _ip_to_hostname.popitem(last=False)
                        _ip_to_hostname[ip] = hostname
                    if ip == target_ip:
                        matched = True
            if matched:
                logger.debug(
                    "tethered: fallback resolved %s to %s (DNS divergence)",
                    target_ip,
                    hostname,
                )
                return hostname
        return None
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
        if resolved_from is None:
            # IP map miss — could be DNS divergence (load-balanced service,
            # short TTL, gevent threadpool latency) where the IP CPython
            # returned to the application differs from what tethered's
            # audit-time getaddrinfo saw.  Re-resolve recently-allowed
            # hostnames to find one that maps to this IP.  Hot path
            # (mapped IP) is unaffected; cost only on the miss.
            resolved_from = _fallback_resolve(host, port)
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


def _describe_subprocess_launch(event: str, args: tuple[Any, ...]) -> str:
    """Build a human-readable description of a subprocess launch for logging."""
    if event == "subprocess.Popen":
        exe = args[0] if args else "<unknown>"
        return f"subprocess.Popen({exe})"
    if event == "os.system":
        cmd = args[0] if args else "<unknown>"
        return f"os.system({cmd!r})"
    if event == "os.exec":
        path = args[0] if args else "<unknown>"
        return f"os.exec*({path})"
    if event == "os.posix_spawn":
        path = args[0] if args else "<unknown>"
        return f"os.posix_spawn({path})"
    if event == "os.spawn":
        path = args[1] if len(args) >= 2 else "<unknown>"
        return f"os.spawn*({path})"
    if event == "os.startfile":
        path = args[0] if args else "<unknown>"
        return f"os.startfile({path})"
    return f"{event}(...)"


def _extract_subprocess_env(event: str, args: tuple[Any, ...]) -> tuple[bool, Any]:
    """Extract the env dict from a subprocess audit event's args.

    Returns ``(has_env_arg, env_value)``.  ``has_env_arg`` is False when the
    event signature has no env arg at all (``os.system``, ``os.startfile``)
    or when the audit-event arg tuple is shorter than expected.
    ``env_value`` may be None (env inherited) or a dict (explicit env).
    """
    if event == "subprocess.Popen" and len(args) >= 4:
        return True, args[3]
    if event in ("os.exec", "os.posix_spawn") and len(args) >= 3:
        return True, args[2]
    if event == "os.spawn" and len(args) >= 4:
        return True, args[3]
    return False, None


# Python interpreter flags that skip site.py (and therefore tethered.pth →
# auto-activation).  Only ``-S`` actually disables site.py; ``-I`` (isolated)
# and ``-E`` (ignore PYTHON* env vars) leave site.py enabled and tethered's
# bootstrap continues to work.  A child invoked with ``-S`` (or a combined
# form containing ``S``, e.g. ``-IS``) cannot auto-inherit the parent's
# policy and is subject to external_subprocess_policy.
_SITE_BYPASS_FLAG_CHARS = "S"


def _has_site_bypass_flag(argv: Any) -> bool:
    """Return True if ``argv`` includes a Python flag that disables ``site.py``.

    Inspects interpreter flags appearing before any ``-c`` / ``-m`` terminator.
    Only ``-S`` (or combined forms containing ``S`` like ``-IS``) actually
    disables ``site.py``; ``-I`` and ``-E`` keep ``site.py`` enabled and so
    are NOT bypass flags.  Returns False for non-list/tuple argvs and for
    argvs that don't reach a bypass flag before the terminator.

    POSIX ``subprocess.Popen`` accepts ``bytes`` and ``os.PathLike`` argv
    elements (which CPython decodes at startup), so we run those through
    ``os.fsdecode`` to match the char sequence the kernel will see —
    otherwise an attacker could pass ``b"-S"`` to slip past a naive
    ``isinstance(arg, str)`` check.
    """
    if not isinstance(argv, (list, tuple)):
        return False
    # argv[0] is the executable name; interpreter flags start at argv[1].
    for arg in argv[1:]:
        if isinstance(arg, (bytes, os.PathLike)):
            try:
                arg = os.fsdecode(arg)
            except (TypeError, ValueError):
                continue
        if not isinstance(arg, str):
            continue
        if arg in ("-c", "-m"):
            return False  # flags after -c/-m belong to user code, not interpreter
        # Combined-flag forms like "-IS" are valid; check each char (skip "--long-form").
        if (
            arg.startswith("-")
            and not arg.startswith("--")
            and any(c in arg[1:] for c in _SITE_BYPASS_FLAG_CHARS)
        ):
            return True
    return False


def _normalize_exe_path(value: Any) -> str | None:
    """Decode and normalize a path-like value for comparison with ``sys.executable``."""
    if not isinstance(value, (str, bytes, os.PathLike)):
        return None
    try:
        s = os.fsdecode(value)
    except (TypeError, ValueError):
        return None
    return os.path.normcase(os.path.normpath(s))


def _parse_windows_cmdline(cmdline: str) -> tuple[str, list[str]] | None:
    """Best-effort parse of a Windows ``subprocess.Popen`` command-line string.

    Returns ``(executable, argv)`` where ``argv`` is suitable for passing
    to :func:`_has_site_bypass_flag`.  Returns ``None`` if the executable
    can't be extracted.

    The Windows command-line format the audit event sees is
    ``<exe-quoted-or-bare> <args...>``.  We extract the executable, then
    whitespace-split the remainder until the first ``-c`` / ``-m``
    terminator and stop — the script body that follows ``-c`` may contain
    embedded quotes and newlines that ``shlex`` rejects (and that we don't
    need to parse anyway, since interpreter flags always come before the
    terminator).  Interpreter flags like ``-S`` never contain spaces or
    quotes, so plain whitespace splitting is sufficient for the
    site-bypass check.
    """
    s = cmdline.strip()
    if not s:
        return None
    if s.startswith('"'):
        close = s.find('"', 1)
        if close == -1:
            return None
        exe = s[1:close]
        rest = s[close + 1 :].lstrip()
    else:
        space = s.find(" ")
        if space == -1:
            exe = s
            rest = ""
        else:
            exe = s[:space]
            rest = s[space + 1 :].lstrip()

    pre_args: list[str] = []
    for tok in rest.split():
        if tok in ("-c", "-m"):
            break
        pre_args.append(tok)
    return exe, [exe, *pre_args]


def _is_auto_inheriting_python_launch(event: str, args: tuple[Any, ...]) -> bool:
    """Return True if a subprocess launch will be covered by ``tethered.pth`` auto-inherit.

    A launch auto-inherits when:

    1. The executable is exactly ``sys.executable`` (same Python interpreter,
       has tethered installed in its site-packages).
    2. The argv doesn't include ``-S`` (which disables ``site.py`` and so
       skips ``tethered.pth``).  ``-I`` and ``-E`` keep ``site.py`` enabled
       and are NOT treated as bypass flags.

    Handles both POSIX and Windows audit-event layouts.  On POSIX,
    ``subprocess.Popen`` fires with ``(executable, argv_list, cwd, env)``.
    On Windows, ``Popen`` builds a command line and fires with
    ``(None, command_line_string, cwd, env)`` — we parse the command line
    with :func:`_parse_windows_cmdline` to recover the executable and the
    pre-terminator tokens for the flag check.

    Used by ``_handle_subprocess`` to skip ``external_subprocess_policy``
    enforcement on launches that auto-inherit handles.  Returns False for
    events that don't directly launch a Python interpreter
    (``os.system``, ``os.startfile``).
    """
    # Identify executable + argv based on the event's audit-arg layout.
    if event in ("subprocess.Popen", "os.exec", "os.posix_spawn") and len(args) >= 2:
        executable, argv = args[0], args[1]
    elif event == "os.spawn" and len(args) >= 3:
        executable, argv = args[1], args[2]
    else:
        return False

    # Windows ``subprocess.Popen``: executable=None, argv is the command-line
    # string.  Parse it ourselves; ``shlex`` chokes on -c-script bodies with
    # embedded quotes and newlines.
    if executable is None and isinstance(argv, str):
        parsed = _parse_windows_cmdline(argv)
        if parsed is None:
            return False
        executable, argv = parsed

    exe_norm = _normalize_exe_path(executable)
    if exe_norm is None:
        return False

    if exe_norm != _normalize_exe_path(sys.executable):
        return False

    return not _has_site_bypass_flag(argv)


# Maximum frames to walk back from the audit hook to find ``_execute_child``.
# In practice the target frame is sys._getframe(2) or (3); the cap is purely
# defensive against unexpected call-stack depth (e.g. profilers, debuggers).
_FRAME_WALK_DEPTH_CAP = 12


def _find_execute_child_frame() -> Any | None:
    """Walk back from the caller and return ``subprocess._execute_child``'s frame.

    The frame is identified by a defensive shape check: ``co_name`` matches,
    the frame's code declares an ``env`` local, AND the frame's globals
    belong to the ``subprocess`` module (rejects user code that happens to
    define a same-named function).  Returns ``None`` if no matching frame is
    found within :data:`_FRAME_WALK_DEPTH_CAP` frames — caller decides
    whether that is fail-closed (locked mode) or warn-and-degrade.
    """
    f = sys._getframe(1)  # start from the caller of this function
    depth = 0
    while f is not None and depth < _FRAME_WALK_DEPTH_CAP:
        code = f.f_code
        if (
            code.co_name == "_execute_child"
            and "env" in code.co_varnames
            and f.f_globals.get("__name__") == "subprocess"
        ):
            return f
        f = f.f_back
        depth += 1
    return None


def _inject_scope_env(frame: Any, new_env: dict[str, Any]) -> bool:
    """Rewrite ``frame.f_locals["env"]`` to ``new_env``.

    On Python ≤ 3.12 the ``f_locals`` dict is a snapshot, so we additionally
    call ``ctypes.pythonapi.PyFrame_LocalsToFast`` to push the write back
    into the fast-locals slot.  On 3.13+ ``f_locals`` is a write-through
    proxy (PEP 667), so the assignment is sufficient and the ctypes call
    would be a no-op (or removed) — skip it.

    Returns ``True`` on success.  Returns ``False`` and logs a warning on
    any failure (ctypes unavailable in sandboxed CPython, write-protected
    frame, etc.) — caller decides whether that is fail-closed (locked mode)
    or warn-and-degrade.
    """
    try:
        frame.f_locals["env"] = new_env
    except Exception:
        logger.warning("tethered: scope env injection failed (f_locals write)", exc_info=True)
        return False
    if sys.version_info < (3, 13):  # pragma: no cover — only on 3.10-3.12
        try:
            import ctypes

            ctypes.pythonapi.PyFrame_LocalsToFast(ctypes.py_object(frame), ctypes.c_int(0))
        except Exception:
            logger.warning(
                "tethered: scope env injection failed (PyFrame_LocalsToFast)",
                exc_info=True,
            )
            return False
    return True


def _build_per_launch_env(
    event: str,
    args: tuple[Any, ...],
    scope_stack: tuple[_ScopeConfig, ...],
    cfg: _Config | None,
) -> dict[str, str]:
    """Build the per-launch env dict to inject into ``_execute_child``.

    Copies the existing env (the explicit ``env=`` arg if it was a dict, else
    ``os.environ``) and overwrites ``_TETHERED_CHILD_POLICY`` with a
    nested-format payload that carries the canonical global plus the active
    scope chain.  All other env vars are preserved verbatim — never
    fabricate a child env from scratch.
    """
    has_env, env_value = _extract_subprocess_env(event, args)
    if has_env and isinstance(env_value, dict):
        new_env: dict[str, str] = dict(env_value)
    else:
        new_env = dict(os.environ)
    global_dict = cfg._global_payload_dict if cfg is not None else None
    new_env[_CHILD_POLICY_ENV] = _build_env_payload(global_dict, scope_stack)
    return new_env


def _handle_subprocess(
    cfg: _Config | None,
    event: str,
    args: tuple[Any, ...],
    scope_stack: tuple[_ScopeConfig, ...] = (),
) -> None:
    """Enforce subprocess launch policy.

    ``cfg`` is ``None`` when only scopes are active (no :func:`activate` ever
    called) — the audit hook still fires so scope policy can propagate to
    child processes.  ``scope_stack`` is the active scope chain, captured
    once by ``_audit_hook`` and passed in to keep the per-event ContextVar
    reads consistent.
    """
    # Locked-mode payload-integrity enforcement.  Verify that the policy the
    # child will see has a canonical 'global' field matching the parent's
    # frozen-at-activate-time _global_payload_dict.  Two source paths:
    #   1. Explicit env=dict — check the dict's value.
    #   2. Inherited env (None) — check os.environ.  Catches Python-level
    #      mutation (os.environ.pop / __setitem__ / __delitem__) AND ctypes-
    #      level mutation (libc setenv / unsetenv) since both ultimately
    #      change what subprocess will inherit.
    # Refuse on absence ("strip"), corruption ("not valid JSON"), or
    # differing 'global' field ("substitution").  Substituted scopes are
    # allowed: scopes can only narrow within the byte-checked global
    # ceiling, so they can't widen child enforcement past the parent.
    # Locked mode requires activate(), so cfg is non-None here.
    if cfg is not None and cfg.locked:
        has_env, env_value = _extract_subprocess_env(event, args)
        if has_env and isinstance(env_value, dict):
            env_payload = env_value.get(_CHILD_POLICY_ENV)
            source = "env"
        else:
            # env=None or event has no env arg → child inherits os.environ
            env_payload = os.environ.get(_CHILD_POLICY_ENV)
            source = "os.environ"

        if env_payload is None:
            desc = _describe_subprocess_launch(event, args)
            logger.warning(
                "tethered: blocked subprocess launch with stripped policy env: %s (%s)",
                desc,
                source,
            )
            raise SubprocessBlocked(
                event,
                f"{desc} — {source} strips {_CHILD_POLICY_ENV}",
            )
        # Parse the env value as JSON.  Corrupted payload is treated as a
        # tamper attempt — wrap json.loads in try/except so the exception
        # never escapes the audit hook (which CPython logs and then ALLOWS
        # the syscall — that would be a bypass).
        try:
            parsed_payload = json.loads(env_payload)
        except (json.JSONDecodeError, TypeError):
            desc = _describe_subprocess_launch(event, args)
            logger.warning(
                "tethered: blocked subprocess launch with corrupted policy payload: %s (%s)",
                desc,
                source,
            )
            raise SubprocessBlocked(
                event,
                f"{desc} — {source} carries a {_CHILD_POLICY_ENV} value that is "
                "not valid JSON (corruption / tamper attempt)",
            ) from None
        if (
            not isinstance(parsed_payload, dict)
            or parsed_payload.get("global") != cfg._global_payload_dict
        ):
            desc = _describe_subprocess_launch(event, args)
            logger.warning(
                "tethered: blocked subprocess launch with substituted policy payload: %s (%s)",
                desc,
                source,
            )
            raise SubprocessBlocked(
                event,
                f"{desc} — {source} carries a {_CHILD_POLICY_ENV} value whose "
                "'global' field differs from the parent's canonical payload "
                "(substitution attempt)",
            )
        # parsed_payload["scopes"] is intentionally NOT integrity-checked.

    # Auto-inheriting Python child launches are covered by tethered.pth →
    # _autoactivate.  For those launches:
    #   - Inject a per-launch env via frame mutation when scopes are active,
    #     so the child observes the parent's effective policy at the launch
    #     site (global + scopes) rather than just the at-rest global.
    #   - Skip external_subprocess_policy (it's for launches auto-inherit
    #     can't reach: non-Python children, different interpreters, or
    #     ``-S``-flag launches that disable ``site.py``).
    if _is_auto_inheriting_python_launch(event, args):
        if scope_stack:
            frame = _find_execute_child_frame()
            if frame is None:
                # No subprocess._execute_child frame in the stack — could be
                # a debugger wrapper, a future CPython refactor, or a
                # platform without the standard implementation.  Locked mode
                # fails closed (better safe than silent).  Otherwise warn
                # once and let the launch proceed with the at-rest global
                # payload from os.environ.
                if cfg is not None and cfg.locked:
                    desc = _describe_subprocess_launch(event, args)
                    logger.warning(
                        "tethered: blocked subprocess launch in locked mode — "
                        "could not locate subprocess._execute_child frame for "
                        "scope env injection: %s",
                        desc,
                    )
                    raise SubprocessBlocked(
                        event,
                        f"{desc} — could not locate subprocess._execute_child frame; "
                        "scope subprocess propagation unavailable on this build "
                        "and locked mode requires fail-closed behavior",
                    )
                logger.warning(
                    "tethered: scope subprocess propagation unavailable on this "
                    "build (no subprocess._execute_child frame in the call stack); "
                    "child will inherit only the global policy"
                )
            else:
                new_env = _build_per_launch_env(event, args, scope_stack, cfg)
                if not _inject_scope_env(frame, new_env) and cfg is not None and cfg.locked:
                    desc = _describe_subprocess_launch(event, args)
                    raise SubprocessBlocked(
                        event,
                        f"{desc} — frame-locals mutation failed; locked mode "
                        "requires fail-closed behavior",
                    )
        return

    # Non-auto-inheriting launch (os.system, external executable, Python
    # with ``-S``).  Scope cannot propagate through these paths
    # (no env channel to inject into), but external_subprocess_policy still
    # applies when a global config is present.  Scope-only without global:
    # nothing to enforce here, return silently.
    if cfg is None:
        return

    sp = cfg.external_subprocess_policy
    if sp == "allow":
        return

    desc = _describe_subprocess_launch(event, args)

    if sp == "warn":
        logger.warning("tethered: external subprocess launch detected: %s", desc)
        return

    # sp == "block"
    logger.warning("tethered: blocked external subprocess launch: %s", desc)
    raise SubprocessBlocked(event, desc)


def _is_open_for_write(args: tuple[Any, ...]) -> bool:
    """Inspect an ``open`` audit event's args and return True for write/append/truncate modes.

    Audit args layout: ``(path, mode, flags)``.  ``mode`` is a str (e.g. ``"rb"``,
    ``"w"``, ``"a+"``, or ``""`` when ``os.open`` was called directly).  ``flags``
    is the integer ``O_*`` bitmask.  Treat the open as write-capable if either
    indicator suggests it.
    """
    mode = args[1] if len(args) >= 2 else None
    flags = args[2] if len(args) >= 3 else None
    if isinstance(mode, str) and any(c in mode for c in "wax+"):
        return True
    if isinstance(flags, int):
        # O_WRONLY = 1, O_RDWR = 2, O_TRUNC, O_CREAT — any write-capable bit
        write_bits = os.O_WRONLY | os.O_RDWR | getattr(os, "O_TRUNC", 0) | getattr(os, "O_CREAT", 0)
        if flags & write_bits:
            return True
    return False


def _path_matches_pth(target: Any, cached: str) -> bool:
    """Return True if ``target`` (str/bytes/PathLike) refers to the cached ``tethered.pth`` path."""
    if not cached:
        return False
    if not isinstance(target, (str, bytes, os.PathLike)):
        return False
    try:
        target_str = os.fsdecode(target)
    except (TypeError, ValueError):
        return False
    return os.path.normcase(os.path.normpath(os.path.abspath(target_str))) == cached


def _handle_pth_fs_op(cfg: _Config, event: str, args: tuple[Any, ...]) -> None:
    """Refuse Python-level deletion, rename, overwrite, or chmod of ``tethered.pth`` in locked mode.

    Catches:

    - ``os.remove`` (also fired by ``os.unlink`` / ``pathlib.Path.unlink`` /
      ``shutil.rmtree`` — they all alias to the same audit event);
    - ``os.rename`` (move-away or replace-with — also fired by ``os.replace``);
    - ``open`` with a write-capable mode (``shutil.copy``, ``Path.write_*``,
      etc. all flow through this);
    - ``os.chmod`` (a permission-strip attack: ``os.chmod(path, 0)`` makes
      the file unreadable, so site.py silently skips it on POSIX → next
      interpreter has no auto-activation).

    The cached path is computed at ``activate()`` time; if it's empty
    (``tethered.__file__`` unavailable, e.g. frozen interpreter), the
    hook is a no-op.

    No effect outside locked mode.  ``ctypes`` calling libc ``unlink`` /
    ``rename`` / ``open`` / ``chmod`` directly bypasses the audit event,
    as does ``os.truncate`` (no audit event) and external tools spawned via
    ``subprocess`` (mitigated by ``external_subprocess_policy="block"``).  See the
    threat-model section of the README.
    """
    if not cfg.locked or not cfg._pth_path:
        return
    if event == "os.remove":
        target = args[0] if args else None
        if _path_matches_pth(target, cfg._pth_path):
            logger.warning("tethered: blocked deletion of %s", cfg._pth_path)
            raise SubprocessBlocked(event, f"refused deletion of {cfg._pth_path} in locked mode")
    elif event == "os.rename":
        src = args[0] if args else None
        dst = args[1] if len(args) >= 2 else None
        if _path_matches_pth(src, cfg._pth_path) or _path_matches_pth(dst, cfg._pth_path):
            logger.warning("tethered: blocked rename touching %s", cfg._pth_path)
            raise SubprocessBlocked(
                event, f"refused rename touching {cfg._pth_path} in locked mode"
            )
    elif event == "open":
        target = args[0] if args else None
        if _path_matches_pth(target, cfg._pth_path) and _is_open_for_write(args):
            logger.warning("tethered: blocked write-open of %s", cfg._pth_path)
            raise SubprocessBlocked(event, f"refused write-open of {cfg._pth_path} in locked mode")
    elif event == "os.chmod":
        target = args[0] if args else None
        if _path_matches_pth(target, cfg._pth_path):
            logger.warning("tethered: blocked chmod of %s", cfg._pth_path)
            raise SubprocessBlocked(event, f"refused chmod of {cfg._pth_path} in locked mode")


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
        label: Optional human-readable label for this scope.  Appears in
            log messages and as ``EgressBlocked.scope_label`` when this
            scope produces a block, so library authors can attribute
            blocks to a specific call site (e.g.
            ``label="WeatherClient.get_forecast"``).  Defaults to an
            auto-derived ``"scope(<first 3 allow rules>)"`` summary.
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
        label: str | None = None,
    ) -> None:
        _validate_allow(allow)
        _validate_bool(allow_localhost, "allow_localhost")
        _validate_bool(log_only, "log_only")
        _validate_bool(fail_closed, "fail_closed")
        _validate_callback(on_blocked)
        _validate_optional_str(label, "label")
        if label is None:
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


def _build_integrity_snapshot(cfg: _Config) -> list[tuple[object, str, bool]]:
    """Build a snapshot of critical object identities for the C guardian.

    Each entry is ``(owner, attr_name, check_code)`` where ``check_code``
    indicates whether the ``__code__`` attribute should also be verified.

    Snapshots ALL slots on ``_Config`` and ``AllowPolicy`` rather than a
    hand-picked list, so new fields are automatically protected.
    """
    entries: list[tuple[object, str, bool]] = []
    this = sys.modules[__name__]
    policy = cfg.policy
    policy_cls = type(policy)

    # All _Config fields (detects object.__setattr__ on frozen dataclass)
    for attr in _Config.__slots__:
        entries.append((cfg, attr, False))

    # All AllowPolicy internals (detects in-place mutation of rule sets)
    for attr in AllowPolicy.__slots__:
        entries.append((policy, attr, False))

    # Policy matching methods (function + bytecode)
    for method in ("is_allowed", "_check_hostname", "_check_ip"):
        entries.append((policy_cls, method, True))

    # Core enforcement handlers (function + bytecode)
    for func in (
        "_audit_hook",
        "_handle_getaddrinfo",
        "_handle_connect",
        "_fallback_resolve",
        "_handle_dns_lookup",
        "_check_scopes",
        "_enforce_scope_block",
        "_handle_subprocess",
        "_handle_pth_fs_op",
        # Scope subprocess propagation helpers — protect them so an
        # attacker can't replace _inject_scope_env with a no-op (which
        # would defeat scope inheritance silently in locked mode).
        "_find_execute_child_frame",
        "_inject_scope_env",
        "_build_per_launch_env",
        "_serialize_scope",
        "_build_env_payload",
        "_is_auto_inheriting_python_launch",
        "_parse_windows_cmdline",
    ):
        entries.append((this, func, True))

    # Exception class identity
    entries.append((this, "EgressBlocked", False))
    entries.append((this, "SubprocessBlocked", False))

    # Event filter sets (prevents silent removal of enforcement categories)
    for attr in (
        "_CONNECT_EVENTS",
        "_DNS_EVENTS",
        "_SUBPROCESS_EVENTS",
        "_PTH_FS_EVENTS",
    ):
        entries.append((this, attr, False))

    return entries


def activate(
    *,
    allow: list[str],
    log_only: bool = False,
    fail_closed: bool = False,
    allow_localhost: bool = True,
    on_blocked: Callable[[str, int | None], None] | None = None,
    locked: bool = False,
    lock_token: object | None = None,
    external_subprocess_policy: str = "warn",
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
            Compared by identity (``is``), not equality.  Must not be a
            ``str``, ``int``, ``float``, ``bytes``, or ``bool`` — CPython
            interns these types, so separate literals can share identity
            and defeat the lock.  Use ``object()`` or a custom instance.
        external_subprocess_policy: Controls parent-side enforcement for
            *external* subprocess launches — non-Python tools, different
            Python interpreters, or ``sys.executable`` launched with the
            ``-S`` flag that disables ``site.py``.  Regular Python
            children of ``sys.executable`` auto-inherit the policy via
            ``tethered.pth`` and are unaffected by this setting.
            ``"warn"`` (default) — log a warning on every external launch
            (the dep-shells-out-to-curl signal you'd want for supply-chain
            visibility).  ``"allow"`` — silent (set this if your workload
            legitimately shells out frequently and the warnings are noise).
            ``"block"`` — refuse all external launches.

    Raises:
        RuntimeError: If ``locked=True`` but the C guardian extension is
            not available.
        TypeError: If ``lock_token`` is an internable type.
        ValueError: If ``locked=True`` is used without ``lock_token``,
            or if ``external_subprocess_policy`` is not a recognized value.
        TetheredLocked: If a locked policy is active and the correct
            ``lock_token`` is not provided.
    """
    global _config, _guardian_token_id

    _validate_allow(allow)
    _validate_bool(log_only, "log_only")
    _validate_bool(fail_closed, "fail_closed")
    _validate_bool(allow_localhost, "allow_localhost")
    _validate_bool(locked, "locked")
    _validate_callback(on_blocked)

    if external_subprocess_policy not in _EXTERNAL_SUBPROCESS_POLICIES:
        msg = (
            f"external_subprocess_policy must be one of {sorted(_EXTERNAL_SUBPROCESS_POLICIES)}, "
            f"got {external_subprocess_policy!r}"
        )
        raise ValueError(msg)

    # pragma: no cover — C extension is required; build fails without it
    if locked and _c_guardian is None:  # pragma: no cover
        msg = (
            "tethered: locked=True requires the C guardian extension, which is "
            "not available. This indicates a broken installation — reinstall tethered."
        )
        raise RuntimeError(msg)

    if locked and lock_token is None:
        msg = "tethered: lock_token is required when locked=True"
        raise ValueError(msg)

    if locked and isinstance(lock_token, (str, int, float, bytes, bool)):
        msg = (
            "lock_token must not be a str, int, float, bytes, or bool — "
            "these types are interned by CPython, so separate literals can "
            "share identity and defeat the lock. Use object() or a custom instance."
        )
        raise TypeError(msg)

    policy = AllowPolicy(allow, allow_localhost=allow_localhost)
    global_payload_dict = _build_global_payload_dict(
        policy,
        log_only=log_only,
        fail_closed=fail_closed,
        external_subprocess_policy=external_subprocess_policy,
        locked=locked,
    )
    serialized_payload = _build_env_payload(global_payload_dict, ())
    pth_path = _compute_pth_path()
    local_hostname = _capture_local_hostname()
    cfg = _Config(
        policy=policy,
        log_only=log_only,
        fail_closed=fail_closed,
        on_blocked=on_blocked,
        locked=locked,
        lock_token=lock_token if locked else None,
        external_subprocess_policy=external_subprocess_policy,
        _serialized_payload=serialized_payload,
        _global_payload_dict=global_payload_dict,
        _pth_path=pth_path,
        _local_hostname=local_hostname,
    )

    token_id = id(lock_token) if lock_token is not None else 0

    with _state_lock:
        # Check lock: C guardian is source of truth when available
        if _c_guardian is not None and _c_guardian.is_active():
            if not _c_guardian.check_token(token_id):
                raise TetheredLocked
        else:  # pragma: no cover — fallback when C guardian is unavailable
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
            _allowed_hostnames.clear()

    # Manage C guardian for tamper-resistant locked enforcement
    if _c_guardian is not None:
        if locked:
            snapshot = _build_integrity_snapshot(cfg)
            try:
                _c_guardian.activate(cfg, EgressBlocked, token_id, snapshot)
            except RuntimeError:  # pragma: no cover — defensive; check_token pre-validates
                raise TetheredLocked from None
            _guardian_token_id = token_id
        elif _c_guardian.is_active():
            try:
                _c_guardian.deactivate(token_id)
            except RuntimeError:  # pragma: no cover — defensive; check_token pre-validates
                raise TetheredLocked from None
            _guardian_token_id = 0

    _install_hook()
    # Propagate the policy to spawn-mode child processes via env var.  The
    # tethered.pth shipped at the top of site-packages reads this in any
    # Python interpreter that has tethered installed and re-engages tethered
    # with the same policy.  Fork-mode children inherit tethered state
    # directly via the OS fork() copy and don't need this.
    _propagate_policy_to_env(cfg)
    # Surface a warning if the auto-propagation hook isn't where we expect.
    # Without it, child processes spawned via subprocess / multiprocessing
    # silently bypass tethered, and locked-mode FS-tamper protection has no
    # real target.  Typical cause: editable install (``pip install -e .``).
    if not pth_path or not os.path.isfile(pth_path):
        logger.warning(
            "tethered: tethered.pth not found at %s — child processes spawned "
            "via subprocess.run / multiprocessing / ProcessPoolExecutor will "
            "NOT auto-inherit the policy.%s This is typical for editable "
            "installs (pip install -e .); reinstall normally for full coverage.",
            pth_path or "<unresolved>",
            (
                " Locked-mode FS-tamper protection on tethered.pth is also unavailable."
                if locked
                else ""
            ),
        )
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

    token_id = id(lock_token) if lock_token is not None else 0

    with _state_lock:
        # Check lock: C guardian is source of truth when available
        if _c_guardian is not None and _c_guardian.is_active():
            try:
                _c_guardian.deactivate(token_id)
            except RuntimeError:
                raise TetheredLocked from None
        else:  # pragma: no cover — fallback when C guardian is unavailable
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
            _allowed_hostnames.clear()

    # Clear the propagation env var so future child processes don't inherit
    # a stale policy.
    _clear_policy_from_env()
    logger.info("tethered: deactivated")


def _serialize_network_rule(rule: Any) -> str:
    """Serialize a ``_NetworkRule`` for round-tripping through child processes.

    Plain ``f"{network}:{port}"`` is unambiguous for IPv4 (``10.0.0.0/8:5432``)
    but ambiguous for IPv6 — the address itself contains colons, so the
    parser cannot tell where the address ends and the port begins.  Bracket
    IPv6 networks when a port is present so the serialized form matches the
    bracketed syntax accepted by ``AllowPolicy`` (``[2001:db8::]/32:443``).
    """
    if rule.port is None:
        return str(rule.network)
    if rule.network.version == 6:
        addr, _, prefix = str(rule.network).partition("/")
        bracketed = f"[{addr}]/{prefix}" if prefix else f"[{addr}]"
        return f"{bracketed}:{rule.port}"
    return f"{rule.network}:{rule.port}"


# Environment variable used to propagate the active tethered policy to child
# processes.  The parent's activate() populates it; deactivate() clears it.
# Spawn-mode children with tethered installed read it via tethered.pth →
# tethered._autoactivate on interpreter startup and re-engage tethered with
# the same policy.  Fork-mode children inherit tethered state directly via
# the OS fork() copy and don't need this env var.
_CHILD_POLICY_ENV = "_TETHERED_CHILD_POLICY"


def _build_global_payload_dict(
    policy: AllowPolicy,
    *,
    log_only: bool,
    fail_closed: bool,
    external_subprocess_policy: str,
    locked: bool,
) -> dict[str, Any]:
    """Build the canonical ``global`` payload child processes consume.

    This is the byte-checked inner half of ``_TETHERED_CHILD_POLICY``.

    ``on_blocked`` and ``lock_token`` are NOT propagated.  Callbacks can't
    cross process boundaries (function identity).  Lock tokens are identity-
    compared and can't survive serialization — each child re-engages locked
    mode (if requested) with its own fresh per-process token.
    """
    return {
        "allow": list(policy._exact_hosts_any_port)
        + [f"{h}:{p}" for h, p in policy._exact_hosts]
        + [r.pattern if r.port is None else f"{r.pattern}:{r.port}" for r in policy._host_rules]
        + [_serialize_network_rule(r) for r in policy._network_rules],
        "allow_localhost": policy._allow_localhost,
        "log_only": log_only,
        "fail_closed": fail_closed,
        "external_subprocess_policy": external_subprocess_policy,
        "locked": locked,
    }


def _serialize_scope(scope_cfg: _ScopeConfig) -> dict[str, Any]:
    """Serialize a ``_ScopeConfig`` for cross-process propagation.

    Mirrors :func:`_build_global_payload_dict`.  ``on_blocked`` is not
    propagated (function identity can't cross process boundaries).
    """
    policy = scope_cfg.policy
    return {
        "allow": list(policy._exact_hosts_any_port)
        + [f"{h}:{p}" for h, p in policy._exact_hosts]
        + [r.pattern if r.port is None else f"{r.pattern}:{r.port}" for r in policy._host_rules]
        + [_serialize_network_rule(r) for r in policy._network_rules],
        "allow_localhost": policy._allow_localhost,
        "log_only": scope_cfg.log_only,
        "fail_closed": scope_cfg.fail_closed,
        "label": scope_cfg.label,
    }


def _build_env_payload(
    global_dict: dict[str, Any] | None,
    scope_stack: tuple[_ScopeConfig, ...],
) -> str:
    """Build the JSON env value: ``{"global": <dict|null>, "scopes": [<dicts>]}``.

    ``global_dict`` is ``None`` only in the scope-only case (no
    :func:`activate` has been called); the child's :mod:`_autoactivate`
    detects ``null`` and skips the activate step, applying scopes only.

    Used for both the at-rest value (empty scopes) written by
    :func:`_propagate_policy_to_env` and the per-launch values built by
    :func:`_handle_subprocess` when scopes are active.
    """
    return json.dumps(
        {
            "global": global_dict,
            "scopes": [_serialize_scope(s) for s in scope_stack],
        }
    )


def _build_child_policy_payload(cfg: _Config) -> dict[str, Any]:
    """Test compatibility helper — returns the canonical ``global`` dict.

    Production code reads ``cfg._global_payload_dict`` directly; this wrapper
    rebuilds it from cfg fields so tests that construct ``_Config`` without
    populating the field continue to work.
    """
    return _build_global_payload_dict(
        cfg.policy,
        log_only=cfg.log_only,
        fail_closed=cfg.fail_closed,
        external_subprocess_policy=cfg.external_subprocess_policy,
        locked=cfg.locked,
    )


def _compute_pth_path() -> str:
    """Compute the absolute, normalized path of the ``tethered.pth`` auto-activation hook.

    Locates ``tethered.pth`` as a sibling of the ``tethered`` package directory —
    ``setup.py``'s ``build_py_with_pth`` lands the ``.pth`` directly next to the
    package on install, so the parent of ``tethered.__file__``'s directory is
    the site-packages that bootstraps THIS tethered installation.  This is
    strictly more correct than ``sysconfig.get_path("purelib")`` for ``--user``
    installs and other schemes where the active site-packages diverges from
    the default purelib.

    Returns ``""`` if ``tethered.__file__`` is unavailable (frozen / embedded
    interpreter, namespace-package edge cases).  The locked-mode FS hook is
    a no-op when the path is empty.
    """
    import tethered

    pkg_init = getattr(tethered, "__file__", None)
    if pkg_init is None:
        return ""
    site_packages = os.path.dirname(os.path.dirname(pkg_init))
    return os.path.normcase(
        os.path.normpath(os.path.abspath(os.path.join(site_packages, "tethered.pth")))
    )


def _capture_local_hostname() -> str:
    """Return the normalized local hostname for the self-introspection exemption.

    Captured at ``activate()`` time from ``socket.gethostname()`` (via the
    C-level ``_socket`` module to avoid pulling in the high-level ``socket``
    module).  Used by ``_handle_dns_lookup`` and ``_handle_getaddrinfo`` to
    short-circuit the policy check when the lookup target equals this value
    — letting ``socket.getfqdn()`` and friends introspect the machine's own
    name without raising ``EgressBlocked``.

    Returns ``""`` when ``gethostname()`` is unavailable, returns nothing,
    or raises (frozen interpreter, sandboxed environment).  An empty value
    disables the exemption — a non-empty hostname argument never compares
    equal to ``""``.
    """
    try:
        raw = _csocket.gethostname()
    except Exception:  # pragma: no cover — defensive; gethostname rarely raises
        return ""
    if not isinstance(raw, str) or not raw:  # pragma: no cover — defensive
        return ""
    return _normalize_host(raw)


def _propagate_policy_to_env(cfg: _Config) -> None:
    """Populate ``_TETHERED_CHILD_POLICY`` so child processes inherit the policy."""
    os.environ[_CHILD_POLICY_ENV] = cfg._serialized_payload


def _clear_policy_from_env() -> None:
    """Remove ``_TETHERED_CHILD_POLICY`` so future children don't inherit a stale policy."""
    os.environ.pop(_CHILD_POLICY_ENV, None)
