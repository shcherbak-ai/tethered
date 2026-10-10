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
import operator
import os
import reprlib
import sys
import threading
import types
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

from tethered._policy import AllowPolicy, _could_be_ip, _normalize_host

try:
    from tethered import _guardian as _c_guardian
except ImportError:  # pragma: no cover
    _c_guardian = None

logger = logging.getLogger("tethered")

# Maximum number of IP -> hostname entries to retain.
_IP_MAP_MAX_SIZE = 4096

# Maximum number of hostnames remembered per IP address.  Several names can
# share one address (CDNs, cloud API front ends, load balancers), so one name
# per address is not enough; bounded so per-connect work stays a small constant.
_IP_MAP_MAX_NAMES = 8


def _rebuild_exception(cls: type[BaseException], args: tuple[Any, ...]) -> BaseException:
    """Recreate a pickled or copied policy exception without calling ``__init__``.

    ``BaseException.__reduce__`` rebuilds an exception as ``cls(*self.args)``.
    ``EgressBlocked`` and ``SubprocessBlocked`` hand ``RuntimeError`` a single
    formatted message but take other positional parameters themselves, so
    that call raises ``TypeError`` — in the process *receiving* the pickle.
    A blocked call in a pool worker then breaks the pool
    (``ProcessPoolExecutor``) or never delivers a result
    (``multiprocessing.Pool``) instead of raising in the parent.

    ``BaseException.__new__`` stores ``args`` by itself, and the attributes
    travel as pickle state, so nothing is lost by skipping ``__init__`` —
    which also keeps this correct for subclasses, whatever signature their
    constructor has.
    """
    return cls.__new__(cls, *args)


class EgressBlocked(RuntimeError):
    """Raised when a network connection is blocked by tethered policy."""

    def __init__(
        self,
        host: str,
        port: int | None,
        *,
        resolved_from: str | None = None,
        scope_label: str | None = None,
        scope_hint: str | None = None,
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
        # Optional actionable guidance carried from the deepest hinted
        # ``scope()`` on the stack at block-time (whitespace-normalized at
        # scope construction).  ``None`` when no hinted scope was active.
        # Surfaces in the default message on its own line as ``Hint: ...``.
        # Named ``scope_hint`` to mirror ``scope_label`` — both are scope-
        # derived; ``activate()`` has no hint API by design.
        self.scope_hint = scope_hint

        msg = f"Blocked by tethered: {host}"
        if port is not None:
            msg += f":{port}"
        if resolved_from and resolved_from != host:
            msg += f" (resolved from {resolved_from})"
        msg += " is not in the allow list"
        if scope_label:
            msg += f" (blocked by {scope_label})"
        if scope_hint:
            msg += f"\nHint: {scope_hint}"
        super().__init__(msg)

    def __reduce__(self) -> tuple[Any, ...]:
        # Picklable and copyable with every attribute — see _rebuild_exception.
        return _rebuild_exception, (type(self), self.args), self.__dict__


class TetheredLocked(RuntimeError):
    """Raised when a locked policy refuses deactivation or replacement."""

    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message
            or (
                "tethered: deactivate() blocked — policy is locked. "
                "Pass the same lock_token to deactivate() to unlock."
            )
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

    def __reduce__(self) -> tuple[Any, ...]:
        # Picklable and copyable with every attribute — see _rebuild_exception.
        return _rebuild_exception, (type(self), self.args), self.__dict__


# ── Immutable config bundle ───────────────────────────────────────
# All per-activation state is bundled into a single frozen object that is
# swapped atomically.  This eliminates the class of TOCTOU bugs where
# _policy, _log_only, and _on_blocked could be read at different times
# and see inconsistent state: a hook reads ``_config`` once and works from
# that one object.  (Nothing here has been validated without the GIL.  The
# C guardian does not declare free-threading support, so on a free-threaded
# build CPython re-enables the GIL when it is imported.)


@dataclass(frozen=True, slots=True)
class _Config:
    """Immutable configuration bundle swapped atomically on activate/deactivate."""

    policy: AllowPolicy
    log_only: bool = False
    fail_closed: bool = False
    on_blocked: Callable[[str, int | None], None] | None = field(default=None, repr=False)
    locked: bool = False
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
    # Optional whitespace-normalized actionable guidance attached to any
    # ``EgressBlocked`` raised while this scope is on the stack and is the
    # deepest hinted scope.  Empty string here means "no hint set" — the
    # ``scope()`` constructor coerces None / empty / whitespace-only inputs
    # to ``""``.  User-facing only: tampering with this field changes the
    # message, never enforcement, so it is not part of the locked-mode
    # integrity snapshot (matches the treatment of ``label``).
    hint: str = ""


# ── Module-level state ──────────────────────────────────────────────
# The audit hook is installed once. activate()/deactivate() swap the config.

# Guards the one-time installation of the audit hook (_install_hook()).
_state_lock = threading.Lock()

# Serializes activate() and deactivate() from start to finish, so that the
# config, the C guardian's state, the installed hook and the child-policy
# environment variable always change together and describe the same policy
# when either call returns.  Re-entrant: the environment writes made inside
# a transition raise audit events that re-enter the hook on the same thread.
# The launch hook takes it as well, for the one write it makes itself
# (_reassert_policy_env).  (_state_lock is not re-entrant; it is never held
# while this lock is being acquired.)
_lifecycle_lock = threading.RLock()


class _UnsharedClaim:
    """Stands in for the C guardian's activation claim where the extension is missing.

    No policy can be locked then, and there is nowhere to keep a claim that
    the other interpreters of the process would see.  This one makes the
    threads of its own interpreter take turns and nothing more: it keeps no
    count for ``held()`` / ``restore()``, so a ``with`` on it is as safe as
    a ``with`` on any lock.
    """

    __slots__ = ("_lock",)

    def __init__(self) -> None:
        self._lock = threading.RLock()

    def __enter__(self) -> None:
        self._lock.acquire()

    def __exit__(self, *exc_info: object) -> None:
        self._lock.release()

    def held(self) -> int:
        return 0

    def restore(self, held: int) -> None:
        pass


# What _lifecycle_lock is within one interpreter, this is across all the
# interpreters of the process: whoever holds it is the one that may write
# the child-policy variable and commit a policy.  The variable is shared by
# every interpreter, and a write to it is under way from its audit event
# until the environment is changed, with every audit hook running in
# between.  Without the claim, an interpreter's write could land after
# another interpreter had published its own policy and locked it.  The
# claim lives in the C guardian (see "The activation claim" there); taking
# it waits, with the GIL released, while another thread holds it, and the
# holding thread may take it again.
#
# Order: _lifecycle_lock first, then the claim, everywhere (activate(),
# deactivate(), and the launch hook in _reassert_policy_env).
#
# A claim that is never given up stops every later transition in every
# interpreter, so each use is a ``with`` inside a ``try`` whose ``finally``
# gives up whatever the thread holds beyond what it held before:
#
#     held = _activation_claim.held()
#     try:
#         with _lifecycle_lock, _activation_claim:
#             ...
#     finally:
#         _activation_claim.restore(held)
#
# The ``with`` alone is not enough on every version.  Python 3.14 raises a
# pending exception (a KeyboardInterrupt, one set from another thread)
# after ``__enter__`` has returned and before the block is entered, and
# then never calls ``__exit__``.
_activation_claim = _UnsharedClaim() if _c_guardian is None else _c_guardian.activation_claim

_config: _Config | None = None

# What activate() / deactivate() say in an interpreter that neither took
# the lock nor joined it.  The usual advice, to pass the lock token, would
# send its user the wrong way: the token lives in another interpreter.
_OUTSIDE_THE_LOCK_MSG = (
    "tethered: {call} blocked — a policy is locked by another interpreter of this "
    "process, and this interpreter is outside that lock: it existed before the lock "
    "was taken, or did not join it when it started. It can neither change nor release "
    "that policy, whatever token it passes. Take the lock before the other "
    "interpreters of the process are created."
)

_TAMPERED_POLICY_MSG = (
    "tethered: the locked policy has failed its integrity check, so it can be "
    "neither replaced nor deactivated — re-activating would take a fresh snapshot "
    "of whatever has been put in place. Restart the process."
)

# IP -> hostnames mapping from intercepted getaddrinfo calls.  The key is the
# canonical text of the address (see ``_canonical_ip``); the value is the
# hostnames that resolved to it, most recent first, at most
# ``_IP_MAP_MAX_NAMES`` (see ``_record_ip_name``).  A connect to the address
# is allowed if any of those names, or the raw IP, is allowed.
# OrderedDict for LRU eviction: move_to_end() on access, popitem(last=False) to evict.
_ip_to_hostname: collections.OrderedDict[str, tuple[str, ...]] = collections.OrderedDict()
_ip_map_lock = threading.Lock()

# Recently-allowed hostnames (lookups that the global policy and every
# enforcing scope let through).  Used by ``_fallback_resolve`` to repair the
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

# Number of scope entries currently active anywhere in the process, over all
# contexts.  A scope stack is context-local, so code running in another thread
# cannot see it; this count is how the audit hook knows that a lookup made in a
# context without scopes may still be on a scope's behalf (see _audit_hook).
# Written only through ``_adjust_scope_count``; read without the lock.
_active_scope_count: int = 0
_scope_count_lock = threading.Lock()


def _adjust_scope_count(delta: int) -> None:
    """Add ``delta`` to the process-wide count of active scope entries."""
    global _active_scope_count
    with _scope_count_lock:
        _active_scope_count = max(0, _active_scope_count + delta)


def _push_scope(scope_cfg: _ScopeConfig) -> None:
    """Push ``scope_cfg`` onto the current context's scope stack."""
    _scopes.set((*_scopes.get(), scope_cfg))
    _adjust_scope_count(1)


def _pop_scope(scope_cfg: _ScopeConfig) -> None:
    """Remove ``scope_cfg`` from the current context's scope stack.

    Removes this scope's own entry — its last occurrence, by identity — and
    leaves every other entry in place.  Restoring a snapshot taken at entry
    (``ContextVar.reset``) is wrong as soon as scopes exit out of order, which
    a generator suspended inside ``with scope():`` makes ordinary: the
    restore would drop scopes entered since and resurrect ones already gone.
    """
    stack = _scopes.get()
    for index in range(len(stack) - 1, -1, -1):
        if stack[index] is scope_cfg:
            _scopes.set(stack[:index] + stack[index + 1 :])
            break
    else:
        # Exited in a different context from the one that entered it (a
        # generator stepped in several contexts, an async generator closed
        # by the event loop).  There is nothing to remove here: the entry
        # stays with the context that holds it, which is the only place the
        # scope was ever enforced.
        logger.warning(
            "tethered: %s was exited in a context that did not enter it; a scope is "
            "enforced only in the context that entered it, so code run elsewhere "
            "inside its block (e.g. a generator stepped across contexts) was not covered",
            scope_cfg.label,
        )
    _adjust_scope_count(-1)


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


# Types whose instances cannot serve as a lock token.  The token is compared
# by identity, so it must be an object of which nobody can obtain a second
# reference just by writing down an equal value.  Singletons (``None``,
# ``Ellipsis``, ``NotImplemented``, ``True``/``False``, the empty tuple, the
# empty frozenset) and immutable values that CPython interns, caches or
# constant-folds (``str``, ``bytes``, numbers, tuples, frozensets) fail that
# test.
_UNSAFE_LOCK_TOKEN_TYPES = (
    str,
    bytes,
    bool,
    int,
    float,
    complex,
    tuple,
    frozenset,
    type(None),
    type(Ellipsis),
    type(NotImplemented),
)


def _validate_lock_token(lock_token: object) -> None:
    """Validate the ``lock_token`` of a ``locked=True`` activation."""
    if lock_token is None:
        msg = "tethered: lock_token is required when locked=True"
        raise ValueError(msg)
    if isinstance(lock_token, _UNSAFE_LOCK_TOKEN_TYPES):
        msg = (
            "lock_token must not be a str, int, float, complex, bytes, bool, tuple "
            "or frozenset, nor None, Ellipsis or NotImplemented — these are "
            "singletons or immutable values that CPython may intern or cache, so a "
            "separately created equal value can be the very same object and defeat "
            "the lock. Use object() or a custom instance."
        )
        raise TypeError(msg)


def _normalize_hint(value: object) -> str:
    """Validate and whitespace-normalize a ``hint=`` argument.

    Returns the normalized string, or ``""`` for ``None`` / empty / whitespace-only
    input.  Collapses runs of any whitespace (including embedded newlines) to a
    single space so multi-line literals render cleanly on the trailing
    ``Hint:`` line of an ``EgressBlocked`` message.  Raises ``TypeError`` for
    non-str, non-None inputs.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        msg = f"hint must be a str or None, got {type(value).__name__}"
        raise TypeError(msg)
    return " ".join(value.split())


# Hook installed flag
_hook_installed: bool = False

# Private audit event with which _install_hook() asks whether _audit_hook is
# really in the interpreter's hook list: sys.addaudithook() drops a hook that
# an existing hook refuses, and returns normally all the same.  The event
# carries a list, and the hook answers by appending to it.
_HOOK_PROBE_EVENT = "tethered.hook_probe"

_HOOK_REFUSED_MSG = (
    "tethered: its audit hook could not be installed — another audit hook in this "
    "process refused it, so nothing would be enforced. (A hook that raises "
    "RuntimeError for the 'sys.addaudithook' event makes sys.addaudithook() drop the "
    "new hook without reporting an error.) Install tethered's hook first, by calling "
    "tethered.activate() or entering a scope before that hook is added, or have that "
    "hook let tethered's through."
)

# Events that trigger connection enforcement.  These are raised by the socket
# object's own methods.  asyncio's ProactorEventLoop (the Windows default)
# connects and sends through _overlapped instead, which raises none of them —
# see _warn_if_proactor_loop.
_CONNECT_EVENTS = frozenset(
    (
        "socket.connect",  # also raised by connect_ex() in CPython
        "socket.sendto",
        "socket.sendmsg",
    )
)

# True while the one-time ProactorEventLoop warning may still be needed: only
# on Windows, and only until it has fired.  The check behind it therefore
# costs nothing on other platforms and nothing once the warning is out.
_proactor_warning_pending: bool = sys.platform == "win32"

# DNS resolution events to intercept outside getaddrinfo.
#
# ``socket.getnameinfo`` is deliberately absent.  Its audit event carries the
# address but not the flags, so a reverse lookup cannot be told apart from
# purely numeric formatting (``NI_NUMERICHOST``), which needs no DNS and which
# libraries call on every peer and local address.  Checking the event would
# refuse those calls for any address no rule names.
_DNS_EVENTS = frozenset(
    (
        "socket.gethostbyname",  # also raised by gethostbyname_ex()
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
        # Launches that never raise ``subprocess.Popen``: Windows
        # ``multiprocessing`` / ``ProcessPoolExecutor`` workers, and POSIX
        # spawn / forkserver workers on CPython 3.14+ (the first version to
        # raise ``_posixsubprocess.fork_exec``).  ``subprocess.Popen`` raises
        # them too, right after its own event.
        "_winapi.CreateProcess",
        "_posixsubprocess.fork_exec",
    )
)

# Events ``subprocess.Popen`` raises after ``subprocess.Popen`` for the same
# launch.  Handled only when they come from somewhere else.
_POPEN_NESTED_EVENTS = frozenset(
    (
        "_winapi.CreateProcess",
        "_posixsubprocess.fork_exec",
        "os.posix_spawn",
    )
)

# Native environment changes.  ``os.environ`` is a cache that does not see
# ``os.putenv()`` / ``os.unsetenv()``; both raise these events, and so do
# assignments and deletions through ``os.environ``.
_ENV_EVENTS = frozenset(("os.putenv", "os.unsetenv"))

# What _audit_hook tests for in place of _ENV_EVENTS: the hook probe shares
# that one membership test, so recognising it costs every other audit event
# in the process nothing.
_ENV_AND_PROBE_EVENTS = _ENV_EVENTS | {_HOOK_PROBE_EVENT}

_EXTERNAL_SUBPROCESS_POLICIES = frozenset(("allow", "warn", "block"))

# Locked-mode FS-tamper detection.  Refuses Python-level deletion, rename,
# overwrite, truncation, or chmod of tethered.pth (the auto-propagation
# hook).  No-op when locked mode is off.  ``os.unlink`` is intentionally
# absent — CPython aliases it to ``os.remove`` and fires the ``os.remove``
# audit event, never ``os.unlink``.  The ``os.chmod`` entry catches a
# permission-strip attack: ``os.chmod(path, 0)`` makes the file unreadable,
# so site.py silently skips it on POSIX → no auto-activation in the next
# interpreter.  ``os.truncate(path, 0)`` empties the file without opening
# it through an audited ``open``; CPython raises an ``os.truncate`` event
# for it (and for ``os.ftruncate``, which passes a file descriptor that
# cannot be matched against a path).
#
# ``_winapi.CopyFile2`` is how ``shutil.copy2`` (and ``copytree`` / ``move``
# built on it) writes its destination on Windows from Python 3.12: the file
# is replaced without an ``open`` event.
#
# ``os.link`` and ``os.symlink`` cannot be used against the ``.pth`` itself:
# both syscalls fail with ``EEXIST`` when the destination already exists, and
# the ``.pth`` is created during ``pip install`` and present at the moment
# this hook starts watching.  They are here for a name that does not exist.
# From Python 3.15 (PEP 829) ``site.py`` ignores the ``import`` line of
# ``tethered.pth`` when a ``tethered.start`` file sits beside it, whatever
# that file contains.  tethered ships no such file, so creating one disables
# auto-activation as surely as deleting the ``.pth`` — see
# :func:`_created_path` for the ways of creating it that are refused.
#
# The C guardian verifies the integrity snapshot on these same events before
# this hook runs (``classify_event`` in ``_guardian.c``), so a replaced
# ``_handle_pth_fs_op`` cannot wave an operation through.  An event added
# here must be added there too; ``tests/test_guardian.py`` checks that.
_PTH_FS_EVENTS = frozenset(
    (
        "os.remove",
        "os.rename",
        "open",
        "os.chmod",
        "os.truncate",
        "os.link",
        "os.symlink",
        "_winapi.CopyFile2",
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


def _canonical_ip(host: str) -> str | None:
    """Return the canonical text of an IP address, or ``None`` if ``host`` is not one.

    The IP map is keyed by this form when storing and when looking up, so that
    different spellings of one address meet: IPv6 compressed and lower-case,
    no scope ID (``fe80::1%eth0`` -> ``fe80::1``), and IPv4-mapped IPv6 as the
    IPv4 address (``::ffff:192.0.2.1`` -> ``192.0.2.1``).
    """
    if not _could_be_ip(host):
        return None
    if "%" in host:
        host = host.partition("%")[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if ip.version == 4:
        # ipaddress accepts a single spelling of an IPv4 address (four decimal
        # octets, no leading zeros), so the text that parsed is the canonical
        # one already; skipping str() keeps the connect hot path short.
        return host
    mapped = ip.ipv4_mapped
    return str(ip if mapped is None else mapped)


def _record_ip_name(ip: str, hostname: str) -> str:
    """Record that ``hostname`` resolved to ``ip``; return the map key used.

    Caller must hold ``_ip_map_lock``.  Keeps up to ``_IP_MAP_MAX_NAMES``
    hostnames per address, most recent first, and marks the address as the
    most recently used one (LRU across addresses).
    """
    key = _canonical_ip(ip) or ip
    names = _ip_to_hostname.get(key)
    if names is None:
        # LRU eviction: remove oldest entry when at capacity
        if len(_ip_to_hostname) >= _IP_MAP_MAX_SIZE:
            _ip_to_hostname.popitem(last=False)
        _ip_to_hostname[key] = (hostname,)
        return key
    if names[0] != hostname:
        others = tuple(name for name in names if name != hostname)
        _ip_to_hostname[key] = (hostname, *others)[:_IP_MAP_MAX_NAMES]
    _ip_to_hostname.move_to_end(key)
    return key


def _host_text(host: Any) -> str | None:
    """Return a socket host argument as ``str``, or ``None`` if tethered cannot read it.

    CPython's socket layer accepts ``str``, ``bytes`` and ``bytearray`` hosts and
    hands byte strings to the resolver unchanged, so they are read as ASCII.  A
    byte string that is not ASCII, and any other type, cannot be matched against
    an allow rule; the caller must treat that as "not allowed", never as
    "nothing to check".
    """
    if isinstance(host, str):
        return host
    if isinstance(host, (bytes, bytearray)):
        try:
            return host.decode("ascii")
        except UnicodeDecodeError:
            return None
    return None


def _extract_host_port(address: Any) -> tuple[str, int | None] | None:
    """Extract (host, port) from a socket address.

    Returns None when ``address`` is not a ``(host, port, ...)`` tuple tethered
    can read: an AF_UNIX path, another family's address shape, or an IP-family
    address whose host or port is unusable.  ``_handle_connect`` tells these
    apart with :func:`_is_ip_family` — the last case is refused, not allowed.

    Handles:
        AF_INET:  (host, port)
        AF_INET6: (host, port, flowinfo, scope_id)

    The host may be ``str``, ``bytes`` or ``bytearray`` and the port any object
    implementing ``__index__`` (``numpy.int64`` and the like) — every form
    CPython itself accepts.
    """
    if isinstance(address, tuple) and len(address) >= 2:
        host = address[0]
        if not isinstance(host, str):
            host = _host_text(host)
            if host is None:
                return None
        try:
            return (host, operator.index(address[1]))
        except Exception:  # TypeError, or whatever a custom __index__ raises
            return None
    return None


# Address families whose socket addresses are ``(host, port, ...)`` IP tuples.
# CPython parses AF_RDS and (FreeBSD) AF_DIVERT addresses exactly like AF_INET.
_IP_FAMILIES = frozenset(
    getattr(_csocket, name)
    for name in ("AF_INET", "AF_INET6", "AF_RDS", "AF_DIVERT")
    if hasattr(_csocket, name)
)


def _is_ip_family(sock: Any, address: Any) -> bool:
    """Return True if a connect/send event targets an IP-family socket.

    Decided by the socket object carried in the audit event.  Synthetic events
    (``sys.audit`` called without a socket) carry ``None``; those are judged by
    the address shape — a tuple of two or more items is an IP-family address.
    """
    family = getattr(sock, "family", None)
    if family is None:
        return isinstance(address, tuple) and len(address) >= 2
    return family in _IP_FAMILIES


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    """The single audit hook installed by tethered."""
    # socket.* is the hot path — handle and return early.
    if event.startswith("socket."):
        cfg = _config
        scope_stack = _scopes.get()

        # Nothing to enforce in this context: return at once.  One exception:
        # while a scope is active somewhere else in the process, a
        # getaddrinfo made here may be on that scope's behalf —
        # loop.getaddrinfo() runs socket.getaddrinfo in an executor thread,
        # which does not carry the caller's context.  That event falls
        # through to _handle_getaddrinfo, which with no config and no scopes
        # enforces nothing and only records the IP -> hostname mapping, so
        # the connect that follows in the scope's own context is matched to
        # the name and judged by that context's scopes.
        if (
            cfg is None
            and not scope_stack
            and (not _active_scope_count or event != "socket.getaddrinfo")
        ):
            return

        if event == "socket.getaddrinfo":
            _handle_getaddrinfo(cfg, scope_stack, args)
        elif event in _CONNECT_EVENTS:
            _handle_connect(cfg, scope_stack, event, args)
        elif event in _DNS_EVENTS:
            _handle_dns_lookup(cfg, scope_stack, event, args)
        elif _proactor_warning_pending and event == "socket.__new__":
            _warn_if_proactor_loop()
        return

    # Subprocess launches: parent-side enforcement (warn/block), locked-mode
    # payload-integrity check, and establishing the child's policy payload
    # in the launch environment.  Covers subprocess.Popen and the launches
    # that never raise it (multiprocessing workers).  Routed whenever there
    # is anything to enforce — global config OR an active scope chain.
    # Scope-only firing (cfg is None) is what makes scope propagation work
    # for libraries doing self-defense without app-level activate().
    if event in _SUBPROCESS_EVENTS:
        cfg = _config
        scope_stack = _scopes.get()
        if cfg is None and not scope_stack:
            return
        _handle_subprocess(cfg, event, args, scope_stack)
        return

    # Native changes to the policy variable that ``os.environ`` may not show,
    # and _install_hook() asking whether this hook is live.
    if event in _ENV_AND_PROBE_EVENTS:
        if event == _HOOK_PROBE_EVENT:
            args[0].append(True)
        else:
            _handle_env_change(event, args)
        return

    # Locked-mode-only tamper detection on FS access to tethered.pth.
    # ``open`` fires constantly during normal program operation, so
    # short-circuit on cfg.locked before doing any per-event work.
    cfg = _config
    if cfg is None or not cfg.locked:
        return
    if event in _PTH_FS_EVENTS:
        _handle_pth_fs_op(cfg, event, args)


def _proactor_loop_running() -> bool:
    """Return True if an asyncio Proactor event loop is running in this thread.

    asyncio is looked up in ``sys.modules``, never imported: if it (or its
    Proactor implementation) has not been imported, no such loop can be
    running.
    """
    asyncio_mod = sys.modules.get("asyncio")
    proactor_mod = sys.modules.get("asyncio.proactor_events")
    if asyncio_mod is None or proactor_mod is None:
        return False
    try:
        loop = asyncio_mod._get_running_loop()
        return isinstance(loop, proactor_mod.BaseProactorEventLoop)
    except Exception:  # a partially imported or replaced asyncio — not our loop
        return False


def _warn_if_proactor_loop() -> None:
    """Warn, once, that connect-time enforcement is unavailable on a Proactor loop.

    Called for a ``socket.__new__`` event while a policy or scope is active.
    ``ProactorEventLoop`` connects through ``_overlapped.ConnectEx`` (and sends
    datagrams through ``_overlapped.WSASendTo``), which raise no audit event
    tethered could act on, and an audit hook cannot add one.  The gap cannot be
    closed here, so it is at least made visible.
    """
    global _proactor_warning_pending
    if not _proactor_loop_running():
        return
    # Cleared before logging: a log handler may itself create a socket.
    _proactor_warning_pending = False
    logger.warning(
        "tethered: an asyncio ProactorEventLoop (the Windows default) is running. "
        "It connects and sends through overlapped I/O calls that raise no "
        "socket.connect / socket.sendto audit event, so connect-time enforcement "
        "is unavailable on this loop: only DNS-time hostname checks apply, and "
        "raw-IP destinations, port rules and scope() connect checks are NOT "
        "enforced. Run the event loop as asyncio.SelectorEventLoop for full "
        "enforcement."
    )


def _hint_from_stack(scope_stack: tuple[_ScopeConfig, ...]) -> str | None:
    """Return the deepest hinted scope's hint, or ``None``.

    "Deepest" means the rightmost (innermost) entry on the scope stack with
    a non-empty hint — irrespective of which scope's rule actually produced
    the block.  The deepest hinted scope is the most context-specific to the
    immediate caller, so its guidance is most likely to be actionable.
    """
    for sc in reversed(scope_stack):
        if sc.hint:
            return sc.hint
    return None


def _allows_any(policy: AllowPolicy, hosts: tuple[str, ...], port: int | None) -> bool:
    """Return True if ``policy`` allows any of ``hosts`` (already normalized) on ``port``."""
    for host in hosts:  # noqa: SIM110 — hot path; any(<genexpr>) costs a generator per call
        if policy.is_allowed(host, port, _normalized=True):
            return True
    return False


def _check_scopes(
    scope_stack: tuple[_ScopeConfig, ...],
    hosts: tuple[str, ...],
    port: int | None,
) -> list[_ScopeConfig]:
    """Check one destination against all active scopes.

    ``hosts`` holds the alternative, already-normalized names of a single
    destination: for a connect, the hostnames its address resolved from and
    the raw IP.  The alternatives are combined inside each scope — a scope
    allows the destination if it allows any one of them — and then every
    scope must allow.  A hostname-only scope and an IP-only scope can
    therefore both be satisfied by the same connect.

    Returns every _ScopeConfig that denies it, outermost first; empty if all
    allow.  All scopes are evaluated — a log-only scope that denies must not
    hide a denial by an enforcing scope elsewhere on the stack.  The caller
    passes each one to :func:`_enforce_scope_block` in order.
    """
    denying: list[_ScopeConfig] = []
    for sc in scope_stack:
        try:
            if not _allows_any(sc.policy, hosts, port):
                denying.append(sc)
        except Exception:
            if sc.fail_closed:
                denying.append(sc)
                continue
            logger.warning(
                "tethered: error checking %s for %s:%s, failing open",
                sc.label,
                "/".join(hosts),
                port,
                exc_info=True,
            )
    return denying


def _enforce_scope_block(
    sc: _ScopeConfig,
    host: str,
    port: int | None,
    event_desc: str,
    *,
    global_allowed: bool = False,
    resolved_from: str | None = None,
    scope_stack: tuple[_ScopeConfig, ...] = (),
) -> None:
    """Log and optionally raise for a scope-level block.

    Returns normally for a log-only scope, so the caller goes on to the next
    denying scope; raises for an enforcing one.
    """
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
        raise EgressBlocked(
            host,
            port,
            resolved_from=resolved_from,
            scope_label=sc.label,
            scope_hint=_hint_from_stack(scope_stack),
        )


def _deny_unreadable(
    cfg: _Config | None,
    scope_stack: tuple[_ScopeConfig, ...],
    event: str,
    value: Any,
) -> None:
    """Refuse a socket event whose host or address tethered cannot read.

    ``value`` is an IP-family socket address or a DNS host argument in a form
    that cannot be matched against any allow rule (a non-ASCII byte string, an
    unusable port, an unexpected type).  No rule can allow it, so every active
    layer denies it through its normal block path: log, ``on_blocked``, and
    raise unless that layer is log-only.
    """
    host = f"<unreadable {reprlib.repr(value)}>"
    what = event.split(".")[-1]

    if cfg is not None:
        logger.warning(
            "tethered: blocked %s for %s (cannot be checked against the allow list)", what, host
        )

        if cfg.on_blocked is not None:
            try:
                cfg.on_blocked(host, None)
            except Exception:
                logger.debug(
                    "tethered: on_blocked callback raised for %s",
                    host,
                    exc_info=True,
                )

        if not cfg.log_only:
            raise EgressBlocked(host, None, scope_hint=_hint_from_stack(scope_stack))

    for sc in scope_stack:
        _enforce_scope_block(sc, host, None, what, scope_stack=scope_stack)


def _remember_allowed_hostname(hostname: str) -> None:
    """Record ``hostname`` as a candidate for :func:`_fallback_resolve` (bounded LRU)."""
    with _ip_map_lock:
        if hostname in _allowed_hostnames:
            _allowed_hostnames.move_to_end(hostname)
        else:
            if len(_allowed_hostnames) >= _ALLOWED_HOSTNAMES_MAX_SIZE:
                _allowed_hostnames.popitem(last=False)
            _allowed_hostnames[hostname] = None


def _handle_dns_lookup(
    cfg: _Config | None,
    scope_stack: tuple[_ScopeConfig, ...],
    event: str,
    args: tuple[Any, ...],
) -> None:
    """Intercept gethostbyname/gethostbyaddr to enforce policy.

    These DNS resolution functions fire different audit events than getaddrinfo,
    so they must be intercepted separately to prevent DNS-based exfiltration.

    Audit event args for gethostbyname: (host,) — also raised by gethostbyname_ex
    Audit event args for gethostbyaddr: (host,)

    The host may be ``str``, ``bytes`` or ``bytearray``.  ``None`` and empty
    hosts name the local machine and are not checked.
    """
    host = args[0]
    if not isinstance(host, str):
        if host is None:
            return
        host = _host_text(host)
        if host is None:
            _deny_unreadable(cfg, scope_stack, event, args[0])
            return
    if not host:
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
                raise EgressBlocked(
                    host_lower, None, scope_hint=_hint_from_stack(scope_stack)
                ) from None
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
                raise EgressBlocked(host_lower, None, scope_hint=_hint_from_stack(scope_stack))

    # ── Scope checks ──
    # Every denying scope is reported; a log-only one returns and the loop
    # moves on, the first enforcing one raises.
    for blocking_scope in _check_scopes(scope_stack, (host_lower,), None):
        _enforce_scope_block(
            blocking_scope,
            host_lower,
            None,
            event,
            global_allowed=global_allowed,
            scope_stack=scope_stack,
        )

    # A forward lookup that the global policy and every enforcing scope let
    # through establishes connect-time identity, as getaddrinfo does: record
    # the name as a fallback candidate so that a connect to the address it
    # returned is matched back to it by _fallback_resolve.  The IP map itself
    # is not populated here — that needs a lookup of our own, and
    # _c_guardian.resolve only accepts _handle_getaddrinfo and
    # _fallback_resolve as callers.  Reverse lookups resolve an address, not
    # a name, so there is nothing to record for them.
    if event == "socket.gethostbyname" and global_allowed:
        _remember_allowed_hostname(host_lower)


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

    Also called with no config and no scopes, for a lookup made in a context
    that has neither while a scope is active elsewhere in the process (see
    ``_audit_hook``).  Then there is nothing to enforce and only the second
    responsibility applies: the name and its addresses are recorded.

    The host may be ``str`` or ``bytes``.  ``None`` and empty hosts name the
    local machine and are not checked.
    """
    host = args[0]
    if not isinstance(host, str):
        if host is None:
            return
        host = _host_text(host)
        if host is None:
            _deny_unreadable(cfg, scope_stack, "socket.getaddrinfo", args[0])
            return
    if not host:
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
                raise EgressBlocked(
                    host_lower, None, scope_hint=_hint_from_stack(scope_stack)
                ) from None
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
                raise EgressBlocked(host_lower, None, scope_hint=_hint_from_stack(scope_stack))
            # Log-only global denial: carry on to the scope checks — an
            # enforcing scope must still be able to refuse the lookup.

    # ── Scope checks (before candidate recording and IP map population) ──
    # Every denying scope is reported; a log-only one returns and the loop
    # moves on, the first enforcing one raises.
    for blocking_scope in _check_scopes(scope_stack, (host_lower,), None):
        _enforce_scope_block(
            blocking_scope,
            host_lower,
            None,
            "getaddrinfo",
            global_allowed=global_allowed,
            scope_stack=scope_stack,
        )
    # If _enforce_scope_block raised (an enforcing scope), we never reach here.
    # For log_only scopes, fall through to populate the IP map — without it,
    # connect-time enforcement can't map the resolved IP back to this hostname,
    # causing the *global* policy to hard-block a connection that the scope
    # only intended to log.

    if not global_allowed:
        # Denied by a log-only global policy: the lookup proceeds, but the name
        # is not recorded — neither as a fallback candidate nor in the IP map.
        return

    # Record the hostname for the connect-time fallback-resolve path.  Done
    # only here, after the global policy and every enforcing scope have let
    # the lookup through: a name one of them refused must never become a
    # candidate, or tethered itself would look it up later from
    # _fallback_resolve.  A name that only log-only scopes object to is
    # recorded, mirroring how _ip_to_hostname is populated below.
    _remember_allowed_hostname(host_lower)

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
        # The audit event ends there: the caller's flags are not part of it,
        # so this lookup is made without any.
        if _c_guardian is not None and _c_guardian.is_active():
            results = _c_guardian.resolve(host, port, family, socktype, proto, 0)
        else:
            results = _csocket.getaddrinfo(host, port, family, socktype, proto, 0)
        with _ip_map_lock:
            for _family, _socktype, _proto, _canonname, sockaddr in results:
                # sockaddr[0] is always str; cast for the type checker
                _record_ip_name(str(sockaddr[0]), host_lower)
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
    return different IP sets, leaving the connect-time IP unmapped.  It is
    also how an address obtained through ``gethostbyname`` /
    ``gethostbyname_ex`` is matched to its name: those lookups record a
    candidate here but no mapping.

    Returns the matching hostname (and enriches :data:`_ip_to_hostname`
    so future connects to the same IP take the fast path) on hit; returns
    ``None`` on miss.  Addresses are compared in canonical form (see
    :func:`_canonical_ip`).  Per-hostname resolve failures are swallowed and
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

    target_key = _canonical_ip(target_ip) or target_ip

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
                    if _record_ip_name(str(sockaddr[0]), hostname) == target_key:
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


def _allowed_by_every_layer(
    cfg: _Config | None,
    scope_stack: tuple[_ScopeConfig, ...],
    host: str,
    port: int | None,
) -> bool:
    """Return True when the global policy and every scope allow ``host`` as given.

    ``host`` must already be normalized.  A policy error counts as "not known
    to be allowed", which leaves the decision, and the reporting of the error,
    to the caller's normal path.
    """
    try:
        if cfg is not None and not cfg.policy.is_allowed(host, port, _normalized=True):
            return False
        return all(sc.policy.is_allowed(host, port, _normalized=True) for sc in scope_stack)
    except Exception:
        return False


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
        # Not an address tethered can read.  For AF_UNIX and other non-IP
        # families that is expected and there is nothing to check.  On an
        # IP-family socket it is refused: an address CPython can connect to
        # but tethered cannot match must not slip past the policy.
        if _is_ip_family(args[0], address):
            _deny_unreadable(cfg, scope_stack, event, address)
        return

    host, port = parsed

    # Look up the original hostname(s) if this is an IP
    resolved_from: str | None = None
    check_host = _normalize_host(host)
    # Every name a policy may allow this destination by: the hostnames its
    # address is known to have resolved from (most recent first), then the
    # host as given.  A policy allows the destination if it allows ANY of them.
    hosts: tuple[str, ...] = (check_host,)

    ip_key = _canonical_ip(check_host)
    if ip_key is not None:
        with _ip_map_lock:
            names = _ip_to_hostname.get(ip_key, ())
            # LRU: move to end on access so recently-used entries survive eviction
            if names:
                _ip_to_hostname.move_to_end(ip_key)
        if not names and not _allowed_by_every_layer(cfg, scope_stack, check_host, port):
            # IP map miss — could be DNS divergence (load-balanced service,
            # short TTL, gevent threadpool latency) where the IP CPython
            # returned to the application differs from what tethered's
            # audit-time getaddrinfo saw.  Re-resolve recently-allowed
            # hostnames to find one that maps to this IP.  Hot path
            # (mapped IP) is unaffected; cost only on the miss.
            #
            # Skipped when every layer already allows the raw IP (loopback,
            # an IP or CIDR rule): no hostname can change that outcome, and
            # the search costs up to _FALLBACK_RESOLVE_MAX_CANDIDATES lookups.
            fallback = _fallback_resolve(ip_key, port)
            if fallback is not None:
                names = (fallback,)
        if names:
            hosts = (*names, check_host)
            # Reported (exception, logs, callbacks) under the name most
            # recently seen for the address.
            resolved_from = check_host = names[0]

    # ── Global policy check ──
    global_allowed = True
    if cfg is not None:
        try:
            # Allowed if any mapped hostname, or the raw IP, is allowed.
            allowed = _allows_any(cfg.policy, hosts, port)
        except Exception:
            if cfg.fail_closed:
                logger.error(
                    "tethered: error checking policy for %s:%s, failing closed",
                    host,
                    port,
                    exc_info=True,
                )
                raise EgressBlocked(
                    host,
                    port,
                    resolved_from=resolved_from,
                    scope_hint=_hint_from_stack(scope_stack),
                ) from None
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
                raise EgressBlocked(
                    host,
                    port,
                    resolved_from=resolved_from,
                    scope_hint=_hint_from_stack(scope_stack),
                )

    # ── Scope checks ──
    # Each scope is asked about the mapped hostnames and the raw IP together:
    # a scope allows the connection if it allows ANY of them (the same rule
    # the global policy applies above), and every scope must allow.
    #
    # Every denying scope is reported; a log-only one returns and the loop
    # moves on, the first enforcing one raises.
    for blocking_scope in _check_scopes(scope_stack, hosts, port):
        _enforce_scope_block(
            blocking_scope,
            check_host,
            port,
            f"{event.split('.')[-1]} to {check_host}:{port}",
            global_allowed=global_allowed,
            resolved_from=resolved_from,
            scope_stack=scope_stack,
        )


# Longest program name a launch description quotes from a Windows command
# line (MAX_PATH); a longer first token is cut.
_LAUNCH_DESC_PROGRAM_MAX = 260


def _cmdline_program(cmdline: str) -> str:
    """Return the program-name token of a Windows command line, for log messages.

    Best effort: the quoted run when the line starts with a quote, else
    everything up to the first whitespace, on one line and cut to
    ``_LAUNCH_DESC_PROGRAM_MAX``.  The arguments are left out on purpose —
    the POSIX description names the executable only, and command lines
    routinely carry credentials that don't belong in logs or exception text.
    """
    line = cmdline.lstrip()
    if line.startswith('"'):
        token = line[1:].partition('"')[0]
    else:
        token = line.split(None, 1)[0] if line else ""
    token = " ".join(token.split())
    if len(token) > _LAUNCH_DESC_PROGRAM_MAX:
        token = token[:_LAUNCH_DESC_PROGRAM_MAX] + "..."
    return token or "<unknown>"


def _describe_subprocess_launch(event: str, args: tuple[Any, ...]) -> str:
    """Build a human-readable description of a subprocess launch for logging."""
    if event == "subprocess.Popen":
        exe = args[0] if args else None
        if exe is None:
            # Windows without ``executable=``: the event's executable is None
            # and only the command line (args[1]) names the program.
            cmdline = args[1] if len(args) >= 2 else None
            exe = _cmdline_program(cmdline) if isinstance(cmdline, str) else "<unknown>"
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

# ``-s`` and ``-I`` keep site.py but skip the per-user site-packages, so they
# bypass the bootstrap only when that is where tethered.pth is installed
# (``pip install --user``).
_USER_SITE_BYPASS_FLAG_CHARS = "sI"

# CPython's interpreter options (``SHORT_OPTS`` and ``longopts`` in
# ``Python/getopt.c``; the same for 3.11-3.15).  A flag stands alone or in a
# cluster (``-IS``).  A value option takes the rest of its token (``-Wdefault``) or,
# when it ends the token, the whole next token — which is therefore never an
# option, whatever it looks like.  ``-c`` and ``-m`` also end the options.
# The interpreter rejects every other option with a usage error (bar one
# oddity, a ``-`` ending a cluster), so those are treated as unparseable.
_INTERPRETER_FLAGS = frozenset("bBdEhiIOPqRsStuvVx?")
_INTERPRETER_VALUE_OPTIONS = frozenset("cmWX")
_INTERPRETER_LONG_FLAGS = frozenset(
    ("--help", "--help-all", "--help-env", "--help-xoptions", "--version")
)
_INTERPRETER_LONG_VALUE_OPTION = "--check-hash-based-pycs"

# ``os.exec*`` hands the child an argv array on POSIX, but on Windows the C
# runtime joins the elements into one command line (see _join_windows_argv).
_WINDOWS = sys.platform == "win32"


def _interpreter_flags(argv: Any) -> str | None:
    """Return the single-letter flags that ``argv`` passes to the interpreter.

    ``argv`` is the interpreter's argument vector, program name first: a
    list or tuple (POSIX layout) or the lazily split tokens of a Windows
    command line.  Options are read with the boundaries CPython's own
    ``_PyOS_GetOpt`` uses, so a token counts only where the interpreter
    treats it as an option: the value of ``-X`` / ``-W`` /
    ``--check-hash-based-pycs`` is skipped, and parsing stops at ``-c`` /
    ``-m`` (joined to their value or not), at ``--``, at ``-`` and at the
    script path — everything after those belongs to the program.

    Returns ``None`` when the options cannot be parsed: ``argv`` is not a
    sequence of ``str`` / ``bytes`` / ``os.PathLike``, or it uses an option
    the interpreter does not know.  Callers must not treat that as a normal
    launch.

    POSIX ``subprocess.Popen`` accepts ``bytes`` and ``os.PathLike`` argv
    elements (which CPython decodes at startup), so those go through
    ``os.fsdecode`` to match the char sequence the kernel will see —
    otherwise ``b"-S"`` would slip past an ``isinstance(arg, str)`` check.
    """
    if isinstance(argv, (str, bytes)):
        return None
    try:
        args = iter(argv)
    except TypeError:
        return None
    next(args, None)  # argv[0] is the program name, never an option
    flags = ""
    for arg in args:
        if isinstance(arg, (bytes, os.PathLike)):
            try:
                arg = os.fsdecode(arg)
            except (TypeError, ValueError):
                return None
        if not isinstance(arg, str):
            return None
        if arg in ("-", "--") or not arg.startswith("-"):
            break  # stdin, the end-of-options marker, or the script path
        if arg.startswith("--"):
            if arg == _INTERPRETER_LONG_VALUE_OPTION:
                next(args, None)  # its value
            elif arg not in _INTERPRETER_LONG_FLAGS:
                return None
            continue
        for end, char in enumerate(arg[1:], 2):
            if char in _INTERPRETER_VALUE_OPTIONS:
                if char in "cm":
                    return flags  # the code / module, then the program's own args
                if end == len(arg):
                    next(args, None)  # the value is the whole next token
                break
            if char not in _INTERPRETER_FLAGS:
                return None
            flags += char
    return flags


def _has_site_bypass_flag(argv: Any, pth_path: str = "") -> bool:
    """Return True unless ``argv`` provably leaves the ``tethered.pth`` bootstrap enabled.

    True when the interpreter options in ``argv`` (program name first)
    include ``-S`` — alone or in a cluster such as ``-IS`` — or cannot be
    parsed at all.  ``-I`` and ``-E`` keep ``site.py`` enabled and so are
    NOT bypass flags, with one exception: when ``pth_path`` (the bootstrap,
    from :func:`_bootstrap_pth_path`) is in the per-user site-packages,
    ``-s`` and ``-I`` skip that directory and the bootstrap with it.
    :func:`_interpreter_flags` decides what counts as an interpreter option:
    ``-S`` after the script path, or as the value of another option, is not
    one.
    """
    flags = _interpreter_flags(argv)
    if flags is None or any(c in flags for c in _SITE_BYPASS_FLAG_CHARS):
        return True
    return any(c in flags for c in _USER_SITE_BYPASS_FLAG_CHARS) and _is_user_site_pth(pth_path)


def _normalize_exe_path(value: Any) -> str | None:
    """Decode and normalize a path-like value for comparison with ``sys.executable``."""
    if not isinstance(value, (str, bytes, os.PathLike)):
        return None
    try:
        s = os.fsdecode(value)
    except (TypeError, ValueError):
        return None
    return os.path.normcase(os.path.normpath(s))


def _normalize_path(path: str) -> str:
    """Return ``path`` in the form ``tethered.pth`` paths are stored and compared in."""
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))


# Bootstrap lookup for launches made with no active config (scope-only use):
# None until first needed, then "" or the hook's path.  While a config is
# active, the path that activate() found is used instead.
_pth_path_cache: str | None = None


def _bootstrap_pth_path() -> str:
    """Return the ``tethered.pth`` that Python children of this process will run, or ``""``.

    While a policy is active this is what ``activate()`` found and stored in
    ``_Config._pth_path`` — the value its missing-hook warning was about,
    and one the locked-mode guardian protects.  With only scopes active
    there is no config, so :func:`_compute_pth_path` runs once and the
    result is kept in ``_pth_path_cache``.
    """
    global _pth_path_cache
    cfg = _config
    if cfg is not None:
        return cfg._pth_path
    cached = _pth_path_cache
    if cached is None:
        cached = _pth_path_cache = _compute_pth_path()
    return cached


def _is_user_site_pth(pth_path: str) -> bool:
    """Return True if ``pth_path`` is the hook in the per-user site-packages directory."""
    if not pth_path:
        return False
    import site

    user_site = site.USER_SITE
    return bool(user_site) and pth_path == _normalize_path(os.path.join(user_site, "tethered.pth"))


def _iter_windows_argv(program: str, args: str) -> Iterator[str]:
    """Yield ``program``, then ``args`` split the way the Microsoft C runtime does.

    Follows ``parse_command_line`` in the UCRT, which builds the ``argv``
    that ``python.exe`` receives: spaces and tabs separate arguments unless
    quoted; a quote toggles quoting and is dropped; 2n backslashes before a
    quote yield n backslashes and the quote toggles, 2n+1 yield n
    backslashes and a literal quote; ``""`` inside quotes is one literal
    quote; any other backslash is literal.  An unterminated quote runs to
    the end of the line, so every string splits.
    """
    yield program
    pos, end = 0, len(args)
    while True:
        while pos < end and args[pos] in " \t":
            pos += 1
        if pos == end:
            return
        arg: list[str] = []
        quoted = False
        while True:
            start = pos
            while pos < end and args[pos] == "\\":
                pos += 1
            slashes = pos - start
            keep = True
            if pos < end and args[pos] == '"':
                if slashes % 2 == 0:
                    if quoted and args[pos + 1 : pos + 2] == '"':
                        pos += 1  # "" inside quotes: drop one, keep the other
                    else:
                        keep = False
                        quoted = not quoted
                slashes //= 2
            arg.append("\\" * slashes)
            if pos == end or (not quoted and args[pos] in " \t"):
                break
            if keep:
                arg.append(args[pos])
            pos += 1
        yield "".join(arg)


def _parse_windows_cmdline(cmdline: str) -> tuple[str, Iterator[str]] | None:
    """Split a Windows command line the way the launched process will.

    Returns ``(program, argv)``: the program-name token, and a lazy iterator
    over the whole argument vector (``program`` first) suitable for passing
    to :func:`_has_site_bypass_flag`.  The arguments are split by
    :func:`_iter_windows_argv` only as far as the caller consumes them, so a
    long ``-c`` body full of quotes and newlines is never scanned.

    Returns ``None`` unless the program name is written in a form that
    everything reading the command line splits alike: ``"quoted"`` (no
    backslash before the closing quote) or a bare token without quotes,
    followed by a space or the end of the line.  ``CreateProcess``, the C
    runtime and the venv launchers that re-issue the command line each have
    their own rules for the first token; given a quote inside it, no space
    after the closing quote, or a tab or newline as the separator, they
    disagree about where the arguments begin, which can turn a script
    argument into an interpreter option.  Such a line is not treated as a
    Python launch whose options are known.
    """
    if cmdline.startswith('"'):
        end = cmdline.find('"', 1)
        if end == -1 or cmdline[end - 1] == "\\":
            return None
        program = cmdline[1:end]
        end += 1
    else:
        end = 0
        while end < len(cmdline) and cmdline[end] != '"' and not cmdline[end].isspace():
            end += 1
        program = cmdline[:end]
        if not program:
            return None
    rest = cmdline[end:]
    args = rest.lstrip(" \t")
    if rest[:1] not in ("", " ") or args[:1].isspace():
        return None
    return program, _iter_windows_argv(program, args)


def _join_windows_argv(argv: Any) -> str | None:
    """Return the command line Windows builds from an ``os.spawn*`` / ``os.exec*`` argv.

    The C runtime joins the elements with single spaces and does not quote
    them, and the child splits the result again — so an element containing a
    space or a quote does not arrive as one argument.  Returns ``None`` when
    ``argv`` is not a list or tuple of ``str`` / ``bytes`` / ``os.PathLike``.
    """
    if not isinstance(argv, (list, tuple)):
        return None
    parts: list[str] = []
    for arg in argv:
        if not isinstance(arg, (str, bytes, os.PathLike)):
            return None
        try:
            parts.append(os.fsdecode(arg))
        except (TypeError, ValueError):
            return None
    return " ".join(parts)


def _is_auto_inheriting_python_launch(event: str, args: tuple[Any, ...]) -> bool:
    """Return True if a subprocess launch will be covered by ``tethered.pth`` auto-inherit.

    A launch auto-inherits when:

    1. The executable is exactly ``sys.executable`` (the same interpreter,
       so the same site directories).
    2. That interpreter processes a ``tethered.pth`` bootstrap
       (:func:`_bootstrap_pth_path`).  An editable install, or a ``pip
       install --target`` directory on ``PYTHONPATH``, has none: no Python
       child auto-activates there, so none is treated as auto-inheriting.
    3. Its interpreter options can be parsed and don't disable that
       bootstrap: no ``-S`` (which skips ``site.py``), and no ``-s`` / ``-I``
       when the bootstrap is in the per-user site-packages.  Otherwise
       ``-I`` and ``-E`` keep ``site.py`` enabled and are NOT treated as
       bypass flags.

    Handles both POSIX and Windows audit-event layouts.  On POSIX,
    ``subprocess.Popen`` fires with ``(executable, argv_list, cwd, env)``
    and the child receives ``argv_list`` as is; its ``argv[0]`` must name
    ``sys.executable`` as well, because that is what tells the child which
    installation or venv it is.

    On Windows the child receives one command-line string and splits it
    itself: ``Popen`` fires with ``(executable_or_None, command_line_string,
    cwd, env)``, and ``os.spawn*`` / ``os.exec*`` fire with an argv list
    that the C runtime then joins.  Either way the string is split with
    :func:`_parse_windows_cmdline`; the launched image is ``executable``
    when given, else the command line's first token.

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

    # ``os.spawn`` is raised on Windows only; ``os.exec`` on every platform.
    if event == "os.spawn" or (event == "os.exec" and _WINDOWS):
        argv = _join_windows_argv(argv)

    if isinstance(argv, str):
        parsed = _parse_windows_cmdline(argv)
        if parsed is None:
            return False
        program, argv = parsed
        if executable is None:
            executable = program
    elif (
        not isinstance(argv, (list, tuple))
        or not argv
        or _normalize_exe_path(argv[0]) != _normalize_exe_path(sys.executable)
    ):
        # POSIX hands the child ``argv`` as is, and an interpreter works out
        # which installation or venv it belongs to from argv[0], not from the
        # file that was executed: started as "python" it looks that name up
        # on PATH and can come up outside this venv, where no tethered.pth is
        # processed.  (On Windows the executable itself decides.)
        return False

    exe_norm = _normalize_exe_path(executable)
    if exe_norm is None:
        return False

    if exe_norm != _normalize_exe_path(sys.executable):
        return False

    pth_path = _bootstrap_pth_path()
    if not pth_path:
        return False

    return not _has_site_bypass_flag(argv, pth_path)


# Maximum frames to walk back from the audit hook to find ``_execute_child``.
# In practice the target frame is sys._getframe(2) or (3); the cap is purely
# defensive against unexpected call-stack depth (e.g. profilers, debuggers).
_FRAME_WALK_DEPTH_CAP = 12


def _find_launch_frame(co_name: str, module: str) -> Any | None:
    """Walk back from the caller's caller for the frame of ``module``'s ``co_name``.

    The frame is identified by a defensive shape check: ``co_name`` matches,
    the frame's code declares an ``env`` local, AND the frame's globals
    belong to ``module`` (rejects user code that happens to define a
    same-named function).  Returns ``None`` if no matching frame is found
    within :data:`_FRAME_WALK_DEPTH_CAP` frames.
    """
    f = sys._getframe(2)  # start from the caller of the function that asked
    depth = 0
    while f is not None and depth < _FRAME_WALK_DEPTH_CAP:
        code = f.f_code
        if (
            code.co_name == co_name
            and "env" in code.co_varnames
            and f.f_globals.get("__name__") == module
        ):
            return f
        f = f.f_back
        depth += 1
    return None


def _find_execute_child_frame() -> Any | None:
    """Walk back from the caller and return ``subprocess._execute_child``'s frame.

    Returns ``None`` if the frame is not on the stack (see
    :func:`_find_launch_frame` for how it is recognized) — caller decides
    whether that is fail-closed (locked mode) or treat-as-external.
    """
    return _find_launch_frame("_execute_child", "subprocess")


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
    or treat-as-external.
    """
    try:
        frame.f_locals["env"] = new_env
    except Exception:
        logger.warning("tethered: scope env injection failed (f_locals write)", exc_info=True)
        return False
    if sys.version_info < (3, 13):  # pragma: no cover — only on 3.11-3.12
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


def _is_policy_env_key(key: Any) -> bool:
    """Return True if ``key`` names ``_TETHERED_CHILD_POLICY`` in a child environment.

    Environment names are case-insensitive on Windows, so every case variant
    is the same variable there (the child's ``os.environ`` upper-cases them).
    POSIX launch APIs accept ``bytes`` and ``os.PathLike`` names next to
    ``str``; every spelling that decodes to the name counts.
    """
    name = _env_text(key)
    if name is None:
        return False
    if _ENV_NAMES_IGNORE_CASE:
        return name.upper() == _CHILD_POLICY_ENV
    return name == _CHILD_POLICY_ENV


def _env_text(value: Any) -> str | None:
    """Decode an environment name or value the way the child sees it (``None`` if it cannot be)."""
    if isinstance(value, str):
        return value
    try:
        return os.fsdecode(value)
    except Exception:
        return None


def _snapshot_env(env: Any) -> list[tuple[Any, Any]] | None:
    """Read a launch environment once and return its ``(name, value)`` pairs.

    Reads through the mapping interface, so every mapping a launch API
    accepts is seen the way that API sees it — ``dict``,
    ``collections.UserDict``, ``types.MappingProxyType``, ``os.environ`` —
    and also takes the ``b"NAME=value"`` sequence ``_posixsubprocess.fork_exec``
    receives.  Returns ``None`` when the object cannot be read.
    """
    if isinstance(env, (list, tuple)):
        try:
            return [(name, value) for name, _, value in (e.partition(b"=") for e in env)]
        except Exception:
            return None
    try:
        return list(env.items())
    except Exception:
        try:
            return list(zip(env.keys(), env.values(), strict=True))
        except Exception:
            return None


def _classify_payload(text: str | None, expected: str, payload: str) -> str:
    """Compare one ``_TETHERED_CHILD_POLICY`` value against what the child must receive.

    ``expected`` is the exact value tethered would write for this launch and
    ``payload`` the canonical at-rest payload.  Returns:

    - ``"exact"`` — the value is ``expected``;
    - ``"same-global"`` — another serialization or scope list around the
      canonical ``global`` (scopes can only narrow within that ceiling);
    - ``"corrupt"`` — not JSON;
    - ``"substituted"`` — a different ``global``.

    The ``global`` comparison is on canonical JSON text, so it is type-exact:
    ``0`` is not ``false`` (a child would reject the former and run with no
    policy).
    """
    if text == expected:
        return "exact"
    if text is None:
        return "corrupt"
    try:
        parsed = json.loads(text)
        same_global = isinstance(parsed, dict) and json.dumps(
            parsed.get("global"), sort_keys=True
        ) == json.dumps(json.loads(payload)["global"], sort_keys=True)
    except (TypeError, ValueError, KeyError, RecursionError):
        return "corrupt"
    return "same-global" if same_global else "substituted"


def _launch_env_state(pairs: list[tuple[Any, Any]], expected: str, payload: str) -> str:
    """Classify the policy payload an explicit launch environment carries.

    Returns ``"missing"`` when no spelling of the policy key is present,
    ``"duplicate"`` when more than one is (which one the child reads is
    platform-dependent), otherwise the :func:`_classify_payload` result for
    the single value.
    """
    values = [value for key, value in pairs if _is_policy_env_key(key)]
    if not values:
        return "missing"
    if len(values) > 1:
        return "duplicate"
    return _classify_payload(_env_text(values[0]), expected, payload)


def _process_env_state(payload: str) -> str:
    """Classify the policy payload a child inheriting the process environment gets.

    ``os.environ`` is a cache: it shows changes made through itself but not
    ``os.putenv()`` / ``os.unsetenv()``.  :func:`_handle_env_change` records
    such a change to the policy variable in ``_env_dirty``; while it is set a
    matching cache entry proves nothing, which is reported as ``"diverged"``.

    The cache is also one interpreter's: it shows nothing of what another
    interpreter of the process does to the variable, and nothing of a
    change made below Python (``ctypes`` calling libc ``setenv`` /
    ``unsetenv``), which raises no audit event.  While a policy is locked,
    a matching cache entry is therefore held against the process
    environment itself (:func:`_process_env_differs`); a difference is
    reported as ``"foreign"``.  Without a lock such changes are not seen.
    """
    value = os.environ.get(_CHILD_POLICY_ENV)
    if value is None:
        return "missing"
    state = _classify_payload(value, payload, payload)
    if state in ("exact", "same-global"):
        if _env_dirty:
            return "diverged"
        if _process_env_differs(payload):
            return "foreign"
    return state


def _process_env_differs(payload: str) -> bool:
    """Return True if, under a lock, a child would not inherit ``payload``'s policy.

    Asks the C guardian for the variable as the process itself holds it,
    which is what a child that is given no environment of its own receives,
    and judges it like any other value (:func:`_classify_payload`).  It
    matters once a process has more than one interpreter with a locked
    policy: each one launches children, each has its own ``os.environ``,
    and only the interpreter that makes a change sees the audit event for
    it.  Always ``False`` when no policy is locked.

    Never raises (it runs inside the audit hook, where only
    ``SubprocessBlocked`` should come out of a refused launch): a variable
    that cannot be read is one nothing can be said for, and counts as
    different.
    """
    if _c_guardian is None or not _c_guardian.is_active():
        return False
    try:
        inherited = _c_guardian.process_policy_env()
    except Exception:
        return True
    return _classify_payload(inherited, payload, payload) not in ("exact", "same-global")


def _handle_env_change(event: str, args: tuple[Any, ...]) -> None:
    """Track ``os.putenv`` / ``os.unsetenv`` on the policy variable.

    Sets ``_env_dirty`` when code other than tethered leaves the native
    variable without the canonical payload, and clears it when the canonical
    payload is put back (a save / clear / restore of the whole environment
    ends clean).  Audit args: ``os.putenv`` ``(name, value)``, ``os.unsetenv``
    ``(name,)`` — ``bytes`` on POSIX, ``str`` on Windows.  Takes no lock: it
    runs inside ``os.environ`` assignments, including tethered's own.
    """
    global _env_dirty
    if not args or not _is_policy_env_key(args[0]) or _in_env_sync.get():
        return
    cfg = _config
    if cfg is None:
        return  # no payload is expected; activate() will write one
    if event == "os.putenv" and len(args) >= 2:
        payload = _canonical_payload(cfg)
        state = _classify_payload(_env_text(args[1]), payload, payload)
        _env_dirty = state not in ("exact", "same-global")
    else:
        _env_dirty = True


def _refuse_launch(event: str, desc: str, source: str, state: str) -> None:
    """Raise ``SubprocessBlocked`` for a locked-mode launch whose environment fails the check."""
    label, detail = {
        "missing": ("stripped policy env", f"{source} strips {_CHILD_POLICY_ENV}"),
        "corrupt": (
            "corrupted policy payload",
            f"{source} carries a {_CHILD_POLICY_ENV} value that is "
            "not valid JSON (corruption / tamper attempt)",
        ),
        "substituted": (
            "substituted policy payload",
            f"{source} carries a {_CHILD_POLICY_ENV} value whose "
            "'global' field differs from the parent's canonical payload "
            "(substitution attempt)",
        ),
        "duplicate": (
            "duplicate policy env entries",
            f"{source} carries more than one spelling of {_CHILD_POLICY_ENV} "
            "(duplicate-key tamper attempt)",
        ),
        "diverged": (
            "unverifiable policy env",
            f"{_CHILD_POLICY_ENV} was changed through os.putenv / os.unsetenv, "
            "so os.environ no longer shows what the child would inherit",
        ),
        "foreign": (
            "policy env changed outside this interpreter",
            f"the environment of the process no longer carries the {_CHILD_POLICY_ENV} "
            "value os.environ shows (it was changed from another interpreter or below "
            "Python), so the child would not inherit the locked policy",
        ),
        "unreadable": ("unreadable env", f"{source} could not be read as a mapping"),
    }[state]
    logger.warning("tethered: blocked subprocess launch with %s: %s (%s)", label, desc, source)
    raise SubprocessBlocked(event, f"{desc} — {detail}")


def _launch_payload(cfg: _Config | None, scope_stack: tuple[_ScopeConfig, ...]) -> str:
    """Return the payload a ``subprocess.Popen`` child launched right now must receive."""
    if cfg is None:
        return _build_env_payload(None, scope_stack)
    payload = _canonical_payload(cfg)
    if not scope_stack:
        return payload
    return _build_env_payload(json.loads(payload)["global"], scope_stack)


def _build_per_launch_env(
    event: str,
    args: tuple[Any, ...],
    scope_stack: tuple[_ScopeConfig, ...],
    cfg: _Config | None,
) -> dict[Any, Any] | None:
    """Build the per-launch env dict to inject into ``_execute_child``.

    Copies the effective launch environment — the explicit ``env=`` mapping
    whatever its type, or ``os.environ`` when the child would inherit — drops
    every spelling of ``_TETHERED_CHILD_POLICY`` and sets the one canonical
    entry: a nested-format payload that carries the canonical global plus
    the active scope chain.  All other env vars are preserved verbatim —
    never fabricate a child env from scratch — and the caller's mapping is
    never mutated.  Returns ``None`` when the caller's mapping cannot be
    read: an environment tethered cannot copy is never replaced by the
    parent's.
    """
    _has_env, env_value = _extract_subprocess_env(event, args)
    pairs = _snapshot_env(os.environ if env_value is None else env_value)
    if pairs is None:
        return None
    new_env = {key: value for key, value in pairs if not _is_policy_env_key(key)}
    new_env[_CHILD_POLICY_ENV] = _launch_payload(cfg, scope_stack)
    return new_env


def _inject_launch_env(
    event: str,
    args: tuple[Any, ...],
    scope_stack: tuple[_ScopeConfig, ...],
    cfg: _Config | None,
) -> str | None:
    """Give ``subprocess.Popen._execute_child`` a constructed environment for this launch.

    Returns ``None`` on success, else the reason it could not be put in
    place — the caller decides what that means (locked mode fails closed).
    """
    frame = _find_execute_child_frame()
    if frame is None:
        return "could not locate subprocess._execute_child frame"
    new_env = _build_per_launch_env(event, args, scope_stack, cfg)
    if new_env is None:
        return "the launch environment could not be read as a mapping"
    if not _inject_scope_env(frame, new_env):
        return "frame-locals mutation failed"
    return None


def _same_path(a: Any, b: Any) -> bool:
    """Return True if two ``str`` paths name the same file, compared lexically."""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return os.path.normcase(os.path.normpath(a)) == os.path.normcase(os.path.normpath(b))


def _resolve_winapi_launch(args: tuple[Any, ...]) -> tuple[tuple[Any, ...], dict[Any, Any] | None]:
    """Describe a ``_winapi.CreateProcess`` launch in the ``subprocess.Popen`` audit layout.

    The event carries ``(application_name, command_line, current_directory)``
    and not the environment.  Besides ``subprocess`` the stdlib caller is
    ``multiprocessing.popen_spawn_win32.Popen.__init__``, whose ``env`` local
    holds it: ``None`` (inherit) or, inside a virtual environment, a private
    copy of ``os.environ`` plus ``__PYVENV_LAUNCHER__ = sys.executable``,
    passed while launching ``sys._base_executable`` — the base interpreter
    then behaves as ``sys.executable`` (bpo-35797), so that launch is
    reported as one of ``sys.executable``.

    Returns ``(popen_args, private_env)``.  ``private_env`` is that private
    copy when there is one: ``CreateProcess`` reads the mapping after the
    audit event, so completing it in place reaches the child (rebinding the
    local would not — the argument is already passed).  Third-party copies
    of that spawner are recognized by the same redirect (see
    :func:`_find_venv_launcher_env`).  For any other caller the environment
    is unknown and the launch is treated as inheriting the process
    environment.

    The command line cannot be relied on either.  CPython 3.11 to 3.15 format
    the event's ``command_line`` argument, a Python object, as a C wide
    string, so what arrives is a character or two of garbage and not the
    command line.  Interpreter options such as ``-S`` are therefore not
    visible on this route: a launch is judged by its executable.  The value
    is still passed on, so a fixed CPython is picked up without a change here.
    """
    executable, cmdline, cwd = (*args, None, None, None)[:3]
    env = None
    launches_base = _same_path(executable, getattr(sys, "_base_executable", None))
    frame = _find_launch_frame("__init__", "multiprocessing.popen_spawn_win32")
    if frame is not None:
        env = frame.f_locals.get("env")
        if type(env) is not dict:
            env = None
    elif launches_base:
        env = _find_venv_launcher_env()
    if (
        env is not None
        and launches_base
        and _same_path(env.get("__PYVENV_LAUNCHER__"), sys.executable)
    ):
        executable = sys.executable
    return (executable, cmdline, cwd, env), env


def _find_venv_launcher_env() -> dict[Any, Any] | None:
    """Find the environment a third-party copy of multiprocessing's spawner is passing.

    Process-pool libraries such as joblib's loky and billiard carry their own
    copy of ``multiprocessing.popen_spawn_win32``.  Inside a virtual
    environment they do what it does: launch ``sys._base_executable`` with a
    private environment in which ``__PYVENV_LAUNCHER__`` is ``sys.executable``
    (bpo-35797).  The frame that called ``_winapi.CreateProcess`` holds that
    mapping in a local whose name differs between libraries, so the mapping is
    recognized by that entry rather than by name.

    Returns the mapping, or ``None`` when the calling frame has no such local
    — the launch is then one of the base interpreter as such.
    """
    f: Any = sys._getframe(1)
    depth = 0
    while f is not None and depth < _FRAME_WALK_DEPTH_CAP:
        if f.f_globals.get("__name__") != __name__:
            # The first frame outside this module is the one that made the call.
            for value in f.f_locals.values():
                if type(value) is dict and _same_path(
                    value.get("__PYVENV_LAUNCHER__"), sys.executable
                ):
                    return value
            return None
        f = f.f_back
        depth += 1
    return None


def _resolve_fork_exec_launch(args: tuple[Any, ...]) -> tuple[Any, ...]:
    """Describe a ``_posixsubprocess.fork_exec`` launch in the ``subprocess.Popen`` audit layout.

    The event (CPython 3.14+) carries ``(exec_list, args, env)``: the
    candidate executable paths in the order they are tried, the argv, and
    the environment as a sequence of ``b"NAME=value"`` entries or ``None``
    (inherit).  ``multiprocessing`` spawn / forkserver / resource-tracker
    launches pass a single executable and ``None``.
    """
    exec_list, argv, env = (*args, None, None, None)[:3]
    executable = exec_list[0] if isinstance(exec_list, (list, tuple)) and exec_list else None
    return (executable, argv, None, env)


def _describe_launch(event: str, args: tuple[Any, ...], launch_args: tuple[Any, ...]) -> str:
    """Describe a launch for logs, covering the events without a ``subprocess.Popen`` shape."""
    if event in ("_winapi.CreateProcess", "_posixsubprocess.fork_exec"):
        program = _env_text(launch_args[0]) if launch_args[0] else None
        if not program:
            # No executable given: name the program from the command line,
            # unless that is unusable.  CPython's _winapi.CreateProcess event
            # does not deliver the real command line (see
            # _resolve_winapi_launch), so never print it unchecked.
            cmdline = launch_args[1]
            program = _cmdline_program(cmdline) if isinstance(cmdline, str) else None
            if not program or not program.isprintable():
                program = "<unknown>"
        return f"{event}({program})"
    return _describe_subprocess_launch(event, args)


def _handle_subprocess(
    cfg: _Config | None,
    event: str,
    args: tuple[Any, ...],
    scope_stack: tuple[_ScopeConfig, ...] = (),
) -> None:
    """Enforce subprocess launch policy and establish the child's policy payload.

    ``cfg`` is ``None`` when only scopes are active (no :func:`activate` ever
    called) — the audit hook still fires so scope policy can propagate to
    child processes.  ``scope_stack`` is the active scope chain, captured
    once by ``_audit_hook`` and passed in to keep the per-event ContextVar
    reads consistent.
    """
    popen = event == "subprocess.Popen"
    if cfg is None:
        # scope() without activate(): no global payload and no
        # external_subprocess_policy.  The scope chain reaches a Python
        # child through the ``_execute_child`` frame; no other route has an
        # env channel tethered can write to.
        if scope_stack and popen and _is_auto_inheriting_python_launch(event, args):
            failure = _inject_launch_env(event, args, scope_stack, None)
            if failure is not None:
                logger.warning(
                    "tethered: scope subprocess propagation unavailable (%s); "
                    "the child will not inherit the active scope",
                    failure,
                )
        return

    # ── What is being launched, and with which environment ─────────────
    # ``subprocess.Popen`` raises a second event for the same launch
    # (``os.posix_spawn`` / ``_posixsubprocess.fork_exec`` /
    # ``_winapi.CreateProcess``); with ``_execute_child`` on the stack that
    # launch was already handled.  From any other caller — multiprocessing
    # and ProcessPoolExecutor workers never raise ``subprocess.Popen`` — the
    # native events are translated to the ``subprocess.Popen`` layout so one
    # classifier and one set of rules serve every route.
    launch_event, launch_args, private_env = event, args, None
    if event in _POPEN_NESTED_EVENTS:
        if _find_execute_child_frame() is not None:
            return
        if event == "_winapi.CreateProcess":
            launch_event = "subprocess.Popen"
            launch_args, private_env = _resolve_winapi_launch(args)
        elif event == "_posixsubprocess.fork_exec":
            launch_event = "subprocess.Popen"
            launch_args = _resolve_fork_exec_launch(args)
    # Auto-inheriting Python child launches are covered by tethered.pth →
    # _autoactivate — provided their environment carries the payload, which
    # is what the rest of this function establishes.
    is_python = _is_auto_inheriting_python_launch(launch_event, launch_args)
    _has_env, env_value = _extract_subprocess_env(launch_event, launch_args)

    # ── The environment the child will actually receive ────────────────
    # ``payload`` (from the immutable ``_serialized_payload``) is the only
    # reference; the mutable ``_global_payload_dict`` is not trusted.
    #
    #   - Inherited (``env`` is None, or the route has no env argument): the
    #     child gets the native process environment.  ``os.environ`` shows
    #     Python-level mutation (os.environ.pop / __setitem__ / __delitem__)
    #     and ``_env_dirty`` covers os.putenv() / os.unsetenv(), which bypass
    #     it.  Changes made by another interpreter or below Python (ctypes →
    #     libc setenv / unsetenv) raise no audit event here; while a policy
    #     is locked the process environment itself is read, otherwise they
    #     are NOT caught.  Locked mode refuses; otherwise the payload is
    #     re-asserted, which also repairs an ordinary whitelist cleanup of
    #     ``os.environ``.
    #   - Explicit: read once through the mapping interface, whatever the
    #     type (dict, UserDict, MappingProxyType, os.environ ...), so the
    #     check sees what the launch API will read.  Locked mode refuses
    #     absence ("strip"), corruption ("not valid JSON"), a differing
    #     'global' ("substitution") and more than one spelling of the key.
    #     A differing scope list is not refused: scopes can only narrow
    #     within the checked global ceiling, so they can't widen child
    #     enforcement past the parent.
    #
    # The comparison never raises, so no stray exception escapes the audit
    # hook in place of ``SubprocessBlocked``.  Locked mode requires
    # activate(), so cfg is non-None here.
    payload = _canonical_payload(cfg)
    acceptable = True  # the environment carries the canonical global, once
    needs_rewrite = False  # ... but not exactly what this launch must carry
    if env_value is None:
        state = _process_env_state(payload)
        if state != "exact":
            if not cfg.locked:
                _reassert_policy_env(cfg)
            elif state != "same-global":
                _refuse_launch(
                    event, _describe_launch(event, args, launch_args), "os.environ", state
                )
        # Scopes never live in os.environ; they need the per-launch copy.
        needs_rewrite = popen and bool(scope_stack)
    elif cfg.locked or is_python:
        expected = _launch_payload(cfg, scope_stack) if popen else payload
        pairs = _snapshot_env(env_value)
        state = "unreadable" if pairs is None else _launch_env_state(pairs, expected, payload)
        acceptable = state in ("exact", "same-global")
        if cfg.locked and not acceptable:
            _refuse_launch(event, _describe_launch(event, args, launch_args), "env", state)
        needs_rewrite = state != "exact"

    # ── Python children: make the environment right ────────────────────
    # They skip external_subprocess_policy (it is for launches auto-inherit
    # can't reach: non-Python children, different interpreters, ``-S``) —
    # unless the payload cannot be put in place, which makes the launch one
    # auto-inherit can't reach.
    reason = ""
    if is_python:
        if popen:
            if not needs_rewrite:
                return  # common case: nothing to change, no frame mutation
            failure = _inject_launch_env(event, args, scope_stack, cfg)
            if failure is None:
                return
            # No subprocess._execute_child frame in the stack (a debugger
            # wrapper, a future CPython refactor, a platform without the
            # standard implementation), an ``env=`` that cannot be read as a
            # mapping, or a failed frame write.  Locked mode fails closed
            # (better safe than silent); otherwise the launch is no longer
            # one tethered can vouch for.
            desc = _describe_launch(event, args, launch_args)
            if cfg.locked:
                logger.warning(
                    "tethered: blocked subprocess launch in locked mode — %s: %s", failure, desc
                )
                raise SubprocessBlocked(
                    event,
                    f"{desc} — {failure}; the child's policy environment could not "
                    "be established and locked mode requires fail-closed behavior",
                )
            logger.warning(
                "tethered: could not establish the policy environment of %s (%s); "
                "treating the launch as external",
                desc,
                failure,
            )
            reason = " — its environment could not be given the launch-site policy"
        elif private_env is not None:
            # multiprocessing's own copy of os.environ: complete it in place.
            if needs_rewrite:
                for key in [k for k in private_env if _is_policy_env_key(k)]:
                    del private_env[key]
                private_env[_CHILD_POLICY_ENV] = payload
            return
        elif acceptable:
            # No env channel to write to on this route.  The child gets the
            # at-rest global; an active scope does not travel (documented).
            return
        else:
            reason = f" — its environment lacks {_CHILD_POLICY_ENV} and cannot be rewritten"

    # ── External launches ──────────────────────────────────────────────
    # os.system, an external executable, Python with ``-S``, or a Python
    # child that cannot be given the policy.
    sp = cfg.external_subprocess_policy
    if sp == "allow":
        return

    desc = _describe_launch(event, args, launch_args) + reason

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


def _created_path(event: str, args: tuple[Any, ...]) -> Any:
    """Return the path at which ``event`` brings a file into being, or ``None``.

    That is the target of a write-capable ``open`` and the destination of a
    rename, a hard link, a symlink or a ``_winapi.CopyFile2`` — the ways of
    creating a file from Python that raise an audit event.  ``os.mknod`` and
    ``os.mkfifo`` raise none.
    """
    if event == "open":
        return args[0] if args and _is_open_for_write(args) else None
    if event in ("os.rename", "os.link", "os.symlink", "_winapi.CopyFile2"):
        return args[1] if len(args) >= 2 else None
    return None


def _path_matches_pth(target: Any, cached: str) -> bool:
    """Return True if ``target`` (str/bytes/PathLike) refers to ``cached``, a guarded path.

    ``cached`` is the ``tethered.pth`` path stored at ``activate()`` time, or
    the ``tethered.start`` path beside it, in :func:`_normalize_path` form.
    """
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
    """Refuse Python-level tampering with ``tethered.pth`` in locked mode.

    Catches:

    - ``os.remove`` (also fired by ``os.unlink`` / ``pathlib.Path.unlink`` /
      ``shutil.rmtree`` — they all alias to the same audit event);
    - ``os.rename`` (move-away or replace-with — also fired by ``os.replace``);
    - ``open`` with a write-capable mode (``shutil.copy``, ``Path.write_*``,
      etc. all flow through this);
    - ``os.chmod`` (a permission-strip attack: ``os.chmod(path, 0)`` makes
      the file unreadable, so site.py silently skips it on POSIX → next
      interpreter has no auto-activation);
    - ``os.truncate`` given a path (emptying the file disables
      auto-activation just as deleting it does);
    - ``_winapi.CopyFile2`` onto the path (``shutil.copy2`` on Windows, which
      replaces the file without an ``open`` event).

    Also refuses creating ``tethered.start`` beside it, which from Python
    3.15 makes ``site.py`` ignore the ``.pth``'s ``import`` line (PEP 829):
    any event for which :func:`_created_path` names that file.  Removing
    such a file is not refused — that can only restore the bootstrap.

    The cached path is computed at ``activate()`` time; if it's empty (no
    ``tethered.pth`` in a directory ``site.py`` processes — see
    :func:`_compute_pth_path`), the hook is a no-op.

    No effect outside locked mode.  Not caught: ``os.ftruncate`` (and
    ``os.truncate`` given a file descriptor) — the event carries the
    descriptor, not a path, though obtaining a writable descriptor through
    ``open`` / ``os.open`` is refused above; ``os.mknod`` creating
    ``tethered.start`` (POSIX), which raises no audit event; ``ctypes``
    calling libc ``unlink`` / ``rename`` / ``open`` / ``chmod`` /
    ``truncate`` directly, which raises none either; and external tools
    spawned via ``subprocess`` (mitigated by
    ``external_subprocess_policy="block"``).  See ``SECURITY.md``.
    """
    if not cfg.locked or not cfg._pth_path:
        return
    created = _created_path(event, args)
    if created is not None:
        start_path = os.path.join(os.path.dirname(cfg._pth_path), "tethered.start")
        if _path_matches_pth(created, start_path):
            logger.warning("tethered: blocked creation of %s", start_path)
            raise SubprocessBlocked(
                event,
                f"refused creation of {start_path} in locked mode "
                "(beside tethered.pth it disables auto-activation on Python 3.15+)",
            )
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
    elif event == "os.truncate":
        # args: (path_or_fd, length).  An int is a file descriptor, which
        # _path_matches_pth() does not match.
        target = args[0] if args else None
        if _path_matches_pth(target, cfg._pth_path):
            logger.warning("tethered: blocked truncation of %s", cfg._pth_path)
            raise SubprocessBlocked(event, f"refused truncation of {cfg._pth_path} in locked mode")
    elif event == "_winapi.CopyFile2":
        # args: (existing_file_name, new_file_name, flags)
        dst = args[1] if len(args) >= 2 else None
        if _path_matches_pth(dst, cfg._pth_path):
            logger.warning("tethered: blocked overwrite of %s", cfg._pth_path)
            raise SubprocessBlocked(event, f"refused overwrite of {cfg._pth_path} in locked mode")


def _install_hook() -> None:
    """Install the audit hook exactly once, and confirm that it is live.

    ``sys.addaudithook()`` first raises a ``sys.addaudithook`` audit event.
    If a hook that is already installed answers it with a ``RuntimeError``,
    the new hook is dropped and the call returns normally all the same, so
    its return says nothing.  The hook is therefore asked to answer a probe
    event: after it is added, which is the only way to learn that it was
    accepted, and before, so that a hook which is already live (the flag
    was lost, e.g. to an interrupt between the two steps) is never added a
    second time.

    Raises ``RuntimeError`` when the hook is not live.  ``_hook_installed``
    then stays ``False`` and a later call tries again.
    """
    global _hook_installed
    with _state_lock:
        if _hook_installed:
            return
        answers: list[bool] = []
        sys.audit(_HOOK_PROBE_EVENT, answers)
        if not answers:
            sys.addaudithook(_audit_hook)
            sys.audit(_HOOK_PROBE_EVENT, answers)
            if not answers:
                raise RuntimeError(_HOOK_REFUSED_MSG)
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

    A scope is active in the context (thread or asyncio task) that entered
    it, from entry until that block exits, wherever the code in between
    runs.  In a generator, do not ``yield`` from inside a ``with scope():``
    block: the scope would stay active in the consumer's context between
    values.  Scope each I/O call inside the generator body instead.

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
        hint: Optional actionable guidance attached to any ``EgressBlocked``
            raised while this scope is the deepest hinted scope on the
            stack.  Surfaces as ``EgressBlocked.scope_hint`` and as a
            trailing ``Hint: ...`` line on the exception message.
            Whitespace is normalized at construction (runs of any
            whitespace, including embedded newlines, collapse to a single
            space) so multi-line literals render cleanly.  ``None``,
            empty, and whitespace-only inputs are equivalent to "no hint
            set" — the exception message is unchanged.  The hint travels
            with the scope through subprocess auto-propagation, so a
            child process blocked by an inherited scope sees the same
            guidance.
    """

    __slots__ = ("_entered", "_scope_cfg")

    def __init__(
        self,
        *,
        allow: list[str],
        allow_localhost: bool = True,
        log_only: bool = False,
        fail_closed: bool = False,
        on_blocked: Callable[[str, int | None], None] | None = None,
        label: str | None = None,
        hint: str | None = None,
    ) -> None:
        _validate_allow(allow)
        _validate_bool(allow_localhost, "allow_localhost")
        _validate_bool(log_only, "log_only")
        _validate_bool(fail_closed, "fail_closed")
        _validate_callback(on_blocked)
        _validate_optional_str(label, "label")
        normalized_hint = _normalize_hint(hint)
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
            hint=normalized_hint,
        )
        self._entered = False

        # Warn about dead or overly broad rules when a global policy is active
        cfg = _config
        if cfg is not None:
            self._warn_scope_overlap(cfg.policy, policy, allow, label)

    @staticmethod
    def _warn_scope_overlap(
        global_policy: AllowPolicy,
        scope_policy: AllowPolicy,
        allow: list[str],
        label: str,
    ) -> None:
        """Warn about scope rules that have no or partial overlap with the global policy.

        Each rule is judged as ``scope_policy`` parsed it (``_parsed_rules``
        has one entry per ``allow`` entry, in the same order); ``allow`` only
        supplies the text the user wrote, for the message.  A rule whose
        overlap cannot be told ("unknown") is not reported: the message would
        state a guess as a fact.
        """
        # strict=False: the two always pair up, and a warning pass is not the
        # place to raise if they ever did not.
        for raw, rule in zip(allow, scope_policy._parsed_rules, strict=False):
            overlap = global_policy._check_rule_overlap(rule)
            if overlap == "none":
                logger.warning(
                    "tethered: %s rule %r has no overlap with global policy — it will never match",
                    label,
                    raw,
                )
            elif overlap == "partial":
                logger.warning(
                    "tethered: %s rule %r is broader than the global policy"
                    " — only a subset will be reachable",
                    label,
                    raw,
                )

    def __enter__(self) -> scope:
        if self._entered:
            msg = "tethered.scope: this instance is already entered; create a new scope() instance"
            raise RuntimeError(msg)
        _install_hook()
        _push_scope(self._scope_cfg)
        self._entered = True
        logger.debug("tethered: entered %s", self._scope_cfg.label)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        self._entered = False
        _pop_scope(self._scope_cfg)
        logger.debug("tethered: exited %s", self._scope_cfg.label)

    def __call__(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Use as a decorator on sync or async functions."""
        if inspect.isgeneratorfunction(fn) or inspect.isasyncgenfunction(fn):
            msg = (
                "tethered.scope cannot decorate generator or async generator functions: "
                "the decorated call returns before the generator body runs, so the scope "
                "would never cover it. Inside the generator body, wrap each I/O call in "
                "its own 'with tethered.scope(allow=[...]):' block and do not yield from "
                "inside one — a scope that is open across a yield stays active in the "
                "consumer's context until the generator resumes."
            )
            raise TypeError(msg)

        scope_cfg = self._scope_cfg

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                _install_hook()
                _push_scope(scope_cfg)
                logger.debug("tethered: entered %s", scope_cfg.label)
                try:
                    return await fn(*args, **kwargs)
                finally:
                    _pop_scope(scope_cfg)
                    logger.debug("tethered: exited %s", scope_cfg.label)

            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            _install_hook()
            _push_scope(scope_cfg)
            logger.debug("tethered: entered %s", scope_cfg.label)
            try:
                return fn(*args, **kwargs)
            finally:
                _pop_scope(scope_cfg)
                logger.debug("tethered: exited %s", scope_cfg.label)

        return sync_wrapper


# ── Locked-mode integrity snapshot ────────────────────────────────
# Kinds of pin understood by the C guardian.  Must match the PIN_*
# constants in _guardian.c.
_PIN_ATTR = 0  # getattr(owner, name) is the object recorded at activation
_PIN_ITEM = 1  # the namespace (module globals / class body) binds name to it
_PIN_ABSENT = 2  # the namespace does not define name
_PIN_CODE = 3  # owner is a function that still has the recorded __code__
_PIN_TYPE = 4  # type(owner) is the recorded class

# A module global of one of these exact types, bound to a lower-case name,
# is runtime state that tethered itself rebinds (a flag, a counter) and is
# therefore not pinned.  Every other module-level name is: functions,
# classes, imported modules, locks, ContextVars, containers, loggers and
# UPPER_CASE constants.
_UNPINNED_SCALAR_TYPES = frozenset((type(None), bool, int, float, str))

# Special methods that intercept every attribute read on an instance.  None
# of tethered's classes defines them, and in locked mode none may appear:
# an injected ``__getattribute__`` would redirect ``policy.is_allowed``
# without rebinding anything that is pinned by identity.
_ATTRIBUTE_HOOKS = ("__getattribute__", "__getattr__")


def _is_unpinned_global(name: str, value: object) -> bool:
    """Return True for a module global the integrity snapshot leaves alone.

    ``_config`` is the object under protection and is tracked by the guardian
    itself.  Lower-case names bound to ``None``/``bool``/``int``/``float``/
    ``str`` are runtime scalar state; pinning their identity would turn
    tethered's own updates into tamper alerts.
    """
    return name == "_config" or (name == name.lower() and type(value) in _UNPINNED_SCALAR_TYPES)


def _functions_behind(value: object) -> list[types.FunctionType]:
    """Return the plain Python functions that run when ``value`` is used.

    That is ``value`` itself when it is a function, and otherwise whatever a
    descriptor or wrapper exposes: the ``__func__`` of a ``staticmethod``,
    ``classmethod`` or bound method, the accessors of a ``property``, the
    ``__wrapped__`` target of a ``functools.wraps``-style wrapper.
    """
    found: list[types.FunctionType] = []
    seen: set[int] = set()
    pending: list[object] = [value]
    while pending:
        obj = pending.pop()
        if obj is None or id(obj) in seen:
            continue
        seen.add(id(obj))
        if isinstance(obj, types.FunctionType):
            found.append(obj)
        if isinstance(obj, property):
            pending += (obj.fget, obj.fset, obj.fdel)
        else:
            pending += (getattr(obj, "__func__", None), getattr(obj, "__wrapped__", None))
    return found


def _referenced_names(code: types.CodeType) -> set[str]:
    """Return the global and attribute names used by ``code`` and the code nested in it."""
    names = set(code.co_names)
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            names |= _referenced_names(const)
    return names


def _build_integrity_snapshot(cfg: _Config) -> list[tuple[object, str, int]]:
    """Build the list of facts the C guardian pins while ``cfg`` is locked.

    Each entry is ``(owner, name, kind)`` with ``kind`` one of the ``_PIN_*``
    constants.  The guardian records the current value of every entry at
    activation and re-checks all of them on each guarded audit event.

    The list is generated from the namespaces themselves, not hand-picked,
    so new code is covered without anyone remembering to register it:

    - every module-level name of this module and of ``tethered._policy``,
      except the runtime state described in :func:`_is_unpinned_global`;
    - every class-level attribute of every class defined in those modules
      (methods, slot descriptors, generated dataclass methods), plus the
      absence of the :data:`_ATTRIBUTE_HOOKS`;
    - the ``__code__`` of every Python function found on the way;
    - the absence, from those two module namespaces, of every builtin name
      their code uses — a module global called ``isinstance`` would shadow
      the builtin for that module only;
    - the exact class and every slot of the active ``_Config`` and of its
      ``AllowPolicy``.

    Not covered, by design: the contents of mutable containers (the
    IP-to-hostname map is written on every lookup), function defaults and
    closures, and everything outside these two modules — the builtins
    themselves and the standard-library functions the policy calls
    (``fnmatch.fnmatchcase``, ``ipaddress.ip_address``, ``json.loads``).
    """
    entries: list[tuple[object, str, int]] = []
    # The two namespaces are taken from the code that runs in them, not
    # looked up by name in ``sys.modules``.
    namespaces = (globals(), AllowPolicy.is_allowed.__globals__)
    module_names = {namespace["__name__"] for namespace in namespaces}
    classes: dict[int, type] = {}
    functions: dict[int, types.FunctionType] = {}

    for namespace in namespaces:
        for name, value in namespace.items():
            if _is_unpinned_global(name, value):
                continue
            entries.append((namespace, name, _PIN_ITEM))
            functions.update((id(func), func) for func in _functions_behind(value))
            if isinstance(value, type) and value.__module__ in module_names:
                classes[id(value)] = value

    # Class bodies are pinned before any instance attribute below: the
    # guardian checks entries in order, so by the time it reads a slot it
    # has already confirmed the descriptor that serves it.
    for cls in classes.values():
        body = vars(cls)
        for name, value in body.items():
            entries.append((cls, name, _PIN_ITEM))
            functions.update((id(func), func) for func in _functions_behind(value))
        entries += ((cls, hook, _PIN_ABSENT) for hook in _ATTRIBUTE_HOOKS if hook not in body)

    for func in functions.values():
        entries.append((func, "__code__", _PIN_CODE))

    for namespace in namespaces:
        used: set[str] = set()
        for func in functions.values():
            if func.__globals__ is namespace:
                used |= _referenced_names(func.__code__) & func.__builtins__.keys()
        entries += ((namespace, name, _PIN_ABSENT) for name in sorted(used - namespace.keys()))

    for obj, cls in ((cfg, _Config), (cfg.policy, AllowPolicy)):
        entries.append((obj, "__class__", _PIN_TYPE))
        entries += ((obj, slot, _PIN_ATTR) for slot in cls.__slots__)

    return entries


def _locked_refusal(call: str, message: str | None) -> TetheredLocked:
    """Word the refusal of ``call`` under a lock for where this interpreter stands.

    ``message`` is what the interpreter that took the lock is told, and one
    that joined it.  An interpreter outside the lock has no locked config of
    its own and is not the holder.
    """
    cfg = _config
    outside = (
        _c_guardian is not None and not _c_guardian.holds_lock() and (cfg is None or not cfg.locked)
    )
    if outside:
        return TetheredLocked(_OUTSIDE_THE_LOCK_MSG.format(call=call))
    return TetheredLocked(message)


def _is_idempotent_reactivation(requested_payload: str) -> bool:
    """Return True when a locked ``activate()`` re-requests the exact active policy.

    Auto-activated children (``tethered.pth``) re-run application startup
    code, so an app that calls ``activate(locked=True)`` at import time —
    the natural placement for a process-wide control (e.g. Django settings)
    — would otherwise crash with ``TetheredLocked`` in every spawn-mode
    child.  A re-activation whose canonical payload
    equals the active one changes nothing: no config swap, no guardian
    re-snapshot, no token rotation.  Treating it as a no-op is therefore
    safe — untrusted code gains nothing by re-requesting the policy that is
    already enforced.  ``on_blocked`` and ``lock_token`` from the no-op
    call are deliberately ignored (adopting a caller-supplied token would
    let untrusted code unlock the policy).

    ``requested_payload`` is the canonical serialized payload of the
    requested policy (what ``_build_env_payload(global, ())`` returns).  It
    is compared with the active config's ``_serialized_payload`` — an
    immutable ``str`` — not with the mutable ``_global_payload_dict``,
    whose contents can be edited in place without changing any pinned
    identity.  Comparing JSON text is also exact about types: ``0`` is not
    ``false``.

    Caller must hold ``_lifecycle_lock``.
    """
    current = _config
    if current is None or not current.locked:
        return False
    active_payload = current._serialized_payload
    if type(active_payload) is not str or type(requested_payload) is not str:
        return False
    if active_payload != requested_payload:
        return False
    logger.info(
        "tethered: activate() no-op — the requested policy is identical to "
        "the active locked policy (inherited via auto-propagation or "
        "activated earlier); on_blocked and lock_token from this call are "
        "ignored"
    )
    return True


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
            ``str``, ``int``, ``float``, ``complex``, ``bytes``, ``bool``,
            ``tuple`` or ``frozenset``, nor ``None``, ``Ellipsis`` or
            ``NotImplemented`` — these are singletons or immutable values
            that CPython may intern or cache, so a separately created equal
            value can be the very same object and defeat the lock.  Use
            ``object()`` or a custom instance.  The token is held only by
            the C guardian; tethered keeps no Python-visible copy of it, so
            whoever needs to unlock must keep their own reference.
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
            not available.  Also if tethered's audit hook cannot be
            installed because another audit hook in this process refused
            it (a hook that raises ``RuntimeError`` for the
            ``sys.addaudithook`` event makes Python drop a new hook without
            reporting an error): nothing would be enforced, so nothing is
            activated.  Also if the call is made from inside an
            ``activate()`` or ``deactivate()`` that the same thread is
            running in another interpreter of the process (waiting for
            that one would never end), or if another thread is in the
            middle of one while Python is shutting down.
        TypeError: If ``lock_token`` is a singleton or an instance of an
            immutable built-in type.
        ValueError: If ``locked=True`` is used without ``lock_token``,
            if ``external_subprocess_policy`` is not a recognized value, or
            if the policy cannot be published to child processes because
            its serialized form does not fit in an environment variable
            (Windows limits one to 32,767 characters).
        TetheredLocked: If a locked policy is active, the correct
            ``lock_token`` is not provided, and the requested policy
            differs from the active one.  Re-activating with an identical
            policy is an idempotent no-op (``on_blocked`` and
            ``lock_token`` from the no-op call are ignored) — this keeps
            apps that call ``activate(locked=True)`` at import time
            working inside auto-activated child processes.  Also raised,
            even with the correct token, when the active locked policy has
            failed its integrity check.

    The call is all-or-nothing: whenever it raises, the previously active
    policy (or none), the lock, and the policy published to child processes
    are exactly as they were.  Calls from several threads are serialized,
    and so are calls from several interpreters of the process: a call waits
    while another interpreter is in the middle of an ``activate()`` or
    ``deactivate()``, and then goes by what it finds (``TetheredLocked`` if
    that interpreter locked a policy).
    """
    global _config

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

    if locked:
        _validate_lock_token(lock_token)

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
        external_subprocess_policy=external_subprocess_policy,
        _serialized_payload=serialized_payload,
        _global_payload_dict=global_payload_dict,
        _pth_path=pth_path,
        _local_hostname=local_hostname,
    )

    activate_locked_msg = (
        "tethered: activate() blocked — a locked policy is active and the "
        "requested policy differs from it. Pass the original lock_token to "
        "replace a locked policy."
    )

    # (The try around the with: see _activation_claim.)
    held = _activation_claim.held()
    try:
        with _lifecycle_lock, _activation_claim:
            # The C guardian owns the lock: a locked policy exists only while
            # the guardian is active (locked=True requires the extension), and
            # only the guardian knows the token.  Without the extension
            # nothing can be locked, so there is nothing to check.  The
            # question is asked with the claim held, so the answer stands
            # until this call is over: an interpreter that waited here while
            # another one locked a policy is refused now, before it has
            # written anything.
            if _c_guardian is not None and _c_guardian.is_active():
                if not _c_guardian.check_token(lock_token):
                    if _is_idempotent_reactivation(serialized_payload):
                        return
                    raise _locked_refusal("activate()", activate_locked_msg)
                if not _c_guardian.verify():
                    raise TetheredLocked(_TAMPERED_POLICY_MSG)

            # Everything that can fail comes before anything is committed.
            _install_hook()
            snapshot = _build_integrity_snapshot(cfg) if locked else []
            previous = _config
            previous_env = os.environ.get(_CHILD_POLICY_ENV)
            try:
                # Publish the policy to spawn-mode child processes.  The
                # tethered.pth shipped at the top of site-packages reads the
                # variable in any Python interpreter that has tethered
                # installed and re-engages tethered with the same policy.
                # (Fork-mode children inherit tethered state through the
                # fork() copy.)  This write is the step most likely to fail —
                # Windows limits a variable to 32,767 characters — and, unlike
                # the commit, it can be undone, so it goes first.
                try:
                    _propagate_policy_to_env(cfg)
                except ValueError as exc:
                    msg = (
                        f"tethered: activate() failed — the policy could not be written to "
                        f"the {_CHILD_POLICY_ENV} environment variable for child processes "
                        f"({exc}). The serialized policy is {len(serialized_payload)} "
                        f"characters long; Windows limits an environment variable to 32,767. "
                        f"Nothing was changed. Shorten the allow list, for example by "
                        f"aggregating address ranges."
                    )
                    raise ValueError(msg) from exc

                # Commit.  When the guardian is involved it rebinds _config
                # itself, in the same uninterruptible step as its own state,
                # so that no audit event on another thread can see a config
                # and a guardian snapshot that belong to different policies.
                # Its deactivate() returns False, having done nothing, when no
                # policy was locked; the rebinding is then left to us.
                if _c_guardian is not None and locked:
                    _c_guardian.activate(globals(), cfg, lock_token, snapshot)
                elif _c_guardian is None or not _c_guardian.deactivate(lock_token, cfg):
                    _config = cfg
            except BaseException:
                # _config tells whether the commit happened: if it did not,
                # the previous policy is still the active one and its variable
                # goes back.
                if _config is not cfg:
                    _restore_policy_env(previous, previous_env)
                raise

            # Mappings recorded under the previous policy are dropped.  Not
            # part of the commit: an entry is a fact about DNS, and the new
            # policy is consulted for whatever hostname it yields.  A call
            # that puts the same policy in place again drops nothing: a
            # thread that has looked a name up and is about to connect
            # would be refused the address it was just given.
            if previous is None or previous._serialized_payload != serialized_payload:
                with _ip_map_lock:
                    _ip_to_hostname.clear()
                    _allowed_hostnames.clear()
    finally:
        _activation_claim.restore(held)

    # Surface a warning if no auto-propagation hook is in a directory that
    # site.py processes (see _compute_pth_path).  Without it, Python children
    # do not auto-activate, sys.executable launches are classified as
    # external, and locked-mode FS-tamper protection has no real target.
    if not pth_path or not os.path.isfile(pth_path):
        logger.warning(
            "tethered: tethered.pth not found at %s — no directory this "
            "interpreter's site.py processes holds it, so Python child processes "
            "will NOT auto-inherit the policy and sys.executable launches are "
            "treated as external (external_subprocess_policy applies).%s Typical "
            "causes: an editable install (pip install -e .), pip install --target "
            "with PYTHONPATH, or running with -S. Install tethered into "
            "site-packages for full coverage.",
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

    Raises:
        TetheredLocked: If a locked policy is active and ``lock_token`` is
            not its token, or if the locked policy has failed its integrity
            check (it then stays in place until the process exits).
        RuntimeError: When the call cannot wait for an ``activate()`` or
            ``deactivate()`` that is under way, in the two cases named for
            ``activate()``.

    Like ``activate()``, the call is all-or-nothing and is serialized with
    the ``activate()`` and ``deactivate()`` calls of other threads and of
    other interpreters of the process.
    """
    global _config

    # (The try around the with: see _activation_claim.)
    held = _activation_claim.held()
    try:
        with _lifecycle_lock, _activation_claim:
            # The C guardian owns the lock (see activate()); without the
            # extension no policy can be locked.
            if _c_guardian is not None and _c_guardian.is_active():
                if not _c_guardian.check_token(lock_token):
                    raise _locked_refusal("deactivate()", None)
                if not _c_guardian.verify():
                    raise TetheredLocked(_TAMPERED_POLICY_MSG)

            previous = _config
            previous_env = os.environ.get(_CHILD_POLICY_ENV)
            try:
                # As in activate(): the environment first, because that step
                # can fail and can be undone, then the commit.  Clearing the
                # variable keeps future child processes from inheriting a
                # policy that is no longer active.
                _clear_policy_from_env()
                if _c_guardian is None or not _c_guardian.deactivate(lock_token, None):
                    _config = None
            except BaseException:
                if _config is not None:
                    _restore_policy_env(previous, previous_env)
                raise

            with _ip_map_lock:
                _ip_to_hostname.clear()
                _allowed_hostnames.clear()
    finally:
        _activation_claim.restore(held)

    logger.info("tethered: deactivated")


def _join_locked(payload: str) -> None:
    """Join this interpreter to the policy another interpreter of the process has locked.

    For the ``tethered.pth`` bootstrap of an interpreter that is created
    while a policy is locked.  A lock exists once per process, and so does
    its token: such an interpreter cannot take the lock, it joins it.  It
    then holds a ``locked`` config of its own, pinned by an integrity
    snapshot of its own modules, and the C guardian verifies its guarded
    events as it does the owner's.  The guardian accepts a join only while
    the interpreter starts — before anything but its startup files has run
    in it — and only once.

    ``payload`` is the guardian's own copy of the locked policy's serialized
    payload (``_c_guardian.locked_payload()``), not the value of
    ``_TETHERED_CHILD_POLICY``, which code in the process can change.  The
    policy is rebuilt from it with the functions :func:`activate` uses; the
    guardian then compares the rebuilt ``_serialized_payload`` with its
    copy, byte for byte, so a payload this code would read differently is
    refused, never approximated.

    Nothing is published: the variable is one for the whole process and
    already carries the payload.  No token is involved: the lock stays the
    owning interpreter's to replace or release, and ``on_blocked`` does not
    cross interpreters.

    Raises ``RuntimeError`` when the guardian refuses the join, and
    ``TypeError`` / ``ValueError`` / ``KeyError`` for a payload that is not
    that of a locked policy.  ``_config`` is bound only by a successful join.
    """
    if _c_guardian is None:
        msg = "tethered: joining a locked policy requires the C guardian extension"
        raise RuntimeError(msg)

    fields = json.loads(payload)["global"]
    allow = fields["allow"]
    external_subprocess_policy = fields["external_subprocess_policy"]
    flags = {
        name: fields[name] for name in ("allow_localhost", "log_only", "fail_closed", "locked")
    }
    _validate_allow(allow)
    for name, value in flags.items():
        _validate_bool(value, name)
    if not flags["locked"] or external_subprocess_policy not in _EXTERNAL_SUBPROCESS_POLICIES:
        msg = "tethered: the payload to join is not that of a locked policy"
        raise ValueError(msg)

    policy = AllowPolicy(allow, allow_localhost=flags["allow_localhost"])
    global_payload_dict = _build_global_payload_dict(
        policy,
        log_only=flags["log_only"],
        fail_closed=flags["fail_closed"],
        external_subprocess_policy=external_subprocess_policy,
        locked=True,
    )
    cfg = _Config(
        policy=policy,
        log_only=flags["log_only"],
        fail_closed=flags["fail_closed"],
        locked=True,
        external_subprocess_policy=external_subprocess_policy,
        _serialized_payload=_build_env_payload(global_payload_dict, ()),
        _global_payload_dict=global_payload_dict,
        _pth_path=_compute_pth_path(),
        _local_hostname=_capture_local_hostname(),
    )
    with _lifecycle_lock:
        _install_hook()
        # The guardian binds _config itself, in one step with its own state
        # (see activate()).
        _c_guardian.join(globals(), cfg, _build_integrity_snapshot(cfg))
    logger.info(
        "tethered: joined the locked policy of this process with %d rules (log_only=%s)",
        len(allow),
        cfg.log_only,
    )


def _restore_policy_env(previous: _Config | None, previous_env: str | None) -> None:
    """Put ``_TETHERED_CHILD_POLICY`` back after a transition that did not commit.

    ``previous`` is the config that is still active and ``previous_env``
    the value the variable had before the transition started.  A locked
    policy's variable is rewritten from the policy itself, through the same
    writer that published it.  Otherwise the earlier value is restored as
    it was — including a value tethered did not write, such as a scope-only
    payload a child inherited without any global policy.
    """
    if previous is not None and previous.locked:
        _propagate_policy_to_env(previous)
    elif previous_env is None:
        _clear_policy_from_env()
    else:
        os.environ[_CHILD_POLICY_ENV] = previous_env


def _serialize_network_rule(rule: Any) -> str:
    """Serialize a ``_NetworkRule`` for round-tripping through child processes.

    Plain ``f"{network}:{port}"`` is unambiguous for IPv4 (``10.0.0.0/8:5432``)
    but ambiguous for IPv6 — the address itself contains colons, so the
    parser cannot tell where the address ends and the port begins.  Bracket
    IPv6 networks when a port is present so the serialized form matches the
    bracketed syntax accepted by ``AllowPolicy`` (``[2001:db8::]/32:443``).

    A rule stores its network as integers; ``rule.network`` rebuilds the
    ``ipaddress`` object on each access, so it is read once here.
    """
    network = rule.network
    if rule.port is None:
        return str(network)
    if network.version == 6:
        addr, _, prefix = str(network).partition("/")
        bracketed = f"[{addr}]/{prefix}" if prefix else f"[{addr}]"
        return f"{bracketed}:{rule.port}"
    return f"{network}:{rule.port}"


def _serialize_allow_list(policy: AllowPolicy) -> list[str]:
    """Serialize a policy's allow rules as a deterministically ordered list.

    Exact-host rules live in frozensets whose iteration order follows string
    hashing — randomized per process (``PYTHONHASHSEED``) — so an unsorted
    dump can differ between the parent that serialized a payload and the
    spawn-mode child that rebuilds its canonical payload from it.  The
    locked-mode payload-integrity check in :func:`_handle_subprocess`
    compares ``allow`` lists order-sensitively (dict equality), so the
    serialization must be reproducible across interpreters: sort the
    combined list.  Sorting is round-trip stable — every entry is a
    normalized string, so parse → re-serialize yields the identical list.

    ``AllowPolicy`` strips exactly one trailing dot from a rule's host
    part, so a stored pattern that still ends in a dot (from ``"host.."``)
    gets that dot back here; otherwise the child would strip the remaining
    one and hold a different rule than the parent.
    """

    def host_rule(pattern: str, port: int | None) -> str:
        if pattern.endswith("."):
            pattern += "."
        return pattern if port is None else f"{pattern}:{port}"

    return sorted(
        [host_rule(h, None) for h in policy._exact_hosts_any_port]
        + [host_rule(h, p) for h, p in policy._exact_hosts]
        + [host_rule(r.pattern, r.port) for r in policy._host_rules]
        + [_serialize_network_rule(r) for r in policy._network_rules]
    )


# Environment variable used to propagate the active tethered policy to child
# processes.  The parent's activate() populates it; deactivate() clears it.
# Spawn-mode children with tethered installed read it via tethered.pth →
# tethered._autoactivate on interpreter startup and re-engage tethered with
# the same policy.  Fork-mode children inherit tethered state directly via
# the OS fork() copy and don't need this env var.
_CHILD_POLICY_ENV = "_TETHERED_CHILD_POLICY"

# Windows environment names are case-insensitive: every case variant of the
# policy key is the same variable to the child.
_ENV_NAMES_IGNORE_CASE = sys.platform == "win32"

# True while a native change to the policy variable that did not come from
# tethered may have left the process environment different from what
# ``os.environ`` shows (see ``_handle_env_change``).  Runtime state: the next
# launch that inherits the environment refuses (locked mode) or re-asserts
# the payload and clears the flag.
_env_dirty: bool = False

# Set while tethered itself writes the policy variable, so its own
# ``os.putenv`` / ``os.unsetenv`` audit events never set ``_env_dirty``.
_in_env_sync: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "tethered_in_env_sync", default=False
)


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
    The ``allow`` list is sorted (:func:`_serialize_allow_list`) so the
    canonical form is identical in every process that holds the same
    policy — a spawn-mode child rebuilding it from the inherited payload
    produces the exact same dict despite per-process hash randomization.

    ``on_blocked`` and ``lock_token`` are NOT propagated.  Callbacks can't
    cross process boundaries (function identity).  Lock tokens are identity-
    compared and can't survive serialization — each child re-engages locked
    mode (if requested) with its own fresh per-process token.
    """
    return {
        "allow": _serialize_allow_list(policy),
        "allow_localhost": policy._allow_localhost,
        "log_only": log_only,
        "fail_closed": fail_closed,
        "external_subprocess_policy": external_subprocess_policy,
        "locked": locked,
    }


def _serialize_scope(scope_cfg: _ScopeConfig) -> dict[str, Any]:
    """Serialize a ``_ScopeConfig`` for cross-process propagation.

    Mirrors :func:`_build_global_payload_dict`.  ``on_blocked`` is not
    propagated (function identity can't cross process boundaries).  ``hint``
    travels alongside ``label`` so a child blocked by an inherited scope
    surfaces the same actionable guidance as the parent would.
    """
    policy = scope_cfg.policy
    return {
        "allow": _serialize_allow_list(policy),
        "allow_localhost": policy._allow_localhost,
        "log_only": scope_cfg.log_only,
        "fail_closed": scope_cfg.fail_closed,
        "label": scope_cfg.label,
        "hint": scope_cfg.hint,
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
    :func:`_launch_payload` when scopes are active.
    """
    return json.dumps(
        {
            "global": global_dict,
            "scopes": [_serialize_scope(s) for s in scope_stack],
        }
    )


def _build_child_policy_payload(cfg: _Config) -> dict[str, Any]:
    """Rebuild the canonical ``global`` dict from ``cfg``'s fields.

    Production configs carry it serialized in ``_serialized_payload`` (see
    :func:`_canonical_payload`); this rebuild serves configs constructed
    without that field, as tests do.
    """
    return _build_global_payload_dict(
        cfg.policy,
        log_only=cfg.log_only,
        fail_closed=cfg.fail_closed,
        external_subprocess_policy=cfg.external_subprocess_policy,
        locked=cfg.locked,
    )


def _canonical_payload(cfg: _Config) -> str:
    """Return the canonical at-rest payload for ``cfg``.

    ``cfg._serialized_payload`` — an immutable ``str`` whose identity the C
    guardian protects in locked mode — is the source of truth for everything
    tethered compares a launch environment against or writes into one.  The
    mutable ``cfg._global_payload_dict`` is never consulted: code in the
    process can alter its contents without changing its identity.  A config
    built without the serialized field gets the payload rebuilt from its
    fields.
    """
    return cfg._serialized_payload or _build_env_payload(_build_child_policy_payload(cfg), ())


def _compute_pth_path() -> str:
    """Return the normalized path of the ``tethered.pth`` hook this interpreter processes.

    ``site.py`` executes ``.pth`` files only in site directories: the
    site-packages of the interpreter's prefixes and, when enabled, the
    per-user site-packages.  A ``tethered.pth`` anywhere else is never run —
    beside the package of an editable checkout, or in a ``pip install
    --target`` directory that is merely on ``PYTHONPATH`` — so it is not a
    bootstrap, however close to the imported package it sits.

    The hook next to the imported package is preferred when that directory
    is a site directory (``setup.py``'s ``build_py_with_pth`` installs it
    there, which also covers ``--user`` installs); otherwise the site
    directories are searched in the order ``site`` processes them.

    Returns ``""`` when no site directory holds the hook, or when this
    interpreter runs without ``site`` (``-S``).  Python children then do not
    auto-activate, and the locked-mode FS hook has nothing to guard.
    """
    if sys.flags.no_site:
        return ""
    import site

    import tethered

    # sys.prefix comes first because, while a venv interpreter starts up,
    # site.PREFIXES still names the base installation at the moment the
    # venv's own site-packages is processed — which is when tethered.pth
    # auto-activates a child and that child's activate() lands here.
    site_dirs = site.getsitepackages([sys.prefix, sys.exec_prefix, *site.PREFIXES])
    if site.ENABLE_USER_SITE and site.USER_SITE:
        site_dirs.append(site.USER_SITE)
    candidates = [_normalize_path(os.path.join(d, "tethered.pth")) for d in site_dirs]

    pkg_init = getattr(tethered, "__file__", None)
    if pkg_init is not None:
        adjacent = _normalize_path(
            os.path.join(os.path.dirname(os.path.dirname(pkg_init)), "tethered.pth")
        )
        if adjacent in candidates:
            candidates.insert(0, adjacent)
    for path in candidates:
        if os.path.isfile(path):
            return path
    return ""


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
    """Populate ``_TETHERED_CHILD_POLICY`` so child processes inherit the policy.

    The assignment updates ``os.environ`` and the native environment
    together, so it ends any divergence ``_env_dirty`` recorded.  The flag
    is cleared first: a foreign change racing with the write leaves it set.

    The caller holds ``_activation_claim``: the variable is the whole
    process's, and no interpreter writes it for tethered while another one
    is publishing and committing a policy.
    """
    global _env_dirty
    token = _in_env_sync.set(True)
    try:
        _env_dirty = False
        os.environ[_CHILD_POLICY_ENV] = _canonical_payload(cfg)
    finally:
        _in_env_sync.reset(token)


def _reassert_policy_env(cfg: _Config) -> None:
    """Put the payload of the unlocked policy ``cfg`` back into the variable.

    For the subprocess hook, when a child would inherit an environment that
    no longer carries the payload (an ordinary cleanup of ``os.environ``, a
    native ``os.unsetenv``).  The write has to take its turn like the one
    ``activate()`` makes, so this is the one place where the hook takes
    locks: ``_lifecycle_lock`` and then the claim, in that order.  That can
    mean waiting for a transition that is under way, in this interpreter or
    in another one.

    Nothing is written if ``cfg`` was replaced or deactivated during that
    wait: the variable then says what the transition left there, and
    ``cfg`` is no longer anybody's to publish.  The launch itself is still
    judged by ``cfg``, the policy it was started under, like every launch
    whose audit event comes just before a transition.

    If another interpreter has locked a policy meanwhile, the write is
    refused by the C guardian and the ``SubprocessBlocked`` it raises
    refuses this launch, like every later launch from this interpreter.
    """
    # (The try around the with: see _activation_claim.)
    held = _activation_claim.held()
    try:
        with _lifecycle_lock, _activation_claim:
            if _config is cfg:
                _propagate_policy_to_env(cfg)
    finally:
        _activation_claim.restore(held)


def _clear_policy_from_env() -> None:
    """Remove ``_TETHERED_CHILD_POLICY`` so future children don't inherit a stale policy.

    The caller holds ``_activation_claim``, as for
    :func:`_propagate_policy_to_env`.
    """
    global _env_dirty
    token = _in_env_sync.set(True)
    try:
        _env_dirty = False
        os.environ.pop(_CHILD_POLICY_ENV, None)
    finally:
        _in_env_sync.reset(token)
