"""Tests for locked mode and the C-level integrity guardian."""

from __future__ import annotations

import _socket
import builtins
import copy
import functools
import gc
import logging
import pickle
import socket
import sys
import threading
import types
import unittest.mock
import weakref

import pytest

import tethered
import tethered._core as _core
import tethered._policy as _policy
from tethered._core import _audit_hook, _ip_map_lock, _ip_to_hostname
from tethered._policy import AllowPolicy

requires_network = pytest.mark.requires_network


class TestLockedMode:
    def test_locked_activation_requires_token(self):
        with pytest.raises(ValueError, match="lock_token is required"):
            tethered.activate(allow=["*.example.com"], locked=True)

    @pytest.mark.parametrize(
        "token",
        [
            "secret",
            42,
            3.14,
            b"key",
            True,
            # Singletons and immutable containers: an independently created
            # equal value is (or can be) the very same object.
            (),
            ("a", "b"),
            frozenset(),
            frozenset({"a"}),
            1j,
            Ellipsis,
            NotImplemented,
        ],
        ids=repr,
    )
    def test_lock_token_rejects_internable_types(self, token):
        with pytest.raises(TypeError, match="must not be a str"):
            tethered.activate(allow=["*.example.com"], locked=True, lock_token=token)
        assert _core._config is None
        assert _core._c_guardian.is_active() is False

    def test_lock_token_internable_type_allowed_when_not_locked(self):
        """Internable lock_token types are accepted when locked=False (token is discarded)."""
        tethered.activate(allow=["*.example.com"], lock_token="secret")
        tethered.deactivate()  # Should succeed — policy is not locked

    def test_lock_token_without_locked_ignored(self):
        """lock_token without locked=True is accepted but ignored for the new policy."""
        tethered.activate(allow=["*.example.com"], lock_token=object())
        tethered.deactivate()  # Should succeed — policy is not locked

    def test_locked_deactivate_without_token_raises(self):
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        with pytest.raises(tethered.TetheredLocked):
            tethered.deactivate()

    def test_locked_deactivate_with_wrong_token_raises(self):
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        with pytest.raises(tethered.TetheredLocked):
            tethered.deactivate(lock_token=object())

    @requires_network
    def test_locked_deactivate_with_correct_token_succeeds(self):
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        tethered.deactivate(lock_token=secret)
        # After deactivation, tethered no longer blocks
        socket.getaddrinfo("dns.google", 80)

    def test_locked_policy_still_enforces(self):
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

    def test_reactivate_over_locked_requires_token(self):
        """activate() over a locked policy requires the correct lock_token."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        with pytest.raises(tethered.TetheredLocked):
            tethered.activate(allow=["evil.test"])

    def test_reactivate_over_locked_with_correct_token(self):
        """activate() with the correct lock_token replaces a locked policy."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        tethered.activate(allow=["evil.test"], lock_token=secret, locked=True)
        # New policy is active
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("other.com", 80)

    def test_reactivate_over_locked_unlocked_replacement(self):
        """activate() with correct token can replace locked with unlocked policy."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        # Same token authenticates against old policy; new policy is unlocked
        # because locked defaults to False when lock_token matches old config
        tethered.activate(allow=["evil.test"], lock_token=secret)
        tethered.deactivate()  # Should succeed (new policy is not locked)

    def test_reactivate_locked_identical_policy_is_noop(self, caplog):
        """activate() re-requesting the exact active locked policy is a no-op.

        Auto-activated children re-run app startup code; apps calling
        activate(locked=True) at import time must not crash there.
        """
        secret = object()
        tethered.activate(
            allow=["*.example.com", "db.internal:5432"], locked=True, lock_token=secret
        )
        before = _core._config
        with caplog.at_level(logging.INFO, logger="tethered"):
            tethered.activate(
                allow=["*.example.com", "db.internal:5432"],
                locked=True,
                lock_token=object(),
            )
        assert _core._config is before
        assert any("no-op" in r.message for r in caplog.records)
        # Policy still enforces after the no-op
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

    def test_reactivate_locked_identical_rules_reordered_is_noop(self):
        """Rule order doesn't matter — the canonical payload comparison is order-stable."""
        secret = object()
        tethered.activate(
            allow=["a.example.com:443", "b.example.com:443"], locked=True, lock_token=secret
        )
        before = _core._config
        tethered.activate(
            allow=["b.example.com:443", "a.example.com:443"],
            locked=True,
            lock_token=object(),
        )
        assert _core._config is before

    def test_reactivate_locked_noop_keeps_original_token(self):
        """The no-op call's lock_token is ignored — only the original token unlocks."""
        secret = object()
        imposter = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=imposter)
        with pytest.raises(tethered.TetheredLocked):
            tethered.deactivate(lock_token=imposter)
        tethered.deactivate(lock_token=secret)  # original token still unlocks

    def test_reactivate_locked_noop_ignores_on_blocked(self):
        """The no-op call's on_blocked callback is not adopted."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        tethered.activate(
            allow=["*.example.com"],
            locked=True,
            lock_token=object(),
            on_blocked=lambda host, port: None,
        )
        assert _core._config.on_blocked is None

    def test_reactivate_locked_different_flag_still_raises(self):
        """Same rules but a differing flag (log_only) is not idempotent — still blocked."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        with pytest.raises(tethered.TetheredLocked, match=r"activate\(\) blocked"):
            tethered.activate(
                allow=["*.example.com"],
                locked=True,
                lock_token=object(),
                log_only=True,
            )


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestLockTokenHeldInC:
    """The lock token lives only in the C guardian (R29)."""

    def test_token_is_not_stored_on_the_python_side(self):
        """No config field or module global holds the token or its id()."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        cfg = _core._config
        assert "lock_token" not in _core._Config.__slots__
        assert not hasattr(cfg, "lock_token")
        assert not hasattr(_core, "_guardian_token_id")
        for slot in _core._Config.__slots__:
            assert getattr(cfg, slot) is not secret
        for module in (_core, sys.modules["tethered._policy"], tethered):
            for name, value in vars(module).items():
                assert value is not secret, name
                assert not (type(value) is int and value == id(secret)), name

    def test_reading_the_token_back_from_the_config_does_not_unlock(self):
        """The report's one-liner: deactivate(lock_token=_config.lock_token)."""
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=object())
        with pytest.raises(tethered.TetheredLocked):
            tethered.deactivate(lock_token=getattr(_core._config, "lock_token", None))
        assert _core._c_guardian.is_active() is True
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

    def test_guardian_rejects_the_token_id(self):
        """The guardian compares the object, so a recovered id() is useless."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        with pytest.raises(RuntimeError, match="lock_token"):
            _core._c_guardian.deactivate(id(secret))
        assert _core._c_guardian.check_token(id(secret)) is False
        assert _core._c_guardian.is_active() is True

    def test_equal_but_distinct_object_does_not_unlock(self):
        """Comparison is by identity: ``__eq__`` is never consulted."""

        class AlwaysEqual:
            def __eq__(self, other):
                return True

            def __hash__(self):
                return 0

        secret = AlwaysEqual()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        with pytest.raises(tethered.TetheredLocked):
            tethered.deactivate(lock_token=AlwaysEqual())
        with pytest.raises(tethered.TetheredLocked):
            tethered.activate(allow=["evil.test"], lock_token=AlwaysEqual())
        tethered.deactivate(lock_token=secret)
        assert _core._c_guardian.is_active() is False

    def test_check_token(self):
        secret = object()
        guardian = _core._c_guardian
        assert guardian.check_token(object()) is True  # nothing is locked
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        assert guardian.check_token(secret) is True
        assert guardian.check_token(object()) is False
        assert guardian.check_token(None) is False

    def test_guardian_keeps_the_token_alive(self):
        """The guardian holds a strong reference, so the address is never reused.

        Uses the unwrapped ``_core.activate`` so conftest's token recorder
        does not hold a reference of its own.
        """

        class Token:
            pass

        secret = Token()
        watcher = weakref.ref(secret)
        _core.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        del secret
        gc.collect()
        survivor = watcher()
        assert survivor is not None, "the guardian must keep the token alive"
        tethered.deactivate(lock_token=survivor)
        del survivor
        gc.collect()
        assert watcher() is None, "deactivation must release the token"

    def test_unlocked_activation_ignores_and_does_not_keep_the_token(self):
        class Token:
            pass

        token = Token()
        watcher = weakref.ref(token)
        _core.activate(allow=["*.example.com"], lock_token=token)
        del token
        gc.collect()
        assert watcher() is None
        tethered.deactivate()


class TestLockedRequiresCGuardian:
    def test_locked_raises_without_c_guardian(self):
        """locked=True raises RuntimeError if C guardian is unavailable."""
        with (
            unittest.mock.patch.object(_core, "_c_guardian", None),
            pytest.raises(RuntimeError, match="C guardian extension"),
        ):
            tethered.activate(allow=["*.example.com"], locked=True, lock_token=object())


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestCGuardian:
    """Tests for the C-level tamper detector."""

    def test_guardian_activates_with_locked_mode(self):
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        assert _core._c_guardian.is_active() is True

    def test_guardian_not_activated_without_locked(self):
        tethered.activate(allow=["*.example.com"])
        assert _core._c_guardian.is_active() is False

    def test_tamper_blocks_all_network(self):
        """Setting _config = None blocks ALL connections (fail-closed)."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        _core._config = None
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)
        # Even allowed hosts are blocked after tamper
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("anything.example.com", 80)

    def test_tamper_with_replacement_config(self):
        """Replacing _config with a permissive policy is detected."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        permissive = _core._Config(policy=AllowPolicy(["evil.test"]))
        _core._config = permissive
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

    def test_monkey_patch_policy_with_config_tamper(self):
        """Monkey-patching is_allowed + _config=None doesn't bypass guardian."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        original = AllowPolicy.is_allowed
        try:
            AllowPolicy.is_allowed = lambda self, *a, **k: True
            _core._config = None
            with pytest.raises(tethered.EgressBlocked):
                socket.getaddrinfo("evil.test", 80)
        finally:
            AllowPolicy.is_allowed = original

    def test_monkey_patch_policy_without_config_tamper(self):
        """Monkey-patching is_allowed without changing _config is also detected."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        original = AllowPolicy.is_allowed
        try:
            AllowPolicy.is_allowed = lambda self, *a, **k: True
            # _config is NOT changed — guardian detects the method replacement
            with pytest.raises(tethered.EgressBlocked):
                socket.getaddrinfo("evil.test", 80)
        finally:
            AllowPolicy.is_allowed = original

    def test_inplace_config_policy_mutation_detected(self):
        """object.__setattr__(cfg, 'policy', ...) is detected."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        cfg = _core._config
        permissive = AllowPolicy(["evil.test"])
        object.__setattr__(cfg, "policy", permissive)
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

    def test_inplace_config_log_only_mutation_detected(self):
        """object.__setattr__(cfg, 'log_only', True) is detected."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        cfg = _core._config
        object.__setattr__(cfg, "log_only", True)
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

    def test_inplace_config_local_hostname_mutation_detected(self):
        """Mutating ``cfg._local_hostname`` to widen the self-introspection exemption is detected.

        Without snapshot protection, a malicious dep could set
        ``cfg._local_hostname = "evil.test"`` to make ``gethostbyaddr("evil.test")``
        bypass the policy check.  Because ``_local_hostname`` is part of
        ``_Config.__slots__``, it's auto-included in the integrity snapshot.
        """
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        cfg = _core._config
        assert cfg is not None
        object.__setattr__(cfg, "_local_hostname", "evil.test")
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

    def test_inplace_policy_internals_mutation_detected(self):
        """Mutating AllowPolicy._exact_hosts_any_port is detected."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        policy = _core._config.policy
        object.__setattr__(policy, "_exact_hosts_any_port", frozenset({"evil.test"}))
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

    def test_guardian_noop_when_not_tampered(self):
        """Guardian is a no-op when _config matches (main hook enforces)."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        # Main hook should block — guardian should not interfere
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

    def test_deactivate_with_correct_token(self):
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        tethered.deactivate(lock_token=secret)
        assert _core._c_guardian.is_active() is False

    def test_inject_scope_env_replacement_detected(self):
        """Replacing _inject_scope_env with a no-op (defeating scope inheritance) is detected."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        original = _core._inject_scope_env
        try:
            _core._inject_scope_env = lambda frame, env: True  # silently no-op
            with pytest.raises(tethered.EgressBlocked):
                socket.getaddrinfo("evil.test", 80)
        finally:
            _core._inject_scope_env = original

    def test_find_execute_child_frame_replacement_detected(self):
        """Replacing _find_execute_child_frame to always return None is detected."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        original = _core._find_execute_child_frame
        try:
            _core._find_execute_child_frame = lambda: None
            with pytest.raises(tethered.EgressBlocked):
                socket.getaddrinfo("evil.test", 80)
        finally:
            _core._find_execute_child_frame = original

    def test_fallback_resolve_replacement_detected(self):
        """Swapping _fallback_resolve with a no-op is detected by the snapshot."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        original = _core._fallback_resolve
        try:
            _core._fallback_resolve = lambda ip, port: None  # silently no-op
            with pytest.raises(tethered.EgressBlocked):
                socket.getaddrinfo("evil.test", 80)
        finally:
            _core._fallback_resolve = original

    def test_deactivate_without_token_blocked_by_guardian(self):
        """C guardian blocks deactivation even if _config is tampered to unlocked."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        # Tamper _config to an unlocked config
        _core._config = _core._Config(policy=AllowPolicy(["*.example.com"]))
        # deactivate() without token should STILL fail — C guardian owns the lock
        with pytest.raises(tethered.TetheredLocked):
            tethered.deactivate()

    def test_reactivate_requires_token_from_guardian(self):
        """activate() over locked policy requires token from C guardian, not _config."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        _core._config = _core._Config(policy=AllowPolicy([]))  # tamper
        with pytest.raises(tethered.TetheredLocked):
            tethered.activate(allow=["evil.test"], locked=True, lock_token=object())

    def test_guardian_replaced_on_reactivate(self):
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        tethered.activate(allow=["*.other.com"], locked=True, lock_token=secret)
        assert _core._c_guardian.is_active() is True

    def test_tamper_alert_writes_to_stderr(self, capfd):
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        _core._config = None
        try:
            socket.getaddrinfo("evil.test", 80)
        except tethered.EgressBlocked:
            pass
        captured = capfd.readouterr()
        assert "TAMPER DETECTED" in captured.err

    def test_sys_modules_replacement_ineffective(self):
        """Replacing sys.modules['tethered._core'] does not bypass guardian.

        The C guardian caches a direct pointer to the real module at
        activation time and never looks it up through sys.modules.
        """
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        real_module = sys.modules["tethered._core"]
        try:
            # Replace the module in sys.modules with a fake
            fake = type(sys)("fake_core")
            fake._config = None
            sys.modules["tethered._core"] = fake
            # Guardian still uses the real cached module — enforcement intact
            with pytest.raises(tethered.EgressBlocked):
                socket.getaddrinfo("evil.test", 80)
        finally:
            sys.modules["tethered._core"] = real_module

    def test_concurrent_socket_during_deactivation(self):
        """Socket events concurrent with deactivation must not crash.

        Exercises the race window where a thread has passed the
        guardian_active check and is walking the snapshot while another
        thread deactivates (clears the snapshot).  With heap-allocated
        snapshots this would be a use-after-free; with the static array
        the worst case is a benign fail-closed block or a no-op.
        """
        secret = object()
        errors: list[BaseException] = []
        barrier = threading.Barrier(2, timeout=5)

        def socket_storm():
            """Hammer getaddrinfo while guardian is being deactivated."""
            try:
                barrier.wait()
                for _ in range(200):
                    try:
                        socket.getaddrinfo("anything.example.com", 80)
                    except (tethered.EgressBlocked, OSError):
                        pass
            except Exception as exc:
                errors.append(exc)

        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)

        t = threading.Thread(target=socket_storm)
        t.start()
        barrier.wait()
        tethered.deactivate(lock_token=secret)
        t.join(timeout=10)

        assert not t.is_alive(), "socket_storm thread hung"
        assert not errors, f"socket_storm raised: {errors}"

    def test_concurrent_socket_during_reactivation(self):
        """Socket events concurrent with reactivation must not crash.

        Exercises the snapshot swap path in build_snapshot (clear old,
        memcpy new) while another thread is iterating the snapshot via
        verify_integrity.
        """
        secret = object()
        errors: list[BaseException] = []
        stop = threading.Event()

        def socket_storm():
            try:
                while not stop.is_set():
                    try:
                        socket.getaddrinfo("anything.example.com", 80)
                    except (tethered.EgressBlocked, OSError):
                        pass
            except Exception as exc:
                errors.append(exc)

        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)

        t = threading.Thread(target=socket_storm)
        t.start()
        # Repeatedly swap the guardian while socket events are firing
        for _ in range(50):
            tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        stop.set()
        t.join(timeout=10)

        assert not t.is_alive(), "socket_storm thread hung"
        assert not errors, f"socket_storm raised: {errors}"


# ── Generated integrity snapshot (R27) ─────────────────────────────

_MODULES = (_core, _policy)

# Module globals that are deliberately NOT identity-pinned in locked mode.
# Every other name in ``tethered._core`` / ``tethered._policy`` must be in the
# snapshot.  A new module-level name that trips
# ``test_every_module_global_is_pinned_or_allowlisted`` needs a decision:
#
# - it is state tethered rebinds at runtime (a flag, a counter): keep it a
#   lower-case ``None``/``bool``/``int``/``float``/``str`` and list it here
#   with the reason;
# - it is anything else: it is pinned automatically — unless it is a
#   lower-case scalar *constant*, in which case give it an UPPER_CASE name.
_MODULE_METADATA = {
    "__name__": "import-system metadata (str); not consulted by enforcement",
    "__doc__": "import-system metadata (str); not consulted by enforcement",
    "__package__": "import-system metadata (str); not consulted by enforcement",
    "__file__": "import-system metadata (str); not consulted by enforcement",
    "__cached__": "import-system metadata (str); not consulted by enforcement",
}
_UNPINNED_GLOBALS = {
    "tethered._core": {
        "_config": "the active config; the guardian tracks its identity separately",
        "_hook_installed": "flips False -> True when the audit hook is installed",
        **_MODULE_METADATA,
    },
    "tethered._policy": dict(_MODULE_METADATA),
}


def _pinned_globals() -> list[tuple[types.ModuleType, str]]:
    return [
        (module, name)
        for module in _MODULES
        for name, value in vars(module).items()
        if not _core._is_unpinned_global(name, value)
    ]


def _global_id(param: tuple[types.ModuleType, str]) -> str:
    module, name = param
    return f"{module.__name__.rpartition('.')[2]}.{name}"


def _own_classes() -> list[type]:
    names = {module.__name__ for module in _MODULES}
    found: dict[int, type] = {}
    for module in _MODULES:
        for value in vars(module).values():
            if isinstance(value, type) and value.__module__ in names:
                found[id(value)] = value
    return list(found.values())


# Class-namespace keys that ``type`` manages through its own setters, so an
# assignment from Python does not simply rebind the key: ``__dict__`` is not
# writable, assigning ``__module__`` also drops ``__firstlineno__`` (3.13+),
# and on 3.14 assigning ``__annotations__`` writes a separate cache key.
# They are pinned like every other key; the rebinding test just cannot
# exercise them with a plain ``setattr``.
_TYPE_MANAGED_ATTRIBUTES = frozenset(
    (
        "__dict__",
        "__module__",
        "__annotations__",
        "__annotate__",
        "__annotate_func__",
        "__annotations_cache__",
    )
)


def _activate_locked(**kwargs: object) -> None:
    kwargs.setdefault("allow", ["*.example.com"])
    tethered.activate(locked=True, lock_token=object(), **kwargs)


def _assert_intact(capfd: pytest.CaptureFixture[str]) -> None:
    """A guarded event the policy allows still passes, with no tamper alert.

    ``localhost`` resolves from the hosts file, so the probe stays offline.
    """
    socket.getaddrinfo("localhost", 80)
    assert "TAMPER DETECTED" not in capfd.readouterr().err


def _assert_tamper_response(
    capfd: pytest.CaptureFixture[str],
    exc: type[BaseException] = tethered.EgressBlocked,
) -> None:
    """Even a destination the policy allows is refused, and the alert is written."""
    capfd.readouterr()
    with pytest.raises(exc):
        socket.getaddrinfo("localhost", 80)
    assert "TAMPER DETECTED" in capfd.readouterr().err


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestSnapshotCoverage:
    """The snapshot is generated from the modules, so nothing is left out by omission."""

    @staticmethod
    def _entries() -> list[tuple[object, str, int]]:
        tethered.activate(allow=["*.example.com"])
        return _core._build_integrity_snapshot(_core._config)

    @pytest.mark.parametrize("module", _MODULES, ids=lambda m: m.__name__)
    def test_every_module_global_is_pinned_or_allowlisted(self, module):
        namespace = vars(module)
        pinned = {
            name
            for owner, name, kind in self._entries()
            if owner is namespace and kind == _core._PIN_ITEM
        }
        allowlist = _UNPINNED_GLOBALS[module.__name__]
        unpinned = set(namespace) - pinned
        undecided = sorted(unpinned - set(allowlist))
        assert not undecided, (
            f"{module.__name__} has module-level names that are neither pinned by the "
            f"locked-mode integrity snapshot nor allow-listed as runtime state: {undecided}. "
            "See the comment above _UNPINNED_GLOBALS in this file."
        )
        # The allowlist must not go stale either: a listed name that exists
        # is really unpinned.
        assert not sorted(set(allowlist) & pinned)

    def test_config_is_never_pinned_as_a_module_global(self):
        """``_config`` is swapped on every activation; the guardian checks it directly."""
        assert all(
            not (owner is vars(_core) and name == "_config") for owner, name, _ in self._entries()
        )

    def test_every_function_of_both_modules_has_a_code_pin(self):
        code_pinned = {id(owner) for owner, _, kind in self._entries() if kind == _core._PIN_CODE}
        missing = []
        for module in _MODULES:
            for name, value in vars(module).items():
                if isinstance(value, types.FunctionType) and id(value) not in code_pinned:
                    missing.append(f"{module.__name__}.{name}")
        for cls in _own_classes():
            for name, value in vars(cls).items():
                func = getattr(value, "__func__", value)
                if isinstance(func, types.FunctionType) and id(func) not in code_pinned:
                    missing.append(f"{cls.__qualname__}.{name}")
        assert not missing

    def test_every_class_attribute_is_pinned(self):
        entries = self._entries()
        classes = _own_classes()
        # The classes the brief names, plus everything else defined in the modules.
        assert {
            _policy.AllowPolicy,
            _policy._HostRule,
            _policy._NetworkRule,
            _core.EgressBlocked,
            _core.SubprocessBlocked,
            _core.TetheredLocked,
            _core._Config,
        } <= set(classes)
        for cls in classes:
            pinned = {
                name for owner, name, kind in entries if owner is cls and kind == _core._PIN_ITEM
            }
            assert pinned == set(vars(cls)), cls
            absent = {
                name for owner, name, kind in entries if owner is cls and kind == _core._PIN_ABSENT
            }
            assert absent == {"__getattribute__", "__getattr__"} - set(vars(cls)), cls

    def test_builtins_used_by_the_modules_are_pinned_absent(self):
        entries = self._entries()
        for module, expected in ((_core, {"isinstance", "len", "str"}), (_policy, {"isinstance"})):
            absent = {
                name
                for owner, name, kind in entries
                if owner is vars(module) and kind == _core._PIN_ABSENT
            }
            assert expected <= absent
            assert not absent & set(vars(module))
            assert absent <= set(vars(builtins))

    def test_active_config_and_policy_are_pinned(self):
        entries = self._entries()
        cfg = _core._config
        for obj, cls in ((cfg, _core._Config), (cfg.policy, _policy.AllowPolicy)):
            assert (obj, "__class__", _core._PIN_TYPE) in entries
            for slot in cls.__slots__:
                assert (obj, slot, _core._PIN_ATTR) in entries

    def test_class_bodies_are_pinned_before_instance_attributes(self):
        """The guardian checks in order; a slot is read only after its descriptor is confirmed."""
        entries = self._entries()
        first_attr = next(i for i, e in enumerate(entries) if e[2] == _core._PIN_ATTR)
        last_class_pin = max(i for i, e in enumerate(entries) if isinstance(e[0], type))
        assert last_class_pin < first_attr

    def test_snapshot_leaves_headroom_in_the_guardian(self):
        """MAX_SNAPSHOT in _guardian.c is 2048; fail well before activation would."""
        assert len(self._entries()) < 1536

    def test_is_unpinned_global(self):
        assert _core._is_unpinned_global("_config", object())
        for value in (None, True, 3, 2.5, "text"):
            assert _core._is_unpinned_global("_some_flag", value)
            assert not _core._is_unpinned_global("_SOME_CONSTANT", value)
        for value in ((), frozenset(), [], {}, object(), len, int):
            assert not _core._is_unpinned_global("_some_object", value)

        class IntSubclass(int):
            pass

        assert not _core._is_unpinned_global("_counter", IntSubclass(1))

    def test_functions_behind(self):
        def plain():
            """A function."""

        def getter(self):
            """A property getter."""

        def setter(self, value):
            """A property setter."""

        @functools.wraps(plain)
        def wrapper():
            """A wrapper."""

        class Holder:
            def method(self):
                """A method."""

        behind = _core._functions_behind
        assert behind(plain) == [plain]
        assert behind(staticmethod(plain)) == [plain]
        assert behind(classmethod(plain)) == [plain]
        assert behind(Holder().method) == [Holder.method]
        assert set(behind(property(getter, setter))) == {getter, setter}
        assert set(behind(wrapper)) == {wrapper, plain}
        for value in (None, 1, "text", object(), len, Holder, _core):
            assert behind(value) == []

    def test_referenced_names_includes_nested_code(self):
        def outer():
            def inner():
                return sorted(())

            return len(inner())

        assert {"len", "sorted"} <= _core._referenced_names(outer.__code__)


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestSnapshotTamperDetection:
    """Rebinding anything the snapshot pins fails closed on the next guarded event."""

    def test_untampered_policy_raises_no_alert(self, capfd):
        _activate_locked()
        _assert_intact(capfd)

    @pytest.mark.parametrize("target", _pinned_globals(), ids=_global_id)
    def test_rebinding_any_pinned_module_global_is_detected(self, target, monkeypatch, capfd):
        module, name = target
        _activate_locked()
        # Undo inside the test: fixture teardown fires audit events of its own,
        # and tethered's hook must be whole again by then.
        with monkeypatch.context() as patch:
            patch.setattr(module, name, object())
            _assert_tamper_response(capfd)
        _assert_intact(capfd)

    @pytest.mark.parametrize(
        "target",
        [
            (module, name)
            for module, name in _pinned_globals()
            if isinstance(vars(module)[name], types.FunctionType)
            and vars(module)[name].__module__ == module.__name__
        ],
        ids=_global_id,
    )
    def test_swapping_the_code_of_any_function_is_detected(self, target, capfd):
        module, name = target
        func = vars(module)[name]
        original = func.__code__
        _activate_locked()
        try:
            # Same function object, same binding — only the bytecode changes.
            func.__code__ = _noop_like(func).__code__
            _assert_tamper_response(capfd)
        finally:
            func.__code__ = original

    @pytest.mark.parametrize(
        "cls, name",
        [
            (cls, name)
            for cls in _own_classes()
            for name in vars(cls)
            if name not in _TYPE_MANAGED_ATTRIBUTES
        ],
        ids=lambda value: value.__qualname__ if isinstance(value, type) else value,
    )
    def test_rebinding_any_class_attribute_is_detected(self, cls, name, monkeypatch, capfd):
        _activate_locked()
        # When the tampered class is EgressBlocked itself, the guardian may be
        # unable to build one; it then refuses with a plain RuntimeError.
        expected = RuntimeError if cls is tethered.EgressBlocked else tethered.EgressBlocked
        with monkeypatch.context() as patch:
            patch.setattr(cls, name, object())
            _assert_tamper_response(capfd, expected)
        _assert_intact(capfd)

    def test_refuses_even_when_the_exception_class_cannot_be_built(self, monkeypatch, capfd):
        """A broken ``EgressBlocked`` must not turn the refusal into a pass or a TypeError."""
        _activate_locked()
        with monkeypatch.context() as patch:
            patch.setattr(tethered.EgressBlocked, "__init__", object())
            capfd.readouterr()
            with pytest.raises(RuntimeError, match="integrity violation") as excinfo:
                socket.getaddrinfo("localhost", 80)
            assert type(excinfo.value) is RuntimeError
            assert "TAMPER DETECTED" in capfd.readouterr().err

    def test_staticmethod_code_swap_is_detected(self, capfd):
        """A function reached only through a descriptor is code-pinned too."""
        func = _core.scope._warn_scope_overlap
        original = func.__code__
        _activate_locked()
        try:
            func.__code__ = (lambda global_policy, allow, label: None).__code__
            _assert_tamper_response(capfd)
        finally:
            func.__code__ = original

    @pytest.mark.parametrize("cls", [_core._Config, _policy.AllowPolicy], ids=lambda c: c.__name__)
    @pytest.mark.parametrize("hook", ["__getattribute__", "__getattr__"])
    def test_injected_attribute_hook_is_detected(self, cls, hook, monkeypatch, capfd):
        """An added ``__getattribute__`` redirects reads without rebinding a pinned name."""
        _activate_locked()
        with monkeypatch.context() as patch:
            patch.setattr(
                cls, hook, lambda self, name: object.__getattribute__(self, name), raising=False
            )
            _assert_tamper_response(capfd)
        _assert_intact(capfd)

    @pytest.mark.parametrize("module", _MODULES, ids=lambda m: m.__name__)
    def test_shadowing_a_builtin_in_a_module_namespace_is_detected(
        self, module, monkeypatch, capfd
    ):
        """``_core.isinstance = ...`` shadows the builtin for that module only."""
        _activate_locked()
        with monkeypatch.context() as patch:
            patch.setattr(module, "isinstance", lambda obj, cls: False, raising=False)
            _assert_tamper_response(capfd)
        _assert_intact(capfd)

    @pytest.mark.parametrize("which", ["config", "policy"])
    def test_swapping_the_class_of_the_active_objects_is_detected(self, which, capfd):
        _activate_locked()
        cfg = _core._config
        target = cfg if which == "config" else cfg.policy

        class Impostor(type(target)):
            __slots__ = ()

        object.__setattr__(target, "__class__", Impostor)
        _assert_tamper_response(capfd)

    def test_tethereds_own_writes_are_not_tampering(self, capfd):
        """A lookup writes the IP map and the allowed-hostname set in place."""
        _activate_locked()
        before = len(_core._ip_to_hostname)
        _assert_intact(capfd)
        assert len(_core._ip_to_hostname) > before
        assert "localhost" in _core._allowed_hostnames
        _assert_intact(capfd)

    def test_lazily_added_class_attributes_are_not_tampering(self, capfd):
        """CPython adds bookkeeping keys to class namespaces on demand.

        ``copy``/``pickle`` cache ``__slotnames__``; annotation access can
        create ``__annotations__`` (or its 3.14 cache keys).  Additions are
        not pinned, only the keys present at activation are.
        """
        _activate_locked()
        cfg = _core._config
        copy.copy(cfg.policy)
        copy.copy(cfg)
        pickle.dumps(tethered.TetheredLocked())
        for cls in _own_classes():
            _ = cls.__annotations__
            _ = cls.__doc__
            _ = getattr(cls, "__annotate__", None)
        for module in _MODULES:
            _ = getattr(module, "__annotations__", None)
        _assert_intact(capfd)


def _noop_like(func: types.FunctionType) -> types.FunctionType:
    """Return a do-nothing function with the same free variables as ``func``.

    ``__code__`` can only be assigned a code object with a matching number
    of free variables, and none of the module-level functions is a closure.
    """
    assert not func.__code__.co_freevars
    return lambda *args, **kwargs: None


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestReportedHelperSwaps:
    """The one-line bypasses from the review's R27 table."""

    @pytest.mark.parametrize(
        "module, name, replacement",
        [
            (_core, "_extract_host_port", lambda address: None),
            (_core, "_normalize_host", lambda h: "allowed.example"),
            (_policy, "_is_localhost", lambda host: True),
        ],
        ids=["_core._extract_host_port", "_core._normalize_host", "_policy._is_localhost"],
    )
    def test_connect_stays_blocked(self, module, name, replacement, monkeypatch, capfd):
        tethered.activate(allow=["allowed.example"], locked=True, lock_token=object())
        blocked = ("192.0.2.1", 443)
        with pytest.raises(tethered.EgressBlocked):
            sys.audit("socket.connect", None, blocked)
        assert "TAMPER DETECTED" not in capfd.readouterr().err

        with monkeypatch.context() as patch:
            patch.setattr(module, name, replacement)
            with pytest.raises(tethered.EgressBlocked):
                sys.audit("socket.connect", None, blocked)
        assert "TAMPER DETECTED" in capfd.readouterr().err

    def test_site_bypass_launch_stays_blocked(self, monkeypatch, capfd):
        tethered.activate(
            allow=["allowed.example"],
            locked=True,
            lock_token=object(),
            external_subprocess_policy="block",
        )
        launch = (sys.executable, [sys.executable, "-S", "-c", "pass"], None, None)
        with pytest.raises(tethered.SubprocessBlocked):
            sys.audit("subprocess.Popen", *launch)
        assert "TAMPER DETECTED" not in capfd.readouterr().err

        with monkeypatch.context() as patch:
            patch.setattr(_core, "_has_site_bypass_flag", lambda argv: False)
            with pytest.raises((tethered.EgressBlocked, tethered.SubprocessBlocked)):
                sys.audit("subprocess.Popen", *launch)
        assert "TAMPER DETECTED" in capfd.readouterr().err


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestSnapshotStaging:
    """A snapshot the guardian cannot build leaves its previous state untouched."""

    @staticmethod
    def _bad_snapshots() -> list[tuple[str, object, type[Exception]]]:
        namespace = vars(_core)
        return [
            ("not a list", (), TypeError),
            ("entry is not a tuple", [["owner", "name", 0]], TypeError),
            ("wrong arity", [(namespace, "logger")], TypeError),
            ("name is not a str", [(namespace, 7, _core._PIN_ITEM)], TypeError),
            ("unknown kind", [(namespace, "logger", 99)], ValueError),
            ("missing item", [(namespace, "no_such_name", _core._PIN_ITEM)], KeyError),
            ("present but pinned absent", [(namespace, "logger", _core._PIN_ABSENT)], ValueError),
            ("namespace is not a dict or class", [(object(), "x", _core._PIN_ITEM)], TypeError),
            ("missing attribute", [(_core, "no_such_name", _core._PIN_ATTR)], AttributeError),
            ("code pin on a non-function", [(len, "__code__", _core._PIN_CODE)], TypeError),
            ("too many entries", [(namespace, "logger", _core._PIN_ITEM)] * 2049, ValueError),
            # A good entry followed by a bad one: the staged good entry is released.
            (
                "fails after a good entry",
                [(namespace, "logger", _core._PIN_ITEM), (namespace, "nope", _core._PIN_ITEM)],
                KeyError,
            ),
        ]

    @pytest.mark.parametrize("index", range(12))
    def test_failed_first_activation_leaves_guardian_inactive(self, index):
        label, snapshot, expected = self._bad_snapshots()[index]
        guardian = _core._c_guardian
        cfg = _core._Config(policy=_policy.AllowPolicy([]))
        with pytest.raises(expected):
            guardian.activate(cfg, tethered.EgressBlocked, object(), snapshot)
        assert guardian.is_active() is False, label
        assert guardian.check_token(None) is True, label

    @pytest.mark.parametrize("index", range(12))
    def test_failed_reactivation_keeps_the_previous_snapshot(self, index, capfd):
        label, snapshot, expected = self._bad_snapshots()[index]
        guardian = _core._c_guardian
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        before = _core._config
        replacement = _core._Config(policy=_policy.AllowPolicy(["evil.test"]))
        with pytest.raises(expected):
            guardian.activate(replacement, tethered.EgressBlocked, secret, snapshot)
        assert guardian.is_active() is True, label
        assert _core._config is before
        # Still enforcing the original policy, still verifying the original snapshot.
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)
        _assert_intact(capfd)
        assert guardian.check_token(secret) is True

    def test_all_pin_kinds_round_trip(self, capfd):
        """Each kind is recorded at activation and verified on the next event."""

        class Probe:
            attr = 1

        def func():
            """A function to code-pin."""

        namespace = {"present": object()}
        probe = Probe()
        secret = object()
        snapshot = [
            (probe, "attr", _core._PIN_ATTR),
            (namespace, "present", _core._PIN_ITEM),
            (namespace, "missing", _core._PIN_ABSENT),
            (Probe, "attr", _core._PIN_ITEM),
            (Probe, "__getattr__", _core._PIN_ABSENT),
            (func, "__code__", _core._PIN_CODE),
            (probe, "__class__", _core._PIN_TYPE),
        ]
        guardian = _core._c_guardian

        def reset() -> None:
            # _core._config is None here, matching the config handed to the guardian.
            guardian.activate(None, tethered.EgressBlocked, secret, snapshot)

        def tampered() -> bool:
            capfd.readouterr()
            try:
                sys.audit("socket.tethered_test_probe")
            except tethered.EgressBlocked:
                return "TAMPER DETECTED" in capfd.readouterr().err
            return False

        try:
            reset()
            assert not tampered()

            probe.attr = 2  # instance attribute now shadows the class attribute
            assert tampered()
            del probe.attr
            reset()
            assert not tampered()

            namespace["present"] = object()
            assert tampered()
            reset()
            del namespace["present"]
            assert tampered()
            namespace["present"] = object()
            reset()

            namespace["missing"] = None
            assert tampered()
            del namespace["missing"]
            reset()

            Probe.attr = 3
            assert tampered()
            reset()

            Probe.__getattr__ = lambda self, name: None
            assert tampered()
            del Probe.__getattr__
            reset()

            original = func.__code__
            func.__code__ = (lambda: None).__code__
            assert tampered()
            func.__code__ = original
            reset()

            probe.__class__ = type("Other", (Probe,), {})
            assert tampered()
        finally:
            guardian.deactivate(secret)


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestContextVarTamperDetection:
    """Tests for C guardian ContextVar consistency checks in locked mode."""

    def test_in_hook_bypass_detected_getaddrinfo(self):
        """Setting _in_hook=True without C-owned resolution is detected on getaddrinfo."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)

        # Manually set the ContextVar — this should be caught by the C guardian
        token = _core._in_hook.set(True)
        try:
            with pytest.raises(tethered.EgressBlocked, match=r"Blocked by tethered"):
                socket.getaddrinfo("anything.example.com", 80)
        finally:
            _core._in_hook.reset(token)

    def test_in_hook_bypass_detected_connect(self):
        """Setting _in_hook=True without C-owned resolution is detected on connect."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)

        # Create socket BEFORE tampering — socket creation fires audit events
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        token = _core._in_hook.set(True)
        try:
            with pytest.raises(tethered.EgressBlocked, match=r"Blocked by tethered"):
                sock.connect(("127.0.0.1", 1))
        finally:
            _core._in_hook.reset(token)
            sock.close()

    def test_legitimate_resolve_still_works(self):
        """Legitimate DNS resolution through _guardian.resolve() still works."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)

        # Normal usage should work — the policy check runs, then resolve() does DNS
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

    @requires_network
    def test_legitimate_resolve_allowed_host(self):
        """An allowed host is resolved through _c_guardian.resolve() in locked mode."""
        secret = object()
        tethered.activate(allow=["dns.google"], locked=True, lock_token=secret)
        # Call _audit_hook directly so coverage tracing sees _handle_getaddrinfo.
        # When invoked via sys.audit, the callback runs in C and isn't traced —
        # the policy check passes, then resolution flows through the C guardian.
        _audit_hook("socket.getaddrinfo", ("dns.google", 53, 0, 0, 0))
        with _ip_map_lock:
            assert any("dns.google" in v for v in _ip_to_hostname.values())

    def test_unauthorized_resolve_call_blocked(self):
        """Calling _guardian.resolve() from non-trusted code is blocked."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)

        with pytest.raises(tethered.EgressBlocked, match=r"Blocked by tethered"):
            _core._c_guardian.resolve("example.com", 80, 0, 0, 0, 0)

    def test_fallback_resolve_authorized_in_locked_mode(self, monkeypatch):
        """_fallback_resolve is the second authorized caller of _c_guardian.resolve.

        In locked mode, _fallback_resolve calls _c_guardian.resolve(), which
        verifies the immediate caller's __code__ against the cached array of
        allowed callers (slot 0 = _handle_getaddrinfo, slot 1 = _fallback_resolve).
        Without slot 1, the call would raise EgressBlocked("unauthorized").
        With it, the call succeeds and returns the resolution result.
        """
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        with _ip_map_lock:
            _core._allowed_hostnames["api.example.com"] = None

        # Patch the underlying _socket.getaddrinfo (the C-level function the
        # guardian's resolve() ultimately calls) so the test stays offline.
        # _c_guardian.resolve looks up "getaddrinfo" on the cached _socket
        # module each call, so attribute patching takes effect.
        fake_results = [(0, 0, 0, "", ("203.0.113.99", 0))]
        monkeypatch.setattr(_socket, "getaddrinfo", lambda *a, **kw: fake_results)

        # _fallback_resolve calls _c_guardian.resolve (because guardian is
        # active); the guardian accepts the call (slot 1) and returns the
        # patched result; the helper finds the matching IP and returns the
        # hostname.  No tamper alert, no unauthorized-caller block.
        result = _core._fallback_resolve("203.0.113.99", 443)
        assert result == "api.example.com"
        with _ip_map_lock:
            assert _ip_to_hostname.get("203.0.113.99") == ("api.example.com",)

    def test_fallback_resolve_repairs_divergence_end_to_end_locked(self, monkeypatch):
        """End-to-end: locked-mode connect to an unmapped IP succeeds via fallback.

        Simulates the production scenario the bug describes: an Entra-style
        load-balanced hostname where the application connects to an IP that
        was not in tethered's IP map at audit time.  The fallback re-resolves
        and finds the match, allowing the connect.
        """
        secret = object()
        tethered.activate(allow=["api.example.com"], locked=True, lock_token=secret)
        # Pretend a prior getaddrinfo populated _allowed_hostnames but not
        # the IP that the app is now connecting to.
        with _ip_map_lock:
            _core._allowed_hostnames["api.example.com"] = None

        monkeypatch.setattr(
            _socket,
            "getaddrinfo",
            lambda *a, **kw: [(0, 0, 0, "", ("203.0.113.42", 0))],
        )

        # The connect path should NOT raise — the fallback finds the match.
        _audit_hook("socket.connect", (None, ("203.0.113.42", 443)))


class TestTetheredLockedException:
    def test_message(self):
        exc = tethered.TetheredLocked()
        assert "locked" in str(exc).lower()
        assert "deactivate" in str(exc).lower()

    def test_is_runtime_error(self):
        assert issubclass(tethered.TetheredLocked, RuntimeError)
        assert isinstance(tethered.TetheredLocked(), RuntimeError)
