"""Tests for locked mode and the C-level integrity guardian."""

from __future__ import annotations

import _socket
import builtins
import codecs
import contextlib
import copy
import functools
import gc
import inspect
import json
import logging
import os
import pickle
import shutil
import site
import socket
import subprocess
import sys
import textwrap
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

    def test_reactivate_noop_ignores_the_mutable_payload_dict(self):
        """Editing ``_global_payload_dict`` in place cannot make a wider request look identical.

        The dict keeps its identity when its contents change, so the
        integrity snapshot does not notice; the comparison therefore uses the
        immutable serialized payload.
        """
        tethered.activate(allow=["a.example.com"], locked=True, lock_token=object())
        cfg = _core._config
        cfg._global_payload_dict["allow"].append("evil.test")
        with pytest.raises(tethered.TetheredLocked, match=r"activate\(\) blocked"):
            tethered.activate(
                allow=["a.example.com", "evil.test"], locked=True, lock_token=object()
            )
        assert _core._config is cfg
        # ... and the genuinely identical request is still recognised.
        tethered.activate(allow=["a.example.com"], locked=True, lock_token=object())
        assert _core._config is cfg

    def test_reactivate_noop_comparison_is_type_exact(self):
        tethered.activate(allow=["a.example.com"], locked=True, lock_token=object())
        payload = _core._config._serialized_payload
        assert "false" in payload
        assert _core._is_idempotent_reactivation(payload) is True
        # JSON text tells 0 from false; a dict comparison does not.
        assert json.loads(payload) == json.loads(payload.replace("false", "0"))
        assert _core._is_idempotent_reactivation(payload.replace("false", "0")) is False
        assert _core._is_idempotent_reactivation(json.loads(payload)) is False

        class EqualToAnything(str):
            def __eq__(self, other):
                return True

            __hash__ = str.__hash__

        assert _core._is_idempotent_reactivation(EqualToAnything("x")) is False

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

    def test_holds_lock_says_whether_this_interpreter_took_the_lock(self):
        """(False in an interpreter that did not: ``test_subinterpreters.py``.)"""
        token = object()
        assert _core._c_guardian.holds_lock() is False
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=token)
        assert _core._c_guardian.holds_lock() is True
        tethered.deactivate(lock_token=token)
        assert _core._c_guardian.holds_lock() is False

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
        "_active_scope_count": "number of scopes entered anywhere in the process (int)",
        "_proactor_warning_pending": "cleared once the Proactor-loop warning has been logged",
        "_uvloop_warning_pending": "cleared once the uvloop warning has been logged",
        "_uvloop_refusal_unlogged": "cleared once a refused import of uvloop has been logged",
        "_pth_path_cache": "bootstrap path cached for scope-only use (None until computed)",
        "_env_dirty": "set when the policy variable changed behind os.environ's back",
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


# The codec ``getaddrinfo`` encodes a host name with, loaded before any test
# tampers with tethered: its first use is an import, and the audit event of an
# import goes through the very hook a test has just damaged, which may answer
# with any error at all before the lookup the test is about is reached.
codecs.lookup("idna")


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
        # Whether these succeed is beside the point (a class may refuse to be
        # copied); what they leave behind in the class namespaces is the test.
        for obj in (cfg.policy, cfg, tethered.TetheredLocked()):
            with contextlib.suppress(Exception):
                copy.copy(obj)
            with contextlib.suppress(Exception):
                pickle.dumps(obj)
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
    The replacement is a generator when ``func`` is one: assigning a code
    object of the other kind is deprecated from Python 3.13.
    """
    assert not func.__code__.co_freevars
    if inspect.isgeneratorfunction(func):

        def noop_generator(*args, **kwargs):
            yield from ()

        return noop_generator
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
            with pytest.raises(tethered.SubprocessBlocked, match="integrity") as excinfo:
                sys.audit("subprocess.Popen", *launch)
        assert excinfo.value.event == "subprocess.Popen"
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
            guardian.activate(vars(_core), cfg, object(), snapshot)
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
            guardian.activate(vars(_core), replacement, secret, snapshot)
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
            guardian.activate(vars(_core), None, secret, snapshot)

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


PTH_LINE = "import tethered._autoactivate\n"


@pytest.fixture
def scratch_pth(tmp_path, monkeypatch):
    """Point tethered at a scratch ``site-packages`` holding a ``tethered.pth``.

    ``_compute_pth_path()`` accepts only a hook in a directory ``site``
    processes and prefers the one beside ``tethered.__file__``, so the scratch
    directory is presented as the interpreter's one site directory.  Policies
    activated while this fixture is in effect guard the scratch file and no
    test can damage the real one.  Only ``site`` and the package's
    ``__file__`` are patched — names the locked-mode snapshot does not pin.
    """
    site_packages = tmp_path / "site-packages"
    (site_packages / "tethered").mkdir(parents=True)
    pth = site_packages / "tethered.pth"
    pth.write_text(PTH_LINE)
    monkeypatch.setattr(tethered, "__file__", str(site_packages / "tethered" / "__init__.py"))
    monkeypatch.setattr(site, "getsitepackages", lambda prefixes=None: [str(site_packages)])
    monkeypatch.setattr(site, "ENABLE_USER_SITE", False)
    return pth


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestPthTruncateGuard:
    """``os.truncate`` raises an audit event, and locked mode refuses it for ``tethered.pth``."""

    def test_event_is_guarded(self):
        assert "os.truncate" in _core._PTH_FS_EVENTS

    @pytest.mark.parametrize("as_bytes", [False, True], ids=["str", "bytes"])
    def test_truncating_the_pth_is_refused(self, scratch_pth, as_bytes):
        _activate_locked()
        assert _core._config._pth_path == os.path.normcase(str(scratch_pth))
        target = os.fsencode(scratch_pth) if as_bytes else str(scratch_pth)
        with pytest.raises(tethered.SubprocessBlocked, match="refused truncation") as excinfo:
            os.truncate(target, 0)
        assert excinfo.value.event == "os.truncate"
        assert scratch_pth.read_text() == PTH_LINE

    def test_truncating_to_any_length_is_refused(self, scratch_pth):
        _activate_locked()
        with pytest.raises(tethered.SubprocessBlocked, match="refused truncation"):
            os.truncate(scratch_pth, 5)
        assert scratch_pth.read_text() == PTH_LINE

    def test_no_writable_descriptor_can_be_obtained_for_ftruncate(self, scratch_pth):
        """``os.ftruncate`` carries only a descriptor; the write-open before it is refused."""
        _activate_locked()
        with pytest.raises(tethered.SubprocessBlocked, match="refused write-open"):
            os.open(scratch_pth, os.O_RDWR)
        with pytest.raises(tethered.SubprocessBlocked, match="refused write-open"):
            open(scratch_pth, "r+")  # noqa: SIM115
        fd = os.open(scratch_pth, os.O_RDONLY)
        try:
            with pytest.raises(OSError):
                os.ftruncate(fd, 0)
        finally:
            os.close(fd)
        assert scratch_pth.read_text() == PTH_LINE

    def test_other_files_can_be_truncated(self, scratch_pth):
        _activate_locked()
        other = scratch_pth.with_name("other.pth")
        other.write_text("data")
        os.truncate(other, 0)
        assert other.read_text() == ""

    def test_not_refused_outside_locked_mode(self, scratch_pth):
        tethered.activate(allow=["*.example.com"])
        os.truncate(scratch_pth, 0)
        assert scratch_pth.read_text() == ""

    def test_handler_ignores_descriptors_and_missing_arguments(self, scratch_pth):
        _activate_locked()
        cfg = _core._config
        _core._handle_pth_fs_op(cfg, "os.truncate", (7, 0))
        _core._handle_pth_fs_op(cfg, "os.truncate", ())
        with pytest.raises(tethered.SubprocessBlocked):
            _core._handle_pth_fs_op(cfg, "os.truncate", (str(scratch_pth), 0))


def test_cpython_ignores_a_pth_import_line_beside_a_start_file(tmp_path):
    """Pins the CPython behaviour the ``tethered.start`` guard is written for.

    PEP 829: from Python 3.15 a ``<name>.start`` file, even an empty one,
    switches off the ``import`` lines of the ``<name>.pth`` beside it.
    Python 3.18 is to ignore those lines altogether; when this starts
    failing there, the ``tethered.pth`` bootstrap no longer runs.
    """
    (tmp_path / "probe.pth").write_text("import sys; sys.stdout.write('pth line ran')\n")
    (tmp_path / "probe.start").write_text("")
    result = subprocess.run(
        [sys.executable, "-c", f"import site; site.addsitedir({str(tmp_path)!r})"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == ("" if sys.version_info >= (3, 15) else "pth line ran")


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestStartFileGuard:
    """Locked mode refuses creating ``tethered.start`` beside ``tethered.pth``."""

    @staticmethod
    def _creations(start, source):
        return {
            "open-w": lambda: open(start, "w"),
            "open-x": lambda: open(start, "x"),
            "open-a": lambda: open(start, "a"),
            "os.open": lambda: os.open(start, os.O_CREAT | os.O_RDONLY),
            "touch": lambda: start.touch(),
            "write_text": lambda: start.write_text(""),
            "rename": lambda: os.rename(source, start),
            "replace": lambda: os.replace(source, start),
            "link": lambda: os.link(source, start),
            "hardlink_to": lambda: start.hardlink_to(source),
            "symlink": lambda: os.symlink(source, start),
            "copyfile": lambda: shutil.copyfile(source, start),
            "copy": lambda: shutil.copy(source, start),
            "copy2": lambda: shutil.copy2(source, start),
            "move": lambda: shutil.move(source, start),
            "bytes-path": lambda: open(os.fsencode(start), "w"),
        }

    @pytest.mark.parametrize(
        "how",
        [
            "open-w",
            "open-x",
            "open-a",
            "os.open",
            "touch",
            "write_text",
            "rename",
            "replace",
            "link",
            "hardlink_to",
            "symlink",
            "copyfile",
            "copy",
            "copy2",
            "move",
            "bytes-path",
        ],
    )
    def test_creating_it_is_refused(self, how, scratch_pth, capfd):
        start = scratch_pth.with_name("tethered.start")
        source = scratch_pth.with_name("empty.txt")
        source.write_text("")
        _activate_locked()
        with pytest.raises(tethered.SubprocessBlocked, match="refused creation") as excinfo:
            self._creations(start, source)[how]()
        assert "tethered.start" in excinfo.value.description
        assert not os.path.lexists(start)
        assert source.read_text() == ""
        assert scratch_pth.read_text() == PTH_LINE
        assert "TAMPER DETECTED" not in capfd.readouterr().err

    def test_copy2_onto_the_pth_is_refused(self, scratch_pth):
        """On Windows ``shutil.copy2`` replaces its destination without an ``open`` event."""
        source = scratch_pth.with_name("empty.txt")
        source.write_text("")
        _activate_locked()
        with pytest.raises(tethered.SubprocessBlocked, match=r"refused (overwrite|write-open)"):
            shutil.copy2(source, scratch_pth)
        assert scratch_pth.read_text() == PTH_LINE

    def test_other_start_files_can_be_created(self, scratch_pth):
        _activate_locked()
        scratch_pth.with_name("other.start").write_text("pkg.mod:func\n")
        elsewhere = scratch_pth.parent.parent / "tethered.start"
        elsewhere.write_text("")
        shutil.copy2(elsewhere, scratch_pth.with_name("copy.start"))
        os.link(elsewhere, scratch_pth.with_name("link.start"))
        assert not os.path.lexists(scratch_pth.with_name("tethered.start"))

    def test_an_existing_one_can_be_read_and_removed(self, scratch_pth):
        """Taking the file away can only bring the bootstrap back."""
        start = scratch_pth.with_name("tethered.start")
        start.write_text("")
        _activate_locked()
        assert start.read_text() == ""
        shutil.copy2(start, scratch_pth.with_name("copy.txt"))
        os.remove(start)
        assert not start.exists()

    def test_not_refused_outside_locked_mode(self, scratch_pth):
        tethered.activate(allow=["*.example.com"])
        start = scratch_pth.with_name("tethered.start")
        start.write_text("")
        assert start.exists()


# ── Integrity verification on non-socket events (R30) ──────────────


class _BareGuardian:
    """The C guardian on its own, pinning one entry of a scratch namespace.

    tethered itself stays inactive (``_core._config`` is ``None``), so the
    Python hook has nothing to enforce and a test sees only what the
    guardian decides.  ``tamper()`` breaks the pinned fact, ``mend()``
    restores it.
    """

    def __init__(self) -> None:
        self._original = object()
        self._namespace = {"pinned": self._original}
        self._token = object()
        _core._c_guardian.activate(
            vars(_core), None, self._token, [(self._namespace, "pinned", _core._PIN_ITEM)]
        )

    def tamper(self) -> None:
        self._namespace["pinned"] = object()

    def mend(self) -> None:
        self._namespace["pinned"] = self._original

    def close(self) -> None:
        _core._c_guardian.deactivate(self._token)


@pytest.fixture
def bare_guardian():
    guardian = _BareGuardian()
    yield guardian
    guardian.close()


LAUNCH_EVENTS = [
    "subprocess.Popen",
    "os.system",
    "os.exec",
    "os.posix_spawn",
    "os.spawn",
    "os.startfile",
    "os.startfile/2",
    "_winapi.CreateProcess",
    "_posixsubprocess.fork_exec",
]

POLICY_VAR = "_TETHERED_CHILD_POLICY"


class _PathLike:
    """A path-like the guardian cannot inspect without running ``__fspath__``."""

    def __fspath__(self) -> str:
        raise AssertionError("the guardian must not call __fspath__")

    def __repr__(self) -> str:
        return "PathLike()"


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestGuardianEventCoverage:
    """Which audit events make the guardian verify, seen through the guardian alone."""

    def test_policy_variable_name_matches_core(self):
        assert _core._CHILD_POLICY_ENV == POLICY_VAR

    # The guardian's event list lives in C (classify_event in _guardian.c)
    # and must cover every event the Python hook enforces something on.
    # These two tests fail when an event is added on the Python side only.

    @pytest.mark.parametrize("event", sorted(_core._SUBPROCESS_EVENTS))
    def test_every_python_side_launch_event_is_verified(self, event, bare_guardian):
        bare_guardian.tamper()
        with pytest.raises(tethered.SubprocessBlocked):
            sys.audit(event, "prog", ["prog"], None, None)

    @pytest.mark.parametrize("event", sorted(_core._PTH_FS_EVENTS))
    def test_every_python_side_filesystem_event_is_verified(self, event, bare_guardian):
        bare_guardian.tamper()
        with pytest.raises(tethered.SubprocessBlocked):
            sys.audit(event, "site-packages/tethered.pth", "w", 0)

    @pytest.mark.parametrize("event", LAUNCH_EVENTS)
    def test_launch_events_are_refused_after_tampering(self, event, bare_guardian, capfd):
        sys.audit(event, "prog", ["prog"], None, None)  # intact: passes
        bare_guardian.tamper()
        with pytest.raises(tethered.SubprocessBlocked, match="integrity") as excinfo:
            sys.audit(event, "prog", ["prog"], None, None)
        assert excinfo.value.event == event
        assert not isinstance(excinfo.value, tethered.EgressBlocked)
        assert "TAMPER DETECTED" in capfd.readouterr().err
        bare_guardian.mend()
        sys.audit(event, "prog", ["prog"], None, None)

    def test_launch_events_need_no_arguments_to_be_refused(self, bare_guardian):
        bare_guardian.tamper()
        with pytest.raises(tethered.SubprocessBlocked):
            sys.audit("os.system")

    # tethered.start is guarded with tethered.pth: beside it, it switches the
    # hook's import line off from Python 3.15 (PEP 829).
    @pytest.mark.parametrize("name", ["tethered.pth", "tethered.start"])
    @pytest.mark.parametrize(
        "event, args",
        [
            ("open", ("{pth}", "w", 0)),
            ("open", ("{pth}", "r", 0)),  # the guardian cannot tell a read from a write
            ("open", ("{pth}", None, os.O_WRONLY)),
            ("os.remove", ("{pth}", -1)),
            ("os.chmod", ("{pth}", 0, -1)),
            ("os.truncate", ("{pth}", 0)),
            ("os.rename", ("{pth}", "elsewhere", -1, -1)),
            ("os.rename", ("elsewhere", "{pth}", -1, -1)),
            ("os.link", ("{pth}", "elsewhere", -1, -1)),
            ("os.link", ("elsewhere", "{pth}", -1, -1)),
            ("os.symlink", ("{pth}", "elsewhere", -1)),
            ("os.symlink", ("elsewhere", "{pth}", -1)),
            ("_winapi.CopyFile2", ("{pth}", "elsewhere", 0)),
            ("_winapi.CopyFile2", ("elsewhere", "{pth}", 0)),
        ],
        ids=lambda value: value if isinstance(value, str) else None,
    )
    def test_filesystem_events_on_the_pth_are_refused_after_tampering(
        self, event, args, name, bare_guardian, capfd
    ):
        pth = os.path.join("site-packages", name)
        args = tuple(a.format(pth=pth) if isinstance(a, str) else a for a in args)
        sys.audit(event, *args)  # intact: passes
        bare_guardian.tamper()
        with pytest.raises(tethered.SubprocessBlocked, match="integrity") as excinfo:
            sys.audit(event, *args)
        assert excinfo.value.event == event
        assert "TAMPER DETECTED" in capfd.readouterr().err

    @pytest.mark.parametrize(
        "path",
        [
            "tethered.pth",
            "site-packages/tethered.pth",
            "C:\\Lib\\site-packages\\tethered.pth",
            "SITE-PACKAGES/TETHERED.PTH",
            "site-packages/Tethered.Pth",
            # normpath() collapses these onto the file, so the Python guard matches them
            "site-packages/tethered.pth/.",
            "site-packages/tethered.pth/",
            "site-packages/tethered.pth/sub/..",
            b"site-packages/tethered.pth",
            b"SITE-PACKAGES\\TETHERED.PTH",
            # wider str kinds (UCS-2 and UCS-4 storage)
            "/srv/данные/tethered.pth",
            "/srv/\U0001f600/Tethered.pth",
            # the name that overrides the hook from Python 3.15
            "tethered.start",
            "site-packages/tethered.start",
            "C:\\Lib\\site-packages\\Tethered.Start",
            "site-packages/tethered.start/sub/..",
            b"SITE-PACKAGES\\TETHERED.START",
            "/srv/данные/tethered.start",
            "/srv/\U0001f600/tethered.start",
            # cannot be inspected without running code: verified to be safe
            _PathLike(),
            bytearray(b"site-packages/tethered.pth"),
        ],
        ids=repr,
    )
    def test_path_spellings_that_trigger_verification(self, path, bare_guardian):
        bare_guardian.tamper()
        with pytest.raises(tethered.SubprocessBlocked):
            sys.audit("open", path, "w", 0)
        with pytest.raises(tethered.SubprocessBlocked):
            sys.audit("os.rename", "elsewhere", path, -1, -1)

    @pytest.mark.parametrize(
        "path",
        [
            "",
            "site-packages/other.pth",
            "site-packages/tethered.pt",
            "site-packages/tethered_pth",
            "site-packages/ethered.pth",
            "site-packages/other.start",
            "site-packages/tethered.star",
            "site-packages/tethered_start",
            "/srv/данные/other.pth",
            "/srv/\U0001f600/other.pth",
            "/srv/\U0001f600/other.start",
            b"site-packages/other.pth",
            b"site-packages/other.start",
            b"",
            7,  # a file descriptor cannot be matched against a path
            None,
        ],
        ids=repr,
    )
    def test_other_paths_are_not_verified(self, path, bare_guardian):
        """Ordinary file activity stays cheap — and is not refused after tampering."""
        bare_guardian.tamper()
        sys.audit("open", path, "w", 0)
        sys.audit("os.remove", path, -1)
        sys.audit("os.rename", path, path, -1, -1)
        sys.audit("os.chmod", path, 0, -1)
        sys.audit("os.truncate", path, 0)
        sys.audit("os.link", path, path, -1, -1)
        sys.audit("os.symlink", path, path, -1)
        sys.audit("_winapi.CopyFile2", path, path, 0)

    def test_only_the_path_arguments_are_checked(self, bare_guardian):
        bare_guardian.tamper()
        sys.audit("os.rename", "a", "b", "tethered.pth", "tethered.pth")
        sys.audit("os.link", "a", "b", "tethered.start", "tethered.start")
        sys.audit("os.symlink", "a", "b", "tethered.start")
        sys.audit("_winapi.CopyFile2", "a", "b", "tethered.pth")
        sys.audit("open", "a", "tethered.pth", 0)  # the mode is not a path

    @pytest.mark.parametrize("event", sorted(_core._PTH_FS_EVENTS))
    def test_filesystem_events_without_arguments_are_ignored(self, event, bare_guardian):
        bare_guardian.tamper()
        sys.audit(event)

    @pytest.mark.parametrize("event", ["os.putenv", "os.unsetenv"])
    @pytest.mark.parametrize(
        "key",
        [
            POLICY_VAR,
            POLICY_VAR.lower(),
            "_Tethered_Child_Policy",
            POLICY_VAR.encode(),
            POLICY_VAR.lower().encode(),
            # Windows folds a few non-ASCII letters onto ASCII ones; anything
            # non-ASCII is verified instead of reasoned about.
            "_TETHERED_CH\u0131LD_POL\u0131CY",
            "\u00e9",
            b"_TETHERED_CH\xc4\xb1LD_POLICY",
            7,
            None,
        ],
        ids=repr,
    )
    def test_environment_events_on_the_policy_variable_are_refused_after_tampering(
        self, event, key, bare_guardian, capfd
    ):
        sys.audit(event, key, "value")  # intact: passes
        bare_guardian.tamper()
        with pytest.raises(tethered.SubprocessBlocked, match="integrity") as excinfo:
            sys.audit(event, key, "value")
        assert excinfo.value.event == event
        assert "TAMPER DETECTED" in capfd.readouterr().err

    @pytest.mark.parametrize("event", ["os.putenv", "os.unsetenv"])
    def test_environment_events_without_a_key_are_verified(self, event, bare_guardian):
        bare_guardian.tamper()
        with pytest.raises(tethered.SubprocessBlocked):
            sys.audit(event)

    @pytest.mark.parametrize(
        "key",
        [
            "PATH",
            "",
            POLICY_VAR + "_X",
            POLICY_VAR[:-1],
            "X" + POLICY_VAR[1:],
            POLICY_VAR.replace("_", "-"),
            b"PATH",
            (POLICY_VAR + "_X").encode(),
        ],
        ids=repr,
    )
    def test_other_environment_variables_are_not_verified(self, key, bare_guardian):
        bare_guardian.tamper()
        sys.audit("os.putenv", key, "value")
        sys.audit("os.unsetenv", key)

    @pytest.mark.parametrize(
        "event",
        [
            "o",
            "os",
            "os.",
            "opener",
            "os.listdir",
            "os.rmdir",
            "os.mkdir",
            "os.removexattr",
            "os.renames",
            "os.execv",
            "os.spawnv",
            "os.putenv2",
            "s",
            "subprocess.Popen2",
            "subprocess.run",
            "sockets.connect",
            "_winapi.CreateFile",
            "_posixsubprocess.fork",
            "import",
            "exec",
            "",
        ],
        ids=repr,
    )
    def test_unguarded_events_are_ignored(self, event, bare_guardian):
        bare_guardian.tamper()
        sys.audit(event, "tethered.pth", POLICY_VAR)

    @pytest.mark.skipif(
        sys.version_info < (3, 14), reason="concurrent.interpreters arrived in Python 3.14"
    )
    def test_events_from_other_interpreters_are_refused_without_verifying(
        self, bare_guardian, capfd
    ):
        """A C audit hook is process-wide, but the guardian's objects belong to one interpreter.

        Another interpreter has its own GIL.  The guardian must not verify on
        its behalf, let alone raise this interpreter's exception classes
        there.  While a policy is locked it refuses that interpreter the
        guarded operations outright — tampered with or not, with an
        exception made there and without a tamper alert — and leaves its
        other events alone.  ``test_subinterpreters.py`` covers this in full.
        """
        interpreters = pytest.importorskip("concurrent.interpreters")
        other = interpreters.create()
        probe = (
            "import sys\n"
            "def refused(event, *args):\n"
            "    try:\n"
            "        sys.audit(event, *args)\n"
            "    except RuntimeError as exc:\n"
            "        return type(exc) is RuntimeError and 'another interpreter' in str(exc)\n"
            "    return False\n"
            "assert refused('socket.connect', None, ('127.0.0.1', 9))\n"
            "assert refused('subprocess.Popen', 'prog', ['prog'], None, None)\n"
            "assert refused('open', 'site-packages/tethered.pth', 'w', 0)\n"
            "assert refused('os.putenv', '_TETHERED_CHILD_POLICY', 'x')\n"
            "sys.audit('socket.tethered_test_probe')\n"
            "sys.audit('open', 'site-packages/tethered.pth', 'r', 0)\n"
        )
        try:
            other.exec(probe)
            assert "TAMPER DETECTED" not in capfd.readouterr().err
            bare_guardian.tamper()
            with pytest.raises(tethered.EgressBlocked):
                sys.audit("socket.tethered_test_probe")
            other.exec(probe)  # no different: nothing is verified for it
        finally:
            other.close()
        # ... while this interpreter's events are still refused.
        with pytest.raises(tethered.SubprocessBlocked):
            sys.audit("open", "site-packages/tethered.pth", "w", 0)

    def test_socket_events_still_raise_egress_blocked(self, bare_guardian, capfd):
        sys.audit("socket.tethered_test_probe")
        bare_guardian.tamper()
        with pytest.raises(tethered.EgressBlocked):
            sys.audit("socket.tethered_test_probe")
        with pytest.raises(tethered.EgressBlocked, match=r"evil\.test"):
            sys.audit("socket.getaddrinfo", "evil.test", 80, 0, 0, 0)
        with pytest.raises(tethered.EgressBlocked, match=r"203\.0\.113\.9"):
            sys.audit("socket.connect", None, ("203.0.113.9", 443))
        with pytest.raises(tethered.EgressBlocked, match="unknown"):
            sys.audit("socket.sendto", None, None)
        with pytest.raises(tethered.EgressBlocked, match="unknown"):
            sys.audit("socket.connect", None)
        # A host that cannot be encoded for the message must not derail the refusal.
        with pytest.raises(tethered.EgressBlocked, match="unknown"):
            sys.audit("socket.getaddrinfo", "bad\udc80host", 80, 0, 0, 0)
        assert "TAMPER DETECTED" in capfd.readouterr().err


@contextlib.contextmanager
def _replaced_pth_guard(monkeypatch: pytest.MonkeyPatch):
    """Swap the Python-side ``tethered.pth`` guard for a no-op, as tampering code would."""
    with monkeypatch.context() as patch:
        patch.setattr(_core, "_handle_pth_fs_op", lambda *args, **kwargs: None)
        yield


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestReplacedGuardsCannotDecide:
    """With tethered active: a replaced Python-side guard no longer gets the last word."""

    @staticmethod
    def _operations(pth, other):
        start = pth.with_name("tethered.start")
        return {
            "open-w": lambda: open(pth, "w"),
            "open-a": lambda: open(pth, "a"),
            "os.open": lambda: os.open(pth, os.O_WRONLY),
            "remove": lambda: os.remove(pth),
            "unlink": lambda: pth.unlink(),
            "rename-away": lambda: os.rename(pth, other.with_name("moved.pth")),
            "replace-onto": lambda: os.replace(other, pth),
            "chmod": lambda: os.chmod(pth, 0o600),
            "truncate": lambda: os.truncate(pth, 0),
            "write_text": lambda: pth.write_text("gone"),
            "copy2-onto": lambda: shutil.copy2(other, pth),
            "start-open-w": lambda: open(start, "w"),
            "start-touch": lambda: start.touch(),
            "start-replace-onto": lambda: os.replace(other, start),
            "start-link": lambda: os.link(other, start),
            "start-symlink": lambda: os.symlink(other, start),
            "start-copy2": lambda: shutil.copy2(other, start),
        }

    @pytest.mark.parametrize(
        "operation",
        [
            "open-w",
            "open-a",
            "os.open",
            "remove",
            "unlink",
            "rename-away",
            "replace-onto",
            "chmod",
            "truncate",
            "write_text",
            "copy2-onto",
            "start-open-w",
            "start-touch",
            "start-replace-onto",
            "start-link",
            "start-symlink",
            "start-copy2",
        ],
    )
    def test_pth_operations_are_refused(self, operation, capfd, scratch_pth, monkeypatch):
        """The review's R30 reproduction, for every guarded filesystem operation."""
        other = scratch_pth.with_name("other.txt")
        other.write_text("other")
        run = self._operations(scratch_pth, other)[operation]
        _activate_locked()
        capfd.readouterr()
        with (
            _replaced_pth_guard(monkeypatch),
            pytest.raises(tethered.SubprocessBlocked, match="integrity"),
        ):
            run()
        assert "TAMPER DETECTED" in capfd.readouterr().err
        assert scratch_pth.read_text() == PTH_LINE
        assert other.read_text() == "other"
        assert not os.path.lexists(scratch_pth.with_name("tethered.start"))

    def test_intact_policy_leaves_the_decision_to_the_python_guard(self, capfd, scratch_pth):
        _activate_locked()
        with pytest.raises(tethered.SubprocessBlocked, match="refused write-open"):
            open(scratch_pth, "w")  # noqa: SIM115
        assert scratch_pth.read_text() == PTH_LINE  # reading is allowed
        assert "TAMPER DETECTED" not in capfd.readouterr().err

    def test_unrelated_files_stay_usable_after_tampering(self, capfd, scratch_pth, monkeypatch):
        other = scratch_pth.with_name("other.txt")
        _activate_locked()
        with _replaced_pth_guard(monkeypatch):
            other.write_text("data")
            os.chmod(other, 0o600)
            os.truncate(other, 0)
            os.rename(other, other.with_name("renamed.txt"))
            os.remove(other.with_name("renamed.txt"))
        assert "TAMPER DETECTED" not in capfd.readouterr().err

    def test_policy_variable_writes_are_refused_after_tampering(self, capfd, monkeypatch):
        _activate_locked()
        before = os.environ[POLICY_VAR]
        operations = [
            lambda: os.environ.__setitem__(POLICY_VAR, "{}"),
            lambda: os.environ.pop(POLICY_VAR),
            lambda: os.putenv(POLICY_VAR, "{}"),
            lambda: os.unsetenv(POLICY_VAR),
            lambda: os.putenv(POLICY_VAR.lower(), "{}"),
        ]
        with _replaced_pth_guard(monkeypatch):
            for operation in operations:
                with pytest.raises(tethered.SubprocessBlocked, match="integrity"):
                    operation()
            os.environ["TETHERED_TEST_UNRELATED"] = "1"
            del os.environ["TETHERED_TEST_UNRELATED"]
        assert os.environ[POLICY_VAR] == before
        assert "TAMPER DETECTED" in capfd.readouterr().err

    def test_refuses_even_when_subprocess_blocked_cannot_be_built(
        self, capfd, scratch_pth, monkeypatch
    ):
        _activate_locked()
        with monkeypatch.context() as patch:
            patch.setattr(tethered.SubprocessBlocked, "__init__", object())
            with pytest.raises(RuntimeError, match="integrity violation") as excinfo:
                os.truncate(scratch_pth, 0)
            assert type(excinfo.value) is RuntimeError
        assert scratch_pth.read_text() == PTH_LINE
        assert "TAMPER DETECTED" in capfd.readouterr().err


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
        # Keep the test offline with a stand-in resolver.  The guardian
        # captures _socket.getaddrinfo when it is activated and calls that
        # object from then on, so the stand-in has to be in place first.
        fake_results = [(0, 0, 0, "", ("203.0.113.99", 0))]
        monkeypatch.setattr(_socket, "getaddrinfo", lambda *a, **kw: fake_results)

        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        with _ip_map_lock:
            _core._allowed_hostnames["api.example.com"] = None

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
        # Stand-in resolver, installed before activation (see the test above).
        monkeypatch.setattr(
            _socket,
            "getaddrinfo",
            lambda *a, **kw: [(0, 0, 0, "", ("203.0.113.42", 0))],
        )

        secret = object()
        tethered.activate(allow=["api.example.com"], locked=True, lock_token=secret)
        # Pretend a prior getaddrinfo populated _allowed_hostnames but not
        # the IP that the app is now connecting to.
        with _ip_map_lock:
            _core._allowed_hostnames["api.example.com"] = None

        # The connect path should NOT raise — the fallback finds the match.
        _audit_hook("socket.connect", (None, ("203.0.113.42", 443)))


# ── The trusted resolver window (R7) ───────────────────────────────


class _StandInResolver:
    """Stand-in for ``_socket.getaddrinfo`` that can run code inside the window.

    The guardian captures ``_socket.getaddrinfo`` when it is activated, so a
    test installs this *before* activating; ``inside`` then runs while the
    guardian's resolution window is open on the calling thread.
    """

    RESOLVED_IP = "203.0.113.7"

    def __init__(self) -> None:
        self.inside = None
        self.hosts: list[object] = []

    def __call__(self, host, port, *rest):
        self.hosts.append(host)
        if self.inside is not None:
            self.inside(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (self.RESOLVED_IP, port or 0))]


class _Abort(BaseException):
    """Not an ``Exception``: escapes the handlers' best-effort ``except``."""


@pytest.fixture
def stand_in_resolver(monkeypatch):
    resolver = _StandInResolver()
    monkeypatch.setattr(_socket, "getaddrinfo", resolver)
    return resolver


@pytest.fixture
def loopback_ports():
    """Two listening TCP ports on 127.0.0.1: one the tests allow, one they do not."""
    servers = []
    for _ in range(2):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(16)
        servers.append(server)
    yield tuple(server.getsockname()[1] for server in servers)
    for server in servers:
        server.close()


def _try_connect(port: int) -> str:
    with socket.socket() as client:
        client.settimeout(5)
        try:
            client.connect(("127.0.0.1", port))
        except tethered.EgressBlocked:
            return "blocked"
        return "connected"


def _try_sendto(port: int) -> str:
    with socket.socket(type=socket.SOCK_DGRAM) as client:
        try:
            client.sendto(b"x", ("127.0.0.1", port))
        except tethered.EgressBlocked:
            return "blocked"
        return "sent"


def _resolve_through(path: str, hostname: str = "allowed.test") -> str | None:
    """Drive one of the two code paths that call ``_c_guardian.resolve``."""
    if path == "getaddrinfo-hook":
        _audit_hook("socket.getaddrinfo", (hostname, 443, 0, 0, 0))
        return hostname
    with _ip_map_lock:
        _core._allowed_hostnames[hostname] = None
        _core._allowed_hostnames.move_to_end(hostname)
    return _core._fallback_resolve(_StandInResolver.RESOLVED_IP, 443)


RESOLVER_PATHS = ["getaddrinfo-hook", "fallback-resolve"]


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestResolverWindow:
    """What the guardian trusts while it is inside its own DNS resolution."""

    @staticmethod
    def _lock(open_port: int) -> None:
        tethered.activate(
            allow=["allowed.test", "other.test", f"127.0.0.1:{open_port}"],
            allow_localhost=False,
            locked=True,
            lock_token=object(),
        )

    @pytest.mark.parametrize("path", RESOLVER_PATHS)
    def test_resolver_replaced_after_activation_is_never_called(self, path, monkeypatch, capfd):
        """The review's R7 reproduction: the replacement never gets inside the window."""
        tethered.activate(allow=["localhost"], locked=True, lock_token=object())
        calls = []

        def replacement(*args):
            calls.append(args)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.66", 0))]

        with monkeypatch.context() as patch:
            patch.setattr(_socket, "getaddrinfo", replacement)
            if path == "getaddrinfo-hook":
                _audit_hook("socket.getaddrinfo", ("localhost", 80, 0, 0, 0))
            else:
                with _ip_map_lock:
                    _core._allowed_hostnames["localhost"] = None
                assert _core._fallback_resolve("127.0.0.1", 80) == "localhost"
        assert calls == []
        with _ip_map_lock:
            # The genuine resolver answered, from the hosts file.
            assert _ip_to_hostname.get("127.0.0.1") == ("localhost",)
            assert "203.0.113.66" not in _ip_to_hostname
        assert "TAMPER DETECTED" not in capfd.readouterr().err

    @pytest.mark.parametrize("path", RESOLVER_PATHS)
    def test_connection_attempts_inside_the_window_are_refused(
        self, path, stand_in_resolver, loopback_ports, capfd
    ):
        open_port, closed_port = loopback_ports
        self._lock(open_port)
        assert _try_connect(open_port) == "connected"
        assert _try_connect(closed_port) == "blocked"

        seen = {}

        def inside(host):
            # Refused whatever the policy says: the Python hook's reentrancy
            # flag is set here, so it would not check anything.
            seen["forbidden"] = _try_connect(closed_port)
            seen["allowed"] = _try_connect(open_port)
            seen["datagram"] = _try_sendto(closed_port)

        stand_in_resolver.inside = inside
        assert _resolve_through(path) == "allowed.test"
        assert seen == {"forbidden": "blocked", "allowed": "blocked", "datagram": "blocked"}

        # Outside the window the policy decides again.
        assert _try_connect(open_port) == "connected"
        assert _try_connect(closed_port) == "blocked"
        assert "TAMPER DETECTED" not in capfd.readouterr().err

    def test_refusal_inside_the_window_names_the_destination(
        self, stand_in_resolver, loopback_ports
    ):
        open_port, _ = loopback_ports
        self._lock(open_port)
        caught = []

        def inside(host):
            for event, args in (
                ("socket.connect", (None, ("127.0.0.1", open_port))),
                ("socket.sendto", (None, ("127.0.0.1", open_port))),
                ("socket.sendmsg", (None, ("127.0.0.1", open_port))),
                ("socket.connect", (None, b"/run/app.sock")),
            ):
                try:
                    sys.audit(event, *args)
                except tethered.EgressBlocked as exc:
                    caught.append(exc.host)

        stand_in_resolver.inside = inside
        _resolve_through("getaddrinfo-hook")
        assert caught == ["127.0.0.1", "127.0.0.1", "127.0.0.1", "unknown (inside DNS resolution)"]

    def test_other_socket_events_inside_the_window_are_still_verified(
        self, stand_in_resolver, loopback_ports, monkeypatch, capfd
    ):
        """Only the resolver's own lookup is exempt; the snapshot still guards the rest."""
        open_port, _ = loopback_ports
        self._lock(open_port)
        seen = {}

        def inside(host):
            sys.audit("socket.tethered_test_probe")  # intact: passes
            sys.audit("socket.getaddrinfo", "anything.test", 80, 0, 0, 0)  # the exempt event
            with monkeypatch.context() as patch:
                patch.setattr(_core, "_FALLBACK_RESOLVE_MAX_CANDIDATES", 1)
                try:
                    sys.audit("socket.tethered_test_probe")
                except tethered.EgressBlocked:
                    seen["tampered"] = "refused"

        stand_in_resolver.inside = inside
        _resolve_through("getaddrinfo-hook")
        assert seen == {"tampered": "refused"}
        assert "TAMPER DETECTED" in capfd.readouterr().err

    @pytest.mark.parametrize("path", RESOLVER_PATHS)
    @pytest.mark.parametrize(
        "error", [OSError("resolver down"), _Abort()], ids=["OSError", "BaseException"]
    )
    def test_window_closes_when_the_resolver_raises(
        self, path, error, stand_in_resolver, loopback_ports, capfd
    ):
        open_port, _ = loopback_ports
        self._lock(open_port)

        def inside(host):
            raise error

        stand_in_resolver.inside = inside
        if isinstance(error, Exception):
            # Both callers treat a failed lookup as best-effort.
            expected = "allowed.test" if path == "getaddrinfo-hook" else None
            assert _resolve_through(path) == expected
        else:
            with pytest.raises(_Abort):
                _resolve_through(path)
        stand_in_resolver.inside = None
        self._assert_window_closed(open_port, capfd)

    def test_window_closes_when_the_genuine_resolver_raises(self, loopback_ports, capfd):
        open_port, _ = loopback_ports
        tethered.activate(
            allow=["localhost", f"127.0.0.1:{open_port}"],
            allow_localhost=False,
            locked=True,
            lock_token=object(),
        )
        # A port the real getaddrinfo() rejects; the hook swallows the error.
        _audit_hook("socket.getaddrinfo", ("localhost", object(), 0, 0, 0))
        self._assert_window_closed(open_port, capfd)

    @staticmethod
    def _assert_window_closed(open_port: int, capfd: pytest.CaptureFixture[str]) -> None:
        """Depth is back to zero: connects follow the policy, and the flag check is live."""
        # With the window stuck open this would be refused ...
        assert _try_connect(open_port) == "connected"
        assert "TAMPER DETECTED" not in capfd.readouterr().err
        # ... and this lookup would be waved through.
        flag = _core._in_hook.set(True)
        try:
            with pytest.raises(tethered.EgressBlocked):
                sys.audit("socket.getaddrinfo", "allowed.test", 443, 0, 0, 0)
        finally:
            _core._in_hook.reset(flag)
        assert "TAMPER DETECTED" in capfd.readouterr().err

    def test_window_is_per_thread(self, stand_in_resolver, loopback_ports, capfd):
        """Overlapping resolutions on two threads, one through each resolver path."""
        open_port, closed_port = loopback_ports
        self._lock(open_port)
        entered = threading.Event()
        release = threading.Event()
        seen = {}

        def inside(host):
            # Pause only the slow thread's own lookup, once.  (A connect to
            # an unmapped IP re-resolves recent hostnames on whichever
            # thread makes it, which lands here as well.)
            if threading.current_thread() is thread and not entered.is_set():
                entered.set()
                assert release.wait(30)
                seen["slow thread, inside"] = _try_connect(open_port)

        stand_in_resolver.inside = inside

        def slow():
            _resolve_through("getaddrinfo-hook", "allowed.test")
            seen["slow thread, after"] = _try_connect(open_port)

        thread = threading.Thread(target=slow)
        thread.start()
        try:
            assert entered.wait(30)
            # The other thread sits inside its window.  This one does not.
            assert _try_connect(open_port) == "connected"
            assert _try_connect(closed_port) == "blocked"
            # This thread resolves too, through the other path, and its own
            # window opens and closes while the first is still open.
            assert _resolve_through("fallback-resolve", "other.test") == "other.test"
            assert _try_connect(open_port) == "connected"
        finally:
            release.set()
            thread.join(30)
        assert not thread.is_alive()
        assert seen == {"slow thread, inside": "blocked", "slow thread, after": "connected"}
        assert {"allowed.test", "other.test"} <= set(stand_in_resolver.hosts)
        assert "TAMPER DETECTED" not in capfd.readouterr().err

    def test_authorized_reactivation_keeps_the_original_resolver(self, monkeypatch):
        """Only locking an unlocked process captures a resolver."""
        secret = object()
        tethered.activate(allow=["localhost"], locked=True, lock_token=secret)
        calls = []

        def replacement(*args):
            calls.append(args)
            return []

        with monkeypatch.context() as patch:
            patch.setattr(_socket, "getaddrinfo", replacement)
            tethered.activate(allow=["localhost", "other.test"], locked=True, lock_token=secret)
            _audit_hook("socket.getaddrinfo", ("localhost", 80, 0, 0, 0))
            assert calls == []

            tethered.deactivate(lock_token=secret)
            tethered.activate(allow=["localhost"], locked=True, lock_token=secret)
            _audit_hook("socket.getaddrinfo", ("localhost", 80, 0, 0, 0))
            assert len(calls) == 1
            tethered.deactivate(lock_token=secret)

    def test_resolve_needs_an_active_guardian(self):
        assert _core._c_guardian.is_active() is False
        with pytest.raises(RuntimeError, match="active guardian"):
            _core._c_guardian.resolve("localhost", 80, 0, 0, 0, 0)


# ── The guardian's own audit hook can be refused by another hook ───

# An audit hook cannot be removed, so a hook that vetoes others is only ever
# installed in a child process.  This runs first in each child.
_VETOING_HOOK_PRELUDE = '''
import json, os, sys

import tethered
import tethered._core as core

guardian = core._c_guardian
PROBE = "tethered._guardian.probe"
VARIABLE = "_TETHERED_CHILD_POLICY"

# tethered's Python hook goes in first, so that only the guardian's C hook
# meets the veto.
core._install_hook()

seen = []  # the two events of interest, in the order they were raised
veto = {}  # event -> exception class the hook below answers it with

def vetoing_hook(event, args):
    if event in ("sys.addaudithook", PROBE):
        seen.append(event)
        if event in veto:
            raise veto[event]("vetoed by another hook")

sys.addaudithook(vetoing_hook)

def lock(token):
    """Try to lock a policy: "locked", or the exception that came out."""
    del seen[:]
    try:
        tethered.activate(allow=["allowed.test"], locked=True, lock_token=token)
    except Exception as exc:
        return [type(exc).__name__, str(exc)]
    return "locked"

def state():
    config = None if core._config is None else "set"
    return [config, guardian.is_active(), os.environ.get(VARIABLE)]

def enforced():
    """Is the guardian's C hook acting?  Only it answers a tampered policy."""
    held = core._config
    core._config = None
    try:
        sys.audit("socket.tethered_test_probe")
    except tethered.EgressBlocked:
        return True
    finally:
        core._config = held
    return False

out = {}
'''

_ADD = "sys.addaudithook"
_PROBE = "tethered._guardian.probe"
_HOOK_REFUSED = "another audit hook in this process refused tethered's audit hook"


def _run_beside_a_vetoing_hook(body: str) -> dict:
    script = _VETOING_HOOK_PRELUDE + textwrap.dedent(body) + "\nprint(json.dumps(out))\n"
    env = {k: v for k, v in os.environ.items() if k != _core._CHILD_POLICY_ENV}
    child = subprocess.run(  # nosec B603
        [sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=120
    )
    assert child.returncode == 0, child.stderr
    return json.loads(child.stdout.splitlines()[-1])


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestHookInstallation:
    """A locked policy is only as good as the guardian's audit hook.

    ``PySys_AddAuditHook`` asks the hooks already installed, and when one of
    them answers with a ``RuntimeError`` it adds nothing and still reports
    success.  ``activate(locked=True)`` used to return normally then, with
    nothing enforced.
    """

    def test_a_refused_hook_fails_the_activation(self):
        out = _run_beside_a_vetoing_hook(
            """
            veto["sys.addaudithook"] = RuntimeError
            out["attempt"] = lock(object())
            out["events"] = list(seen)
            out["state"] = state()
            """
        )
        kind, message = out["attempt"]
        assert kind == "RuntimeError"
        assert _HOOK_REFUSED in message
        assert "it raised on the sys.addaudithook event" in message
        assert out["events"] == [_ADD, _PROBE]
        # All-or-nothing: no config, no lock, nothing published.
        assert out["state"] == [None, False, None]

    def test_the_policy_that_was_active_stays_as_it_was(self):
        out = _run_beside_a_vetoing_hook(
            """
            tethered.activate(allow=["first.test"])
            before = core._config, os.environ[VARIABLE]
            veto["sys.addaudithook"] = RuntimeError
            out["attempt"] = lock(object())[0]
            out["unchanged"] = [
                core._config is before[0],
                os.environ[VARIABLE] == before[1],
                guardian.is_active(),
            ]
            try:
                sys.audit("socket.connect", None, ("203.0.113.9", 443))
            except tethered.EgressBlocked as exc:
                out["still enforced"] = str(exc)
            """
        )
        assert out["attempt"] == "RuntimeError"
        assert out["unchanged"] == [True, True, False]
        assert out["still enforced"] == (
            "Blocked by tethered: 203.0.113.9:443 is not in the allow list"
        )

    def test_a_later_attempt_installs_the_hook_and_only_once(self):
        out = _run_beside_a_vetoing_hook(
            """
            token = object()
            veto["sys.addaudithook"] = RuntimeError
            out["first"] = [lock(token)[0], list(seen)]
            veto.clear()
            out["second"] = [lock(token), list(seen), enforced()]
            tethered.deactivate(lock_token=token)
            out["third"] = [lock(token), list(seen), enforced()]
            """
        )
        assert out["first"] == ["RuntimeError", [_ADD, _PROBE]]
        # It looks before it adds, adds, and looks again ...
        assert out["second"] == ["locked", [_PROBE, _ADD, _PROBE], True]
        # ... and once the hook is confirmed, never again.
        assert out["third"] == ["locked", [], True]

    def test_a_python_hook_refusing_the_probe_changes_nothing(self):
        """C hooks are called before Python hooks: the guardian has seen its probe by then."""
        out = _run_beside_a_vetoing_hook(
            """
            veto[PROBE] = RuntimeError
            out["attempt"] = [lock(object()), list(seen), enforced()]
            """
        )
        assert out["attempt"] == ["locked", [_ADD, _PROBE], True]

    def test_no_second_hook_while_a_first_cannot_be_ruled_out(self):
        """A refused probe says nothing; without an answer the hook is not added again."""
        out = _run_beside_a_vetoing_hook(
            """
            token = object()
            veto["sys.addaudithook"] = veto[PROBE] = RuntimeError
            out["first"] = [lock(token), list(seen)]
            del veto["sys.addaudithook"]
            out["second"] = [lock(token), list(seen), state()]
            veto.clear()
            out["third"] = [lock(token), list(seen), enforced()]
            """
        )
        first, first_events = out["first"]
        second, second_events, second_state = out["second"]
        for kind, message in (first, second):
            assert kind == "RuntimeError"
            assert _HOOK_REFUSED in message
            assert "it raised on the probe event" in message
        assert first_events == [_ADD, _PROBE]
        assert second_events == [_PROBE]  # looked, could not tell, added nothing
        assert second_state == [None, False, None]
        assert out["third"] == ["locked", [_PROBE, _ADD, _PROBE], True]

    def test_a_refusal_that_is_not_a_runtime_error_is_passed_on(self):
        """CPython swallows only ``RuntimeError``; anything else already failed loudly."""
        out = _run_beside_a_vetoing_hook(
            """
            token = object()
            veto["sys.addaudithook"] = PermissionError
            out["first"] = [lock(token), list(seen), state()]
            veto.clear()
            out["second"] = [lock(token), list(seen), enforced()]
            """
        )
        assert out["first"] == [
            ["PermissionError", "vetoed by another hook"],
            [_ADD],
            [None, False, None],
        ]
        assert out["second"] == ["locked", [_ADD, _PROBE], True]

    def test_the_probe_is_raised_once_per_process(self):
        """Other hooks see one private event, the first time a policy is locked."""
        out = _run_beside_a_vetoing_hook(
            """
            token = object()
            out["first"] = [lock(token), list(seen)]
            tethered.deactivate(lock_token=token)
            out["second"] = [lock(token), list(seen)]
            del seen[:]
            sys.audit(PROBE)  # anyone may raise an event of that name: it is only a name
            out["by name"] = [list(seen), guardian.is_active(), enforced()]
            """
        )
        assert out["first"] == ["locked", [_ADD, _PROBE]]
        assert out["second"] == ["locked", []]
        assert out["by name"] == [[_PROBE], True, True]

    def test_a_hook_that_locks_a_policy_while_being_asked_is_refused(self):
        """One thread at a time installs the guardian's hook — the same thread included.

        Another audit hook, asked about the guardian's hook, tries to lock a
        policy of its own: that would install the hook from inside its own
        installation.  It is refused, and the installation it interrupted
        goes on to complete, once.
        """
        out = _run_beside_a_vetoing_hook(
            """
            inner = []

            def locking_hook(event, args):
                if event == "sys.addaudithook" and not inner:
                    inner.append("asked")
                    try:
                        guardian.activate(vars(core), None, object(), [])
                    except Exception as exc:
                        inner.append([type(exc).__name__, str(exc)])
                    else:
                        inner.append("locked")

            sys.addaudithook(locking_hook)
            token = object()
            out["outer"] = [lock(token), list(seen), enforced()]
            out["inner"] = inner
            out["state"] = [guardian.is_active(), guardian.check_token(token)]
            tethered.deactivate(lock_token=token)
            out["again"] = [lock(token), list(seen), enforced()]
            """
        )
        assert out["inner"] == [
            "asked",
            [
                "RuntimeError",
                "tethered: a policy cannot be locked from inside an audit hook that is "
                "being asked about tethered's own audit hook",
            ],
        ]
        # The lock that was being taken is taken, by the caller that asked for it ...
        assert out["outer"] == ["locked", [_ADD, _PROBE], True]
        assert out["state"] == [True, True]
        # ... and the hook was added once: nothing is installed again later.
        assert out["again"] == ["locked", [], True]


# ── The lock as other interpreters meet it: join() and locked_payload() ──
# Seen here from the main interpreter, which is either the owner or has
# nothing to join.  ``test_subinterpreters.py`` joins for real.

_CANNOT_JOIN = "tethered: cannot join the locked policy: "


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestJoinIsNotForTheOwner:
    def test_nothing_to_join_without_a_lock(self):
        guardian = _core._c_guardian
        with pytest.raises(RuntimeError) as excinfo:
            guardian.join(vars(_core), object(), [])
        assert str(excinfo.value) == _CANNOT_JOIN + "no policy is locked in this process"
        assert _core._config is None
        assert guardian.is_active() is False

    def test_the_interpreter_that_holds_the_lock_cannot_join_it(self, capfd):
        """Else ``join()`` would be a way to swap the owner's pinned config for another."""
        guardian = _core._c_guardian
        token = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=token)
        held = _core._config
        permissive = _core._Config(
            policy=AllowPolicy(["0.0.0.0/0"]), _serialized_payload=held._serialized_payload
        )
        for offered in (permissive, held, None):
            with pytest.raises(RuntimeError) as excinfo:
                guardian.join(vars(_core), offered, [])
            assert str(excinfo.value) == (
                _CANNOT_JOIN + "this interpreter is the one that holds the lock"
            )
        with pytest.raises(RuntimeError, match="holds the lock"):
            _core._join_locked(guardian.locked_payload())

        # Nothing moved: the same config, intact, still the token's to release.
        assert _core._config is held
        assert guardian.verify() is True
        assert guardian.check_token(token) is True
        with pytest.raises(tethered.EgressBlocked, match="is not in the allow list"):
            sys.audit("socket.connect", None, ("203.0.113.9", 443))
        assert "TAMPER DETECTED" not in capfd.readouterr().err
        tethered.deactivate(lock_token=token)
        assert guardian.is_active() is False

    @pytest.mark.parametrize(
        "args",
        [(), (None, None, []), ([], None, []), ({}, None), ({}, None, [], "extra")],
        ids=["none", "namespace-none", "namespace-list", "too-few", "too-many"],
    )
    def test_arguments_are_checked_before_anything_else(self, args):
        with pytest.raises(TypeError):
            _core._c_guardian.join(*args)
        assert _core._config is None


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestLockedPayload:
    """``locked_payload()``: the guardian's own copy of what is locked."""

    def test_none_while_nothing_is_locked(self):
        assert _core._c_guardian.locked_payload() is None
        tethered.activate(allow=["*.example.com"])  # active, not locked
        assert _core._c_guardian.locked_payload() is None

    def test_it_is_the_locked_configs_payload_and_follows_the_lock(self):
        guardian = _core._c_guardian
        token = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=token)
        first = _core._config._serialized_payload
        assert guardian.locked_payload() == first == os.environ[_core._CHILD_POLICY_ENV]

        tethered.activate(allow=["*.other.com"], log_only=True, locked=True, lock_token=token)
        second = _core._config._serialized_payload
        assert second != first
        assert guardian.locked_payload() == second

        tethered.activate(allow=["*.unlocked.com"], lock_token=token)  # replaced by an unlocked one
        assert guardian.locked_payload() is None
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=token)
        assert guardian.locked_payload() == first
        tethered.deactivate(lock_token=token)
        assert guardian.locked_payload() is None

    def test_it_is_a_copy_nothing_in_python_reaches(self):
        """Not the config's own string: rewriting the config's slot changes nothing here."""
        guardian = _core._c_guardian
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=object())
        published = _core._config._serialized_payload
        forged = published.replace("*.example.com", "*")
        object.__setattr__(_core._config, "_serialized_payload", forged)
        try:
            assert _core._config._serialized_payload == forged
            assert guardian.locked_payload() == published
            assert guardian.locked_payload() is not published
        finally:
            object.__setattr__(_core._config, "_serialized_payload", published)
        assert guardian.verify() is True

    @pytest.mark.parametrize(
        "payload",
        [None, 7, b'{"global": null}', "lone surrogate \udc80", ...],
        ids=["None", "int", "bytes", "unencodable", "missing"],
    )
    def test_a_lock_without_a_usable_payload_has_none(self, payload):
        """As when the guardian is exercised on its own: nobody can join such a lock."""
        guardian = _core._c_guardian
        token = object()
        fields = {} if payload is ... else {"_serialized_payload": payload}
        stand_in = types.SimpleNamespace(locked=True, log_only=False, **fields)
        guardian.activate(vars(_core), stand_in, token, [])
        try:
            assert guardian.is_active() is True
            assert guardian.locked_payload() is None
        finally:
            guardian.deactivate(token)

    def test_a_payload_of_any_text_is_returned_unchanged(self):
        guardian = _core._c_guardian
        token = object()
        text = '{"global": "é中\U0001f600", "scopes": []}' + " " * 5000
        stand_in = types.SimpleNamespace(locked=True, log_only=False, _serialized_payload=text)
        guardian.activate(vars(_core), stand_in, token, [])
        try:
            assert guardian.locked_payload() == text
        finally:
            guardian.deactivate(token)
        assert guardian.locked_payload() is None


# ── One state per interpreter, however many module objects ──────────


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestModuleInstances:
    """The extension can be imported again after it is removed from ``sys.modules``.

    That gives a second module object in the same interpreter.  Both must
    work on the same state: a fresh, empty one would be an interpreter with
    no lock to honour.
    """

    @pytest.fixture
    def second(self, monkeypatch):
        """Another instance of the extension module, not the one ``_core`` uses."""
        import importlib

        first = sys.modules["tethered._guardian"]
        monkeypatch.delitem(sys.modules, "tethered._guardian")
        again = importlib.import_module("tethered._guardian")
        monkeypatch.setitem(sys.modules, "tethered._guardian", first)
        # (importing a submodule also rebinds the package attribute)
        monkeypatch.setattr(tethered, "_guardian", first, raising=False)
        assert again is not first
        assert _core._c_guardian is first
        return again

    def test_a_second_instance_sees_the_same_lock(self, second, capfd):
        first = _core._c_guardian
        token = object()
        assert second.is_active() is False
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=token)

        assert second.is_active() is True
        assert second.verify() is True
        assert second.check_token(token) is True
        assert second.check_token(object()) is False
        assert second.locked_payload() == first.locked_payload()
        # It is no way around the token ...
        with pytest.raises(RuntimeError, match="requires correct lock_token"):
            second.deactivate(object())
        with pytest.raises(RuntimeError, match="requires correct lock_token"):
            second.activate(vars(_core), _core._config, object(), [])
        with pytest.raises(RuntimeError, match="holds the lock"):
            second.join(vars(_core), _core._config, [])
        assert first.is_active() is True
        assert first.verify() is True
        assert "TAMPER DETECTED" not in capfd.readouterr().err

        # ... and with the token it releases the one lock there is.
        assert second.deactivate(token) is True
        assert first.is_active() is False
        assert _core._config is None

    def test_dropping_a_second_instance_changes_nothing(self, capfd):
        """It is freed while the first one is in use, with a policy locked."""
        import importlib

        first = sys.modules["tethered._guardian"]
        token = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=token)

        del sys.modules["tethered._guardian"]
        try:
            again = importlib.import_module("tethered._guardian")
        finally:
            sys.modules["tethered._guardian"] = first
            tethered._guardian = first
        assert again is not first
        assert again.is_active() is True
        watcher = weakref.ref(again)
        del again
        gc.collect()
        assert watcher() is None, "the second instance was expected to be freed"

        assert _core._c_guardian is first
        assert _core._c_guardian.is_active() is True
        assert _core._c_guardian.verify() is True
        assert _core._c_guardian.check_token(token) is True
        with pytest.raises(tethered.EgressBlocked, match="is not in the allow list"):
            sys.audit("socket.connect", None, ("203.0.113.9", 443))
        sys.audit("socket.connect", None, ("127.0.0.1", 443))
        assert "TAMPER DETECTED" not in capfd.readouterr().err
        tethered.deactivate(lock_token=token)
        assert _core._c_guardian.is_active() is False

    def test_a_lock_taken_through_the_second_instance_is_the_same_lock(self, second):
        """It is the interpreter that holds a lock, not a module object."""
        token = object()
        stand_in = types.SimpleNamespace(locked=True, log_only=False)
        second.activate(vars(_core), stand_in, token, [])
        try:
            assert _core._c_guardian.is_active() is True
            assert _core._c_guardian.check_token(token) is True
            assert _core._c_guardian.verify() is True
        finally:
            assert _core._c_guardian.deactivate(token) is True
        assert second.is_active() is False


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestWhatTheCollectorIsTold:
    """The module tells the garbage collector what the guardian holds — but not the token.

    It has to tell: the snapshot pins ``tethered._core``'s namespace, which
    names the module, and a cycle the collector cannot see would outlive
    the interpreter.  Whatever it tells, ``gc.get_referents()`` repeats to
    anyone.
    """

    class _Token:
        """A token the collector tracks, so that it could turn up in a traversal."""

        def __init__(self) -> None:
            self.cycle = self

    def test_the_token_is_not_among_the_modules_referents(self):
        guardian = _core._c_guardian
        token = self._Token()
        assert gc.is_tracked(token)
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=token)
        cfg = _core._config

        told = gc.get_referents(guardian)
        # The collector is told about what is pinned (so this is not vacuous) ...
        assert any(obj is cfg for obj in told)
        assert any(obj is vars(_core) for obj in told)
        # ... and not about the token: neither directly nor one step on.
        assert not any(obj is token for obj in told)
        for obj in told:
            if obj is not token.__dict__ and gc.is_tracked(obj) and not isinstance(obj, dict):
                assert not any(inner is token for inner in gc.get_referents(obj)), obj
        # Asking who refers to the token does not name the guardian either.
        assert not any(obj is guardian for obj in gc.get_referrers(token))

        assert guardian.check_token(token) is True
        tethered.deactivate(lock_token=token)

    def test_a_collection_leaves_a_locked_policy_as_it_is(self, capfd):
        token = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=token)
        for _ in range(3):
            gc.collect()
        assert _core._c_guardian.is_active() is True
        assert _core._c_guardian.verify() is True
        assert _core._c_guardian.check_token(token) is True
        with pytest.raises(tethered.EgressBlocked, match="is not in the allow list"):
            sys.audit("socket.connect", None, ("203.0.113.9", 443))
        assert "TAMPER DETECTED" not in capfd.readouterr().err

    def test_nothing_is_held_once_the_lock_is_released(self):
        guardian = _core._c_guardian
        token = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=token)
        cfg = _core._config
        # (A _Config has slots and takes no weak reference: ask the collector.)
        assert any(obj is guardian for obj in gc.get_referrers(cfg))
        assert any(obj is guardian for obj in gc.get_referrers(cfg.policy))
        tethered.deactivate(lock_token=token)
        assert not any(obj is guardian for obj in gc.get_referrers(cfg))
        assert not any(obj is guardian for obj in gc.get_referrers(cfg.policy))
        assert not any(obj is cfg for obj in gc.get_referents(guardian))
        # The namespace of tethered._core is let go of as well.
        assert not any(obj is vars(_core) for obj in gc.get_referents(guardian))


# Child process of TestTheOwnerWithoutItsState: the lock taken there is never released.
_LOSE_THE_STATE = """
import gc, json, sys

import tethered
import tethered._core as core

out = {}

def outcome(call, *args):
    try:
        call(*args)
    except RuntimeError as exc:
        return [type(exc).__name__, str(exc)]
    return "ok"

token = object()
tethered.activate(allow=["127.0.0.1"], locked=True, lock_token=token)
out["before"] = [
    outcome(sys.audit, "socket.connect", None, ("127.0.0.1", 9)),
    core._c_guardian.verify(),
]

# Every reference to the extension module goes: the names in tethered._core
# (which the snapshot pins; the activation claim is an object of the module
# and keeps it alive), the package attribute, sys.modules.
core._c_guardian = None
core._activation_claim = None
del tethered._guardian
del sys.modules["tethered._guardian"]
gc.collect()

out["after"] = {
    "connect": outcome(sys.audit, "socket.connect", None, ("127.0.0.1", 9)),
    "new socket": outcome(sys.audit, "socket.__new__", None, 2, 1, 0),
    "launch": outcome(sys.audit, "os.system", "prog"),
    "other file": outcome(sys.audit, "open", "data/other.txt", "w", 0),
    "the bootstrap": outcome(sys.audit, "open", "site-packages/tethered.pth", "w", 0),
    "other variable": outcome(sys.audit, "os.putenv", "PATH", "x"),
    "unguarded": outcome(sys.audit, "tethered.test.unguarded"),
}

# Importing it again gives the interpreter a new, empty state: no way back.
import tethered._guardian as again
out["again"] = {
    "is_active": again.is_active(),
    "verify": again.verify(),
    "check_token": again.check_token(token),
    "activate": outcome(again.activate, vars(core), None, token, []),
    "deactivate": outcome(again.deactivate, token),
    "join": outcome(again.join, vars(core), None, []),
    "resolve": outcome(again.resolve, "localhost", 80, 0, 0, 0, 0),
    "connect": outcome(sys.audit, "socket.connect", None, ("127.0.0.1", 9)),
}
print(json.dumps(out))
"""


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestTheOwnerWithoutItsState:
    """The interpreter that took the lock lets go of every instance of the extension.

    That takes rebinding names the snapshot pins.  The guardian's state for
    the interpreter goes with the module — and with it everything a guarded
    event could be verified against, and the token.  The lock is the
    process's and stays: the interpreter is refused what tethered guards,
    for good.

    Run in a child process, which stays locked until it exits.
    """

    def test_it_is_refused_everything_guarded_and_cannot_unlock(self):
        env = {k: v for k, v in os.environ.items() if k != _core._CHILD_POLICY_ENV}
        child = subprocess.run(  # nosec B603
            [sys.executable, "-c", _LOSE_THE_STATE],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert child.returncode == 0, child.stderr
        out = json.loads(child.stdout.splitlines()[-1])
        assert out["before"] == ["ok", True]

        violation = "Blocked by tethered (integrity violation): "
        assert out["after"] == {
            "connect": ["RuntimeError", violation + "127.0.0.1"],
            "new socket": ["RuntimeError", violation + "unknown"],
            "launch": ["RuntimeError", violation + "os.system"],
            "other file": "ok",
            "the bootstrap": ["RuntimeError", violation + "open"],
            "other variable": "ok",
            "unguarded": "ok",
        }
        gone = (
            "tethered: this interpreter locked the policy, but the guardian's state "
            "for it is gone, so the lock can be neither replaced nor released"
        )
        assert out["again"] == {
            "is_active": True,
            "verify": False,
            "check_token": False,
            "activate": ["RuntimeError", gone],
            "deactivate": ["RuntimeError", gone],
            "join": [
                "RuntimeError",
                _CANNOT_JOIN + "this interpreter is the one that holds the lock",
            ],
            "resolve": ["RuntimeError", violation + "unauthorized _guardian.resolve() call"],
            "connect": ["RuntimeError", violation + "127.0.0.1"],
        }
        # Said once, however many events are refused.
        assert child.stderr.count("TAMPER DETECTED") == 1


class TestTetheredLockedException:
    def test_message(self):
        exc = tethered.TetheredLocked()
        assert "locked" in str(exc).lower()
        assert "deactivate" in str(exc).lower()

    def test_is_runtime_error(self):
        assert issubclass(tethered.TetheredLocked, RuntimeError)
        assert isinstance(tethered.TetheredLocked(), RuntimeError)
