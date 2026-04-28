"""Tests for locked mode and the C-level integrity guardian."""

from __future__ import annotations

import _socket
import socket
import sys
import threading
import unittest.mock

import pytest

import tethered
import tethered._core as _core
from tethered._core import _audit_hook, _ip_map_lock, _ip_to_hostname
from tethered._policy import AllowPolicy

requires_network = pytest.mark.requires_network


class TestLockedMode:
    def test_locked_activation_requires_token(self):
        with pytest.raises(ValueError, match="lock_token is required"):
            tethered.activate(allow=["*.example.com"], locked=True)

    @pytest.mark.parametrize("token", ["secret", 42, 3.14, b"key", True])
    def test_lock_token_rejects_internable_types(self, token):
        with pytest.raises(TypeError, match="must not be a str"):
            tethered.activate(allow=["*.example.com"], locked=True, lock_token=token)

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
            assert any(v == "dns.google" for v in _ip_to_hostname.values())

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
            assert _ip_to_hostname.get("203.0.113.99") == "api.example.com"

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
