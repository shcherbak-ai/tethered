"""Integration tests for tethered activate/deactivate with real sockets."""

from __future__ import annotations

import asyncio
import logging
import socket
import subprocess
import sys
import threading

import pytest

import tethered
from tethered._core import (
    _IP_MAP_MAX_SIZE,
    _audit_hook,
    _check_scopes,
    _csocket,
    _enforce_scope_block,
    _extract_host_port,
    _handle_connect,
    _handle_dns_lookup,
    _handle_getaddrinfo,
    _in_hook,
    _ip_map_lock,
    _ip_to_hostname,
    _is_ip,
    _reset_state,
    _ScopeConfig,
    _scopes,
)
from tethered._policy import AllowPolicy


def _raise_runtime(self, host, port=None):
    raise RuntimeError("simulated policy bug")


def _has_network() -> bool:
    """Check if external DNS resolution is available."""
    try:
        socket.getaddrinfo("dns.google", 443)
        return True
    except OSError:
        return False


requires_network = pytest.mark.skipif(
    not _has_network(),
    reason="No network access",
)


@pytest.fixture(autouse=True)
def _cleanup():
    """Reset tethered state after each test."""
    yield
    _reset_state()


class TestInputValidation:
    """Validate that public APIs reject invalid input with clear errors."""

    def test_activate_allow_not_list(self):
        with pytest.raises(TypeError, match="allow must be a list"):
            tethered.activate(allow="*.stripe.com")

    def test_activate_allow_item_not_string(self):
        with pytest.raises(TypeError, match=r"allow\[0\] must be a string"):
            tethered.activate(allow=[123])

    def test_activate_allow_none(self):
        with pytest.raises(TypeError, match="allow must be a list"):
            tethered.activate(allow=None)

    def test_activate_on_blocked_not_callable(self):
        with pytest.raises(TypeError, match="on_blocked must be callable"):
            tethered.activate(allow=[], on_blocked="bad")

    def test_scope_allow_not_list(self):
        with pytest.raises(TypeError, match="allow must be a list"):
            tethered.scope(allow="*.stripe.com")

    def test_scope_allow_item_not_string(self):
        with pytest.raises(TypeError, match=r"allow\[0\] must be a string"):
            tethered.scope(allow=[None])

    def test_scope_on_blocked_not_callable(self):
        with pytest.raises(TypeError, match="on_blocked must be callable"):
            tethered.scope(allow=[], on_blocked=42)

    def test_activate_locked_not_bool(self):
        with pytest.raises(TypeError, match="locked must be a bool"):
            tethered.activate(allow=[], locked="true", lock_token=object())

    def test_activate_log_only_not_bool(self):
        with pytest.raises(TypeError, match="log_only must be a bool"):
            tethered.activate(allow=[], log_only="false")

    def test_activate_fail_closed_not_bool(self):
        with pytest.raises(TypeError, match="fail_closed must be a bool"):
            tethered.activate(allow=[], fail_closed=1)

    def test_activate_allow_localhost_not_bool(self):
        with pytest.raises(TypeError, match="allow_localhost must be a bool"):
            tethered.activate(allow=[], allow_localhost=0)

    def test_scope_log_only_not_bool(self):
        with pytest.raises(TypeError, match="log_only must be a bool"):
            tethered.scope(allow=[], log_only="false")

    def test_scope_fail_closed_not_bool(self):
        with pytest.raises(TypeError, match="fail_closed must be a bool"):
            tethered.scope(allow=[], fail_closed="yes")

    def test_scope_allow_localhost_not_bool(self):
        with pytest.raises(TypeError, match="allow_localhost must be a bool"):
            tethered.scope(allow=[], allow_localhost=None)


class TestActivateDeactivate:
    def test_blocks_disallowed_getaddrinfo(self):
        tethered.activate(allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

    def test_blocks_disallowed_connect(self):
        tethered.activate(allow=["*.example.com"])
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(tethered.EgressBlocked):
                s.connect(("192.0.2.1", 80))
        finally:
            s.close()

    def test_allows_localhost(self):
        # Localhost is allowed by default (allow_localhost=True)
        tethered.activate(allow=[])
        socket.getaddrinfo("localhost", 80)

    def test_allows_localhost_connect(self):
        # Localhost is allowed by default (allow_localhost=True)
        tethered.activate(allow=[])
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(1)
            try:
                s.connect(("127.0.0.1", 1))
            except (ConnectionError, TimeoutError, OSError):
                pass  # Connection refused is fine, EgressBlocked is not
        finally:
            s.close()

    @requires_network
    def test_deactivate_allows_everything(self):
        tethered.activate(allow=["*.example.com"])
        tethered.deactivate()
        # After deactivate, tethered's hook is a no-op — previously
        # blocked hostnames are no longer blocked by tethered.
        # Use dns.google (allowed by conftest egress guard) to verify.
        socket.getaddrinfo("dns.google", 80)

    def test_allows_ip_in_cidr(self):
        tethered.activate(allow=["198.51.100.0/24"])
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(2)
            try:
                s.connect(("198.51.100.1", 53))
            except (ConnectionError, TimeoutError, OSError):
                pass  # Network-level failure is fine, EgressBlocked is not
        finally:
            s.close()


class TestConnectEx:
    def test_blocks_connect_ex(self):
        tethered.activate(allow=["*.example.com"])
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(tethered.EgressBlocked):
                s.connect_ex(("192.0.2.1", 80))
        finally:
            s.close()


class TestUDPSendTo:
    def test_blocks_sendto(self):
        tethered.activate(allow=["*.example.com"])
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(tethered.EgressBlocked):
                s.sendto(b"hello", ("192.0.2.1", 9999))
        finally:
            s.close()

    def test_allows_sendto_for_allowed_ip(self):
        tethered.activate(allow=["198.51.100.0/24"])
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Should not raise EgressBlocked
            s.sendto(b"hello", ("198.51.100.1", 53))
        finally:
            s.close()


class TestGetaddrinfoEnforcement:
    def test_blocks_dns_for_disallowed_host(self):
        tethered.activate(allow=["*.stripe.com"])
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 443)

    def test_allows_dns_for_localhost(self):
        # Localhost is allowed by default (allow_localhost=True)
        tethered.activate(allow=[])
        socket.getaddrinfo("localhost", 80)


class TestPolicySwap:
    def test_reactivate_with_different_rules(self):
        tethered.activate(allow=["*.stripe.com"])
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

        # Swap policy — stripe.com should now be blocked
        tethered.activate(allow=["evil.test"])
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("api.stripe.com", 443)


class TestLogOnly:
    def test_log_only_does_not_raise(self):
        blocked: list[tuple[str, int | None]] = []

        def on_blocked(host: str, port: int | None) -> None:
            blocked.append((host, port))

        tethered.activate(
            allow=["*.example.com"],
            log_only=True,
            on_blocked=on_blocked,
        )

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(2)
            try:
                s.connect(("192.0.2.1", 9999))
            except (ConnectionError, TimeoutError, OSError):
                pass
        finally:
            s.close()

        assert len(blocked) > 0

    def test_log_only_getaddrinfo_does_not_raise(self):
        blocked: list[tuple[str, int | None]] = []

        def on_blocked(host: str, port: int | None) -> None:
            blocked.append((host, port))

        tethered.activate(
            allow=["*.example.com"],
            log_only=True,
            on_blocked=on_blocked,
        )

        socket.getaddrinfo("dns.google", 80)
        assert len(blocked) > 0
        assert blocked[0][0] == "dns.google"


class TestOnBlocked:
    def test_callback_receives_host_and_port(self):
        blocked: list[tuple[str, int | None]] = []

        def on_blocked(host: str, port: int | None) -> None:
            blocked.append((host, port))

        tethered.activate(
            allow=["*.example.com"],
            on_blocked=on_blocked,
        )

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(tethered.EgressBlocked):
                s.connect(("203.0.113.1", 9999))
        finally:
            s.close()

        assert len(blocked) == 1
        assert blocked[0] == ("203.0.113.1", 9999)

    def test_callback_receives_normalized_host(self):
        """on_blocked should receive the same normalized form from both paths."""
        blocked: list[tuple[str, int | None]] = []

        def on_blocked(host: str, port: int | None) -> None:
            blocked.append((host, port))

        tethered.activate(allow=["*.stripe.com"], on_blocked=on_blocked)

        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(tethered.EgressBlocked):
                s.connect(("203.0.113.1", 9999))
        finally:
            s.close()

        assert len(blocked) == 2
        # getaddrinfo path delivers normalized hostname
        assert blocked[0] == ("evil.test", None)
        # connect path delivers normalized IP
        assert blocked[1] == ("203.0.113.1", 9999)


class TestAsyncSockets:
    @pytest.mark.asyncio
    async def test_blocks_async_getaddrinfo(self):
        tethered.activate(allow=["*.example.com"])
        loop = asyncio.get_event_loop()

        with pytest.raises(tethered.EgressBlocked):
            await loop.getaddrinfo("evil.test", 80)

    @pytest.mark.asyncio
    async def test_blocks_async_connect(self):
        tethered.activate(allow=["*.example.com"])

        with pytest.raises(tethered.EgressBlocked):
            await asyncio.open_connection("evil.test", 80)

    @pytest.mark.asyncio
    async def test_allows_async_localhost_connect(self):
        # Localhost is allowed by default (allow_localhost=True)
        tethered.activate(allow=[])
        try:
            await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", 1),
                timeout=0.5,
            )
        except (ConnectionError, TimeoutError, asyncio.TimeoutError, OSError):
            pass  # Connection refused/timeout is fine — EgressBlocked would be wrong

    @pytest.mark.asyncio
    async def test_async_log_only_does_not_raise(self):
        blocked: list[tuple[str, int | None]] = []
        tethered.activate(
            allow=["*.example.com"],
            log_only=True,
            on_blocked=lambda h, p: blocked.append((h, p)),
        )
        loop = asyncio.get_event_loop()
        await loop.getaddrinfo("dns.google", 80)
        assert any(h == "dns.google" for h, _ in blocked)

    @pytest.mark.asyncio
    async def test_async_on_blocked_callback(self):
        blocked: list[tuple[str, int | None]] = []
        tethered.activate(
            allow=["*.example.com"],
            on_blocked=lambda h, p: blocked.append((h, p)),
        )
        with pytest.raises(tethered.EgressBlocked):
            await asyncio.open_connection("evil.test", 80)
        assert any(h == "evil.test" for h, _ in blocked)

    @pytest.mark.asyncio
    async def test_async_fail_closed(self, monkeypatch):
        tethered.activate(allow=["*.example.com"], fail_closed=True)
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        loop = asyncio.get_event_loop()
        with pytest.raises(tethered.EgressBlocked):
            await loop.getaddrinfo("evil.test", 80)

    @pytest.mark.asyncio
    async def test_async_concurrent_enforcement(self):
        """Multiple async tasks hitting the policy concurrently."""
        tethered.activate(allow=["*.example.com"])

        async def blocked_resolve():
            loop = asyncio.get_event_loop()
            with pytest.raises(tethered.EgressBlocked):
                await loop.getaddrinfo("evil.test", 80)

        await asyncio.gather(*[blocked_resolve() for _ in range(10)])

    @pytest.mark.asyncio
    async def test_async_conftest_guard_blocks(self):
        """Conftest guard blocks async DNS when tethered is deactivated."""
        # _cleanup fixture ensures _config is None after each test,
        # but we start deactivated here explicitly
        with pytest.raises(tethered.EgressBlocked, match=r"evil\.test"):
            loop = asyncio.get_event_loop()
            await loop.getaddrinfo("evil.test", 80)


class TestTransparency:
    """Verify tethered does not intercept or modify allowed traffic."""

    def test_tcp_data_roundtrip(self):
        """Data sent through an allowed connection arrives byte-for-byte unchanged."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen(1)

        payload = b"\x00\x01\x02\xff" * 256  # 1 KiB of binary data

        # Localhost is allowed by default (allow_localhost=True)
        tethered.activate(allow=[])

        def echo_server():
            conn, _ = server.accept()
            data = b""
            while len(data) < len(payload):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            conn.sendall(data)
            conn.close()

        t = threading.Thread(target=echo_server)
        t.start()

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(("127.0.0.1", port))
        client.sendall(payload)
        received = b""
        while len(received) < len(payload):
            chunk = client.recv(4096)
            if not chunk:
                break
            received += chunk
        client.close()
        t.join(timeout=5)
        server.close()

        assert received == payload

    def test_dns_resolution_unchanged(self):
        """getaddrinfo returns the same results with and without tethered."""
        # Resolve localhost without tethered
        baseline = socket.getaddrinfo("localhost", 80, socket.AF_INET)

        # Localhost is allowed by default (allow_localhost=True)
        tethered.activate(allow=[])
        with_tethered = socket.getaddrinfo("localhost", 80, socket.AF_INET)

        assert baseline == with_tethered

    def test_preexisting_connection_survives_activate(self):
        """Connections established before activate() continue to work."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen(1)

        payload = b"pre-existing-connection-test"

        # Connect BEFORE tethered is activated
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(("127.0.0.1", port))
        srv_conn, _ = server.accept()

        # Now activate with an empty allow list (only localhost allowed)
        tethered.activate(allow=[])

        # Read/write on the pre-existing connection should still work
        client.sendall(payload)
        received = b""
        while len(received) < len(payload):
            chunk = srv_conn.recv(4096)
            if not chunk:
                break
            received += chunk

        client.close()
        srv_conn.close()
        server.close()

        assert received == payload

    @pytest.mark.asyncio
    async def test_async_tcp_data_roundtrip(self):
        """Async data sent through an allowed connection arrives unchanged."""
        payload = b"async-test-payload-" + bytes(range(256))

        server = await asyncio.start_server(
            lambda r, w: _async_echo(r, w, len(payload)),
            "127.0.0.1",
            0,
        )
        port = server.sockets[0].getsockname()[1]

        # Localhost is allowed by default (allow_localhost=True)
        tethered.activate(allow=[])

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(payload)
        await writer.drain()
        received = await asyncio.wait_for(reader.readexactly(len(payload)), timeout=5)
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()

        assert received == payload


async def _async_echo(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    expected: int,
) -> None:
    data = await reader.readexactly(expected)
    writer.write(data)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


class TestEgressBlockedException:
    def test_attributes(self):
        exc = tethered.EgressBlocked("evil.test", 443)
        assert exc.host == "evil.test"
        assert exc.port == 443
        assert exc.resolved_from is None
        assert "evil.test:443" in str(exc)

    def test_with_resolved_from(self):
        exc = tethered.EgressBlocked("203.0.113.1", 443, resolved_from="evil.test")
        assert exc.resolved_from == "evil.test"
        assert "resolved from evil.test" in str(exc)

    def test_no_port(self):
        exc = tethered.EgressBlocked("evil.test", None)
        assert "evil.test is not in the allow list" in str(exc)

    def test_is_runtime_error(self):
        assert issubclass(tethered.EgressBlocked, RuntimeError)
        assert isinstance(tethered.EgressBlocked("h", 1), RuntimeError)


class TestFailOpen:
    def test_fail_open_getaddrinfo(self, monkeypatch):
        """If policy.is_allowed raises, getaddrinfo should proceed (fail-open)."""
        tethered.activate(allow=["*.example.com"])

        def boom(self, host, port=None):
            raise ValueError("simulated policy bug")

        monkeypatch.setattr(AllowPolicy, "is_allowed", boom)
        # Should not raise -- fail-open on internal errors
        socket.getaddrinfo("dns.google", 80)

    def test_fail_open_connect(self, monkeypatch):
        """If policy.is_allowed raises, connect should proceed (fail-open)."""
        tethered.activate(allow=["*.example.com"])

        def boom(self, host, port=None):
            raise ValueError("simulated policy bug")

        monkeypatch.setattr(AllowPolicy, "is_allowed", boom)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(1)
            try:
                s.connect(("192.0.2.1", 80))
            except (ConnectionError, TimeoutError, OSError):
                pass  # Network failure OK; ValueError/EgressBlocked would be wrong
        finally:
            s.close()


class TestFailClosed:
    def test_fail_closed_getaddrinfo(self, monkeypatch):
        """If policy.is_allowed raises and fail_closed=True, getaddrinfo should block."""
        tethered.activate(allow=["*.example.com"], fail_closed=True)

        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

    def test_fail_closed_connect(self, monkeypatch):
        """If policy.is_allowed raises and fail_closed=True, connect should block."""
        tethered.activate(allow=["*.example.com"], fail_closed=True)

        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(tethered.EgressBlocked):
                s.connect(("192.0.2.1", 80))
        finally:
            s.close()

    def test_fail_closed_direct_getaddrinfo(self, monkeypatch):
        tethered.activate(allow=["*.example.com"], fail_closed=True)
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))

    def test_fail_closed_direct_connect(self, monkeypatch):
        tethered.activate(allow=["*.example.com"], fail_closed=True)
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.connect", (None, ("192.0.2.1", 80)))

    def test_fail_closed_dns_lookup(self, monkeypatch):
        """Fail-closed should also work for gethostbyname/gethostbyaddr events."""
        tethered.activate(allow=["*.example.com"], fail_closed=True)
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.gethostbyname", ("evil.test",))


class TestLockedMode:
    def test_locked_activation_requires_token(self):
        with pytest.raises(ValueError, match="lock_token is required"):
            tethered.activate(allow=["*.example.com"], locked=True)

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


class TestTetheredLockedException:
    def test_message(self):
        exc = tethered.TetheredLocked()
        assert "locked" in str(exc).lower()
        assert "deactivate" in str(exc).lower()

    def test_is_runtime_error(self):
        assert issubclass(tethered.TetheredLocked, RuntimeError)
        assert isinstance(tethered.TetheredLocked(), RuntimeError)


class TestIsIp:
    def test_ipv4(self):
        assert _is_ip("192.0.2.1") is True

    def test_ipv6(self):
        assert _is_ip("::1") is True

    def test_hostname(self):
        assert _is_ip("example.com") is False

    def test_empty(self):
        assert _is_ip("") is False

    def test_invalid_ip_like_hostname(self):
        assert _is_ip("1example.com") is False


class TestExtractHostPort:
    def test_ipv4_tuple(self):
        assert _extract_host_port(("192.0.2.1", 80)) == ("192.0.2.1", 80)

    def test_ipv6_tuple(self):
        assert _extract_host_port(("::1", 443, 0, 0)) == ("::1", 443)

    def test_unix_path(self):
        assert _extract_host_port("/tmp/socket") is None

    def test_non_tuple(self):
        assert _extract_host_port(None) is None

    def test_wrong_types(self):
        assert _extract_host_port((123, 80)) is None
        assert _extract_host_port(("host", "80")) is None


class TestAuditHookDirect:
    """Call _audit_hook directly (bypasses C audit system) for coverage."""

    def test_noop_without_policy(self):
        _audit_hook("socket.connect", (None, ("192.0.2.1", 80)))

    def test_non_socket_event_skipped(self):
        tethered.activate(allow=["*.example.com"])
        _audit_hook("os.open", ("/some/path",))

    def test_unknown_event_ignored(self):
        tethered.activate(allow=["*.example.com"])
        _audit_hook("socket.unknown_event", ())

    def test_connect_blocks_disallowed_ip(self):
        tethered.activate(allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.connect", (None, ("192.0.2.1", 80)))

    def test_connect_allows_cidr(self):
        tethered.activate(allow=["198.51.100.0/24"])
        _audit_hook("socket.connect", (None, ("198.51.100.1", 80)))

    def test_connect_allows_localhost(self):
        tethered.activate(allow=["*.example.com"])
        _audit_hook("socket.connect", (None, ("127.0.0.1", 80)))

    def test_connect_af_unix_allowed(self):
        tethered.activate(allow=["*.example.com"])
        _audit_hook("socket.connect", (None, "/tmp/socket"))

    def test_connect_uses_ip_map(self):
        tethered.activate(allow=["*.stripe.com"])
        with _ip_map_lock:
            _ip_to_hostname["198.51.100.1"] = "api.stripe.com"
        _audit_hook("socket.connect", (None, ("198.51.100.1", 443)))

    def test_connect_ip_map_hostname_blocked(self):
        tethered.activate(allow=["*.stripe.com"])
        with _ip_map_lock:
            _ip_to_hostname["198.51.100.1"] = "evil.test"
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.connect", (None, ("198.51.100.1", 443)))

    def test_connect_log_only(self):
        blocked: list[tuple[str, int | None]] = []
        tethered.activate(
            allow=["*.example.com"],
            log_only=True,
            on_blocked=lambda h, p: blocked.append((h, p)),
        )
        _audit_hook("socket.connect", (None, ("192.0.2.1", 80)))
        assert blocked == [("192.0.2.1", 80)]

    def test_connect_on_blocked_exception_logged(self):
        """on_blocked exceptions are logged at DEBUG, not silently suppressed."""

        def bad_callback(host, port):
            raise RuntimeError("callback bug")

        tethered.activate(
            allow=["*.example.com"],
            on_blocked=bad_callback,
        )
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.connect", (None, ("192.0.2.1", 80)))

    def test_getaddrinfo_blocks_hostname(self):
        tethered.activate(allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))

    def test_getaddrinfo_skips_ip_host(self):
        tethered.activate(allow=["*.example.com"])
        _audit_hook("socket.getaddrinfo", ("192.0.2.1", 80, 0, 0, 0))

    def test_getaddrinfo_skips_empty_host(self):
        tethered.activate(allow=["*.example.com"])
        _audit_hook("socket.getaddrinfo", ("", 80, 0, 0, 0))

    def test_getaddrinfo_skips_non_string_host(self):
        tethered.activate(allow=["*.example.com"])
        _audit_hook("socket.getaddrinfo", (None, 80, 0, 0, 0))

    def test_getaddrinfo_log_only(self):
        blocked: list[tuple[str, int | None]] = []
        tethered.activate(
            allow=["*.example.com"],
            log_only=True,
            on_blocked=lambda h, p: blocked.append((h, p)),
        )
        _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))
        assert blocked == [("evil.test", None)]

    def test_getaddrinfo_on_blocked_exception_logged(self):
        def bad_callback(host, port):
            raise RuntimeError("callback bug")

        tethered.activate(
            allow=["*.example.com"],
            on_blocked=bad_callback,
        )
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))

    @requires_network
    def test_getaddrinfo_allowed_populates_ip_map(self):
        tethered.activate(allow=["dns.google"])
        _audit_hook("socket.getaddrinfo", ("dns.google", 443, 0, 0, 0))
        with _ip_map_lock:
            assert any(v == "dns.google" for v in _ip_to_hostname.values())

    def test_getaddrinfo_allowed_refreshes_existing_ip_map_entry(self, monkeypatch):
        tethered.activate(allow=["dns.google"])

        with _ip_map_lock:
            _ip_to_hostname.clear()
            _ip_to_hostname["203.0.113.10"] = "old.example.com"
            _ip_to_hostname["198.51.100.20"] = "stale.example.com"

        monkeypatch.setattr(
            _csocket,
            "getaddrinfo",
            lambda *args: [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.10", 443)),
            ],
        )

        _audit_hook("socket.getaddrinfo", ("dns.google", 443, 0, 0, 0, 0))

        with _ip_map_lock:
            assert _ip_to_hostname["203.0.113.10"] == "dns.google"
            assert list(_ip_to_hostname.keys())[-1] == "203.0.113.10"

    def test_getaddrinfo_forwards_caller_args(self, monkeypatch):
        """getaddrinfo forwards family/socktype/proto/flags to C-level resolver."""
        tethered.activate(allow=["dns.google"])
        captured = {}

        def _capture(*args):
            captured["args"] = args
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 443))]

        monkeypatch.setattr(_csocket, "getaddrinfo", _capture)
        _audit_hook(
            "socket.getaddrinfo",
            ("dns.google", 443, socket.AF_INET6, socket.SOCK_STREAM, 6, socket.AI_CANONNAME),
        )
        host, port, family, socktype, proto, flags = captured["args"]
        assert host == "dns.google"
        assert port == 443
        assert family == socket.AF_INET6
        assert socktype == socket.SOCK_STREAM
        assert proto == 6
        assert flags == socket.AI_CANONNAME

    def test_getaddrinfo_allowed_handles_dns_failure(self):
        tethered.activate(allow=["nonexistent.invalid"])
        _audit_hook("socket.getaddrinfo", ("nonexistent.invalid", 80, 0, 0, 0))

    def test_getaddrinfo_allowed_handles_non_os_error(self, monkeypatch):
        """IP map resolution tolerates non-OSError from C-level getaddrinfo."""
        tethered.activate(allow=["api.example.com"])

        def _boom(*_args, **_kwargs):
            raise RuntimeError("unexpected resolver failure")

        monkeypatch.setattr(_csocket, "getaddrinfo", _boom)
        # Should not raise — the IP map population is best-effort
        _audit_hook("socket.getaddrinfo", ("api.example.com", 443, 0, 0, 0))
        # No IP mapping stored (resolution failed), but DNS-level check passed
        with _ip_map_lock:
            assert not any(v == "api.example.com" for v in _ip_to_hostname.values())

    def test_getaddrinfo_bypasses_monkey_patched_socket(self, monkeypatch):
        """IP map resolution uses C-level _socket, not monkey-patchable socket.

        gevent/eventlet monkey-patch socket.getaddrinfo to use a real OS thread
        pool for DNS. Under load this causes thread explosion and memory
        exhaustion. tethered must use _socket.getaddrinfo (the C implementation)
        which is immune to monkey-patching.
        """
        # allow_localhost=True is the default, so localhost is already allowed
        tethered.activate(allow=[])

        patched_calls: list[tuple] = []

        def _spy(*args, **_kwargs):
            patched_calls.append(args)
            raise RuntimeError("gevent thread pool exhausted")

        monkeypatch.setattr(socket, "getaddrinfo", _spy)
        _audit_hook("socket.getaddrinfo", ("localhost", 80, 0, 0, 0))

        # socket.getaddrinfo was NOT called by _handle_getaddrinfo
        assert patched_calls == []
        # IP map was populated via C-level _socket.getaddrinfo
        with _ip_map_lock:
            assert any(v == "localhost" for v in _ip_to_hostname.values())

    def test_connect_ex_fires_connect_event(self):
        """connect_ex raises audit event socket.connect in CPython, not socket.connect_ex."""
        tethered.activate(allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.connect", (None, ("192.0.2.1", 80)))

    def test_sendto_blocks(self):
        tethered.activate(allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.sendto", (None, ("192.0.2.1", 80)))

    def test_sendmsg_blocks(self):
        tethered.activate(allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.sendmsg", (None, ("192.0.2.1", 80)))

    def test_reentrancy_guard_getaddrinfo(self):
        tethered.activate(allow=["*.example.com"])
        token = _in_hook.set(True)
        try:
            _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))
        finally:
            _in_hook.reset(token)

    def test_reentrancy_guard_connect(self):
        tethered.activate(allow=["*.example.com"])
        token = _in_hook.set(True)
        try:
            _audit_hook("socket.connect", (None, ("192.0.2.1", 80)))
        finally:
            _in_hook.reset(token)

    def test_fail_open_getaddrinfo_direct(self, monkeypatch):
        tethered.activate(allow=["*.example.com"])
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))

    def test_fail_open_connect_direct(self, monkeypatch):
        tethered.activate(allow=["*.example.com"])
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        _audit_hook("socket.connect", (None, ("192.0.2.1", 80)))

    @requires_network
    def test_getaddrinfo_ip_map_eviction(self):
        tethered.activate(allow=["dns.google"])
        with _ip_map_lock:
            for i in range(_IP_MAP_MAX_SIZE):
                _ip_to_hostname[f"198.51.{i // 256}.{i % 256}"] = f"host{i}.example.com"
        _audit_hook("socket.getaddrinfo", ("dns.google", 443, 0, 0, 0))
        with _ip_map_lock:
            # After eviction + adding dns.google IPs, should be at or below capacity
            assert len(_ip_to_hostname) <= _IP_MAP_MAX_SIZE
            # dns.google entries should be present
            assert any(v == "dns.google" for v in _ip_to_hostname.values())

    def test_getaddrinfo_policy_none_guard(self):
        """Direct call with a dummy config to verify early exits."""
        # These handlers now require a cfg argument; test the audit hook
        # path instead, which handles the None-config guard.
        _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))

    def test_connect_policy_none_guard(self):
        """Direct call with no active policy — audit hook returns early."""
        _audit_hook("socket.connect", (None, ("192.0.2.1", 80)))


class TestDNSLookupInterception:
    """Test interception of gethostbyname/gethostbyaddr audit events."""

    def test_gethostbyname_blocks_disallowed(self):
        tethered.activate(allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.gethostbyname", ("evil.test",))

    def test_gethostbyaddr_blocks_disallowed(self):
        tethered.activate(allow=["198.51.100.0/24"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.gethostbyaddr", ("203.0.113.1",))

    def test_gethostbyaddr_allows_allowed_ip(self):
        tethered.activate(allow=["198.51.100.0/24"])
        _audit_hook("socket.gethostbyaddr", ("198.51.100.1",))

    def test_gethostbyname_allows_allowed(self):
        tethered.activate(allow=["*.example.com"])
        _audit_hook("socket.gethostbyname", ("sub.example.com",))

    def test_gethostbyname_skips_ip(self):
        tethered.activate(allow=["*.example.com"])
        _audit_hook("socket.gethostbyname", ("192.0.2.1",))

    def test_gethostbyname_skips_empty(self):
        tethered.activate(allow=["*.example.com"])
        _audit_hook("socket.gethostbyname", ("",))

    def test_gethostbyname_skips_non_string(self):
        tethered.activate(allow=["*.example.com"])
        _audit_hook("socket.gethostbyname", (None,))

    def test_gethostbyname_log_only(self):
        blocked: list[tuple[str, int | None]] = []
        tethered.activate(
            allow=["*.example.com"],
            log_only=True,
            on_blocked=lambda h, p: blocked.append((h, p)),
        )
        _audit_hook("socket.gethostbyname", ("evil.test",))
        assert blocked == [("evil.test", None)]

    def test_gethostbyname_noop_without_policy(self):
        _audit_hook("socket.gethostbyname", ("evil.test",))

    def test_dns_lookup_policy_none_guard(self):
        """No active policy — audit hook returns early."""
        _audit_hook("socket.gethostbyname", ("evil.test",))

    def test_dns_lookup_on_blocked_callback_raises(self):
        """on_blocked raising in _handle_dns_lookup should be caught (lines 200-201)."""

        def bad_callback(host, port):
            raise ValueError("callback bug")

        tethered.activate(
            allow=["*.example.com"],
            log_only=True,
            on_blocked=bad_callback,
        )
        # Should not propagate the ValueError
        _audit_hook("socket.gethostbyname", ("evil.test",))

    def test_gethostbyname_fail_open(self, monkeypatch):
        tethered.activate(allow=["*.example.com"])
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        _audit_hook("socket.gethostbyname", ("evil.test",))

    def test_gethostbyname_fail_closed(self, monkeypatch):
        tethered.activate(allow=["*.example.com"], fail_closed=True)
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.gethostbyname", ("evil.test",))


class TestIPMapEviction:
    def test_lru_eviction_removes_oldest(self):
        """LRU eviction should remove the least-recently-used entries."""
        tethered.activate(allow=["198.51.100.0/24"])

        with _ip_map_lock:
            _ip_to_hostname.clear()
            # Fill the map with 10 entries
            for i in range(10):
                _ip_to_hostname[f"10.0.0.{i}"] = "old.example.com"

        # Access the first entry to make it "recently used"
        with _ip_map_lock:
            _ip_to_hostname.move_to_end("10.0.0.0")

        # Evict the 5 oldest (LRU) entries
        with _ip_map_lock:
            for _ in range(5):
                _ip_to_hostname.popitem(last=False)

        with _ip_map_lock:
            # "10.0.0.0" was moved to end, so it should survive
            assert "10.0.0.0" in _ip_to_hostname
            # "10.0.0.1" was the oldest after the move, so it should be evicted
            assert "10.0.0.1" not in _ip_to_hostname
            assert len(_ip_to_hostname) == 5

    def test_ip_map_access_moves_to_end(self):
        """Accessing an IP in _handle_connect should mark it as recently used."""
        tethered.activate(allow=["*.stripe.com"])

        with _ip_map_lock:
            _ip_to_hostname.clear()
            _ip_to_hostname["198.51.100.1"] = "api.stripe.com"
            _ip_to_hostname["198.51.100.2"] = "other.stripe.com"

        # Connect to first IP -- should move it to end of LRU
        _audit_hook("socket.connect", (None, ("198.51.100.1", 443)))

        with _ip_map_lock:
            keys = list(_ip_to_hostname.keys())
            # 198.51.100.1 should now be after 198.51.100.2 (moved to end)
            assert keys.index("198.51.100.1") > keys.index("198.51.100.2")


class TestIPv6Integration:
    """Test IPv6 connect path via audit hook direct calls."""

    def test_ipv6_connect_allowed(self):
        tethered.activate(allow=["2001:db8::/32"])
        # AF_INET6 address tuple: (host, port, flowinfo, scope_id)
        _audit_hook("socket.connect", (None, ("2001:db8::1", 443, 0, 0)))

    def test_ipv6_connect_blocked(self):
        tethered.activate(allow=["2001:db8::/32"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.connect", (None, ("2001:db9::1", 443, 0, 0)))

    def test_ipv6_localhost_allowed(self):
        tethered.activate(allow=["*.example.com"])
        _audit_hook("socket.connect", (None, ("::1", 80, 0, 0)))

    def test_ipv4_mapped_ipv6_connect(self):
        tethered.activate(allow=["192.0.2.0/24"])
        _audit_hook("socket.connect", (None, ("::ffff:192.0.2.1", 443, 0, 0)))

    def test_ipv4_mapped_ipv6_blocked(self):
        tethered.activate(allow=["192.0.2.0/24"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.connect", (None, ("::ffff:198.51.100.1", 443, 0, 0)))

    def test_ipv6_sendto_blocked(self):
        tethered.activate(allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.sendto", (None, ("2001:db8::1", 80, 0, 0)))

    def test_ipv6_real_socket_localhost(self):
        """Test IPv6 with a real socket connecting to localhost."""
        # Localhost is allowed by default (allow_localhost=True)
        tethered.activate(allow=[])
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        except OSError:
            pytest.skip("IPv6 not supported on this system")
        try:
            s.settimeout(1)
            try:
                s.connect(("::1", 1, 0, 0))
            except (ConnectionError, TimeoutError, OSError):
                pass  # Connection error is fine, EgressBlocked would be wrong
        finally:
            s.close()


class TestConcurrency:
    """Thread-safety tests for concurrent access."""

    def test_concurrent_policy_enforcement(self):
        """Multiple threads making blocked connections should all see EgressBlocked."""
        tethered.activate(allow=["*.example.com"])
        errors: list[Exception] = []

        def worker():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.connect(("192.0.2.1", 80))
                    errors.append(AssertionError("Should have raised EgressBlocked"))
                except tethered.EgressBlocked:
                    pass  # Expected
                except (ConnectionError, TimeoutError, OSError):
                    errors.append(AssertionError("Got network error instead of EgressBlocked"))
                finally:
                    s.close()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Thread errors: {errors}"

    def test_concurrent_activate_deactivate(self):
        """Rapid activate/deactivate from multiple threads should not crash."""
        errors: list[Exception] = []

        def activator():
            try:
                for _ in range(50):
                    tethered.activate(allow=["*.example.com"])
            except Exception as e:
                errors.append(e)

        def deactivator():
            try:
                for _ in range(50):
                    try:
                        tethered.deactivate()
                    except tethered.TetheredLocked:
                        pass
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=activator),
            threading.Thread(target=deactivator),
            threading.Thread(target=activator),
            threading.Thread(target=deactivator),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Thread errors: {errors}"

    def test_concurrent_ip_map_access(self):
        """Concurrent reads and writes to the IP map should not corrupt it."""
        tethered.activate(allow=["*.stripe.com"])
        errors: list[Exception] = []

        def writer():
            try:
                for i in range(200):
                    with _ip_map_lock:
                        _ip_to_hostname[f"10.0.0.{i % 256}"] = f"host{i}.stripe.com"
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(200):
                    _audit_hook("socket.connect", (None, ("10.0.0.1", 443)))
            except tethered.EgressBlocked:
                pass  # May or may not be blocked depending on timing
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=writer),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Thread errors: {errors}"

    def test_reentrancy_guard_per_thread(self):
        """Each thread should have its own reentrancy guard."""
        tethered.activate(allow=["*.example.com"])
        results: list[bool] = []

        def worker():
            # Each thread should independently enforce the policy
            try:
                _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))
                results.append(False)  # Should have raised
            except tethered.EgressBlocked:
                results.append(True)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert all(results), "All threads should see EgressBlocked"
        assert len(results) == 4


class TestDeactivateReactivate:
    """Adversarial deactivate-then-reconnect scenarios."""

    def test_deactivate_then_connect_is_allowed(self):
        """After deactivate(), previously blocked connections succeed."""
        tethered.activate(allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.connect", (None, ("192.0.2.1", 80)))

        tethered.deactivate()
        # Now the same connection should succeed (no EgressBlocked)
        _audit_hook("socket.connect", (None, ("192.0.2.1", 80)))

    def test_reactivate_after_deactivate(self):
        """activate() -> deactivate() -> activate() should re-enforce."""
        tethered.activate(allow=["*.example.com"])
        tethered.deactivate()
        tethered.activate(allow=["*.stripe.com"])

        # evil.test should now be blocked again
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))

    def test_ip_map_cleared_on_deactivate(self):
        """deactivate() should clear the IP map."""
        tethered.activate(allow=["*.stripe.com"])
        with _ip_map_lock:
            _ip_to_hostname["198.51.100.1"] = "api.stripe.com"

        tethered.deactivate()

        with _ip_map_lock:
            assert len(_ip_to_hostname) == 0

    def test_ip_map_not_carried_across_reactivation(self):
        """IP map from old policy should not affect new policy."""
        tethered.activate(allow=["*.stripe.com"])
        with _ip_map_lock:
            _ip_to_hostname["198.51.100.1"] = "api.stripe.com"

        tethered.deactivate()
        tethered.activate(allow=["*.example.com"])

        # The old IP mapping should be gone
        with _ip_map_lock:
            assert "198.51.100.1" not in _ip_to_hostname

    def test_ip_map_cleared_on_reactivate_without_deactivate(self):
        """activate() -> activate() (no deactivate) must clear the IP map."""
        tethered.activate(allow=["*.stripe.com"])
        with _ip_map_lock:
            _ip_to_hostname["198.51.100.1"] = "api.stripe.com"

        # Re-activate with a different policy — no deactivate() in between
        tethered.activate(allow=["*.example.com"])

        with _ip_map_lock:
            assert "198.51.100.1" not in _ip_to_hostname

        # The stale mapping must not cause a false block on the raw IP
        # when the new policy allows it by CIDR
        tethered.activate(allow=["198.51.100.0/24"])
        _audit_hook("socket.connect", (None, ("198.51.100.1", 443)))


class TestParamNoResiduals:
    """Verify that no params from a prior activate() leak into the next one."""

    def test_log_only_not_inherited(self):
        """activate(log_only=True) -> deactivate -> activate(log_only=False) must raise."""
        tethered.activate(allow=["*.example.com"], log_only=True)
        # log_only: no exception
        _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))

        tethered.deactivate()
        tethered.activate(allow=["*.example.com"], log_only=False)
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))

    def test_log_only_swap_without_deactivate(self):
        """activate(log_only=True) -> activate(log_only=False) must raise."""
        tethered.activate(allow=["*.example.com"], log_only=True)
        _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))

        tethered.activate(allow=["*.example.com"], log_only=False)
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))

    def test_fail_closed_not_inherited(self):
        """activate(fail_closed=True) -> deactivate -> activate() must fail open."""
        tethered.activate(allow=["*.example.com"], fail_closed=True)
        tethered.deactivate()
        tethered.activate(allow=["*.example.com"])
        # Monkey-patch to trigger the error path
        original = AllowPolicy.is_allowed
        AllowPolicy.is_allowed = _raise_runtime
        try:
            # fail_closed=False (default): should NOT raise EgressBlocked
            _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))
        finally:
            AllowPolicy.is_allowed = original

    def test_on_blocked_not_inherited(self):
        """activate(on_blocked=cb1) -> deactivate -> activate(on_blocked=cb2)."""
        calls_1: list[str] = []
        calls_2: list[str] = []

        tethered.activate(
            allow=["*.example.com"],
            on_blocked=lambda h, _: calls_1.append(h),
        )
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))
        assert calls_1 == ["evil.test"]

        tethered.deactivate()
        tethered.activate(
            allow=["*.example.com"],
            on_blocked=lambda h, _: calls_2.append(h),
        )
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))
        # Old callback must not fire, new callback must fire
        assert calls_1 == ["evil.test"]
        assert calls_2 == ["evil.test"]

    def test_on_blocked_none_not_inherited(self):
        """activate(on_blocked=cb) -> deactivate -> activate() — no callback."""
        calls: list[str] = []

        tethered.activate(
            allow=["*.example.com"],
            on_blocked=lambda h, _: calls.append(h),
        )
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))
        assert len(calls) == 1

        tethered.deactivate()
        tethered.activate(allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))
        # Old callback must not have been called again
        assert len(calls) == 1

    def test_allow_localhost_not_inherited(self):
        """activate(allow_localhost=True) -> deactivate -> activate(allow_localhost=False)."""
        tethered.activate(allow=["*.example.com"], allow_localhost=True)
        _audit_hook("socket.connect", (None, ("127.0.0.1", 80)))  # allowed

        tethered.deactivate()
        tethered.activate(allow=["*.example.com"], allow_localhost=False)
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.connect", (None, ("127.0.0.1", 80)))

    def test_locked_not_inherited(self):
        """activate(locked=True) -> activate(locked=False, token) -> deactivate() works."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        with pytest.raises(tethered.TetheredLocked):
            tethered.deactivate()

        tethered.activate(allow=["*.example.com"], lock_token=secret)
        tethered.deactivate()  # should succeed — new policy is not locked

    def test_allow_list_not_inherited(self):
        """activate(allow=[A]) -> deactivate -> activate(allow=[B]) — A must be blocked."""
        tethered.activate(allow=["*.stripe.com"])
        _audit_hook("socket.getaddrinfo", ("api.stripe.com", 443, 0, 0, 0))

        tethered.deactivate()
        tethered.activate(allow=["*.example.com"])
        # stripe.com must now be blocked
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("api.stripe.com", 443, 0, 0, 0))
        # example.com must now be allowed
        _audit_hook("socket.getaddrinfo", ("sub.example.com", 80, 0, 0, 0))


class TestPortBoundaries:
    """Test port edge cases."""

    def test_port_zero_connect(self):
        tethered.activate(allow=["192.0.2.0/24:0"])
        _audit_hook("socket.connect", (None, ("192.0.2.1", 0)))

    def test_port_65535_connect(self):
        tethered.activate(allow=["192.0.2.0/24:65535"])
        _audit_hook("socket.connect", (None, ("192.0.2.1", 65535)))

    def test_port_mismatch_blocked(self):
        tethered.activate(allow=["192.0.2.0/24:443"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.connect", (None, ("192.0.2.1", 80)))


class TestPortValidation:
    """Test port range validation in AllowPolicy."""

    def test_invalid_port_too_high(self):
        with pytest.raises(ValueError, match="out of valid range"):
            AllowPolicy(["host:99999"])

    def test_invalid_port_too_high_cidr(self):
        with pytest.raises(ValueError, match="out of valid range"):
            AllowPolicy(["192.0.2.0/24:70000"])

    def test_valid_port_zero(self):
        policy = AllowPolicy(["host:0"])
        assert policy.is_allowed("host", 0) is True

    def test_valid_port_65535(self):
        policy = AllowPolicy(["host:65535"])
        assert policy.is_allowed("host", 65535) is True


# ── Tests requiring network access ──────────────────────────────────
# These validate the full hostname -> DNS resolution -> IP mapping -> connect
# flow using a real external hostname. Skipped in air-gapped/CI environments.


@requires_network
class TestHostnameResolutionFlow:
    def test_allows_allowed_hostname(self):
        tethered.activate(allow=["dns.google"])
        socket.getaddrinfo("dns.google", 443)

    def test_allows_wildcard_hostname(self):
        tethered.activate(allow=["*.google"])
        socket.getaddrinfo("dns.google", 443)

    def test_trailing_dot_hostname(self):
        tethered.activate(allow=["dns.google"])
        socket.getaddrinfo("dns.google.", 443)

    @pytest.mark.asyncio
    async def test_allows_async_allowed_host(self):
        tethered.activate(allow=["dns.google"])
        loop = asyncio.get_event_loop()
        await loop.getaddrinfo("dns.google", 443)


class TestProcessIsolation:
    """Verify that tethered's audit hook does not leak to child processes."""

    def test_subprocess_no_tethered_state(self):
        """Child process has no tethered config — _config is None."""
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=object())

        result = subprocess.run(  # nosec B603 B607
            [
                sys.executable,
                "-c",
                (
                    "import tethered._core as c; "
                    "assert c._config is None, 'child should have no tethered config'"
                ),
            ],
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr.decode()


class TestConftestEgressGuard:
    """Verify that the conftest egress guard blocks unexpected network access."""

    def test_dns_blocked_when_tethered_inactive(self):
        """Guard blocks DNS for non-allowed hosts when tethered is deactivated."""
        # _cleanup fixture has called _reset_state(), so _config is None
        with pytest.raises(tethered.EgressBlocked, match=r"evil\.test"):
            socket.getaddrinfo("evil.test", 80)

    @requires_network
    def test_dns_allowed_for_guard_allowlist(self):
        """Guard allows DNS for hosts in conftest allow list."""
        socket.getaddrinfo("dns.google", 80)

    def test_localhost_allowed_when_tethered_inactive(self):
        """Guard allows localhost connections when tethered is deactivated."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        try:
            sock.connect(("127.0.0.1", 1))
        except OSError:
            pass  # Connection refused is fine — not EgressBlocked
        finally:
            sock.close()


# ── scope() tests ─────────────────────────────────────────────────


class TestScope:
    """Basic scope() context manager tests."""

    def test_scope_blocks_disallowed_getaddrinfo(self):
        """scope() blocks DNS resolution for hosts not in scope allow list."""
        with tethered.scope(allow=["*.example.com"]), pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

    @requires_network
    def test_scope_allows_allowed_host(self):
        """scope() permits DNS resolution for hosts in scope allow list."""
        with tethered.scope(allow=["dns.google"]):
            socket.getaddrinfo("dns.google", 443)

    def test_scope_allows_localhost_by_default(self):
        """scope() allows localhost connections by default."""
        with tethered.scope(allow=[]):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                sock.connect(("127.0.0.1", 1))
            except OSError:
                pass  # Connection refused is fine — not EgressBlocked
            finally:
                sock.close()

    def test_scope_blocks_localhost_when_disabled(self):
        """scope(allow_localhost=False) blocks localhost."""
        with (
            tethered.scope(allow=[], allow_localhost=False),
            pytest.raises(tethered.EgressBlocked),
        ):
            socket.getaddrinfo("localhost", 80)

    def test_scope_exit_restores_policy(self):
        """After exiting a scope, previously blocked hosts are accessible."""
        with tethered.scope(allow=["*.example.com"]), pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

        # Outside scope: no enforcement (no activate() either)
        # conftest guard allows dns.google
        socket.getaddrinfo("dns.google", 443)

    def test_scope_without_activate(self):
        """scope() works independently when activate() was never called."""
        with tethered.scope(allow=["*.example.com"]), pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)

    def test_scope_reentrant_guard(self):
        """Same scope instance cannot be entered twice."""
        s = tethered.scope(allow=["*.example.com"])
        with s, pytest.raises(RuntimeError, match="already entered"), s:
            pass  # pragma: no cover

    def test_scope_connect_enforcement(self):
        """scope() blocks socket.connect to disallowed destinations."""
        with tethered.scope(allow=["*.example.com"]):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                with pytest.raises(tethered.EgressBlocked):
                    sock.connect(("198.51.100.1", 80))
            finally:
                sock.close()

    def test_scope_dns_lookup_enforcement(self):
        """scope() blocks gethostbyname for disallowed hosts."""
        with tethered.scope(allow=["*.example.com"]), pytest.raises(tethered.EgressBlocked):
            socket.gethostbyname("evil.test")


class TestScopeIntersection:
    """Test intersection semantics between activate() and scope()."""

    def test_scope_intersects_with_global(self):
        """Connection must be allowed by both global and scope."""
        tethered.activate(allow=["*.stripe.com", "*.example.com"])

        with (
            tethered.scope(allow=["*.stripe.com"]),
            pytest.raises(tethered.EgressBlocked),
        ):
            # example.com is in global but NOT in scope → blocked
            socket.getaddrinfo("api.example.com", 80)

    def test_scope_cannot_widen_global(self):
        """scope() cannot allow hosts that global policy blocks."""
        tethered.activate(allow=["*.stripe.com"])

        with (
            tethered.scope(allow=["*.stripe.com", "*.evil.test"]),
            pytest.raises(tethered.EgressBlocked),
        ):
            # evil.test is in scope but NOT in global → blocked by global
            socket.getaddrinfo("evil.test", 80)

    @requires_network
    def test_intersection_allows_common_hosts(self):
        """Hosts in both global and scope are allowed."""
        tethered.activate(allow=["dns.google", "*.example.com"])

        with tethered.scope(allow=["dns.google"]):
            socket.getaddrinfo("dns.google", 443)

    def test_scope_connect_intersection(self):
        """Connect-level enforcement respects intersection."""
        tethered.activate(allow=["*.stripe.com", "*.example.com"])

        with tethered.scope(allow=["*.stripe.com"]):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                with pytest.raises(tethered.EgressBlocked):
                    sock.connect(("198.51.100.1", 80))
            finally:
                sock.close()


class TestScopeNesting:
    """Test nested scope behavior."""

    def test_nested_scopes_intersection(self):
        """Nested scopes produce intersection of all policies."""
        with (
            tethered.scope(allow=["*.stripe.com", "*.example.com"]),
            tethered.scope(allow=["*.stripe.com"]),
            # example.com is in outer scope but not inner → blocked
            pytest.raises(tethered.EgressBlocked),
        ):
            socket.getaddrinfo("api.example.com", 80)

    def test_inner_scope_exit_restores_outer(self):
        """Exiting inner scope restores outer scope's policy."""
        with tethered.scope(allow=["*.stripe.com", "*.example.com"]):
            with (
                tethered.scope(allow=["*.stripe.com"]),
                pytest.raises(tethered.EgressBlocked),
            ):
                socket.getaddrinfo("api.example.com", 80)

            # After inner scope exits, example.com should be allowed again
            # (only outer scope active, which allows it).
            scope_stack = _scopes.get()
            assert len(scope_stack) == 1
            assert scope_stack[0].policy.is_allowed("api.example.com") is True

    def test_triple_nesting(self):
        """Three levels of nesting produce intersection of all three."""
        with (
            tethered.scope(allow=["a.com", "b.com", "c.com"]),
            tethered.scope(allow=["a.com", "b.com"]),
            tethered.scope(allow=["a.com"]),
        ):
            with pytest.raises(tethered.EgressBlocked):
                socket.getaddrinfo("b.com", 80)
            with pytest.raises(tethered.EgressBlocked):
                socket.getaddrinfo("c.com", 80)


class TestScopeDecorator:
    """Test scope() as a function/method decorator."""

    def test_sync_decorator(self):
        """@scope() works on sync functions."""

        @tethered.scope(allow=["*.example.com"])
        def guarded():
            socket.getaddrinfo("evil.test", 80)

        with pytest.raises(tethered.EgressBlocked):
            guarded()

    def test_async_decorator(self):
        """@scope() works on async functions."""

        @tethered.scope(allow=["*.example.com"])
        async def guarded():
            await asyncio.get_event_loop().getaddrinfo("evil.test", 80)

        with pytest.raises(tethered.EgressBlocked):
            asyncio.get_event_loop().run_until_complete(guarded())

    def test_decorator_preserves_name(self):
        """@scope() preserves __name__ via functools.wraps."""

        @tethered.scope(allow=["*.example.com"])
        def my_function():
            pass  # pragma: no cover

        assert my_function.__name__ == "my_function"

    def test_async_decorator_preserves_name(self):
        """@scope() preserves __name__ on async functions."""

        @tethered.scope(allow=["*.example.com"])
        async def my_async_function():
            pass  # pragma: no cover

        assert my_async_function.__name__ == "my_async_function"

    def test_decorator_rejects_generator(self):
        """@scope() raises TypeError on generator functions."""
        with pytest.raises(TypeError, match="generator"):

            @tethered.scope(allow=["*.example.com"])
            def gen():
                yield 1

    def test_decorator_rejects_async_generator(self):
        """@scope() raises TypeError on async generator functions."""
        with pytest.raises(TypeError, match="generator"):

            @tethered.scope(allow=["*.example.com"])
            async def gen():
                yield 1

    def test_decorator_propagates_exception(self):
        """Exceptions from the decorated function propagate normally."""

        @tethered.scope(allow=["*.example.com"])
        def guarded():
            msg = "test error"
            raise ValueError(msg)

        with pytest.raises(ValueError, match="test error"):
            guarded()

    def test_decorator_returns_value(self):
        """Decorated function's return value is preserved."""

        @tethered.scope(allow=["*.example.com"])
        def guarded():
            return 42

        assert guarded() == 42

    def test_async_decorator_returns_value(self):
        """Async decorated function's return value is preserved."""

        @tethered.scope(allow=["*.example.com"])
        async def guarded():
            return 42

        result = asyncio.get_event_loop().run_until_complete(guarded())
        assert result == 42

    def test_decorator_scope_exits_after_call(self):
        """Scope is no longer active after decorated function returns."""

        @tethered.scope(allow=["*.example.com"])
        def guarded():
            assert len(_scopes.get()) == 1

        guarded()
        assert len(_scopes.get()) == 0


class TestScopeAsync:
    """Test scope() with async contexts."""

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        """scope() as context manager inside an async function."""
        with tethered.scope(allow=["*.example.com"]), pytest.raises(tethered.EgressBlocked):
            await asyncio.get_event_loop().getaddrinfo("evil.test", 80)

    @pytest.mark.asyncio
    async def test_async_context_isolation(self):
        """Two concurrent async tasks with different scopes enforce independently."""
        results: dict[str, bool] = {}

        async def task_a():
            with tethered.scope(allow=["a.example.com"]):
                try:
                    socket.getaddrinfo("b.example.com", 80)
                    results["a_blocked_b"] = False
                except tethered.EgressBlocked:
                    results["a_blocked_b"] = True

        async def task_b():
            with tethered.scope(allow=["b.example.com"]):
                try:
                    socket.getaddrinfo("a.example.com", 80)
                    results["b_blocked_a"] = False
                except tethered.EgressBlocked:
                    results["b_blocked_a"] = True

        await asyncio.gather(task_a(), task_b())
        assert results["a_blocked_b"] is True
        assert results["b_blocked_a"] is True


class TestScopeThreading:
    """Test scope() thread isolation."""

    def test_scope_thread_isolation(self):
        """Scope in one thread does not affect another thread."""
        results: dict[str, bool] = {}
        barrier = threading.Barrier(2, timeout=5)

        def thread_with_scope():
            with tethered.scope(allow=["*.example.com"]):
                barrier.wait()
                try:
                    socket.getaddrinfo("evil.test", 80)
                    results["scoped_blocked"] = False
                except tethered.EgressBlocked:
                    results["scoped_blocked"] = True

        def thread_without_scope():
            barrier.wait()
            # This thread has no scope — only conftest guard applies.
            # dns.google is in the conftest guard allow list.
            try:
                socket.getaddrinfo("dns.google", 443)
                results["unscoped_allowed"] = True
            except tethered.EgressBlocked:
                results["unscoped_allowed"] = False

        t1 = threading.Thread(target=thread_with_scope)
        t2 = threading.Thread(target=thread_without_scope)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        assert results["scoped_blocked"] is True
        assert results["unscoped_allowed"] is True


class TestScopeLogOnly:
    """Test scope() log_only mode and on_blocked callback."""

    def test_log_only_does_not_raise(self):
        """scope(log_only=True) logs but does not raise."""
        with tethered.scope(allow=["*.example.com"], log_only=True):
            # Should not raise — just logs. Uses dns.google (resolvable, not in scope)
            socket.getaddrinfo("dns.google", 80)

    def test_on_blocked_callback(self):
        """scope on_blocked callback is invoked on blocked connections."""
        blocked: list[tuple[str, int | None]] = []

        def on_blocked(host: str, port: int | None) -> None:
            blocked.append((host, port))

        with (
            tethered.scope(allow=["*.example.com"], on_blocked=on_blocked),
            pytest.raises(tethered.EgressBlocked),
        ):
            socket.getaddrinfo("evil.test", 80)

        assert ("evil.test", None) in blocked

    def test_log_only_with_callback(self):
        """log_only + on_blocked: callback fires, no exception raised."""
        blocked: list[tuple[str, int | None]] = []

        def on_blocked(host: str, port: int | None) -> None:
            blocked.append((host, port))

        with tethered.scope(allow=["*.example.com"], log_only=True, on_blocked=on_blocked):
            socket.getaddrinfo("dns.google", 80)

        assert ("dns.google", None) in blocked

    @requires_network
    def test_log_only_scope_populates_ip_map(self):
        """log_only scope must populate IP map so connect-time enforcement works."""
        tethered.activate(allow=["dns.google"])

        blocked: list[tuple[str, int | None]] = []
        with tethered.scope(
            allow=["*.example.com"],
            log_only=True,
            on_blocked=lambda h, p: blocked.append((h, p)),
        ):
            addrs = socket.getaddrinfo("dns.google", 443, socket.AF_INET, socket.SOCK_STREAM)
            ip = addrs[0][4][0]

            # IP map must be populated so connect can map IP -> hostname
            with _ip_map_lock:
                assert ip in _ip_to_hostname, "IP map not populated after log_only scope"

            # Connect must succeed — scope is log_only, global allows dns.google
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            try:
                s.connect((ip, 443))
            except tethered.EgressBlocked:
                pytest.fail("log_only scope caused global policy to hard-block connect")
            except (ConnectionError, TimeoutError, OSError):
                pass  # Network-level failure is fine, EgressBlocked would be wrong
            finally:
                s.close()

        # Scope should have logged both intercept points
        assert any(h == "dns.google" for h, _ in blocked)


class TestScopeFailClosed:
    """Test scope() fail_closed behavior."""

    def test_scope_fail_closed(self, monkeypatch):
        """scope(fail_closed=True) blocks on policy errors."""
        tethered.activate(allow=["*.example.com"])
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)

        with tethered.scope(allow=["*.example.com"], fail_closed=True):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            try:
                with pytest.raises(tethered.EgressBlocked):
                    s.connect(("192.0.2.1", 80))
            finally:
                s.close()

    def test_scope_fail_open(self, monkeypatch):
        """scope(fail_closed=False) allows on policy errors (default)."""
        tethered.activate(allow=["*.example.com"])
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)

        with tethered.scope(allow=["*.example.com"], fail_closed=False):
            # Should not raise EgressBlocked — fails open
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            try:
                s.connect(("192.0.2.1", 80))
            except (ConnectionError, TimeoutError, OSError):
                pass  # Network failure OK; EgressBlocked would be wrong
            finally:
                s.close()


class TestScopeLogging:
    """Test scope() logging behavior."""

    def test_scope_enter_exit_logged(self, caplog):
        """DEBUG messages logged on scope enter/exit."""
        with (
            caplog.at_level(logging.DEBUG, logger="tethered"),
            tethered.scope(allow=["*.example.com"]),
        ):
            pass

        assert "entered scope(*.example.com)" in caplog.text
        assert "exited scope(*.example.com)" in caplog.text

    def test_scope_blocked_identifies_scope(self, caplog):
        """WARNING log identifies which scope blocked the connection."""
        with (
            caplog.at_level(logging.WARNING, logger="tethered"),
            tethered.scope(allow=["*.example.com"]),
            pytest.raises(tethered.EgressBlocked),
        ):
            socket.getaddrinfo("evil.test", 80)

        assert "scope(*.example.com)" in caplog.text
        assert "blocked" in caplog.text

    def test_scope_blocked_notes_global_allowed(self, caplog):
        """When scope blocks but global allows, log notes it."""
        tethered.activate(allow=["*.stripe.com", "*.example.com"])

        with (
            caplog.at_level(logging.WARNING, logger="tethered"),
            tethered.scope(allow=["*.stripe.com"]),
            pytest.raises(tethered.EgressBlocked),
        ):
            socket.getaddrinfo("api.example.com", 80)

        assert "allowed by global policy" in caplog.text

    def test_dead_rules_warning(self, caplog):
        """Warning logged when scope rules don't overlap with global policy."""
        tethered.activate(allow=["*.stripe.com"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["api.sendgrid.com:443"])

        assert "no overlap with global policy" in caplog.text
        assert "api.sendgrid.com:443" in caplog.text

    def test_exact_host_no_port_vs_global_port_warns_broader(self, caplog):
        """Scope 10.0.0.1 (any port) vs global 10.0.0.1:5432 warns broader."""
        tethered.activate(allow=["10.0.0.1:5432"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["10.0.0.1"])

        assert "broader than the global policy" in caplog.text

    def test_exact_host_matching_port_no_warning(self, caplog):
        """Scope 10.0.0.1:5432 vs global 10.0.0.1:5432 — no warning."""
        tethered.activate(allow=["10.0.0.1:5432"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["10.0.0.1:5432"])

        assert "no overlap" not in caplog.text
        assert "broader" not in caplog.text

    def test_exact_host_any_port_global_no_warning(self, caplog):
        """Scope 10.0.0.1 (any port) vs global 10.0.0.1 (any port) — no warning."""
        tethered.activate(allow=["10.0.0.1"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["10.0.0.1"])

        assert "no overlap" not in caplog.text
        assert "broader" not in caplog.text

    def test_port_zero_scope_no_port_vs_global_port_zero(self, caplog):
        """Scope no port vs global :0 — broader (scope allows all ports, global only 0)."""
        tethered.activate(allow=["10.0.0.1:0"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["10.0.0.1"])

        assert "broader than the global policy" in caplog.text

    def test_port_zero_scope_zero_vs_global_zero(self, caplog):
        """Scope :0 vs global :0 — identical, no warning."""
        tethered.activate(allow=["10.0.0.1:0"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["10.0.0.1:0"])

        assert "no overlap" not in caplog.text
        assert "broader" not in caplog.text

    def test_port_zero_scope_zero_vs_global_other(self, caplog):
        """Scope :0 vs global :5432 — disjoint ports, no overlap."""
        tethered.activate(allow=["10.0.0.1:5432"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["10.0.0.1:0"])

        assert "no overlap with global policy" in caplog.text

    def test_exact_host_no_port_dead_rule(self, caplog):
        """Scope unknown.host (no port) vs global with no match — dead rule."""
        tethered.activate(allow=["api.stripe.com:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["unknown.host"])

        assert "no overlap with global policy" in caplog.text

    def test_exact_host_no_port_vs_global_wildcard_any_port(self, caplog):
        """Scope api.stripe.com (no port) vs global *.stripe.com (any port) — no warning."""
        tethered.activate(allow=["*.stripe.com"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["api.stripe.com"])

        assert "no overlap" not in caplog.text
        assert "broader" not in caplog.text

    def test_ip_like_hostname_no_crash(self, caplog):
        """IP-like hostname (e.g. 1.2.3.4.5) doesn't crash _has_any_port_rule."""
        tethered.activate(allow=["10.0.0.0/8"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["1.2.3.4.5"])

        assert "no overlap with global policy" in caplog.text

    def test_exact_ip_no_port_vs_global_cidr_any_port(self, caplog):
        """Scope 10.0.0.1 (no port) vs global 10.0.0.0/8 (any port) — no warning."""
        tethered.activate(allow=["10.0.0.0/8"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["10.0.0.1"])

        assert "no overlap" not in caplog.text
        assert "broader" not in caplog.text

    def test_dead_wildcard_warning(self, caplog):
        """Warning logged when a scope wildcard has zero overlap with global."""
        tethered.activate(allow=["api.stripe.com:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["*.example.test"])

        assert "no overlap with global policy" in caplog.text
        assert "*.example.test" in caplog.text

    def test_broad_wildcard_warning(self, caplog):
        """Warning logged when a scope wildcard is broader than global policy."""
        tethered.activate(allow=["api.stripe.com:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["*.stripe.com"])

        assert "broader than the global policy" in caplog.text
        assert "*.stripe.com" in caplog.text

    def test_matching_wildcard_no_warning(self, caplog):
        """No warning when scope wildcard matches identical global wildcard."""
        tethered.activate(allow=["*.stripe.com:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["*.stripe.com:443"])

        assert "no overlap" not in caplog.text
        assert "broader" not in caplog.text

    def test_dead_cidr_warning(self, caplog):
        """Warning logged when a scope CIDR has zero overlap with global."""
        tethered.activate(allow=["api.stripe.com:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["192.168.0.0/16"])

        assert "no overlap with global policy" in caplog.text
        assert "192.168.0.0/16" in caplog.text

    def test_broad_cidr_warning(self, caplog):
        """Warning logged when a scope CIDR is broader than global."""
        tethered.activate(allow=["10.0.1.0/24:5432"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["10.0.0.0/8:5432"])

        assert "broader than the global policy" in caplog.text
        assert "10.0.0.0/8:5432" in caplog.text

    def test_matching_cidr_no_warning(self, caplog):
        """No warning when scope CIDR is same or narrower than global."""
        tethered.activate(allow=["10.0.0.0/8:5432"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["10.0.1.0/24:5432"])

        assert "no overlap" not in caplog.text
        assert "broader" not in caplog.text

    def test_empty_rule_in_scope_raises(self):
        """Empty rules in scope allow list raise ValueError."""
        tethered.activate(allow=["api.stripe.com:443"])

        with pytest.raises(ValueError, match="empty or whitespace"):
            tethered.scope(allow=["", "api.stripe.com:443"])

    def test_ipv6_bracketed_scope_rule(self, caplog):
        """Bracketed IPv6 scope rules are parsed for overlap checking."""
        tethered.activate(allow=["[2001:db8::]/32:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["[2001:db8::1]:443"])

        assert "no overlap" not in caplog.text

    def test_wildcard_wildcard_suffix_overlap(self, caplog):
        """Scope wildcard overlaps with global wildcard via common suffix."""
        tethered.activate(allow=["*.api.stripe.com:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["*.stripe.com"])

        assert "broader than the global policy" in caplog.text

    def test_wildcard_wildcard_suffix_overlap_port_match(self, caplog):
        """Scope wildcard with same port but broader pattern warns broader."""
        tethered.activate(allow=["*.api.stripe.com:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["*.stripe.com:443"])

        # *.stripe.com covers more than *.api.stripe.com — broader
        assert "broader than the global policy" in caplog.text

    def test_cidr_port_mismatch_warns_no_overlap(self, caplog):
        """Same CIDR, different specific ports — no overlap (disjoint ports)."""
        tethered.activate(allow=["10.0.0.0/8:5432"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["10.0.0.0/8:3306"])

        assert "no overlap with global policy" in caplog.text

    def test_cidr_cross_family_no_crash(self, caplog):
        """IPv4 scope CIDR vs IPv6 global CIDR doesn't crash."""
        tethered.activate(allow=["[2001:db8::]/32"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["10.0.0.0/8"])

        assert "no overlap with global policy" in caplog.text

    def test_wildcard_port_mismatch_is_partial(self, caplog):
        """Scope *.stripe.com (any port) vs global *.stripe.com:443 warns broader."""
        tethered.activate(allow=["*.stripe.com:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["*.stripe.com"])

        assert "broader than the global policy" in caplog.text

    def test_wildcard_different_port_is_none(self, caplog):
        """Scope *.stripe.com:3306 vs global api.stripe.com:443 warns no overlap."""
        tethered.activate(allow=["api.stripe.com:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["*.stripe.com:3306"])

        assert "no overlap with global policy" in caplog.text

    def test_cidr_no_port_vs_global_with_port_is_partial(self, caplog):
        """Scope 10.0.0.0/8 (any port) vs global 10.0.0.0/8:5432 warns broader."""
        tethered.activate(allow=["10.0.0.0/8:5432"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["10.0.0.0/8"])

        assert "broader than the global policy" in caplog.text

    def test_ipv6_cidr_bracket_overlap(self, caplog):
        """Bracketed IPv6 CIDR scope overlaps with global IPv6 CIDR."""
        tethered.activate(allow=["[2001:db8:1::]/48"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["[2001:db8::]/32"])

        assert "broader than the global policy" in caplog.text

    def test_ipv6_cidr_bracket_with_port(self, caplog):
        """Bracketed IPv6 CIDR with port parses correctly for overlap check."""
        tethered.activate(allow=["[2001:db8::]/32:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["[2001:db8::]/32:443"])

        assert "no overlap" not in caplog.text
        assert "broader" not in caplog.text

    def test_wildcard_scope_no_port_matches_exact_any_port(self, caplog):
        """Scope *.stripe.com (no port) vs global api.stripe.com (no port) — broader."""
        tethered.activate(allow=["api.stripe.com"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["*.stripe.com"])

        # Wildcard covers more hosts than the single exact hostname — broader
        assert "broader than the global policy" in caplog.text

    def test_wildcard_scope_no_port_matches_exact_with_port_only(self, caplog):
        """Scope *.stripe.com (no port) vs global api.stripe.com:443 — partial (broader on port)."""
        tethered.activate(allow=["api.stripe.com:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["*.stripe.com"])

        assert "broader than the global policy" in caplog.text

    def test_wildcard_scope_with_port_vs_exact_port(self, caplog):
        """Scope wildcard:443 vs global exact:443 — broader (covers more hosts)."""
        tethered.activate(allow=["api.stripe.com:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["*.stripe.com:443"])

        assert "broader than the global policy" in caplog.text

    def test_wildcard_scope_with_port_vs_exact_any_port(self, caplog):
        """Scope *.stripe.com:443 vs global api.stripe.com (any port) — broader."""
        tethered.activate(allow=["api.stripe.com"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["*.stripe.com:443"])

        assert "broader than the global policy" in caplog.text

    def test_cidr_multi_rule_second_matches(self, caplog):
        """Second global CIDR rule matches even though first has disjoint port."""
        tethered.activate(allow=["10.0.0.0/8:5432", "10.0.0.0/8:3306"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["10.0.0.0/8:3306"])

        assert "no overlap" not in caplog.text

    def test_wildcard_multi_rule_second_matches(self, caplog):
        """Second global wildcard matches even though first has disjoint port."""
        tethered.activate(allow=["*.api.stripe.com:443", "*.api.stripe.com:3306"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["*.stripe.com:3306"])

        assert "no overlap" not in caplog.text
        assert "broader than the global policy" in caplog.text

    def test_invalid_cidr_in_scope_skipped(self, caplog):
        """Invalid CIDR-like rule in scope is skipped without error."""
        tethered.activate(allow=["api.stripe.com:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["not-a-cidr/99"])

        # Should not crash; the invalid rule is treated as unparseable

    def test_decorator_enter_exit_logged(self, caplog):
        """DEBUG messages logged on decorator enter/exit."""

        @tethered.scope(allow=["*.example.com"])
        def guarded():
            pass

        with caplog.at_level(logging.DEBUG, logger="tethered"):
            guarded()

        assert "entered scope(*.example.com)" in caplog.text
        assert "exited scope(*.example.com)" in caplog.text


class TestScopeRestrictionOnly:
    """Verify scopes can only restrict, never widen."""

    def test_scope_broader_than_global_still_restricted(self):
        """A broad scope cannot widen the global policy."""
        tethered.activate(allow=["*.stripe.com"])

        with (
            tethered.scope(allow=["*.test"]),
            # evil.test passes the scope but fails the global
            pytest.raises(tethered.EgressBlocked),
        ):
            socket.getaddrinfo("evil.test", 80)

    def test_empty_global_blocks_everything_in_scope(self):
        """activate(allow=[]) blocks even if scope allows broadly."""
        tethered.activate(allow=[], allow_localhost=False)

        with tethered.scope(allow=["*.test"]), pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.test", 80)


class TestScopeDirect:
    """Direct-call tests for scope internals (coverage for audit-hook paths)."""

    def test_check_scopes_blocks(self):
        """_check_scopes returns blocking scope when host not allowed."""
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(policy=policy, label="test-scope")
        result = _check_scopes((sc,), "evil.test", 80, _normalized=True)
        assert result is sc

    def test_check_scopes_allows(self):
        """_check_scopes returns None when host is allowed."""
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(policy=policy, label="test-scope")
        result = _check_scopes((sc,), "api.example.com", 80, _normalized=True)
        assert result is None

    def test_check_scopes_fail_closed(self, monkeypatch):
        """_check_scopes returns scope on error when fail_closed=True."""
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(policy=policy, fail_closed=True, label="test-scope")
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        result = _check_scopes((sc,), "test.example.com", 80, _normalized=True)
        assert result is sc

    def test_check_scopes_fail_open(self, monkeypatch):
        """_check_scopes returns None on error when fail_closed=False."""
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(policy=policy, fail_closed=False, label="test-scope")
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        result = _check_scopes((sc,), "test.example.com", 80, _normalized=True)
        assert result is None

    def test_enforce_scope_block_raises(self):
        """_enforce_scope_block raises EgressBlocked when log_only=False."""
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(policy=policy, label="test-scope")
        with pytest.raises(tethered.EgressBlocked):
            _enforce_scope_block(sc, "evil.test", 80, "connect to evil.test:80")

    def test_enforce_scope_block_log_only(self):
        """_enforce_scope_block does not raise when log_only=True."""
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(policy=policy, log_only=True, label="test-scope")
        _enforce_scope_block(sc, "evil.test", 80, "connect to evil.test:80")

    def test_enforce_scope_block_on_blocked_callback(self):
        """_enforce_scope_block calls on_blocked callback."""
        blocked: list[tuple[str, int | None]] = []
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(
            policy=policy,
            log_only=True,
            on_blocked=lambda h, p: blocked.append((h, p)),
            label="test-scope",
        )
        _enforce_scope_block(sc, "evil.test", 80, "connect")
        assert blocked == [("evil.test", 80)]

    def test_enforce_scope_block_callback_exception(self):
        """_enforce_scope_block handles on_blocked callback exceptions."""
        policy = AllowPolicy(["*.example.com"])

        def bad_callback(h, p):
            msg = "callback error"
            raise ValueError(msg)

        sc = _ScopeConfig(
            policy=policy,
            log_only=True,
            on_blocked=bad_callback,
            label="test-scope",
        )
        # Should not raise — callback exception is swallowed
        _enforce_scope_block(sc, "evil.test", 80, "connect")

    def test_enforce_scope_block_global_allowed_log(self, caplog):
        """_enforce_scope_block includes 'allowed by global policy' in log."""
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(policy=policy, log_only=True, label="test-scope")
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _enforce_scope_block(
                sc,
                "evil.test",
                80,
                "connect",
                global_allowed=True,
            )
        assert "allowed by global policy" in caplog.text

    def test_handle_getaddrinfo_scope_blocks(self):
        """_handle_getaddrinfo with scope blocks disallowed hosts."""
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(policy=policy, label="test-scope")
        with pytest.raises(tethered.EgressBlocked):
            _handle_getaddrinfo(None, (sc,), ("evil.test", 80, 0, 0, 0, 0))

    def test_handle_getaddrinfo_scope_log_only(self):
        """_handle_getaddrinfo scope with log_only does not raise."""
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(policy=policy, log_only=True, label="test-scope")
        # Should not raise — log_only scope
        _handle_getaddrinfo(None, (sc,), ("evil.test", 80, 0, 0, 0, 0))

    def test_handle_dns_lookup_scope_blocks(self):
        """_handle_dns_lookup with scope blocks disallowed hosts."""
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(policy=policy, label="test-scope")
        with pytest.raises(tethered.EgressBlocked):
            _handle_dns_lookup(None, (sc,), "socket.gethostbyname", ("evil.test",))

    def test_handle_connect_scope_blocks(self):
        """_handle_connect with scope blocks disallowed connections."""
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(policy=policy, label="test-scope")
        with pytest.raises(tethered.EgressBlocked):
            _handle_connect(None, (sc,), "socket.connect", (None, ("192.0.2.1", 80)))

    def test_handle_connect_scope_callback_receives_hostname(self):
        """Scope on_blocked callback receives resolved hostname, not raw IP."""
        blocked: list[tuple[str, int | None]] = []
        policy = AllowPolicy(["*.stripe.com"])
        sc = _ScopeConfig(
            policy=policy,
            log_only=True,
            on_blocked=lambda h, p: blocked.append((h, p)),
            label="test-scope",
        )
        # Prime IP map with a hostname mapping
        with _ip_map_lock:
            _ip_to_hostname["198.51.100.1"] = "evil.example.com"
        _handle_connect(None, (sc,), "socket.connect", (None, ("198.51.100.1", 443)))
        # Callback should receive the resolved hostname, not the raw IP
        assert blocked == [("evil.example.com", 443)]

    def test_handle_connect_scope_ip_fallback_allows(self):
        """Scope blocks hostname but CIDR rule on raw IP allows the connection."""
        # Scope allows a CIDR range but not the hostname
        policy = AllowPolicy(["10.0.0.0/8"])
        sc = _ScopeConfig(policy=policy, label="cidr-scope")

        # Prime IP map: 10.0.0.1 -> "db.internal"
        with _ip_map_lock:
            _ip_to_hostname["10.0.0.1"] = "db.internal"

        # "db.internal" is not in the scope, but 10.0.0.1 matches 10.0.0.0/8
        # Should be allowed (IP fallback), not blocked
        _handle_connect(None, (sc,), "socket.connect", (None, ("10.0.0.1", 5432)))
