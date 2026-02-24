"""Integration tests for tethered activate/deactivate with real sockets."""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import threading

import pytest

import tethered
from tethered._core import (
    _IP_MAP_MAX_SIZE,
    _audit_hook,
    _extract_host_port,
    _in_hook,
    _ip_map_lock,
    _ip_to_hostname,
    _is_ip,
    _reset_state,
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


class TestActivateDeactivate:
    def test_blocks_disallowed_getaddrinfo(self):
        tethered.activate(allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.com", 80)

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
            socket.getaddrinfo("evil.com", 443)

    def test_allows_dns_for_localhost(self):
        # Localhost is allowed by default (allow_localhost=True)
        tethered.activate(allow=[])
        socket.getaddrinfo("localhost", 80)


class TestPolicySwap:
    def test_reactivate_with_different_rules(self):
        tethered.activate(allow=["*.stripe.com"])
        with pytest.raises(tethered.EgressBlocked):
            socket.getaddrinfo("evil.com", 80)

        tethered.activate(allow=["evil.com"])
        # evil.com now allowed -- but this triggers real DNS, so use localhost
        # to test the policy swap without network
        tethered.activate(allow=["localhost"])
        socket.getaddrinfo("localhost", 80)

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

        socket.getaddrinfo("evil.com", 80)
        assert len(blocked) > 0
        assert blocked[0][0] == "evil.com"


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
            socket.getaddrinfo("evil.com", 80)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(tethered.EgressBlocked):
                s.connect(("203.0.113.1", 9999))
        finally:
            s.close()

        assert len(blocked) == 2
        # getaddrinfo path delivers normalized hostname
        assert blocked[0] == ("evil.com", None)
        # connect path delivers normalized IP
        assert blocked[1] == ("203.0.113.1", 9999)


class TestAsyncSockets:
    @pytest.mark.asyncio
    async def test_blocks_async_getaddrinfo(self):
        tethered.activate(allow=["*.example.com"])
        loop = asyncio.get_event_loop()

        with pytest.raises(tethered.EgressBlocked):
            await loop.getaddrinfo("evil.com", 80)

    @pytest.mark.asyncio
    async def test_blocks_async_connect(self):
        tethered.activate(allow=["*.example.com"])

        with pytest.raises(tethered.EgressBlocked):
            await asyncio.open_connection("evil.com", 80)

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
        await loop.getaddrinfo("evil.com", 80)
        assert any(h == "evil.com" for h, _ in blocked)

    @pytest.mark.asyncio
    async def test_async_on_blocked_callback(self):
        blocked: list[tuple[str, int | None]] = []
        tethered.activate(
            allow=["*.example.com"],
            on_blocked=lambda h, p: blocked.append((h, p)),
        )
        with pytest.raises(tethered.EgressBlocked):
            await asyncio.open_connection("evil.com", 80)
        assert any(h == "evil.com" for h, _ in blocked)

    @pytest.mark.asyncio
    async def test_async_fail_closed(self, monkeypatch):
        tethered.activate(allow=["*.example.com"], fail_closed=True)
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        loop = asyncio.get_event_loop()
        with pytest.raises(tethered.EgressBlocked):
            await loop.getaddrinfo("evil.com", 80)

    @pytest.mark.asyncio
    async def test_async_concurrent_enforcement(self):
        """Multiple async tasks hitting the policy concurrently."""
        tethered.activate(allow=["*.example.com"])

        async def blocked_resolve():
            loop = asyncio.get_event_loop()
            with pytest.raises(tethered.EgressBlocked):
                await loop.getaddrinfo("evil.com", 80)

        await asyncio.gather(*[blocked_resolve() for _ in range(10)])

    @pytest.mark.asyncio
    async def test_async_conftest_guard_blocks(self):
        """Conftest guard blocks async DNS when tethered is deactivated."""
        # _cleanup fixture ensures _config is None after each test,
        # but we start deactivated here explicitly
        with pytest.raises(tethered.EgressBlocked, match=r"evil\.com"):
            loop = asyncio.get_event_loop()
            await loop.getaddrinfo("evil.com", 80)


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
        exc = tethered.EgressBlocked("evil.com", 443)
        assert exc.host == "evil.com"
        assert exc.port == 443
        assert exc.resolved_from is None
        assert "evil.com:443" in str(exc)

    def test_with_resolved_from(self):
        exc = tethered.EgressBlocked("203.0.113.1", 443, resolved_from="evil.com")
        assert exc.resolved_from == "evil.com"
        assert "resolved from evil.com" in str(exc)

    def test_no_port(self):
        exc = tethered.EgressBlocked("evil.com", None)
        assert "evil.com is not in the allow list" in str(exc)

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
        socket.getaddrinfo("evil.com", 80)

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
            socket.getaddrinfo("evil.com", 80)

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
            _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))

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
            _audit_hook("socket.gethostbyname", ("evil.com",))


class TestLockedMode:
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
            socket.getaddrinfo("evil.com", 80)

    def test_reactivate_replaces_locked_policy(self):
        """activate() always works, even over a locked policy."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        # A new activate() replaces the locked policy
        tethered.activate(allow=["evil.com"])
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
            _ip_to_hostname["198.51.100.1"] = "evil.com"
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
            _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))

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
        _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))
        assert blocked == [("evil.com", None)]

    def test_getaddrinfo_on_blocked_exception_logged(self):
        def bad_callback(host, port):
            raise RuntimeError("callback bug")

        tethered.activate(
            allow=["*.example.com"],
            on_blocked=bad_callback,
        )
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))

    @requires_network
    def test_getaddrinfo_allowed_populates_ip_map(self):
        tethered.activate(allow=["dns.google"])
        _audit_hook("socket.getaddrinfo", ("dns.google", 443, 0, 0, 0))
        with _ip_map_lock:
            assert any(v == "dns.google" for v in _ip_to_hostname.values())

    def test_getaddrinfo_allowed_handles_dns_failure(self):
        tethered.activate(allow=["nonexistent.invalid"])
        _audit_hook("socket.getaddrinfo", ("nonexistent.invalid", 80, 0, 0, 0))

    def test_getaddrinfo_allowed_handles_non_os_error(self, monkeypatch):
        """IP map resolution tolerates non-OSError (e.g. gevent RuntimeError)."""
        tethered.activate(allow=["api.example.com"])

        def _boom(*_args, **_kwargs):
            raise RuntimeError("can't start new thread")

        monkeypatch.setattr(socket, "getaddrinfo", _boom)
        # Should not raise — the IP map population is best-effort
        _audit_hook("socket.getaddrinfo", ("api.example.com", 443, 0, 0, 0))
        # No IP mapping stored (resolution failed), but DNS-level check passed
        with _ip_map_lock:
            assert not any(v == "api.example.com" for v in _ip_to_hostname.values())

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
            _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))
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
        _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))

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
        _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))

    def test_connect_policy_none_guard(self):
        """Direct call with no active policy — audit hook returns early."""
        _audit_hook("socket.connect", (None, ("192.0.2.1", 80)))


class TestDNSLookupInterception:
    """Test interception of gethostbyname/gethostbyaddr audit events."""

    def test_gethostbyname_blocks_disallowed(self):
        tethered.activate(allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.gethostbyname", ("evil.com",))

    def test_gethostbyaddr_blocks_disallowed(self):
        tethered.activate(allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.gethostbyaddr", ("evil.com",))

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
        _audit_hook("socket.gethostbyname", ("evil.com",))
        assert blocked == [("evil.com", None)]

    def test_gethostbyname_noop_without_policy(self):
        _audit_hook("socket.gethostbyname", ("evil.com",))

    def test_dns_lookup_policy_none_guard(self):
        """No active policy — audit hook returns early."""
        _audit_hook("socket.gethostbyname", ("evil.com",))

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
        _audit_hook("socket.gethostbyname", ("evil.com",))

    def test_gethostbyname_fail_open(self, monkeypatch):
        tethered.activate(allow=["*.example.com"])
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        _audit_hook("socket.gethostbyname", ("evil.com",))

    def test_gethostbyname_fail_closed(self, monkeypatch):
        tethered.activate(allow=["*.example.com"], fail_closed=True)
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.gethostbyname", ("evil.com",))


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
                _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))
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

        # evil.com should now be blocked again
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))

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
        _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))

        tethered.deactivate()
        tethered.activate(allow=["*.example.com"], log_only=False)
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))

    def test_log_only_swap_without_deactivate(self):
        """activate(log_only=True) -> activate(log_only=False) must raise."""
        tethered.activate(allow=["*.example.com"], log_only=True)
        _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))

        tethered.activate(allow=["*.example.com"], log_only=False)
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))

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
            _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))
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
            _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))
        assert calls_1 == ["evil.com"]

        tethered.deactivate()
        tethered.activate(
            allow=["*.example.com"],
            on_blocked=lambda h, _: calls_2.append(h),
        )
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))
        # Old callback must not fire, new callback must fire
        assert calls_1 == ["evil.com"]
        assert calls_2 == ["evil.com"]

    def test_on_blocked_none_not_inherited(self):
        """activate(on_blocked=cb) -> deactivate -> activate() — no callback."""
        calls: list[str] = []

        tethered.activate(
            allow=["*.example.com"],
            on_blocked=lambda h, _: calls.append(h),
        )
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))
        assert len(calls) == 1

        tethered.deactivate()
        tethered.activate(allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.getaddrinfo", ("evil.com", 80, 0, 0, 0))
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
        """activate(locked=True) -> activate(locked=False) -> deactivate() works."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        with pytest.raises(tethered.TetheredLocked):
            tethered.deactivate()

        tethered.activate(allow=["*.example.com"])
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
        with pytest.raises(tethered.EgressBlocked, match=r"evil\.com"):
            socket.getaddrinfo("evil.com", 80)

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
