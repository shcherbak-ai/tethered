"""Integration tests for tethered activate/deactivate with real sockets."""

from __future__ import annotations

import asyncio
import asyncio.proactor_events
import contextlib
import contextvars
import logging
import socket
import sys
import threading
import types

import pytest

import tethered
import tethered._core as _core
from tethered import _autoactivate
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
    _hint_from_stack,
    _in_hook,
    _ip_map_lock,
    _ip_to_hostname,
    _is_ip,
    _ScopeConfig,
    _scopes,
)
from tethered._policy import AllowPolicy


def _raise_runtime(self, host, port=None):
    raise RuntimeError("simulated policy bug")


requires_network = pytest.mark.requires_network


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

    @requires_network
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
        except (ConnectionError, TimeoutError, OSError):
            pass  # Connection refused/timeout is fine — EgressBlocked would be wrong

    @requires_network
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

    def test_scope_label_attribute_default_is_none(self):
        """Without a scope-driven block, ``scope_label`` is ``None``."""
        exc = tethered.EgressBlocked("evil.test", 443)
        assert exc.scope_label is None
        assert "blocked by" not in str(exc)

    def test_scope_label_appears_in_message_when_provided(self):
        """When a scope produced the block, the label is part of the message."""
        exc = tethered.EgressBlocked("evil.test", 443, scope_label="scope(api.mylib.com:443)")
        assert exc.scope_label == "scope(api.mylib.com:443)"
        assert "(blocked by scope(api.mylib.com:443))" in str(exc)

    def test_scope_label_set_when_scope_blocks_real_call(self):
        """End-to-end: a scope-driven block raises with ``scope_label`` populated."""
        tethered.activate(allow=["*.allowed.com"])
        with tethered.scope(allow=["api.allowed.com"]):
            try:
                socket.getaddrinfo("other.allowed.com", 80)
            except tethered.EgressBlocked as exc:
                assert exc.scope_label is not None
                assert "scope(" in exc.scope_label
            else:
                pytest.fail("expected EgressBlocked")

    def test_scope_label_none_when_global_blocks(self):
        """A block from the global policy (no scope on the stack) has ``scope_label=None``."""
        tethered.activate(allow=["*.allowed.com"])
        try:
            socket.getaddrinfo("evil.test", 80)
        except tethered.EgressBlocked as exc:
            assert exc.scope_label is None
        else:
            pytest.fail("expected EgressBlocked")

    def test_user_provided_scope_label_propagates_to_egress_blocked(self):
        """A ``label=`` passed to scope() shows up as ``EgressBlocked.scope_label``."""
        tethered.activate(allow=["*.allowed.com"])
        with tethered.scope(allow=["api.allowed.com"], label="WeatherClient.fetch"):
            try:
                socket.getaddrinfo("other.allowed.com", 80)
            except tethered.EgressBlocked as exc:
                assert exc.scope_label == "WeatherClient.fetch"
                assert "(blocked by WeatherClient.fetch)" in str(exc)
            else:
                pytest.fail("expected EgressBlocked")


class TestScopeLabelParam:
    """Tests for the ``label=`` parameter on scope()."""

    def test_default_label_auto_derived_from_allow(self):
        """Without ``label=``, the auto-derived ``scope(<rules>)`` form is used."""
        s = tethered.scope(allow=["api.example.com:443"])
        assert s._scope_cfg.label == "scope(api.example.com:443)"

    def test_custom_label_used_verbatim(self):
        """A user-provided ``label=`` is stored verbatim, no ``scope(...)`` wrapper added."""
        s = tethered.scope(allow=["api.example.com:443"], label="MyClient.fetch")
        assert s._scope_cfg.label == "MyClient.fetch"

    def test_label_appears_in_log_warning(self, caplog):
        """The label is what shows up in log messages when the scope blocks."""
        tethered.activate(allow=["*.allowed.com"])
        with (
            caplog.at_level(logging.WARNING, logger="tethered"),
            tethered.scope(allow=["api.allowed.com"], label="lib.task"),
        ):
            try:
                socket.getaddrinfo("other.allowed.com", 80)
            except tethered.EgressBlocked:
                pass
        assert any("lib.task blocked" in r.message for r in caplog.records)

    def test_invalid_label_type_raises(self):
        """Non-str, non-None ``label`` is rejected at construction time."""
        with pytest.raises(TypeError, match="label must be a str or None"):
            tethered.scope(allow=[], label=123)
        with pytest.raises(TypeError, match="label must be a str or None"):
            tethered.scope(allow=[], label=object())

    def test_explicit_none_label_uses_default(self):
        """``label=None`` is equivalent to omitting the parameter."""
        s = tethered.scope(allow=["api.example.com"], label=None)
        assert s._scope_cfg.label == "scope(api.example.com)"

    def test_empty_string_label_preserved(self):
        """An empty string is a valid label and is NOT replaced by the auto-derived default."""
        s = tethered.scope(allow=["api.example.com"], label="")
        assert s._scope_cfg.label == ""


class TestScopeHintParam:
    """Tests for the ``hint=`` parameter on scope() and ``EgressBlocked.scope_hint``."""

    def test_default_hint_is_none_on_exception(self):
        """Without a hinted scope, ``EgressBlocked.scope_hint`` is None and shows no Hint line."""
        tethered.activate(allow=["*.allowed.com"])
        try:
            socket.getaddrinfo("evil.test", 80)
        except tethered.EgressBlocked as exc:
            assert exc.scope_hint is None
            assert "Hint:" not in str(exc)
        else:
            pytest.fail("expected EgressBlocked")

    def test_hint_surfaces_when_scope_blocks(self):
        """A scope-driven block raises with the scope's hint attached."""
        tethered.activate(allow=["*.allowed.com"])
        with tethered.scope(
            allow=["api.allowed.com"],
            hint="this lib needs api.allowed.com — see docs/security.md",
        ):
            try:
                socket.getaddrinfo("other.allowed.com", 80)
            except tethered.EgressBlocked as exc:
                assert exc.scope_hint == "this lib needs api.allowed.com — see docs/security.md"
                assert ("\nHint: this lib needs api.allowed.com — see docs/security.md") in str(exc)
            else:
                pytest.fail("expected EgressBlocked")

    def test_hint_attaches_when_global_blocks_inside_scope(self):
        """A global-policy block while inside a hinted scope still surfaces the hint."""
        tethered.activate(allow=["*.allowed.com"])
        with tethered.scope(allow=["*.allowed.com"], hint="must call into the allowed.com surface"):
            try:
                socket.getaddrinfo("evil.test", 80)
            except tethered.EgressBlocked as exc:
                assert exc.scope_hint == "must call into the allowed.com surface"
                assert "Hint: must call into the allowed.com surface" in str(exc)
            else:
                pytest.fail("expected EgressBlocked")

    def test_message_unchanged_when_hint_is_none(self):
        """``EgressBlocked.__str__()`` is unchanged when ``scope_hint=None``."""
        exc = tethered.EgressBlocked("evil.test", 443)
        assert exc.scope_hint is None
        assert "Hint:" not in str(exc)

    def test_message_appends_hint_once(self):
        """The hint appears exactly once in ``str(exc)``."""
        exc = tethered.EgressBlocked("evil.test", 443, scope_hint="see docs")
        assert exc.scope_hint == "see docs"
        assert str(exc).count("Hint: see docs") == 1

    def test_nested_hinted_scopes_innermost_wins(self):
        """When nested hinted scopes are active, the deepest hinted scope's hint surfaces."""
        tethered.activate(allow=["*.allowed.com"])
        with (
            tethered.scope(allow=["*.allowed.com"], hint="OUTER hint"),
            tethered.scope(allow=["api.allowed.com"], hint="INNER hint"),
        ):
            try:
                socket.getaddrinfo("other.allowed.com", 80)
            except tethered.EgressBlocked as exc:
                assert exc.scope_hint == "INNER hint"
                assert "OUTER" not in str(exc)
            else:
                pytest.fail("expected EgressBlocked")

    def test_inner_unhinted_falls_back_to_outer_hint(self):
        """When the deepest scope has no hint, the next-deepest hinted scope wins."""
        tethered.activate(allow=["*.allowed.com"])
        with (
            tethered.scope(allow=["*.allowed.com"], hint="OUTER hint"),
            tethered.scope(allow=["api.allowed.com"]),  # no hint
        ):
            try:
                socket.getaddrinfo("other.allowed.com", 80)
            except tethered.EgressBlocked as exc:
                assert exc.scope_hint == "OUTER hint"
            else:
                pytest.fail("expected EgressBlocked")

    def test_invalid_hint_type_raises(self):
        """Non-str, non-None ``hint`` is rejected at construction time."""
        with pytest.raises(TypeError, match="hint must be a str or None"):
            tethered.scope(allow=[], hint=123)
        with pytest.raises(TypeError, match="hint must be a str or None"):
            tethered.scope(allow=[], hint=object())

    def test_empty_and_whitespace_only_hint_normalized_to_none(self):
        """Empty or whitespace-only hint produces no Hint line on the exception."""
        for value in ("", "   ", "\n\t  \n"):
            s = tethered.scope(allow=["api.example.com"], hint=value)
            assert s._scope_cfg.hint == ""
        # End-to-end: scope with whitespace-only hint behaves like an unhinted scope.
        tethered.activate(allow=["*.allowed.com"])
        with tethered.scope(allow=["api.allowed.com"], hint="   "):
            try:
                socket.getaddrinfo("other.allowed.com", 80)
            except tethered.EgressBlocked as exc:
                assert exc.scope_hint is None
                assert "Hint:" not in str(exc)
            else:
                pytest.fail("expected EgressBlocked")

    def test_hint_whitespace_normalized(self):
        """Embedded newlines and runs of whitespace collapse to single spaces."""
        s = tethered.scope(
            allow=["api.example.com"],
            hint="line one\n\nline two\t  with   extra",
        )
        assert s._scope_cfg.hint == "line one line two with extra"

    def test_hint_from_stack_helper_branches(self):
        """Direct exercise of ``_hint_from_stack`` covering all return paths.

        End-to-end tests above already exercise this via the audit hook, but
        coverage tooling on Python 3.13 occasionally fails to attribute lines
        executed from ``sys.audit``-invoked callbacks.  This test calls the
        helper synchronously so every branch is unambiguously measured.
        """
        sc_outer = _ScopeConfig(policy=AllowPolicy(["x"]), hint="OUTER")
        sc_inner = _ScopeConfig(policy=AllowPolicy(["x"]), hint="INNER")
        sc_unhinted = _ScopeConfig(policy=AllowPolicy(["x"]))
        assert _hint_from_stack(()) is None
        assert _hint_from_stack((sc_unhinted,)) is None
        assert _hint_from_stack((sc_outer, sc_inner)) == "INNER"
        assert _hint_from_stack((sc_outer, sc_unhinted)) == "OUTER"


class TestFailOpen:
    @requires_network
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

    def test_bytes_and_bytearray_hosts(self):
        assert _extract_host_port((b"192.0.2.1", 80)) == ("192.0.2.1", 80)
        assert _extract_host_port((bytearray(b"192.0.2.1"), 80)) == ("192.0.2.1", 80)
        assert _extract_host_port((b"::1", 443, 0, 0)) == ("::1", 443)

    def test_index_port(self):
        result = _extract_host_port(("192.0.2.1", _IndexPort(8080)))
        assert result == ("192.0.2.1", 8080)
        assert type(result[1]) is int

    def test_unreadable_host_or_port(self):
        assert _extract_host_port((b"\xff\xfe", 80)) is None  # not ASCII
        assert _extract_host_port(("192.0.2.1", _RaisingPort())) is None
        assert _extract_host_port(("192.0.2.1", 80.0)) is None
        assert _extract_host_port(("192.0.2.1",)) is None


class _IndexPort:
    """Stands in for ``numpy.int64`` and other integers that are not ``int``."""

    def __init__(self, value: int) -> None:
        self.value = value

    def __index__(self) -> int:
        return self.value


class _RaisingPort:
    def __index__(self) -> int:
        raise ValueError("no port")


@pytest.fixture
def tcp_listener():
    """A loopback TCP listener that never accepts; yields its port."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    try:
        yield server.getsockname()[1]
    finally:
        server.close()


@pytest.fixture
def udp_port():
    """A bound loopback UDP socket; yields its port."""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    try:
        yield server.getsockname()[1]
    finally:
        server.close()


class _FakeDns:
    """Stand-in for tethered's own resolver call.

    Answers from ``table`` (hostname -> list of IP strings; unknown names
    resolve to nothing) and records every call in ``calls``.
    """

    def __init__(self) -> None:
        self.table: dict[str, list[str]] = {}
        self.calls: list[tuple] = []

    def getaddrinfo(self, host, *args):
        self.calls.append((host, *args))
        return [
            (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))
            for ip in self.table.get(host, [])
        ]


@pytest.fixture
def fake_dns(monkeypatch):
    """Replace tethered's own resolver call with a :class:`_FakeDns`.

    Keeps synthetic-event tests offline even when a name is allowed through and
    tethered goes on to resolve it, and lets a test decide what a name maps to
    without touching the IP map's internal layout.
    """
    fake = _FakeDns()
    monkeypatch.setattr(_csocket, "getaddrinfo", fake.getaddrinfo)
    return fake


@pytest.fixture
def no_dns(fake_dns):
    """Like ``fake_dns`` with an empty table; returns the list of resolver calls."""
    return fake_dns.calls


def _learn(name: str) -> None:
    """Have tethered resolve ``name`` (through ``fake_dns``) and record the mapping.

    Runs inside a scope that allows only that name, the way a caller that has
    not yet entered an IP-only scope would look it up.
    """
    with tethered.scope(allow=[name], allow_localhost=False):
        _audit_hook("socket.getaddrinfo", (name, None, 0, 0, 0))


@contextlib.contextmanager
def _restricted(mode: str, allow: list[str], label: str = "restricted"):
    """Apply ``allow`` (localhost exemption off) through one enforcement layer.

    ``mode`` is ``"global"``, ``"locked"`` or ``"scope"`` (a scope on its own,
    labelled ``label``).
    """
    if mode == "scope":
        with tethered.scope(allow=allow, allow_localhost=False, label=label):
            yield
        return
    if mode == "locked":
        token = object()
        tethered.activate(
            allow=allow, allow_localhost=False, fail_closed=True, locked=True, lock_token=token
        )
        try:
            yield
        finally:
            tethered.deactivate(lock_token=token)
        return
    tethered.activate(allow=allow, allow_localhost=False, fail_closed=True)
    yield


def _deny_all(mode: str):
    """Deny everything, loopback included, through one enforcement layer."""
    return _restricted(mode, [], label="deny-all")


_DENY_MODES = ["global", "locked", "scope"]

# Every (host, port) form CPython's socket layer accepts for an AF_INET address.
_ADDRESS_SHAPES = [
    pytest.param(lambda port: ("127.0.0.1", port), id="str-int"),
    pytest.param(lambda port: (b"127.0.0.1", port), id="bytes-int"),
    pytest.param(lambda port: (bytearray(b"127.0.0.1"), port), id="bytearray-int"),
    pytest.param(lambda port: ("127.0.0.1", _IndexPort(port)), id="str-index"),
    pytest.param(lambda port: (b"127.0.0.1", _IndexPort(port)), id="bytes-index"),
]


class TestAddressShapes:
    """Every address form CPython accepts is checked, not only ``(str, int)``.

    A deny-all policy must block ``bytes``/``bytearray`` hosts and ``__index__``
    ports exactly as it blocks the plain form.  The scope-only cases assert
    ``scope_label`` so a block from the conftest guard cannot satisfy them.
    """

    @staticmethod
    def _assert_blocked(exc: tethered.EgressBlocked, mode: str, port: int) -> None:
        assert exc.host == "127.0.0.1"
        assert exc.port == port
        assert exc.scope_label == ("deny-all" if mode == "scope" else None)

    @pytest.mark.parametrize("mode", _DENY_MODES)
    @pytest.mark.parametrize("make_address", _ADDRESS_SHAPES)
    def test_connect_blocked(self, tcp_listener, mode, make_address):
        with (
            _deny_all(mode),
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client,
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            client.connect(make_address(tcp_listener))
        self._assert_blocked(exc_info.value, mode, tcp_listener)

    @pytest.mark.parametrize("mode", _DENY_MODES)
    @pytest.mark.parametrize("make_address", _ADDRESS_SHAPES)
    def test_connect_ex_blocked(self, tcp_listener, mode, make_address):
        with (
            _deny_all(mode),
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client,
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            client.connect_ex(make_address(tcp_listener))
        self._assert_blocked(exc_info.value, mode, tcp_listener)

    @pytest.mark.parametrize("mode", _DENY_MODES)
    @pytest.mark.parametrize("make_address", _ADDRESS_SHAPES)
    def test_udp_sendto_blocked(self, udp_port, mode, make_address):
        with (
            _deny_all(mode),
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client,
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            client.sendto(b"x", make_address(udp_port))
        self._assert_blocked(exc_info.value, mode, udp_port)

    @pytest.mark.parametrize("make_address", _ADDRESS_SHAPES)
    def test_connect_allowed_when_a_rule_matches(self, tcp_listener, make_address):
        """Normalization reads the real destination: a matching rule still allows it."""
        tethered.activate(allow=[f"127.0.0.1:{tcp_listener}"], allow_localhost=False)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(make_address(tcp_listener))

    def test_index_port_is_matched_against_port_rules(self, tcp_listener):
        """A port given through ``__index__`` is the port the rule is checked against."""
        tethered.activate(allow=[f"127.0.0.1:{tcp_listener + 1}"], allow_localhost=False)
        with (
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client,
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            client.connect(("127.0.0.1", _IndexPort(tcp_listener)))
        assert exc_info.value.port == tcp_listener

    @pytest.mark.parametrize("mode", _DENY_MODES)
    def test_ipv6_bytes_host_blocked(self, mode):
        try:
            server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        except OSError:
            pytest.skip("IPv6 not supported on this system")
        try:
            try:
                server.bind(("::1", 0))
            except OSError:
                pytest.skip("IPv6 loopback not available")
            server.listen(1)
            port = server.getsockname()[1]
            with (
                _deny_all(mode),
                socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as client,
                pytest.raises(tethered.EgressBlocked) as exc_info,
            ):
                client.connect((b"::1", _IndexPort(port), 0, 0))
        finally:
            server.close()
        assert exc_info.value.host == "::1"
        assert exc_info.value.port == port
        assert exc_info.value.scope_label == ("deny-all" if mode == "scope" else None)

    # ── DNS calls with byte-string hosts ──
    # ``.invalid`` never resolves, and the block is raised before any query is
    # sent, so these stay offline.

    @pytest.mark.parametrize("mode", _DENY_MODES)
    @pytest.mark.parametrize(
        ("lookup", "host", "expected"),
        [
            pytest.param(
                lambda h: socket.getaddrinfo(h, 80),
                b"blocked.invalid",
                "blocked.invalid",
                id="getaddrinfo-bytes",
            ),
            pytest.param(
                socket.gethostbyname,
                b"blocked.invalid",
                "blocked.invalid",
                id="gethostbyname-bytes",
            ),
            pytest.param(
                socket.gethostbyname,
                bytearray(b"blocked.invalid"),
                "blocked.invalid",
                id="gethostbyname-bytearray",
            ),
            pytest.param(
                socket.gethostbyname_ex,
                b"blocked.invalid",
                "blocked.invalid",
                id="gethostbyname_ex-bytes",
            ),
            pytest.param(socket.gethostbyaddr, b"192.0.2.7", "192.0.2.7", id="gethostbyaddr-bytes"),
            pytest.param(
                socket.gethostbyaddr,
                bytearray(b"192.0.2.7"),
                "192.0.2.7",
                id="gethostbyaddr-bytearray",
            ),
        ],
    )
    def test_dns_byte_string_host_blocked(self, mode, lookup, host, expected):
        with _deny_all(mode), pytest.raises(tethered.EgressBlocked) as exc_info:
            lookup(host)
        assert exc_info.value.host == expected
        assert exc_info.value.scope_label == ("deny-all" if mode == "scope" else None)

    def test_getaddrinfo_bytes_host_establishes_identity(self, tcp_listener):
        """An allowed byte-string lookup is recorded like the ``str`` form."""
        tethered.activate(allow=["localhost"], allow_localhost=False)
        socket.getaddrinfo(b"localhost", tcp_listener, socket.AF_INET)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(("127.0.0.1", tcp_listener))

    def test_none_and_empty_dns_hosts_are_local(self):
        tethered.activate(allow=[], allow_localhost=False)
        _audit_hook("socket.getaddrinfo", (None, 80, 0, 0, 0))
        _audit_hook("socket.getaddrinfo", (b"", 80, 0, 0, 0))
        _audit_hook("socket.gethostbyname", (None,))
        _audit_hook("socket.gethostbyname", (bytearray(),))

    # ── Addresses tethered cannot read ──

    @pytest.mark.parametrize(
        "address",
        [
            pytest.param((b"\xff\xfe", 80), id="non-ascii-bytes-host"),
            pytest.param((123, 80), id="int-host"),
            pytest.param(("192.0.2.1", "80"), id="str-port"),
            pytest.param(("192.0.2.1", _RaisingPort()), id="raising-port"),
        ],
    )
    @pytest.mark.parametrize("event", ["socket.connect", "socket.sendto", "socket.sendmsg"])
    def test_unreadable_ip_address_is_blocked(self, event, address):
        tethered.activate(allow=["192.0.2.0/24"])
        with pytest.raises(tethered.EgressBlocked) as exc_info:
            _audit_hook(event, (None, address))
        assert exc_info.value.host.startswith("<unreadable ")
        assert exc_info.value.port is None

    def test_unreadable_address_on_a_real_ip_socket_is_blocked(self):
        tethered.activate(allow=["192.0.2.0/24"])
        with (
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
            pytest.raises(tethered.EgressBlocked),
        ):
            _audit_hook("socket.connect", (sock, (b"\xff\xfe", 80)))

    def test_unreadable_address_on_a_non_ip_socket_is_not_checked(self):
        """Other address families keep their own address shapes and are skipped."""
        tethered.activate(allow=[], allow_localhost=False)
        unix_like = types.SimpleNamespace(family=getattr(socket, "AF_UNIX", 1))
        _audit_hook("socket.connect", (unix_like, (123, 456)))
        _audit_hook("socket.connect", (unix_like, b"/tmp/socket"))
        _audit_hook("socket.connect", (None, "/tmp/socket"))

    @pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="AF_UNIX not available")
    def test_real_unix_socket_is_not_checked(self):
        """Refused by the OS (nothing listens there), not by tethered."""
        tethered.activate(allow=[], allow_localhost=False)
        with (
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client,
            pytest.raises(OSError),
        ):
            # A short fixed path: AF_UNIX paths are limited to about 100 bytes,
            # and a longer one is rejected before the audit event is raised.
            client.connect("/tmp/tethered-no-listener.sock")

    def test_is_ip_family(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            assert _core._is_ip_family(sock, "anything") is True
        assert _core._is_ip_family(types.SimpleNamespace(family=-1), ("h", 1)) is False
        # No socket (synthetic event): decided by the address shape.
        assert _core._is_ip_family(None, ("h", 1)) is True
        assert _core._is_ip_family(None, ("h",)) is False
        assert _core._is_ip_family(None, "/tmp/socket") is False

    def test_unreadable_address_log_only_reports_and_allows(self):
        blocked: list[tuple[str, int | None]] = []
        tethered.activate(allow=[], log_only=True, on_blocked=lambda h, p: blocked.append((h, p)))
        _audit_hook("socket.connect", (None, (b"\xff\xfe", 80)))
        assert len(blocked) == 1
        assert blocked[0][0].startswith("<unreadable ")
        assert blocked[0][1] is None

    def test_unreadable_address_on_blocked_exception_is_swallowed(self):
        def bad_callback(host, port):
            raise RuntimeError("callback bug")

        tethered.activate(allow=[], on_blocked=bad_callback)
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.connect", (None, (b"\xff\xfe", 80)))

    def test_unreadable_address_blocked_by_scope_alone(self, caplog):
        seen: list[str] = []
        with (
            caplog.at_level(logging.WARNING, logger="tethered"),
            tethered.scope(
                allow=["192.0.2.0/24"],
                log_only=True,
                on_blocked=lambda h, p: seen.append("monitor"),
            ),
            tethered.scope(allow=["192.0.2.0/24"], label="enforcing"),
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            _audit_hook("socket.connect", (None, (b"\xff\xfe", 80)))
        assert seen == ["monitor"]
        assert exc_info.value.scope_label == "enforcing"
        assert r"enforcing blocked connect for <unreadable (b'\xff\xfe', 80)>" in caplog.text

    @pytest.mark.parametrize(
        ("event", "args"),
        [
            pytest.param("socket.getaddrinfo", (b"\xff.example", 80, 0, 0, 0), id="getaddrinfo"),
            pytest.param("socket.getaddrinfo", (123, 80, 0, 0, 0), id="getaddrinfo-int"),
            pytest.param("socket.gethostbyname", (b"\xff.example",), id="gethostbyname"),
            pytest.param("socket.gethostbyaddr", (bytearray(b"\xff"),), id="gethostbyaddr"),
        ],
    )
    def test_unreadable_dns_host_is_blocked(self, event, args):
        tethered.activate(allow=["*.example"])
        with pytest.raises(tethered.EgressBlocked) as exc_info:
            _audit_hook(event, args)
        assert exc_info.value.host.startswith("<unreadable ")

    @pytest.mark.parametrize(
        ("event", "args"),
        [
            pytest.param("socket.getaddrinfo", (b"\xff.example", 80, 0, 0, 0), id="getaddrinfo"),
            pytest.param("socket.gethostbyname", (b"\xff.example",), id="gethostbyname"),
            pytest.param("socket.gethostbyaddr", (bytearray(b"\xff"),), id="gethostbyaddr"),
        ],
    )
    def test_unreadable_dns_host_log_only_reports_and_allows(self, event, args):
        blocked: list[tuple[str, int | None]] = []
        tethered.activate(allow=[], log_only=True, on_blocked=lambda h, p: blocked.append((h, p)))
        _audit_hook(event, args)
        assert len(blocked) == 1
        assert blocked[0][0].startswith("<unreadable ")
        assert blocked[0][1] is None

    def test_host_text(self):
        assert _core._host_text("Example.COM") == "Example.COM"
        assert _core._host_text(b"example.com") == "example.com"
        assert _core._host_text(bytearray(b"192.0.2.1")) == "192.0.2.1"
        assert _core._host_text(b"") == ""
        assert _core._host_text(b"\xc3\xa9.example") is None  # UTF-8, not ASCII
        assert _core._host_text(None) is None
        assert _core._host_text(123) is None


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
            _ip_to_hostname["198.51.100.1"] = ("api.stripe.com",)
        _audit_hook("socket.connect", (None, ("198.51.100.1", 443)))

    def test_connect_ip_map_hostname_blocked(self):
        tethered.activate(allow=["*.stripe.com"])
        with _ip_map_lock:
            _ip_to_hostname["198.51.100.1"] = ("evil.test",)
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
            assert any("dns.google" in v for v in _ip_to_hostname.values())

    def test_getaddrinfo_allowed_refreshes_existing_ip_map_entry(self, monkeypatch):
        tethered.activate(allow=["dns.google"])

        with _ip_map_lock:
            _ip_to_hostname.clear()
            _ip_to_hostname["203.0.113.10"] = ("old.example.com",)
            _ip_to_hostname["198.51.100.20"] = ("stale.example.com",)

        monkeypatch.setattr(
            _csocket,
            "getaddrinfo",
            lambda *args: [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.10", 443)),
            ],
        )

        _audit_hook("socket.getaddrinfo", ("dns.google", 443, 0, 0, 0))

        with _ip_map_lock:
            # The new name goes first; the name already known for the address stays.
            assert _ip_to_hostname["203.0.113.10"] == ("dns.google", "old.example.com")
            assert list(_ip_to_hostname.keys())[-1] == "203.0.113.10"

    def test_getaddrinfo_forwards_caller_args(self, monkeypatch):
        """getaddrinfo forwards the event's family/socktype/proto to the C-level resolver.

        The audit event is ``(host, port, family, type, protocol)``; the
        caller's flags are not part of it, so tethered's lookup passes none.
        """
        tethered.activate(allow=["dns.google"])
        captured = {}

        def _capture(*args):
            captured["args"] = args
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 443))]

        monkeypatch.setattr(_csocket, "getaddrinfo", _capture)
        _audit_hook(
            "socket.getaddrinfo",
            ("dns.google", 443, socket.AF_INET6, socket.SOCK_STREAM, 6),
        )
        host, port, family, socktype, proto, flags = captured["args"]
        assert host == "dns.google"
        assert port == 443
        assert family == socket.AF_INET6
        assert socktype == socket.SOCK_STREAM
        assert proto == 6
        assert flags == 0

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
            assert not any("api.example.com" in v for v in _ip_to_hostname.values())

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
            assert any("localhost" in v for v in _ip_to_hostname.values())

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
                _ip_to_hostname[f"198.51.{i // 256}.{i % 256}"] = (f"host{i}.example.com",)
        _audit_hook("socket.getaddrinfo", ("dns.google", 443, 0, 0, 0))
        with _ip_map_lock:
            # After eviction + adding dns.google IPs, should be at or below capacity
            assert len(_ip_to_hostname) <= _IP_MAP_MAX_SIZE
            # dns.google entries should be present
            assert any("dns.google" in v for v in _ip_to_hostname.values())

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


class TestGetnameinfoIsNotChecked:
    """``socket.getnameinfo`` is deliberately left unchecked.

    Its audit event carries the address but not the flags, so a reverse lookup
    cannot be told apart from purely numeric formatting (``NI_NUMERICHOST``),
    which servers and clients use on every peer address.  Refusing the event
    would break those calls for addresses no rule names.
    """

    @pytest.mark.parametrize("mode", _DENY_MODES)
    def test_numeric_formatting_works_under_deny_all(self, mode):
        flags = socket.NI_NUMERICHOST | socket.NI_NUMERICSERV
        with _deny_all(mode):
            assert socket.getnameinfo(("192.0.2.7", 80), flags) == ("192.0.2.7", "80")

    def test_event_is_ignored(self):
        tethered.activate(allow=[], allow_localhost=False)
        _audit_hook("socket.getnameinfo", (("192.0.2.7", 80),))
        _audit_hook("socket.getnameinfo", ((),))


# Forward lookups that return one IPv4 address for a hostname.
_FORWARD_LOOKUPS = [
    pytest.param(socket.gethostbyname, id="gethostbyname"),
    pytest.param(lambda host: socket.gethostbyname_ex(host)[2][0], id="gethostbyname_ex"),
    pytest.param(
        lambda host: socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0], id="getaddrinfo"
    ),
]


class TestGethostbynameIdentity:
    """A ``gethostbyname`` lookup supports the connect that follows it.

    ``ip = gethostbyname(host); connect((ip, port))`` must behave like the same
    sequence through ``getaddrinfo``: the address is matched back to the name
    that made the lookup permissible.
    """

    @pytest.mark.parametrize("mode", _DENY_MODES)
    @pytest.mark.parametrize("lookup", _FORWARD_LOOKUPS)
    def test_lookup_then_connect_is_allowed(self, tcp_listener, mode, lookup):
        with _restricted(mode, ["localhost"]):
            ip = lookup("localhost")
            assert ip.startswith("127.")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect((ip, tcp_listener))

    @pytest.mark.parametrize("mode", _DENY_MODES)
    @pytest.mark.parametrize("lookup", _FORWARD_LOOKUPS)
    def test_port_rule_still_applies(self, tcp_listener, mode, lookup):
        other_port = tcp_listener - 1
        with _restricted(mode, [f"localhost:{other_port}"]):
            ip = lookup("localhost")
            with (
                socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client,
                pytest.raises(tethered.EgressBlocked) as exc_info,
            ):
                client.connect((ip, tcp_listener))
        assert exc_info.value.resolved_from == "localhost"
        assert exc_info.value.port == tcp_listener
        assert exc_info.value.scope_label == ("restricted" if mode == "scope" else None)

    @pytest.mark.parametrize("mode", _DENY_MODES)
    def test_port_rule_allows_matching_port(self, tcp_listener, mode):
        with _restricted(mode, [f"localhost:{tcp_listener}"]):
            ip = socket.gethostbyname("localhost")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect((ip, tcp_listener))

    def test_allowed_lookup_records_a_candidate(self):
        tethered.activate(allow=["*.invalid"])
        _audit_hook("socket.gethostbyname", ("API.Example.invalid.",))
        assert list(_core._allowed_hostnames) == ["api.example.invalid"]

    def test_blocked_lookup_records_nothing(self):
        tethered.activate(allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.gethostbyname", ("blocked.invalid",))
        assert not _core._allowed_hostnames

    def test_scope_blocked_lookup_records_nothing(self):
        tethered.activate(allow=["*.invalid"])
        with (
            tethered.scope(allow=["api.invalid"], label="lib"),
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            _audit_hook("socket.gethostbyname", ("blocked.invalid",))
        assert exc_info.value.scope_label == "lib"
        assert not _core._allowed_hostnames

    def test_global_log_only_denial_records_nothing(self):
        tethered.activate(allow=["*.example.com"], log_only=True)
        _audit_hook("socket.gethostbyname", ("blocked.invalid",))
        assert not _core._allowed_hostnames

    def test_reverse_lookups_and_ip_literals_record_nothing(self):
        tethered.activate(allow=["192.0.2.0/24"])
        _audit_hook("socket.gethostbyaddr", ("192.0.2.1",))
        _audit_hook("socket.getnameinfo", (("192.0.2.1", 80),))
        _audit_hook("socket.gethostbyname", ("192.0.2.1",))
        assert not _core._allowed_hostnames


class TestIPMapEviction:
    def test_lru_eviction_removes_oldest(self):
        """LRU eviction should remove the least-recently-used entries."""
        tethered.activate(allow=["198.51.100.0/24"])

        with _ip_map_lock:
            _ip_to_hostname.clear()
            # Fill the map with 10 entries
            for i in range(10):
                _ip_to_hostname[f"10.0.0.{i}"] = ("old.example.com",)

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
            _ip_to_hostname["198.51.100.1"] = ("api.stripe.com",)
            _ip_to_hostname["198.51.100.2"] = ("other.stripe.com",)

        # Connect to first IP -- should move it to end of LRU
        _audit_hook("socket.connect", (None, ("198.51.100.1", 443)))

        with _ip_map_lock:
            keys = list(_ip_to_hostname.keys())
            # 198.51.100.1 should now be after 198.51.100.2 (moved to end)
            assert keys.index("198.51.100.1") > keys.index("198.51.100.2")


class TestSharedAddresses:
    """Several hostnames can share one address, and each keeps its identity.

    The IP map remembers a bounded list of names per address.  A connect is
    allowed if any of those names, or the raw IP, is allowed — so resolving a
    second name that lives on the same address (a CDN, a cloud front end, a
    load balancer) must not take the first name's permission away.
    """

    def test_two_names_one_address_distinct_ports(self, fake_dns):
        fake_dns.table["a.example.com"] = ["203.0.113.7"]
        fake_dns.table["b.example.com"] = ["203.0.113.7"]
        tethered.activate(allow=["a.example.com:8001", "b.example.com:8002"], allow_localhost=False)

        _audit_hook("socket.getaddrinfo", ("a.example.com", 8001, 0, 0, 0))
        _audit_hook("socket.connect", (None, ("203.0.113.7", 8001)))

        _audit_hook("socket.getaddrinfo", ("b.example.com", 8002, 0, 0, 0))
        _audit_hook("socket.connect", (None, ("203.0.113.7", 8001)))  # still a.example.com's
        _audit_hook("socket.connect", (None, ("203.0.113.7", 8002)))

        with pytest.raises(tethered.EgressBlocked) as exc_info:
            _audit_hook("socket.connect", (None, ("203.0.113.7", 8003)))
        assert exc_info.value.host == "203.0.113.7"
        assert exc_info.value.resolved_from == "b.example.com"  # the most recent name

    def test_two_names_one_address_real_sockets(self, fake_dns, tcp_listener):
        """Both names resolve to loopback; each rule names a different listener."""
        second = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        second.bind(("127.0.0.1", 0))
        second.listen(4)
        try:
            port_a, port_b = tcp_listener, second.getsockname()[1]
            fake_dns.table["a.invalid"] = ["127.0.0.1"]
            fake_dns.table["b.invalid"] = ["127.0.0.1"]
            tethered.activate(
                allow=[f"a.invalid:{port_a}", f"b.invalid:{port_b}"], allow_localhost=False
            )
            _audit_hook("socket.getaddrinfo", ("a.invalid", port_a, 0, 0, 0))
            _audit_hook("socket.getaddrinfo", ("b.invalid", port_b, 0, 0, 0))
            for port in (port_a, port_b, port_a):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                    client.settimeout(5)
                    client.connect(("127.0.0.1", port))
        finally:
            second.close()

    def test_raw_ip_rule_allows_whatever_names_are_mapped(self, fake_dns):
        fake_dns.table["a.example.com"] = ["203.0.113.7"]
        tethered.activate(allow=["a.example.com:8001", "203.0.113.7:443"], allow_localhost=False)
        _audit_hook("socket.getaddrinfo", ("a.example.com", 8001, 0, 0, 0))
        _audit_hook("socket.connect", (None, ("203.0.113.7", 443)))

    def test_cross_scope_interleaving(self, fake_dns):
        """A lookup made under another scope does not hijack this scope's address."""
        fake_dns.table["a.example.com"] = ["203.0.113.7"]
        fake_dns.table["b.example.com"] = ["203.0.113.7"]
        ctx_a, ctx_b = contextvars.copy_context(), contextvars.copy_context()
        scope_a = tethered.scope(allow=["a.example.com"], allow_localhost=False, label="A")
        scope_b = tethered.scope(allow=["b.example.com"], allow_localhost=False, label="B")
        ctx_a.run(scope_a.__enter__)
        ctx_b.run(scope_b.__enter__)
        try:
            ctx_a.run(_audit_hook, "socket.getaddrinfo", ("a.example.com", 443, 0, 0, 0))
            ctx_b.run(_audit_hook, "socket.getaddrinfo", ("b.example.com", 443, 0, 0, 0))
            # Each context reaches the shared address through its own name.
            ctx_a.run(_audit_hook, "socket.connect", (None, ("203.0.113.7", 443)))
            ctx_b.run(_audit_hook, "socket.connect", (None, ("203.0.113.7", 443)))
        finally:
            ctx_b.run(scope_b.__exit__, None, None, None)
            ctx_a.run(scope_a.__exit__, None, None, None)

    def test_a_scope_allowing_none_of_the_names_still_blocks(self, fake_dns):
        fake_dns.table["a.example.com"] = ["203.0.113.7"]
        fake_dns.table["b.example.com"] = ["203.0.113.7"]
        _learn("a.example.com")
        _learn("b.example.com")
        with (
            tethered.scope(allow=["c.example.com"], allow_localhost=False, label="C"),
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            _audit_hook("socket.connect", (None, ("203.0.113.7", 443)))
        assert exc_info.value.scope_label == "C"
        assert exc_info.value.resolved_from == "b.example.com"

    # ── One address, several spellings ──

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("192.0.2.1", "192.0.2.1"),
            ("::ffff:192.0.2.1", "192.0.2.1"),
            ("::FFFF:C000:0201", "192.0.2.1"),
            ("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
            ("2001:db8::1", "2001:db8::1"),
            ("fe80::1%eth0", "fe80::1"),
            ("::1", "::1"),
            ("example.com", None),
            ("1example.com", None),
            ("cafe::bad::", None),
            ("", None),
            # _canonical_ip returns IPv4 text unchanged, which is only right
            # while ipaddress accepts exactly one spelling of an IPv4 address.
            ("010.0.0.1", None),
            ("10.0.0.01", None),
            ("10.1", None),
            ("0x0a.0.0.1", None),
            (" 10.0.0.1", None),
        ],
    )
    def test_canonical_ip(self, text, expected):
        assert _core._canonical_ip(text) == expected

    @pytest.mark.parametrize(
        ("resolved", "connect_to"),
        [
            pytest.param("203.0.113.7", ("::ffff:203.0.113.7", 443, 0, 0), id="mapped-connect"),
            pytest.param("203.0.113.7", ("::FFFF:CB00:7107", 443, 0, 0), id="mapped-hex-connect"),
            pytest.param("::ffff:203.0.113.7", ("203.0.113.7", 443), id="mapped-resolve"),
            pytest.param(
                "2001:db8::1",
                ("2001:0DB8:0000:0000:0000:0000:0000:0001", 443, 0, 0),
                id="expanded-ipv6",
            ),
            pytest.param("fe80::1", ("fe80::1%eth0", 443, 0, 3), id="scoped-connect"),
            pytest.param("fe80::1%eth0", ("fe80::1", 443, 0, 3), id="scoped-resolve"),
        ],
    )
    def test_any_spelling_of_the_address_finds_the_name(self, fake_dns, resolved, connect_to):
        fake_dns.table["api.example.com"] = [resolved]
        tethered.activate(allow=["api.example.com"], allow_localhost=False)
        _audit_hook("socket.getaddrinfo", ("api.example.com", 443, 0, 0, 0))
        _audit_hook("socket.connect", (None, connect_to))

    def test_dual_stack_socket_reaches_a_name_mapped_to_ipv4(self, tcp_listener):
        """A real AF_INET6 socket connecting to the IPv4-mapped form of the address."""
        try:
            client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        except OSError:
            pytest.skip("IPv6 not supported on this system")
        with client:
            try:
                client.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pytest.skip("dual-stack sockets not supported on this system")
            client.settimeout(5)
            tethered.activate(allow=[f"localhost:{tcp_listener}"], allow_localhost=False)
            socket.getaddrinfo("localhost", tcp_listener, socket.AF_INET)  # maps 127.0.0.1
            try:
                client.connect(("::ffff:127.0.0.1", tcp_listener, 0, 0))
            except OSError as exc:  # EgressBlocked is not an OSError and would fail the test
                pytest.skip(f"IPv4-mapped connect not possible here: {exc}")

    def test_fallback_resolve_matches_in_canonical_form(self, fake_dns):
        fake_dns.table["api.example.com"] = ["203.0.113.7"]
        tethered.activate(allow=["api.example.com"], allow_localhost=False)
        _core._remember_allowed_hostname("api.example.com")
        assert _core._fallback_resolve("::ffff:203.0.113.7", 443) == "api.example.com"

    # ── Bounds ──

    def test_names_per_address_are_bounded_most_recent_first(self, fake_dns):
        limit = _core._IP_MAP_MAX_NAMES
        tethered.activate(allow=["*.example.com"], allow_localhost=False)
        for i in range(limit + 3):
            fake_dns.table[f"h{i}.example.com"] = ["203.0.113.7"]
            _audit_hook("socket.getaddrinfo", (f"h{i}.example.com", 443, 0, 0, 0))
        with _ip_map_lock:
            names = _ip_to_hostname["203.0.113.7"]
        assert names == tuple(f"h{i}.example.com" for i in range(limit + 2, 2, -1))
        assert len(names) == limit

    def test_resolving_a_known_name_again_moves_it_to_the_front(self, fake_dns):
        tethered.activate(allow=["*.example.com"], allow_localhost=False)
        for name in ("a.example.com", "b.example.com", "c.example.com", "a.example.com"):
            fake_dns.table[name] = ["203.0.113.7"]
            _audit_hook("socket.getaddrinfo", (name, 443, 0, 0, 0))
        with _ip_map_lock:
            assert _ip_to_hostname["203.0.113.7"] == (
                "a.example.com",
                "c.example.com",
                "b.example.com",
            )
        # Resolving the front name again changes nothing.
        _audit_hook("socket.getaddrinfo", ("a.example.com", 443, 0, 0, 0))
        with _ip_map_lock:
            assert _ip_to_hostname["203.0.113.7"][0] == "a.example.com"
            assert len(_ip_to_hostname["203.0.113.7"]) == 3

    def test_lru_eviction_drops_whole_addresses(self, fake_dns):
        tethered.activate(allow=["*.example.com"], allow_localhost=False)
        with _ip_map_lock:
            _ip_to_hostname["10.0.0.0"] = ("old-a.example.com", "old-b.example.com")
            for i in range(1, _IP_MAP_MAX_SIZE):
                _ip_to_hostname[f"10.{i // 65536}.{i // 256 % 256}.{i % 256}"] = (
                    "filler.example.com",
                )
        fake_dns.table["new.example.com"] = ["203.0.113.7"]
        _audit_hook("socket.getaddrinfo", ("new.example.com", 443, 0, 0, 0))
        with _ip_map_lock:
            assert len(_ip_to_hostname) == _IP_MAP_MAX_SIZE
            assert "10.0.0.0" not in _ip_to_hostname
            assert _ip_to_hostname["203.0.113.7"] == ("new.example.com",)


class TestAllowedHostnamesRecording:
    """``_allowed_hostnames`` LRU is populated by ``_handle_getaddrinfo``.

    Used as the candidate pool by ``_fallback_resolve`` when the IP map
    misses (DNS divergence under gevent/load-balanced services).
    """

    def test_globally_allowed_hostname_is_recorded(self):
        """A getaddrinfo that passes the global policy populates ``_allowed_hostnames``."""
        tethered.activate(allow=["api.example.com"])
        # Use the audit-hook entry directly so the test stays offline.
        _audit_hook("socket.getaddrinfo", ("api.example.com", 443, 0, 0, 0))
        assert "api.example.com" in _core._allowed_hostnames

    def test_globally_blocked_hostname_is_not_recorded(self):
        """A getaddrinfo that fails the global policy is NOT recorded."""
        tethered.activate(allow=["api.example.com"])
        try:
            _audit_hook("socket.getaddrinfo", ("evil.test", 80, 0, 0, 0))
        except tethered.EgressBlocked:
            pass
        assert "evil.test" not in _core._allowed_hostnames

    def test_repeat_lookup_moves_hostname_to_end(self):
        """Re-resolving a recorded hostname promotes it to most-recent (LRU)."""
        tethered.activate(allow=["*.example.com"])
        _audit_hook("socket.getaddrinfo", ("a.example.com", 443, 0, 0, 0))
        _audit_hook("socket.getaddrinfo", ("b.example.com", 443, 0, 0, 0))
        _audit_hook("socket.getaddrinfo", ("a.example.com", 443, 0, 0, 0))
        keys = list(_core._allowed_hostnames)
        # ``a.example.com`` was re-looked-up after ``b.example.com``, so it
        # should be the most-recent (rightmost).
        assert keys[-1] == "a.example.com"
        assert keys.index("a.example.com") > keys.index("b.example.com")

    def test_lru_eviction_at_max_size(self):
        """Once ``_ALLOWED_HOSTNAMES_MAX_SIZE`` is reached, oldest entries evict."""
        tethered.activate(allow=["*.example.com"])
        with _ip_map_lock:
            _core._allowed_hostnames.clear()
            # Pre-fill to one below the cap so the next insert evicts.
            for i in range(_core._ALLOWED_HOSTNAMES_MAX_SIZE):
                _core._allowed_hostnames[f"h{i}.example.com"] = None
        # Inserting one more should evict ``h0.example.com`` (the oldest).
        _audit_hook("socket.getaddrinfo", ("new.example.com", 443, 0, 0, 0))
        assert len(_core._allowed_hostnames) == _core._ALLOWED_HOSTNAMES_MAX_SIZE
        assert "h0.example.com" not in _core._allowed_hostnames
        assert "new.example.com" in _core._allowed_hostnames

    def test_activate_clears_allowed_hostnames(self):
        """``activate()`` clears ``_allowed_hostnames`` (no carryover from prior policy)."""
        tethered.activate(allow=["*.example.com"])
        _audit_hook("socket.getaddrinfo", ("api.example.com", 443, 0, 0, 0))
        assert "api.example.com" in _core._allowed_hostnames
        tethered.activate(allow=["*.different.com"])
        assert "api.example.com" not in _core._allowed_hostnames

    def test_deactivate_clears_allowed_hostnames(self):
        """``deactivate()`` clears ``_allowed_hostnames``."""
        tethered.activate(allow=["*.example.com"])
        _audit_hook("socket.getaddrinfo", ("api.example.com", 443, 0, 0, 0))
        assert "api.example.com" in _core._allowed_hostnames
        tethered.deactivate()
        assert "api.example.com" not in _core._allowed_hostnames

    # ── A name is a candidate only once every enforcing layer has allowed it ──

    def test_scope_blocked_hostname_is_not_recorded(self, no_dns):
        """Scope alone: a refused lookup must not be re-issued by tethered later."""
        with tethered.scope(allow=["api.mylib.invalid:443"], allow_localhost=False, label="lib"):
            with pytest.raises(tethered.EgressBlocked) as exc_info:
                _audit_hook("socket.getaddrinfo", ("secret-payload.attacker.invalid", 443, 0, 0, 0))
            assert exc_info.value.scope_label == "lib"
            assert not _core._allowed_hostnames

            # A later connect to an unmapped address runs _fallback_resolve.
            # It must find no candidate, so tethered issues no lookup at all.
            with pytest.raises(tethered.EgressBlocked):
                _audit_hook("socket.connect", (None, ("203.0.113.9", 443)))
        assert no_dns == []

    def test_scope_blocked_hostname_is_not_recorded_with_global_policy(self, no_dns):
        """Global policy allows the name, the scope refuses it: still not a candidate."""
        tethered.activate(allow=["*.invalid"], allow_localhost=False)
        with tethered.scope(allow=["api.mylib.invalid:443"], allow_localhost=False, label="lib"):
            with pytest.raises(tethered.EgressBlocked) as exc_info:
                _audit_hook("socket.getaddrinfo", ("secret-payload.attacker.invalid", 443, 0, 0, 0))
            assert exc_info.value.scope_label == "lib"
            assert not _core._allowed_hostnames

            with pytest.raises(tethered.EgressBlocked):
                _audit_hook("socket.connect", (None, ("203.0.113.9", 443)))
        assert no_dns == []

    def test_inner_enforcing_scope_block_is_not_recorded(self, no_dns):
        """Recording waits for the whole stack, not just the first scope."""
        with (
            tethered.scope(allow=["*.invalid"], allow_localhost=False),
            tethered.scope(allow=["api.mylib.invalid"], allow_localhost=False, label="inner"),
        ):
            with pytest.raises(tethered.EgressBlocked) as exc_info:
                _audit_hook("socket.getaddrinfo", ("other.invalid", 443, 0, 0, 0))
            assert exc_info.value.scope_label == "inner"
        assert not _core._allowed_hostnames
        assert no_dns == []

    def test_scope_allowed_hostname_is_recorded(self, no_dns):
        with tethered.scope(allow=["api.mylib.invalid:443"], allow_localhost=False):
            _audit_hook("socket.getaddrinfo", ("api.mylib.invalid", 443, 0, 0, 0))
        assert list(_core._allowed_hostnames) == ["api.mylib.invalid"]

    def test_log_only_scope_denial_is_still_recorded(self, no_dns):
        """A log-only scope lets the lookup through, so the name stays a candidate."""
        with tethered.scope(allow=["api.mylib.invalid:443"], allow_localhost=False, log_only=True):
            _audit_hook("socket.getaddrinfo", ("other.invalid", 443, 0, 0, 0))
        assert list(_core._allowed_hostnames) == ["other.invalid"]
        assert [call[0] for call in no_dns] == ["other.invalid"]


class TestFallbackSkippedWhenRawIPAllowed:
    """A connect to an unmapped address that every layer already allows by IP
    does not re-resolve the candidate hostnames: no name could change the
    outcome, and the search costs a DNS lookup per candidate.
    """

    @staticmethod
    def _seed_candidate():
        with _ip_map_lock:
            _core._allowed_hostnames["api.example.com"] = None

    @staticmethod
    def _record_resolves(monkeypatch) -> list[str]:
        calls: list[str] = []

        def fake_getaddrinfo(host, *args, **kwargs):
            calls.append(host)
            return []

        monkeypatch.setattr(_core._csocket, "getaddrinfo", fake_getaddrinfo)
        return calls

    def test_cidr_allowed_ip_skips_fallback(self, monkeypatch):
        tethered.activate(allow=["api.example.com", "198.51.100.0/24"])
        self._seed_candidate()
        calls = self._record_resolves(monkeypatch)
        _audit_hook("socket.connect", (None, ("198.51.100.7", 443)))
        assert calls == []

    def test_loopback_skips_fallback(self, monkeypatch):
        tethered.activate(allow=["api.example.com"])
        self._seed_candidate()
        calls = self._record_resolves(monkeypatch)
        _audit_hook("socket.connect", (None, ("127.0.0.1", 6379)))
        assert calls == []

    def test_ip_not_allowed_still_falls_back(self, monkeypatch):
        tethered.activate(allow=["api.example.com"])
        self._seed_candidate()
        calls = self._record_resolves(monkeypatch)
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.connect", (None, ("203.0.113.9", 443)))
        assert calls == ["api.example.com"]

    def test_scope_that_denies_the_ip_still_falls_back(self, monkeypatch):
        tethered.activate(allow=["api.example.com", "198.51.100.0/24"])
        self._seed_candidate()
        calls = self._record_resolves(monkeypatch)
        with (
            tethered.scope(allow=["api.example.com"], label="names-only"),
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            _audit_hook("socket.connect", (None, ("198.51.100.7", 443)))
        assert exc_info.value.scope_label == "names-only"
        assert calls == ["api.example.com"]

    def test_policy_error_is_not_treated_as_allowed(self, monkeypatch):
        tethered.activate(allow=["198.51.100.0/24"])
        cfg = _core._config
        assert _core._allowed_by_every_layer(cfg, (), "198.51.100.7", 443) is True
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        assert _core._allowed_by_every_layer(cfg, (), "198.51.100.7", 443) is False


class TestFallbackResolve:
    """Direct unit tests for ``_fallback_resolve`` (DNS-divergence repair).

    Mocks ``_csocket.getaddrinfo`` (non-locked path) and ``_c_guardian.is_active`` /
    ``_c_guardian.resolve`` (locked path) so the tests stay offline.  Exercises:

    - Empty candidate pool → returns ``None`` immediately.
    - Match found → returns hostname AND enriches ``_ip_to_hostname``.
    - No match → returns ``None`` after iterating all candidates.
    - Per-hostname resolve exceptions → swallowed; loop continues.
    - Bound by ``_FALLBACK_RESOLVE_MAX_CANDIDATES``.
    - LRU eviction of ``_ip_to_hostname`` during enrichment.
    - Locked-mode branch routes through ``_c_guardian.resolve``.
    """

    @staticmethod
    def _fake_addrinfo(*ips):
        """Build a fake getaddrinfo result list for the given IPs."""
        return [(0, 0, 0, "", (ip, 0)) for ip in ips]

    def test_returns_none_when_no_candidates(self):
        """Empty ``_allowed_hostnames`` → no work, immediate ``None``."""
        # No activate() and the cleanup fixture clears the pool, so we start empty.
        assert _core._fallback_resolve("203.0.113.1", 443) is None

    def test_finds_matching_ip(self, monkeypatch):
        """Re-resolve hits and returns the matching hostname."""
        tethered.activate(allow=["*.example.com"])
        with _ip_map_lock:
            _core._allowed_hostnames["api.example.com"] = None

        monkeypatch.setattr(
            _core._csocket,
            "getaddrinfo",
            lambda *a, **kw: self._fake_addrinfo("203.0.113.99"),
        )
        assert _core._fallback_resolve("203.0.113.99", 443) == "api.example.com"
        # IP map enriched for the fast path on the next connect.
        with _ip_map_lock:
            assert _ip_to_hostname.get("203.0.113.99") == ("api.example.com",)

    def test_returns_none_when_no_candidate_matches(self, monkeypatch):
        """All candidates resolve, none match the target IP → ``None``."""
        tethered.activate(allow=["*.example.com"])
        with _ip_map_lock:
            _core._allowed_hostnames["a.example.com"] = None
            _core._allowed_hostnames["b.example.com"] = None

        monkeypatch.setattr(
            _core._csocket,
            "getaddrinfo",
            lambda host, *a, **kw: self._fake_addrinfo("198.51.100.1"),
        )
        assert _core._fallback_resolve("203.0.113.99", 443) is None

    def test_per_hostname_exception_swallowed(self, monkeypatch):
        """A failing resolve doesn't abort the search — next candidate still tried."""
        tethered.activate(allow=["*.example.com"])
        # Insert ``good`` first so it's the OLDER entry; ``bad`` becomes the
        # newest and is tried FIRST (LRU iteration is newest-first).  The bad
        # one raises, exception is swallowed, the loop continues to ``good``
        # which matches.
        with _ip_map_lock:
            _core._allowed_hostnames.clear()
            _core._allowed_hostnames["good.example.com"] = None
            _core._allowed_hostnames["bad.example.com"] = None

        def fake(host, *a, **kw):
            if host == "good.example.com":
                return self._fake_addrinfo("203.0.113.42")
            raise OSError("simulated resolver failure")

        monkeypatch.setattr(_core._csocket, "getaddrinfo", fake)
        assert _core._fallback_resolve("203.0.113.42", 443) == "good.example.com"

    def test_bounded_by_max_candidates(self, monkeypatch):
        """Iteration stops at ``_FALLBACK_RESOLVE_MAX_CANDIDATES`` even when no match."""
        tethered.activate(allow=["*.example.com"])
        # Fill candidates with more than the cap.
        with _ip_map_lock:
            _core._allowed_hostnames.clear()
            for i in range(_core._FALLBACK_RESOLVE_MAX_CANDIDATES + 20):
                _core._allowed_hostnames[f"h{i}.example.com"] = None

        call_count = 0

        def fake(*a, **kw):
            nonlocal call_count
            call_count += 1
            return self._fake_addrinfo("198.51.100.1")  # never matches target

        monkeypatch.setattr(_core._csocket, "getaddrinfo", fake)
        assert _core._fallback_resolve("203.0.113.99", 443) is None
        assert call_count == _core._FALLBACK_RESOLVE_MAX_CANDIDATES

    def test_enrichment_evicts_when_ip_map_full(self, monkeypatch):
        """During enrichment, hitting ``_IP_MAP_MAX_SIZE`` triggers LRU eviction."""
        tethered.activate(allow=["*.example.com"])
        with _ip_map_lock:
            _core._allowed_hostnames.clear()
            _core._allowed_hostnames["h.example.com"] = None
            _ip_to_hostname.clear()
            # Fill IP map to capacity with sentinel entries.
            for i in range(_IP_MAP_MAX_SIZE):
                _ip_to_hostname[f"10.0.0.{i}"] = ("old.example.com",)

        monkeypatch.setattr(
            _core._csocket,
            "getaddrinfo",
            lambda *a, **kw: self._fake_addrinfo("203.0.113.42"),
        )
        result = _core._fallback_resolve("203.0.113.42", 443)
        assert result == "h.example.com"
        with _ip_map_lock:
            # The new IP was inserted; the oldest sentinel was evicted.
            assert "203.0.113.42" in _ip_to_hostname
            assert "10.0.0.0" not in _ip_to_hostname
            assert len(_ip_to_hostname) == _IP_MAP_MAX_SIZE

    def test_enrichment_updates_existing_ip_entry(self, monkeypatch):
        """When re-resolution returns an IP already in the map, the entry is refreshed."""
        tethered.activate(allow=["*.example.com"])
        with _ip_map_lock:
            _core._allowed_hostnames["new.example.com"] = None
            _ip_to_hostname["203.0.113.5"] = ("stale.example.com",)

        monkeypatch.setattr(
            _core._csocket,
            "getaddrinfo",
            lambda *a, **kw: self._fake_addrinfo("203.0.113.5"),
        )
        assert _core._fallback_resolve("203.0.113.5", 443) == "new.example.com"
        with _ip_map_lock:
            # Most recent name first; the earlier name for the address is kept.
            assert _ip_to_hostname["203.0.113.5"] == ("new.example.com", "stale.example.com")

    def test_locked_mode_routes_through_c_guardian(self, monkeypatch):
        """When the C guardian is active, ``_fallback_resolve`` calls its trusted resolve."""
        tethered.activate(allow=["*.example.com"])
        with _ip_map_lock:
            _core._allowed_hostnames["api.example.com"] = None

        # Pretend the C guardian is active even though it isn't (mock both probes).
        monkeypatch.setattr(_core, "_c_guardian", _FakeGuardian())
        assert _core._fallback_resolve("203.0.113.7", 443) == "api.example.com"

    def test_recent_first_iteration_order(self, monkeypatch):
        """Most-recently-allowed hostname is tried first (LRU order, newest-first)."""
        tethered.activate(allow=["*.example.com"])
        with _ip_map_lock:
            _core._allowed_hostnames.clear()
            _core._allowed_hostnames["old.example.com"] = None
            _core._allowed_hostnames["new.example.com"] = None  # most-recent

        attempted: list[str] = []

        def fake(host, *a, **kw):
            attempted.append(host)
            return self._fake_addrinfo("203.0.113.99")  # always matches

        monkeypatch.setattr(_core._csocket, "getaddrinfo", fake)
        assert _core._fallback_resolve("203.0.113.99", 443) == "new.example.com"
        assert attempted == ["new.example.com"]  # stopped at first match

    def test_handle_connect_calls_fallback_on_miss(self, monkeypatch):
        """The miss path in ``_handle_connect`` invokes ``_fallback_resolve``.

        Simulates DNS divergence: ``api.example.com`` is in the allowed-pool
        (passed a prior global getaddrinfo check), but the IP CPython is
        connecting to (``203.0.113.42``) was not seen by tethered's earlier
        resolution.  Without the fallback, this would raise ``EgressBlocked``;
        with it, the fallback re-resolves and finds the match.
        """
        tethered.activate(allow=["api.example.com"])
        with _ip_map_lock:
            _core._allowed_hostnames["api.example.com"] = None
            # Note: _ip_to_hostname does NOT contain ``203.0.113.42`` — that's
            # the divergence we're simulating.

        monkeypatch.setattr(
            _core._csocket,
            "getaddrinfo",
            lambda *a, **kw: self._fake_addrinfo("203.0.113.42"),
        )
        # No EgressBlocked should be raised.
        _audit_hook("socket.connect", (None, ("203.0.113.42", 443)))
        # The fallback enriched the map; future connects take the fast path.
        with _ip_map_lock:
            assert _ip_to_hostname.get("203.0.113.42") == ("api.example.com",)

    def test_handle_connect_blocks_when_fallback_finds_no_match(self, monkeypatch):
        """A genuinely-disallowed IP is still blocked after the fallback.

        Fallback iterates the candidate pool, none resolves to the target IP,
        returns ``None`` — the connect-time policy check then sees the bare
        IP, which doesn't match any hostname allow rule, and blocks.
        """
        tethered.activate(allow=["api.example.com"])
        with _ip_map_lock:
            _core._allowed_hostnames["api.example.com"] = None

        monkeypatch.setattr(
            _core._csocket,
            "getaddrinfo",
            # Candidate resolves to a different IP than the connect target.
            lambda *a, **kw: self._fake_addrinfo("198.51.100.1"),
        )
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.connect", (None, ("203.0.113.99", 443)))


class TestSelfIntrospectionExemption:
    """Self-introspection of the local hostname is exempt from the policy check.

    ``socket.getfqdn()``, ``gethostbyaddr(gethostname())``, and similar paths
    consult the local resolver / ``/etc/hosts`` / NSS to retrieve the canonical
    name string — no network connection is made.  Affects any caller that
    introspects its own machine identity: ``smtplib`` HELO/EHLO,
    ``email.utils.make_msgid``, the stdlib ``logging.handlers.SMTPHandler``
    (and its downstream users like Django's ``AdminEmailHandler``),
    ``paramiko``/``fabric`` host-identification code, etc.  Prior to the
    exemption, the policy check ran on the local hostname (often a
    container or VM short ID that doesn't match any allow rule), blocking
    these introspection paths.  The most visible production failure mode
    was the Django email-on-error cascade — any logged 4xx escalated into
    a 500 because ``AdminEmailHandler.emit()`` couldn't build its message
    — but the fix is general.

    Scope: ONLY the DNS-lookup audit-hook path is exempted.  Connect-time
    enforcement on the IP the hostname resolves to is unchanged.
    """

    @staticmethod
    def _local_hostname() -> str:
        """Return the same captured hostname tethered uses internally."""
        return _core._capture_local_hostname()

    def test_capture_local_hostname_returns_normalized_string(self):
        """``_capture_local_hostname`` returns the OS hostname, normalized."""
        assert isinstance(self._local_hostname(), str)
        # Real OSes always have a hostname; an empty result would point to a
        # broken environment, which is fine for the helper but uninteresting
        # for this test.
        assert self._local_hostname()

    def test_getfqdn_succeeds_without_blocking(self):
        """``socket.getfqdn()`` returns the FQDN string without raising."""
        tethered.activate(allow=["api.example.com"])
        # Returns a string; never raises EgressBlocked.
        result = socket.getfqdn()
        assert isinstance(result, str)
        assert result  # non-empty in any sane environment

    def test_gethostbyaddr_of_gethostname_succeeds(self):
        """``gethostbyaddr(gethostname())`` is the cascading-failure path."""
        tethered.activate(allow=["api.example.com"])
        local = self._local_hostname()
        # gethostbyaddr may return OSError if the hostname isn't resolvable
        # (common in stripped Docker images), but it must not raise
        # EgressBlocked from tethered.
        try:
            socket.gethostbyaddr(local)
        except OSError:
            pass  # acceptable — we're testing tethered doesn't block

    def test_gethostbyname_of_gethostname_succeeds(self):
        """``gethostbyname(gethostname())`` also bypasses the policy check."""
        tethered.activate(allow=["api.example.com"])
        local = self._local_hostname()
        try:
            socket.gethostbyname(local)
        except OSError:
            pass

    def test_getaddrinfo_of_gethostname_succeeds(self):
        """``getaddrinfo(gethostname(), 0)`` also bypasses the policy check."""
        tethered.activate(allow=["api.example.com"])
        local = self._local_hostname()
        try:
            socket.getaddrinfo(local, 0)
        except OSError:
            pass

    def test_unrelated_hostname_still_blocked(self):
        """Sanity: only the captured hostname is exempt; other names still block."""
        tethered.activate(allow=["api.example.com"])
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.gethostbyaddr", ("evil.attacker.com",))

    def test_handle_dns_lookup_short_circuit(self):
        """Direct ``_handle_dns_lookup`` call short-circuits for the local hostname."""
        tethered.activate(allow=["api.example.com"])
        local = self._local_hostname()
        # Should not raise; should not log a block.
        _audit_hook("socket.gethostbyaddr", (local,))

    def test_handle_getaddrinfo_short_circuit(self):
        """Direct ``_handle_getaddrinfo`` call short-circuits for the local hostname."""
        tethered.activate(allow=["api.example.com"])
        local = self._local_hostname()
        # Should not raise; should not populate the IP map (no resolve runs
        # on the short-circuit path).
        with _ip_map_lock:
            initial_size = len(_ip_to_hostname)
        _audit_hook("socket.getaddrinfo", (local, 0, 0, 0, 0))
        with _ip_map_lock:
            # The short-circuit returns before the resolve+populate step.
            assert len(_ip_to_hostname) == initial_size

    def test_empty_local_hostname_disables_exemption(self, monkeypatch):
        """If ``_local_hostname`` is empty, no hostname is exempted."""
        # Capture a real hostname first, then construct a Config with an empty
        # local hostname to verify the exemption is gated on non-empty value.
        tethered.activate(allow=["api.example.com"])
        # Mutate the frozen field via object.__setattr__ for the test (in
        # locked mode this would be detected, but we're not locked here).
        cfg = _core._config
        assert cfg is not None
        object.__setattr__(cfg, "_local_hostname", "")
        # Even a connection to the real local hostname is now subject to
        # the normal policy check (which blocks it).
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook(
                "socket.gethostbyaddr",
                (self._local_hostname(),),
            )

    def test_self_introspection_does_not_widen_connect(self):
        """The exemption applies ONLY to DNS lookups, not to connect.

        A connect to a non-loopback IP is blocked even if that IP would be
        reachable via ``gethostname()`` resolution.  This is the security
        property the surgical fix preserves: the cascade is fixed, but no
        new egress is allowed.
        """
        tethered.activate(allow=["api.example.com"])
        # Pretend the hostname resolves to a non-loopback IP.  The connect
        # to that IP must still be blocked (the exemption is DNS-only).
        with pytest.raises(tethered.EgressBlocked):
            _audit_hook("socket.connect", (None, ("203.0.113.42", 80)))


class _FakeGuardian:
    """Minimal stand-in for the C guardian used by ``TestFallbackResolve``."""

    def is_active(self) -> bool:
        return True

    def resolve(self, host, port, family, socktype, proto, flags):
        return [(0, 0, 0, "", ("203.0.113.7", 0))]


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
                        _ip_to_hostname[f"10.0.0.{i % 256}"] = (f"host{i}.stripe.com",)
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
            _ip_to_hostname["198.51.100.1"] = ("api.stripe.com",)

        tethered.deactivate()

        with _ip_map_lock:
            assert len(_ip_to_hostname) == 0

    def test_ip_map_not_carried_across_reactivation(self):
        """IP map from old policy should not affect new policy."""
        tethered.activate(allow=["*.stripe.com"])
        with _ip_map_lock:
            _ip_to_hostname["198.51.100.1"] = ("api.stripe.com",)

        tethered.deactivate()
        tethered.activate(allow=["*.example.com"])

        # The old IP mapping should be gone
        with _ip_map_lock:
            assert "198.51.100.1" not in _ip_to_hostname

    def test_ip_map_cleared_on_reactivate_without_deactivate(self):
        """activate() -> activate() (no deactivate) must clear the IP map."""
        tethered.activate(allow=["*.stripe.com"])
        with _ip_map_lock:
            _ip_to_hostname["198.51.100.1"] = ("api.stripe.com",)

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


class TestConftestEgressGuard:
    """Verify that the conftest egress guard blocks unexpected network access."""

    def test_dns_blocked_when_tethered_inactive(self):
        """Guard blocks DNS for non-allowed hosts when tethered is deactivated."""
        # _cleanup fixture has reset _core._config to None
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

    @requires_network
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
        """@scope() works on async functions.

        The lookup is made in the coroutine's own context, where the scope is
        visible, and ``scope_label`` proves the scope produced the block.  (A
        ``loop.getaddrinfo`` here would run in an executor thread that does
        not carry the scope, and only the conftest guard would refuse it.)
        """

        @tethered.scope(allow=["*.example.com"], label="async-decorator")
        async def guarded():
            socket.getaddrinfo("evil.test", 80)

        with pytest.raises(tethered.EgressBlocked) as exc_info:
            asyncio.run(guarded())
        assert exc_info.value.scope_label == "async-decorator"

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

    def test_generator_error_recommends_scoping_each_io_call(self):
        """The message must not recommend wrapping the body, yields included, in one scope."""
        with pytest.raises(TypeError) as exc_info:

            @tethered.scope(allow=["*.example.com"])
            def gen():
                yield 1

        message = str(exc_info.value)
        assert "each I/O call" in message
        assert "do not yield from inside one" in message
        assert "consumer's context" in message

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

        result = asyncio.run(guarded())
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
        """scope() as context manager inside an async function.

        The lookup is made in the task's own context, where the scope is
        visible.  ``scope_label`` proves the scope produced the block: the
        conftest guard raises ``EgressBlocked`` too, without a label.
        """
        with (
            tethered.scope(allow=["*.example.com"], label="async-cm"),
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            socket.getaddrinfo("evil.test", 80)
        assert exc_info.value.scope_label == "async-cm"

    @pytest.mark.asyncio
    async def test_executor_lookup_is_recorded_but_not_checked_by_the_scope(self):
        """``loop.getaddrinfo`` runs in an executor thread that does not carry the scope.

        The scope's DNS-time check cannot run there (a documented limit), so
        the lookup itself goes through.  It is recorded, though, and the
        connect that follows in the scope's own context is judged by the scope
        under the name it was resolved from.
        """
        loop = asyncio.get_running_loop()
        with tethered.scope(allow=[], allow_localhost=False, label="deny-all"):
            await loop.getaddrinfo("localhost", 80, family=socket.AF_INET)
            with _ip_map_lock:
                assert "localhost" in _ip_to_hostname.get("127.0.0.1", ())
            with pytest.raises(tethered.EgressBlocked) as exc_info:
                _audit_hook("socket.connect", (None, ("127.0.0.1", 80)))
        assert exc_info.value.scope_label == "deny-all"
        assert exc_info.value.resolved_from == "localhost"

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


def _run_on_loop(main, loop_factory):
    """Run ``main()`` to completion on a fresh event loop made by ``loop_factory``."""
    if sys.version_info >= (3, 12):
        return asyncio.run(main(), loop_factory=loop_factory)
    loop = loop_factory()
    try:
        return loop.run_until_complete(main())
    finally:
        loop.run_until_complete(loop.shutdown_default_executor())
        loop.close()


def _run_on_selector_loop(main):
    """Run ``main()`` to completion on a fresh ``asyncio.SelectorEventLoop``.

    Connect-time enforcement needs a selector loop: the Proactor loop (the
    Windows default) connects without raising a ``socket.connect`` audit event.
    """
    return _run_on_loop(main, asyncio.SelectorEventLoop)


@contextlib.asynccontextmanager
async def _loopback_server():
    """An asyncio TCP server on 127.0.0.1 that closes each connection; yields its port."""
    server = await asyncio.start_server(lambda reader, writer: writer.close(), "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


def _in_thread(fn, *args):
    """Run ``fn(*args)`` in a new thread whose context has no scope stack; re-raise its error.

    The empty context is explicit because Python 3.14 can start threads with a
    copy of the caller's context (``sys.flags.thread_inherit_context``), and
    these tests are about code that does not see the caller's scopes.
    """
    errors: list[BaseException] = []

    def target():
        try:
            contextvars.Context().run(fn, *args)
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=target)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive()
    if errors:
        raise errors[0]


class TestScopeUnderAsyncio:
    """A scope holds for asyncio connections made by hostname.

    ``loop.getaddrinfo`` runs ``socket.getaddrinfo`` in an executor thread,
    which does not carry the caller's context.  The lookup is recorded there
    anyway while any scope is active, so the connect — which does run in the
    scope's context — is matched to the hostname and judged by the scope.

    Every block asserts ``scope_label``: the conftest guard also raises
    ``EgressBlocked`` in threads where it sees no tethered state, and must not
    be able to satisfy these tests.
    """

    def test_scope_alone_allows_the_host_it_names(self):
        async def main():
            async with _loopback_server() as port:
                with tethered.scope(allow=["localhost"], allow_localhost=False, label="lib"):
                    _reader, writer = await asyncio.open_connection(
                        "localhost", port, family=socket.AF_INET
                    )
                    writer.close()
                    await writer.wait_closed()

        _run_on_selector_loop(main)
        assert _core._active_scope_count == 0

    def test_scope_alone_blocks_a_host_it_does_not_name(self):
        async def main():
            async with _loopback_server() as port:
                with (
                    tethered.scope(allow=["other.invalid"], allow_localhost=False, label="lib"),
                    pytest.raises(tethered.EgressBlocked) as exc_info,
                ):
                    await asyncio.open_connection("localhost", port, family=socket.AF_INET)
            return exc_info.value

        exc = _run_on_selector_loop(main)
        assert exc.scope_label == "lib"
        assert exc.resolved_from == "localhost"

    def test_global_policy_and_scope_both_allow(self):
        async def main():
            async with _loopback_server() as port:
                # Activated here, not before the loop exists: on Windows a
                # selector loop needs a loopback socket pair to start.
                tethered.activate(allow=["localhost"], allow_localhost=False)
                try:
                    with tethered.scope(allow=["localhost"], allow_localhost=False, label="lib"):
                        _reader, writer = await asyncio.open_connection(
                            "localhost", port, family=socket.AF_INET
                        )
                        writer.close()
                        await writer.wait_closed()
                finally:
                    tethered.deactivate()

        _run_on_selector_loop(main)

    def test_global_policy_allows_but_scope_blocks(self):
        async def main():
            async with _loopback_server() as port:
                tethered.activate(allow=["localhost"], allow_localhost=False)
                try:
                    with (
                        tethered.scope(allow=["other.invalid"], allow_localhost=False, label="lib"),
                        pytest.raises(tethered.EgressBlocked) as exc_info,
                    ):
                        await asyncio.open_connection("localhost", port, family=socket.AF_INET)
                finally:
                    tethered.deactivate()
            return exc_info.value

        exc = _run_on_selector_loop(main)
        assert exc.scope_label == "lib"
        assert exc.resolved_from == "localhost"

    def test_global_policy_blocks_the_lookup_inside_an_allowing_scope(self):
        """The global policy is process-wide, so it is enforced in the executor thread."""

        async def main():
            async with _loopback_server() as port:
                tethered.activate(allow=["other.invalid"], allow_localhost=False)
                try:
                    with (
                        tethered.scope(allow=["localhost"], allow_localhost=False, label="lib"),
                        pytest.raises(tethered.EgressBlocked) as exc_info,
                    ):
                        await asyncio.open_connection("localhost", port, family=socket.AF_INET)
                finally:
                    tethered.deactivate()
            return exc_info.value

        exc = _run_on_selector_loop(main)
        assert exc.host == "localhost"
        assert exc.scope_label is None

    # ── The mechanism, without an event loop ──

    def test_lookup_in_another_thread_is_recorded_while_a_scope_is_active(self, fake_dns):
        fake_dns.table["api.example.com"] = ["203.0.113.7"]
        lookup = ("socket.getaddrinfo", ("api.example.com", 443, 0, 0, 0))
        with tethered.scope(allow=["api.example.com"], allow_localhost=False, label="lib"):
            _in_thread(_audit_hook, *lookup)
            with _ip_map_lock:
                assert _ip_to_hostname["203.0.113.7"] == ("api.example.com",)
            assert "api.example.com" in _core._allowed_hostnames
            _audit_hook("socket.connect", (None, ("203.0.113.7", 443)))

    def test_recorded_lookup_is_judged_by_the_connecting_scope(self, fake_dns):
        fake_dns.table["other.example.com"] = ["203.0.113.7"]
        lookup = ("socket.getaddrinfo", ("other.example.com", 443, 0, 0, 0))
        with tethered.scope(allow=["api.example.com"], allow_localhost=False, label="lib"):
            _in_thread(_audit_hook, *lookup)  # no scope there: recorded, not refused
            with pytest.raises(tethered.EgressBlocked) as exc_info:
                _audit_hook("socket.connect", (None, ("203.0.113.7", 443)))
        assert exc_info.value.scope_label == "lib"
        assert exc_info.value.resolved_from == "other.example.com"

    def test_nothing_is_enforced_in_the_thread_without_scopes(self, fake_dns):
        def unscoped():
            _audit_hook("socket.getaddrinfo", ("other.example.com", 443, 0, 0, 0))
            _audit_hook("socket.getaddrinfo", (b"\xff", 443, 0, 0, 0))
            _audit_hook("socket.gethostbyname", ("other.example.com",))
            _audit_hook("socket.gethostbyaddr", ("203.0.113.9",))
            _audit_hook("socket.connect", (None, ("203.0.113.9", 443)))

        with tethered.scope(allow=[], allow_localhost=False):
            _in_thread(unscoped)
        # Only the readable getaddrinfo led to a lookup of tethered's own.
        assert [call[0] for call in fake_dns.calls] == ["other.example.com"]

    def test_no_scope_anywhere_keeps_the_immediate_return(self, no_dns):
        _core._install_hook()
        assert _core._active_scope_count == 0
        _audit_hook("socket.getaddrinfo", ("api.example.com", 443, 0, 0, 0))
        assert no_dns == []
        assert not _core._allowed_hostnames

    def test_recording_stops_when_the_last_scope_exits(self, no_dns):
        with tethered.scope(allow=[]):
            pass
        _in_thread(_audit_hook, "socket.getaddrinfo", ("api.example.com", 443, 0, 0, 0))
        assert no_dns == []


class TestActiveScopeCount:
    """``_active_scope_count`` tracks scope entries across every context."""

    def test_context_manager_and_nesting(self):
        assert _core._active_scope_count == 0
        with tethered.scope(allow=[]):
            assert _core._active_scope_count == 1
            with tethered.scope(allow=[]):
                assert _core._active_scope_count == 2
            assert _core._active_scope_count == 1
        assert _core._active_scope_count == 0

    def test_exception_in_block(self):
        with pytest.raises(ValueError, match="boom"), tethered.scope(allow=[]):
            raise ValueError("boom")
        assert _core._active_scope_count == 0

    def test_failed_reentry_is_not_counted(self):
        s = tethered.scope(allow=[])
        with s:
            with pytest.raises(RuntimeError, match="already entered"), s:
                pass  # pragma: no cover
            assert _core._active_scope_count == 1
        assert _core._active_scope_count == 0

    def test_sync_decorator(self):
        seen: list[int] = []

        @tethered.scope(allow=[])
        def guarded(fail: bool) -> None:
            seen.append(_core._active_scope_count)
            if fail:
                raise ValueError("boom")

        guarded(False)
        with pytest.raises(ValueError, match="boom"):
            guarded(True)
        assert seen == [1, 1]
        assert _core._active_scope_count == 0

    def test_async_decorator(self):
        seen: list[int] = []

        @tethered.scope(allow=[])
        async def guarded(fail: bool) -> None:
            seen.append(_core._active_scope_count)
            if fail:
                raise ValueError("boom")

        asyncio.run(guarded(False))
        with pytest.raises(ValueError, match="boom"):
            asyncio.run(guarded(True))
        assert seen == [1, 1]
        assert _core._active_scope_count == 0

    def test_scopes_in_other_threads_are_counted(self):
        entered, release = threading.Event(), threading.Event()

        def hold_scope():
            with tethered.scope(allow=[]):
                entered.set()
                release.wait(timeout=10)

        worker = threading.Thread(target=hold_scope)
        worker.start()
        try:
            assert entered.wait(timeout=10)
            assert _scopes.get() == ()  # not on this thread's stack ...
            assert _core._active_scope_count == 1  # ... but counted process-wide
        finally:
            release.set()
            worker.join(timeout=10)
        assert _core._active_scope_count == 0

    def test_concurrent_enter_and_exit_balance(self):
        def churn():
            for _ in range(300):
                with tethered.scope(allow=[]), tethered.scope(allow=[]):
                    pass

        workers = [threading.Thread(target=churn) for _ in range(8)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=30)
        assert _core._active_scope_count == 0

    def test_inherited_scopes_are_counted(self):
        _autoactivate._inherit_scopes(
            [
                {"allow": ["api.example.com"], "label": "one"},
                {"allow": ["api.example.com"], "label": "two"},
                "not-a-scope",
            ]
        )
        assert len(_scopes.get()) == 2
        assert _core._active_scope_count == 2

    def test_never_negative(self):
        _core._adjust_scope_count(-3)
        assert _core._active_scope_count == 0


class _FakeProactorLoop(asyncio.proactor_events.BaseProactorEventLoop):
    """Has the type of a Proactor loop without being one; usable on any platform."""

    _closed = True  # keeps BaseEventLoop.__del__ quiet

    def __init__(self) -> None:
        pass


def _proactor_warnings(caplog) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if "ProactorEventLoop" in record.getMessage()
    ]


_NEW_SOCKET_EVENT = ("socket.__new__", (None, socket.AF_INET, socket.SOCK_STREAM, 0))


class TestProactorLoopWarning:
    """asyncio's ProactorEventLoop (the Windows default) bypasses connect-time checks.

    It connects through ``_overlapped.ConnectEx``, which raises no
    ``socket.connect`` audit event, so tethered cannot enforce there.  It warns
    once instead, when a socket is created under an active policy or scope
    while such a loop is running.
    """

    # ── Detection helper (platform-independent) ──

    def test_not_running_when_asyncio_is_not_imported(self, monkeypatch):
        with monkeypatch.context() as patch:
            patch.setitem(sys.modules, "asyncio", None)
            assert _core._proactor_loop_running() is False

    def test_not_running_when_proactor_support_is_not_imported(self, monkeypatch):
        with monkeypatch.context() as patch:
            patch.setitem(sys.modules, "asyncio.proactor_events", None)
            assert _core._proactor_loop_running() is False

    def test_not_running_without_an_event_loop(self):
        assert _core._proactor_loop_running() is False

    def test_not_running_on_a_selector_loop(self):
        async def main() -> bool:
            return _core._proactor_loop_running()

        assert _run_on_selector_loop(main) is False

    def test_running_when_the_loop_is_a_proactor_loop(self, monkeypatch):
        monkeypatch.setattr(asyncio, "_get_running_loop", _FakeProactorLoop)
        assert _core._proactor_loop_running() is True

    def test_not_running_when_asyncio_is_unusable(self, monkeypatch):
        def broken():
            raise RuntimeError("half-imported asyncio")

        monkeypatch.setattr(asyncio, "_get_running_loop", broken)
        assert _core._proactor_loop_running() is False

    # ── The one-time warning (platform-independent: flag and loop are simulated) ──

    def test_warns_once_under_an_active_policy(self, monkeypatch, caplog):
        monkeypatch.setattr(_core, "_proactor_warning_pending", True)
        monkeypatch.setattr(asyncio, "_get_running_loop", _FakeProactorLoop)
        tethered.activate(allow=["*.example.com"])
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _audit_hook(*_NEW_SOCKET_EVENT)
            _audit_hook(*_NEW_SOCKET_EVENT)
        messages = _proactor_warnings(caplog)
        assert len(messages) == 1
        assert "connect-time enforcement is unavailable" in messages[0]
        assert "only DNS-time hostname checks apply" in messages[0]
        assert "asyncio.SelectorEventLoop" in messages[0]
        assert _core._proactor_warning_pending is False

    def test_warns_under_a_scope_alone(self, monkeypatch, caplog):
        monkeypatch.setattr(_core, "_proactor_warning_pending", True)
        monkeypatch.setattr(asyncio, "_get_running_loop", _FakeProactorLoop)
        with caplog.at_level(logging.WARNING, logger="tethered"), tethered.scope(allow=[]):
            _audit_hook(*_NEW_SOCKET_EVENT)
        assert len(_proactor_warnings(caplog)) == 1

    def test_no_warning_when_nothing_is_active(self, monkeypatch, caplog):
        monkeypatch.setattr(_core, "_proactor_warning_pending", True)
        monkeypatch.setattr(asyncio, "_get_running_loop", _FakeProactorLoop)
        _core._install_hook()
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _audit_hook(*_NEW_SOCKET_EVENT)
        assert _proactor_warnings(caplog) == []
        assert _core._proactor_warning_pending is True

    def test_no_warning_without_a_proactor_loop(self, monkeypatch, caplog):
        monkeypatch.setattr(_core, "_proactor_warning_pending", True)
        tethered.activate(allow=["*.example.com"])
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _audit_hook(*_NEW_SOCKET_EVENT)
        assert _proactor_warnings(caplog) == []
        assert _core._proactor_warning_pending is True  # still to be checked later

    def test_no_check_at_all_once_the_flag_is_clear(self, monkeypatch):
        """Other platforms, and Windows after the warning: the detection never runs."""

        def must_not_run() -> bool:
            raise AssertionError("loop detection ran with the flag clear")

        monkeypatch.setattr(_core, "_proactor_warning_pending", False)
        monkeypatch.setattr(_core, "_proactor_loop_running", must_not_run)
        tethered.activate(allow=["*.example.com"])
        _audit_hook(*_NEW_SOCKET_EVENT)

    def test_flag_starts_set_only_on_windows(self):
        if sys.platform != "win32":
            assert _core._proactor_warning_pending is False

    # ── The real loop ──

    @pytest.mark.skipif(sys.platform != "win32", reason="ProactorEventLoop is Windows-only")
    def test_real_proactor_loop_warns_once_and_connect_is_not_blocked(self, monkeypatch, caplog):
        """Documents the gap: under deny-all, the Proactor loop still connects.

        A blocking socket in the same policy is blocked; ``asyncio.open_connection``
        on the Proactor loop is not, because no ``socket.connect`` event is
        raised for it.  tethered says so once.
        """
        monkeypatch.setattr(_core, "_proactor_warning_pending", True)

        async def main() -> None:
            async with _loopback_server() as port:
                tethered.activate(allow=[], allow_localhost=False)
                try:
                    with socket.socket() as blocking, pytest.raises(tethered.EgressBlocked):
                        blocking.connect(("127.0.0.1", port))
                    for _ in range(2):
                        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
                        writer.close()
                        await writer.wait_closed()
                finally:
                    tethered.deactivate()

        with caplog.at_level(logging.WARNING, logger="tethered"):
            _run_on_loop(main, asyncio.ProactorEventLoop)
        assert len(_proactor_warnings(caplog)) == 1
        assert _core._proactor_warning_pending is False


def _labels() -> list[str]:
    """Labels on the current context's scope stack, outermost first."""
    return [sc.label for sc in _scopes.get()]


def _scoped_generator(label: str):
    """A generator that yields twice from inside a deny-all scope."""
    with tethered.scope(allow=[], allow_localhost=False, label=label):
        yield 1
        yield 2


class TestScopeExitOutOfOrder:
    """A scope's exit removes its own entry, whatever was entered or exited since.

    Scopes normally nest, but a generator suspended inside ``with scope():``
    exits whenever its consumer resumes it.  Exit used to restore the stack
    snapshot taken at entry, which deleted scopes entered in between and
    resurrected ones that had already exited.
    """

    def test_generator_exit_keeps_the_callers_scope(self):
        gen = _scoped_generator("GEN")
        assert next(gen) == 1
        # Inherent to generators and context variables: between yields the
        # scope sits on the consumer's stack.
        assert _labels() == ["GEN"]

        with tethered.scope(allow=[], allow_localhost=False, label="CALLER"):
            assert list(gen) == [2]  # GEN exits here, before CALLER
            assert _labels() == ["CALLER"]
            with pytest.raises(tethered.EgressBlocked) as exc_info:
                _audit_hook("socket.connect", (None, ("127.0.0.1", 9)))
            assert exc_info.value.scope_label == "CALLER"

        # ... and GEN does not come back when CALLER's block ends.
        assert _labels() == []
        assert _core._active_scope_count == 0

    def test_generator_exit_keeps_the_callers_scope_real_socket(self, tcp_listener):
        gen = _scoped_generator("GEN")
        next(gen)
        with tethered.scope(allow=[], allow_localhost=False, label="CALLER"):
            list(gen)
            with (
                socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client,
                pytest.raises(tethered.EgressBlocked) as exc_info,
            ):
                client.connect(("127.0.0.1", tcp_listener))
        assert exc_info.value.scope_label == "CALLER"
        assert _labels() == []

    def test_closing_a_suspended_generator_removes_its_scope(self):
        gen = _scoped_generator("GEN")
        next(gen)
        assert _labels() == ["GEN"]
        gen.close()
        assert _labels() == []
        assert _core._active_scope_count == 0

    def test_interleaved_generators(self):
        first, second = _scoped_generator("FIRST"), _scoped_generator("SECOND")
        next(first)
        next(second)
        assert _labels() == ["FIRST", "SECOND"]
        first.close()  # not the innermost entry
        assert _labels() == ["SECOND"]
        second.close()
        assert _labels() == []
        assert _core._active_scope_count == 0

    def test_in_order_nesting_is_unchanged(self):
        with tethered.scope(allow=[], label="OUTER"):
            with tethered.scope(allow=[], label="INNER"):
                assert _labels() == ["OUTER", "INNER"]
            assert _labels() == ["OUTER"]
        assert _labels() == []

    def test_sync_decorator_exit_keeps_a_scope_entered_inside_the_call(self):
        gen = _scoped_generator("GEN")

        @tethered.scope(allow=[], label="DECORATED")
        def start() -> list[str]:
            next(gen)
            return _labels()

        assert start() == ["DECORATED", "GEN"]
        assert _labels() == ["GEN"]  # the generator is still inside its scope
        gen.close()
        assert _labels() == []
        assert _core._active_scope_count == 0

    def test_sync_decorator_survives_an_exit_from_under_it(self):
        gen = _scoped_generator("GEN")
        next(gen)

        @tethered.scope(allow=[], label="DECORATED")
        def finish() -> list[str]:
            gen.close()  # removes GEN from below DECORATED
            return _labels()

        assert finish() == ["DECORATED"]
        assert _labels() == []
        assert _core._active_scope_count == 0

    def test_async_decorator_exits_out_of_order(self):
        async def main() -> tuple[list[str], list[str], list[str]]:
            gen = _scoped_generator("GEN")

            @tethered.scope(allow=[], label="DECORATED")
            async def start() -> list[str]:
                next(gen)
                return _labels()

            inside = await start()
            after = _labels()
            gen.close()
            return inside, after, _labels()

        assert asyncio.run(main()) == (["DECORATED", "GEN"], ["GEN"], [])
        assert _core._active_scope_count == 0

    def test_recursive_decorated_call_removes_one_entry_per_exit(self):
        depths: list[int] = []

        @tethered.scope(allow=[], label="RECURSIVE")
        def descend(n: int) -> None:
            depths.append(len(_scopes.get()))
            if n:
                descend(n - 1)
            assert len(_scopes.get()) == depths[-1 - n]

        descend(2)
        assert depths == [1, 2, 3]
        assert _labels() == []
        assert _core._active_scope_count == 0

    def test_exit_in_another_context_warns_and_keeps_the_count_consistent(self, caplog):
        """A scope entered in one context and exited in another has nothing to remove."""
        outer = tethered.scope(allow=[], label="MINE")
        stray = tethered.scope(allow=[], label="STRAY")
        other_context = contextvars.copy_context()
        other_context.run(stray.__enter__)
        assert _core._active_scope_count == 1

        with outer, caplog.at_level(logging.WARNING, logger="tethered"):
            stray.__exit__(None, None, None)  # this context never entered it
            assert _labels() == ["MINE"]  # nobody else's entry was touched
        assert "STRAY was exited in a context that did not enter it" in caplog.text
        assert _labels() == []
        assert _core._active_scope_count == 0
        # The entry stays with the context that holds it.
        assert [sc.label for sc in other_context[_scopes]] == ["STRAY"]

    def test_instance_can_be_entered_again_after_exit(self):
        s = tethered.scope(allow=[], label="REUSED")
        for _ in range(2):
            with s:
                assert _labels() == ["REUSED"]
            assert _labels() == []

    def test_one_instance_shared_by_threads_leaves_no_entries_behind(self):
        """Contending threads may be refused entry, but none keeps a stale entry."""
        shared = tethered.scope(allow=[], label="SHARED")
        leftovers: list[list[str]] = []

        def churn():
            for _ in range(300):
                try:
                    with shared:
                        pass
                except RuntimeError:  # "already entered" — another thread is inside
                    pass
            leftovers.append(_labels())

        workers = [threading.Thread(target=churn) for _ in range(8)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=30)
        assert leftovers == [[]] * 8
        assert _core._active_scope_count == 0


class TestScopeThreading:
    """Test scope() thread isolation."""

    @requires_network
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

    @requires_network
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

    @requires_network
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


# One event of every kind tethered enforces, each for a destination that a
# deny-all policy (localhost exemption off) refuses.
_DENIED_EVENTS = [
    pytest.param("socket.connect", (None, ("192.0.2.1", 443)), id="connect"),
    pytest.param("socket.sendto", (None, ("192.0.2.1", 53)), id="sendto"),
    pytest.param("socket.sendmsg", (None, ("192.0.2.1", 53)), id="sendmsg"),
    pytest.param("socket.getaddrinfo", ("blocked.invalid", 443, 0, 0, 0), id="getaddrinfo"),
    pytest.param("socket.gethostbyname", ("blocked.invalid",), id="gethostbyname"),
    pytest.param("socket.gethostbyaddr", ("192.0.2.1",), id="gethostbyaddr"),
]


class TestLogOnlyDoesNotStopEnforcement:
    """A log-only layer reports a denial; it never switches off an enforcing layer.

    Every scope on the stack is evaluated.  Each denying log-only scope logs and
    calls its ``on_blocked``; the first denying enforcing scope raises.  A global
    log-only denial does not end the evaluation either.
    """

    @staticmethod
    def _monitor(seen: list[str], name: str = "monitor") -> tethered.scope:
        return tethered.scope(
            allow=[],
            allow_localhost=False,
            log_only=True,
            on_blocked=lambda h, p: seen.append(name),
            label=name,
        )

    @pytest.mark.parametrize(("event", "args"), _DENIED_EVENTS)
    def test_outer_log_only_inner_enforcing(self, no_dns, event, args):
        seen: list[str] = []
        with (
            self._monitor(seen),
            tethered.scope(allow=[], allow_localhost=False, label="enforcer"),
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            _audit_hook(event, args)
        assert exc_info.value.scope_label == "enforcer"
        assert seen == ["monitor"]
        assert no_dns == []

    @pytest.mark.parametrize(("event", "args"), _DENIED_EVENTS)
    def test_outer_enforcing_inner_log_only(self, no_dns, event, args):
        seen: list[str] = []
        with (
            tethered.scope(allow=[], allow_localhost=False, label="enforcer"),
            self._monitor(seen),
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            _audit_hook(event, args)
        assert exc_info.value.scope_label == "enforcer"
        assert seen == []  # the enforcing scope raised before the inner one was reached
        assert no_dns == []

    def test_real_audit_event_outer_log_only_inner_enforcing(self):
        """The same composition through ``sys.audit`` instead of a direct hook call."""
        with (
            tethered.scope(allow=[], allow_localhost=False, log_only=True),
            tethered.scope(allow=[], allow_localhost=False, label="enforcer"),
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            sys.audit("socket.connect", None, ("192.0.2.1", 443))
        assert exc_info.value.scope_label == "enforcer"

    @pytest.mark.parametrize(("event", "args"), _DENIED_EVENTS)
    def test_global_log_only_does_not_hide_enforcing_scope(self, no_dns, event, args):
        seen: list[str] = []
        tethered.activate(
            allow=[],
            allow_localhost=False,
            log_only=True,
            on_blocked=lambda h, p: seen.append("global"),
        )
        with (
            tethered.scope(allow=[], allow_localhost=False, label="enforcer"),
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            _audit_hook(event, args)
        assert exc_info.value.scope_label == "enforcer"
        assert seen == ["global"]
        assert no_dns == []

    @pytest.mark.parametrize(("event", "args"), _DENIED_EVENTS)
    def test_every_monitoring_layer_is_notified(self, no_dns, event, args):
        seen: list[str] = []
        tethered.activate(
            allow=[],
            allow_localhost=False,
            log_only=True,
            on_blocked=lambda h, p: seen.append("global"),
        )
        with self._monitor(seen, "outer"), self._monitor(seen, "inner"):
            _audit_hook(event, args)  # nothing enforces, so nothing raises
        assert seen == ["global", "outer", "inner"]
        # A name the global policy denied (log-only) is still not recorded.
        assert no_dns == []
        assert "blocked.invalid" not in _core._allowed_hostnames
        with _ip_map_lock:
            assert not _ip_to_hostname

    @pytest.mark.parametrize(("event", "args"), _DENIED_EVENTS)
    def test_only_the_monitoring_layer_denies(self, no_dns, event, args):
        seen: list[str] = []
        with (
            self._monitor(seen),
            tethered.scope(allow=["192.0.2.0/24", "*.invalid"], label="enforcer"),
        ):
            _audit_hook(event, args)
        assert seen == ["monitor"]

    @pytest.mark.parametrize(("event", "args"), _DENIED_EVENTS)
    def test_only_the_enforcing_layer_denies(self, no_dns, event, args):
        seen: list[str] = []
        with (
            tethered.scope(
                allow=["192.0.2.0/24", "*.invalid"],
                log_only=True,
                on_blocked=lambda h, p: seen.append("monitor"),
            ),
            tethered.scope(allow=[], allow_localhost=False, label="enforcer"),
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            _audit_hook(event, args)
        assert exc_info.value.scope_label == "enforcer"
        assert seen == []
        assert no_dns == []


class TestScopeHostnameOrIp:
    """Each scope may allow a connect by hostname or by IP; then all must allow.

    The rule is ``all(scope allows name OR scope allows ip)``, not
    ``all(scopes allow name) OR all(scopes allow ip)``.
    """

    def test_hostname_only_outer_ip_only_inner_real_socket(self, tcp_listener):
        with tethered.scope(allow=["localhost"], allow_localhost=False, label="by-name"):
            socket.getaddrinfo("localhost", tcp_listener, socket.AF_INET)
            with (
                tethered.scope(allow=["127.0.0.1"], allow_localhost=False, label="by-ip"),
                socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client,
            ):
                client.settimeout(5)
                client.connect(("127.0.0.1", tcp_listener))

    def test_ip_only_outer_hostname_only_inner_real_socket(self, tcp_listener):
        # The lookup happens before the IP-only scope is entered: inside it the
        # lookup itself would be refused, which is the designed behaviour.
        with tethered.scope(allow=["localhost"], allow_localhost=False):
            socket.getaddrinfo("localhost", tcp_listener, socket.AF_INET)
        with (
            tethered.scope(allow=["127.0.0.1"], allow_localhost=False, label="by-ip"),
            tethered.scope(allow=["localhost"], allow_localhost=False, label="by-name"),
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client,
        ):
            client.settimeout(5)
            client.connect(("127.0.0.1", tcp_listener))

    @pytest.mark.parametrize("order", ["name-ip-range", "range-ip-name"])
    def test_mixed_representations_across_scopes(self, fake_dns, order):
        fake_dns.table["db.internal"] = ["10.0.0.1"]
        _learn("db.internal")
        rules = [["db.internal"], ["10.0.0.1"], ["10.0.0.0/8"]]
        if order == "range-ip-name":
            rules.reverse()
        with contextlib.ExitStack() as stack:
            for allow in rules:
                stack.enter_context(tethered.scope(allow=allow, allow_localhost=False))
            _audit_hook("socket.connect", (None, ("10.0.0.1", 5432)))

    def test_a_scope_allowing_neither_still_blocks(self, fake_dns):
        fake_dns.table["db.internal"] = ["10.0.0.1"]
        _learn("db.internal")
        with (
            tethered.scope(allow=["db.internal"], allow_localhost=False, label="by-name"),
            tethered.scope(allow=["10.0.0.1"], allow_localhost=False, label="by-ip"),
            tethered.scope(allow=["other.internal"], allow_localhost=False, label="neither"),
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            _audit_hook("socket.connect", (None, ("10.0.0.1", 5432)))
        assert exc_info.value.scope_label == "neither"
        assert exc_info.value.resolved_from == "db.internal"

    def test_port_rules_apply_to_each_alternative(self, fake_dns):
        fake_dns.table["db.internal"] = ["10.0.0.1"]
        _learn("db.internal")
        with (
            tethered.scope(allow=["db.internal:5432"], allow_localhost=False, label="by-name"),
            tethered.scope(allow=["10.0.0.1:5432"], allow_localhost=False, label="by-ip"),
        ):
            _audit_hook("socket.connect", (None, ("10.0.0.1", 5432)))
            with pytest.raises(tethered.EgressBlocked) as exc_info:
                _audit_hook("socket.connect", (None, ("10.0.0.1", 80)))
        assert exc_info.value.scope_label == "by-name"

    def test_without_a_mapping_the_hostname_scope_blocks(self, no_dns):
        with (
            tethered.scope(allow=["db.internal"], allow_localhost=False, label="by-name"),
            tethered.scope(allow=["10.0.0.1"], allow_localhost=False, label="by-ip"),
            pytest.raises(tethered.EgressBlocked) as exc_info,
        ):
            _audit_hook("socket.connect", (None, ("10.0.0.1", 5432)))
        assert exc_info.value.scope_label == "by-name"
        assert exc_info.value.resolved_from is None

    def test_monitoring_scope_between_mixed_scopes(self, fake_dns):
        fake_dns.table["db.internal"] = ["10.0.0.1"]
        _learn("db.internal")
        seen: list[tuple[str, int | None]] = []
        with (
            tethered.scope(allow=["db.internal"], allow_localhost=False),
            tethered.scope(
                allow=["other.internal"],
                allow_localhost=False,
                log_only=True,
                on_blocked=lambda h, p: seen.append((h, p)),
            ),
            tethered.scope(allow=["10.0.0.1"], allow_localhost=False),
        ):
            _audit_hook("socket.connect", (None, ("10.0.0.1", 5432)))
        assert seen == [("db.internal", 5432)]

    def test_global_policy_and_scopes_each_pick_their_own_alternative(self, fake_dns):
        fake_dns.table["db.internal"] = ["10.0.0.1"]
        tethered.activate(allow=["db.internal", "10.0.0.0/8"], allow_localhost=False)
        _audit_hook("socket.getaddrinfo", ("db.internal", 5432, 0, 0, 0))
        with (
            tethered.scope(allow=["10.0.0.1"], allow_localhost=False),
            tethered.scope(allow=["db.internal"], allow_localhost=False),
        ):
            _audit_hook("socket.connect", (None, ("10.0.0.1", 5432)))


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

    def test_hostname_with_a_slash_is_judged_as_a_hostname(self, caplog):
        """``not-a-cidr/99`` is no network: the parser keeps it as a hostname rule."""
        tethered.activate(allow=["api.stripe.com:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=["not-a-cidr/99"])

        assert "'not-a-cidr/99' has no overlap with global policy" in caplog.text

    def test_decorator_enter_exit_logged(self, caplog):
        """DEBUG messages logged on decorator enter/exit."""

        @tethered.scope(allow=["*.example.com"])
        def guarded():
            pass

        with caplog.at_level(logging.DEBUG, logger="tethered"):
            guarded()

        assert "entered scope(*.example.com)" in caplog.text
        assert "exited scope(*.example.com)" in caplog.text


# One rule in two spellings that the parser reads as the same rule.
_SAME_RULE_SPELLINGS = [
    ("api.example.com", "api.example.com"),
    ("api.example.com", " API.Example.com. "),
    ("api.example.com:443", "api.example.com:443"),
    ("api.example.com:443", "API.Example.com.:443"),
    ("not-a-cidr/99", "not-a-cidr/99"),
    ("*.example.com", "*.example.com"),
    ("*.example.com", "*.EXAMPLE.com."),
    ("*.example.com:443", "*.example.com:443"),
    ("*.example.com:443", "*.Example.com.:443"),
    ("api-??.example.com:443", "api-??.example.com:443"),
    ("[ab].example.com", "[ab].example.com"),
    ("[ab].example.com:443", "[ab].example.com:443"),
    ("[ab].example.com:443", "[AB].Example.com.:443"),
    ("[!a].example.com:443", "[!a].example.com:443"),
    ("edge-[0-9].example.com", "edge-[0-9].example.com"),
    ("edge-[0-9].example.com:443", "edge-[0-9].example.com:443"),
    ("192.0.2.7", "192.0.2.7"),
    ("192.0.2.7", "192.0.2.7/32"),
    ("192.0.2.7", "[192.0.2.7]"),
    ("192.0.2.7:443", "192.0.2.7:443"),
    ("192.0.2.7:443", "[192.0.2.7]:443"),
    ("192.0.2.7:443", "192.0.2.7/32:443"),
    ("2001:db8::1", "2001:db8::1"),
    ("2001:db8::1", "[2001:db8::1]"),
    ("2001:db8::1", "2001:DB8:0:0:0:0:0:1"),
    ("2001:db8::1", "2001:db8::1/128"),
    ("2001:db8::443", "2001:db8::443"),
    ("2001:db8::a", "2001:db8::a"),
    ("::1", "::1"),
    ("::1", "[::1]"),
    ("[2001:db8::1]:443", "[2001:db8::1]:443"),
    ("[2001:db8::1]:443", "[2001:DB8::1]/128:443"),
    ("fe80::1%eth0", "fe80::1"),
    ("198.51.100.0/24", "198.51.100.0/24"),
    ("198.51.100.0/24", "198.51.100.9/24"),
    ("198.51.100.0/24", "[198.51.100.0]/24"),
    ("198.51.100.0/24:443", "198.51.100.0/24:443"),
    ("198.51.100.0/24:443", "[198.51.100.0]/24:443"),
    ("2001:db8::/32", "2001:db8::/32"),
    ("2001:db8::/32", "[2001:db8::]/32"),
    ("[2001:db8::]/32:443", "[2001:db8::]/32:443"),
    ("[2001:db8::]/32:443", "[2001:DB8::]/32:443"),
]


class TestScopeOverlapFollowsThePolicyParser:
    """The overlap warnings judge each scope rule as ``AllowPolicy`` parsed it.

    Offline: scopes are only constructed and the log records inspected.
    """

    @staticmethod
    def _overlap_warnings(caplog, global_allow, scope_allow, **activate_kwargs):
        """Return ``(kind, rule text)`` for each overlap warning, in the order logged."""
        tethered.activate(allow=global_allow, **activate_kwargs)
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=scope_allow, label="probe")
        found = []
        for record in caplog.records:
            message = record.getMessage()
            if "has no overlap with global policy — it will never match" in message:
                kind = "none"
            elif "is broader than the global policy — only a subset will be reachable" in message:
                kind = "broader"
            else:
                continue
            assert record.args[0] == "probe"
            assert repr(record.args[1]) in message
            found.append((kind, record.args[1]))
        return found

    @pytest.mark.parametrize("swap", [False, True], ids=["as-listed", "swapped"])
    @pytest.mark.parametrize(("first", "second"), _SAME_RULE_SPELLINGS)
    def test_rule_identical_to_a_global_rule_is_not_reported(self, caplog, first, second, swap):
        """For every rule kind, with and without a port, in each spelling of the rule."""
        assert AllowPolicy([first])._parsed_rules == AllowPolicy([second])._parsed_rules
        global_rule, scope_rule = (second, first) if swap else (first, second)

        # allow_localhost=False: nothing but the rule itself can account for "::1".
        warnings = self._overlap_warnings(
            caplog, [global_rule], [scope_rule], allow_localhost=False
        )

        assert warnings == []

    def test_leading_character_set_is_not_read_as_a_bracketed_ip(self, caplog):
        """``[ab].example.com:443`` was read as the IP ``ab`` and reported as never matching."""
        assert (
            self._overlap_warnings(caplog, ["[ab].example.com:443"], ["[ab].example.com:443"]) == []
        )

    @pytest.mark.parametrize("rule", ["2001:db8::1", "::1", "2001:db8::443"])
    def test_last_group_of_an_unbracketed_ipv6_address_is_not_a_port(self, caplog, rule):
        assert self._overlap_warnings(caplog, [rule], [rule], allow_localhost=False) == []

    def test_character_set_pattern_is_judged_as_a_wildcard(self, caplog):
        """It covers more hostnames than the one exact host the global policy lists."""
        assert self._overlap_warnings(
            caplog, ["xa.example.com:443"], ["x[ab].example.com:443"]
        ) == [("broader", "x[ab].example.com:443")]

    def test_character_set_pattern_without_overlap(self, caplog):
        assert self._overlap_warnings(caplog, ["*.stripe.com"], ["x[ab].example.com"]) == [
            ("none", "x[ab].example.com")
        ]

    @pytest.mark.parametrize(
        ("global_allow", "scope_rule", "activate_kwargs"),
        [
            # Reported as never matching, although the global rule covers it.
            (["*.example.*"], "*.example.com", {}),
            (["*.example.*"], "x[ab].example.com", {}),
            # Reported as broader, although the two share no hostname.
            (["??.example.com"], "[ab].example.com", {}),
            (["??.example.com"], "*.api.example.com", {}),
            # Reported as never matching, although the addresses are allowed.
            (["10.0.0.0/24"], "10.0.0.*", {"allow_localhost": False}),
            (["192.0.2.*"], "192.0.2.0/24", {"allow_localhost": False}),
            (["api.example.com:443"], "127.0.0.0/8", {}),
            (["api.example.com:443"], "local*", {}),
        ],
    )
    def test_nothing_is_reported_when_the_overlap_cannot_be_told(
        self, caplog, global_allow, scope_rule, activate_kwargs
    ):
        """A guess would be logged as a fact; these used to be wrong ones."""
        assert self._overlap_warnings(caplog, global_allow, [scope_rule], **activate_kwargs) == []

    def test_warning_names_the_rule_as_the_user_wrote_it(self, caplog):
        written = "  Dead.Example.TEST.:443 "
        tethered.activate(allow=["api.stripe.com:443"])

        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.scope(allow=[written])

        assert f"rule {written!r} has no overlap with global policy" in caplog.text

    def test_each_warning_is_paired_with_its_own_rule(self, caplog):
        """Rules of every kind, mixed and repeated: the text follows the parsed rule."""
        warnings = self._overlap_warnings(
            caplog,
            ["api.example.com:443", "10.0.0.0/8:5432"],
            [
                "10.9.9.9",
                "api.example.com:443",
                "*.dead.test",
                " API.Example.com.:443 ",
                "10.0.0.0/8",
                "[10.1.0.0]/16:5432",
                "dead.test",
                "*.dead.test",
            ],
        )

        assert warnings == [
            ("broader", "10.9.9.9"),
            ("none", "*.dead.test"),
            ("broader", "10.0.0.0/8"),
            ("none", "dead.test"),
            ("none", "*.dead.test"),
        ]

    @pytest.mark.parametrize(
        ("global_rule", "scope_rule"),
        [
            ("10.0.0.0/8", "10.1.2.3:443"),
            ("10.0.0.0/8", "10.1.2.3/32:443"),
            ("192.0.2.*", "192.0.2.7"),
            ("192.0.2.*", "192.0.2.7/32"),
            ("2001:db8::/32", "[2001:db8::1]:443"),
            ("2001:db8::/32", "[2001:db8::1]/128:443"),
        ],
    )
    def test_single_address_is_judged_alike_with_and_without_a_prefix(
        self, caplog, global_rule, scope_rule
    ):
        """``ADDR/32`` is the rule ``ADDR``; it used to take the CIDR path and be reported."""
        assert self._overlap_warnings(caplog, [global_rule], [scope_rule]) == []

    @pytest.mark.parametrize(
        ("global_rule", "scope_rule"),
        [
            ("*.example.com", "*.example.com:443"),
            ("10.0.0.0/8", "10.0.0.0/8:5432"),
            ("10.0.0.0/8", "10.0.1.0/24:5432"),
            ("2001:db8::/32", "[2001:db8:1::]/48:443"),
        ],
    )
    def test_port_specific_rule_inside_an_any_port_rule_is_not_reported(
        self, caplog, global_rule, scope_rule
    ):
        assert self._overlap_warnings(caplog, [global_rule], [scope_rule]) == []
        tethered.deactivate()
        # The other way round the scope rule is the broader one.
        assert self._overlap_warnings(caplog, [scope_rule], [global_rule]) == [
            ("broader", global_rule)
        ]

    @pytest.mark.parametrize(
        ("global_rule", "scope_rule"),
        [
            ("*.amazonaws.com:443", "*.s3.amazonaws.com:443"),
            ("*.amazonaws.com", "*.s3.amazonaws.com:443"),
            ("*.example.com:443", "shard-[0-9].example.com:443"),
            ("*.example.com", "[ab].example.com"),
        ],
    )
    def test_wildcard_inside_a_suffix_wildcard_is_not_reported(
        self, caplog, global_rule, scope_rule
    ):
        assert self._overlap_warnings(caplog, [global_rule], [scope_rule]) == []

    def test_wildcard_inside_a_suffix_wildcard_on_other_ports(self, caplog):
        assert self._overlap_warnings(caplog, ["*.amazonaws.com:443"], ["*.s3.amazonaws.com"]) == [
            ("broader", "*.s3.amazonaws.com")
        ]
        tethered.deactivate()
        assert self._overlap_warnings(
            caplog, ["*.amazonaws.com:443"], ["*.s3.amazonaws.com:80"]
        ) == [("none", "*.s3.amazonaws.com:80")]

    @pytest.mark.parametrize("rule", ["localhost", "127.0.0.1", "::1"])
    def test_localhost_rule_without_a_port(self, caplog, rule):
        """The global policy allows localhost on every port, or not at all."""
        assert self._overlap_warnings(caplog, ["api.stripe.com:443"], [rule]) == []
        tethered.deactivate()
        assert self._overlap_warnings(
            caplog, ["api.stripe.com:443"], [rule], allow_localhost=False
        ) == [("none", rule)]


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
        """_check_scopes returns the denying scope when host not allowed."""
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(policy=policy, label="test-scope")
        result = _check_scopes((sc,), ("evil.test",), 80)
        assert result == [sc]

    def test_check_scopes_allows(self):
        """_check_scopes returns nothing when host is allowed."""
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(policy=policy, label="test-scope")
        result = _check_scopes((sc,), ("api.example.com",), 80)
        assert result == []

    def test_check_scopes_fail_closed(self, monkeypatch):
        """_check_scopes returns scope on error when fail_closed=True."""
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(policy=policy, fail_closed=True, label="test-scope")
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        result = _check_scopes((sc,), ("test.example.com",), 80)
        assert result == [sc]

    def test_check_scopes_fail_open(self, monkeypatch):
        """_check_scopes returns nothing on error when fail_closed=False."""
        policy = AllowPolicy(["*.example.com"])
        sc = _ScopeConfig(policy=policy, fail_closed=False, label="test-scope")
        monkeypatch.setattr(AllowPolicy, "is_allowed", _raise_runtime)
        result = _check_scopes((sc,), ("test.example.com",), 80)
        assert result == []

    def test_check_scopes_returns_every_denying_scope_in_stack_order(self):
        """Evaluation does not stop at the first denial, log-only or not."""
        monitor = _ScopeConfig(policy=AllowPolicy([]), log_only=True, label="monitor")
        allows = _ScopeConfig(policy=AllowPolicy(["192.0.2.0/24"]), label="allows")
        enforcer = _ScopeConfig(policy=AllowPolicy([]), label="enforcer")
        result = _check_scopes((monitor, allows, enforcer), ("192.0.2.1",), 443)
        assert result == [monitor, enforcer]

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
            _ip_to_hostname["198.51.100.1"] = ("evil.example.com",)
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
            _ip_to_hostname["10.0.0.1"] = ("db.internal",)

        # "db.internal" is not in the scope, but 10.0.0.1 matches 10.0.0.0/8
        # Should be allowed (IP fallback), not blocked
        _handle_connect(None, (sc,), "socket.connect", (None, ("10.0.0.1", 5432)))
