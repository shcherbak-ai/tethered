"""Test-suite egress guard — uses tethered's AllowPolicy.

Installs an independent audit hook that prevents accidental network egress
when tethered is not active (between tests / during cleanup). When tethered
IS active, its own hook handles enforcement and this guard is a no-op.
"""

from __future__ import annotations

import ipaddress
import socket
import sys

import pytest

import tethered._core as _core
from tethered._core import _CONNECT_EVENTS, _DNS_EVENTS, EgressBlocked
from tethered._policy import AllowPolicy

# Destinations the test suite may reach; localhost is allowed by default
_GUARD_POLICY = AllowPolicy(["dns.google"], allow_localhost=True)

# _DNS_EVENTS in _core only covers gethostbyname/gethostbyaddr;
# getaddrinfo is dispatched separately, so we add it here.
_ALL_DNS_EVENTS = _DNS_EVENTS | {"socket.getaddrinfo"}


def _test_egress_guard(event: str, args: tuple) -> None:
    """Block unexpected network access when tethered is not active."""
    if _core._config is not None:
        return  # tethered is active — its hook handles enforcement
    if _core._c_guardian is not None and _core._c_guardian.is_active():
        return  # C guardian is active — it handles enforcement
    if _core._scopes.get():
        return  # scope is active — its hook handles enforcement

    if event in _ALL_DNS_EVENTS:
        host = args[0] if args else None
        if not isinstance(host, str) or not host:
            return
        if event != "socket.gethostbyaddr":
            # IP-literal gethostbyname/getaddrinfo calls do not trigger DNS.
            try:
                ipaddress.ip_address(host)
                return
            except ValueError:
                pass
        if not _GUARD_POLICY.is_allowed(host):
            raise EgressBlocked(host, None)

    elif event in _CONNECT_EVENTS:
        addr = args[1] if len(args) >= 2 else None
        if not isinstance(addr, tuple) or len(addr) < 2:
            return
        host = addr[0]
        port = addr[1] if isinstance(addr[1], int) else None
        if not isinstance(host, str) or not host:
            return
        if not _GUARD_POLICY.is_allowed(host, port):
            raise EgressBlocked(host, port)


sys.addaudithook(_test_egress_guard)


def _has_network() -> bool:
    """Check if external DNS resolution is available."""
    try:
        socket.getaddrinfo("dns.google", 443)
        return True
    except OSError:
        return False


@pytest.fixture(autouse=True)
def _skip_if_no_network(request):
    """Skip @requires_network tests at runtime when DNS is unavailable."""
    if request.node.get_closest_marker("requires_network") and not _has_network():
        pytest.skip("No network access")
