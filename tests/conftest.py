"""Test-suite egress guard — uses tethered's AllowPolicy.

Installs an independent audit hook that prevents accidental network egress
when tethered is not active (between tests / during cleanup). When tethered
IS active, its own hook handles enforcement and this guard is a no-op.

Also installs ``tethered.pth`` into site-packages for the duration of the
test session.  Editable installs (``pip install -e .``, ``uv pip install
-e .``) don't run our ``setup.py`` ``build_py`` cmdclass, so the .pth that
ships with the wheel doesn't land in site-packages automatically.  Tests
that exercise subprocess auto-propagation need it there to work end-to-end.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import sys
import sysconfig
from pathlib import Path

import pytest

import tethered._core as _core
from tethered._core import (
    _CHILD_POLICY_ENV,
    _CONNECT_EVENTS,
    _DNS_EVENTS,
    EgressBlocked,
    _ip_map_lock,
    _ip_to_hostname,
    _scopes,
)
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


@pytest.fixture(autouse=True)
def _cleanup():
    """Reset tethered state after each test.

    Ensures the C guardian is deactivated, the global config is cleared,
    the IP-to-hostname map is emptied, the scope stack is reset, and the
    propagation env var is removed.
    """
    yield
    # Deactivate C guardian first (using stored token_id)
    if _core._c_guardian is not None and _core._c_guardian.is_active():
        _core._c_guardian.deactivate(_core._guardian_token_id)
    with _core._state_lock, _ip_map_lock:
        _core._config = None
        _ip_to_hostname.clear()
        _core._allowed_hostnames.clear()
    _scopes.set(())
    os.environ.pop(_CHILD_POLICY_ENV, None)


@pytest.fixture(scope="session", autouse=True)
def _ensure_pth_installed():
    """Install ``tethered.pth`` into site-packages for the test session.

    The shipped wheel installs the .pth via setup.py's build_py cmdclass,
    but editable installs (``pip install -e .``) bypass that path.  Tests
    that subprocess.run a fresh Python interpreter need the .pth in
    site-packages to exercise auto-propagation; install it here and remove
    on session teardown.  No-op if the .pth already exists (real wheel
    install scenario).
    """
    purelib = Path(sysconfig.get_path("purelib"))
    pth_dst = purelib / "tethered.pth"
    pth_src = Path(__file__).resolve().parent.parent / "src" / "tethered.pth"
    installed_by_us = False
    if not pth_dst.exists() and pth_src.exists():
        shutil.copy(pth_src, pth_dst)
        installed_by_us = True
    yield
    if installed_by_us:
        try:
            pth_dst.unlink()
        except OSError:  # pragma: no cover — best-effort cleanup
            pass
