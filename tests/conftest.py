"""Test-suite egress guard — uses tethered's AllowPolicy.

Installs an independent audit hook that prevents accidental network egress
when tethered is not active (between tests / during cleanup). When tethered
IS active, its own hook handles enforcement and this guard is a no-op.

Also installs ``tethered.pth`` into site-packages for the duration of the
test run.  Editable installs (``pip install -e .``, ``uv pip install
-e .``) don't run our ``setup.py`` ``build_py`` cmdclass, so the .pth that
ships with the wheel doesn't land in site-packages automatically.  Tests
that exercise subprocess auto-propagation need it there to work end-to-end.
"""

from __future__ import annotations

import contextlib
import functools
import ipaddress
import os
import shutil
import socket
import sys
import sysconfig
from pathlib import Path

import pytest

import tethered
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


# ── Lock-token bookkeeping for cleanup ────────────────────────────
# The lock token is held only inside the C guardian: tethered keeps no
# Python-visible copy and offers no way to force-deactivate.  To unlock
# between tests, remember every token a test hands to ``tethered.activate``
# (which is also how ``_autoactivate`` reaches it).  This lives entirely on
# the test side — the package knows nothing about it.
_seen_lock_tokens: list[object] = []
_real_activate = tethered.activate


@functools.wraps(_real_activate)
def _recording_activate(*args, **kwargs):
    token = kwargs.get("lock_token")
    if token is not None:
        _seen_lock_tokens.append(token)
    return _real_activate(*args, **kwargs)


@pytest.fixture(scope="session", autouse=True)
def _record_lock_tokens():
    """Route ``tethered.activate`` through the token-recording wrapper."""
    tethered.activate = _recording_activate
    yield
    tethered.activate = _real_activate


def _unlock_guardian() -> None:
    """Deactivate the C guardian with whichever recorded token it holds."""
    guardian = _core._c_guardian
    if guardian is None:
        return
    try:
        if guardian.is_active():
            for token in _seen_lock_tokens:
                if guardian.check_token(token):
                    guardian.deactivate(token)
                    break
        assert not guardian.is_active(), (
            "a test left the C guardian locked with a token that was not passed "
            "through tethered.activate(); conftest cannot unlock it"
        )
    finally:
        _seen_lock_tokens.clear()


@pytest.fixture(autouse=True)
def _no_real_exec(monkeypatch):
    """Fail a test that lets tethered replace the test process.

    tethered's launch hook carries out some ``os.exec*`` calls itself
    (``_core._exec_with_policy``).  A test that reaches that with the real
    ``os.execve`` in place does not fail: pytest is gone, and the run ends
    without a summary.  Tests about that route put their own stand-in here.
    """

    def refuse(path, argv, env):
        raise AssertionError(
            f"a test would have replaced the test process with {path!r}: "
            "replace os.execve in the test"
        )

    monkeypatch.setattr(os, "execve", refuse)


@pytest.fixture(autouse=True)
def _cleanup():
    """Reset tethered state after each test.

    Ensures the C guardian is deactivated, the global config is cleared,
    the IP-to-hostname map is emptied, the scope stack and the active-scope
    count are reset, the propagation env var is removed, and the native-env
    dirty flag is cleared.
    """
    _quiet_once_per_process_messages()
    yield
    # Deactivate the C guardian first (using the token the test supplied)
    _unlock_guardian()
    with _core._state_lock, _ip_map_lock:
        _core._config = None
        _ip_to_hostname.clear()
        _core._allowed_hostnames.clear()
    _scopes.set(())
    _core._active_scope_count = 0
    os.environ.pop(_CHILD_POLICY_ENV, None)
    _core._env_dirty = False
    _quiet_once_per_process_messages()


def _quiet_once_per_process_messages() -> None:
    """Switch off what tethered says once per process, unless a test asks for it.

    The hint for a refused address would appear in whichever test refuses an
    address first, and the warning about a fork server in whichever test
    activates a policy first after some other test started a process pool
    (the fork server is the default start method on Linux from Python 3.14).
    """
    _core._unnamed_address_hint_pending = False
    _core._fork_server_warning_pending = False


# The ``tethered.pth`` this run copied into site-packages, for
# ``pytest_unconfigure`` to take away again.
_INSTALLED_PTH = pytest.StashKey[Path]()


def pytest_configure(config: pytest.Config) -> None:
    """Install ``tethered.pth`` into site-packages for the test run.

    The shipped wheel installs the .pth via setup.py's build_py cmdclass,
    but editable installs (``pip install -e .``) bypass that path.  Tests
    that subprocess.run a fresh Python interpreter need the .pth in
    site-packages to exercise auto-propagation; install it here and remove
    it in ``pytest_unconfigure``.  No-op if the .pth already exists (real
    wheel install scenario).

    These are hooks and not a session fixture because of pytest-xdist
    (``-n``): every worker has a session of its own, and site-packages is
    one directory for all of them.  The worker that finished first would
    remove the file under the workers still running.  So the process that
    starts the workers installs it before the first of them starts and
    removes it after the last has ended; a worker does neither.
    """
    if hasattr(config, "workerinput"):
        return  # a pytest-xdist worker
    pth_dst = Path(sysconfig.get_path("purelib")) / "tethered.pth"
    pth_src = Path(__file__).resolve().parent.parent / "src" / "tethered.pth"
    if not pth_dst.exists() and pth_src.exists():
        shutil.copy(pth_src, pth_dst)
        config.stash[_INSTALLED_PTH] = pth_dst


def pytest_unconfigure(config: pytest.Config) -> None:
    """Remove the ``tethered.pth`` that ``pytest_configure`` installed."""
    pth_dst = config.stash.get(_INSTALLED_PTH, None)
    if pth_dst is not None:
        with contextlib.suppress(OSError):  # best-effort cleanup
            pth_dst.unlink()


@pytest.fixture
def alias_of():
    """Give a directory another name: ``alias_of(directory, alias)`` returns ``alias``.

    A symlink, and on Windows a junction, which needs no privilege.  The
    aliases are taken away again after the test, before pytest clears the
    temporary directory they are in.
    """
    made: list[Path] = []

    def make(directory: Path, alias: Path) -> Path:
        if sys.platform == "win32":
            import _winapi

            _winapi.CreateJunction(str(directory), str(alias))
        else:
            alias.symlink_to(directory, target_is_directory=True)
        made.append(alias)
        return alias

    yield make
    for alias in made:
        with contextlib.suppress(OSError):
            (os.rmdir if sys.platform == "win32" else os.unlink)(alias)
