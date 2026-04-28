"""Tests for tethered subprocess control: external_subprocess_policy and serialization."""

from __future__ import annotations

import asyncio
import ctypes
import json
import logging
import multiprocessing as mp
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import ClassVar

import pytest

import tethered
import tethered._core as _core
from tethered._core import (
    _CHILD_POLICY_ENV,
    _audit_hook,
    _build_per_launch_env,
    _compute_pth_path,
    _Config,
    _describe_subprocess_launch,
    _extract_subprocess_env,
    _find_execute_child_frame,
    _handle_pth_fs_op,
    _handle_subprocess,
    _has_site_bypass_flag,
    _inject_scope_env,
    _is_auto_inheriting_python_launch,
    _parse_windows_cmdline,
    _path_matches_pth,
    _ScopeConfig,
    _serialize_network_rule,
)
from tethered._policy import AllowPolicy, _NetworkRule


def _check_egress_worker(host: str) -> str:
    """Module-level worker for multiprocessing.Pool / ProcessPoolExecutor tests.

    Returns ``"TETHERED_BLOCKED"`` if tethered raised ``EgressBlocked``,
    ``"OTHER:<exc>"`` for any other exception, or ``"ALLOWED"`` if no
    exception fired.  Must live at module scope to be pickleable by
    multiprocessing's spawn-mode child bootstrap (the child re-imports
    this module to find the function).
    """
    import socket

    import tethered as _tethered

    try:
        socket.getaddrinfo(host, 80)
    except _tethered.EgressBlocked:
        return "TETHERED_BLOCKED"
    except Exception as e:
        return f"OTHER:{type(e).__name__}"
    return "ALLOWED"


def _inspect_state_worker() -> dict:
    """Worker that returns the child's tethered state for inheritance verification."""
    import tethered._core as _c

    return {
        "config_active": _c._config is not None,
        "scope_count": len(_c._scopes.get()),
        "scope_labels": [s.label for s in _c._scopes.get()],
    }


class TestSubprocessPolicy:
    """Tests for external_subprocess_policy parameter and parent-side enforcement.

    Note: Python children inherit the policy automatically via ``tethered.pth``;
    these tests cover the parent-side audit (mainly useful for monitoring or
    blocking non-Python subprocess launches like a dependency shelling out to
    curl).
    """

    def test_default_external_subprocess_policy_is_warn(self, caplog):
        """Default external_subprocess_policy is 'warn' — non-Python launches log a warning."""
        tethered.activate(allow=["*.example.com"])
        with caplog.at_level(logging.WARNING, logger="tethered"):
            os.system("echo hi")  # nosec B605 B607 — non-Python launch
        assert any("external subprocess launch detected" in r.message for r in caplog.records)

    def test_default_silent_for_auto_inheriting_python_launches(self, caplog):
        """Even at the new 'warn' default, sys.executable launches stay silent (auto-inherit)."""
        tethered.activate(allow=["*.example.com"])
        with caplog.at_level(logging.WARNING, logger="tethered"):
            result = subprocess.run(
                [sys.executable, "-c", "print('ok')"],
                capture_output=True,
                timeout=10,
            )  # nosec B603 B607
        assert result.returncode == 0
        assert not any("external subprocess launch" in r.message for r in caplog.records)

    def test_invalid_external_subprocess_policy(self):
        """Invalid external_subprocess_policy raises ValueError."""
        with pytest.raises(ValueError, match="external_subprocess_policy must be one of"):
            tethered.activate(allow=[], external_subprocess_policy="invalid")

    def test_external_subprocess_policy_warn_for_external_launch(self, caplog):
        """external_subprocess_policy='warn' logs warning for non-Python launches."""
        tethered.activate(allow=["*.example.com"], external_subprocess_policy="warn")
        with caplog.at_level(logging.WARNING, logger="tethered"):
            os.system("echo hi")  # nosec B605 B607 — non-Python launch
        assert any("external subprocess launch detected" in r.message for r in caplog.records)

    def test_external_subprocess_policy_warn_skips_python_auto_inherit(self, caplog):
        """sys.executable launches are auto-inheriting and NOT logged at 'warn'."""
        tethered.activate(allow=["*.example.com"], external_subprocess_policy="warn")
        with caplog.at_level(logging.WARNING, logger="tethered"):
            result = subprocess.run(
                [sys.executable, "-c", "print('ok')"],
                capture_output=True,
                timeout=10,
            )  # nosec B603 B607
        assert result.returncode == 0
        assert not any("external subprocess launch detected" in r.message for r in caplog.records)

    def test_external_subprocess_policy_block_for_external_launch(self):
        """external_subprocess_policy='block' blocks non-Python launches."""
        tethered.activate(allow=[], external_subprocess_policy="block")
        with pytest.raises(tethered.SubprocessBlocked, match=r"os\.system"):
            os.system("echo blocked")  # nosec B605 B607

    def test_external_subprocess_policy_block_skips_python_auto_inherit(self):
        """sys.executable launches are auto-inheriting and NOT blocked even at 'block'."""
        tethered.activate(allow=["*.example.com"], external_subprocess_policy="block")
        # No SubprocessBlocked — auto-inherit covers this Python child.
        result = subprocess.run(
            [sys.executable, "-c", "print('ok')"],
            capture_output=True,
            timeout=10,
        )  # nosec B603 B607
        assert result.returncode == 0

    def test_external_subprocess_policy_block_blocks_python_with_dash_S(self):
        """sys.executable + ``-S`` skips ``site.py`` so the child can't auto-inherit."""
        tethered.activate(allow=[], external_subprocess_policy="block")
        with pytest.raises(tethered.SubprocessBlocked):
            subprocess.run(
                [sys.executable, "-S", "-c", "pass"],
                capture_output=True,
                timeout=10,
            )  # nosec B603 B607

    def test_run_python_no_longer_exists(self):
        """The old run_python() public API has been removed."""
        assert not hasattr(tethered, "run_python")


class TestSubprocessPolicyDirect:
    """Direct unit tests for _handle_subprocess and _describe_subprocess_launch."""

    def test_handle_subprocess_allow_noop(self):
        """_handle_subprocess is a no-op when policy is 'allow'."""
        cfg = _Config(
            policy=AllowPolicy([], allow_localhost=True),
            external_subprocess_policy="allow",
        )
        # Should not raise
        _handle_subprocess(cfg, "subprocess.Popen", ("/usr/bin/python", ["-c", "pass"], None, None))

    def test_describe_subprocess_launch_popen(self):
        """_describe_subprocess_launch formats Popen events correctly."""
        desc = _describe_subprocess_launch("subprocess.Popen", ("/usr/bin/python",))
        assert "subprocess.Popen" in desc
        assert "/usr/bin/python" in desc

    def test_describe_subprocess_launch_os_system(self):
        """_describe_subprocess_launch formats os.system events correctly."""
        desc = _describe_subprocess_launch("os.system", ("echo hello",))
        assert "os.system" in desc

    def test_describe_subprocess_launch_unknown(self):
        """_describe_subprocess_launch handles unknown events gracefully."""
        desc = _describe_subprocess_launch("os.unknown_event", ())
        assert "os.unknown_event" in desc

    def test_describe_subprocess_launch_os_exec(self):
        """_describe_subprocess_launch formats os.exec events correctly."""
        desc = _describe_subprocess_launch("os.exec", ("/bin/ls",))
        assert "os.exec" in desc
        assert "/bin/ls" in desc

    def test_describe_subprocess_launch_os_posix_spawn(self):
        """_describe_subprocess_launch formats os.posix_spawn events correctly."""
        desc = _describe_subprocess_launch("os.posix_spawn", ("/usr/bin/env",))
        assert "os.posix_spawn" in desc
        assert "/usr/bin/env" in desc

    def test_describe_subprocess_launch_os_spawn(self):
        """_describe_subprocess_launch formats os.spawn events (path is args[1])."""
        desc = _describe_subprocess_launch("os.spawn", (1, "/bin/sh"))
        assert "os.spawn" in desc
        assert "/bin/sh" in desc

    def test_describe_subprocess_launch_os_startfile(self):
        """_describe_subprocess_launch formats os.startfile events correctly."""
        desc = _describe_subprocess_launch("os.startfile", ("C:\\\\malware.exe",))
        assert "os.startfile" in desc
        assert "malware.exe" in desc

    def test_subprocess_blocked_exception_attributes(self):
        """SubprocessBlocked.__init__ sets event/description and a clear message."""
        exc = tethered.SubprocessBlocked("subprocess.Popen", "subprocess.Popen(/bin/sh)")
        assert exc.event == "subprocess.Popen"
        assert exc.description == "subprocess.Popen(/bin/sh)"
        assert "Blocked by tethered" in str(exc)
        assert "subprocess.Popen(/bin/sh)" in str(exc)

    def test_handle_subprocess_warn_logs_and_returns(self, caplog):
        """_handle_subprocess with policy='warn' logs and returns without raising."""
        cfg = _Config(
            policy=AllowPolicy([], allow_localhost=True),
            external_subprocess_policy="warn",
        )
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _handle_subprocess(cfg, "subprocess.Popen", ("/bin/sh",))
        assert any("external subprocess launch detected" in r.message for r in caplog.records)

    def test_handle_subprocess_block_raises(self):
        """_handle_subprocess with policy='block' raises SubprocessBlocked."""
        cfg = _Config(
            policy=AllowPolicy([], allow_localhost=True),
            external_subprocess_policy="block",
        )
        with pytest.raises(tethered.SubprocessBlocked, match=r"subprocess\.Popen"):
            _handle_subprocess(cfg, "subprocess.Popen", ("/bin/sh",))

    def test_handle_subprocess_auto_inheriting_python_skips_block(self):
        """sys.executable launches skip external_subprocess_policy enforcement."""
        cfg = _Config(
            policy=AllowPolicy([], allow_localhost=True),
            external_subprocess_policy="block",
        )
        # Even at "block", a sys.executable launch with no site-bypass flags
        # is allowed because auto-inherit handles policy in the child.
        _handle_subprocess(
            cfg,
            "subprocess.Popen",
            (sys.executable, [sys.executable, "-c", "pass"], None, None),
        )  # should not raise

    def test_audit_hook_subprocess_dispatch(self):
        """_audit_hook dispatches subprocess events to _handle_subprocess."""
        tethered.activate(allow=[], external_subprocess_policy="block")
        with pytest.raises(tethered.SubprocessBlocked):
            _audit_hook("subprocess.Popen", ("/bin/sh",))

    def test_audit_hook_subprocess_noop_when_inactive(self):
        """_audit_hook is a no-op for subprocess events when tethered is inactive."""
        # tethered not active in this test (autouse fixture clears _config)
        # Should not raise, should not log
        _audit_hook("subprocess.Popen", ("/bin/sh",))


class TestExtractSubprocessEnv:
    """Tests for _extract_subprocess_env — finds the env arg per audit-event signature."""

    def test_subprocess_popen_env_at_index_3(self):
        has_env, env = _extract_subprocess_env(
            "subprocess.Popen",
            ("/bin/sh", ["-c", "x"], None, {"FOO": "bar"}),
        )
        assert has_env is True
        assert env == {"FOO": "bar"}

    def test_subprocess_popen_short_args_returns_no_env(self):
        has_env, env = _extract_subprocess_env("subprocess.Popen", ("/bin/sh",))
        assert has_env is False
        assert env is None

    def test_os_exec_env_at_index_2(self):
        has_env, env = _extract_subprocess_env(
            "os.exec",
            ("/bin/ls", ["ls"], {"FOO": "bar"}),
        )
        assert has_env is True
        assert env == {"FOO": "bar"}

    def test_os_posix_spawn_env_at_index_2(self):
        has_env, env = _extract_subprocess_env(
            "os.posix_spawn",
            ("/bin/ls", ["ls"], {"FOO": "bar"}),
        )
        assert has_env is True
        assert env == {"FOO": "bar"}

    def test_os_spawn_env_at_index_3(self):
        has_env, env = _extract_subprocess_env(
            "os.spawn",
            (1, "/bin/ls", ["ls"], {"FOO": "bar"}),
        )
        assert has_env is True
        assert env == {"FOO": "bar"}

    def test_os_system_has_no_env(self):
        has_env, env = _extract_subprocess_env("os.system", ("echo hi",))
        assert has_env is False
        assert env is None

    def test_os_startfile_has_no_env(self):
        has_env, env = _extract_subprocess_env("os.startfile", ("foo.exe",))
        assert has_env is False
        assert env is None

    def test_unknown_event_has_no_env(self):
        has_env, env = _extract_subprocess_env("os.unknown", ())
        assert has_env is False
        assert env is None


class TestHasSiteBypassFlag:
    """Unit tests for _has_site_bypass_flag."""

    def test_argv_with_dash_S_returns_true(self):
        assert _has_site_bypass_flag(["python", "-S", "-c", "pass"]) is True

    def test_argv_with_dash_I_returns_false(self):
        """``-I`` (isolated mode) does NOT disable ``site.py`` — auto-inherit still works."""
        assert _has_site_bypass_flag(["python", "-I", "-c", "pass"]) is False

    def test_argv_with_dash_E_returns_false(self):
        """``-E`` only ignores ``PYTHON*`` env vars; ``site.py`` still runs."""
        assert _has_site_bypass_flag(["python", "-E", "-c", "pass"]) is False

    def test_argv_with_combined_flags_IS_returns_true(self):
        """Combined form like -IS contains ``S``, so it IS a bypass."""
        assert _has_site_bypass_flag(["python", "-IS", "-c", "pass"]) is True

    def test_argv_with_combined_flags_IE_returns_false(self):
        """``-IE`` (no ``S``) keeps ``site.py`` enabled."""
        assert _has_site_bypass_flag(["python", "-IE", "-c", "pass"]) is False

    def test_argv_with_dash_X_returns_false(self):
        """-X dev is not a site-bypass flag."""
        assert _has_site_bypass_flag(["python", "-X", "dev", "-c", "pass"]) is False

    def test_argv_without_flags_returns_false(self):
        assert _has_site_bypass_flag(["python", "script.py"]) is False

    def test_argv_with_S_after_dash_c_returns_false(self):
        """The 'S' literal in user code (after -c) doesn't count as a site-bypass flag."""
        assert _has_site_bypass_flag(["python", "-c", "import S"]) is False

    def test_argv_with_S_after_dash_m_returns_false(self):
        assert _has_site_bypass_flag(["python", "-m", "Smodule"]) is False

    def test_long_form_flag_returns_false(self):
        """--isolated isn't a real Python flag, but long-form is skipped anyway."""
        assert _has_site_bypass_flag(["python", "--something-with-S", "-c", "pass"]) is False

    def test_non_list_returns_false(self):
        assert _has_site_bypass_flag("not a list") is False
        assert _has_site_bypass_flag(None) is False

    def test_non_string_args_skipped(self):
        # Non-string entries in argv are skipped, not raised on
        assert _has_site_bypass_flag(["python", 123, "-S", "-c", "pass"]) is True

    def test_bytes_dash_S_detected(self):
        """``b"-S"`` is what POSIX subprocess passes through to execve — must be detected."""
        assert _has_site_bypass_flag(["python", b"-S", b"-c", b"pass"]) is True

    def test_bytes_combined_IS_detected(self):
        """Combined ``b"-IS"`` (contains ``S``) is detected after fsdecode."""
        assert _has_site_bypass_flag(["python", b"-IS", b"-c", b"pass"]) is True

    def test_bytes_dash_I_returns_false(self):
        """``b"-I"`` (no ``S``) is correctly NOT flagged after fsdecode."""
        assert _has_site_bypass_flag(["python", b"-I", b"-c", b"pass"]) is False

    def test_bytes_after_dash_c_ignored(self):
        """Bytes args appearing after ``b"-c"`` (user code) don't count as flags."""
        assert _has_site_bypass_flag(["python", b"-c", b"import S; pass"]) is False

    def test_pathlike_dash_S_detected(self):
        """``os.PathLike`` argv elements are decoded via ``os.fsdecode``."""

        class _PL:
            def __fspath__(self) -> str:
                return "-S"

        assert _has_site_bypass_flag(["python", _PL(), "-c", "pass"]) is True

    def test_pathlike_with_failing_fspath_skipped(self):
        """A ``__fspath__`` raising ``TypeError`` is handled gracefully (skipped, not raised)."""

        class _BadPL:
            def __fspath__(self) -> str:
                raise TypeError("simulated bad PathLike")

        # The bad PathLike is skipped; the real ``-S`` still gets detected.
        assert _has_site_bypass_flag(["python", _BadPL(), "-S", "-c", "pass"]) is True

    def test_str_and_bytes_mixed_args(self):
        """Mixed str + bytes argv (legitimate on POSIX) is parsed coherently."""
        assert _has_site_bypass_flag(["python", "-I", b"-S", "-c", "pass"]) is True
        assert _has_site_bypass_flag(["python", b"-I", "-E", "-c", "pass"]) is False


class TestIsAutoInheritingPythonLaunch:
    """Unit tests for _is_auto_inheriting_python_launch."""

    def test_sys_executable_with_c_flag_is_auto_inheriting(self):
        args = (sys.executable, [sys.executable, "-c", "pass"], None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is True

    def test_sys_executable_with_S_flag_is_not_auto_inheriting(self):
        args = (sys.executable, [sys.executable, "-S", "-c", "pass"], None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False

    def test_sys_executable_with_I_flag_is_auto_inheriting(self):
        """``-I`` (isolated mode) leaves ``site.py`` enabled — bootstrap still works."""
        args = (sys.executable, [sys.executable, "-I", "-c", "pass"], None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is True

    def test_sys_executable_with_E_flag_is_auto_inheriting(self):
        """``-E`` only ignores ``PYTHON*`` env vars — bootstrap still works."""
        args = (sys.executable, [sys.executable, "-E", "-c", "pass"], None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is True

    def test_sys_executable_with_IE_flags_is_auto_inheriting(self):
        """Combined ``-IE`` (no ``S``) is still auto-inheriting."""
        args = (sys.executable, [sys.executable, "-IE", "-c", "pass"], None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is True

    def test_different_executable_is_not_auto_inheriting(self):
        args = ("/usr/bin/python3", ["/usr/bin/python3", "-c", "pass"], None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False

    def test_non_python_executable_is_not_auto_inheriting(self):
        args = ("/bin/sh", ["sh", "-c", "echo hi"], None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False

    def test_os_system_event_is_not_auto_inheriting(self):
        """os.system has no executable arg in its audit signature."""
        assert _is_auto_inheriting_python_launch("os.system", ("echo hi",)) is False

    def test_os_startfile_event_is_not_auto_inheriting(self):
        assert _is_auto_inheriting_python_launch("os.startfile", ("foo.exe",)) is False

    def test_os_exec_with_sys_executable_is_auto_inheriting(self):
        args = (sys.executable, [sys.executable, "-c", "pass"], {"PATH": "/"})
        assert _is_auto_inheriting_python_launch("os.exec", args) is True

    def test_os_posix_spawn_with_sys_executable_is_auto_inheriting(self):
        args = (sys.executable, [sys.executable, "-c", "pass"], {"PATH": "/"})
        assert _is_auto_inheriting_python_launch("os.posix_spawn", args) is True

    def test_os_spawn_layout_is_handled(self):
        """os.spawn audit args are (mode, path, argv, env)."""
        args = (1, sys.executable, [sys.executable, "-c", "pass"], None)
        assert _is_auto_inheriting_python_launch("os.spawn", args) is True

    def test_short_args_returns_false(self):
        assert _is_auto_inheriting_python_launch("subprocess.Popen", ()) is False
        assert _is_auto_inheriting_python_launch("os.spawn", (1,)) is False

    def test_non_path_executable_returns_false(self):
        args = (123, ["python", "-c", "pass"], None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False

    def test_pathlike_executable_with_failing_fspath_returns_false(self):
        class BadPath:
            def __fspath__(self):
                raise TypeError("not a real path")

        args = (BadPath(), ["python", "-c", "pass"], None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False

    def test_windows_command_line_form_with_sys_executable(self):
        """Windows: subprocess.Popen audit fires with (None, command_line_str, ...)."""
        cmdline = f'"{sys.executable}" -c "print(0)"'
        args = (None, cmdline, None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is True

    def test_windows_command_line_form_with_S_flag(self):
        cmdline = f'"{sys.executable}" -S -c "print(0)"'
        args = (None, cmdline, None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False

    def test_windows_command_line_form_different_python(self):
        args = (None, '"C:\\Python311\\python.exe" -c "print(0)"', None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False

    def test_windows_command_line_with_invalid_quotes_returns_false(self):
        """Malformed command line (shlex parse error) is treated as non-auto-inheriting."""
        args = (None, '"unterminated quote', None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False

    def test_windows_command_line_empty_returns_false(self):
        args = (None, "", None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False


class TestLockedPayloadIntegrity:
    """Direct unit tests for locked-mode payload-integrity enforcement in _handle_subprocess.

    Covers both the explicit-env-dict path (env=`{...}` passed to subprocess)
    and the inherited-env path (env=None → child reads os.environ).  The latter
    catches Python-level os.environ mutation and ctypes-level setenv/unsetenv
    by checking os.environ at launch time regardless of how it was set.
    """

    _GLOBAL_DICT: ClassVar[dict[str, object]] = {
        "allow": ["*.example.com"],
        "allow_localhost": True,
        "log_only": False,
        "fail_closed": False,
        "external_subprocess_policy": "allow",
        "locked": True,
    }
    _CANONICAL = json.dumps({"global": _GLOBAL_DICT, "scopes": []})

    def _locked_cfg(self, external_subprocess_policy: str = "allow") -> _Config:
        return _Config(
            policy=AllowPolicy([], allow_localhost=True),
            external_subprocess_policy=external_subprocess_policy,
            locked=True,
            lock_token=object(),
            _serialized_payload=self._CANONICAL,
            _global_payload_dict=self._GLOBAL_DICT,
        )

    def _set_canonical_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_CHILD_POLICY_ENV, self._CANONICAL)

    def test_locked_strip_blocks_popen(self, caplog, monkeypatch):
        """subprocess.Popen with env={} in locked mode raises SubprocessBlocked."""
        self._set_canonical_env(monkeypatch)
        cfg = self._locked_cfg()
        with (
            caplog.at_level(logging.WARNING, logger="tethered"),
            pytest.raises(tethered.SubprocessBlocked, match=r"strips _TETHERED_CHILD_POLICY"),
        ):
            _handle_subprocess(cfg, "subprocess.Popen", ("/bin/sh", [], None, {}))
        assert any("stripped policy env" in r.message for r in caplog.records)

    def test_locked_with_canonical_payload_allowed(self, monkeypatch):
        """env carrying the canonical payload value is allowed."""
        self._set_canonical_env(monkeypatch)
        cfg = self._locked_cfg()
        _handle_subprocess(
            cfg,
            "subprocess.Popen",
            ("/bin/sh", [], None, {_CHILD_POLICY_ENV: self._CANONICAL}),
        )  # should not raise

    def test_locked_with_substituted_payload_blocked(self, caplog, monkeypatch):
        """env carrying a different payload value is blocked as a substitution attempt."""
        self._set_canonical_env(monkeypatch)
        cfg = self._locked_cfg()
        with (
            caplog.at_level(logging.WARNING, logger="tethered"),
            pytest.raises(tethered.SubprocessBlocked, match=r"substitution attempt"),
        ):
            _handle_subprocess(
                cfg,
                "subprocess.Popen",
                ("/bin/sh", [], None, {_CHILD_POLICY_ENV: '{"allow": ["evil.test"]}'}),
            )
        assert any("substituted policy payload" in r.message for r in caplog.records)

    def test_locked_inherited_env_with_canonical_allowed(self, monkeypatch):
        """env=None inherits os.environ; if it carries the canonical, allowed."""
        self._set_canonical_env(monkeypatch)
        cfg = self._locked_cfg()
        _handle_subprocess(cfg, "subprocess.Popen", ("/bin/sh", [], None, None))  # should not raise

    def test_locked_inherited_env_with_stripped_environ_blocked(self, monkeypatch):
        """If os.environ has been stripped, env=None inheritance is blocked."""
        monkeypatch.delenv(_CHILD_POLICY_ENV, raising=False)
        cfg = self._locked_cfg()
        with pytest.raises(tethered.SubprocessBlocked, match=r"os\.environ strips"):
            _handle_subprocess(cfg, "subprocess.Popen", ("/bin/sh", [], None, None))

    def test_locked_inherited_env_with_substituted_environ_blocked(self, monkeypatch):
        """If os.environ has been mutated to a different value, env=None inheritance is blocked.

        This catches both Python-level os.environ mutation AND ctypes-level
        setenv (the check inspects os.environ at launch time, regardless of
        how it was set).
        """
        monkeypatch.setenv(_CHILD_POLICY_ENV, '{"allow": ["evil.test"]}')
        cfg = self._locked_cfg()
        with pytest.raises(tethered.SubprocessBlocked, match=r"substitution attempt"):
            _handle_subprocess(cfg, "subprocess.Popen", ("/bin/sh", [], None, None))

    def test_unlocked_strip_not_enforced(self):
        """env={} in non-locked mode does NOT trigger payload-integrity enforcement."""
        cfg = _Config(
            policy=AllowPolicy([], allow_localhost=True),
            external_subprocess_policy="allow",
            locked=False,
        )
        _handle_subprocess(cfg, "subprocess.Popen", ("/bin/sh", [], None, {}))  # should not raise

    def test_locked_no_env_arg_event_still_checks_environ(self, monkeypatch):
        """Events without an env arg (os.system) still verify os.environ in locked mode."""
        self._set_canonical_env(monkeypatch)
        cfg = self._locked_cfg()
        _handle_subprocess(cfg, "os.system", ("echo hi",))  # should not raise

    def test_locked_no_env_arg_event_blocked_when_environ_stripped(self, monkeypatch):
        """If os.environ is stripped, no-env-arg events (os.system) are blocked in locked mode."""
        monkeypatch.delenv(_CHILD_POLICY_ENV, raising=False)
        cfg = self._locked_cfg()
        with pytest.raises(tethered.SubprocessBlocked, match=r"os\.environ strips"):
            _handle_subprocess(cfg, "os.system", ("echo hi",))

    def test_locked_strip_blocks_posix_spawn(self, monkeypatch):
        """os.posix_spawn with env={} in locked mode also raises."""
        self._set_canonical_env(monkeypatch)
        cfg = self._locked_cfg()
        with pytest.raises(tethered.SubprocessBlocked, match=r"strips _TETHERED_CHILD_POLICY"):
            _handle_subprocess(cfg, "os.posix_spawn", ("/bin/ls", ["ls"], {}))


class TestPthFsHook:
    """Tests for the locked-mode FS hook protecting tethered.pth.

    Refuses Python-level deletion (``os.remove`` audit event, fired by
    ``os.remove`` / ``os.unlink`` / ``pathlib.Path.unlink`` / ``shutil.rmtree``),
    rename touching the path, write-mode open of the path, and chmod of
    the path.  ``ctypes`` calling libc directly bypasses the audit event
    entirely (documented limit).
    """

    _PTH = os.path.normcase(os.path.normpath(os.path.abspath("/site-packages/tethered.pth")))

    def _locked_cfg(self) -> _Config:
        return _Config(
            policy=AllowPolicy([], allow_localhost=True),
            locked=True,
            lock_token=object(),
            _serialized_payload="{}",
            _pth_path=self._PTH,
        )

    def test_unlock_no_pth_path_is_noop(self):
        """If _pth_path is empty (sysconfig couldn't determine purelib), hook is a no-op."""
        cfg = _Config(
            policy=AllowPolicy([], allow_localhost=True),
            locked=True,
            lock_token=object(),
            _serialized_payload="{}",
            _pth_path="",
        )
        _handle_pth_fs_op(cfg, "os.remove", ("/site-packages/tethered.pth",))  # no raise

    def test_unlock_unlocked_mode_is_noop(self):
        """Outside locked mode, FS hook does nothing."""
        cfg = _Config(
            policy=AllowPolicy([], allow_localhost=True),
            locked=False,
            _pth_path=self._PTH,
        )
        _handle_pth_fs_op(cfg, "os.remove", ("/site-packages/tethered.pth",))  # no raise

    def test_remove_pth_blocked(self, caplog):
        """The os.remove audit event (fired by os.remove, os.unlink, Path.unlink, shutil.rmtree)
        is blocked when targeting tethered.pth."""
        cfg = self._locked_cfg()
        with (
            caplog.at_level(logging.WARNING, logger="tethered"),
            pytest.raises(tethered.SubprocessBlocked, match=r"refused deletion"),
        ):
            _handle_pth_fs_op(cfg, "os.remove", ("/site-packages/tethered.pth",))
        assert any("blocked deletion of" in r.message for r in caplog.records)

    def test_remove_unrelated_path_allowed(self):
        cfg = self._locked_cfg()
        _handle_pth_fs_op(cfg, "os.remove", ("/tmp/other.txt",))  # no raise

    def test_rename_from_pth_blocked(self):
        cfg = self._locked_cfg()
        with pytest.raises(tethered.SubprocessBlocked, match=r"refused rename"):
            _handle_pth_fs_op(
                cfg,
                "os.rename",
                ("/site-packages/tethered.pth", "/tmp/elsewhere"),
            )

    def test_rename_to_pth_blocked(self):
        cfg = self._locked_cfg()
        with pytest.raises(tethered.SubprocessBlocked, match=r"refused rename"):
            _handle_pth_fs_op(
                cfg,
                "os.rename",
                ("/tmp/evil.pth", "/site-packages/tethered.pth"),
            )

    def test_rename_unrelated_paths_allowed(self):
        cfg = self._locked_cfg()
        _handle_pth_fs_op(cfg, "os.rename", ("/tmp/a", "/tmp/b"))  # no raise

    def test_open_pth_for_write_blocked(self):
        cfg = self._locked_cfg()
        with pytest.raises(tethered.SubprocessBlocked, match=r"refused write-open"):
            _handle_pth_fs_op(cfg, "open", ("/site-packages/tethered.pth", "wb", 0))

    def test_open_pth_with_append_mode_blocked(self):
        cfg = self._locked_cfg()
        with pytest.raises(tethered.SubprocessBlocked, match=r"refused write-open"):
            _handle_pth_fs_op(cfg, "open", ("/site-packages/tethered.pth", "a", 0))

    def test_open_pth_with_write_flags_blocked(self):
        cfg = self._locked_cfg()
        with pytest.raises(tethered.SubprocessBlocked, match=r"refused write-open"):
            _handle_pth_fs_op(cfg, "open", ("/site-packages/tethered.pth", "", os.O_WRONLY))

    def test_open_pth_for_read_allowed(self):
        cfg = self._locked_cfg()
        _handle_pth_fs_op(cfg, "open", ("/site-packages/tethered.pth", "rb", 0))  # no raise

    def test_open_unrelated_path_allowed(self):
        cfg = self._locked_cfg()
        _handle_pth_fs_op(cfg, "open", ("/tmp/other.txt", "wb", 0))  # no raise

    def test_open_pth_with_pathlike_target_blocked(self):
        cfg = self._locked_cfg()
        with pytest.raises(tethered.SubprocessBlocked):
            _handle_pth_fs_op(
                cfg,
                "open",
                (Path("/site-packages/tethered.pth"), "wb", 0),
            )

    def test_remove_with_bytes_path_blocked(self):
        """Audit events may pass paths as bytes; the hook handles both."""
        cfg = self._locked_cfg()
        with pytest.raises(tethered.SubprocessBlocked):
            _handle_pth_fs_op(cfg, "os.remove", (b"/site-packages/tethered.pth",))

    def test_remove_with_non_path_arg_ignored(self):
        cfg = self._locked_cfg()
        _handle_pth_fs_op(cfg, "os.remove", (123,))  # no raise

    def test_chmod_pth_blocked(self, caplog):
        """os.chmod on tethered.pth is blocked (catches ``chmod 0`` permission-strip attack)."""
        cfg = self._locked_cfg()
        with (
            caplog.at_level(logging.WARNING, logger="tethered"),
            pytest.raises(tethered.SubprocessBlocked, match=r"refused chmod"),
        ):
            _handle_pth_fs_op(cfg, "os.chmod", ("/site-packages/tethered.pth", 0))
        assert any("blocked chmod of" in r.message for r in caplog.records)

    def test_chmod_pth_with_any_mode_blocked(self):
        """Any chmod of tethered.pth is refused, not just chmod-to-0."""
        cfg = self._locked_cfg()
        with pytest.raises(tethered.SubprocessBlocked, match=r"refused chmod"):
            _handle_pth_fs_op(cfg, "os.chmod", ("/site-packages/tethered.pth", 0o644))

    def test_chmod_unrelated_path_allowed(self):
        cfg = self._locked_cfg()
        _handle_pth_fs_op(cfg, "os.chmod", ("/tmp/other.txt", 0))  # no raise

    def test_unknown_event_is_noop(self):
        """Events not in the dispatch table are silently ignored."""
        cfg = self._locked_cfg()
        # ``os.unlink`` is documented as firing ``os.remove``, but if some platform
        # ever fires ``os.unlink`` directly we want it to be a no-op (event name
        # mismatch) rather than crash, since the canonical event is what we hook.
        _handle_pth_fs_op(cfg, "os.unlink", ("/site-packages/tethered.pth",))  # no raise


class TestPathMatchesPthEdgeCases:
    """Direct tests for _path_matches_pth — covers branches not exercised by FS hook tests."""

    def test_empty_cached_returns_false(self):
        assert _path_matches_pth("/some/path", "") is False

    def test_fsdecode_failure_returns_false(self):
        """A PathLike whose __fspath__ raises TypeError is handled gracefully."""

        class BadPath:
            def __fspath__(self):
                raise TypeError("not a real path")

        # isinstance(BadPath(), os.PathLike) is True (has __fspath__),
        # so we reach os.fsdecode which raises TypeError → caught.
        assert _path_matches_pth(BadPath(), "/site-packages/tethered.pth") is False


class TestComputePthPath:
    """Direct tests for _compute_pth_path."""

    def test_returns_empty_when_tethered_file_missing(self, monkeypatch):
        """If ``tethered.__file__`` is unavailable (frozen interpreter, etc.), returns ''."""
        monkeypatch.setattr(tethered, "__file__", None)
        assert _compute_pth_path() == ""

    def test_returns_normalized_absolute_path(self):
        """Normal case: returns an absolute, normalized path ending in tethered.pth."""
        result = _compute_pth_path()
        assert result.endswith("tethered.pth") or result.endswith("tethered.pth".lower())
        assert os.path.isabs(result)


class TestPthAvailabilityWarning:
    """activate() warns when tethered.pth is missing — children won't auto-inherit."""

    def test_warning_when_pth_path_unresolved(self, monkeypatch, caplog):
        """``_compute_pth_path`` returning '' triggers the auto-propagation warning."""
        monkeypatch.setattr(_core, "_compute_pth_path", lambda: "")
        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.activate(allow=["*.example.com"])
        msgs = [r.message for r in caplog.records if "tethered.pth not found" in r.message]
        assert msgs, caplog.records
        assert "<unresolved>" in msgs[0]
        assert "auto-inherit the policy" in msgs[0]

    def test_warning_when_pth_path_does_not_exist(self, monkeypatch, caplog):
        """A computed path that doesn't actually exist on disk triggers the same warning."""
        monkeypatch.setattr(_core, "_compute_pth_path", lambda: "/nonexistent/path/tethered.pth")
        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.activate(allow=["*.example.com"])
        msgs = [r.message for r in caplog.records if "tethered.pth not found" in r.message]
        assert msgs
        assert "/nonexistent/path/tethered.pth" in msgs[0]

    def test_no_warning_when_pth_present(self, caplog):
        """Healthy install: .pth exists at the computed path → no warning emitted."""
        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.activate(allow=["*.example.com"])
        assert not [r for r in caplog.records if "tethered.pth not found" in r.message]

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_warning_in_locked_mode_mentions_fs_protection(self, monkeypatch, caplog):
        """Locked mode adds a note that FS-tamper protection is unavailable."""
        monkeypatch.setattr(_core, "_compute_pth_path", lambda: "")
        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.activate(allow=[], locked=True, lock_token=object())
        msg = next(r.message for r in caplog.records if "tethered.pth not found" in r.message)
        assert "FS-tamper protection" in msg

    def test_warning_outside_locked_mode_omits_fs_note(self, monkeypatch, caplog):
        """Non-locked activate omits the FS-tamper sentence (it's not relevant)."""
        monkeypatch.setattr(_core, "_compute_pth_path", lambda: "")
        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.activate(allow=["*.example.com"])
        msg = next(r.message for r in caplog.records if "tethered.pth not found" in r.message)
        assert "FS-tamper protection" not in msg


class TestAuditHookFsAndAllowDispatch:
    """Direct tests for the _audit_hook dispatch into _handle_pth_fs_op and the
    subprocess no-raise return path.
    """

    def test_audit_hook_subprocess_returns_when_allow(self):
        """_audit_hook dispatches a subprocess event then returns when policy is 'allow'."""
        tethered.activate(allow=[], external_subprocess_policy="allow")
        # Should not raise and should not log a warning either.
        _audit_hook("subprocess.Popen", ("/bin/sh", [], None, None))

    def test_audit_hook_routes_open_to_pth_fs_op_in_locked_mode(self):
        """_audit_hook routes open events to _handle_pth_fs_op when locked."""
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=object())
        cached = _core._config._pth_path
        with pytest.raises(tethered.SubprocessBlocked, match=r"refused write-open"):
            _audit_hook("open", (cached, "wb", 0))

    def test_audit_hook_skips_fs_events_when_unlocked(self):
        """_audit_hook does NOT enter the FS hook when locked mode is off."""
        tethered.activate(allow=["*.example.com"])  # not locked
        # Should not raise even for an open event on the .pth path
        cached = _core._compute_pth_path()
        _audit_hook("open", (cached, "wb", 0))


class TestSerializeNetworkRule:
    """Tests for _serialize_network_rule.

    Used by ``activate()`` to serialize network rules into the
    ``_TETHERED_CHILD_POLICY`` env var so spawn-mode child processes can
    re-parse them via ``AllowPolicy``.  Round-trip correctness is critical
    for IPv6 + port (which requires bracketed syntax to disambiguate the
    address-end from the port colon).
    """

    def _round_trip(self, rule_str: str) -> _NetworkRule:
        """Parse a rule string, serialize the resulting network rule, and
        re-parse it.  Returns the round-tripped network rule.
        """
        policy = AllowPolicy([rule_str])
        assert len(policy._network_rules) == 1, f"expected 1 network rule from {rule_str!r}"
        serialized = _serialize_network_rule(policy._network_rules[0])
        reparsed = AllowPolicy([serialized])
        assert len(reparsed._network_rules) == 1, (
            f"{rule_str!r} serialized to {serialized!r} but did not re-parse as a network rule"
        )
        return reparsed._network_rules[0]

    def test_ipv4_no_port(self):
        rule = self._round_trip("10.0.0.0/8")
        assert str(rule.network) == "10.0.0.0/8"
        assert rule.port is None

    def test_ipv4_with_port(self):
        rule = self._round_trip("10.0.0.0/8:5432")
        assert str(rule.network) == "10.0.0.0/8"
        assert rule.port == 5432

    def test_ipv6_no_port(self):
        rule = self._round_trip("[2001:db8::]/32")
        assert rule.network.version == 6
        assert rule.port is None

    def test_ipv6_with_port(self):
        """The bug case: IPv6 CIDR + port must round-trip via bracketed syntax."""
        rule = self._round_trip("[2001:db8::]/32:443")
        assert rule.network.version == 6
        assert rule.port == 443

    def test_ipv6_single_address_with_port(self):
        rule = self._round_trip("[2001:db8::1]:443")
        assert rule.network.version == 6
        assert rule.port == 443

    def test_ipv4_single_address_with_port(self):
        rule = self._round_trip("198.51.100.1:443")
        assert rule.network.version == 4
        assert rule.port == 443


class TestFrameMutationHelpers:
    """Direct tests for _find_execute_child_frame, _inject_scope_env, _build_per_launch_env.

    These helpers underpin the per-launch scope-env injection.  The frame
    finder uses a defensive shape check (co_name + co_varnames + module
    name); the injector branches on Python version to handle the PEP 667
    write-through proxy on 3.13+ vs PyFrame_LocalsToFast on ≤ 3.12.
    """

    def test_find_execute_child_frame_finds_synthetic_subprocess_frame(self):
        """A _execute_child frame whose globals say ``__name__ == 'subprocess'`` is matched."""
        captured: dict[str, object] = {"frame": None}
        exec_globals = {
            "__name__": "subprocess",
            "_find": _find_execute_child_frame,
            "out": captured,
        }
        # Building the function via exec() ensures f_globals is exec_globals
        # (so f_globals["__name__"] == "subprocess") and the code's co_name
        # matches the def-statement (so co_name == "_execute_child").
        exec(  # nosec B102 — controlled local source for the test fixture
            "def _execute_child(env=None):\n"
            "    out['frame'] = _find()\n"
            "_execute_child(env={'X': '1'})\n",
            exec_globals,
        )
        frame = captured["frame"]
        assert frame is not None
        assert frame.f_code.co_name == "_execute_child"
        assert "env" in frame.f_code.co_varnames

    def test_find_execute_child_frame_rejects_user_code_with_same_name(self):
        """A user function named _execute_child outside subprocess module is NOT matched."""
        captured: dict[str, object] = {}

        def _execute_child(env=None):  # type: ignore[unused-ignore]
            captured["frame"] = _find_execute_child_frame()

        _execute_child(env={})
        assert captured["frame"] is None  # rejected: f_globals["__name__"] is this test module

    def test_find_execute_child_frame_returns_none_when_not_in_stack(self):
        assert _find_execute_child_frame() is None

    def test_inject_scope_env_writes_local(self):
        """_inject_scope_env mutates env in the target frame; the local sees the new value."""
        observed: dict[str, object] = {}

        def target():
            env = {"original": "value"}
            # Capture before mutation
            observed["before"] = dict(env)
            # Pretend an audit hook called us; mutate this frame's env local
            ok = _inject_scope_env(sys._getframe(0), {"new": "value"})
            observed["ok"] = ok
            # Re-read env from the local; should be the new dict (env is
            # rebound by the helper via f_locals write-through proxy on 3.13+
            # or PyFrame_LocalsToFast on 3.10-3.12).
            observed["after"] = dict(env)

        target()
        assert observed["ok"] is True
        # On 3.13+ the proxy writes through immediately; on ≤ 3.12 PyFrame_LocalsToFast
        # is what makes the local binding observe the new value.  Either way the
        # local should reflect the new dict by the time we read it again.
        assert observed["after"] == {"new": "value"}

    def test_build_per_launch_env_preserves_existing_env_dict(self):
        """Explicit env dict: existing keys preserved, policy var overwritten."""
        cfg = _Config(
            policy=AllowPolicy(["api.example.com"]),
            _global_payload_dict={"allow": ["api.example.com"], "log_only": False},
        )
        env_arg = {"PATH": "/usr/bin", _CHILD_POLICY_ENV: "old-value"}
        new_env = _build_per_launch_env(
            "subprocess.Popen",
            ("/bin/sh", [], None, env_arg),
            (),
            cfg,
        )
        assert new_env["PATH"] == "/usr/bin"
        assert new_env[_CHILD_POLICY_ENV] != "old-value"
        # Ensure we didn't mutate the caller's dict
        assert env_arg[_CHILD_POLICY_ENV] == "old-value"

    def test_build_per_launch_env_copies_os_environ_when_env_none(self, monkeypatch):
        """env=None inheritance triggers a copy of os.environ as the base dict."""
        monkeypatch.setenv("TETHERED_TEST_VAR", "preserved")
        cfg = _Config(
            policy=AllowPolicy([]),
            _global_payload_dict={"allow": [], "log_only": False},
        )
        new_env = _build_per_launch_env("subprocess.Popen", ("/bin/sh", [], None, None), (), cfg)
        assert new_env["TETHERED_TEST_VAR"] == "preserved"
        assert _CHILD_POLICY_ENV in new_env

    def test_build_per_launch_env_serializes_scopes(self):
        """The injected payload's 'scopes' field reflects the active scope chain."""
        cfg = _Config(
            policy=AllowPolicy([]),
            _global_payload_dict={"allow": [], "log_only": False},
        )
        scope_cfg = _ScopeConfig(
            policy=AllowPolicy(["api.allowed.com"]),
            log_only=False,
            fail_closed=False,
            on_blocked=None,
            label="test-scope",
        )
        new_env = _build_per_launch_env(
            "subprocess.Popen", ("/bin/sh", [], None, None), (scope_cfg,), cfg
        )
        payload = json.loads(new_env[_CHILD_POLICY_ENV])
        assert payload["scopes"]
        assert payload["scopes"][0]["allow"] == ["api.allowed.com"]
        assert payload["scopes"][0]["label"] == "test-scope"

    def test_build_per_launch_env_global_null_when_no_cfg(self):
        """Scope-only mode (cfg=None) emits global=null in the payload."""
        scope_cfg = _ScopeConfig(
            policy=AllowPolicy(["api.allowed.com"]),
            log_only=False,
            fail_closed=False,
            on_blocked=None,
            label="scope-only",
        )
        new_env = _build_per_launch_env(
            "subprocess.Popen", ("/bin/sh", [], None, None), (scope_cfg,), None
        )
        payload = json.loads(new_env[_CHILD_POLICY_ENV])
        assert payload["global"] is None
        assert payload["scopes"][0]["allow"] == ["api.allowed.com"]

    def test_inject_scope_env_handles_f_locals_write_failure(self, monkeypatch, caplog):
        """If the f_locals write itself raises, _inject_scope_env returns False and warns."""

        class StubFrame:
            f_code = type("c", (), {"co_name": "x"})()

            class _PropFails:
                def __setitem__(self, k, v):
                    raise RuntimeError("boom")

            f_locals = _PropFails()

        with caplog.at_level(logging.WARNING, logger="tethered"):
            result = _inject_scope_env(StubFrame(), {"X": "1"})
        assert result is False
        assert any(
            "scope env injection failed (f_locals write)" in r.message for r in caplog.records
        )

    def test_inject_scope_env_handles_ctypes_failure(self, monkeypatch, caplog):
        """If PyFrame_LocalsToFast raises (3.10-3.12 path), returns False and warns."""
        if sys.version_info >= (3, 13):
            pytest.skip("PyFrame_LocalsToFast path not used on 3.13+")

        # Use a dict frame so f_locals write succeeds; force ctypes to fail
        # by patching the import inside the helper.
        def _broken_call(*a, **kw):
            raise OSError("simulated ctypes failure")

        monkeypatch.setattr(ctypes.pythonapi, "PyFrame_LocalsToFast", _broken_call)

        f = sys._getframe(0)
        with caplog.at_level(logging.WARNING, logger="tethered"):
            result = _inject_scope_env(f, {"X": "1"})
        assert result is False
        assert any("PyFrame_LocalsToFast" in r.message for r in caplog.records)


class TestParseWindowsCmdline:
    """Tests for _parse_windows_cmdline (Windows command-line parser)."""

    def test_unquoted_exe_with_args(self):
        # pre_args excludes the -c terminator and everything after.
        result = _parse_windows_cmdline("python.exe -c pass")
        assert result == ("python.exe", ["python.exe"])

    def test_unquoted_exe_no_args(self):
        result = _parse_windows_cmdline("python.exe")
        assert result == ("python.exe", ["python.exe"])

    def test_quoted_exe(self):
        result = _parse_windows_cmdline('"C:\\Program Files\\Python\\python.exe" -c pass')
        assert result == (
            "C:\\Program Files\\Python\\python.exe",
            ["C:\\Program Files\\Python\\python.exe"],
        )

    def test_quoted_exe_unterminated_quote(self):
        # Quoted exe with no closing quote — return None (can't parse safely).
        assert _parse_windows_cmdline('"unterminated') is None

    def test_empty_string(self):
        assert _parse_windows_cmdline("") is None
        assert _parse_windows_cmdline("   ") is None

    def test_pre_args_stops_at_minus_c(self):
        result = _parse_windows_cmdline("python.exe -S -c 'script body'")
        assert result == ("python.exe", ["python.exe", "-S"])  # stops before -c

    def test_pre_args_stops_at_minus_m(self):
        result = _parse_windows_cmdline("python.exe -I -m mymod arg")
        assert result == ("python.exe", ["python.exe", "-I"])  # stops before -m


class TestScopeSubprocessPropagation:
    """End-to-end tests for scope propagation to spawn-mode child processes.

    Covers the full path: parent enters a scope → audit hook fires for
    subprocess.Popen → ``_find_execute_child_frame`` walks the stack →
    ``_inject_scope_env`` rewrites the frame's env local → child observes
    the per-launch payload.
    """

    # Reads the inherited state via _scopes ContextVar (not os.environ —
    # the child's _autoactivate.activate() overwrites os.environ back to
    # the at-rest payload after parsing it).  Returns global allow + each
    # scope's allow as JSON.
    _CHILD_PRINT_INHERITED_STATE = (
        "import json, tethered._core as c; "
        "print(json.dumps({"
        "'global_allow': c._config.policy._exact_hosts_any_port and "
        "list(c._config.policy._exact_hosts_any_port) "
        "or [r.pattern for r in c._config.policy._host_rules] "
        "if c._config else None, "
        "'scope_allow': ["
        "(list(s.policy._exact_hosts_any_port) "
        "or [r.pattern for r in s.policy._host_rules]) "
        "for s in c._scopes.get()"
        "]"
        "}))"
    )

    def test_global_plus_scope_round_trip(self):
        """Parent activate() + active scope: child inherits both into _config and _scopes."""
        tethered.activate(allow=["*.allowed.com"])
        with tethered.scope(allow=["api.allowed.com"]):
            result = subprocess.run(  # nosec B603 B607
                [sys.executable, "-c", self._CHILD_PRINT_INHERITED_STATE],
                capture_output=True,
                text=True,
                timeout=15,
            )
        assert result.returncode == 0, result.stderr
        observed = json.loads(result.stdout.strip())
        assert observed["global_allow"] == ["*.allowed.com"]
        assert observed["scope_allow"] == [["api.allowed.com"]]

    def test_scope_only_propagates_when_no_activate(self):
        """A library using only scope() (no activate) still propagates to its subprocesses."""
        with tethered.scope(allow=["api.allowed.com"]):
            result = subprocess.run(  # nosec B603 B607
                [sys.executable, "-c", self._CHILD_PRINT_INHERITED_STATE],
                capture_output=True,
                text=True,
                timeout=15,
            )
        assert result.returncode == 0, result.stderr
        observed = json.loads(result.stdout.strip())
        assert observed["global_allow"] is None
        assert observed["scope_allow"] == [["api.allowed.com"]]

    def test_no_scope_no_inheritance_change(self):
        """Without any scope, the child has the global config and an empty scope chain."""
        tethered.activate(allow=["*.allowed.com"])
        result = subprocess.run(  # nosec B603 B607
            [sys.executable, "-c", self._CHILD_PRINT_INHERITED_STATE],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr
        observed = json.loads(result.stdout.strip())
        assert observed["global_allow"] == ["*.allowed.com"]
        assert observed["scope_allow"] == []

    def test_child_actually_enforces_inherited_scope(self):
        """The inherited scope blocks connections to hosts outside its allow list."""
        tethered.activate(allow=["*.allowed.com"])
        with tethered.scope(allow=["api.allowed.com"]):
            r = subprocess.run(  # nosec B603 B607
                [
                    sys.executable,
                    "-c",
                    (
                        "import socket\n"
                        "try:\n"
                        "    socket.getaddrinfo('other.allowed.com', 80)\n"
                        "    print('ALLOWED')\n"
                        "except Exception as e:\n"
                        "    print(f'BLOCKED:{type(e).__name__}')"
                    ),
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
        assert r.returncode == 0, r.stderr
        # Parent allows *.allowed.com (other.allowed.com would pass), but the
        # inherited scope only allows api.allowed.com — so other.allowed.com
        # is blocked by the scope intersection.
        assert "BLOCKED" in r.stdout

    def test_scope_decorator_propagates_to_subprocess(self):
        """``@scope`` decorator form propagates the same as the context-manager form.

        The decorator wraps the call in the same ``__enter__``/``__exit__``
        context, so the subprocess.Popen audit hook sees the active scope on
        the per-call ``_scopes`` ContextVar and injects it into the child
        env exactly as it does for ``with scope(...):``.
        """
        tethered.activate(allow=["*.allowed.com"])

        @tethered.scope(allow=["api.allowed.com"])
        def launch_child() -> subprocess.CompletedProcess[str]:
            return subprocess.run(  # nosec B603 B607
                [sys.executable, "-c", self._CHILD_PRINT_INHERITED_STATE],
                capture_output=True,
                text=True,
                timeout=15,
            )

        result = launch_child()
        assert result.returncode == 0, result.stderr
        observed = json.loads(result.stdout.strip())
        assert observed["global_allow"] == ["*.allowed.com"]
        assert observed["scope_allow"] == [["api.allowed.com"]]

    def test_multi_thread_isolation(self):
        """Two threads in different scopes launch concurrently; each child sees its own scope."""
        tethered.activate(allow=["*.allowed.com"])
        results: dict[str, list[list[str]]] = {}
        errors: list[str] = []

        def worker(name: str, allow: list[str]) -> None:
            try:
                with tethered.scope(allow=allow):
                    r = subprocess.run(  # nosec B603 B607
                        [sys.executable, "-c", self._CHILD_PRINT_INHERITED_STATE],
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    if r.returncode != 0:
                        errors.append(f"{name}: rc={r.returncode}, stderr={r.stderr}")
                        return
                    observed = json.loads(r.stdout.strip())
                    results[name] = observed["scope_allow"]
            except Exception as e:
                errors.append(f"{name}: {type(e).__name__}: {e}")

        ta = threading.Thread(target=worker, args=("a", ["a.allowed.com"]))
        tb = threading.Thread(target=worker, args=("b", ["b.allowed.com"]))
        ta.start()
        tb.start()
        ta.join(timeout=30)
        tb.join(timeout=30)

        assert not errors, errors
        assert results == {"a": [["a.allowed.com"]], "b": [["b.allowed.com"]]}

    def test_explicit_env_dict_preserves_user_vars(self):
        """When the user passes env={...}, their vars are preserved and the policy is added."""
        tethered.activate(allow=["*.allowed.com"])
        minimal_env = {
            k: v
            for k, v in os.environ.items()
            if k.upper() in {"PATH", "SYSTEMROOT", "PATHEXT", "TEMP", "TMP"}
        }
        minimal_env["TETHERED_USER_VAR"] = "user-value"
        with tethered.scope(allow=["api.allowed.com"]):
            r = subprocess.run(  # nosec B603 B607
                [
                    sys.executable,
                    "-c",
                    (
                        "import os, json, tethered._core as c; "
                        "scopes = [list(s.policy._exact_hosts_any_port) "
                        "or [r.pattern for r in s.policy._host_rules] "
                        "for s in c._scopes.get()]; "
                        "print(json.dumps({"
                        "'user': os.environ.get('TETHERED_USER_VAR'), "
                        "'scope_allow': scopes"
                        "}))"
                    ),
                ],
                capture_output=True,
                text=True,
                timeout=15,
                env=minimal_env,
            )
        assert r.returncode == 0, r.stderr
        observed = json.loads(r.stdout.strip())
        assert observed["user"] == "user-value"
        assert observed["scope_allow"] == [["api.allowed.com"]]

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_locked_plus_scope_canonical_global_preserved(self):
        """In locked mode, the child inherits both the canonical global AND the active scope."""
        tethered.activate(allow=["*.allowed.com"], locked=True, lock_token=object())
        with tethered.scope(allow=["api.allowed.com"]):
            r = subprocess.run(  # nosec B603 B607
                [sys.executable, "-c", self._CHILD_PRINT_INHERITED_STATE],
                capture_output=True,
                text=True,
                timeout=15,
            )
        assert r.returncode == 0, r.stderr
        observed = json.loads(r.stdout.strip())
        assert observed["global_allow"] == ["*.allowed.com"]
        assert observed["scope_allow"] == [["api.allowed.com"]]

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_locked_corrupted_env_payload_blocked(self):
        """Locked mode rejects a launch whose explicit env carries a non-JSON policy value."""
        tethered.activate(allow=[], locked=True, lock_token=object())
        with pytest.raises(tethered.SubprocessBlocked, match=r"not valid JSON"):
            subprocess.run(  # nosec B603 B607
                [sys.executable, "-c", "pass"],
                env={_CHILD_POLICY_ENV: "{not valid json"},
                capture_output=True,
                timeout=10,
            )

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_locked_substituted_global_blocked(self):
        """Locked mode rejects a launch whose env carries a different 'global' field."""
        tethered.activate(allow=["*.allowed.com"], locked=True, lock_token=object())
        substituted = json.dumps(
            {"global": {"allow": ["evil.test"], "log_only": False}, "scopes": []}
        )
        with pytest.raises(tethered.SubprocessBlocked, match=r"substitution attempt"):
            subprocess.run(  # nosec B603 B607
                [sys.executable, "-c", "pass"],
                env={_CHILD_POLICY_ENV: substituted},
                capture_output=True,
                timeout=10,
            )

    def test_handle_subprocess_no_frame_locked_fails_closed(self, monkeypatch):
        """When the _execute_child frame is unfindable in locked mode, the launch is blocked."""
        # Force frame finder to return None
        monkeypatch.setattr(_core, "_find_execute_child_frame", lambda: None)
        tethered.activate(allow=["*.allowed.com"], locked=True, lock_token=object())
        with (
            tethered.scope(allow=["api.allowed.com"]),
            pytest.raises(tethered.SubprocessBlocked, match=r"could not locate.*_execute_child"),
        ):
            _handle_subprocess(
                _core._config,
                "subprocess.Popen",
                (sys.executable, [sys.executable], None, None),
                _core._scopes.get(),
            )

    def test_handle_subprocess_no_frame_unlocked_warns_and_proceeds(self, monkeypatch, caplog):
        """When the _execute_child frame is unfindable without locked mode, warn and proceed."""
        monkeypatch.setattr(_core, "_find_execute_child_frame", lambda: None)
        tethered.activate(allow=["*.allowed.com"])
        with (
            tethered.scope(allow=["api.allowed.com"]),
            caplog.at_level(logging.WARNING, logger="tethered"),
        ):
            _handle_subprocess(
                _core._config,
                "subprocess.Popen",
                (sys.executable, [sys.executable], None, None),
                _core._scopes.get(),
            )
        assert any("scope subprocess propagation unavailable" in r.message for r in caplog.records)

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_handle_subprocess_inject_failure_locked_fails_closed(self, monkeypatch):
        """If frame mutation reports failure in locked mode, the launch is blocked."""
        monkeypatch.setattr(_core, "_inject_scope_env", lambda frame, env: False)
        fake_frame = type("F", (), {})()
        monkeypatch.setattr(_core, "_find_execute_child_frame", lambda: fake_frame)
        tethered.activate(allow=["*.allowed.com"], locked=True, lock_token=object())
        with (
            tethered.scope(allow=["api.allowed.com"]),
            pytest.raises(tethered.SubprocessBlocked, match=r"frame-locals mutation failed"),
        ):
            _handle_subprocess(
                _core._config,
                "subprocess.Popen",
                (sys.executable, [sys.executable], None, None),
                _core._scopes.get(),
            )

    def test_handle_subprocess_scope_only_non_auto_inheriting_returns(self):
        """Scope-only without global config: non-auto-inheriting launches return silently."""
        # cfg=None, scope active.  os.system is non-auto-inheriting and there
        # is no global config to apply external_subprocess_policy from.
        with tethered.scope(allow=["api.allowed.com"]):
            _handle_subprocess(
                None,
                "os.system",
                ("echo hi",),
                _core._scopes.get(),
            )

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_handle_subprocess_locked_json_decode_error_direct(self):
        """Direct unit test of locked-mode integrity check raising on JSONDecodeError."""
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=object())
        with pytest.raises(tethered.SubprocessBlocked, match=r"not valid JSON"):
            _handle_subprocess(
                _core._config,
                "subprocess.Popen",
                ("/bin/sh", [], None, {_CHILD_POLICY_ENV: "{not valid json"}),
            )

    @pytest.mark.skipif(
        sys.version_info >= (3, 13), reason="PyFrame_LocalsToFast path is 3.10-3.12 only"
    )
    def test_inject_scope_env_pyframe_localstofast_path(self):
        """The PyFrame_LocalsToFast path runs on Python 3.10-3.12 only."""

        def target():
            env = {"original": "value"}
            ok = _inject_scope_env(sys._getframe(0), {"new": "value"})
            return ok, env

        ok, env_after = target()
        assert ok is True
        assert env_after == {"new": "value"}


class TestHigherLevelLaunchAPIs:
    """End-to-end propagation tests for documented higher-level subprocess APIs.

    All of these delegate to ``subprocess.Popen._execute_child`` internally
    (or, for fork mode, copy process state via the OS).  The unit + Popen
    integration tests verify the underlying chain; these tests verify the
    documented call-site shapes — multiprocessing.Pool, ProcessPoolExecutor,
    asyncio.create_subprocess_exec, shell=True, fork mode, multi-level
    subprocess chains — really do hit it.
    """

    _MP_TIMEOUT = 30  # spawn-mode worker startup is slow on Windows
    _SP_TIMEOUT = 20

    def test_multiprocessing_pool_spawn_inherits_policy(self):
        """multiprocessing.Pool (spawn mode) workers inherit the parent's policy."""
        tethered.activate(allow=["api.allowed.com"])
        ctx = mp.get_context("spawn")
        with ctx.Pool(processes=1) as pool:
            result = pool.apply(_check_egress_worker, ("evil.test",))
        assert result == "TETHERED_BLOCKED", result

    def test_multiprocessing_pool_spawn_does_not_propagate_scope(self):
        """Documented limit: spawn-mode multiprocessing bypasses ``subprocess.Popen``.

        ``multiprocessing.popen_spawn_{posix,win32}.Popen`` calls
        ``_posixsubprocess.fork_exec`` (POSIX) or ``_winapi.CreateProcess``
        (Windows) directly.  Neither fires the ``subprocess.Popen`` audit
        event, so frame mutation can't inject the active scope chain.
        Workers see only the parent's GLOBAL policy (which propagates via
        inherited ``os.environ``).  Use fork mode (POSIX) if you need
        scope propagation in multiprocessing workers, or restructure to
        call ``subprocess.run([sys.executable, ...])`` directly.
        """
        tethered.activate(allow=["*.allowed.com"])
        ctx = mp.get_context("spawn")
        with (
            tethered.scope(allow=["api.allowed.com"], label="parent_scope"),
            ctx.Pool(processes=1) as pool,
        ):
            state = pool.apply(_inspect_state_worker)
        # Global propagates via env var inheritance.
        assert state["config_active"], state
        # But scope does NOT propagate — no subprocess.Popen audit fires.
        assert state["scope_count"] == 0, (
            "unexpected scope inheritance through multiprocessing.Pool spawn — "
            "this is supposed to be a documented limitation; "
            f"workers saw scopes: {state['scope_labels']}"
        )

    def test_process_pool_executor_inherits_policy(self):
        """concurrent.futures.ProcessPoolExecutor workers inherit the parent's GLOBAL policy."""
        tethered.activate(allow=["api.allowed.com"])
        with ProcessPoolExecutor(max_workers=1, mp_context=mp.get_context("spawn")) as executor:
            future = executor.submit(_check_egress_worker, "evil.test")
            result = future.result(timeout=self._MP_TIMEOUT)
        assert result == "TETHERED_BLOCKED", result

    def test_process_pool_executor_does_not_propagate_scope(self):
        """Same limit as multiprocessing.Pool — ProcessPoolExecutor uses the spawn path."""
        tethered.activate(allow=["*.allowed.com"])
        with (
            tethered.scope(allow=["api.allowed.com"], label="parent_scope"),
            ProcessPoolExecutor(max_workers=1, mp_context=mp.get_context("spawn")) as executor,
        ):
            state = executor.submit(_inspect_state_worker).result(timeout=self._MP_TIMEOUT)
        assert state["config_active"], state
        assert state["scope_count"] == 0, (
            "unexpected scope inheritance through ProcessPoolExecutor spawn — "
            f"workers saw scopes: {state['scope_labels']}"
        )

    @pytest.mark.skipif(sys.platform != "linux", reason="fork mode only reliable on Linux")
    def test_multiprocessing_fork_inherits_via_state_copy(self):
        """multiprocessing.Pool (fork mode) inherits policy via OS-level state copy.

        Linux only — fork copies the entire process state including
        ``_config``.  The child's ``tethered.pth`` bootstrap is a no-op
        (idempotency check) since ``_config`` is already populated from
        the forked parent state.
        """
        tethered.activate(allow=["api.allowed.com"])
        ctx = mp.get_context("fork")
        with ctx.Pool(processes=1) as pool:
            result = pool.apply(_check_egress_worker, ("evil.test",))
        assert result == "TETHERED_BLOCKED", result

    @pytest.mark.skipif(sys.platform != "linux", reason="fork mode only reliable on Linux")
    def test_multiprocessing_fork_inherits_scope_via_contextvar_copy(self):
        """Fork mode also copies ``_scopes`` ContextVar — child sees the parent's scope."""
        tethered.activate(allow=["*.allowed.com"])
        ctx = mp.get_context("fork")
        with (
            tethered.scope(allow=["api.allowed.com"]),
            ctx.Pool(processes=1) as pool,
        ):
            result = pool.apply(_check_egress_worker, ("other.allowed.com",))
        assert result == "TETHERED_BLOCKED", result

    async def test_asyncio_create_subprocess_exec_inherits_policy(self):
        """``asyncio.create_subprocess_exec`` children inherit the parent's policy."""
        tethered.activate(allow=["api.allowed.com"])
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            "import socket\n"
            "import tethered\n"
            "try:\n"
            "    socket.getaddrinfo('evil.test', 80)\n"
            "    print('ALLOWED')\n"
            "except tethered.EgressBlocked:\n"
            "    print('TETHERED_BLOCKED')\n"
            "except Exception as e:\n"
            "    print(f'OTHER:{type(e).__name__}')",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self._SP_TIMEOUT)
        assert b"TETHERED_BLOCKED" in stdout, (stdout, stderr)

    async def test_asyncio_with_active_scope_propagates(self):
        """A scope active during ``create_subprocess_exec`` propagates via frame mutation.

        ``other.allowed.com`` is allowed by the global but blocked by the scope.
        The async coroutine and the audit hook share the same context, so the
        scope is visible at the launch site.
        """
        tethered.activate(allow=["*.allowed.com"])
        with tethered.scope(allow=["api.allowed.com"]):
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                "import socket\n"
                "import tethered\n"
                "try:\n"
                "    socket.getaddrinfo('other.allowed.com', 80)\n"
                "    print('ALLOWED')\n"
                "except tethered.EgressBlocked:\n"
                "    print('TETHERED_BLOCKED')\n"
                "except Exception as e:\n"
                "    print(f'OTHER:{type(e).__name__}')",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self._SP_TIMEOUT)
        assert b"TETHERED_BLOCKED" in stdout, (stdout, stderr)

    def test_subprocess_run_shell_true_subject_to_external_policy(self):
        """``shell=True`` launches a non-Python shell — covered by ``external_subprocess_policy``.

        On POSIX it's ``/bin/sh``, on Windows it's ``cmd.exe``.  Either way,
        the audit hook sees a non-``sys.executable`` launch and routes through
        the external-subprocess path.
        """
        tethered.activate(allow=[], external_subprocess_policy="block")
        with pytest.raises(tethered.SubprocessBlocked):
            subprocess.run(  # nosec B602 B603 B607
                "echo hi",
                shell=True,
                capture_output=True,
                timeout=5,
            )

    def test_three_level_chain_grandchild_inherits(self):
        """Grandchild process inherits the policy through two levels of ``subprocess.run``.

        Parent activates → spawns child → child spawns grandchild.  The
        grandchild's egress is enforced by the same chain (each level's
        ``tethered.pth`` re-engages tethered with the inherited policy).
        """
        grandchild = (
            "import socket\n"
            "import tethered\n"
            "try:\n"
            "    socket.getaddrinfo('evil.test', 80)\n"
            "    print('ALLOWED')\n"
            "except tethered.EgressBlocked:\n"
            "    print('TETHERED_BLOCKED')\n"
            "except Exception as e:\n"
            "    print(f'OTHER:{type(e).__name__}')"
        )
        child = (
            "import subprocess, sys\n"
            f"r = subprocess.run([sys.executable, '-c', {grandchild!r}], "
            "capture_output=True, text=True, timeout=20)\n"
            "print(r.stdout, end='')"
        )
        tethered.activate(allow=["api.allowed.com"])
        result = subprocess.run(  # nosec B603
            [sys.executable, "-c", child],
            capture_output=True,
            text=True,
            timeout=self._MP_TIMEOUT,
        )
        assert "TETHERED_BLOCKED" in result.stdout, (result.stdout, result.stderr)


class TestScopeSubprocessPerformance:
    """Microbenchmarks for the scope-subprocess audit hook helpers.

    These tests measure relative timing to catch structural regressions —
    an infinite frame walk, an O(n²) env-dict construction, accidental
    re-serialization on every event, etc.  Bounds are deliberately ~100x
    the expected value on a modern laptop, so they don't flake on slow CI
    but do trip on real algorithmic regressions.
    """

    _ITERATIONS = 1000

    def _measure(self, fn, iterations: int | None = None) -> float:
        """Return per-iteration mean wall time in microseconds."""
        n = iterations or self._ITERATIONS
        # Warm-up: avoid first-call import / JIT effects in timing.
        for _ in range(min(50, n)):
            fn()
        start = time.perf_counter()
        for _ in range(n):
            fn()
        elapsed = time.perf_counter() - start
        return (elapsed / n) * 1_000_000

    def test_handle_subprocess_no_scope_is_near_zero(self):
        """The no-scope, no-cfg early-return path must stay essentially free.

        cfg=None, scope_stack=() → _handle_subprocess returns on the first
        if-branch in the audit hook (subprocess events).  This is the path
        every scope-free, activate-free app pays.
        """

        def call() -> None:
            _handle_subprocess(None, "subprocess.Popen", ("/x", [], None, None), ())

        per_us = self._measure(call)
        # Expected: ~100ns; ceiling 50µs (500x headroom for CI variance).
        assert per_us < 50, f"_handle_subprocess no-scope path took {per_us:.2f}µs / call"

    def test_find_execute_child_frame_bounded(self):
        """Frame walking is O(stack depth) and must stay bounded.

        Calls the finder from a realistic 8-frame-deep call stack.  If the
        depth-cap or co_name check regresses (infinite walk, expensive
        per-frame work), this trips.
        """

        def deep(n: int) -> object:
            if n == 0:
                return _find_execute_child_frame()
            return deep(n - 1)

        def call() -> None:
            deep(8)

        per_us = self._measure(call)
        # Expected: ~5µs; ceiling 500µs.
        assert per_us < 500, f"_find_execute_child_frame from depth 8 took {per_us:.2f}µs / call"

    def test_build_per_launch_env_bounded(self):
        """Building the per-launch env scales linearly with os.environ size.

        Simulates a realistic env (~100 vars).  If a future refactor copies
        os.environ multiple times or re-serializes on every launch, this trips.
        """
        cfg = _Config(
            policy=AllowPolicy(["*.example.com"]),
            _global_payload_dict={"allow": ["*.example.com"], "log_only": False},
        )
        scope_cfg = _ScopeConfig(
            policy=AllowPolicy(["api.example.com"]),
            log_only=False,
            fail_closed=False,
            on_blocked=None,
            label="bench",
        )

        def call() -> None:
            _build_per_launch_env("subprocess.Popen", ("/x", [], None, None), (scope_cfg,), cfg)

        per_us = self._measure(call, iterations=500)  # heavier work, fewer iterations
        # Expected: ~30µs; ceiling 3ms.
        assert per_us < 3000, f"_build_per_launch_env took {per_us:.2f}µs / call"

    def test_inject_scope_env_bounded(self):
        """Frame mutation is a single dict write (3.13+) or ctypes call (≤ 3.12)."""

        # Anchor frame: a real Python frame with an `env` local.
        def target_frame_owner() -> object:
            env = None  # noqa: F841 — present so the frame has the local
            return sys._getframe(0)

        frame = target_frame_owner()
        new_env = {"X": "1"}

        def call() -> None:
            _inject_scope_env(frame, new_env)

        per_us = self._measure(call, iterations=500)
        # Expected: ~1µs (3.13+) or ~5µs (≤ 3.12); ceiling 200µs.
        assert per_us < 200, f"_inject_scope_env took {per_us:.2f}µs / call"

    def test_audit_hook_socket_event_unchanged(self):
        """The hot path (socket events) must not regress when subprocess code grows."""

        # No active config / scope → audit hook returns immediately on the
        # socket.* branch.  Measures only the dispatch overhead.
        def call() -> None:
            _audit_hook("socket.connect", (None, ("127.0.0.1", 80)))

        per_us = self._measure(call, iterations=2000)
        # Expected: ~1µs; ceiling 100µs.
        assert per_us < 100, f"_audit_hook socket path took {per_us:.2f}µs / call"
