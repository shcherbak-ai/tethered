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
    _build_global_payload_dict,
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

    def test_block_blocks_dash_S_with_explicit_executable(self):
        """``executable=`` doesn't hide ``-S`` (on Windows the event then carries both)."""
        tethered.activate(allow=[], external_subprocess_policy="block")
        with pytest.raises(tethered.SubprocessBlocked):
            subprocess.run(
                [sys.executable, "-S", "-c", "pass"],
                executable=sys.executable,
                capture_output=True,
                timeout=10,
            )  # nosec B603 B607

    def test_block_blocks_dash_S_after_an_option_value(self):
        """``-X -c`` makes ``-c`` the value of ``-X``; the ``-S`` after it is a real option."""
        tethered.activate(allow=[], external_subprocess_policy="block")
        with pytest.raises(tethered.SubprocessBlocked):
            subprocess.run(
                [sys.executable, "-X", "-c", "-S", "-c", "pass"],
                capture_output=True,
                timeout=10,
            )  # nosec B603 B607

    @pytest.mark.skipif(sys.platform != "win32", reason="command-line strings are a Windows form")
    @pytest.mark.parametrize("flag", ['"-S"', '-"S"', "-S"])
    def test_block_blocks_dash_S_in_a_command_line_string(self, flag):
        """A quoted ``"-S"`` in a command-line string is still ``-S`` to the child."""
        tethered.activate(allow=[], external_subprocess_policy="block")
        for kwargs in ({}, {"executable": sys.executable}):
            with pytest.raises(tethered.SubprocessBlocked):
                subprocess.run(
                    f'"{sys.executable}" {flag} -c "pass"',
                    capture_output=True,
                    timeout=10,
                    **kwargs,
                )  # nosec B603 B607

    _CHILD_REPORT = (
        "import sys, tethered._core as c; "
        "print('PASS', sys.flags.no_site, c._config is not None, sys.argv[1:])"
    )

    def test_block_allows_script_with_dash_S_argument(self, tmp_path):
        """``-S`` after the script path is the script's argument, not the interpreter's."""
        script = tmp_path / "report.py"
        script.write_text(self._CHILD_REPORT.replace("; ", "\n"))
        tethered.activate(allow=[], external_subprocess_policy="block")
        result = subprocess.run(
            [sys.executable, str(script), "-S"],
            capture_output=True,
            text=True,
            timeout=10,
        )  # nosec B603 B607
        assert result.returncode == 0, result.stderr
        # site.py ran, so the child auto-activated; the script got -S as its own argument.
        assert result.stdout.strip() == "PASS 0 True ['-S']"

    @pytest.mark.parametrize(
        "options",
        [
            ["-c" + _CHILD_REPORT],  # joined -cCODE with an upper-case S in the code
            ["-Wignore::SyntaxWarning", "-c", _CHILD_REPORT],
            ["-W", "-S", "-c", _CHILD_REPORT],  # "-S" is the (invalid, ignored) value of -W
            ["-I", "-E", "-X", "dev", "-c", _CHILD_REPORT],
        ],
    )
    def test_block_allows_python_launches_that_keep_site(self, options):
        """Launches the old scanner took for ``-S`` launches run, and are tethered."""
        tethered.activate(allow=[], external_subprocess_policy="block")
        result = subprocess.run(
            [sys.executable, *options],
            capture_output=True,
            text=True,
            timeout=10,
        )  # nosec B603 B607
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "PASS 0 True []"

    def test_block_and_a_child_started_under_another_name(self):
        """``executable=sys.executable`` with a different ``argv[0]``.

        On POSIX the child decides which installation it is from ``argv[0]``:
        as ``python`` it may not come up as this venv's interpreter at all, so
        the launch is external.  On Windows the executable alone decides, and
        the child is this interpreter, tethered included.
        """
        tethered.activate(allow=[], external_subprocess_policy="block")

        def launch():
            return subprocess.run(
                ["python", "-c", self._CHILD_REPORT],
                executable=sys.executable,
                capture_output=True,
                text=True,
                timeout=10,
            )  # nosec B603 B607

        if sys.platform == "win32":
            result = launch()
            assert result.returncode == 0, result.stderr
            assert result.stdout.strip() == "PASS 0 True []"
        else:
            with pytest.raises(tethered.SubprocessBlocked):
                launch()

    @pytest.mark.parametrize(
        "options",
        [
            ["-S"],
            ["-IS"],
            ["-Sc"],
            ["-X", "-c", "-S"],
            ["-W", "-c", "-S"],
            ["-X", "dev", "-W", "ignore", "-S"],
            ["--check-hash-based-pycs", "never", "-S"],
            ["-I"],
            ["-W", "-S"],
            ["-X", "-S"],
            ["-Wignore::SyntaxWarning"],
            ["--check-hash-based-pycs", "never"],
        ],
    )
    def test_site_bypass_verdict_matches_the_real_interpreter(self, options):
        """Whatever the flag check concludes, this interpreter does the same with the options."""
        argv = [sys.executable, *options]
        if not options[-1].endswith("c"):
            argv.append("-c")
        argv.append("import sys; print(sys.flags.no_site)")
        tethered.activate(allow=[], external_subprocess_policy="allow")
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)  # nosec B603 B607
        assert result.returncode == 0, result.stderr
        assert _has_site_bypass_flag(argv) is (result.stdout.strip() == "1")

    def test_block_refuses_python_child_when_no_bootstrap_is_processed(self, monkeypatch, caplog):
        """No ``tethered.pth`` that ``site`` runs: the child would start with no policy."""
        monkeypatch.setattr(_core, "_compute_pth_path", lambda: "")
        with caplog.at_level(logging.WARNING, logger="tethered"):
            tethered.activate(allow=[], external_subprocess_policy="block")
            with pytest.raises(tethered.SubprocessBlocked, match=r"subprocess\.Popen"):
                subprocess.run(
                    [sys.executable, "-c", "pass"],
                    capture_output=True,
                    timeout=10,
                )  # nosec B603 B607
        assert any("blocked external subprocess launch" in r.message for r in caplog.records)

    def test_warn_reports_python_child_when_no_bootstrap_is_processed(self, monkeypatch, caplog):
        """Under the default policy the unprotected child still runs, but not silently."""
        monkeypatch.setattr(_core, "_compute_pth_path", lambda: "")
        tethered.activate(allow=[])
        with caplog.at_level(logging.WARNING, logger="tethered"):
            result = subprocess.run(
                [sys.executable, "-c", "print('ok')"],
                capture_output=True,
                timeout=10,
            )  # nosec B603 B607
        assert result.returncode == 0
        assert any("external subprocess launch detected" in r.message for r in caplog.records)

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

    @pytest.mark.parametrize(
        ("cmdline", "program"),
        [
            ("curl -s https://evil.test/x", "curl"),
            ("curl", "curl"),
            ("  curl\t-s", "curl"),
            ('"C:\\Program Files\\Git\\bin\\git.exe" clone https://u:secret@host/r', None),
            ('"C:\\Program Files\\Git\\bin\\git.exe"', None),
            ('"C:\\Program Files\\Git\\bin\\git.exe', None),  # unterminated quote
            ('"two\nlines.exe" arg', "two lines.exe"),  # never a multi-line log record
            ("", "<unknown>"),
            ("   ", "<unknown>"),
            ('"" arg', "<unknown>"),
        ],
    )
    def test_describe_subprocess_launch_popen_windows_command_line(self, cmdline, program):
        """Windows: the executable is None and the command line names the program."""
        if program is None:
            program = "C:\\Program Files\\Git\\bin\\git.exe"
        desc = _describe_subprocess_launch("subprocess.Popen", (None, cmdline, None, None))
        assert desc == f"subprocess.Popen({program})"

    def test_describe_subprocess_launch_popen_leaves_arguments_out(self):
        """Arguments can hold credentials; like the POSIX layout, only the program is named."""
        cmdline = "mysql --user=root --password=hunter2 -e \"select 'x'\""
        desc = _describe_subprocess_launch("subprocess.Popen", (None, cmdline, None, None))
        assert desc == "subprocess.Popen(mysql)"

    def test_describe_subprocess_launch_popen_windows_explicit_executable(self):
        """With ``executable=`` the launched image is known; it is what gets reported."""
        args = ("C:\\Windows\\System32\\cmd.exe", 'cmd.exe /c "echo hi"', None, None)
        desc = _describe_subprocess_launch("subprocess.Popen", args)
        assert desc == "subprocess.Popen(C:\\Windows\\System32\\cmd.exe)"

    def test_describe_subprocess_launch_popen_long_program_is_cut(self):
        desc = _describe_subprocess_launch("subprocess.Popen", (None, "x" * 5000 + " arg"))
        assert desc == "subprocess.Popen(" + "x" * 260 + "...)"

    @pytest.mark.parametrize("args", [(), (None,), (None, None), (None, ["curl", "-s"])])
    def test_describe_subprocess_launch_popen_without_a_program(self, args):
        """Nothing usable in the event: say so instead of printing ``None``."""
        assert _describe_subprocess_launch("subprocess.Popen", args) == (
            "subprocess.Popen(<unknown>)"
        )

    def test_blocked_launch_names_the_program_on_every_platform(self, caplog):
        """The same launch reads the same in the log and in the exception, POSIX or Windows."""
        tethered.activate(allow=[], external_subprocess_policy="block")
        with (
            caplog.at_level(logging.WARNING, logger="tethered"),
            pytest.raises(tethered.SubprocessBlocked) as excinfo,
        ):
            subprocess.run(["tethered-test-no-such-tool", "--token", "hunter2"])  # nosec B603 B607
        assert excinfo.value.description == "subprocess.Popen(tethered-test-no-such-tool)"
        messages = [r.message for r in caplog.records]
        assert (
            "tethered: blocked external subprocess launch: "
            "subprocess.Popen(tethered-test-no-such-tool)"
        ) in messages

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

    def test_user_site_hook_makes_dash_s_and_dash_I_bypass_flags(self, tmp_path, monkeypatch):
        """``-s`` / ``-I`` skip the user site-packages — a bypass only if the hook is there."""
        import site

        monkeypatch.setattr(site, "USER_SITE", str(tmp_path))
        user_hook = _core._normalize_path(str(tmp_path / "tethered.pth"))
        assert _has_site_bypass_flag(["python", "-I", "-c", "pass"], user_hook) is True
        assert _has_site_bypass_flag(["python", "-s", "-c", "pass"], user_hook) is True
        assert _has_site_bypass_flag(["python", "-E", "-c", "pass"], user_hook) is False
        assert _has_site_bypass_flag(["python", "-c", "pass", "-s"], user_hook) is False
        other_hook = _core._normalize_path(str(tmp_path / "elsewhere" / "tethered.pth"))
        assert _has_site_bypass_flag(["python", "-I", "-c", "pass"], other_hook) is False

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

    def test_unknown_long_option_is_not_trusted(self):
        """An option the interpreter doesn't know makes the command line unparseable."""
        assert _has_site_bypass_flag(["python", "--something-with-S", "-c", "pass"]) is True
        assert _has_site_bypass_flag(["python", "--isolated", "-c", "pass"]) is True

    @pytest.mark.parametrize(
        "option", ["--help", "--help-all", "--help-env", "--help-xoptions", "--version"]
    )
    def test_known_long_flags_are_not_bypass_flags(self, option):
        assert _has_site_bypass_flag(["python", option]) is False
        assert _has_site_bypass_flag(["python", option, "-S"]) is True

    def test_non_list_is_not_trusted(self):
        """An argv that can't be read as a sequence of arguments is never a known-safe launch."""
        assert _has_site_bypass_flag("python -c pass") is True
        assert _has_site_bypass_flag(b"python -c pass") is True
        assert _has_site_bypass_flag(None) is True
        assert _has_site_bypass_flag(123) is True

    def test_non_string_arg_is_not_trusted(self):
        """A non-string element can't be an argument; the launch is not treated as known-safe."""
        assert _has_site_bypass_flag(["python", 123, "-S", "-c", "pass"]) is True
        assert _has_site_bypass_flag(["python", 123, "-c", "pass"]) is True

    def test_argv0_is_never_an_option(self):
        """argv[0] is the program name even when it looks like a flag."""
        assert _has_site_bypass_flag(["-S", "-c", "pass"]) is False
        assert _has_site_bypass_flag(["python"]) is False
        assert _has_site_bypass_flag([]) is False

    def test_accepts_a_lazy_token_stream(self):
        """The Windows parser hands over an iterator, not a list."""
        assert _has_site_bypass_flag(iter(["python", "-S", "-c", "pass"])) is True
        assert _has_site_bypass_flag(iter(["python", "-I", "-c", "pass"])) is False

    @pytest.mark.parametrize(
        "options",
        [
            # -S as the interpreter's own option, alone or in a cluster
            ["-S"],
            ["-S", "script.py"],
            ["-IS", "-c", "pass"],
            ["-SE", "-c", "pass"],
            ["-Sc", "pass"],
            ["-ISc", "pass"],
            ["-Sm", "json.tool"],
            ["-I", "-E", "-S", "-m", "json.tool"],
            # the token after -X / -W is that option's value, so parsing goes on past it
            ["-X", "-c", "-S", "-c", "pass"],
            ["-X", "dev", "-S", "-c", "pass"],
            ["-Xdev", "-S", "-c", "pass"],
            ["-W", "-c", "-S", "-c", "pass"],
            ["-W", "-S", "-S", "-c", "pass"],
            ["-Wignore", "-S", "-c", "pass"],
            ["-IX", "dev", "-S", "-c", "pass"],
            ["-IXdev", "-S", "-c", "pass"],
            ["--check-hash-based-pycs", "never", "-S", "-c", "pass"],
            # options the interpreter rejects: not provably a normal launch
            ["-Z", "-c", "pass"],
            ["-J", "-c", "pass"],
            ["-I-S", "-c", "pass"],
            ["-S-", "-c", "pass"],
            ["--check-hash-based-pycs=never", "-c", "pass"],
        ],
    )
    def test_site_bypass_detected(self, options):
        assert _has_site_bypass_flag(["python", *options]) is True

    @pytest.mark.parametrize(
        "options",
        [
            # everything after the script path belongs to the script
            ["script.py", "-S"],
            ["-I", "script.py", "-S"],
            ["-u", "-B", "script.py", "-IS"],
            # -c / -m end the options, joined to their value or not
            ["-c", "pass", "-S"],
            ["-cprint('PASS')"],
            ["-cimport sys; print('S')", "-S"],
            ["-Ic", "pass", "-S"],
            ["-m", "json.tool", "-S"],
            ["-mSmodule", "-S"],
            # "--" and "-" end the options too
            ["--", "-S"],
            ["-", "-S"],
            # a value is never an option, whatever it looks like
            ["-W", "-S", "-c", "pass"],
            ["-X", "-S", "-c", "pass"],
            ["-EW", "-S", "-c", "pass"],
            ["--check-hash-based-pycs", "-S", "-c", "pass"],
            # joined values that merely contain an upper-case S
            ["-Wignore::SyntaxWarning", "-c", "pass"],
            ["-XS", "-c", "pass"],
            ["-WS", "-c", "pass"],
            # every flag that exists but leaves site.py alone
            ["-bBdEhiIOPqRstuvVx?", "-c", "pass"],
            ["-OO", "-q", "-c", "pass"],
            # a value option with nothing after it: the interpreter exits with a usage error
            ["-X"],
            ["--check-hash-based-pycs"],
        ],
    )
    def test_site_bypass_not_detected(self, options):
        assert _has_site_bypass_flag(["python", *options]) is False

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

    def test_pathlike_with_failing_fspath_is_not_trusted(self):
        """A ``__fspath__`` raising ``TypeError`` doesn't escape; the argv is just unparseable."""

        class _BadPL:
            def __fspath__(self) -> str:
                raise TypeError("simulated bad PathLike")

        assert _has_site_bypass_flag(["python", _BadPL(), "-S", "-c", "pass"]) is True
        assert _has_site_bypass_flag(["python", _BadPL(), "-c", "pass"]) is True

    def test_pathlike_script_ends_the_options(self):
        """A ``Path`` script (the usual way to pass one) is decoded like any other argument."""
        assert _has_site_bypass_flag(["python", Path("script.py"), "-S"]) is False
        assert _has_site_bypass_flag(["python", b"script.py", b"-S"]) is False

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
        args = (123, [sys.executable, "-c", "pass"], None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False

    def test_pathlike_executable_with_failing_fspath_returns_false(self):
        class BadPath:
            def __fspath__(self):
                raise TypeError("not a real path")

        args = (BadPath(), [sys.executable, "-c", "pass"], None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False
        # The same object as argv[0] is no better.
        args = (sys.executable, [BadPath(), "-c", "pass"], None, None)
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

    # ── POSIX layout: (executable, argv_list, cwd, env) ──

    @pytest.mark.parametrize(
        ("options", "expected"),
        [
            (["-X", "-c", "-S", "-c", "pass"], False),  # "-c" is the value of -X
            (["-IS", "-c", "pass"], False),
            (["-Sc", "pass"], False),
            (["script.py", "-S"], True),  # -S belongs to the script
            (["-cprint('PASS')"], True),  # joined -c; the S is code
            (["-Wignore::SyntaxWarning", "-c", "print('PASS')"], True),
            (["-m", "json.tool", "-S"], True),
            (["--bogus"], False),  # unparseable
        ],
    )
    def test_posix_layout_reads_real_option_boundaries(self, options, expected):
        args = (sys.executable, [sys.executable, *options], None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is expected
        assert _is_auto_inheriting_python_launch("os.posix_spawn", (*args[:2], {})) is expected

    @pytest.mark.parametrize(
        "argv0",
        ["python", "python3", "worker", "-S", "/usr/bin/python3", b"python", 123, None],
    )
    def test_posix_layout_argv0_must_name_sys_executable(self, argv0):
        """A POSIX child takes its identity from argv[0], not from the file that was exec'd.

        Started as ``python`` it looks that name up on ``PATH``; from a venv
        that is not on ``PATH`` it comes up as the base installation, where
        no ``tethered.pth`` is processed.
        """
        for event, tail in (("subprocess.Popen", (None, None)), ("os.posix_spawn", ({},))):
            args = (sys.executable, [argv0, "-c", "pass"], *tail)
            assert _is_auto_inheriting_python_launch(event, args) is False

    def test_posix_layout_argv0_may_be_bytes_or_pathlike(self):
        for argv0 in (os.fsencode(sys.executable), Path(sys.executable)):
            args = (sys.executable, [argv0, "-c", "pass"], None, None)
            assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is True
            args = (sys.executable, [argv0, "-S", "-c", "pass"], None, None)
            assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False

    def test_posix_layout_empty_or_unusable_argv_returns_false(self):
        for argv in ([], (), None, 123, {"python": 1}):
            args = (sys.executable, argv, None, None)
            assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False

    # ── Windows layout: (executable_or_None, command_line, cwd, env) ──

    @pytest.mark.parametrize(
        ("tail", "expected"),
        [
            ('-S -c "print(0)"', False),
            ('"-S" -c "print(0)"', False),  # quoting every argument is a normal thing to do
            ('-"S" -c "print(0)"', False),
            ('-""S -c "print(0)"', False),
            ("-IS -c pass", False),
            ("-Sc pass", False),
            ("-X -c -S -c pass", False),
            ('-X dev "-S" -c pass', False),
            ("\t-S\t-c\tpass", False),
            ("--check-hash-based-pycs never -S -c pass", False),
            ("--bogus -c pass", False),
            ('-c "print(0)"', True),
            ("script.py -S", True),
            ('"my script.py" "-S"', True),
            ("-cprint('PASS')", True),
            ("\"-cprint('PASS S')\" -S", True),
            ("-Wignore::SyntaxWarning -c \"print('PASS')\"", True),
            ("-W -S -c pass", True),
            ('-c "import sys\nprint(\\"-S\\", \'S\')" -S', True),  # quotes and newlines in the body
            ("-m json.tool -S", True),
            ("-I -E -c pass", True),
            ('\\"-S -c pass', True),  # an escaped quote starts a script name, not an option
            ("", True),
        ],
    )
    def test_windows_layout_reads_real_option_boundaries(self, tail, expected):
        quoted = f'"{sys.executable}" {tail}'
        # Without executable=: the image is the command line's first token.
        assert (
            _is_auto_inheriting_python_launch("subprocess.Popen", (None, quoted, None, None))
            is expected
        )
        # With executable=: same options, whatever the first token says.
        for cmdline in (quoted, f"python {tail}", f'"some other name" {tail}'):
            args = (sys.executable, cmdline, None, None)
            assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is expected

    def test_windows_layout_explicit_executable_names_the_image(self):
        """With ``executable=``, the command line's first token is not the launched program."""
        cmdline = f'"{sys.executable}" -c "print(0)"'
        args = ("C:\\Windows\\System32\\cmd.exe", cmdline, None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False

    def test_windows_layout_path_with_spaces(self, monkeypatch):
        exe = "C:\\Program Files\\Python313\\python.exe"
        monkeypatch.setattr(sys, "executable", exe)

        def check(executable, cmdline):
            args = (executable, cmdline, None, None)
            return _is_auto_inheriting_python_launch("subprocess.Popen", args)

        assert check(None, f'"{exe}" -c pass') is True
        assert check(None, f'"{exe}" -S -c pass') is False
        assert check(None, f'"{exe}" "-S" -c pass') is False
        # Unquoted, the first token is "C:\Program": some other program.
        assert check(None, f"{exe} -c pass") is False
        # With executable= the child still splits the line at the space, so
        # "Files\Python313\python.exe" is its script and -S is a script argument.
        assert check(exe, f"{exe} -S -c pass") is True

    @pytest.mark.parametrize(
        "template",
        [
            '"{exe}"-S -c pass',  # nothing between the closing quote and the next token
            '"{exe}"x -S -c pass',
            '"{exe}" \n-S -c pass',  # a newline is whitespace to some launchers only
            '"{exe}" \x0b-S -c pass',
            '"{exe}"\t-S -c pass',
            "{exe}\tx -S -c pass",  # tab-terminated bare name
            "{exe}\nx -S -c pass",
            '{exe}" x -S -c pass',  # quote inside a bare name
            '"{exe}\\" x -S -c pass',  # backslash before the closing quote
            ' "{exe}" -c pass',  # leading whitespace
            '"{exe} -c pass',  # unterminated quote
        ],
    )
    def test_windows_layout_ambiguous_program_name_is_not_trusted(self, template, monkeypatch):
        """Forms that CreateProcess, the C runtime and venv launchers split differently."""
        # A fixed path: the bare forms mean something else again when it contains a space.
        monkeypatch.setattr(sys, "executable", "C:\\Python313\\python.exe")
        cmdline = template.format(exe=sys.executable)
        for executable in (None, sys.executable):
            args = (executable, cmdline, None, None)
            assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False

    # ── os.spawn* / os.exec*: Windows joins the argv, unquoted ──

    def test_os_spawn_argv_is_resplit_by_the_child(self):
        """An element holding ``-X dev -S`` reaches a Windows child as three arguments."""
        exe = sys.executable

        def check(argv):
            return _is_auto_inheriting_python_launch("os.spawn", (0, exe, argv, None))

        assert check(["python", "-c", "pass"]) is True
        assert check(["python", "-X dev -S", "-c", "pass"]) is False
        assert check(["python", "-Wignore -S", "-c", "pass"]) is False
        assert check(["python", '"-S"', "-c", "pass"]) is False
        assert check(("python", b"-S", "-c", "pass")) is False
        assert check(["python", "my script.py", "-S"]) is True
        assert check(["python", Path("script.py"), "-S"]) is True

    def test_os_spawn_unusable_argv_returns_false(self):
        class BadPath:
            def __fspath__(self):
                raise TypeError("not a real path")

        for argv in (["python", 123], ["python", BadPath()], "python -c pass", None):
            args = (0, sys.executable, argv, None)
            assert _is_auto_inheriting_python_launch("os.spawn", args) is False

    def test_os_exec_argv_is_joined_on_windows_only(self, monkeypatch):
        # A fixed, space-free path so that joining argv doesn't split argv[0] as well.
        monkeypatch.setattr(sys, "executable", "/opt/python/bin/python3")
        args = (sys.executable, [sys.executable, "-Wignore -S", "-c", "pass"], {})
        monkeypatch.setattr(_core, "_WINDOWS", True)
        assert _is_auto_inheriting_python_launch("os.exec", args) is False
        # POSIX execve passes the element through whole: it is -W's (invalid) value.
        monkeypatch.setattr(_core, "_WINDOWS", False)
        assert _is_auto_inheriting_python_launch("os.exec", args) is True
        for windows in (True, False):
            monkeypatch.setattr(_core, "_WINDOWS", windows)
            plain = (sys.executable, ["python", "-S", "-c", "pass"], {})
            assert _is_auto_inheriting_python_launch("os.exec", plain) is False

    # ── The bootstrap has to be one this interpreter processes ──

    _PLAIN_LAUNCH = (sys.executable, [sys.executable, "-c", "pass"], None, None)

    def test_no_processed_bootstrap_is_not_auto_inheriting(self, monkeypatch):
        """Without a hook that ``site`` runs, a Python child is as external as any other."""
        monkeypatch.setattr(_core, "_pth_path_cache", None)
        monkeypatch.setattr(_core, "_compute_pth_path", lambda: "")
        assert _is_auto_inheriting_python_launch("subprocess.Popen", self._PLAIN_LAUNCH) is False
        cmdline = f'"{sys.executable}" -c "print(0)"'
        args = (None, cmdline, None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is False

    def test_bootstrap_lookup_is_cached_when_no_config_is_active(self, monkeypatch):
        """Scope-only use has no config to hold the path, so one lookup serves every launch."""
        calls = []
        real = _core._compute_pth_path

        def counting():
            calls.append(1)
            return real()

        monkeypatch.setattr(_core, "_pth_path_cache", None)
        monkeypatch.setattr(_core, "_compute_pth_path", counting)
        for _ in range(3):
            assert _is_auto_inheriting_python_launch("subprocess.Popen", self._PLAIN_LAUNCH) is True
        assert len(calls) == 1
        assert _core._pth_path_cache == real()
        # A launch of some other program never needs the lookup at all.
        monkeypatch.setattr(_core, "_pth_path_cache", None)
        other = ("/bin/sh", ["sh", "-c", "true"], None, None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", other) is False
        assert _core._pth_path_cache is None

    def test_active_config_decides_over_the_cache(self, monkeypatch):
        """With a policy active, the path activate() found is the one that counts."""
        monkeypatch.setattr(_core, "_pth_path_cache", "/stale/site-packages/tethered.pth")
        monkeypatch.setattr(_core, "_compute_pth_path", lambda: "")
        tethered.activate(allow=[])
        assert _core._config._pth_path == ""
        assert _is_auto_inheriting_python_launch("subprocess.Popen", self._PLAIN_LAUNCH) is False

        monkeypatch.setattr(_core, "_pth_path_cache", "")
        monkeypatch.setattr(_core, "_compute_pth_path", lambda: "/site-packages/tethered.pth")
        tethered.activate(allow=[])
        assert _is_auto_inheriting_python_launch("subprocess.Popen", self._PLAIN_LAUNCH) is True

    @pytest.mark.parametrize(
        ("options", "in_user_site", "elsewhere"),
        [
            (["-c", "pass"], True, True),
            (["-E", "-c", "pass"], True, True),
            (["-I", "-c", "pass"], False, True),  # isolated mode implies -s
            (["-s", "-c", "pass"], False, True),
            (["-Es", "script.py"], False, True),
            (["script.py", "-s", "-I"], True, True),  # the script's own arguments
            (["-S", "-c", "pass"], False, False),
        ],
    )
    def test_user_site_bootstrap_is_skipped_by_dash_s_and_dash_I(
        self, tmp_path, monkeypatch, options, in_user_site, elsewhere
    ):
        """``pip install --user``: the hook is in the one directory ``-s`` / ``-I`` leave out."""
        import site

        monkeypatch.setattr(site, "USER_SITE", str(tmp_path / "user-site"))
        user_hook = _core._normalize_path(str(tmp_path / "user-site" / "tethered.pth"))
        other_hook = _core._normalize_path(str(tmp_path / "site-packages" / "tethered.pth"))
        args = (sys.executable, [sys.executable, *options], None, None)

        monkeypatch.setattr(_core, "_pth_path_cache", user_hook)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is in_user_site
        monkeypatch.setattr(_core, "_pth_path_cache", other_hook)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is elsewhere
        # No user site known at all (site never computed it): nothing can be in it.
        monkeypatch.setattr(site, "USER_SITE", None)
        assert _is_auto_inheriting_python_launch("subprocess.Popen", args) is elsewhere


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


class TestPayloadDeterminism:
    """The canonical payload must be reproducible across interpreters.

    Regression tests for the false "substitution attempt" block: exact-host
    rules live in frozensets, so an unsorted serialization followed
    per-process hash randomization (PYTHONHASHSEED).  A process manager
    (honcho-style) that captures ``os.environ`` into a plain dict and hands
    it to a spawn-mode Python child then failed the locked-mode
    payload-integrity check on the child's next launch — the child's
    rebuilt canonical payload ordered the same entries differently.
    """

    _MIXED_RULES: ClassVar[list[str]] = [
        "api.example.com:443",
        "auth.example.com:443",
        "billing.example.com:443",
        "search.example.com:443",
        "cache-host:1111",
        "pool-host:2222",
        "convert-host:3333",
        "internal-host",
        "*.example.org:443",
        "*.wildcard.test",
        "10.0.0.0/8:5432",
        "192.168.0.1:80",
    ]

    def _payload(self, rules: list[str]) -> dict[str, object]:
        return _build_global_payload_dict(
            AllowPolicy(rules),
            log_only=False,
            fail_closed=False,
            external_subprocess_policy="warn",
            locked=True,
        )

    def test_allow_list_input_order_insensitive(self):
        """Policies built from differently ordered rule lists serialize identically."""
        assert self._payload(self._MIXED_RULES) == self._payload(list(reversed(self._MIXED_RULES)))

    def test_allow_list_is_sorted(self):
        """The serialized allow list is in sorted order (the canonical form)."""
        allow = self._payload(self._MIXED_RULES)["allow"]
        assert allow == sorted(allow)

    def test_allow_list_round_trip_stable(self):
        """Re-parsing a serialized allow list re-serializes to the identical payload."""
        first = self._payload(self._MIXED_RULES)
        second = self._payload(list(first["allow"]))
        assert first == second

    def test_payload_identical_across_hash_seeds(self):
        """Two interpreters with different hash seeds serialize identical payload bytes."""
        code = (
            "import json, sys\n"
            "from tethered._core import _build_global_payload_dict\n"
            "from tethered._policy import AllowPolicy\n"
            f"rules = {self._MIXED_RULES!r}\n"
            "payload = _build_global_payload_dict(\n"
            "    AllowPolicy(rules), log_only=False, fail_closed=False,\n"
            "    external_subprocess_policy='warn', locked=True,\n"
            ")\n"
            "sys.stdout.write(json.dumps(payload))\n"
        )
        outputs = []
        for seed in ("1", "2"):
            env = {**os.environ, "PYTHONHASHSEED": seed}
            env.pop(_CHILD_POLICY_ENV, None)
            r = subprocess.run(  # nosec B603 B607
                [sys.executable, "-c", code],
                capture_output=True,
                text=True,
                env=env,
                timeout=15,
            )
            assert r.returncode == 0, r.stderr
            outputs.append(r.stdout)
        assert outputs[0] == outputs[1]

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_locked_spawn_child_relaunches_with_parent_env_snapshot(self):
        """A spawn child holding the parent's env snapshot can launch grandchildren.

        The honcho / process-manager pattern: the parent activates locked
        mode, captures ``os.environ`` into a plain dict, and hands it to a
        spawn-mode Python child, which launches a grandchild with
        ``env=<that dict>``.  The grandchild's env carries the PARENT's
        serialization while the child's canonical payload is rebuilt by its
        own interpreter — before deterministic ordering this raised a false
        "substitution attempt" ``SubprocessBlocked``.  Run at two forced
        hash seeds so at most one child can accidentally share the parent's
        pre-fix ordering.
        """
        tethered.activate(
            allow=self._MIXED_RULES,
            locked=True,
            lock_token=object(),
            external_subprocess_policy="allow",
        )
        parent_payload = os.environ[_CHILD_POLICY_ENV]
        child_code = (
            "import os, subprocess, sys\n"
            "snapshot = dict(os.environ)\n"
            "snapshot['_TETHERED_CHILD_POLICY'] = "
            "os.environ['TETHERED_TEST_PARENT_PAYLOAD']\n"
            "subprocess.run([sys.executable, '-c', 'pass'], env=snapshot, check=True)\n"
            "print('OK')\n"
        )
        for seed in ("1", "2"):
            env = {
                **os.environ,
                "TETHERED_TEST_PARENT_PAYLOAD": parent_payload,
                "PYTHONHASHSEED": seed,
            }
            r = subprocess.run(  # nosec B603 B607
                [sys.executable, "-c", child_code],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            assert r.returncode == 0, f"seed {seed}: {r.stderr}"
            assert "OK" in r.stdout


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
    """Direct tests for _compute_pth_path.

    The hook only counts where ``site`` executes ``.pth`` files: the
    site-packages of the interpreter's prefixes and the enabled user site.
    """

    @staticmethod
    def _site_packages(prefix: Path, *, hook: bool) -> Path:
        """Create the site-packages directory ``site`` derives from ``prefix``."""
        import site

        directory = Path(site.getsitepackages([str(prefix)])[-1])
        directory.mkdir(parents=True)
        if hook:
            (directory / "tethered.pth").write_text("# hook\n")
        return directory

    @staticmethod
    def _lookup(monkeypatch, sys_prefix, *, site_prefixes=None, user_site=None, package_in=None):
        """Run _compute_pth_path() as an interpreter with the given site layout would."""
        import site

        prefixes = [sys_prefix] if site_prefixes is None else site_prefixes
        with monkeypatch.context() as m:
            m.setattr(sys, "prefix", str(sys_prefix))
            m.setattr(sys, "exec_prefix", str(sys_prefix))
            m.setattr(site, "PREFIXES", [str(p) for p in prefixes])
            m.setattr(site, "ENABLE_USER_SITE", user_site is not None)
            m.setattr(site, "USER_SITE", None if user_site is None else str(user_site))
            if package_in is not None:
                m.setattr(tethered, "__file__", str(package_in / "tethered" / "__init__.py"))
            return _compute_pth_path()

    def test_finds_the_hook_in_site_packages(self):
        """In this environment the hook that runs is the one in the venv's site-packages.

        The suite runs from an editable install, where the package (and a
        ``tethered.pth`` beside it) lives in ``src/``; ``src/`` is on
        ``sys.path`` but is not a site directory.
        """
        import sysconfig

        expected = _core._normalize_path(
            os.path.join(sysconfig.get_path("purelib"), "tethered.pth")
        )
        assert _compute_pth_path() == expected
        assert os.path.isfile(expected)

    def test_returns_normalized_absolute_path(self):
        """Normal case: returns an absolute, normalized path ending in tethered.pth."""
        result = _compute_pth_path()
        assert result.endswith("tethered.pth") or result.endswith("tethered.pth".lower())
        assert os.path.isabs(result)
        # The form the locked-mode FS guard compares against.
        assert _path_matches_pth(result, result)

    def test_tethered_file_missing_still_searches_site_dirs(self, monkeypatch):
        """Without ``tethered.__file__`` there is no adjacent hook to prefer, only the search."""
        expected = _compute_pth_path()
        monkeypatch.setattr(tethered, "__file__", None)
        assert _compute_pth_path() == expected

    def test_hook_beside_package_outside_site_dirs_is_not_accepted(self, tmp_path, monkeypatch):
        """``pip install --target`` + ``PYTHONPATH``: on sys.path, yet its .pth files never run."""
        target = tmp_path / "target"
        (target / "tethered").mkdir(parents=True)
        (target / "tethered.pth").write_text("# hook\n")
        monkeypatch.syspath_prepend(str(target))
        prefix = tmp_path / "prefix"
        site_packages = self._site_packages(prefix, hook=False)

        assert self._lookup(monkeypatch, prefix, package_in=target) == ""

        # Once a site directory has the hook, that one is reported — never the target's.
        (site_packages / "tethered.pth").write_text("# hook\n")
        found = self._lookup(monkeypatch, prefix, package_in=target)
        assert found == _core._normalize_path(str(site_packages / "tethered.pth"))

    def test_hook_beside_package_in_a_site_dir_is_preferred(self, tmp_path, monkeypatch):
        first = self._site_packages(tmp_path / "first", hook=True)
        second = self._site_packages(tmp_path / "second", hook=True)
        prefixes = [tmp_path / "first", tmp_path / "second"]

        def lookup(package_in):
            return self._lookup(
                monkeypatch, prefixes[0], site_prefixes=prefixes, package_in=package_in
            )

        # Imported from the second site directory: its own hook is the one that matters.
        assert lookup(second) == _core._normalize_path(str(second / "tethered.pth"))
        # Imported from somewhere that is not a site directory: first hook in site's order.
        assert lookup(tmp_path / "elsewhere") == _core._normalize_path(str(first / "tethered.pth"))

    def test_user_site_hook_counts_only_when_user_site_is_enabled(self, tmp_path, monkeypatch):
        prefix = tmp_path / "prefix"
        self._site_packages(prefix, hook=False)
        user_site = tmp_path / "user-site"
        user_site.mkdir()
        (user_site / "tethered.pth").write_text("# hook\n")

        found = self._lookup(monkeypatch, prefix, user_site=user_site, package_in=user_site)
        assert found == _core._normalize_path(str(user_site / "tethered.pth"))
        # -s / PYTHONNOUSERSITE / a venv: the directory exists but site skips it.
        assert self._lookup(monkeypatch, prefix, package_in=user_site) == ""

    def test_sys_prefix_is_searched_even_when_site_prefixes_lags(self, tmp_path, monkeypatch):
        """While a venv interpreter starts up, ``site.PREFIXES`` still names the base install."""
        venv = self._site_packages(tmp_path / "venv", hook=True)
        self._site_packages(tmp_path / "base", hook=False)
        found = self._lookup(monkeypatch, tmp_path / "venv", site_prefixes=[tmp_path / "base"])
        assert found == _core._normalize_path(str(venv / "tethered.pth"))

    def test_returns_empty_when_site_is_disabled(self, monkeypatch):
        """Under ``-S`` this interpreter processed no .pth file at all."""
        import types

        names = [n for n in dir(sys.flags) if not n.startswith("_") and n not in ("count", "index")]
        flags = types.SimpleNamespace(**{n: getattr(sys.flags, n) for n in names})
        flags.no_site = 1
        with monkeypatch.context() as m:
            m.setattr(sys, "flags", flags)
            result = _compute_pth_path()
        assert result == ""

    def test_child_resolves_the_hook_during_its_own_startup(self):
        """An auto-activated child calls activate() from inside site.py and must still find it."""
        tethered.activate(allow=[])
        result = subprocess.run(
            [sys.executable, "-c", "import tethered._core as c; print(c._config._pth_path)"],
            capture_output=True,
            text=True,
            timeout=10,
        )  # nosec B603 B607
        assert result.returncode == 0, result.stderr
        assert _core._config._pth_path
        assert result.stdout.strip() == _core._config._pth_path
        # No missing-hook warning from the child's activate().
        assert "tethered.pth" not in result.stderr

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_locked_mode_guards_the_hook_that_site_runs(self):
        """The locked-mode FS guard watches the processed hook, spelled by the caller's own path."""
        import sysconfig

        hook = os.path.join(sysconfig.get_path("purelib"), "tethered.pth")
        tethered.activate(allow=[], locked=True, lock_token=object())
        with pytest.raises(tethered.SubprocessBlocked, match=r"refused write-open"):
            open(hook, "a").close()
        with pytest.raises(tethered.SubprocessBlocked, match=r"refused deletion"):
            os.remove(hook)
        assert os.path.isfile(hook)

    def test_target_install_on_pythonpath_has_no_bootstrap(self, tmp_path):
        """End to end, in an interpreter that has tethered only via ``--target`` + ``PYTHONPATH``.

        The hook sits next to the package, yet ``site`` never runs it: the
        lookup is empty, ``activate()`` says so, and a ``sys.executable``
        child is an external launch instead of a silently unprotected one.
        """
        import shutil

        venv = tmp_path / "venv"
        subprocess.run(
            [sys.executable, "-m", "venv", "--without-pip", str(venv)],
            check=True,
            capture_output=True,
            timeout=120,
        )  # nosec B603 B607
        python = venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        package = Path(tethered.__file__).parent
        target = tmp_path / "target"
        shutil.copytree(package, target / "tethered", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy(package.parent / "tethered.pth", target / "tethered.pth")
        script = (
            "import logging, subprocess, sys\n"
            "logging.basicConfig()\n"
            "import tethered, tethered._core as c\n"
            "tethered.activate(allow=[], external_subprocess_policy='block')\n"
            "print(tethered.__file__)\n"
            "print('pth', repr(c._config._pth_path))\n"
            "try:\n"
            "    subprocess.run([sys.executable, '-c', 'pass'])\n"
            "    print('child ran')\n"
            "except tethered.SubprocessBlocked:\n"
            "    print('child blocked')\n"
        )
        env = {**os.environ, "PYTHONPATH": str(target)}
        env.pop(_CHILD_POLICY_ENV, None)
        result = subprocess.run(
            [str(python), "-c", script], env=env, capture_output=True, text=True, timeout=60
        )  # nosec B603 B607
        assert result.returncode == 0, result.stderr
        imported_from, *verdict = result.stdout.splitlines()
        assert os.path.samefile(os.path.dirname(imported_from), target / "tethered")
        assert verdict == ["pth ''", "child blocked"]
        # activate() reported the missing hook instead of staying silent.
        assert "tethered.pth" in result.stderr


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

    @staticmethod
    def _split(cmdline: str) -> tuple[str, list[str]]:
        parsed = _parse_windows_cmdline(cmdline)
        assert parsed is not None, cmdline
        program, argv = parsed
        return program, list(argv)

    def test_unquoted_exe_with_args(self):
        assert self._split("python.exe -c pass") == (
            "python.exe",
            ["python.exe", "-c", "pass"],
        )

    def test_unquoted_exe_no_args(self):
        assert self._split("python.exe") == ("python.exe", ["python.exe"])
        assert self._split("python.exe  \t ") == ("python.exe", ["python.exe"])

    def test_quoted_exe(self):
        exe = "C:\\Program Files\\Python\\python.exe"
        assert self._split(f'"{exe}" -c pass') == (exe, [exe, "-c", "pass"])
        assert self._split(f'"{exe}"') == (exe, [exe])
        assert self._split('"" -S') == ("", ["", "-S"])

    def test_quoted_exe_unterminated_quote(self):
        # Quoted exe with no closing quote — return None (can't parse safely).
        assert _parse_windows_cmdline('"unterminated') is None

    def test_empty_string(self):
        assert _parse_windows_cmdline("") is None
        assert _parse_windows_cmdline("   ") is None

    @pytest.mark.parametrize(
        "cmdline",
        [
            '"python.exe"-S',  # closing quote not followed by a space
            '"python.exe"\t-S',
            'python.exe"-S" x',  # quote inside a bare name
            "python.exe\t-S",  # bare name ended by a tab
            "python.exe\n-S",
            '"python.exe\\" -S',  # backslash before the closing quote
            '"python.exe" \n-S',  # separator run continues with other whitespace
            "python.exe \r-S",
            " python.exe -S",  # leading whitespace
        ],
    )
    def test_ambiguous_program_name_returns_none(self, cmdline):
        assert _parse_windows_cmdline(cmdline) is None

    @pytest.mark.parametrize(
        ("args", "expected"),
        [
            # Each expectation is what python.exe's C runtime produces (checked
            # against real children by test_windows_cmdline_split_matches_real_child).
            ("-S -c pass", ["-S", "-c", "pass"]),
            ("  -S \t -c\tpass  ", ["-S", "-c", "pass"]),
            ('"-S" -"S" -""S "-"S', ["-S", "-S", "-S", "-S"]),
            ('"c d" e" "f', ["c d", "e f"]),
            ('""', [""]),
            ('"" "" x', ["", "", "x"]),
            ('a\\"b', ['a"b']),  # 1 backslash + quote: literal quote
            ('e\\\\"f g"', ["e\\f g"]),  # 2 backslashes + quote: one backslash, quote toggles
            ('h\\\\\\"i', ['h\\"i']),  # 3: one backslash and a literal quote
            ('\\\\\\\\"x y\\\\\\\\" z', ["\\\\x y\\\\", "z"]),
            ("a\\\\ b\\", ["a\\\\", "b\\"]),  # backslashes not before a quote are literal
            ("C:\\dir\\file.py", ["C:\\dir\\file.py"]),
            ('"a""b" "c"" d" x', ['a"b', 'c" d', "x"]),  # "" inside quotes: one literal quote
            ('"a"""b', ['a"b']),
            ('"unterminated quote here', ["unterminated quote here"]),
            ("a\nb\rc", ["a\nb\rc"]),  # only space and tab separate arguments
            ('-c "print(\'x\')\nprint(\\"y\\")" -S', ["-c", "print('x')\nprint(\"y\")", "-S"]),
        ],
    )
    def test_arguments_split_by_c_runtime_rules(self, args, expected):
        assert self._split(f"python.exe {args}") == ("python.exe", ["python.exe", *expected])

    def test_arguments_are_split_lazily(self):
        """The flag check stops at ``-c``: a long body full of quotes is never scanned."""
        body = "print('a b')\nprint(1)\n" * 1000
        parsed = _parse_windows_cmdline(f'python.exe -I -c "{body}" -S')
        assert parsed is not None
        _program, argv = parsed
        assert _has_site_bypass_flag(argv) is False
        # The iterator is still parked right after "-c"; the body is the next token.
        assert next(argv) == body
        assert list(argv) == ["-S"]

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows command-line layout")
    @pytest.mark.parametrize(
        "args",
        [
            '"-S" -c "{probe}"',
            '-"S" -c "{probe}"',
            '-c "{probe}" a\\"b "c d" e\\\\"f g" h\\\\\\"i',
            '-c "{probe}" "a""b" "c"" d" x ""',
            '-c "{probe}" a\\\\ b\\ "unterminated quote',
            "-X -c -S -c \"{probe}\" 'x y'",
            '-I\t-c\t"{probe}"\t-S',
        ],
    )
    def test_windows_cmdline_split_matches_real_child(self, args):
        """The interpreter's own view of the command line agrees with the parser."""
        probe = "import sys,json;print(json.dumps(sys.orig_argv[1:]))"
        cmdline = f'"{sys.executable}" ' + args.format(probe=probe)
        result = subprocess.run(  # nosec B603 B607
            cmdline, capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0, result.stderr
        _program, argv = self._split(cmdline)
        assert json.loads(result.stdout) == argv[1:]


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

    def test_scope_hint_round_trip_to_subprocess(self):
        """A hinted scope on the parent surfaces in a child process's EgressBlocked message.

        The hint contains a non-ASCII character (em dash) deliberately — that's what real
        package authors will write.  Pin both the child's stdout encoding and the parent's
        decode to UTF-8 so the assertion doesn't depend on the runner's locale (Windows
        cp1252 vs POSIX UTF-8 vs CI default).  The auto-propagation env injection adds
        ``_TETHERED_CHILD_POLICY`` on top of whatever env we pass.
        """
        tethered.activate(allow=["*.allowed.com"])
        child_env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        with tethered.scope(
            allow=["api.allowed.com"],
            label="lib.task",
            hint="lib.task needs api.allowed.com — see docs/security.md",
        ):
            r = subprocess.run(  # nosec B603 B607
                [
                    sys.executable,
                    "-c",
                    (
                        "import socket, tethered\n"
                        "try:\n"
                        "    socket.getaddrinfo('other.allowed.com', 80)\n"
                        "    print('ALLOWED')\n"
                        "except tethered.EgressBlocked as exc:\n"
                        "    print(f'HINT={exc.scope_hint!r}')\n"
                        "    print(f'STR={str(exc)!r}')"
                    ),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=child_env,
                timeout=15,
            )
        assert r.returncode == 0, r.stderr
        assert "HINT='lib.task needs api.allowed.com — see docs/security.md'" in r.stdout
        assert "Hint: lib.task needs api.allowed.com" in r.stdout

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


# ── Launch-environment tests ──────────────────────────────────────────
# What the child process actually receives: the mapping the caller passed,
# the process environment, and the policy payload tethered puts into them.

# Prints the child's tethered state as JSON.  ``tethered._core`` is only in
# ``sys.modules`` when the tethered.pth bootstrap ran.
_CHILD_STATE_PROBE = (
    "import json, os, sys\n"
    "core = sys.modules.get('tethered._core')\n"
    "cfg = core._config if core else None\n"
    "print(json.dumps({\n"
    "    'active': cfg is not None,\n"
    "    'locked': bool(cfg and cfg.locked),\n"
    "    'allow': core._build_child_policy_payload(cfg)['allow'] if cfg else None,\n"
    "    'scopes': len(core._scopes.get()) if core else 0,\n"
    "    'sentinel': os.environ.get('TETHERED_SENTINEL'),\n"
    "    'parent_only': os.environ.get('TETHERED_PARENT_ONLY'),\n"
    "}))\n"
)

_ENV_MAPPING_KINDS = ("dict", "UserDict", "MappingProxyType")


def _minimal_child_env() -> dict[str, str]:
    """The sanitized environment an application would hand a child (no policy variable)."""
    keep = {"PATH", "SYSTEMROOT", "PATHEXT", "TEMP", "TMP"}
    return {k: v for k, v in os.environ.items() if k.upper() in keep}


def _as_mapping(kind: str, data: dict):
    """Wrap ``data`` in one of the mapping types launch APIs accept."""
    import collections
    import types

    if kind == "UserDict":
        return collections.UserDict(data)
    if kind == "MappingProxyType":
        return types.MappingProxyType(dict(data))
    return dict(data)


def _launch_probe(**popen_kwargs) -> dict:
    """Launch a real child of ``sys.executable`` and return the state it reports."""
    r = subprocess.run(  # nosec B603
        [sys.executable, "-c", _CHILD_STATE_PROBE],
        capture_output=True,
        text=True,
        timeout=30,
        **popen_kwargs,
    )
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _call_in_execute_child(fn, env):
    """Call ``fn()`` from a frame shaped like ``subprocess.Popen._execute_child``.

    Returns that frame's ``env`` local afterwards — the object the real
    ``_execute_child`` would hand to the OS.  Audit hooks run untraced, so
    coverage of the hook's code comes from direct calls like this one.
    """
    namespace = {"__name__": "subprocess", "fn": fn}
    exec(  # nosec B102 — controlled local source for the test fixture
        "def _execute_child(env):\n    fn()\n    return env\n",
        namespace,
    )
    return namespace["_execute_child"](env)


class TestLaunchEnvMappingCopy:
    """The injected environment is a copy of whatever mapping the caller supplied.

    Regression tests for scope propagation replacing a non-``dict`` ``env=``
    with the parent's ``os.environ``: variables the caller withheld reached
    the child and variables the caller added vanished.
    """

    _SCOPE = _ScopeConfig(policy=AllowPolicy(["api.allowed.com"]), label="mapping-copy")

    def _cfg(self) -> _Config:
        return _Config(policy=AllowPolicy(["*.allowed.com"]))

    @pytest.mark.parametrize("kind", _ENV_MAPPING_KINDS)
    def test_copies_the_callers_mapping(self, kind, monkeypatch):
        monkeypatch.setenv("TETHERED_PARENT_ONLY", "1")
        env_arg = _as_mapping(kind, {"TETHERED_SENTINEL": "from-caller"})
        new_env = _build_per_launch_env(
            "subprocess.Popen", ("/x", [], None, env_arg), (self._SCOPE,), self._cfg()
        )
        assert type(new_env) is dict
        assert new_env["TETHERED_SENTINEL"] == "from-caller"
        assert "TETHERED_PARENT_ONLY" not in new_env
        assert json.loads(new_env[_CHILD_POLICY_ENV])["scopes"][0]["label"] == "mapping-copy"
        # The caller's mapping is never mutated.
        assert dict(env_arg) == {"TETHERED_SENTINEL": "from-caller"}

    def test_copies_os_environ_passed_explicitly(self, monkeypatch):
        """``env=os.environ`` is a mapping like any other, and is left untouched."""
        monkeypatch.setenv("TETHERED_SENTINEL", "from-environ")
        monkeypatch.setenv(_CHILD_POLICY_ENV, "untouched")
        new_env = _build_per_launch_env(
            "subprocess.Popen", ("/x", [], None, os.environ), (self._SCOPE,), self._cfg()
        )
        assert new_env["TETHERED_SENTINEL"] == "from-environ"
        assert new_env[_CHILD_POLICY_ENV] != "untouched"
        assert os.environ[_CHILD_POLICY_ENV] == "untouched"

    def test_copies_mapping_without_items(self):
        """Windows ``CreateProcess`` reads ``keys()`` / ``values()``; so does the copy."""

        class KeysAndValues:
            def keys(self):
                return ["TETHERED_SENTINEL"]

            def values(self):
                return ["from-caller"]

        new_env = _build_per_launch_env(
            "subprocess.Popen", ("/x", [], None, KeysAndValues()), (self._SCOPE,), self._cfg()
        )
        assert new_env["TETHERED_SENTINEL"] == "from-caller"
        assert _CHILD_POLICY_ENV in new_env

    def test_unreadable_env_is_not_replaced_by_the_parents(self):
        """An object that is not a mapping yields no environment at all."""
        assert (
            _build_per_launch_env(
                "subprocess.Popen", ("/x", [], None, object()), (self._SCOPE,), self._cfg()
            )
            is None
        )

    @pytest.mark.parametrize("kind", _ENV_MAPPING_KINDS)
    def test_handler_injects_the_copy_into_execute_child(self, kind):
        """The ``_execute_child`` frame ends up with the copy, not the parent's environment."""
        env_arg = _as_mapping(kind, {"TETHERED_SENTINEL": "from-caller"})
        args = (sys.executable, [sys.executable, "-c", "pass"], None, env_arg)
        injected = _call_in_execute_child(
            lambda: _handle_subprocess(self._cfg(), "subprocess.Popen", args, (self._SCOPE,)),
            env_arg,
        )
        assert injected is not env_arg
        assert set(injected) == {"TETHERED_SENTINEL", _CHILD_POLICY_ENV}
        assert _CHILD_POLICY_ENV not in env_arg

    def test_unreadable_env_unlocked_warns(self, monkeypatch, caplog):
        monkeypatch.setattr(_core, "_find_execute_child_frame", lambda: object())
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _handle_subprocess(
                self._cfg(),
                "subprocess.Popen",
                (sys.executable, [sys.executable, "-c", "pass"], None, object()),
                (self._SCOPE,),
            )
        assert any("could not be read as a mapping" in r.message for r in caplog.records)

    def test_unreadable_env_locked_fails_closed(self, monkeypatch):
        payload = json.dumps({"global": {"allow": [], "locked": True}, "scopes": []})
        monkeypatch.setenv(_CHILD_POLICY_ENV, payload)
        monkeypatch.setattr(_core, "_find_execute_child_frame", lambda: object())
        cfg = _Config(policy=AllowPolicy([]), locked=True, _serialized_payload=payload)
        with pytest.raises(tethered.SubprocessBlocked, match=r"could not be read as a mapping"):
            _handle_subprocess(
                cfg,
                "subprocess.Popen",
                (sys.executable, [sys.executable, "-c", "pass"], None, object()),
                (self._SCOPE,),
            )

    @pytest.mark.parametrize("kind", _ENV_MAPPING_KINDS)
    def test_child_sees_the_callers_env_not_the_parents(self, kind, monkeypatch):
        """End to end: the sentinel survives and a parent-only variable does not appear."""
        tethered.activate(allow=["*.allowed.com"])
        monkeypatch.setenv("TETHERED_PARENT_ONLY", "1")
        base = _minimal_child_env()
        base["TETHERED_SENTINEL"] = "from-caller"
        with tethered.scope(allow=["api.allowed.com"]):
            state = _launch_probe(env=_as_mapping(kind, base))
        assert state["sentinel"] == "from-caller"
        assert state["parent_only"] is None
        assert state["active"] is True
        assert state["scopes"] == 1


class TestTypeExactPayloadComparison:
    """The launch payload's ``global`` must equal the canonical one type-exactly.

    Dict equality treats ``0`` as ``False``, so a payload the child's
    ``activate()`` rejects used to pass the locked-mode check — and the child
    then ran with no policy.  The canonical side comes from the immutable
    ``_serialized_payload``, never from the mutable ``_global_payload_dict``.
    """

    _GLOBAL: ClassVar[dict[str, object]] = {
        "allow": ["*.example.com"],
        "allow_localhost": True,
        "log_only": False,
        "fail_closed": False,
        "external_subprocess_policy": "allow",
        "locked": True,
    }
    _CANONICAL = json.dumps({"global": _GLOBAL, "scopes": []})

    def _cfg(self, **fields: object) -> _Config:
        return _Config(
            policy=AllowPolicy(["*.example.com"]),
            external_subprocess_policy="allow",
            locked=True,
            _serialized_payload=self._CANONICAL,
            **fields,
        )

    def _payload(self, **overrides: object) -> str:
        return json.dumps({"global": {**self._GLOBAL, **overrides}, "scopes": []})

    def _classify(self, text: str | None) -> str:
        return _core._classify_payload(text, self._CANONICAL, self._CANONICAL)

    def test_identical_text_is_exact(self):
        assert self._classify(self._CANONICAL) == "exact"

    def test_other_serialization_of_the_same_global(self):
        """Key order, whitespace and the scope list do not change the ``global``."""
        reordered = json.dumps(
            {"scopes": [{"allow": []}], "global": dict(reversed(list(self._GLOBAL.items())))},
            indent=2,
        )
        assert self._classify(reordered) == "same-global"

    @pytest.mark.parametrize("field", ["log_only", "fail_closed", "allow_localhost", "locked"])
    @pytest.mark.parametrize("as_type", [int, float])
    def test_number_for_bool_is_a_substitution(self, field, as_type):
        """Equal under ``==``, but not the same JSON value."""
        value = as_type(self._GLOBAL[field])
        assert value == self._GLOBAL[field]
        assert self._classify(self._payload(**{field: value})) == "substituted"

    def test_missing_or_extra_field_is_a_substitution(self):
        missing = {k: v for k, v in self._GLOBAL.items() if k != "log_only"}
        assert self._classify(json.dumps({"global": missing, "scopes": []})) == "substituted"
        assert self._classify(self._payload(extra=None)) == "substituted"

    @pytest.mark.parametrize("text", ["[1, 2]", "null", '{"allow": ["evil.test"]}'])
    def test_json_without_the_canonical_global_is_a_substitution(self, text):
        assert self._classify(text) == "substituted"

    @pytest.mark.parametrize("text", ["{not json", "", None])
    def test_not_json_is_corrupt(self, text):
        assert self._classify(text) == "corrupt"

    @pytest.mark.parametrize("field", ["log_only", "fail_closed", "allow_localhost"])
    def test_locked_check_refuses_number_for_bool_in_explicit_env(self, field):
        tampered = self._payload(**{field: int(self._GLOBAL[field])})
        with pytest.raises(tethered.SubprocessBlocked, match=r"substitution attempt"):
            _handle_subprocess(
                self._cfg(),
                "subprocess.Popen",
                ("/bin/sh", [], None, {_CHILD_POLICY_ENV: tampered}),
            )

    def test_locked_check_refuses_number_for_bool_in_os_environ(self, monkeypatch):
        monkeypatch.setenv(_CHILD_POLICY_ENV, self._payload(log_only=0))
        with pytest.raises(tethered.SubprocessBlocked, match=r"substitution attempt"):
            _handle_subprocess(self._cfg(), "subprocess.Popen", ("/bin/sh", [], None, None))

    def test_mutated_global_payload_dict_is_not_trusted(self, monkeypatch):
        """Widening the mutable dict in place neither passes the check nor reaches a child."""
        monkeypatch.setenv(_CHILD_POLICY_ENV, self._CANONICAL)
        cfg = self._cfg(_global_payload_dict=json.loads(self._CANONICAL)["global"])
        cfg._global_payload_dict["allow"].append("evil.test")
        widened = json.dumps({"global": cfg._global_payload_dict, "scopes": []})
        with pytest.raises(tethered.SubprocessBlocked, match=r"substitution attempt"):
            _handle_subprocess(
                cfg, "subprocess.Popen", ("/bin/sh", [], None, {_CHILD_POLICY_ENV: widened})
            )
        scope_cfg = _ScopeConfig(policy=AllowPolicy(["api.example.com"]), label="s")
        new_env = _build_per_launch_env(
            "subprocess.Popen", ("/x", [], None, None), (scope_cfg,), cfg
        )
        assert json.loads(new_env[_CHILD_POLICY_ENV])["global"] == self._GLOBAL

    def test_canonical_payload_is_rebuilt_for_a_config_without_the_serialized_field(self):
        cfg = _Config(policy=AllowPolicy(["b.example.com", "a.example.com"]), fail_closed=True)
        assert json.loads(_core._canonical_payload(cfg)) == {
            "global": {
                "allow": ["a.example.com", "b.example.com"],
                "allow_localhost": True,
                "log_only": False,
                "fail_closed": True,
                "external_subprocess_policy": "warn",
                "locked": False,
            },
            "scopes": [],
        }

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    @pytest.mark.parametrize("field", ["log_only", "fail_closed", "allow_localhost"])
    def test_locked_parent_refuses_to_launch_with_number_for_bool(self, field):
        """End to end: the parent no longer approves a payload the child would reject."""
        tethered.activate(allow=[], locked=True, lock_token=object())
        payload = json.loads(os.environ[_CHILD_POLICY_ENV])
        payload["global"][field] = int(payload["global"][field])
        env = {**os.environ, _CHILD_POLICY_ENV: json.dumps(payload)}
        with pytest.raises(tethered.SubprocessBlocked, match=r"substitution attempt"):
            subprocess.run(  # nosec B603
                [sys.executable, "-c", "pass"], env=env, capture_output=True, timeout=30
            )
