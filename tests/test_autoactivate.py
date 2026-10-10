"""Tests for tethered._autoactivate and end-to-end subprocess auto-propagation."""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import subprocess
import sys
import threading

import pytest

import tethered
import tethered._autoactivate as _autoactivate
import tethered._core as _core
from tethered._core import (
    _CHILD_POLICY_ENV,
    _build_child_policy_payload,
    _clear_policy_from_env,
    _Config,
    _serialize_allow_list,
)
from tethered._policy import AllowPolicy


def _payload(*, scopes: list | None = None, **overrides: object) -> str:
    """Build a JSON-encoded child policy payload (nested format).

    Defaults populate the canonical ``global`` field; ``overrides`` go inside
    ``global``.  Pass ``scopes=[...]`` to populate the parallel scope chain.
    """
    global_defaults: dict[str, object] = {
        "allow": [],
        "allow_localhost": True,
        "log_only": False,
        "fail_closed": False,
        "external_subprocess_policy": "allow",
        "locked": False,
    }
    global_defaults.update(overrides)
    return json.dumps({"global": global_defaults, "scopes": scopes or []})


class TestAutoactivateUnit:
    """Direct unit tests for _autoactivate_from_env() in-process."""

    def test_no_env_var_is_noop(self, monkeypatch):
        """When the policy env var is absent, _autoactivate is a no-op."""
        monkeypatch.delenv(_CHILD_POLICY_ENV, raising=False)
        _autoactivate._autoactivate_from_env()
        assert _core._config is None

    def test_malformed_json_logs_and_returns(self, monkeypatch, caplog):
        """Malformed JSON in the env var logs a warning and does not raise."""
        monkeypatch.setenv(_CHILD_POLICY_ENV, "not valid json {")
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _autoactivate._autoactivate_from_env()
        assert _core._config is None
        assert any("malformed _TETHERED_CHILD_POLICY" in r.message for r in caplog.records)

    def test_valid_payload_activates(self, monkeypatch):
        """A valid payload activates tethered with the inherited fields."""
        monkeypatch.setenv(_CHILD_POLICY_ENV, _payload(allow=["*.example.com"]))
        _autoactivate._autoactivate_from_env()
        assert _core._config is not None
        assert _core._config.policy.is_allowed("api.example.com", 443)

    def test_idempotent_when_already_active(self, monkeypatch):
        """If tethered is already active, _autoactivate is a no-op (fork-inheritance case)."""
        # Activate first with one policy
        tethered.activate(allow=["*.first.com"])
        first_config = _core._config
        # Then run autoactivate with a different payload — it should not replace
        monkeypatch.setenv(_CHILD_POLICY_ENV, _payload(allow=["*.second.com"]))
        _autoactivate._autoactivate_from_env()
        assert _core._config is first_config  # unchanged

    def test_optional_fields_default_when_missing(self, monkeypatch):
        """Bootstrap applies defaults when only ``allow`` is provided in the payload."""
        monkeypatch.setenv(
            _CHILD_POLICY_ENV,
            json.dumps({"global": {"allow": ["*.example.com"]}, "scopes": []}),
        )
        _autoactivate._autoactivate_from_env()
        cfg = _core._config
        assert cfg is not None
        assert cfg.policy._allow_localhost is True
        assert cfg.log_only is False
        assert cfg.fail_closed is False
        assert cfg.external_subprocess_policy == "warn"
        assert cfg.locked is False

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_locked_propagation(self, monkeypatch):
        """Payload with locked=true → child auto-activates with locked=True and a fresh token."""
        monkeypatch.setenv(_CHILD_POLICY_ENV, _payload(allow=["*.example.com"], locked=True))
        _autoactivate._autoactivate_from_env()
        cfg = _core._config
        assert cfg is not None
        assert cfg.locked is True
        # The child's fresh per-process token lives only in the C guardian.
        assert _core._c_guardian.is_active() is True
        assert _core._c_guardian.check_token(None) is False

    def test_locked_without_c_extension_refuses_to_start(self, monkeypatch):
        """The parent asked for locked mode; a child that cannot lock must not run unlocked."""
        monkeypatch.setenv(_CHILD_POLICY_ENV, _payload(allow=["*.example.com"], locked=True))
        monkeypatch.setattr(_core, "_c_guardian", None)
        with pytest.raises(SystemExit, match=r"C guardian extension is not available"):
            _autoactivate._autoactivate_from_env()
        assert _core._config is None


class TestAutoactivateIntegration:
    """End-to-end tests that spawn real Python subprocesses and verify auto-propagation."""

    def test_child_inherits_policy(self):
        """Plain subprocess.run launches a child that inherits the parent's allow list."""
        tethered.activate(allow=["*.example.com"])
        result = subprocess.run(  # nosec B603 B607
            [
                sys.executable,
                "-c",
                (
                    "import socket\n"
                    "try:\n"
                    "    socket.getaddrinfo('evil.test', 80)\n"
                    "    print('FAIL: should have been blocked')\n"
                    "except Exception as e:\n"
                    "    print(f'BLOCKED: {type(e).__name__}')"
                ),
            ],
            capture_output=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr.decode()
        assert b"BLOCKED" in result.stdout

    def test_child_has_active_config(self):
        """Child interpreter has a non-None _config after auto-activation."""
        tethered.activate(allow=["*.example.com"])
        result = subprocess.run(  # nosec B603 B607
            [
                sys.executable,
                "-c",
                (
                    "import tethered._core as c; "
                    "assert c._config is not None, 'child should have tethered active'; "
                    "print('OK')"
                ),
            ],
            capture_output=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr.decode()
        assert b"OK" in result.stdout

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_child_app_reactivate_identical_locked_policy_is_noop(self):
        """An auto-activated child can re-run app startup code calling activate(locked=True).

        The Django/import-time pattern: the parent activates locked mode and
        spawns a Python child, which auto-activates via tethered.pth and then
        imports application settings that call activate() with the same
        policy and a fresh lock_token.  Before idempotent re-activation this
        raised TetheredLocked in every spawn-mode child.
        """
        tethered.activate(
            allow=["api.allowed.com:443", "db.internal:5432"],
            locked=True,
            lock_token=object(),
        )
        result = subprocess.run(  # nosec B603 B607
            [
                sys.executable,
                "-c",
                (
                    "import tethered\n"
                    "tethered.activate(\n"
                    "    allow=['db.internal:5432', 'api.allowed.com:443'],\n"
                    "    locked=True,\n"
                    "    lock_token=object(),\n"
                    ")\n"
                    "print('OK')"
                ),
            ],
            capture_output=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr.decode()
        assert b"OK" in result.stdout

    def test_no_propagation_when_parent_inactive(self):
        """Without parent activation, the child also has no policy."""
        # The conftest _cleanup fixture clears any prior activation
        result = subprocess.run(  # nosec B603 B607
            [
                sys.executable,
                "-c",
                "import tethered._core as c; print('inactive' if c._config is None else 'active')",
            ],
            capture_output=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr.decode()
        assert b"inactive" in result.stdout

    def test_child_with_dash_I_still_auto_activates(self):
        """``-I`` (isolated mode) does NOT disable ``site.py`` — auto-activation still works."""
        tethered.activate(allow=["api.allowed.com"])
        result = subprocess.run(  # nosec B603 B607
            [
                sys.executable,
                "-I",
                "-c",
                "import tethered._core as c; "
                "print('active' if c._config is not None else 'inactive')",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr
        assert "active" in result.stdout

    def test_child_with_dash_E_still_auto_activates(self):
        """``-E`` (ignore ``PYTHON*`` env vars) does NOT disable ``site.py``."""
        tethered.activate(allow=["api.allowed.com"])
        result = subprocess.run(  # nosec B603 B607
            [
                sys.executable,
                "-E",
                "-c",
                "import tethered._core as c; "
                "print('active' if c._config is not None else 'inactive')",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr
        assert "active" in result.stdout

    def test_child_with_combined_IE_still_auto_activates(self):
        """Combined ``-IE`` (no ``S``) keeps ``site.py`` enabled."""
        tethered.activate(allow=["api.allowed.com"])
        result = subprocess.run(  # nosec B603 B607
            [
                sys.executable,
                "-IE",
                "-c",
                "import tethered._core as c; "
                "print('active' if c._config is not None else 'inactive')",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr
        assert "active" in result.stdout

    def test_child_with_dash_S_does_not_auto_activate(self):
        """``-S`` actually disables ``site.py`` — child does NOT inherit policy."""
        tethered.activate(allow=["api.allowed.com"])
        # ``-S`` skips site-packages discovery entirely, so we can't even
        # ``import tethered._core`` the conventional way.  A conditional
        # check via ``sys.modules`` works: site.py never ran tethered.pth,
        # so ``tethered._autoactivate`` is not in ``sys.modules``.
        result = subprocess.run(  # nosec B603 B607
            [
                sys.executable,
                "-S",
                "-c",
                "import sys; "
                "print('bootstrapped' if 'tethered._autoactivate' in sys.modules "
                "else 'not_bootstrapped')",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr
        assert "not_bootstrapped" in result.stdout

    def test_child_with_dash_I_inherits_enforcement(self):
        """``-I`` child auto-activates AND enforces — egress to non-allowed host blocked."""
        tethered.activate(allow=["api.allowed.com"])
        result = subprocess.run(  # nosec B603 B607
            [
                sys.executable,
                "-I",
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
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr
        assert "TETHERED_BLOCKED" in result.stdout

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_locked_propagation_end_to_end(self):
        """Parent locked=True → child is locked (with its own per-process token)."""
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        result = subprocess.run(  # nosec B603 B607
            [
                sys.executable,
                "-c",
                ("import tethered._core as c; print('locked' if c._config.locked else 'unlocked')"),
            ],
            capture_output=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr.decode()
        assert b"locked" in result.stdout

    def test_env_strip_in_non_locked_mode_still_inherits(self):
        """A sanitized env= in non-locked mode succeeds and the child still gets the policy."""
        tethered.activate(allow=["*.example.com"])
        # The caller's env lacks the propagation var; tethered puts it into the
        # environment the child receives (the caller's dict is left alone).
        # Pass a minimal env so Python can still find its standard library on Windows.
        minimal_env = {
            k: v
            for k, v in os.environ.items()
            if k.upper() in {"PATH", "SYSTEMROOT", "PATHEXT", "TEMP", "TMP"}
        }
        result = subprocess.run(  # nosec B603 B607
            [
                sys.executable,
                "-c",
                "import tethered._core as c; print('inactive' if c._config is None else 'active')",
            ],
            capture_output=True,
            timeout=15,
            env=minimal_env,
        )
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout.strip() == b"active"
        assert _CHILD_POLICY_ENV not in minimal_env

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_env_strip_in_locked_mode_blocked(self):
        """env={} in locked mode raises SubprocessBlocked before the launch."""
        tethered.activate(allow=[], locked=True, lock_token=object())
        with pytest.raises(tethered.SubprocessBlocked, match=r"strips _TETHERED_CHILD_POLICY"):
            subprocess.run(  # nosec B603 B607
                [sys.executable, "-c", "pass"],
                env={},
                capture_output=True,
                timeout=10,
            )

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_env_with_explicit_policy_carry_through_in_locked_mode(self):
        """Explicit env carrying the canonical _TETHERED_CHILD_POLICY is allowed in locked mode."""
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=object())
        # Build a minimal env that explicitly carries the policy var
        minimal_env = {
            k: v
            for k, v in os.environ.items()
            if k.upper() in {"PATH", "SYSTEMROOT", "PATHEXT", "TEMP", "TMP"}
        }
        minimal_env[_CHILD_POLICY_ENV] = os.environ[_CHILD_POLICY_ENV]
        result = subprocess.run(  # nosec B603 B607
            [
                sys.executable,
                "-c",
                "import tethered._core as c; print('active' if c._config else 'inactive')",
            ],
            capture_output=True,
            timeout=15,
            env=minimal_env,
        )
        assert result.returncode == 0, result.stderr.decode()
        assert b"active" in result.stdout

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_env_substitution_in_locked_mode_blocked(self):
        """Explicit env carrying a different (substituted) payload is blocked in locked mode."""
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=object())
        with pytest.raises(tethered.SubprocessBlocked, match=r"substitution attempt"):
            subprocess.run(  # nosec B603 B607
                [sys.executable, "-c", "pass"],
                env={_CHILD_POLICY_ENV: '{"allow": ["evil.test"]}'},
                capture_output=True,
                timeout=10,
            )

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_environ_pop_then_inherit_blocked_in_locked_mode(self, monkeypatch):
        """An attacker stripping the policy var from os.environ then spawning with env=None
        is caught by the locked-mode os.environ-equality check."""
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=object())
        # Simulate the bypass attempt: strip the policy var from os.environ, then spawn
        # with env=None (inherits the now-stripped env).
        monkeypatch.delenv(_CHILD_POLICY_ENV, raising=False)
        with pytest.raises(tethered.SubprocessBlocked, match=r"os\.environ strips"):
            subprocess.run(  # nosec B603 B607
                [sys.executable, "-c", "pass"],
                capture_output=True,
                timeout=10,
            )

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_environ_substitution_then_inherit_blocked_in_locked_mode(self, monkeypatch):
        """Mutating os.environ to a permissive value, then spawning with env=None, is blocked."""
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=object())
        monkeypatch.setenv(_CHILD_POLICY_ENV, '{"allow": ["evil.test"]}')
        with pytest.raises(tethered.SubprocessBlocked, match=r"substitution attempt"):
            subprocess.run(  # nosec B603 B607
                [sys.executable, "-c", "pass"],
                capture_output=True,
                timeout=10,
            )

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_pth_unlink_blocked_in_locked_mode(self, tmp_path, monkeypatch):
        """Attempting to delete tethered.pth in locked mode is blocked at audit time."""
        # Activate locked, then try to delete the cached .pth path
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=object())
        cached = _core._config._pth_path
        with pytest.raises(tethered.SubprocessBlocked, match=r"refused deletion"):
            os.unlink(cached)

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_pth_overwrite_blocked_in_locked_mode(self):
        """Attempting to open tethered.pth for writing in locked mode is blocked."""
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=object())
        cached = _core._config._pth_path
        with (
            pytest.raises(tethered.SubprocessBlocked, match=r"refused write-open"),
            open(cached, "w") as f,
        ):
            f.write("malicious")


class TestPolicyEnvVarLifecycle:
    """activate() / deactivate() manage the _TETHERED_CHILD_POLICY env var."""

    def test_activate_populates_env(self):
        tethered.activate(allow=["*.example.com"])
        raw = os.environ.get(_CHILD_POLICY_ENV)
        assert raw is not None
        payload = json.loads(raw)
        assert payload["global"]["allow"] == ["*.example.com"]
        assert payload["global"]["locked"] is False
        assert payload["scopes"] == []

    def test_deactivate_clears_env(self):
        tethered.activate(allow=["*.example.com"])
        assert _CHILD_POLICY_ENV in os.environ
        tethered.deactivate()
        assert _CHILD_POLICY_ENV not in os.environ

    def test_reactivate_replaces_env(self):
        tethered.activate(allow=["*.first.com"])
        first = os.environ[_CHILD_POLICY_ENV]
        tethered.activate(allow=["*.second.com"])
        second = os.environ[_CHILD_POLICY_ENV]
        assert first != second
        assert "second.com" in second

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_locked_propagation_includes_locked_field(self):
        secret = object()
        tethered.activate(allow=["*.example.com"], locked=True, lock_token=secret)
        payload = json.loads(os.environ[_CHILD_POLICY_ENV])
        assert payload["global"]["locked"] is True
        # Cleanup: deactivate with the token
        tethered.deactivate(lock_token=secret)


class TestPayloadHelpers:
    """Direct unit tests for _build_child_policy_payload and the env-var helpers."""

    def test_build_payload_includes_all_fields(self):
        cfg = _Config(
            policy=AllowPolicy(["api.example.com:443", "10.0.0.0/8"]),
            log_only=True,
            fail_closed=True,
            external_subprocess_policy="warn",
            locked=False,
        )
        payload = _build_child_policy_payload(cfg)
        assert "api.example.com:443" in payload["allow"]
        assert "10.0.0.0/8" in payload["allow"]
        assert payload["log_only"] is True
        assert payload["fail_closed"] is True
        assert payload["external_subprocess_policy"] == "warn"
        assert payload["locked"] is False
        assert payload["allow_localhost"] is True

    def test_clear_policy_from_env_is_idempotent(self):
        os.environ.pop(_CHILD_POLICY_ENV, None)
        _clear_policy_from_env()  # should not raise even if not present
        assert _CHILD_POLICY_ENV not in os.environ


class TestAutoactivateNestedFormat:
    """Tests for nested-format parsing and scope inheritance in _autoactivate."""

    def test_non_object_payload_logs_and_returns(self, monkeypatch, caplog):
        """A JSON payload that isn't an object (e.g. a list) logs warning and skips."""
        monkeypatch.setenv(_CHILD_POLICY_ENV, "[1, 2, 3]")
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _autoactivate._autoactivate_from_env()
        assert _core._config is None
        assert any("not a JSON object" in r.message for r in caplog.records)

    def test_nested_format_with_scopes_inherits(self, monkeypatch):
        """Nested payload with scopes pushes them onto the per-context scope stack."""
        payload = json.dumps(
            {
                "global": {"allow": ["*.example.com"]},
                "scopes": [
                    {
                        "allow": ["api.example.com"],
                        "allow_localhost": True,
                        "log_only": False,
                        "fail_closed": False,
                        "label": "test-scope",
                    }
                ],
            }
        )
        monkeypatch.setenv(_CHILD_POLICY_ENV, payload)
        _autoactivate._autoactivate_from_env()
        assert _core._config is not None
        scopes = _core._scopes.get()
        assert len(scopes) == 1
        assert scopes[0].label == "test-scope"
        assert scopes[0].policy.is_allowed("api.example.com", 443)

    def test_global_null_with_scopes_only(self, monkeypatch):
        """global=null + scopes: child has no _config but has inherited scopes."""
        payload = json.dumps(
            {
                "global": None,
                "scopes": [
                    {"allow": ["api.example.com"], "label": "scope-only"},
                ],
            }
        )
        monkeypatch.setenv(_CHILD_POLICY_ENV, payload)
        _autoactivate._autoactivate_from_env()
        assert _core._config is None  # global was null
        scopes = _core._scopes.get()
        assert len(scopes) == 1
        assert scopes[0].label == "scope-only"


class TestInheritScopes:
    """Direct unit tests for _autoactivate._inherit_scopes."""

    def test_inherit_scopes_pushes_onto_stack(self):
        scopes_payload = [
            {
                "allow": ["api.example.com"],
                "allow_localhost": True,
                "log_only": False,
                "fail_closed": False,
                "label": "first",
            },
            {
                "allow": ["api2.example.com"],
                "label": "second",
            },
        ]
        _autoactivate._inherit_scopes(scopes_payload)
        scopes = _core._scopes.get()
        assert [s.label for s in scopes] == ["first", "second"]

    def test_inherit_scopes_skips_non_dict_entries(self, caplog):
        """Non-dict scope entries are logged and skipped."""
        scopes_payload = ["not-a-dict", {"allow": ["api.example.com"]}]
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _autoactivate._inherit_scopes(scopes_payload)
        scopes = _core._scopes.get()
        assert len(scopes) == 1  # only the valid one inherited
        assert any("malformed scope entry" in r.message for r in caplog.records)

    def test_inherit_scopes_skips_invalid_allow_rules(self, caplog):
        """Scope entries with invalid allow rules are logged and skipped."""
        scopes_payload = [
            {"allow": ["://invalid"]},  # URL-shape rejected by AllowPolicy
            {"allow": ["api.example.com"], "label": "valid"},
        ]
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _autoactivate._inherit_scopes(scopes_payload)
        scopes = _core._scopes.get()
        assert len(scopes) == 1
        assert scopes[0].label == "valid"
        assert any("failed to inherit scope" in r.message for r in caplog.records)

    def test_inherit_scopes_no_op_when_all_invalid(self, caplog):
        """If every scope entry is malformed, no scope is pushed."""
        scopes_payload = ["not-a-dict", 42]
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _autoactivate._inherit_scopes(scopes_payload)
        assert _core._scopes.get() == ()

    def test_inherit_scopes_carries_hint(self):
        """A hint serialized into the child policy survives reconstruction."""
        scopes_payload = [
            {
                "allow": ["api.example.com"],
                "label": "lib.task",
                "hint": "lib.task needs api.example.com — see docs",
            },
        ]
        _autoactivate._inherit_scopes(scopes_payload)
        scopes = _core._scopes.get()
        assert len(scopes) == 1
        assert scopes[0].hint == "lib.task needs api.example.com — see docs"

    def test_inherit_scopes_missing_hint_defaults_to_empty(self):
        """A scope payload without a hint reconstructs with an empty hint."""
        _autoactivate._inherit_scopes([{"allow": ["api.example.com"], "label": "no-hint"}])
        scopes = _core._scopes.get()
        assert scopes[0].hint == ""

    def test_inherit_scopes_non_string_hint_is_dropped(self):
        """A malformed (non-string) hint in the payload is treated as empty."""
        _autoactivate._inherit_scopes(
            [{"allow": ["api.example.com"], "label": "bad-hint", "hint": 42}],
        )
        scopes = _core._scopes.get()
        assert scopes[0].hint == ""

    def test_inherit_scopes_non_string_label_falls_back(self):
        """A non-string label never reaches log messages; the default is used."""
        _autoactivate._inherit_scopes([{"allow": ["api.example.com"], "label": 42}])
        assert _core._scopes.get()[0].label == "inherited-scope"

    def test_inherit_scopes_skips_non_string_allow_items(self, caplog):
        """A non-string allow item skips that entry only — it used to drop every scope."""
        scopes_payload = [
            {"allow": ["api.example.com", 5], "label": "bad"},
            {"allow": ["api.example.com"], "label": "valid"},
        ]
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _autoactivate._inherit_scopes(scopes_payload)
        assert [s.label for s in _core._scopes.get()] == ["valid"]
        assert any(r"scopes[0].allow[1] must be str" in r.message for r in caplog.records)

    def test_inherit_scopes_strict_refuses_malformed_entry(self):
        with pytest.raises(SystemExit, match=r"scopes\[0\]\.log_only must be bool"):
            _autoactivate._inherit_scopes(
                [{"allow": ["api.example.com"], "log_only": 0}], strict=True
            )
        assert _core._scopes.get() == ()

    def test_inherit_scopes_strict_refuses_rule_the_policy_rejects(self):
        with pytest.raises(SystemExit, match=r"failed to inherit scope"):
            _autoactivate._inherit_scopes([{"allow": ["://invalid"]}], strict=True)
        assert _core._scopes.get() == ()


_STRICT_FLAGS = ("locked", "fail_closed")


class TestInheritedPayloadValidation:
    """The payload schema is validated before use, with exact field types.

    When the inherited global asks for ``locked`` or ``fail_closed`` a policy
    that cannot be established terminates startup (``SystemExit`` — the only
    thing ``site.py`` does not swallow from a ``.pth`` line).  Otherwise the
    problem is logged and the child continues, as before.
    """

    def _run(self, monkeypatch, global_payload: object, scopes: object = None) -> None:
        payload = {"global": global_payload, "scopes": [] if scopes is None else scopes}
        monkeypatch.setenv(_CHILD_POLICY_ENV, json.dumps(payload))
        _autoactivate._autoactivate_from_env()

    @staticmethod
    def _global(**overrides: object) -> dict[str, object]:
        return json.loads(_payload(**overrides))["global"]

    @pytest.mark.parametrize("strict_flag", _STRICT_FLAGS)
    @pytest.mark.parametrize("field", ["log_only", "allow_localhost"])
    @pytest.mark.parametrize("value", [0, 0.0, 1, "false", None])
    def test_wrong_type_refuses_to_start_when_strict(self, monkeypatch, strict_flag, field, value):
        """``0`` is not ``false``: the child used to log a warning and run unprotected."""
        global_payload = self._global(**{strict_flag: True, field: value})
        with pytest.raises(SystemExit, match=rf"global\.{field} must be bool"):
            self._run(monkeypatch, global_payload)
        assert _core._config is None

    @pytest.mark.parametrize("strict_flag", _STRICT_FLAGS)
    @pytest.mark.parametrize("value", [1, 0, "yes", None])
    def test_mistyped_strict_flag_cannot_downgrade(self, monkeypatch, strict_flag, value):
        """A flag that is not exactly ``false`` still counts as asking for it."""
        with pytest.raises(SystemExit, match=rf"global\.{strict_flag} must be bool"):
            self._run(monkeypatch, self._global(**{strict_flag: value}))
        assert _core._config is None

    def test_wrong_type_logs_and_continues_otherwise(self, monkeypatch, caplog):
        with caplog.at_level(logging.WARNING, logger="tethered"):
            self._run(monkeypatch, self._global(log_only=0))
        assert _core._config is None
        assert any(
            "auto-activation failed: global.log_only must be bool, got int: 0" in r.message
            for r in caplog.records
        )

    def test_missing_allow_logs_and_continues(self, monkeypatch, caplog):
        """A missing ``allow`` used to raise ``KeyError`` out of the bootstrap."""
        with caplog.at_level(logging.WARNING, logger="tethered"):
            self._run(monkeypatch, {"log_only": False})
        assert _core._config is None
        assert any("global is missing 'allow'" in r.message for r in caplog.records)

    def test_missing_allow_refuses_to_start_when_strict(self, monkeypatch):
        with pytest.raises(SystemExit, match=r"global is missing 'allow'"):
            self._run(monkeypatch, {"fail_closed": True})
        assert _core._config is None

    @pytest.mark.parametrize("allow", ["*.example.com", ["*.example.com", 5], None])
    def test_allow_must_be_a_list_of_str(self, monkeypatch, allow):
        with pytest.raises(SystemExit, match=r"global\.allow"):
            self._run(monkeypatch, self._global(fail_closed=True, allow=allow))
        assert _core._config is None

    def test_unknown_field_is_ignored_unless_strict(self, monkeypatch):
        global_payload = self._global(allow=["*.example.com"])
        global_payload["from_a_newer_version"] = True
        self._run(monkeypatch, global_payload)
        assert _core._config is not None
        assert _core._config.policy.is_allowed("api.example.com", 443)

    def test_unknown_field_refuses_to_start_when_strict(self, monkeypatch):
        global_payload = self._global(fail_closed=True)
        global_payload["from_a_newer_version"] = True
        with pytest.raises(SystemExit, match=r"global has unknown field 'from_a_newer_version'"):
            self._run(monkeypatch, global_payload)
        assert _core._config is None

    def test_unknown_top_level_field_refuses_to_start_when_strict(self, monkeypatch):
        payload = {"global": self._global(fail_closed=True), "scopes": [], "deny": ["x"]}
        monkeypatch.setenv(_CHILD_POLICY_ENV, json.dumps(payload))
        with pytest.raises(SystemExit, match=r"unknown field 'deny'"):
            _autoactivate._autoactivate_from_env()
        assert _core._config is None

    def test_activation_error_logs_and_continues(self, monkeypatch, caplog):
        """A rule the parent serialized but ``AllowPolicy`` rejects here."""
        with caplog.at_level(logging.WARNING, logger="tethered"):
            self._run(monkeypatch, self._global(allow=["://not-a-rule"]))
        assert _core._config is None
        assert any("auto-activation failed: ValueError" in r.message for r in caplog.records)

    def test_activation_error_refuses_to_start_when_strict(self, monkeypatch):
        with pytest.raises(SystemExit, match=r"auto-activation failed: ValueError"):
            self._run(monkeypatch, self._global(fail_closed=True, allow=["://not-a-rule"]))
        assert _core._config is None

    def test_global_that_is_not_an_object_still_inherits_scopes(self, monkeypatch, caplog):
        with caplog.at_level(logging.WARNING, logger="tethered"):
            self._run(monkeypatch, 5, scopes=[{"allow": ["api.example.com"], "label": "kept"}])
        assert _core._config is None
        assert [s.label for s in _core._scopes.get()] == ["kept"]
        assert any("global must be an object, got int" in r.message for r in caplog.records)

    def test_scopes_that_are_not_a_list_log_and_continue(self, monkeypatch, caplog):
        with caplog.at_level(logging.WARNING, logger="tethered"):
            self._run(monkeypatch, self._global(allow=["*.example.com"]), scopes={"allow": []})
        assert _core._config is not None
        assert _core._scopes.get() == ()
        assert any("scopes must be a list, got dict" in r.message for r in caplog.records)

    def test_scopes_that_are_not_a_list_refuse_to_start_when_strict(self, monkeypatch):
        with pytest.raises(SystemExit, match=r"scopes must be a list, got int"):
            self._run(monkeypatch, self._global(fail_closed=True), scopes=7)

    def test_malformed_scope_refuses_to_start_when_strict(self, monkeypatch):
        """A non-string allow item used to raise ``AttributeError`` and drop every scope."""
        with pytest.raises(SystemExit, match=r"scopes\[1\]\.allow\[0\] must be str"):
            self._run(
                monkeypatch,
                self._global(fail_closed=True),
                scopes=[{"allow": ["api.example.com"]}, {"allow": [5]}],
            )
        assert _core._scopes.get() == ()

    def test_malformed_scope_is_skipped_otherwise(self, monkeypatch):
        self._run(
            monkeypatch,
            self._global(allow=["*.example.com"]),
            scopes=[{"allow": [5], "label": "bad"}, {"allow": ["api.example.com"], "label": "ok"}],
        )
        assert _core._config is not None
        assert [s.label for s in _core._scopes.get()] == ["ok"]


class TestChildStartupFailsClosed:
    """Real children: when a strict policy cannot be established, user code does not run."""

    _USER_CODE = (
        "import sys\n"
        "core = sys.modules.get('tethered._core')\n"
        "print('USER CODE RAN active=%s' % bool(core and core._config))\n"
    )

    def _child(self, payload: object) -> subprocess.CompletedProcess[str]:
        raw = payload if isinstance(payload, str) else json.dumps(payload)
        return subprocess.run(  # nosec B603
            [sys.executable, "-c", self._USER_CODE],
            env={**os.environ, _CHILD_POLICY_ENV: raw},
            capture_output=True,
            text=True,
            timeout=30,
        )

    @staticmethod
    def _global(**overrides: object) -> dict[str, object]:
        return json.loads(_payload(**overrides))["global"]

    def test_valid_payload_runs_protected(self):
        r = self._child({"global": self._global(fail_closed=True), "scopes": []})
        assert r.returncode == 0, r.stderr
        assert "USER CODE RAN active=True" in r.stdout

    @pytest.mark.parametrize("field", ["log_only", "fail_closed", "allow_localhost"])
    @pytest.mark.parametrize("value", [0, 0.0])
    def test_locked_payload_with_number_for_bool_does_not_run(self, field, value):
        """The report's case: one field of a locked payload changed from ``false`` to ``0``."""
        r = self._child({"global": self._global(locked=True, **{field: value}), "scopes": []})
        assert r.returncode != 0
        assert "USER CODE RAN" not in r.stdout
        assert "tethered: refusing to start" in r.stderr
        assert f"global.{field} must be bool" in r.stderr

    @pytest.mark.parametrize(
        ("global_payload", "scopes", "expected"),
        [
            ({"fail_closed": True}, [], "global is missing 'allow'"),
            (
                {"allow": [], "fail_closed": True, "from_a_newer_version": 1},
                [],
                "unknown field 'from_a_newer_version'",
            ),
            ({"allow": ["://not-a-rule"], "fail_closed": True}, [], "auto-activation failed"),
            (
                {"allow": [], "fail_closed": True},
                [{"allow": [5]}],
                "scopes[0].allow[0] must be str",
            ),
            ({"allow": [], "fail_closed": True}, [{"allow": ["://x"]}], "failed to inherit scope"),
        ],
        ids=["missing-allow", "unknown-field", "activation-raises", "scope-type", "scope-rule"],
    )
    def test_strict_payload_that_cannot_be_established_does_not_run(
        self, global_payload, scopes, expected
    ):
        r = self._child({"global": global_payload, "scopes": scopes})
        assert r.returncode != 0
        assert "USER CODE RAN" not in r.stdout
        assert "tethered: refusing to start" in r.stderr
        assert expected in r.stderr

    def test_non_strict_payload_that_cannot_be_established_still_runs(self):
        """Neither flag set: today's fail-open default — a warning, then the workload."""
        r = self._child({"global": self._global(log_only=0), "scopes": []})
        assert r.returncode == 0, r.stderr
        assert "USER CODE RAN active=False" in r.stdout
        assert "auto-activation failed: global.log_only must be bool" in r.stderr

    def test_payload_that_is_not_json_still_runs(self):
        """Nothing can be read from it, so nothing asked for fail-closed startup."""
        r = self._child("{not json")
        assert r.returncode == 0, r.stderr
        assert "USER CODE RAN active=False" in r.stdout
        assert "malformed _TETHERED_CHILD_POLICY" in r.stderr


class _FakeInterpreters:
    """Stands in for ``_interpreters`` / ``_xxsubinterpreters``."""

    def __init__(self, current: object, main: object) -> None:
        self._current = current
        self._main = main

    def get_current(self) -> object:
        if isinstance(self._current, Exception):
            raise self._current
        return self._current

    def get_main(self) -> object:
        return self._main


class _InterpreterID:
    """Like the ``InterpreterID`` objects of Python 3.11 - 3.12: read through ``int()``."""

    def __init__(self, value: int) -> None:
        self._value = value

    def __int__(self) -> int:
        return self._value

    def __repr__(self) -> str:
        return f"InterpreterID({self._value})"


class TestInSubinterpreter:
    """``_in_subinterpreter()``, the question a locked payload makes the bootstrap ask.

    The answer inside a real subinterpreter is tested in
    ``test_subinterpreters.py``; here the stdlib modules are stood in for, so
    that every form of their answer is covered on every Python version.
    """

    def test_the_main_interpreter_is_not_one(self):
        assert _autoactivate._in_subinterpreter() is False

    @pytest.mark.parametrize(
        ("current", "main", "expected"),
        [
            ((0, 1), (0, 1), False),  # Python 3.13+: (id, whence)
            ((3, 5), (0, 1), True),
            ((3, 1), (0, 1), True),
            ((0, 5), (0, 1), False),  # the ID decides, not the whence
            (0, 0, False),
            (7, 0, True),
            (_InterpreterID(0), _InterpreterID(0), False),  # Python 3.11 - 3.12
            (_InterpreterID(7), _InterpreterID(0), True),
        ],
        ids=repr,
    )
    def test_compares_the_two_ids(self, monkeypatch, current, main, expected):
        monkeypatch.setitem(sys.modules, "_interpreters", _FakeInterpreters(current, main))
        assert _autoactivate._in_subinterpreter() is expected

    def test_falls_back_to_the_module_of_older_pythons(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "_interpreters", None)  # import raises ImportError
        fake = _FakeInterpreters(_InterpreterID(4), _InterpreterID(0))
        monkeypatch.setitem(sys.modules, "_xxsubinterpreters", fake)
        assert _autoactivate._in_subinterpreter() is True

    def test_without_either_module_it_counts_as_the_main_interpreter(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "_interpreters", None)
        monkeypatch.setitem(sys.modules, "_xxsubinterpreters", None)
        assert _autoactivate._in_subinterpreter() is False

    @pytest.mark.parametrize(
        "current", [RuntimeError("no interpreter state"), "not an id", None, ()], ids=repr
    )
    def test_an_answer_that_cannot_be_read_counts_as_the_main_interpreter(
        self, monkeypatch, current
    ):
        monkeypatch.setitem(sys.modules, "_interpreters", _FakeInterpreters(current, 0))
        assert _autoactivate._in_subinterpreter() is False


class TestLockedPayloadInASubinterpreter:
    """A lock exists once per process, so a subinterpreter enforces the policy unlocked.

    Run in the main interpreter with only the question "is this a
    subinterpreter?" answered differently: coverage does not see code that
    runs inside another interpreter.  ``test_subinterpreters.py`` runs the
    same paths for real.
    """

    @pytest.fixture
    def as_subinterpreter(self, monkeypatch):
        monkeypatch.setattr(_autoactivate, "_in_subinterpreter", lambda: True)

    def _run(self, monkeypatch, scopes: list | None = None, **overrides: object) -> str:
        raw = _payload(scopes=scopes, **{"locked": True, **overrides})
        monkeypatch.setenv(_CHILD_POLICY_ENV, raw)
        _autoactivate._autoactivate_from_env()
        return raw

    def test_the_policy_is_established_unlocked(self, as_subinterpreter, monkeypatch, caplog):
        with caplog.at_level(logging.INFO, logger="tethered"):
            raw = self._run(
                monkeypatch,
                allow=["*.example.com", "10.0.0.0/8:5432"],
                allow_localhost=False,
                fail_closed=True,
                external_subprocess_policy="block",
            )
        cfg = _core._config
        assert cfg is not None
        assert cfg.locked is False
        assert cfg.fail_closed is True
        assert cfg.log_only is False
        assert cfg.external_subprocess_policy == "block"
        assert cfg.policy._allow_localhost is False
        assert cfg.policy.is_allowed("api.example.com", 443)
        assert cfg.policy.is_allowed("10.1.2.3", 5432)
        assert not cfg.policy.is_allowed("evil.test", 443)
        assert json.loads(cfg._serialized_payload)["global"] == {
            **json.loads(raw)["global"],
            "locked": False,
        }
        if _core._c_guardian is not None:
            assert _core._c_guardian.is_active() is False
        # Not published: the process-wide variable still carries the locked payload.
        assert os.environ[_CHILD_POLICY_ENV] == raw
        # Reported once, at INFO — a pool creates many interpreters.
        assert [r.levelno for r in caplog.records if "subinterpreter" in r.message] == [
            logging.INFO
        ]
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

    def test_the_allow_list_is_enforced(self, as_subinterpreter, monkeypatch):
        self._run(monkeypatch, allow=["*.example.com"])
        with pytest.raises(tethered.EgressBlocked, match="is not in the allow list"):
            sys.audit("socket.connect", None, ("203.0.113.9", 443))
        sys.audit("socket.connect", None, ("127.0.0.1", 443))
        tethered.deactivate()  # unlocked: no token involved
        assert _core._config is None

    def test_the_config_is_the_one_activate_would_build(self, as_subinterpreter, monkeypatch):
        """Guards against drift: apart from ``locked``, what ``activate()`` builds."""
        fields = {
            "allow": ["*.example.com", "10.0.0.0/8:5432", "db.internal"],
            "allow_localhost": False,
            "log_only": True,
            "fail_closed": True,
            "external_subprocess_policy": "block",
        }
        tethered.activate(**fields)
        expected = _core._config
        tethered.deactivate()

        self._run(monkeypatch, **fields)
        actual = _core._config
        assert actual is not None
        assert actual is not expected
        for field in dataclasses.fields(_Config):
            if field.name != "policy":
                assert getattr(actual, field.name) == getattr(expected, field.name), field.name
        assert _serialize_allow_list(actual.policy) == _serialize_allow_list(expected.policy)
        assert actual.policy._allow_localhost == expected.policy._allow_localhost

    def test_optional_fields_default_as_in_activate(self, as_subinterpreter, monkeypatch):
        payload = {"global": {"allow": ["*.example.com"], "locked": True}, "scopes": []}
        monkeypatch.setenv(_CHILD_POLICY_ENV, json.dumps(payload))
        _autoactivate._autoactivate_from_env()
        cfg = _core._config
        assert cfg is not None
        assert (cfg.locked, cfg.log_only, cfg.fail_closed) == (False, False, False)
        assert cfg.external_subprocess_policy == "warn"
        assert cfg.policy._allow_localhost is True

    def test_the_c_extension_is_not_needed(self, as_subinterpreter, monkeypatch):
        """An interpreter with its own GIL cannot load it; that used to stop its startup."""
        monkeypatch.setattr(_core, "_c_guardian", None)
        self._run(monkeypatch, allow=["*.example.com"])
        assert _core._config is not None
        assert _core._config.locked is False

    def test_inherited_scopes_are_applied_too(self, as_subinterpreter, monkeypatch):
        self._run(
            monkeypatch,
            scopes=[{"allow": ["api.example.com"], "label": "inherited"}],
            allow=["*.example.com"],
        )
        assert _core._config is not None
        assert [s.label for s in _core._scopes.get()] == ["inherited"]

    @pytest.mark.parametrize(
        ("overrides", "expected"),
        [
            ({"log_only": 0}, r"global\.log_only must be bool"),
            ({"locked": 1}, r"global\.locked must be bool"),
            ({"from_a_newer_version": True}, r"unknown field 'from_a_newer_version'"),
            ({"allow": ["://not-a-rule"]}, r"auto-activation failed: ValueError"),
            ({"allow": "*.example.com"}, r"global\.allow must be list"),
            (
                {"external_subprocess_policy": "sometimes"},
                r"external_subprocess_policy: unknown value 'sometimes'",
            ),
        ],
        ids=["wrong-type", "mistyped-flag", "unknown-field", "bad-rule", "allow-type", "bad-value"],
    )
    def test_every_other_strict_failure_still_stops_startup(
        self, as_subinterpreter, monkeypatch, overrides, expected
    ):
        with pytest.raises(SystemExit, match=expected):
            self._run(monkeypatch, **overrides)
        assert _core._config is None

    def test_a_malformed_scope_still_stops_startup(self, as_subinterpreter, monkeypatch):
        with pytest.raises(SystemExit, match=r"scopes\[0\]\.allow\[0\] must be str"):
            self._run(monkeypatch, scopes=[{"allow": [5]}])

    def test_a_fail_closed_policy_that_cannot_be_established_still_stops_startup(
        self, as_subinterpreter, monkeypatch
    ):
        with pytest.raises(SystemExit, match=r"auto-activation failed: ValueError"):
            self._run(monkeypatch, locked=False, fail_closed=True, allow=["://not-a-rule"])
        assert _core._config is None

    def test_a_hook_that_cannot_be_installed_stops_startup(self, as_subinterpreter, monkeypatch):
        def refuse() -> None:
            raise RuntimeError("no audit hook")

        monkeypatch.setattr(_core, "_install_hook", refuse)
        with pytest.raises(SystemExit, match=r"auto-activation failed: RuntimeError: no audit"):
            self._run(monkeypatch, allow=["*.example.com"])
        assert _core._config is None

    def test_only_a_locked_payload_asks_which_interpreter_this_is(self, monkeypatch):
        """The question costs a module import; no other startup pays for it."""
        asked: list[bool] = []

        def in_subinterpreter() -> bool:
            asked.append(True)
            return False

        monkeypatch.setattr(_autoactivate, "_in_subinterpreter", in_subinterpreter)
        for raw in (
            _payload(allow=["*.example.com"]),
            _payload(allow=["*.example.com"], fail_closed=True),
            _payload(allow=["*.example.com"], log_only=0),  # invalid, not strict
            json.dumps({"global": None, "scopes": [{"allow": ["api.example.com"]}]}),
        ):
            monkeypatch.setenv(_CHILD_POLICY_ENV, raw)
            _autoactivate._autoactivate_from_env()
            _core._config = None
        assert asked == []

        # A locked payload that fails validation is refused without asking.
        monkeypatch.setenv(_CHILD_POLICY_ENV, _payload(locked=True, log_only=0))
        with pytest.raises(SystemExit):
            _autoactivate._autoactivate_from_env()
        assert asked == []

    @pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
    def test_a_valid_locked_payload_asks_once_and_locks_in_the_main_interpreter(self, monkeypatch):
        asked: list[bool] = []

        def in_subinterpreter() -> bool:
            asked.append(True)
            return False

        monkeypatch.setattr(_autoactivate, "_in_subinterpreter", in_subinterpreter)
        monkeypatch.setenv(_CHILD_POLICY_ENV, _payload(allow=["*.example.com"], locked=True))
        _autoactivate._autoactivate_from_env()
        assert asked == [True]
        assert _core._config.locked is True
        assert _core._c_guardian.is_active() is True


class _LockHeldElsewhere:
    """Stands in for the C guardian of a process in which another interpreter holds the lock.

    The real guardian accepts a join only from an interpreter that is still
    starting, which the main interpreter of a test run never is; and code
    that runs in a real subinterpreter is invisible to coverage.  So the
    Python side of a join is run here, against this: ``join()`` does what
    the real one does on success (it binds ``_config`` itself) or refuses
    with ``refusal``.  ``test_subinterpreters.py`` joins for real.
    """

    def __init__(self, payload: str | None, *, refusal: str | None = None) -> None:
        self._payload = payload
        self._refusal = refusal
        self.joins: list[tuple[dict, object, list]] = []

    def is_active(self) -> bool:
        return self._payload is not None

    def holds_lock(self) -> bool:
        return False  # another interpreter does

    def locked_payload(self) -> str | None:
        return self._payload

    def process_policy_env(self) -> str | None:
        # What the process holds: in a test run, what os.environ shows.
        return os.environ.get(_CHILD_POLICY_ENV)

    def join(self, namespace: dict, config: object, snapshot: list) -> None:
        self.joins.append((namespace, config, snapshot))
        if self._refusal is not None:
            raise RuntimeError(self._refusal)
        namespace["_config"] = config

    def check_token(self, token: object) -> bool:
        return False  # no interpreter but the owner holds the token

    def verify(self) -> bool:
        return True


def _locked_payload_of(**policy: object) -> str:
    """The payload the guardian holds for a policy: what ``activate()`` serializes for it."""
    token = object()
    tethered.activate(**policy, locked=True, lock_token=token)
    payload = _core._config._serialized_payload
    tethered.deactivate(lock_token=token)
    assert _core._config is None
    return payload


_JOINED_POLICY = {
    "allow": ["*.example.com", "10.0.0.0/8:5432", "db.internal"],
    "allow_localhost": False,
    "fail_closed": True,
    "external_subprocess_policy": "block",
}


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestJoinLocked:
    """``_core._join_locked()``: the policy an interpreter offers the guardian when it joins."""

    @pytest.fixture
    def elsewhere(self, monkeypatch):
        """A lock on ``_JOINED_POLICY`` held by another interpreter; returns the stand-in."""
        stand_in = _LockHeldElsewhere(_locked_payload_of(**_JOINED_POLICY))
        monkeypatch.setattr(_core, "_c_guardian", stand_in)
        return stand_in

    def test_it_offers_a_locked_copy_of_the_policy(self, elsewhere, caplog):
        payload = elsewhere.locked_payload()
        with caplog.at_level(logging.INFO, logger="tethered"):
            _core._join_locked(payload)

        ((namespace, offered, snapshot),) = elsewhere.joins
        cfg = _core._config
        assert cfg is offered  # bound by the guardian, in its own commit
        assert namespace is vars(_core)
        assert cfg.locked is True
        assert cfg.fail_closed is True
        assert cfg.log_only is False
        assert cfg.external_subprocess_policy == "block"
        assert cfg.on_blocked is None  # callbacks do not cross interpreters
        assert cfg.policy._allow_localhost is False
        assert cfg.policy.is_allowed("api.example.com", 443)
        assert cfg.policy.is_allowed("10.1.2.3", 5432)
        assert not cfg.policy.is_allowed("evil.test", 443)
        # What the guardian compares with its own copy, byte for byte.
        assert cfg._serialized_payload == payload
        # The snapshot pins this very config and its policy.
        assert (cfg, "__class__", _core._PIN_TYPE) in snapshot
        assert (cfg.policy, "__class__", _core._PIN_TYPE) in snapshot
        assert (vars(_core), "_join_locked", _core._PIN_ITEM) in snapshot
        assert _core._hook_installed is True
        assert [r.getMessage() for r in caplog.records if "joined" in r.getMessage()] == [
            "tethered: joined the locked policy of this process with 3 rules (log_only=False)"
        ]

    def test_the_policy_is_enforced(self, elsewhere):
        _core._join_locked(elsewhere.locked_payload())
        with pytest.raises(tethered.EgressBlocked, match="is not in the allow list"):
            sys.audit("socket.connect", None, ("203.0.113.9", 443))
        sys.audit("socket.connect", None, ("10.1.2.3", 5432))
        # No token exists here: the lock is not this interpreter's to give up.
        with pytest.raises(tethered.TetheredLocked):
            tethered.deactivate()
        with pytest.raises(tethered.TetheredLocked):
            tethered.activate(allow=["0.0.0.0/0"])
        assert _core._config.locked is True

    def test_nothing_is_published(self, elsewhere, monkeypatch):
        """The variable is the whole process's, and the owner has written it."""
        monkeypatch.setenv(_CHILD_POLICY_ENV, "left as it was")
        _core._join_locked(elsewhere.locked_payload())
        assert os.environ[_CHILD_POLICY_ENV] == "left as it was"
        monkeypatch.delenv(_CHILD_POLICY_ENV)
        _core._config = None
        _core._join_locked(elsewhere.locked_payload())
        assert _CHILD_POLICY_ENV not in os.environ

    def test_the_config_is_the_one_activate_would_build(self, monkeypatch):
        """Guards against drift: field for field, what the owner's ``activate()`` built."""
        token = object()
        tethered.activate(**_JOINED_POLICY, locked=True, lock_token=token)
        expected = _core._config
        tethered.deactivate(lock_token=token)

        monkeypatch.setattr(_core, "_c_guardian", _LockHeldElsewhere(expected._serialized_payload))
        _core._join_locked(expected._serialized_payload)
        actual = _core._config
        assert actual is not None
        assert actual is not expected
        for field in dataclasses.fields(_Config):
            if field.name != "policy":
                assert getattr(actual, field.name) == getattr(expected, field.name), field.name
        assert _serialize_allow_list(actual.policy) == _serialize_allow_list(expected.policy)
        assert actual.policy._allow_localhost == expected.policy._allow_localhost

    @pytest.mark.parametrize(
        "policy",
        [
            {"allow": []},
            {"allow": ["api.example.com:443", "*.example.org"], "log_only": True},
            {"allow": ["[2001:db8::]/32:443", "2001:db8::1", "192.0.2.0/24"]},
            {"allow": ["b.test", "a.test", "A.TEST:8443", "trailing.dot."]},
            {"allow": ["xn--bcher-kva.example", "*.sub.example.com:8080"], "fail_closed": True},
            {"allow": ["127.0.0.1:5000"], "allow_localhost": False},
            {"allow": ["*.example.com"], "external_subprocess_policy": "allow"},
        ],
        ids=["empty", "ports", "ipv6", "order-and-case", "idna", "no-localhost", "subprocess"],
    )
    def test_the_rebuilt_payload_is_the_guardians_to_the_byte(self, policy, monkeypatch):
        """Else the guardian would refuse every join of that policy."""
        payload = _locked_payload_of(**policy)
        stand_in = _LockHeldElsewhere(payload)
        monkeypatch.setattr(_core, "_c_guardian", stand_in)
        _core._join_locked(payload)
        assert _core._config._serialized_payload == payload
        assert _core._config.locked is True

    def test_a_join_the_guardian_refuses_binds_nothing(self, monkeypatch):
        payload = _locked_payload_of(**_JOINED_POLICY)
        stand_in = _LockHeldElsewhere(payload, refusal="tethered: cannot join the locked policy")
        monkeypatch.setattr(_core, "_c_guardian", stand_in)
        with pytest.raises(RuntimeError, match="cannot join the locked policy"):
            _core._join_locked(payload)
        assert len(stand_in.joins) == 1
        assert _core._config is None

    def test_it_needs_the_extension(self, monkeypatch):
        payload = _locked_payload_of(**_JOINED_POLICY)
        monkeypatch.setattr(_core, "_c_guardian", None)
        with pytest.raises(RuntimeError, match="requires the C guardian extension"):
            _core._join_locked(payload)
        assert _core._config is None

    @staticmethod
    def _altered(payload: str, **changes: object) -> str:
        parsed = json.loads(payload)
        for name, value in changes.items():
            if value is ...:
                del parsed["global"][name]
            else:
                parsed["global"][name] = value
        return json.dumps(parsed)

    @pytest.mark.parametrize(
        ("changes", "expected"),
        [
            ({"locked": False}, ValueError),
            ({"locked": 1}, TypeError),
            ({"log_only": 0}, TypeError),
            ({"fail_closed": "no"}, TypeError),
            ({"allow_localhost": None}, TypeError),
            ({"external_subprocess_policy": "sometimes"}, ValueError),
            ({"external_subprocess_policy": 5}, ValueError),
            ({"external_subprocess_policy": ["allow"]}, TypeError),
            ({"allow": "*.example.com"}, TypeError),
            ({"allow": ["*.example.com", 5]}, TypeError),
            ({"allow": ["://not-a-rule"]}, ValueError),
            ({"allow": ...}, KeyError),
            ({"locked": ...}, KeyError),
            ({"log_only": ...}, KeyError),
            ({"external_subprocess_policy": ...}, KeyError),
        ],
        ids=[
            "not-locked",
            "locked-not-bool",
            "log-only-not-bool",
            "fail-closed-not-bool",
            "allow-localhost-not-bool",
            "unknown-subprocess-policy",
            "subprocess-policy-not-str",
            "subprocess-policy-a-list",
            "allow-not-a-list",
            "allow-item-not-str",
            "bad-rule",
            "no-allow",
            "no-locked",
            "no-log-only",
            "no-subprocess-policy",
        ],
    )
    def test_a_payload_that_is_not_a_locked_policys_is_not_offered(
        self, changes, expected, elsewhere
    ):
        """Nothing is guessed or defaulted: the guardian is not even asked."""
        with pytest.raises(expected):
            _core._join_locked(self._altered(elsewhere.locked_payload(), **changes))
        assert elsewhere.joins == []
        assert _core._config is None

    @pytest.mark.parametrize(
        ("payload", "expected"),
        [
            ("{not json", ValueError),
            ("[]", TypeError),
            ("null", TypeError),
            ("{}", KeyError),
            ('{"global": null, "scopes": []}', TypeError),
            ('{"global": [], "scopes": []}', TypeError),
            ('{"global": "locked", "scopes": []}', TypeError),
        ],
        ids=["not-json", "a-list", "null", "no-global", "null-global", "list-global", "str-global"],
    )
    def test_a_payload_of_another_shape_is_not_offered(self, payload, expected, elsewhere):
        with pytest.raises(expected):
            _core._join_locked(payload)
        assert elsewhere.joins == []
        assert _core._config is None


_JOIN_WARNING = "tethered: this interpreter could not join the locked policy of its process"


@pytest.mark.skipif(_core._c_guardian is None, reason="C guardian extension not available")
class TestBootstrapUnderALock:
    """The bootstrap of an interpreter that starts while another one holds the lock.

    Run in the main interpreter against a stand-in for the guardian (see
    ``_LockHeldElsewhere``); ``test_subinterpreters.py`` runs the same paths
    for real, in interpreters coverage cannot see.
    """

    @pytest.fixture
    def locked_payload(self) -> str:
        return _locked_payload_of(**_JOINED_POLICY)

    @pytest.fixture
    def elsewhere(self, locked_payload, monkeypatch):
        stand_in = _LockHeldElsewhere(locked_payload)
        monkeypatch.setattr(_core, "_c_guardian", stand_in)
        return stand_in

    @staticmethod
    def _warnings(caplog) -> list[str]:
        return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]

    def test_it_joins_with_the_guardians_payload(self, elsewhere, locked_payload, monkeypatch):
        monkeypatch.setenv(_CHILD_POLICY_ENV, locked_payload)
        _autoactivate._autoactivate_from_env()
        assert len(elsewhere.joins) == 1
        assert _core._config.locked is True
        assert _core._config._serialized_payload == locked_payload
        assert _core._scopes.get() == ()

    @pytest.mark.parametrize(
        "variable",
        [
            _payload(allow=["0.0.0.0/0"], locked=False),
            _payload(allow=["0.0.0.0/0"], locked=True),
            json.dumps({"global": None, "scopes": []}),
            json.dumps({"scopes": []}),
        ],
        ids=["unlocked-and-permissive", "locked-and-permissive", "null-global", "no-global"],
    )
    def test_the_policy_is_not_the_variables_to_say(
        self, variable, elsewhere, locked_payload, monkeypatch, caplog
    ):
        """Whatever was done to the variable, what is joined is what is locked."""
        monkeypatch.setenv(_CHILD_POLICY_ENV, variable)
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _autoactivate._autoactivate_from_env()
        assert _core._config._serialized_payload == locked_payload
        assert _core._config.locked is True
        assert not _core._config.policy.is_allowed("evil.test", 443)
        assert os.environ[_CHILD_POLICY_ENV] == variable  # and it is left as it was
        assert self._warnings(caplog) == []

    @pytest.mark.parametrize("variable", ["{not json", "[]", "7"], ids=["not-json", "list", "int"])
    def test_a_variable_that_cannot_be_read_does_not_undo_the_join(
        self, variable, elsewhere, locked_payload, monkeypatch, caplog
    ):
        monkeypatch.setenv(_CHILD_POLICY_ENV, variable)
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _autoactivate._autoactivate_from_env()
        assert _core._config._serialized_payload == locked_payload
        (warning,) = self._warnings(caplog)
        assert "malformed _TETHERED_CHILD_POLICY" in warning

    def test_without_the_variable_nothing_is_joined(self, elsewhere, monkeypatch):
        """The bootstrap does nothing at all then — the guardian is not even asked."""
        monkeypatch.delenv(_CHILD_POLICY_ENV, raising=False)
        _autoactivate._autoactivate_from_env()
        assert elsewhere.joins == []
        assert _core._config is None

    def test_scopes_are_still_inherited_from_the_variable(
        self, elsewhere, locked_payload, monkeypatch
    ):
        variable = json.loads(locked_payload)
        variable["scopes"] = [{"allow": ["api.example.com"], "label": "inherited"}]
        monkeypatch.setenv(_CHILD_POLICY_ENV, json.dumps(variable))
        _autoactivate._autoactivate_from_env()
        assert _core._config.locked is True
        assert [s.label for s in _core._scopes.get()] == ["inherited"]

    @pytest.mark.parametrize(
        ("variable", "expected"),
        [
            # The variable says "unlocked": the policy that was joined is a
            # locked one all the same, and what cannot be established stops startup.
            ({"global": {"allow": [], "locked": False}, "scopes": [{"allow": [5]}]}, "scopes"),
            ({"global": {"allow": []}, "scopes": "none"}, "scopes must be a list"),
            ({"global": None, "scopes": [], "from_a_newer_version": 1}, "unknown field"),
        ],
        ids=["bad-scope", "scopes-not-a-list", "unknown-field"],
    )
    def test_having_joined_it_is_strict_about_the_rest(
        self, variable, expected, elsewhere, monkeypatch
    ):
        monkeypatch.setenv(_CHILD_POLICY_ENV, json.dumps(variable))
        with pytest.raises(SystemExit, match=expected):
            _autoactivate._autoactivate_from_env()
        assert _core._config.locked is True  # the join itself stands

    def test_a_policy_already_in_place_is_left_alone(self, monkeypatch, locked_payload):
        """A state copied by ``fork()``: nothing is joined over it."""

        class MustNotBeAsked(_LockHeldElsewhere):
            def locked_payload(self) -> str | None:
                raise AssertionError("the guardian was asked")

        tethered.activate(allow=["*.first.com"])
        first = _core._config
        monkeypatch.setattr(_core, "_c_guardian", MustNotBeAsked(locked_payload))
        monkeypatch.setenv(_CHILD_POLICY_ENV, locked_payload)
        assert _autoactivate._join_locked_policy() is False
        _autoactivate._autoactivate_from_env()
        assert _core._config is first

    def test_nothing_is_joined_where_nothing_is_locked(self, monkeypatch):
        """The real guardian, inactive: startup goes by the variable, as ever."""
        assert _core._c_guardian.locked_payload() is None
        assert _autoactivate._join_locked_policy() is False
        monkeypatch.setenv(_CHILD_POLICY_ENV, _payload(allow=["*.example.com"]))
        _autoactivate._autoactivate_from_env()
        assert _core._config.locked is False
        assert _core._config.policy.is_allowed("api.example.com", 443)

    def test_nothing_is_joined_without_the_extension(self, monkeypatch):
        monkeypatch.setattr(_core, "_c_guardian", None)
        assert _autoactivate._join_locked_policy() is False
        assert _core._config is None

    # ── A join that fails must not stop the interpreter from starting ──

    def test_a_refused_join_is_reported_and_startup_goes_on(
        self, locked_payload, monkeypatch, caplog
    ):
        refusal = "tethered: cannot join the locked policy: this interpreter's startup is over"
        stand_in = _LockHeldElsewhere(locked_payload, refusal=refusal)
        monkeypatch.setattr(_core, "_c_guardian", stand_in)
        with caplog.at_level(logging.WARNING, logger="tethered"):
            assert _autoactivate._join_locked_policy() is False
        assert len(stand_in.joins) == 1
        assert _core._config is None
        assert self._warnings(caplog) == [
            f"{_JOIN_WARNING} (RuntimeError: {refusal}) — while that lock is held it gets "
            "no network access and no process launches"
        ]

    def test_a_payload_that_cannot_be_joined_is_reported_too(self, monkeypatch, caplog):
        """Not only the guardian's refusal: anything the join raises."""
        stand_in = _LockHeldElsewhere(_payload(allow=["*.example.com"], locked=False))
        monkeypatch.setattr(_core, "_c_guardian", stand_in)
        with caplog.at_level(logging.WARNING, logger="tethered"):
            assert _autoactivate._join_locked_policy() is False
        assert stand_in.joins == []
        (warning,) = self._warnings(caplog)
        assert warning.startswith(f"{_JOIN_WARNING} (ValueError: ")

    def test_after_a_failed_join_a_locked_variable_is_enforced_unlocked(
        self, locked_payload, monkeypatch, caplog
    ):
        """In a subinterpreter, as when nothing is locked: the guardian refuses it meanwhile."""
        stand_in = _LockHeldElsewhere(locked_payload, refusal="no")
        monkeypatch.setattr(_core, "_c_guardian", stand_in)
        monkeypatch.setattr(_autoactivate, "_in_subinterpreter", lambda: True)
        monkeypatch.setenv(_CHILD_POLICY_ENV, locked_payload)
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _autoactivate._autoactivate_from_env()  # no SystemExit
        cfg = _core._config
        assert cfg is not None
        assert cfg.locked is False
        assert not cfg.policy.is_allowed("evil.test", 443)
        (warning,) = self._warnings(caplog)
        assert warning.startswith(_JOIN_WARNING)

    def test_after_a_failed_join_an_unlocked_variable_cannot_be_activated(
        self, locked_payload, monkeypatch, caplog
    ):
        """Another interpreter's lock is active: ``activate()`` refuses, startup goes on."""
        stand_in = _LockHeldElsewhere(locked_payload, refusal="no")
        monkeypatch.setattr(_core, "_c_guardian", stand_in)
        monkeypatch.setenv(_CHILD_POLICY_ENV, _payload(allow=["*.example.com"]))
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _autoactivate._autoactivate_from_env()  # no SystemExit
        assert _core._config is None
        first, second = self._warnings(caplog)
        assert first.startswith(_JOIN_WARNING)
        assert second.startswith("tethered: auto-activation failed: TetheredLocked")

    def test_a_guardian_that_cannot_be_asked_joins_nothing(
        self, locked_payload, monkeypatch, caplog
    ):
        class CannotBeAsked(_LockHeldElsewhere):
            def locked_payload(self) -> str | None:
                raise RuntimeError("no answer")

        stand_in = CannotBeAsked(locked_payload)
        monkeypatch.setattr(_core, "_c_guardian", stand_in)
        with caplog.at_level(logging.WARNING, logger="tethered"):
            assert _autoactivate._join_locked_policy() is False
        assert stand_in.joins == []
        assert self._warnings(caplog) == []

    def test_a_core_module_that_cannot_be_imported_is_reported_once(self, monkeypatch, caplog):
        """By the code that needs it next, in its own words — not as a failed join."""
        monkeypatch.setitem(sys.modules, "tethered._core", None)  # import raises ImportError
        monkeypatch.setenv(_CHILD_POLICY_ENV, _payload(allow=["*.example.com"]))
        with caplog.at_level(logging.WARNING, logger="tethered"):
            assert _autoactivate._join_locked_policy() is False
            _autoactivate._autoactivate_from_env()
        (warning,) = self._warnings(caplog)
        assert warning.startswith("tethered: auto-activation failed: ")
        assert _JOIN_WARNING not in warning


class TestBootstrapTakesItsTurn:
    """The bootstrap waits for an ``activate()`` / ``deactivate()`` under way elsewhere.

    The variable is written before a policy is committed, so an interpreter
    that starts in between would go by a state that never was.  It takes
    the activation claim like those calls do.  (Between real interpreters:
    ``test_subinterpreters.py``.)
    """

    @staticmethod
    def _bootstrap_in_a_thread():
        done = threading.Event()
        errors: list[BaseException] = []

        def run() -> None:
            try:
                _autoactivate._autoactivate_from_env()
            except BaseException as exc:  # handed to the test
                errors.append(exc)
            finally:
                done.set()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread, done, errors

    def test_it_waits_and_then_establishes_the_policy(self, monkeypatch):
        monkeypatch.setenv(_CHILD_POLICY_ENV, _payload(allow=["*.example.com"]))
        with _core._activation_claim:
            thread, done, errors = self._bootstrap_in_a_thread()
            assert not done.wait(0.3)
            assert _core._config is None
        assert done.wait(30)
        thread.join(30)
        assert errors == []
        assert _core._config.policy.is_allowed("api.example.com", 443)
        assert _core._activation_claim.held() == 0

    @pytest.mark.parametrize("meanwhile", ["replaced", "removed"])
    def test_after_the_wait_it_goes_by_what_the_process_holds(self, meanwhile, monkeypatch):
        """What it found when it started may be a policy that was never committed."""
        monkeypatch.setenv(_CHILD_POLICY_ENV, _payload(allow=["*.first.com"]))
        with _core._activation_claim:
            thread, done, errors = self._bootstrap_in_a_thread()
            assert not done.wait(0.3)
            if meanwhile == "replaced":
                monkeypatch.setenv(_CHILD_POLICY_ENV, _payload(allow=["*.second.com"]))
            else:
                monkeypatch.delenv(_CHILD_POLICY_ENV)
        assert done.wait(30)
        thread.join(30)
        assert errors == []
        if meanwhile == "replaced":
            assert _core._config.policy.is_allowed("api.second.com", 443)
            assert not _core._config.policy.is_allowed("api.first.com", 443)
        else:
            assert _core._config is None

    def test_where_it_cannot_wait_it_goes_by_what_it_found(self, monkeypatch):
        """On a thread that is inside another interpreter's transition, or at shutdown."""
        payload = _locked_payload_of(allow=["*.example.com"])

        class _NoWaiting:
            restored: int | None = None

            def held(self) -> int:
                return 0

            def __enter__(self) -> None:
                raise RuntimeError("tethered: this call cannot wait")

            def __exit__(self, *exc_info: object) -> None:
                raise AssertionError("never entered")

            def restore(self, held: int) -> None:
                self.restored = held

        claim = _NoWaiting()
        monkeypatch.setattr(_core, "_activation_claim", claim)
        monkeypatch.setattr(_autoactivate, "_in_subinterpreter", lambda: True)
        monkeypatch.setenv(_CHILD_POLICY_ENV, payload)
        _autoactivate._autoactivate_from_env()
        assert _core._config is not None
        assert _core._config.locked is False
        assert not _core._config.policy.is_allowed("evil.test", 443)
        assert claim.restored == 0

    def test_an_error_after_the_wait_is_not_taken_for_a_wait_that_failed(self, monkeypatch):
        calls = []

        def fails(raw: str) -> None:
            calls.append(raw)
            raise RuntimeError("boom")

        monkeypatch.setattr(_autoactivate, "_bootstrap", fails)
        monkeypatch.setenv(_CHILD_POLICY_ENV, _payload(allow=["*.example.com"]))
        with pytest.raises(RuntimeError, match="boom"):
            _autoactivate._autoactivate_from_env()
        assert len(calls) == 1
        assert _core._activation_claim.held() == 0
