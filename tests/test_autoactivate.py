"""Tests for tethered._autoactivate and end-to-end subprocess auto-propagation."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys

import pytest

import tethered
import tethered._autoactivate as _autoactivate
import tethered._core as _core
from tethered._core import (
    _CHILD_POLICY_ENV,
    _build_child_policy_payload,
    _clear_policy_from_env,
    _Config,
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
        assert cfg.lock_token is not None
        # Required because cleanup needs the token to deactivate the C guardian
        _core._c_guardian.deactivate(_core._guardian_token_id)
        with _core._state_lock:
            _core._config = None

    def test_c_extension_fallback(self, monkeypatch, caplog):
        """If C extension is unavailable, locked=true falls back to non-locked + warning."""
        monkeypatch.setenv(_CHILD_POLICY_ENV, _payload(allow=["*.example.com"], locked=True))
        monkeypatch.setattr(_core, "_c_guardian", None)
        with caplog.at_level(logging.WARNING, logger="tethered"):
            _autoactivate._autoactivate_from_env()
        cfg = _core._config
        assert cfg is not None
        assert cfg.locked is False  # fell back
        assert any("C guardian extension is not available" in r.message for r in caplog.records)


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

    def test_env_strip_in_non_locked_mode_no_inheritance(self):
        """env={} in non-locked mode succeeds but the child has no policy."""
        tethered.activate(allow=["*.example.com"])
        # Stripping env loses the propagation var; child runs uncontrolled (documented gap).
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
        assert b"inactive" in result.stdout

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
