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
