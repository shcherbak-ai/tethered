"""Auto-activation hook for tethered child processes.

Installed via the top-level ``tethered.pth`` file shipped in the package.
Every Python interpreter that has ``tethered`` in its site-packages runs
``import tethered._autoactivate`` on startup.  This module checks the
``_TETHERED_CHILD_POLICY`` environment variable populated by a parent
process's ``tethered.activate()`` call and, if present, activates tethered
in the child with the same policy.

Spawn-mode children (macOS / Windows multiprocessing, plain
``subprocess.run([sys.executable, ...])``) get the policy via this hook.
Fork-mode children inherit tethered state directly via the OS ``fork()``
copy and don't need this hook to run; the idempotency check below makes
the call a no-op for them.
"""

from __future__ import annotations

import json
import logging
import os

logger = logging.getLogger("tethered")


def _autoactivate_from_env() -> None:
    """Activate tethered from ``_TETHERED_CHILD_POLICY`` if present.

    Payload shape:

    .. code-block:: json

        {"global": {<global fields> | null}, "scopes": [{<scope fields>}, ...]}

    A non-null ``global`` calls :func:`tethered.activate` with the inherited
    fields.  Each entry in ``scopes`` is pushed onto the per-context scope
    stack (no ``__exit__`` ever fires — the inherited scope persists for the
    child's lifetime, mirroring the parent's at-the-launch-site policy).
    """
    raw = os.environ.get("_TETHERED_CHILD_POLICY")
    if raw is None:
        return

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.warning("tethered: malformed _TETHERED_CHILD_POLICY: %s", e)
        return

    if not isinstance(payload, dict):
        logger.warning("tethered: malformed _TETHERED_CHILD_POLICY: not a JSON object")
        return

    global_payload = payload.get("global")
    scopes_payload = payload.get("scopes") or []

    # Late imports — keep the no-policy path cheap (just an env-var lookup)
    # and avoid pulling tethered._core in if the user didn't want tethered.
    import tethered
    import tethered._core as _core

    # Idempotent: fork-spawned children already have tethered active via
    # process-state copy.  Don't re-activate over an existing policy.
    if _core._config is not None:
        return

    if isinstance(global_payload, dict):
        locked = bool(global_payload.get("locked", False))
        activate_kwargs: dict = {
            "allow": global_payload["allow"],
            "allow_localhost": global_payload.get("allow_localhost", True),
            "log_only": global_payload.get("log_only", False),
            "fail_closed": global_payload.get("fail_closed", False),
            "external_subprocess_policy": global_payload.get("external_subprocess_policy", "warn"),
        }

        if locked:
            # The parent's lock_token cannot survive serialization (identity
            # comparison).  Each child gets a fresh per-process token so
            # untrusted code in this child can't disable tethered.  The
            # parent has no special control over the child's lock — they're
            # separate processes.
            if _core._c_guardian is None:
                logger.warning(
                    "tethered: parent requested locked mode but the C guardian "
                    "extension is not available in this child; falling back to "
                    "non-locked enforcement"
                )
            else:
                activate_kwargs["locked"] = True
                activate_kwargs["lock_token"] = object()

        try:
            tethered.activate(**activate_kwargs)
        except Exception as e:  # pragma: no cover — defensive; activate() should not raise here
            logger.warning("tethered: auto-activation failed: %s", e)
            return

    # Push inherited scopes onto _scopes ContextVar.  No ``__exit__`` will
    # fire — the inherited scope persists for the child's lifetime.  Use
    # _ScopeConfig directly so the audit hook is installed via _install_hook
    # without going through the public scope() class (which warns on overlap
    # checks that aren't relevant in the child).
    if scopes_payload:
        _inherit_scopes(scopes_payload)


def _inherit_scopes(scopes_payload: list) -> None:
    """Push parent-serialized scopes onto the per-context scope stack."""
    import tethered._core as _core
    from tethered._policy import AllowPolicy

    inherited: list = []
    for s in scopes_payload:
        if not isinstance(s, dict):
            logger.warning("tethered: skipping malformed scope entry in inherited payload")
            continue
        try:
            policy = AllowPolicy(
                s.get("allow", []),
                allow_localhost=s.get("allow_localhost", True),
            )
        except (TypeError, ValueError) as e:
            logger.warning("tethered: failed to inherit scope: %s", e)
            continue
        inherited.append(
            _core._ScopeConfig(
                policy=policy,
                log_only=bool(s.get("log_only", False)),
                fail_closed=bool(s.get("fail_closed", False)),
                on_blocked=None,  # callbacks don't cross process boundaries
                label=s.get("label", "inherited-scope"),
            )
        )

    if not inherited:
        return

    _core._install_hook()
    current = _core._scopes.get()
    _core._scopes.set((*current, *inherited))


_autoactivate_from_env()
