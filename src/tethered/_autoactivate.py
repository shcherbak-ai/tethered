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

A payload whose ``global`` asks for ``locked`` or ``fail_closed`` must not
fail open: if it cannot be established here, interpreter startup is
terminated with ``SystemExit`` (``site.py`` swallows ordinary exceptions
raised by a ``.pth`` line, so anything else would let the workload run
unprotected).
"""

from __future__ import annotations

import json
import logging
import os

logger = logging.getLogger("tethered")

# Payload schema: field -> exact JSON type.  ``object`` marks fields that
# never affect enforcement (message text only) and are coerced instead.
_GLOBAL_FIELDS: dict[str, type] = {
    "allow": list,
    "allow_localhost": bool,
    "log_only": bool,
    "fail_closed": bool,
    "external_subprocess_policy": str,
    "locked": bool,
}
_SCOPE_FIELDS: dict[str, type] = {
    "allow": list,
    "allow_localhost": bool,
    "log_only": bool,
    "fail_closed": bool,
    "label": object,
    "hint": object,
}


def _schema_problem(obj: object, fields: dict[str, type], what: str, strict: bool) -> str | None:
    """Return a description of the first schema violation in ``obj``, or ``None``.

    Types are compared exactly — JSON ``0`` is not ``false`` — and ``allow``
    must be a list of ``str``.  Fields this version does not know are a
    violation only when ``strict``; otherwise they are ignored.
    """
    if not isinstance(obj, dict):
        return f"{what} must be an object, got {type(obj).__name__}"
    for key, value in obj.items():
        expected = fields.get(key)
        if expected is None:
            if strict:
                return f"{what} has unknown field {key!r}"
        elif expected is not object and type(value) is not expected:
            got = type(value).__name__
            return f"{what}.{key} must be {expected.__name__}, got {got}: {value!r}"
    for i, item in enumerate(obj.get("allow", ())):
        if type(item) is not str:
            return f"{what}.allow[{i}] must be str, got {type(item).__name__}: {item!r}"
    return None


def _fail(what: str, detail: object, strict: bool) -> None:
    """Report a part of the inherited policy that could not be established.

    ``strict`` — the inherited global asks for ``locked`` or ``fail_closed``
    — terminates interpreter startup; otherwise the problem is logged and
    the child continues (the library's fail-open default).
    """
    if strict:
        msg = (
            "tethered: refusing to start — the inherited policy asks for locked or "
            f"fail_closed enforcement and could not be established ({what}: {detail}). "
            "Fix or unset _TETHERED_CHILD_POLICY."
        )
        raise SystemExit(msg)
    logger.warning("tethered: %s: %s", what, detail)


def _autoactivate_from_env() -> None:
    """Activate tethered from ``_TETHERED_CHILD_POLICY`` if present.

    Payload shape:

    .. code-block:: json

        {"global": {<global fields> | null}, "scopes": [{<scope fields>}, ...]}

    A non-null ``global`` calls :func:`tethered.activate` with the inherited
    fields.  Each entry in ``scopes`` is pushed onto the per-context scope
    stack (no ``__exit__`` ever fires — the inherited scope persists for the
    child's lifetime, mirroring the parent's at-the-launch-site policy).

    The payload is validated before use.  When the ``global`` asks for
    ``locked`` or ``fail_closed`` and any part of the policy cannot be
    established — a schema violation, an unknown field, ``activate()``
    raising, locked mode without the C guardian — ``SystemExit`` is raised.
    Otherwise the problem is logged and the child continues without that
    part.  A value that is not a JSON object at all cannot ask for anything
    and is logged and ignored.
    """
    raw = os.environ.get("_TETHERED_CHILD_POLICY")
    if raw is None:
        return

    try:
        payload = json.loads(raw)
    except (ValueError, RecursionError) as e:
        logger.warning("tethered: malformed _TETHERED_CHILD_POLICY: %s", e)
        return

    if not isinstance(payload, dict):
        logger.warning("tethered: malformed _TETHERED_CHILD_POLICY: not a JSON object")
        return

    # Read leniently: anything but an explicit ``false`` counts as asking, so
    # a mistyped flag (``"locked": 1``) cannot downgrade the failure mode.
    global_payload = payload.get("global")
    strict = isinstance(global_payload, dict) and not (
        global_payload.get("locked", False) is False
        and global_payload.get("fail_closed", False) is False
    )
    try:
        _apply_inherited_policy(payload, strict)
    except Exception as e:
        _fail("auto-activation failed", f"{type(e).__name__}: {e}", strict)


def _apply_inherited_policy(payload: dict, strict: bool) -> None:
    """Validate and apply the inherited ``global`` and ``scopes``."""
    # Late imports — keep the no-policy path cheap (just an env-var lookup)
    # and avoid pulling tethered._core in if the user didn't want tethered.
    import tethered
    import tethered._core as _core

    # Idempotent: fork-spawned children already have tethered active via
    # process-state copy.  Don't re-activate over an existing policy.
    if _core._config is not None:
        return

    if strict:
        for key in payload:
            if key not in ("global", "scopes"):
                _fail("malformed _TETHERED_CHILD_POLICY", f"unknown field {key!r}", strict)

    global_payload = payload.get("global")
    if global_payload is not None:
        problem = _schema_problem(global_payload, _GLOBAL_FIELDS, "global", strict)
        if problem is None and "allow" not in global_payload:
            problem = "global is missing 'allow'"
        if problem is None and global_payload.get("locked") and _core._c_guardian is None:
            problem = (
                "the parent requested locked mode but the C guardian extension "
                "is not available in this child"
            )
        if problem is not None:
            _fail("auto-activation failed", problem, strict)
        else:
            activate_kwargs = {k: global_payload[k] for k in _GLOBAL_FIELDS if k in global_payload}
            if activate_kwargs.get("locked"):
                # The parent's lock_token cannot survive serialization
                # (identity comparison).  Each child gets a fresh per-process
                # token so untrusted code in this child can't disable
                # tethered.  The parent has no special control over the
                # child's lock — they're separate processes.
                activate_kwargs["lock_token"] = object()
            tethered.activate(**activate_kwargs)

    # Push inherited scopes onto _scopes ContextVar.  No ``__exit__`` will
    # fire — the inherited scope persists for the child's lifetime.  Use
    # _ScopeConfig directly so the audit hook is installed via _install_hook
    # without going through the public scope() class (which warns on overlap
    # checks that aren't relevant in the child).
    scopes_payload = payload.get("scopes", [])
    if type(scopes_payload) is not list:
        _fail(
            "skipping malformed scopes in inherited payload",
            f"scopes must be a list, got {type(scopes_payload).__name__}",
            strict,
        )
    elif scopes_payload:
        _inherit_scopes(scopes_payload, strict=strict)


def _inherit_scopes(scopes_payload: list, *, strict: bool = False) -> None:
    """Push parent-serialized scopes onto the per-context scope stack.

    A malformed entry is skipped with a warning; when ``strict`` it
    terminates interpreter startup instead (see :func:`_fail`).
    """
    import tethered._core as _core
    from tethered._policy import AllowPolicy

    inherited: list = []
    for i, s in enumerate(scopes_payload):
        problem = _schema_problem(s, _SCOPE_FIELDS, f"scopes[{i}]", strict)
        if problem is not None:
            _fail("skipping malformed scope entry in inherited payload", problem, strict)
            continue
        try:
            policy = AllowPolicy(
                s.get("allow", []),
                allow_localhost=s.get("allow_localhost", True),
            )
        except (TypeError, ValueError) as e:
            _fail("failed to inherit scope", e, strict)
            continue
        raw_label = s.get("label", "inherited-scope")
        raw_hint = s.get("hint", "")
        inherited.append(
            _core._ScopeConfig(
                policy=policy,
                log_only=s.get("log_only", False),
                fail_closed=s.get("fail_closed", False),
                on_blocked=None,  # callbacks don't cross process boundaries
                label=raw_label if isinstance(raw_label, str) else "inherited-scope",
                hint=raw_hint if isinstance(raw_hint, str) else "",
            )
        )

    if not inherited:
        return

    _core._install_hook()
    current = _core._scopes.get()
    _core._scopes.set((*current, *inherited))
    # Count them as active scopes: lookups made on this context's behalf in
    # other threads (asyncio's executor) are then still recorded.
    _core._adjust_scope_count(len(inherited))


_autoactivate_from_env()
