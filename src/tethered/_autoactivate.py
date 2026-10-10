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

A subinterpreter runs this module too, with the environment of the process
it lives in.  A lock exists once per process: the C guardian holds it for
the interpreter that took it.  A subinterpreter that starts while a policy
is locked joins that lock — it gets a locked, pinned copy of the policy,
built from the guardian's own record of it and not from the variable (see
:func:`_join_locked_policy`).  One that cannot join starts all the same and
is refused the guarded operations by the guardian for as long as the lock
is held.  Where no lock is active, a subinterpreter that inherits a
``locked`` policy enforces the same policy unlocked instead of refusing to
start (see :func:`_establish_unlocked`).
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

    In a subinterpreter of a process in which a policy is locked, the
    global policy does not come from the variable at all: the interpreter
    joins the lock (:func:`_join_locked_policy`) and only ``scopes`` is read
    from the variable.  Where no lock is active, a ``locked`` global is
    established unlocked in a subinterpreter, since the lock exists once
    per process (:func:`_establish_unlocked`).  Every other strict failure
    terminates a subinterpreter's startup as well.
    """
    raw = os.environ.get("_TETHERED_CHILD_POLICY")
    if raw is None:
        return

    # Before the variable is read: what a locked process enforces is not
    # for the variable to say.
    joined = _join_locked_policy()

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
    # The policy that was joined is a locked one whatever the variable says.
    global_payload = payload.get("global")
    strict = joined or (
        isinstance(global_payload, dict)
        and not (
            global_payload.get("locked", False) is False
            and global_payload.get("fail_closed", False) is False
        )
    )
    try:
        _apply_inherited_policy(payload, strict, joined)
    except Exception as e:
        _fail("auto-activation failed", f"{type(e).__name__}: {e}", strict)


def _join_locked_policy() -> bool:
    """Join the policy that is locked in this process, if one is.  Return True if joined.

    The lock is taken by one interpreter and binds all of them.  An
    interpreter that starts while it is held — this one, if the guardian
    reports a locked payload — gets a locked copy of that policy, pinned by
    the guardian like the owner's, through :func:`tethered._core._join_locked`.
    The policy is the guardian's record of it: the variable is not
    consulted, so nothing that was done to it changes what is enforced
    here.

    A join that fails must not stop the interpreter from starting (up to
    Python 3.12 that would end the whole process): the failure is logged
    and startup continues.  The guardian then refuses this interpreter the
    guarded operations for as long as the lock is held.

    Nothing is joined when no policy is locked, when the C extension cannot
    be loaded here, or when a policy is already in place (a state copied by
    ``fork()``).
    """
    try:
        import tethered._core as _core

        guardian = _core._c_guardian
        payload = (
            None if guardian is None or _core._config is not None else guardian.locked_payload()
        )
    except Exception:
        # (_apply_inherited_policy() meets the same failure and reports it.)
        return False
    if payload is None:
        return False
    try:
        _core._join_locked(payload)
    except Exception as e:
        logger.warning(
            "tethered: this interpreter could not join the locked policy of its process "
            "(%s: %s) — while that lock is held it gets no network access and no "
            "process launches",
            type(e).__name__,
            e,
        )
        return False
    return True


def _apply_inherited_policy(payload: dict, strict: bool, joined: bool = False) -> None:
    """Validate and apply the inherited ``global`` and ``scopes``.

    ``joined`` — the interpreter has joined the locked policy of its
    process, which is its global policy; only ``scopes`` is applied.
    """
    # Late imports — keep the no-policy path cheap (just an env-var lookup)
    # and avoid pulling tethered._core in if the user didn't want tethered.
    import tethered
    import tethered._core as _core

    # Idempotent: fork-spawned children already have tethered active via
    # process-state copy.  Don't re-activate over an existing policy.
    if _core._config is not None and not joined:
        return

    if strict:
        for key in payload:
            if key not in ("global", "scopes"):
                _fail("malformed _TETHERED_CHILD_POLICY", f"unknown field {key!r}", strict)

    global_payload = None if joined else payload.get("global")
    if global_payload is not None:
        problem = _schema_problem(global_payload, _GLOBAL_FIELDS, "global", strict)
        if problem is None and "allow" not in global_payload:
            problem = "global is missing 'allow'"
        # Which interpreter this is matters for a locked policy only, so
        # nothing else pays for the question.
        locked = problem is None and bool(global_payload.get("locked"))
        unlocked_here = locked and _in_subinterpreter()
        if locked and not unlocked_here and _core._c_guardian is None:
            problem = (
                "the parent requested locked mode but the C guardian extension "
                "is not available in this child"
            )
        if problem is not None:
            _fail("auto-activation failed", problem, strict)
        elif unlocked_here:
            _establish_unlocked(global_payload)
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


def _in_subinterpreter() -> bool:
    """Return True if this is not the main interpreter of the process.

    Python offers no public way to ask before 3.14, so the private stdlib
    modules are used: ``_interpreters`` (3.13+) or ``_xxsubinterpreters``
    (3.10 to 3.12).  Their ``get_current()`` and ``get_main()`` return an
    interpreter ID, from 3.13 as an ``(id, whence)`` pair.  A build without
    either module, or any failure, counts as the main interpreter: a locked
    policy is then established or startup refused, as in any child process.
    """
    try:
        # (Imported by name: these modules have no type stubs for every
        # supported version.)
        try:
            interpreters = __import__("_interpreters")
        except ImportError:
            interpreters = __import__("_xxsubinterpreters")
        current, main = (
            int(found[0] if isinstance(found, tuple) else found)
            for found in (interpreters.get_current(), interpreters.get_main())
        )
    except Exception:
        return False
    return current != main


def _establish_unlocked(global_payload: dict) -> None:
    """Enforce an inherited ``locked`` policy in this subinterpreter, unlocked.

    A lock exists once per process.  While another interpreter holds it, the
    C guardian refuses this one every connection, lookup and process launch,
    whatever the allow list says, so the policy installed here decides
    nothing; it is what still enforces the allow list from Python if the
    lock is released, or was never taken, while this interpreter lives.
    Every field but ``locked`` is the inherited one.

    The config is bound directly, not through :func:`tethered.activate`.
    That call publishes the policy to ``_TETHERED_CHILD_POLICY``, which is
    one variable for the whole process: an unlocked payload written here
    would be what every later child process inherits (the guardian refuses
    that write from this interpreter).  And where the C extension can be
    loaded, ``activate()`` refuses to act at all while a policy is locked.

    ``global_payload`` has passed the strict schema check.  What
    ``activate()`` validates beyond types is validated here; an exception
    terminates startup like any other strict failure.
    """
    import tethered._core as _core
    from tethered._policy import AllowPolicy

    external = global_payload.get("external_subprocess_policy", "warn")
    if external not in _core._EXTERNAL_SUBPROCESS_POLICIES:
        msg = f"external_subprocess_policy: unknown value {external!r}"
        raise ValueError(msg)
    log_only = global_payload.get("log_only", False)
    fail_closed = global_payload.get("fail_closed", False)
    policy = AllowPolicy(
        global_payload["allow"], allow_localhost=global_payload.get("allow_localhost", True)
    )
    global_dict = _core._build_global_payload_dict(
        policy,
        log_only=log_only,
        fail_closed=fail_closed,
        external_subprocess_policy=external,
        locked=False,
    )
    cfg = _core._Config(
        policy=policy,
        log_only=log_only,
        fail_closed=fail_closed,
        locked=False,
        external_subprocess_policy=external,
        _serialized_payload=_core._build_env_payload(global_dict, ()),
        _global_payload_dict=global_dict,
        _pth_path=_core._compute_pth_path(),
        _local_hostname=_core._capture_local_hostname(),
    )
    with _core._lifecycle_lock:
        _core._install_hook()
        _core._config = cfg
    logger.info(
        "tethered: this subinterpreter inherited a locked policy and enforces it "
        "unlocked — a lock exists once per process; while another interpreter "
        "holds it, this one gets no network access and no process launches"
    )


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
