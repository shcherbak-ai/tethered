# Subprocess control

[← Back to README](../README.md)

- [Auto-propagation to Python child processes](#auto-propagation-to-python-child-processes)
- [Locked-mode propagation](#locked-mode-propagation)
- [Parent-side enforcement of "external" subprocess launches](#parent-side-enforcement-of-external-subprocess-launches)
- [Locked-mode hardening of the auto-propagation channel](#locked-mode-hardening-of-the-auto-propagation-channel)
- [Scopes propagate to subprocesses too](#scopes-propagate-to-subprocesses-too)
- [What's inherited and what isn't](#whats-inherited-and-what-isnt)

## Auto-propagation to Python child processes

Python children **automatically inherit** the parent's tethered policy. `tethered.activate()` populates `_TETHERED_CHILD_POLICY` in the environment; a small `tethered.pth` file shipped with the package runs `tethered._autoactivate` on every Python interpreter startup, re-engaging tethered with the same policy before user code runs. This works for `multiprocessing.Pool`, `ProcessPoolExecutor`, gunicorn/uvicorn workers, and plain `subprocess.run([sys.executable, ...])`:

```python
import tethered, subprocess, sys

tethered.activate(allow=["*.stripe.com:443"])

# Plain subprocess.run — child auto-activates tethered with the same policy.
subprocess.run(
    [sys.executable, "-c", "import urllib.request; urllib.request.urlopen('https://evil.test')"]
)
# Child raises EgressBlocked — evil.test is not in the allow list
```

On Linux, `os.fork()` already copies tethered's audit hook into child processes, so gunicorn workers were already covered. The `.pth` mechanism extends the same protection to **spawn-mode** children — macOS/Windows multiprocessing, `ProcessPoolExecutor` on those platforms, and any explicit `subprocess.run([sys.executable, ...])` everywhere.

## Locked-mode propagation

If the parent activated with `locked=True`, child processes also auto-activate in locked mode — each child gets a fresh per-process `lock_token`. The parent has no special control over the child's lock (correct: separate processes). If the C extension isn't available in the child's environment (rare), the child logs a warning and falls back to non-locked enforcement.

## Parent-side enforcement of "external" subprocess launches

The `.pth` mechanism only protects **Python** children that launch via `sys.executable` (the same interpreter, with tethered installed). Everything else falls outside auto-inherit's reach: non-Python tools (`curl`, `bash`, `ffmpeg`), different Python interpreters (`/usr/bin/python3` without tethered), or `sys.executable` launched with `-S` (which disables `site.py` and so the `.pth` bootstrap). `-I` and `-E` keep `site.py` enabled and so are NOT bypass flags — auto-inherit works under those. `external_subprocess_policy` controls parent-side enforcement on the launches the bootstrap can't reach:

| Policy | Behavior |
|---|---|
| `"warn"` (default) | Log a warning on every external subprocess launch. The supply-chain-visibility default — silent for normal apps, speaks up when a dep unexpectedly shells out. |
| `"allow"` | No parent-side enforcement on external launches. Set this if your workload legitimately shells out frequently (image-processing apps using `ffmpeg`, git wrappers, etc.) and the warnings are noise. |
| `"block"` | Refuse every external subprocess launch. |

What counts as "external" vs auto-inheriting:

| Launch | External? |
|---|---|
| `subprocess.run([sys.executable, "-c", ...])` | No (auto-inherits) |
| `subprocess.run([sys.executable, "script.py"])` | No (auto-inherits) |
| `subprocess.run([sys.executable, "-I", "-c", ...])` | No (auto-inherits — `-I` keeps `site.py` enabled) |
| `subprocess.run([sys.executable, "-E", "-c", ...])` | No (auto-inherits — `-E` only ignores `PYTHON*` env vars) |
| `multiprocessing.Pool` workers (uses `sys.executable`) | No (auto-inherits) |
| `subprocess.run([sys.executable, "-S", ...])` | Yes (`-S` disables `site.py`) |
| `subprocess.run(["/usr/bin/python3", ...])` | Yes (different interpreter) |
| `subprocess.run(["curl", ...])` | Yes (non-Python) |
| `os.system("rm -rf /")` | Yes (non-Python) |

```python
# Hard lockdown: no external subprocess launches at all.
# (Regular Python children still work — they auto-inherit.)
tethered.activate(
    allow=["*.stripe.com:443"],
    external_subprocess_policy="block",
)

import subprocess, sys

# OK — sys.executable, site.py runs, .pth fires → auto-inheriting
subprocess.run([sys.executable, "-c", "pass"])

# OK — -I and -E keep site.py enabled
subprocess.run([sys.executable, "-I", "-c", "pass"])
subprocess.run([sys.executable, "-E", "-c", "pass"])

# Blocked — non-Python launch
import os
os.system("curl evil.test")  # raises SubprocessBlocked

# Blocked — -S disables site.py, so the .pth bootstrap can't run
subprocess.run([sys.executable, "-S", "-c", "pass"])  # raises SubprocessBlocked
```

## Locked-mode hardening of the auto-propagation channel

In **locked mode**, tethered adds three Python-level tamper checks to defend the auto-propagation channel against a dependency that knows tethered is installed:

- **Payload-integrity check at every subprocess launch.** The child's policy must equal the parent's canonical payload. This catches:
  - explicit `env={}` that strips `_TETHERED_CHILD_POLICY`;
  - explicit `env={..., "_TETHERED_CHILD_POLICY": "<permissive value>"}` substitution;
  - inherited env (`env=None`) where `os.environ` has been mutated to strip or substitute the var (via `os.environ.pop`, `os.environ[...] = ...`, or a direct `ctypes` call to libc `setenv`/`unsetenv` — the check inspects `os.environ` at launch time regardless of how it was set).
- **`tethered.pth` filesystem-tamper check.** Refuses Python-level deletion (`os.remove` audit event — fired by `os.remove`, `os.unlink`, `pathlib.Path.unlink`, `shutil.rmtree`), rename touching the path (`os.rename` — also `os.replace`), write-mode `open` of the cached path (also covers `shutil.copy`, `pathlib.Path.write_*`), and `os.chmod` of the path (catches a permission-strip attack that would make site.py silently skip the file). Note: `os.truncate` is unfixable — CPython doesn't fire an audit event for it.

All three are no-ops outside locked mode (the user opted into the strict mode for hardening). And all three have the same `ctypes`-bypass caveat called out in [SECURITY.md](../SECURITY.md): a deliberately-malicious dep with `ctypes` access can call libc `unlink`, `setenv`, and `connect` directly, bypassing every audit-event-based defense tethered ships.

## Scopes propagate to subprocesses too

`tethered.scope()` propagates to children launched via `subprocess.Popen` (and APIs built on it like `subprocess.run` and `asyncio.create_subprocess_exec`): the child inherits both the parent's global policy AND the active scope chain, observing the parent's *effective* policy at the launch site (global ∩ scopes), not just the at-rest global. Some lower-level launch paths bypass `subprocess.Popen` and propagate the global only — see Limitations below.

```python
import tethered, subprocess, sys

tethered.activate(allow=["*.allowed.com"])

with tethered.scope(allow=["api.allowed.com"]):
    # Child inherits global *.allowed.com AND scope api.allowed.com.
    # Connections to other.allowed.com (allowed by global, blocked by scope)
    # are blocked in the child too.
    subprocess.run([sys.executable, "-c", "..."])
```

This works **without** `activate()` — a library can use `scope()` alone for self-defense and the narrowing extends through subprocess boundaries:

```python
# Inside a library, no app-level activate() needed:
@tethered.scope(allow=["api.mylib.com"])
def do_work():
    subprocess.run([sys.executable, "-m", "mylib_helper"])
    # The helper subprocess only reaches api.mylib.com.
```

Race-free across threads (frame-locals are per-call, not shared global state): two threads can be in different scopes and concurrently launch subprocesses that each receive their parent thread's scope.

**How it works.** When `subprocess.Popen._execute_child` fires the `subprocess.Popen` audit event, tethered walks the call stack to the `_execute_child` frame and rewrites its `env` local to a per-call dict containing the scope-aware `_TETHERED_CHILD_POLICY` payload. The child reads this on startup. PEP 667 makes this a write-through proxy on Python 3.13+; on 3.10–3.12 tethered uses `ctypes.pythonapi.PyFrame_LocalsToFast` to push the fast-locals slot.

**Limitations.**

- Scope cannot propagate through `os.system`, `os.exec*`, or `os.startfile` — those launch paths have no env channel that tethered can intercept. Those launches still receive the parent's at-rest global only and remain subject to `external_subprocess_policy`.
- **Scope cannot propagate through `multiprocessing.Pool` / `ProcessPoolExecutor` in spawn mode.** These launch paths call `_posixsubprocess.fork_exec` (POSIX) or `_winapi.CreateProcess` (Windows) directly, bypassing `subprocess.Popen` entirely. The `subprocess.Popen` audit event never fires, so frame mutation has nothing to hook. Workers see only the parent's GLOBAL policy (which propagates via inherited `os.environ`). For scope propagation to multiprocessing workers, use **fork mode** (`mp.get_context("fork").Pool(...)`, Linux only) — fork copies the entire process state including the `_scopes` ContextVar, so children inherit scopes via OS-level state copy. Or restructure to launch workers via `subprocess.run([sys.executable, ...])` directly. `asyncio.create_subprocess_exec` IS supported because it uses `subprocess.Popen` internally.
- Forked children inherit scope at fork time and persist it for their lifetime — they are independent processes, so the parent's `with` exit doesn't reach them.
- In locked mode, the child's canonical `global` field is byte-checked; the scopes part is not byte-checked because scopes can only narrow within the byte-checked global ceiling.

## What's inherited and what isn't

The child re-activates with: `allow`, `allow_localhost`, `log_only`, `fail_closed`, `external_subprocess_policy`, `locked` (with a fresh per-process token), and the active scope chain (each scope's `allow`, `allow_localhost`, `log_only`, `fail_closed`, `label`).

Not inherited: `on_blocked` (callbacks can't cross process boundaries), the parent's exact `lock_token` (identity-compared; can't survive serialization).

> **Important:** This is defense-in-depth for **Python child processes**, not a system sandbox. Non-Python executables can be monitored/blocked at the parent (`external_subprocess_policy`), but tethered cannot enforce egress rules *inside* them. For hard subprocess isolation, combine with OS-level controls (seccomp, containers).
