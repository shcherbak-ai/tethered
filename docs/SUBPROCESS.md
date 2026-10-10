# Subprocess control

[← Back to README](../README.md)

- [Auto-propagation to Python child processes](#auto-propagation-to-python-child-processes)
- [Locked-mode propagation](#locked-mode-propagation)
- [Parent-side enforcement of "external" subprocess launches](#parent-side-enforcement-of-external-subprocess-launches)
- [Locked-mode hardening of the auto-propagation channel](#locked-mode-hardening-of-the-auto-propagation-channel)
- [Scopes propagate to subprocesses too](#scopes-propagate-to-subprocesses-too)
- [What's inherited and what isn't](#whats-inherited-and-what-isnt)

## Auto-propagation to Python child processes

Python children **automatically inherit** the parent's tethered policy. `tethered.activate()` populates `_TETHERED_CHILD_POLICY` in the environment; a small `tethered.pth` file shipped with the package runs `tethered._autoactivate` on Python interpreter startup, re-engaging tethered with the same policy before user code runs. This works for `multiprocessing.Pool`, `ProcessPoolExecutor`, gunicorn/uvicorn workers, and plain `subprocess.run([sys.executable, ...])`:

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

**The bootstrap has to be installed where Python runs it.** `site.py` executes `tethered.pth` only from a site directory: the interpreter's site-packages, or the per-user site-packages when enabled. `pip install tethered` and `uv add tethered` put it there. An editable install (`pip install -e .`) and `pip install --target` + `PYTHONPATH` do not. In that case `activate()` logs a warning, no Python child auto-inherits, and every `sys.executable` launch is treated as external (see [below](#parent-side-enforcement-of-external-subprocess-launches)).

**The payload is established at launch, not only at `activate()`.** The subprocess hook makes sure each Python child's launch environment carries the payload. When `subprocess` is given an explicit `env=` (a mapping of any type) that lacks it, the child receives a copy with the payload added; the caller's mapping is not modified. When the child inherits the environment and the variable has been removed from `os.environ` (for example by a keep-list cleanup at startup), it is written back before the launch. In locked mode a missing or altered payload is refused instead (see [hardening](#locked-mode-hardening-of-the-auto-propagation-channel)). One route is out of reach: `multiprocessing` spawn / forkserver launches on POSIX with Python 3.10–3.13 raise no audit event, so nothing is checked or repaired for them.

A blocked call in a pool worker reaches the parent as `EgressBlocked`: the exception is picklable with all its attributes, so `multiprocessing.Pool` and `ProcessPoolExecutor` re-raise it in the parent.

## Locked-mode propagation

If the parent activated with `locked=True`, child processes also auto-activate in locked mode — each child gets a fresh per-process `lock_token`. The parent has no special control over the child's lock (correct: separate processes).

When the inherited policy has `locked` or `fail_closed` set and cannot be established in the child, the child refuses to start: the bootstrap raises `SystemExit`, interpreter startup fails, and the process exits with status 1 before any user code runs. This covers a payload that fails validation (a field of the wrong type, an unknown field), `activate()` raising, a malformed inherited scope, and locked mode when the C extension is not available in the child. With neither flag set, the problem is logged as a warning and the child continues without the part that failed; unknown payload fields are ignored. A value that is not a JSON object carries no flags: it is logged and ignored, and the child starts without a policy.

The same bootstrap runs when a new interpreter is created inside a process (a subinterpreter, a `concurrent.futures.InterpreterPoolExecutor` worker) whose environment carries the payload. An unlocked policy is established there as in a child process: the interpreter gets its own instance. A lock is different, because it exists once per process and a new interpreter cannot take one of its own:

- **The process holds a lock: the interpreter joins it.** It gets a locked copy of the policy, taken from the C guardian's own record of the locked policy and not from the variable, and from then on it is checked like the interpreter that holds the lock. It reaches what the policy allows, cannot deactivate or replace the policy, and cannot change the policy variable. Inherited scopes are still read from the variable. A child process it launches inherits the locked policy like any other.
- **It cannot join: it starts anyway, outside the lock.** One warning is logged. While the lock is held, the C guardian refuses that interpreter every connection, lookup and process launch, and any change to the bootstrap files or the policy variable; under a locked `log_only` policy its connections and lookups pass. An interpreter in which the bootstrap did not run at all, and one that already existed when the lock was taken, are refused in the same way: a join is accepted only while an interpreter starts.
- **The process holds no lock.** An inherited `locked` policy is established there unlocked (logged at INFO).

The other strict failures (an invalid payload, a fail-closed policy that cannot be established, an audit hook that refuses tethered's) still stop the new interpreter's startup; on Python 3.12 and earlier an interpreter that fails to start takes the process down with it. See [SECURITY.md](../SECURITY.md#locked-mode--what-it-does-and-does-not-do) for when a join is accepted and for what it does and does not cover.

Two limits of older Python versions matter when a process uses subinterpreters. On Python 3.12 and earlier, a process that exits while subinterpreters are still alive under a locked policy aborts at exit with `Fatal Python error: PyInterpreterState_Delete: remaining subinterpreters` (0.5.3 behaved the same): destroy them before the process exits. On Python 3.12, destroying an interpreter from a thread other than the one that created it hangs once that interpreter has imported `logging`, which importing tethered does: destroy each interpreter from the thread that created it. Neither happens from Python 3.13 on.

## Parent-side enforcement of "external" subprocess launches

The `.pth` mechanism only protects **Python** children that launch via `sys.executable` (the same interpreter, with tethered installed). Everything else falls outside auto-inherit's reach: non-Python tools (`curl`, `bash`, `ffmpeg`), different Python interpreters (`/usr/bin/python3` without tethered), or `sys.executable` launched with `-S` (which disables `site.py` and so the `.pth` bootstrap). `-I` and `-E` keep `site.py` enabled and so are NOT bypass flags — auto-inherit works under those, unless tethered is installed in the per-user site-packages (`pip install --user`), which `-s` and `-I` skip. `external_subprocess_policy` controls parent-side enforcement on the launches the bootstrap can't reach:

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
| `subprocess.run([sys.executable, "script.py", "-S"])` | No (auto-inherits — `-S` after the script path is the script's argument) |
| `subprocess.run([sys.executable, "-I", "-c", ...])` | No (auto-inherits — `-I` keeps `site.py` enabled); Yes if tethered is in the per-user site-packages |
| `subprocess.run([sys.executable, "-E", "-c", ...])` | No (auto-inherits — `-E` only ignores `PYTHON*` env vars) |
| `multiprocessing.Pool` workers (uses `sys.executable`) | No (auto-inherits) |
| `subprocess.run([sys.executable, "-S", ...])` | Yes (`-S` disables `site.py`) |
| `subprocess.run([sys.executable, "-X", "-c", "-S", "-c", ...])` | Yes (`-c` is the value of `-X` here, so `-S` is an interpreter option) |
| `sys.executable` with an option the interpreter does not know | Yes (the options cannot be parsed) |
| `subprocess.run(["python", ...], executable=sys.executable)` | POSIX: Yes (`argv[0]` is not `sys.executable`). Windows: No |
| Any Python launch when no `tethered.pth` is in a processed site directory | Yes (the child would not auto-activate) |
| `os.execve` / `os.spawnve` / `os.posix_spawn` of `sys.executable` with an explicit env that lacks the payload | Yes (that environment cannot be rewritten) |
| A `subprocess` launch of `sys.executable` whose environment cannot be given the payload (unreadable `env=`, launch frame not found or not writable) | Yes (locked mode refuses it) |
| `multiprocessing` workers after `multiprocessing.set_executable(<other interpreter>)` | Yes (different interpreter) |
| `subprocess.run(["/usr/bin/python3", ...])` | Yes (different interpreter) |
| `subprocess.run(["curl", ...])` | Yes (non-Python) |
| `os.system("rm -rf /")` | Yes (non-Python) |
| Direct `_winapi.CreateProcess` of a non-Python program (Windows) | Yes (non-Python) |

Interpreter options are read with the boundaries CPython itself uses, so `-S` counts only where the interpreter would treat it as an option. On Windows it is recognized when quoted inside a command-line string and when `executable=` is given. `multiprocessing` launches are classified on Windows and, from Python 3.14, on POSIX; on POSIX with Python 3.10–3.13 they raise no audit event.

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

# OK — "-S" after the script path belongs to the script, not the interpreter
subprocess.run([sys.executable, "script.py", "-S"])

# Blocked — non-Python launch
import os
os.system("curl evil.test")  # raises SubprocessBlocked

# Blocked — -S disables site.py, so the .pth bootstrap can't run
subprocess.run([sys.executable, "-S", "-c", "pass"])  # raises SubprocessBlocked
```

## Locked-mode hardening of the auto-propagation channel

In **locked mode**, tethered adds three Python-level tamper checks to defend the auto-propagation channel against a dependency that knows tethered is installed. Before any of them runs, the C guardian verifies its integrity snapshot on the same events — process launches, filesystem events whose path mentions `tethered.pth` or `tethered.start`, and `os.putenv` / `os.unsetenv` of the policy variable — and refuses the operation with `SubprocessBlocked` on a mismatch, so a check that has been replaced does not get to decide.

- **Payload-integrity check at every process launch tethered sees.** The child's policy must equal the parent's canonical payload; the comparison is type-exact, on canonical JSON text (`0` is not `false`). The canonical form is deterministic — the `allow` list is sorted — so every process holding the same policy serializes the identical payload regardless of per-process hash randomization, and env snapshots captured in one process (e.g. by a honcho-style process manager) stay valid when a spawn-mode child launches with them. The check covers `subprocess`, `os.system`, `os.exec*`, `os.spawn*`, `os.posix_spawn` and `os.startfile`, and `multiprocessing` / `ProcessPoolExecutor` launches on Windows and, from Python 3.14, on POSIX. `multiprocessing` spawn / forkserver launches on POSIX with Python 3.10–3.13 raise no audit event and are not checked. This catches:
  - an explicit environment that strips `_TETHERED_CHILD_POLICY` — `env={}` or a mapping of any other type;
  - explicit `env={..., "_TETHERED_CHILD_POLICY": "<permissive value>"}` substitution, and a value that is not valid JSON;
  - more than one spelling of the key in one environment (Windows environment names are case-insensitive, so `_tethered_child_policy` is the same variable there; on POSIX the `str` and `bytes` spellings of the name);
  - inherited env (`env=None`) where the variable has been stripped or substituted through `os.environ` (`os.environ.pop`, `os.environ[...] = ...`) or through `os.putenv()` / `os.unsetenv()`, which `os.environ` does not show and tethered tracks through their audit events;
  - inherited env where the variable was changed out of this interpreter's sight: from another interpreter of the process (each one has its own `os.environ`, a copy made when it starts, and sees only its own audit events) or below Python (`ctypes` calling libc `setenv` / `unsetenv`, which raises no audit event). The launch reads the variable from the environment of the process itself and is refused when that does not carry the locked policy. This is a check made at the launches tethered sees; it does not stop native code from changing the variable after the check or from starting a process itself.
- **`tethered.pth` filesystem-tamper check.** Refuses Python-level deletion (`os.remove` audit event — fired by `os.remove`, `os.unlink`, `pathlib.Path.unlink`, `shutil.rmtree`), rename touching the path (`os.rename` — also `os.replace`), write-mode `open` of the cached path (also covers `shutil.copy`, `pathlib.Path.write_*`), `os.chmod` of the path (catches a permission-strip attack that would make site.py silently skip the file), `os.truncate` of the path, and a `_winapi.CopyFile2` onto the path (how `shutil.copy2` writes its destination on Windows from Python 3.12, with no `open` event). `os.ftruncate` carries a file descriptor, which cannot be matched against the path, but a writable descriptor for the file cannot be obtained through `open` / `os.open` while the policy is locked. Paths are compared lexically, so a different path to the same file is not matched.
- **`tethered.start` creation check.** From Python 3.15, `site.py` ignores the `import` line of `tethered.pth` when a file named `tethered.start` sits beside it, even an empty one ([PEP 829](https://peps.python.org/pep-0829/)); Python children then start without the policy, and a child that should have refused to start does not. tethered ships no such file, so creating one is refused: a write-mode `open` of that path (also `pathlib.Path.touch` / `write_*`, `shutil.copy`), a rename or `shutil.copy2` onto it, `os.link` and `os.symlink`. Removing such a file is not refused. `os.mknod` (POSIX) raises no audit event and is **not** caught, and a `tethered.start` that is already there when the policy is locked is not detected.

These checks apply only in locked mode. Outside it, a launch environment that lacks the payload is not refused: tethered re-establishes the payload or treats the launch as external, as described above. And all of them have the same `ctypes`-bypass caveat called out in [SECURITY.md](../SECURITY.md): a deliberately-malicious dep with `ctypes` access can call libc `unlink`, `setenv`, and `connect` directly, bypassing every audit-event-based defense tethered ships. SECURITY.md also lists what in-process Python code can still do against locked mode [without `ctypes`](../SECURITY.md#locked-mode--what-it-does-and-does-not-do).

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

**How it works.** When `subprocess.Popen._execute_child` fires the `subprocess.Popen` audit event, tethered walks the call stack to the `_execute_child` frame and rewrites its `env` local to a per-call dict containing the scope-aware `_TETHERED_CHILD_POLICY` payload. The child reads this on startup. PEP 667 makes this a write-through proxy on Python 3.13+; on 3.10–3.12 tethered uses `ctypes.pythonapi.PyFrame_LocalsToFast` to push the fast-locals slot. The rewrite is not specific to scopes: it happens whenever the launch environment does not already carry exactly the right payload, for example an explicit `env=` without it. The per-call dict is a copy of the caller's mapping, whatever its type, with every spelling of the key replaced by the one canonical entry.

**Limitations.**

- Scope cannot propagate through `os.system`, `os.exec*`, or `os.startfile` — those launch paths have no env channel that tethered can intercept. Those launches still receive the parent's at-rest global only and remain subject to `external_subprocess_policy`. For the same reason an `os.exec*` / `os.spawn*` / `os.posix_spawn` launch of `sys.executable` with an explicit env that lacks the payload is treated as external.
- **Scope cannot propagate through `multiprocessing.Pool` / `ProcessPoolExecutor` in spawn mode.** These launch paths call `_posixsubprocess.fork_exec` (POSIX) or `_winapi.CreateProcess` (Windows) directly, bypassing `subprocess.Popen` entirely. The `subprocess.Popen` audit event never fires, so the `_execute_child` frame mutation has nothing to hook. tethered does handle `_winapi.CreateProcess` and, from Python 3.14, `_posixsubprocess.fork_exec` for the payload check, payload repair and `external_subprocess_policy`, but the scope chain does not travel. Workers see only the parent's GLOBAL policy (which propagates via inherited `os.environ`). For scope propagation to multiprocessing workers, use **fork mode** (`mp.get_context("fork").Pool(...)`, Linux only) — fork copies the entire process state including the `_scopes` ContextVar, so children inherit scopes via OS-level state copy. Or restructure to launch workers via `subprocess.run([sys.executable, ...])` directly. `asyncio.create_subprocess_exec` IS supported because it uses `subprocess.Popen` internally.
- Forked children inherit scope at fork time and persist it for their lifetime — they are independent processes, so the parent's `with` exit doesn't reach them.
- In locked mode, the child's canonical `global` field is compared type-exactly as canonical JSON; the scopes part is not compared because scopes can only narrow within the checked global ceiling.

## What's inherited and what isn't

The child re-activates with: `allow`, `allow_localhost`, `log_only`, `fail_closed`, `external_subprocess_policy`, `locked` (with a fresh per-process token), and the active scope chain (each scope's `allow`, `allow_localhost`, `log_only`, `fail_closed`, `label`, `hint`).

Not inherited: `on_blocked` (callbacks can't cross process boundaries), the parent's exact `lock_token` (identity-compared; can't survive serialization).

A new interpreter inside the same process is not a child process. Under a lock it gets no token of its own: it joins the lock of its process (see [Locked-mode propagation](#locked-mode-propagation)). `on_blocked` does not cross interpreters either.

Inherited scopes are pushed onto the scope stack of the context the child starts in (its main thread) and are never exited. Like any scope they are context-local, not a process-wide floor: code that copies that context (asyncio tasks) carries them, a thread the child starts does not, and a grandchild launched from such a thread receives the global policy only. A grandchild launched through `subprocess` from the inheriting context receives them.

Auto-activation runs before user code, so a child that re-runs application startup (e.g. a Django dev server under a process manager, a spawn-mode worker re-importing settings) will typically call `activate()` again. That call is an idempotent no-op when the requested policy is identical to the inherited one — including `locked=True` — so import-time `activate()` keeps working in children. A *differing* policy still raises `TetheredLocked` in locked mode.

> **Important:** This is defense-in-depth for **Python child processes**, not a system sandbox. Non-Python executables can be monitored/blocked at the parent (`external_subprocess_policy`), but tethered cannot enforce egress rules *inside* them. For hard subprocess isolation, combine with OS-level controls (seccomp, containers).
