---
title: "Subprocess control"
description: "How a tethered policy and a scope reach Python child processes, and what external_subprocess_policy does with every other launch."
---

# Subprocess control

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

A worker that inherits an enforcing policy at start-up also cannot load uvloop: tethered refuses the import, and a server that prefers uvloop (uvicorn, its gunicorn worker) runs that worker on the standard asyncio event loop, where the policy is enforced. That is why activating in the process that starts the server works for every server tested. A worker that inherits a `log_only` policy is not kept from uvloop, and reports nothing that goes through such a loop. See [the cookbook](COOKBOOK.md#servers-and-interpreter-pools) for what each server needs and [the security model](security.md#what-tethered-does-not-protect-against) for the limits.

**A policy reaches a process when it starts.** Processes that already exist when `activate()` is called are not told: pool workers started earlier hold no policy until they are replaced. That includes multiprocessing's fork server. A worker of the `forkserver` start method (the default on Linux from Python 3.14) is a copy of the fork server process, so a fork server that was started before `activate()` keeps producing workers without a policy, under a locked policy too, and asking it for a worker raises no audit event that tethered could act on. `activate()` logs one warning when it finds a fork server running. Call `activate()` before the first pool or process is started.

**The bootstrap has to be installed where Python runs it.** `site.py` executes `tethered.pth` only from a site directory: the interpreter's site-packages, or the per-user site-packages when enabled. `uv add tethered` and `pip install tethered` put it there. An editable install (`-e`) and a `--target` install used through `PYTHONPATH` do not, whether uv or pip makes them. In that case `activate()` logs a warning, no Python child auto-inherits, and every `sys.executable` launch is treated as external (see [below](#parent-side-enforcement-of-external-subprocess-launches)).

**And it has to be tethered's own file.** tethered takes a `tethered.pth` for its bootstrap only while the file holds the line tethered installs there. Another distribution that ships a top-level `tethered.pth` replaces the file when it is installed, and neither pip nor uv says so; `activate()` then logs a warning (`tethered: ... is not the file tethered installs under that name ...`) and Python launches are treated as external, as with no file at all. The file is read again at every launch of a Python child that would inherit. One that has been emptied, removed or replaced while the process runs (by an installer, by another program, by code the locked-mode guard does not see) changes what that launch is. Without a lock it is an external one, with the reason in the log line (`... — tethered.pth no longer holds tethered's bootstrap line: the child holds no policy`): under the default `"warn"` the child is still started, without a policy, and under `"block"` the launch is refused. Under a locked policy it is refused whatever the setting. The same goes, from Python 3.15, for a hook that has a `tethered.start` file beside it, which makes `site.py` skip the hook's import line.
**The payload is established at launch, not only at `activate()`.** The subprocess hook makes sure each Python child's launch environment carries the payload:

- **`subprocess` with an explicit `env=` that lacks it** (a mapping of any type): the child receives a copy with the payload added; the caller's mapping is not modified.
- **An inherited environment from which the variable has been removed** (for example by a keep-list cleanup of `os.environ` at startup): it is written back before the launch.
- **An `os.exec*` of the same interpreter with an explicit environment that lacks it:** the environment of an exec has been converted by the time the audit event is raised, so nothing written to the caller's mapping would arrive. An exec does not return, though, so tethered makes the call itself, with the same program and arguments and a copy of the environment that carries the payload. If that exec fails, the error is the one the caller's own call would have met (`os.execvp*` goes on to the next `PATH` directory, as always). Without a lock an exec environment that carries a wrong value is replaced in the same way.

Locked mode does the same for a `subprocess` environment or an exec environment that lacks the payload, and refuses an altered one and a process environment that lost it (see [hardening](#locked-mode-hardening-of-the-auto-propagation-channel)). Two routes are out of reach, because they raise no audit event, so nothing is checked or repaired for them: `multiprocessing` spawn / forkserver launches on POSIX with Python 3.11–3.13, and launches made through a uvloop event loop (see [below](#launches-made-through-a-uvloop-event-loop)).

A blocked call in a pool worker reaches the parent as `EgressBlocked`: the exception is picklable with all its attributes, so `multiprocessing.Pool` and `ProcessPoolExecutor` re-raise it in the parent.

## Locked-mode propagation

If the parent activated with `locked=True`, child processes also auto-activate in locked mode — each child gets a fresh per-process `lock_token`. The parent has no special control over the child's lock (correct: separate processes).

When the inherited policy has `locked` or `fail_closed` set and cannot be established in the child, the child refuses to start: the bootstrap raises `SystemExit`, interpreter startup fails, and the process exits with status 1 before any user code runs. This covers a payload that fails validation (a field of the wrong type, an unknown field), `activate()` raising, a malformed inherited scope, and locked mode when the C extension is not available in the child. With neither flag set, the problem is logged as a warning and the child continues without the part that failed; unknown payload fields are ignored. A value that is not a JSON object carries no flags: it is logged and ignored, and the child starts without a policy.

The same bootstrap runs when a new interpreter is created inside a process (a subinterpreter, a `concurrent.futures.InterpreterPoolExecutor` worker) whose environment carries the payload. An unlocked policy is established there as in a child process: the interpreter gets its own instance. A lock is different, because it exists once per process and a new interpreter cannot take one of its own:

- **The process holds a lock: the interpreter joins it.** It gets a locked copy of the policy, taken from the C guardian's own record of the locked policy and not from the variable, and from then on it is checked like the interpreter that holds the lock. It reaches what the policy allows, cannot deactivate or replace the policy, and cannot change the policy variable. Inherited scopes are still read from the variable. A child process it launches inherits the locked policy like any other.
- **It cannot join: it starts anyway, outside the lock.** One warning is logged. While the lock is held, the C guardian refuses that interpreter every connection, lookup and process launch, and any change to the bootstrap files or the policy variable; under a locked `log_only` policy its connections and lookups pass. An interpreter in which the bootstrap did not run at all, and one that already existed when the lock was taken, are refused in the same way: a join is accepted only while an interpreter starts.
- **The process holds no lock.** An inherited `locked` policy is established there unlocked (logged at INFO).

When the interpreter starts decides which of these applies, and a server or a pool may choose that moment for the application: mod_wsgi creates an application group's interpreter at its first request, and `InterpreterPoolExecutor` starts a worker when a task needs one. [The cookbook](COOKBOOK.md#servers-and-interpreter-pools) has the setups that work.

Unlocked policies of different interpreters do not stay apart where child processes are concerned. Each interpreter enforces its own policy on its own connections, but all of them share the one `_TETHERED_CHILD_POLICY` variable, and every `activate()` writes it. A Python child process therefore gets the policy of whichever interpreter activated last, whichever interpreter launches it, and an interpreter created afterwards starts under that policy even if the code in it never imports tethered. Without a lock a launch is not compared with the environment of the process itself, so this goes unreported. Two mod_wsgi application groups with different unlocked policies in one process are an example; give each application its own process.

The other strict failures (an invalid payload, a fail-closed policy that cannot be established, an audit hook that refuses tethered's) still stop the new interpreter's startup; on Python 3.12 and earlier an interpreter that fails to start takes the process down with it. See [the security model](security.md#locked-mode--what-it-does-and-does-not-do) for when a join is accepted and for what it does and does not cover.

Two limits of older Python versions matter when a process uses subinterpreters. On Python 3.12 and earlier, a process that exits while subinterpreters are still alive under a locked policy aborts at exit with `Fatal Python error: PyInterpreterState_Delete: remaining subinterpreters`: destroy them before the process exits. On Python 3.12, destroying an interpreter from a thread other than the one that created it hangs once that interpreter has imported `logging`, which importing tethered does: destroy each interpreter from the thread that created it. Neither happens from Python 3.13 on.

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
| A Python launch after `tethered.pth` was emptied, removed, replaced, or switched off by a `tethered.start` beside it (Python 3.15+) | Yes (the child would not auto-activate); refused under a locked policy |
| `os.execve` / `os.execvpe` of `sys.executable` with an explicit env that lacks the payload | No (tethered carries the exec out itself, with the payload added; under a lock too) |
| `os.spawnve` / `os.posix_spawn` of `sys.executable` with an explicit env that lacks the payload | Yes (that environment cannot be rewritten; locked mode refuses it) |
| A `subprocess` launch of `sys.executable` whose environment cannot be given the payload (unreadable `env=`, launch frame not found or not writable) | Yes (locked mode refuses it) |
| `multiprocessing` workers after `multiprocessing.set_executable(<other interpreter>)` | Yes (different interpreter) |
| `subprocess.run(["/usr/bin/python3", ...])` | Yes (different interpreter) |
| `subprocess.run(["python3", ...])` | Yes (not `sys.executable`: warned about, or refused under `"block"`, even where `PATH` leads to the same interpreter and the child does inherit) |
| `subprocess.run(["curl", ...])` | Yes (non-Python) |
| `os.system("rm -rf /")` | Yes (non-Python) |
| Direct `_winapi.CreateProcess` of a non-Python program (Windows) | Yes (non-Python) |

For a launch of `sys.executable` that counts as external, the warning and the `SubprocessBlocked` end with the reason: `tethered: external subprocess launch detected: subprocess.Popen(/usr/local/bin/python) — -S skips site.py and the tethered.pth bootstrap with it: the child holds no policy`.

Interpreter options are read with the boundaries CPython itself uses, so `-S` counts only where the interpreter would treat it as an option. On Windows it is recognized when quoted inside a command-line string and when `executable=` is given. `multiprocessing` launches are classified on Windows and, from Python 3.14, on POSIX; on POSIX with Python 3.11–3.13 they raise no audit event.

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

### Launches made through a uvloop event loop

Everything in this document depends on a launch raising an audit event. `asyncio.create_subprocess_exec` and `asyncio.create_subprocess_shell` raise `subprocess.Popen` on the standard asyncio event loop, where they are handled like any other `subprocess` launch. On a uvloop event loop they raise nothing, because uvloop starts the process itself, so tethered does not see the launch at all:

- `external_subprocess_policy` is not applied.
- The launch environment is neither checked nor completed.
- An active `scope()` does not travel to the child.

A Python child that inherits the environment still auto-activates the global policy, since that needs no hook in the parent. With an enforcing policy this cannot arise, because tethered keeps uvloop out of such a process: it refuses the import of uvloop while the policy is active and refuses to activate over a loaded uvloop. It applies where tethered runs next to uvloop all the same: under a `log_only` policy, whose report then lacks these launches, and for a `scope()` with no policy under it. See [the security model](security.md#what-tethered-does-not-protect-against).

### Launches under gunicorn's gevent worker

gevent brings a `subprocess` implementation of its own, which forks and calls `os.exec*` from Python. Under `gunicorn -k gevent` a `subprocess` launch therefore does not reach tethered as one `subprocess.Popen` event. It is seen as `os.exec*` events inside the forked child, one for each `PATH` directory that is tried. The rules are the same; where the messages go is not:

| Launch | `"warn"` | `"block"` |
|---|---|---|
| `[sys.executable, ...]` | The child inherits the policy; nothing is logged. | The same. |
| The same with an `env=` that lacks the policy variable | Launched with the policy added. Under a lock one line `... carried out with the locked policy added` is written. | The same. |
| `[sys.executable, "-S", ...]` | One warning; the child has no policy. | `SubprocessBlocked` in the worker. |
| `["python3", ...]`, `["bash", ...]` | One warning for each `PATH` directory tried. | `SubprocessBlocked`, naming the first candidate path. |

Whatever tethered logs for such a launch is logged by the forked child and written to that child's stderr, which is the pipe the application captures. The lines end up in the output the application reads from its subprocess (ahead of the tool's own output with `stderr=subprocess.STDOUT`) and not in the server log; with inherited stderr they are in the server log, under the forked child's pid. Under `"block"` with captured stderr the refusal is logged nowhere: only the exception arrives.

### When `sys.executable` is not Python

tethered recognizes a Python child by `sys.executable`. Where Python is embedded in another program, that need not be an interpreter: under uWSGI it is the uwsgi binary, and `subprocess.run([sys.executable, "script.py"])` starts uWSGI. tethered checks for this once, when it is imported. An interpreter that was started by its own executable has its command line in `sys.orig_argv`; an embedded one has none, and an embedded interpreter whose `sys.executable` is not named `python…` or `pypy…` is taken for a program that is not Python (mod_wsgi is embedded too, and leaves the path of a real interpreter there). `activate()` then logs a warning, and every launch is treated as external, with the reason in the log line: a launch of `sys.executable`, and a launch of the real interpreter too, although that child does inherit the policy. `uwsgi --py-sys-executable /path/to/python` makes `sys.executable` name the interpreter and puts it right. See [the cookbook](COOKBOOK.md#uwsgi).

### What `"block"` also refuses

`"block"` refuses every external launch, whoever makes it, and the standard library makes some. On Linux `ctypes.util.find_library()` runs `ldconfig`, so importing a library that looks a shared object up while it is imported (trio, asyncssh, psycopg 3 in its Python implementation) raises `SubprocessBlocked` under `"block"`; `platform.platform()` and `platform.processor()` run `uname` and catch only `OSError`, which stops `celery worker` at its banner. Import such libraries, and call `platform.platform()` once, before `activate()`. Under `"warn"` each of these launches is logged as an external launch and carried out, under a locked policy as well.

## Locked-mode hardening of the auto-propagation channel

In **locked mode**, tethered adds four Python-level checks to defend the auto-propagation channel against a dependency that knows tethered is installed. Before any of them runs, the C guardian verifies its integrity snapshot on the same events — process launches, filesystem events whose path mentions `tethered.pth` or `tethered.start`, and `os.putenv` / `os.unsetenv` of the policy variable — and refuses the operation with `SubprocessBlocked` on a mismatch, so a check that has been replaced does not get to decide.

- **Payload-integrity check at every process launch tethered sees.** The child's policy must equal the parent's canonical payload; the comparison is type-exact, on canonical JSON text (`0` is not `false`). The canonical form is deterministic — the `allow` list is sorted — so every process holding the same policy serializes the identical payload regardless of per-process hash randomization, and env snapshots captured in one process (e.g. by a honcho-style process manager) stay valid when a spawn-mode child launches with them. The check covers `subprocess`, `os.system`, `os.exec*`, `os.spawn*`, `os.posix_spawn` and `os.startfile`, and `multiprocessing` / `ProcessPoolExecutor` launches on Windows and, from Python 3.14, on POSIX. `multiprocessing` spawn / forkserver launches on POSIX with Python 3.11–3.13 raise no audit event and are not checked, and neither are launches made through a uvloop event loop (see [above](#launches-made-through-a-uvloop-event-loop)). This catches:
    - an explicit environment that lacks `_TETHERED_CHILD_POLICY` (`env={}` or a mapping of any other type) on the routes whose environment cannot be completed: `os.posix_spawn`, `os.spawn*`, and an `os.exec*` of another program. On the other routes such an environment is completed instead of refused, see below;
    - explicit `env={..., "_TETHERED_CHILD_POLICY": "<permissive value>"}` substitution, and a value that is not valid JSON, on every route;
    - more than one spelling of the key in one environment (Windows environment names are case-insensitive, so `_tethered_child_policy` is the same variable there; on POSIX the `str` and `bytes` spellings of the name);
    - inherited env (`env=None`) where the variable has been stripped or substituted through `os.environ` (`os.environ.pop`, `os.environ[...] = ...`) or through `os.putenv()` / `os.unsetenv()`, which `os.environ` does not show and tethered tracks through their audit events;
    - inherited env where the variable was changed out of this interpreter's sight: from another interpreter of the process (each one has its own `os.environ`, a copy made when it starts, and sees only its own audit events) or below Python (`ctypes` calling libc `setenv` / `unsetenv`, which raises no audit event). The launch reads the variable from the environment of the process itself and is refused when that does not carry the locked policy. This is a check made at the launches tethered sees; it does not stop native code from changing the variable after the check or from starting a process itself.
- **`tethered.pth` filesystem-tamper check.** Refuses the Python-level operations that would remove the file or change it:
    - deletion (the `os.remove` audit event, raised by `os.remove`, `os.unlink`, `pathlib.Path.unlink` and `shutil.rmtree`);
    - a rename touching the path (`os.rename`, also raised by `os.replace`);
    - a write-mode `open` of the path (also covers `shutil.copy` and `pathlib.Path.write_*`);
    - `os.chmod` of the path (a permission strip would make `site.py` silently skip the file);
    - `os.truncate` of the path;
    - a `_winapi.CopyFile2` onto the path (how `shutil.copy2` writes its destination on Windows from Python 3.12, with no `open` event).

    `os.ftruncate` carries a file descriptor, which cannot be matched against the path, but the `open` / `os.open` that would yield a writable descriptor for the file is refused while the policy is locked (the exceptions are named below).

    The file is recognised by its name (in any case of the letters) and its directory, however the call names that directory: through a symlink or a junction, by a Windows short name or with a `\\?\` prefix, or relative to a directory descriptor (`dir_fd`), which is how `shutil.rmtree` removes files on POSIX. On Windows `tethered.pth::$DATA` is the file too.

    A `tethered.pth` in another directory is left alone, unless it is the same file. uv installs by hard-linking out of its cache, so in an environment uv made the cache holds the hook under its own name, and a write there empties it. The operations that change a file in place (a write-mode `open`, `os.chmod`, `os.truncate`, a copy onto it) are therefore refused on such a file as on the hook. Reading it, removing it and clearing the cache are not: they leave the hook as it is.

    The file cannot be given a further name either. `os.link` and `os.symlink` with the file as their source are refused, and so is renaming that other `tethered.pth`: a write through a name that does not mention `tethered.pth` would not be looked at, so the name is stopped where it is made.

    Not matched: a name of another spelling that existed before the policy was locked; on Linux `/proc/self/fd/N`, which names an open file without any link; and `os.open(..., dir_fd=...)`, whose audit event does not carry the descriptor. A hook that is emptied on one of these routes is noticed at the next launch of a Python child, which is then an external launch (see [above](#auto-propagation-to-python-child-processes)).

- **`tethered.start` creation check.** From Python 3.15, `site.py` ignores the `import` line of `tethered.pth` when a file named `tethered.start` sits beside it, even an empty one ([PEP 829](https://peps.python.org/pep-0829/)); Python children then start without the policy, and a child that should have refused to start does not. tethered ships no such file, so creating one is refused: a write-mode `open` of that path (also `pathlib.Path.touch` / `write_*`, `shutil.copy`), a rename or `shutil.copy2` onto it, `os.link` and `os.symlink`. Removing such a file is not refused. `os.mknod` (POSIX) raises no audit event, so that way of creating it is **not** refused. A `tethered.start` that is there all the same, or was there before the policy was locked, is found by the next check.
- **A lost hook ends Python launches.** The hook is read again at every launch of a Python child (see [above](#auto-propagation-to-python-child-processes)). If it no longer holds tethered's line, or has a `tethered.start` beside it on Python 3.15 and later, the launch is refused, whatever `external_subprocess_policy` says: the child would start without the locked policy. This covers what the two file checks cannot see: `/proc/self/fd/N`, `os.open(..., dir_fd=...)`, `os.mknod`, another process, an installer that is run from outside.

**Installing, upgrading or removing tethered is refused like any other change to the file.** `pip` is Python: started with `[sys.executable, "-m", "pip", ...]` from a locked process, it inherits the locked policy, and when it moves or rewrites `tethered.pth` it gets `SubprocessBlocked`. pip stops there and does not undo what it had already done: the package's `.dist-info` directory stays renamed to `~ethered-<version>.dist-info`, so tethered keeps working but pip no longer lists it. Manage tethered's installation from outside the processes that hold a locked policy (a deployment step, a shell), not from a child of one. An installer that is not Python (`uv`) is an external program: the guard does not see what it does, and `external_subprocess_policy="block"` refuses its launch. [The compatibility page](COMPATIBILITY.md#installing-upgrading-and-removing-tethered) has what was measured, including how to repair the half-removed installation.

**An environment that merely lacks the variable is completed, not refused, where that is possible.** An environment built from a list of its own is what ordinary code passes, CPython included: on Linux `ctypes.util.find_library()` runs `ldconfig -p` with `env={"LC_ALL": "C", "LANG": "C"}`, at the import of every library that looks a shared object up. The lock promises that no Python starts without the policy, and it keeps that promise by adding the variable:

- A `subprocess` launch gets it through the copy of the environment that `_execute_child` is given, as an unlocked policy already does for Python children. Under a lock this is done for an external program as well, since whatever Python that program starts has to inherit the policy; the launch is then judged by `external_subprocess_policy` like any other. The caller's mapping is not written to. If the variable cannot be added (no `_execute_child` frame, a failed frame write), the launch is refused.
- An `os.exec*` of the same interpreter is carried out by tethered with the variable added, and logged (`tethered: os.exec*(...) was given an environment without _TETHERED_CHILD_POLICY; carried out with the locked policy added`). A refusal would be the wrong answer on this route in particular: whoever calls `os.exec*` has usually just forked, and an exception there leaves a second copy of the parent running the parent's code. gunicorn's binary upgrade (`SIGUSR2`) is such a call: it passes the environment gunicorn saved at start-up, which under `--preload` predates the application's `activate()`. The upgrade completes under a locked policy, and the new master's own `activate()` is the idempotent no-op.

A locked policy also survives such a re-execution: the new process has it before the application is imported and cannot replace it. [The cookbook](COOKBOOK.md#changing-a-locked-policy) says what that means for reloads and upgrades.

These checks apply only in locked mode. Outside it, a launch environment that lacks the payload is not refused: tethered re-establishes the payload or treats the launch as external, as described above. And all of them have the same `ctypes`-bypass caveat called out in [the security model](security.md): a deliberately-malicious dep with `ctypes` access can call libc `unlink`, `setenv`, and `connect` directly, bypassing every audit-event-based defense tethered ships. That page also lists what in-process Python code can still do against locked mode [without `ctypes`](security.md#locked-mode--what-it-does-and-does-not-do).

## Scopes propagate to subprocesses too

`tethered.scope()` propagates to children launched via `subprocess.Popen` (and APIs built on it like `subprocess.run` and, on the standard asyncio event loop, `asyncio.create_subprocess_exec`) and to a Python child started with `os.exec*`, which is how gevent's `Popen` launches: the child inherits both the parent's global policy AND the active scope chain, observing the parent's *effective* policy at the launch site (global ∩ scopes), not just the at-rest global. Some lower-level launch paths bypass `subprocess.Popen` and propagate the global only — see Limitations below.

```python
import tethered, subprocess, sys

tethered.activate(allow=["*.allowed.com"])

with tethered.scope(allow=["api.allowed.com"]):
    # Child inherits global *.allowed.com AND scope api.allowed.com.
    # Connections to other.allowed.com (allowed by global, blocked by scope)
    # are blocked in the child too.
    subprocess.run([sys.executable, "-c", "..."])
```

This works **without** `activate()`: a scope used on its own narrows its code path, and the narrowing extends through subprocess boundaries:

```python
# No activate() needed:
@tethered.scope(allow=["api.example.com"])
def do_work():
    subprocess.run([sys.executable, "-m", "myapp.helper"])
    # The helper subprocess only reaches api.example.com.
```

Race-free across threads (frame-locals are per-call, not shared global state): two threads can be in different scopes and concurrently launch subprocesses that each receive their parent thread's scope.

**How it works.** When `subprocess.Popen._execute_child` fires the `subprocess.Popen` audit event, tethered walks the call stack to the `_execute_child` frame and rewrites its `env` local to a per-call dict containing the scope-aware `_TETHERED_CHILD_POLICY` payload. The child reads this on startup. PEP 667 makes this a write-through proxy on Python 3.13+; on 3.11–3.12 tethered uses `ctypes.pythonapi.PyFrame_LocalsToFast` to push the fast-locals slot. The rewrite is not specific to scopes: it happens whenever the launch environment does not already carry exactly the right payload, for example an explicit `env=` without it. The per-call dict is a copy of the caller's mapping, whatever its type, with every spelling of the key replaced by the one canonical entry.

An `os.exec*` of the same interpreter has no such frame. tethered carries that exec out itself, as described under [auto-propagation](#auto-propagation-to-python-child-processes), with the scope-aware payload in the environment (the environment of the process when none was passed). The hook runs in the context that entered the scope, also in a child that was just forked, so it knows the scope chain. That is the route under gevent: after monkey-patching, `subprocess.Popen` is gevent's own class, which forks and calls `os.exec*` from Python.

**Limitations.**

- Scope cannot propagate through `os.system`, `os.startfile`, `os.spawn*` or `os.posix_spawn`, or through an `os.exec*` of another program — those launch paths have no env channel that tethered can intercept. Those launches still receive the parent's at-rest global only and remain subject to `external_subprocess_policy`. For the same reason an `os.spawn*` / `os.posix_spawn` launch of `sys.executable` with an explicit env that lacks the payload is treated as external (and refused under a lock).
- **Scope cannot propagate through `multiprocessing.Pool` / `ProcessPoolExecutor` in spawn mode.** These launch paths call `_posixsubprocess.fork_exec` (POSIX) or `_winapi.CreateProcess` (Windows) directly, bypassing `subprocess.Popen` entirely. The `subprocess.Popen` audit event never fires, so the `_execute_child` frame mutation has nothing to hook. tethered does handle `_winapi.CreateProcess` and, from Python 3.14, `_posixsubprocess.fork_exec` for the payload check, payload repair and `external_subprocess_policy`, but the scope chain does not travel. Workers see only the parent's GLOBAL policy (which propagates via inherited `os.environ`). For scope propagation to multiprocessing workers, use **fork mode** (`mp.get_context("fork").Pool(...)`, Linux only) — fork copies the entire process state including the `_scopes` ContextVar, so children inherit scopes via OS-level state copy. Or restructure to launch workers via `subprocess.run([sys.executable, ...])` directly.
- **`asyncio.create_subprocess_exec` / `create_subprocess_shell` carry the scope on the standard asyncio event loop only.** There they use `subprocess.Popen` internally and are supported. On a uvloop event loop they raise no audit event and the scope does not travel: the child gets only what the inherited environment carries, which is the global policy if there is one (see [Launches made through a uvloop event loop](#launches-made-through-a-uvloop-event-loop)).
- Forked children inherit scope at fork time and persist it for their lifetime — they are independent processes, so the parent's `with` exit doesn't reach them.
- In locked mode, the child's canonical `global` field is compared type-exactly as canonical JSON; the scopes part is not compared because scopes can only narrow within the checked global ceiling.

## What's inherited and what isn't

The child re-activates with: `allow`, `allow_localhost`, `log_only`, `fail_closed`, `external_subprocess_policy`, `locked` (with a fresh per-process token), and the active scope chain (each scope's `allow`, `allow_localhost`, `log_only`, `fail_closed`, `label`, `hint`).

Not inherited: `on_blocked` (callbacks can't cross process boundaries), the parent's exact `lock_token` (identity-compared; can't survive serialization).

A new interpreter inside the same process is not a child process. Under a lock it gets no token of its own: it joins the lock of its process (see [Locked-mode propagation](#locked-mode-propagation)). `on_blocked` does not cross interpreters either.

Inherited scopes are pushed onto the scope stack of the context the child starts in (its main thread) and are never exited. Like any scope they are context-local, not a process-wide floor: code that copies that context (asyncio tasks) carries them, a thread the child starts does not, and a grandchild launched from such a thread receives the global policy only. A grandchild launched through `subprocess` from the inheriting context receives them.

Auto-activation runs before user code, so a child that re-runs application startup (e.g. a Django dev server under a process manager, a spawn-mode worker re-importing settings) will typically call `activate()` again. That call is an idempotent no-op when the requested policy is identical to the inherited one — including `locked=True` — so import-time `activate()` keeps working in children. A *differing* policy still raises `TetheredLocked` in locked mode.

> **Important:** This is defense-in-depth for **Python child processes**, not a system sandbox. Non-Python executables can be monitored/blocked at the parent (`external_subprocess_policy`), but tethered cannot enforce egress rules *inside* them. For hard subprocess isolation, combine with OS-level controls (seccomp, containers).
