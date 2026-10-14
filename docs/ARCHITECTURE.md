---
title: "Architecture"
description: "How tethered works: the audit hook and the events it handles, scopes, child processes, the C guardian behind locked mode, the measured overhead, and what tethered relies on that CPython does not promise."
---

# Architecture — how tethered works

tethered uses [`sys.addaudithook`](https://docs.python.org/3/library/sys.html#sys.addaudithook) (PEP 578) to intercept socket operations at the interpreter level:

- **`socket.getaddrinfo`** — blocks DNS resolution for disallowed hostnames and records IP-to-hostname mappings for allowed hosts.
- **`socket.gethostbyname` / `socket.gethostbyaddr`** — intercept alternative DNS resolution paths, including reverse-DNS lookups of raw IPs. An allowed `gethostbyname` (the event `gethostbyname_ex` raises too) records the name as a fallback candidate, so that a later connect to the address it returned can be matched back to the name. `socket.getnameinfo` is not checked: its audit event carries the address but not the flags, so a reverse lookup cannot be told apart from numeric formatting.
- **`socket.connect`** (including `connect_ex`, which raises the `socket.connect` audit event in CPython) — enforces the allow list on TCP connections. One connect passes whatever the layers say: the one with which `socket.socketpair()` joins its own two sockets where the platform has no `socketpair()` of its own (Windows), which the constructor of every asyncio event loop makes. `_is_own_socketpair_connect` recognises it by the frame that made it, which runs the code object `socket._fallback_socketpair` had when tethered was imported; by its target, 127.0.0.1 or ::1; and by that frame's listening socket, which has to listen on exactly that address, read through the `getsockname` and `getsockopt(SO_ACCEPTCONN)` of the C type; macOS cannot answer the second, and there, where `socketpair()` is native, no connect is let through this way. It is asked only where a layer refuses the address (before the [fallback search](#dns-divergence-fallback), which it spares), so an allowed connect pays nothing for it.
- **`socket.sendto` / `socket.sendmsg`** — enforces the allow list on UDP datagrams. `sendmsg()` without an address raises the event with `None` in its place: that is a write on a connected socket, which names no destination, and it passes. From Python 3.12 asyncio's selector transports write this way (every `writelines()`, and whatever part of a `write()` one `send()` did not take).
- **`socket.__new__`** — no enforcement. It is used for two one-time warnings about event loops that tethered cannot see into: on Windows when a socket is created while an asyncio `ProactorEventLoop` is running, and elsewhere when one is created while uvloop is loaded, which can only be under a log-only policy or a scope without a policy (see [Event loops](#event-loops)).
- **`import`** — while a policy that is not log-only is active, an import of uvloop or pycares is refused with `ImportError` (see [Event loops](#event-loops)). Nothing else is done for import events.

This works with libraries built on CPython sockets (requests, httpx, urllib3, aiohttp) and frameworks like Django, Flask, and FastAPI — they all call `socket.getaddrinfo` and `socket.connect` under the hood. A library that resolves and connects inside a C library of its own raises neither event and is not seen; [the compatibility page](COMPATIBILITY.md#client-libraries) lists which of some seventy client-library arrangements do which. What a check costs per event is measured [below](#performance).

When `getaddrinfo` resolves a hostname, tethered records the IP-to-hostname mapping in a bounded LRU cache: up to 4096 addresses, keyed by the canonical text of the address (IPv6 compressed and without scope ID, IPv4-mapped IPv6 as the IPv4 address), each with up to 8 hostnames, most recent first. When a subsequent `connect()` targets that IP, tethered looks up the hostnames and checks them, and the raw IP, against the allow list; the connection is allowed if any of them is. If denied, `EgressBlocked` is raised before the connection is attempted.

One caveat: CPython resolves a hostname passed directly to `connect()` / `sendto()` before it raises the audit event, so that lookup has already happened when tethered refuses the call.

The map belongs to a policy: `deactivate()` drops it, and so does an `activate()` that changes the policy. An `activate()` that puts the same policy in place again (an identical serialized payload) keeps it, because a thread that has just looked a name up and is about to connect would otherwise find no name for the address and be refused a host the policy allows.

Addresses are read in every form CPython accepts: `str`, `bytes` or `bytearray` hosts, and any port object with `__index__`. An address on an IP-family socket that tethered cannot read is refused. `connect()` and `sendto()` always name an address; only `sendmsg()` can come without one, and that case is the write on a connected socket described above.

When a connection to an IP address is refused and no hostname is known for that address, the fallback search below included, the hook logs one hint per process (`_hint_at_unnamed_address`), provided the policy has hostname rules. Usually such an address is simply one that nothing allows. But a library that resolves names without `socket.getaddrinfo` (c-ares, dnspython, eventlet's greendns, gevent's ares resolver) leaves tethered with the address alone, and then every host that is allowed by name is refused with a message that names an address the user has never seen. The hint says where the name went and what to change.

## DNS-divergence fallback

The audit-hook architecture has an inherent limitation: tethered's resolution (called from inside the `socket.getaddrinfo` audit hook, before CPython's) and CPython's own resolution (whose result is returned to the application) are **two independent DNS queries**. For a name whose answers differ from one query to the next, as with a load balancer that hands out a different subset of its addresses each time, the two queries can return different IP sets wherever no cache answers both — leaving the connect-time IP unmapped. Without a cache that holds whatever the TTL; behind a caching stub only for a TTL of 0. gevent's default resolver makes no difference: both queries run one after the other in the same thread of its pool. Eager population can never be perfect within the audit API; [the security model](security.md#known-residual-dns-divergence) has the measured refusal rates.

When `_handle_connect` sees an unmapped IP, `_fallback_resolve` re-resolves up to 30 most-recently-allowed hostnames (LRU order, newest first) and checks if any maps to the connecting IP. On a hit it returns the hostname and enriches the IP map so future connects to that IP take the fast path. On a miss it returns `None` and the connect-time policy check then sees the bare IP, which doesn't match any hostname allow rule, and blocks. Hot path (mapped IP) is unaffected — the fallback fires only on misses, and it is skipped when every layer already allows the raw IP (loopback, an IP or CIDR rule), because no hostname could change that outcome. A miss costs one lookup per name searched, until one matches: through a caching stub a local round trip, without one an upstream round trip, and nothing is remembered of a search that found no name, so the next connect to the address searches again ([measured](#the-fallback-search)).

Candidates are recorded after the scope checks, so only names whose lookup the global policy and every enforcing scope let through are ever re-resolved. `gethostbyname` lookups record a candidate too, but no mapping; the fallback is how an address obtained that way is matched to its name.

In locked mode, `_fallback_resolve` is the second authorized caller of `_c_guardian.resolve` (slot 1 in the C guardian's `expected_caller_codes` array; slot 0 is `_handle_getaddrinfo`). Like every function in the module it is covered by the C guardian's integrity snapshot, so replacing it with a no-op that defeats the divergence repair is detected. The resolver that `_c_guardian.resolve` calls is the `_socket.getaddrinfo` captured when the policy was locked or, in an interpreter that joined the lock, its own `_socket.getaddrinfo` as it was when it joined. Inside the resolution only the resolver's own `socket.getaddrinfo` event is exempt from the guardian's checks; a `connect`, `sendto` or `sendmsg` event raised from inside it is refused.

## Event loops

asyncio is supported on its own selector event loop: the socket calls that loop makes raise the same audit events, so asyncio streams, `aiohttp`, and `httpx` async go through the same connect-time checks as synchronous code. One thing differs there. `loop.getaddrinfo` runs `socket.getaddrinfo` in an executor thread, where the global policy applies and the caller's scopes are not visible; so that the connect can still be matched to the name, a lookup made in a context with no policy and no scope is recorded while any scope is active in the process.

Two event loops do their I/O through calls that raise no audit event, and an audit hook cannot add one. tethered enforces nothing it cannot see, so for the first of them it refuses to run at all, and for the second it logs a one-time warning.

- **uvloop** implements the event loop in libuv, below Python's `socket` module. Nothing the loop does itself raises an event: `loop.getaddrinfo`, `loop.create_connection(host, port)` and the streams built on it, both kinds of datagram endpoint, and the process launches behind `asyncio.create_subprocess_exec` / `create_subprocess_shell`. An audit trace taken without tethered shows `socket.getaddrinfo` and `socket.connect` for `asyncio.open_connection` on the selector loop and no event at all on uvloop. What still raises events under uvloop is a Python socket object: `loop.sock_connect(sock, ...)`, and blocking code wherever it runs.

    The hook cannot see into the loop, but it does see the import. `_REFUSED_IMPORTS` maps the names of the `import` audit events at which a library is refused to that library: `uvloop` and `uvloop.loop`, `pycares` and `pycares._cares`. Two names each, because `import uvloop` raises an event for the package while `importlib.import_module("uvloop")` raises none for it, only for what the package's `__init__` imports, of which `uvloop.loop` is the extension that holds the event loop. When such an event arrives while a policy that is not log-only is active, `_refuse_import` raises `ImportError` and logs the refusal once per library, because what prefers these libraries catches the error and falls back without a word: uvicorn then runs on the standard loop. Before it refuses the package itself it asks the import system whether the library exists (`importlib.util.find_spec` of a top-level name imports nothing), so that a server which merely probes for a loop it prefers gets Python's own "No module named" where there is none. Neither event is raised again once a library is loaded, so one that was imported before the policy is not touched by this.

    A uvloop that is already loaded cannot be taken away. `activate()` therefore refuses every policy that is not log-only when `uvloop` is in `sys.modules`: it logs `_UVLOOP_LOADED_MSG` at error level and raises it as `RuntimeError`, before anything is changed. It is logged as well as raised because the exception does not always reach anyone. A log-only policy refuses nothing, this included; for it, and for a `scope()` with no policy under it, `_warn_if_uvloop` logs one warning when `uvloop` is in `sys.modules`. tethered never imports uvloop, and that it is loaded is taken as the sign that it is in use. That check is made when a log-only policy is activated, when a scope is entered, and for a `socket.__new__` event while a policy or a scope is active, until the warning is out. The module-level flag `_uvloop_warning_pending` starts clear on Windows, where uvloop does not exist.

    All of this is per interpreter, like the rest of `_core`: an interpreter with no policy of its own is not kept from importing uvloop by a policy, or a lock, held in another one.

- **pycares** is not an event loop, but it is refused by the same mechanism and for the same reason. c-ares, which aiohttp resolves with whenever aiodns is installed, looks names up in C: tethered then sees a connection to an address it has no name for, no hostname rule can match it, and the lookup of a forbidden name still leaves the process. With the import refused, aiodns fails to import and aiohttp takes its threaded resolver, which calls `socket.getaddrinfo`. The refusal is logged at info level, since this is what a correctly working default installation does. A pycares that was loaded before the policy is left alone, unlike uvloop: what it resolves is refused at the connection.
- **The Windows `ProactorEventLoop`**, the default there, connects and sends through `_overlapped` calls that raise no `socket.connect` / `socket.sendto` event, so there is no connect-time enforcement on that loop. tethered logs its warning when a socket is created while such a loop is running (`_warn_if_proactor_loop`), and `asyncio.SelectorEventLoop` is the supported loop.

The import refusal is a guard against a deployment that would silently not be enforced. It is not a barrier to code that is out to get around tethered: such code can load any other extension that does its own networking.

## Scopes

`scope()` uses `contextvars.ContextVar` to push a per-context policy onto a stack. The audit hook checks the context-local scope stack in addition to the global policy. When a scope is active, a connection must pass both the global policy and every scope on the stack. When the context manager exits (or the decorated function returns), the scope's own entry is removed from the stack, by identity, so exits that happen out of order do not disturb other scopes. A generator suspended inside a `with scope():` block leaves that scope on the consumer's stack until it resumes. Because `ContextVar` is async-safe, scopes propagate correctly through `await` chains and `asyncio.create_task()`. Scopes do **not** automatically propagate to child threads — use `scope()` at the I/O point inside the thread, or use `activate()` for a process-wide ceiling.

## Subprocess audit handling

In addition to socket events, the audit hook intercepts process launches:

- `subprocess.Popen`, `os.system`, `os.exec*`, `os.posix_spawn`, `os.spawn*` and `os.startfile`;
- the two events raised by launches that bypass `subprocess.Popen`, such as `multiprocessing` workers: `_winapi.CreateProcess` on Windows and, from Python 3.14, `_posixsubprocess.fork_exec` on POSIX.

At these events it enforces `external_subprocess_policy`, establishes the policy payload in the child's launch environment, makes the locked-mode payload-integrity check, and hands an active scope on to a spawn-mode child (through the `_execute_child` frame of `subprocess.Popen`, and for an `os.exec*` of the same interpreter by carrying the exec out with a completed environment).

It also handles `os.putenv` / `os.unsetenv` for the policy variable, because `os.environ` does not show changes made through them. A change made from another interpreter or below Python shows up neither in `os.environ` nor in these events, so in locked mode a launch that inherits the environment also reads the variable from the process environment itself (see [The policy variable](#the-policy-variable)).

A launch that raises none of these events is not handled at all:

- `multiprocessing` on POSIX before Python 3.14;
- a worker that multiprocessing's fork server forks on request (the request goes over a socket; `activate()` warns once when a fork server is already running, `_warn_if_fork_server_runs`);
- `asyncio.create_subprocess_exec` / `create_subprocess_shell` on a uvloop event loop, which starts the process in libuv (on the selector loop they go through `subprocess.Popen`).

See [the subprocess page](SUBPROCESS.md) for the full mechanics.

An audit hook cannot change the arguments of the call it is asked about, so the hook gives a child its policy in two indirect ways. For `subprocess.Popen` it rewrites the `env` local of the `_execute_child` frame, which the launch reads afterwards. For `os.exec*` there is no such frame, and the environment has been converted by the time the event is raised; but an exec does not return, so for an exec of the same interpreter whose explicit environment lacks the payload the hook makes the call itself (`_exec_with_policy`): `os.execve` with the same program and arguments and a copy of the environment that carries the payload. If it succeeds the process is replaced, as the caller asked; if it fails, the error leaves the hook as the exception of the caller's own call. Under a lock both ways are also how an environment that merely lacks the variable is completed instead of refused, for an external program started through `subprocess` as well. `os.posix_spawn` and `os.spawn*` offer neither way.

In locked mode, the audit hook also intercepts filesystem events (`os.remove`, `os.rename`, `open` write-mode, `os.chmod`, `os.truncate`, and `_winapi.CopyFile2`, which `shutil.copy2` writes through on Windows) on the `tethered.pth` path to refuse Python-level tampering with the auto-propagation hook. That path is the hook found in a site directory this interpreter processes; it is empty when there is none, and then there is nothing to guard. An event's path is matched against it as text first, and then by what it names: a path whose last component is `tethered.pth` is the hook when its directory is the hook's directory, compared by identity (`os.stat`) and resolved against the event's `dir_fd` where it has one. So a symlink or junction to the directory, a Windows short name and a descriptor-relative `os.remove` (which is what `shutil.rmtree` issues on POSIX) all name the hook, and a file called `tethered.pth` in another directory does not. An event whose paths do not mention `tethered.` ends at one substring test, which is what the `open` of any other file costs under a lock, and only a path that ends in the file's name is looked up in the file system.

One file can have several names, and the hook often has: uv installs by hard-linking out of its cache, so the `tethered.pth` of an environment it made is also a `tethered.pth` in the cache directory. For the events that change a file in place (a write-mode `open`, `os.chmod`, `os.truncate`, `_winapi.CopyFile2`), a `tethered.pth` in another directory is therefore compared with the hook as a file as well, by one more `os.stat` of each, and refused when it is the same file. Removing that other name is not refused, because it leaves the hook as it is. Giving the file a further name is: `os.link` and `os.symlink` with the file as their source (`_gives_pth_another_name`), and a rename of that other `tethered.pth`. A name that does not end in `tethered.pth` is never looked at afterwards, so it has to be stopped where it is made. Some names need no making and stay open: on Linux `/proc/self/fd/N` names any open file.

What the file guard cannot refuse is met from the other side. A `tethered.pth` counts as the hook only while it holds the one line tethered installs (`_is_bootstrap_file` compares the file with `_PTH_BOOTSTRAP`): `activate()` looks for a file with that content, and warns when a file of that name is there with another, which is what a second distribution that ships a `tethered.pth` leaves behind. The launch classifier reads the file again for every launch of a Python child that would inherit, and a hook that was emptied, removed or replaced since makes that launch an external one; under a locked policy `_handle_subprocess` refuses it outright, as it refuses a launch whose process environment has lost the policy variable. The read is an `open` event like any other; under a locked policy that has failed its integrity check the guardian refuses it too, and the file then counts as not confirmed.

The same hook refuses creating a `tethered.start` file beside `tethered.pth` (a write-mode `open`, the destination of `os.rename`, `os.link`, `os.symlink` or `_winapi.CopyFile2`). The bootstrap is an `import` line in a `.pth` file, and PEP 829 changes how Python treats those: from Python 3.15, `site.py` ignores the `import` lines of `<name>.pth` when a `<name>.start` file sits beside it, whatever that file contains, and Python 3.18 is to ignore such lines altogether in favour of `.start` entry points. tethered ships no `tethered.start`; on Python 3.15–3.17 the `.pth` line runs as before. A `tethered.start` that is there all the same (made with `os.mknod`, which raises no audit event, by another process, or before the policy) switches the hook off, so it is looked for where the hook's content is checked: at `activate()`, which warns, and at each launch of a Python child (`_start_file_beside`).

## C guardian — tamper-resistant locked mode

When `activate(locked=True)` is called, a C extension (`_guardian.c`) records a list of facts that `_core` generates from the namespaces of `tethered._core` and `tethered._policy`:

- what every module-level name is bound to (except `_config`, which the guardian tracks itself, and lower-case scalar runtime state);
- every class attribute of the classes defined there;
- the `__code__` of every Python function found;
- that no builtin those modules use is shadowed in their namespaces;
- that no `__getattribute__` / `__getattr__` has been added to those classes;
- the class and every slot of the active `_Config` and `AllowPolicy`.

The guardian re-checks the list on every socket audit event, every process-launch event, and the filesystem and environment events above when they concern `tethered.pth`, `tethered.start` or the policy variable (those are pre-filtered in C, so ordinary `open` calls stay cheap). Any mismatch (object replaced, method monkey-patched, frozen field mutated via `object.__setattr__`, bytecode swapped) refuses the operation — `EgressBlocked` for socket events, `SubprocessBlocked` for the others — and a tamper alert is written to fd 2. What the snapshot does not cover is listed in [the security model](security.md#locked-mode--what-it-does-and-does-not-do).

The C guardian also owns the lock state. It alone holds the token, `deactivate()` and `activate()` go through C for token verification, and it rebinds `_core._config` itself as part of its own commit, so no audit event sees a config and a snapshot that belong to different policies and swapping `_config` to an unlocked configuration doesn't help. A policy that fails the integrity check can be neither replaced nor deactivated. The token is not reported to the garbage collector, so `gc.get_referents()` does not hand it out.

`holds_lock()` tells the Python side whether the calling interpreter is the one that took the lock, so that a refused `activate()` / `deactivate()` can be worded for the caller: the holder without its token and an interpreter that joined are told about the token, and an interpreter that is neither the holder nor has a locked config of its own is told that it is outside the lock and that no token will help (`_locked_refusal`).

When the guardian adds its hook it confirms the hook is live with a private probe event (`tethered._guardian.probe`), and activation fails with `RuntimeError` if another audit hook refused it. `locked=True` requires the C extension; the extension is always built during installation, and a C compiler is required for source installs.

Importing tethered does not load the extension. `activate()`, `deactivate()` and the startup bootstrap load it (`_load_guardian()`), before they take a lock, so every transition goes through the guardian's activation claim and a policy is locked only once the extension is in place; `scope()` never loads it. Without the extension, an unlocked policy works and `locked=True` raises `RuntimeError`.

### Interpreters

A process can hold several interpreters, and the two hooks see them differently. tethered's Python hook is added with `sys.addaudithook` and belongs to one interpreter: each interpreter has its own `tethered._core`, its own `_config` and its own hook. The guardian's hook is added with `PySys_AddAuditHook` and is called for the events of every interpreter in the process. So there is one lock per process, taken by one interpreter (the lock holder; the source calls it the owner), while everything the guardian verifies is a Python object that belongs to exactly one interpreter. The guardian's state is split along that line.

**Per-interpreter state.** One struct for each interpreter that has imported the extension (an interpreter that never imported it has none, and stands outside a lock like one whose struct has no role): its role (none, holder or joined), its snapshot, config and resolver, the exception classes raised on its behalf, the `_in_hook` ContextVar, the code objects allowed to call `resolve()`, and for the holder the token. A struct is found through the interpreter's ID, at the cost of a thread-local read and one atomic load when a thread stays in one interpreter, and it is touched only by threads of that interpreter with its GIL held. Structs are pooled and never freed, so a pointer a thread has cached is always safe to check. The extension uses multi-phase initialisation and, from Python 3.12, declares support for interpreters that have their own GIL. Importing it again in the same interpreter (after removing it from `sys.modules`) gives another module object that works on the same struct.

**Process-wide state.** Threads of different interpreters, which may hold different GILs, read and write this at the same time. What the hook reads on every event is atomic: whether a policy is locked, the holder's interpreter ID, the policy's `log_only` flag copied at commit, and a generation counter. The rest sits behind one spinlock, inside which no Python API is called and nothing is allocated: a C-owned copy of the locked policy's serialized payload, the record of which interpreters have finished starting, and the list of structs. On POSIX the forking thread takes the spinlock before `fork()` and both processes release it afterwards, so a child process is never left with it held by a thread it does not have. One piece of process-wide state is held for much longer than a critical section, and is atomics of its own: the activation claim, by which the interpreters take turns at `activate()` and `deactivate()` (see [The policy variable](#the-policy-variable)). The holder is known by its interpreter ID, which CPython never gives out twice, and not by the address of its state, which the next interpreter created would be given: when the holder is destroyed the process stays locked and nobody is the holder.

**The startup window.** The guardian cannot authenticate Python objects: code already running in an interpreter could build stand-ins for `tethered._core` and offer those for pinning. An interpreter may therefore join only while it starts, when nothing has run in it but `site.py`, the `.pth` files and what they import. When `site.py` has processed the `.pth` files it executes `import sitecustomize`, which raises the `import` audit event with that name whether or not the module exists, and all of this happens before the call that creates the interpreter returns. The hook watches for that event in every interpreter, whether or not a policy is locked, and closes the window of the interpreter that raised it. An interpreter that already existed when the hook was first installed, which the first `activate(locked=True)` of the process does, can never join: its startup was not observed. In a process that runs without `site` (`-S`) the event never comes, so nobody joins. The record is C memory and nothing reopens a window.

**Joining.** The `tethered.pth` bootstrap of a new interpreter asks the guardian for the payload of the locked policy (`locked_payload()`). If there is one, `_core._join_locked()` rebuilds the policy and a locked `_Config` from it with the functions `activate()` uses, builds a snapshot of that interpreter's own modules, and calls `join()`. The guardian accepts when a policy is locked, the caller is not the holder, its window is open, and the offered config carries the locked policy's payload byte for byte. In one step it then binds that interpreter's `_core._config`, installs the snapshot, records the current generation and closes the window. No token is involved, and nothing is written to the policy variable. The policy comes from the guardian's copy and not from `_TETHERED_CHILD_POLICY`, so nothing done to the variable changes what is joined; inherited scopes are still read from the variable.

**Generations.** The generation counter moves when the holder commits a policy whose payload differs from the one before, and when the lock is released. A joined interpreter counts as joined only while the generation it recorded is the current one. This is how a replaced policy puts its earlier joiners outside the lock without the guardian touching their state, which belongs to other interpreters, and why re-activating an identical policy keeps them joined.

**Dispatch.** For every audit event the hook goes through these steps and stops at the first that applies:

1. Its own probe event: answer it.
2. An `import` of `sitecustomize`: close the calling interpreter's window.
3. No policy is locked, or the event is not one tethered guards: let it pass.
4. The caller is the holder: verify its snapshot (filesystem and environment events are pre-filtered first). If the snapshot holds, the holder's Python hook decides by the allow list. If the holder no longer has any state, because every instance of the extension in it has been freed, the event is refused.
5. The caller has joined, under the current generation: the same verification against its own snapshot, with its own exception classes, resolver and tamper alert. One thing differs: `os.putenv` / `os.unsetenv` of the policy variable is refused outright.
6. Anyone else: refuse the guarded operations with an exception created in the calling interpreter, reading only the atomics and the event's own arguments, never another interpreter's objects. Under a log-only lock, socket events pass.

### The policy variable

`_TETHERED_CHILD_POLICY` is one variable for the whole process, but each interpreter looks at it through its own `os.environ`, a copy made when that interpreter starts, and an `os.putenv` / `os.unsetenv` audit event reaches only the Python hook of the interpreter that raised it. With several interpreters launching children, a change made by one is invisible to the others, and so is a change made below Python. Under a lock, a launch that inherits the environment therefore also asks the guardian for the variable as the process holds it (`process_policy_env()`, which calls `getenv` or `GetEnvironmentVariableW`) and is refused when that is not the locked policy. An interpreter that has joined is refused changing the variable at all.

Without a lock there is no such check. Interpreters with different unlocked policies each enforce their own on their own events, but the variable holds whatever the last `activate()` in any of them wrote. A Python child launched from any of them inherits that policy, because a child that is given no environment of its own gets the environment of the process, and an interpreter created afterwards runs its bootstrap on it.

**The activation claim.** The interpreters of a process also take turns at changing the variable. `activate()` and `deactivate()` write it before they commit, and a write is not one step: `os.putenv` raises its audit event, every audit hook of the interpreter runs, and only then does the environment change. An interpreter could be anywhere in there while another one publishes its own policy and locks it, and its value would then land in the environment of a process whose lock it does not hold.

So the guardian holds one more piece of process-wide state, the activation claim (`_guardian.activation_claim`, a context manager): whoever is about to write the variable on tethered's behalf takes it first and gives it up when its transition is committed, or has failed and been undone. That is `activate()` and `deactivate()`, locked or not, and the launch hook for the moment in which it puts the payload of an unlocked policy back into a cleaned environment (it writes only if that policy is still the active one). All of them take their interpreter's lifecycle lock first and the claim second.

A thread that finds the claim taken waits for it with its GIL released, since the holder may be a thread of an interpreter that shares that GIL, and looks again once it has it: an interpreter that waited while another one locked a policy gets `TetheredLocked` before it has written anything. When several interpreters race for the first lock of a process, the winner's payload is therefore the only one that is written, and the losers are told at the door. The thread that holds the claim may take it again. The wait has no time limit, like a wait for the lifecycle lock; in the main thread a signal handler that raises ends it. Four cases are handled apart:

- A call made from inside a transition that the same thread is running in another interpreter raises `RuntimeError`, because that transition could not finish while the call waited for it.
- A call that finds the claim taken while Python is shutting down does not wait either and raises `RuntimeError`.
- The claim of an interpreter that is destroyed while it holds it is given up.
- A child created by `fork()` does not inherit a claim held by a thread it does not have.

A claim that was never given up would stop every later transition in the process, so the `with` statement is not trusted alone to give it up: Python 3.14 raises a pending exception after `__enter__` has returned and before the block is entered, and then never calls `__exit__`. Each use therefore notes how often the thread holds the claim beforehand (`held()`) and gives up anything beyond that in a `finally` (`restore()`).

The claim covers the writes tethered makes. A value that application code in another interpreter assigns to `os.environ`, or that is set below Python, is met by the launch check above.

The bootstrap of a new interpreter takes its turn as well, before it decides anything: it waits for a transition that is under way in another interpreter and then goes by the variable as the process holds it and by the lock as it stands, so it never acts on a policy that was published and not committed. Where it cannot wait, in the two cases in which `activate()` raises `RuntimeError` instead of waiting, it goes by the variable as its own `os.environ` showed it at startup. An interpreter created while a locked policy is being replaced therefore joins the new policy. One created while the first lock of a process is being taken still stays outside it: the guardian starts to watch interpreters at that lock, so this one counts as having existed before it.

## Thread safety

`AllowPolicy` is deeply immutable after construction: rules are tuples of strings and integers, networks are stored as integers, and matching reads plain tuples, so no rule field can be reassigned in place. The `_Config` bundle is a frozen `dataclass` swapped by a single reference assignment; a hook reads `_config` once and works from that object. `activate()` and `deactivate()` are serialized from start to finish by a re-entrant lifecycle lock, so the config, the guardian state and the child-policy variable change together; `_state_lock` only guards the one-time installation of the audit hook. Installation is confirmed with the private audit event `tethered.hook_probe`, raised before adding (a hook that is already live is never added twice) and after (unanswered means another audit hook refused tethered's, and `activate()` / `scope()` raise `RuntimeError`). The IP-to-hostname map is an `OrderedDict` guarded by `_ip_map_lock` with LRU eviction. The process-wide count of active scope entries is guarded by its own lock. Reentrancy guard uses `contextvars.ContextVar` (async-safe, faster than `threading.local()`).

All of the above is per interpreter: each interpreter has its own `tethered._core` with its own locks, config and maps. Interpreters can run in parallel from Python 3.12, each under its own GIL. What they share lives in the C guardian, behind atomics and one spinlock (see [Interpreters](#interpreters)). Their `activate()` and `deactivate()` calls take turns through the guardian's activation claim (see [The policy variable](#the-policy-variable)): when several of them call `activate(locked=True)` at the same moment, one takes the lock and each of the others gets `TetheredLocked` when its turn comes.

A forked child gets these locks back unlocked. `os.fork()` copies the forking thread only, so a lock that another thread held at that moment would stay locked in the child for ever. An `os.register_at_fork` handler resets tethered's locks in the child, in place (`_at_fork_reinit`, as `logging` and `threading` do with theirs), so the lock objects stay the ones a locked policy has pinned; a re-entrant lock that the forking thread itself holds is left to it. Importing tethered does not register the handler: the first `activate()`, `deactivate()`, `scope()` or startup bootstrap does, before it takes any of these locks. The C guardian gives up its activation claim in a forked child for the same reason, from handlers it registers when it is loaded.

None of this has been validated on free-threaded Python (PEP 703). The C extension does not declare free-threaded support, so loading it on a free-threaded build re-enables the GIL. Importing tethered does not load it, and `scope()` alone does not either: the GIL stays off until the first `activate()` or `deactivate()`, or the startup bootstrap of an interpreter that inherits a policy, loads the extension and so re-enables it. No free-threaded wheels are published.

## Performance

The audit hook runs on every relevant socket event, but the cost per event is small: the TCP handshake, TLS and application logic dominate the time a real connection takes. The overheads below apply whether tethered was engaged through `activate()` or `scope()`. Measured on CPython 3.13 against localhost with the benchmark's default settings (3,000 TCP-connect iterations, median of 3; 5,000 iterations for the other events):

| Operation | Overhead added |
|---|---|
| `socket.connect` | ~25 µs |
| `socket.getaddrinfo` | ~120 µs (~2×) for `localhost`: tethered resolves the name itself to record which hostname each address belongs to. Against a DNS server that second lookup costs what the resolver charges for it, [below](#the-second-lookup-against-a-dns-server) |
| Any audit event that is not a network event | ~150 ns |
| `with tethered.scope(...)` enter + exit | ~1 µs (the cost of the context manager, with or without `activate()`) |

Numbers vary with hardware, operating system and Python version. Reproduce them with [`uv run python benchmarks/overhead.py`](https://github.com/shcherbak-ai/tethered/blob/main/benchmarks/overhead.py).

### The second lookup against a DNS server

When an allowed name is looked up, tethered looks it up a second time itself, inside the audit hook and before CPython's own lookup, to record which addresses belong to the name (`_csocket.getaddrinfo`, under a lock `_c_guardian.resolve`). It does so under every policy, a log-only one included, and in every thread while a scope is open anywhere in the process. `localhost` is answered from `/etc/hosts`; against a DNS server the second lookup costs what the resolver between the process and the server charges for it. [`benchmarks/dns_lookups.py`](https://github.com/shcherbak-ai/tethered/blob/main/benchmarks/dns_lookups.py) measures it in a container with no network, where a DNS server of the benchmark's own plays the upstream: it answers every query 20 ms after it arrives (`--latency-ms`), and counts the queries it receives. `socket.getaddrinfo(name, 443, type=SOCK_STREAM)`, 300 calls per row, allow list naming the host:

| Between the process and the upstream | Lookups reaching the upstream per call, deactivated → activated | Median, deactivated → activated | Added |
|---|---|---|---|
| Nothing: glibc asks the upstream that `/etc/resolv.conf` names, as in a slim container image | 1 → 2 | 20.5 → 41.2 ms | +20.7 ms, one upstream round trip |
| The same, locked | 1 → 2 | 20.5 → 40.8 ms | +20.4 ms |
| The same, through gevent's default resolver (a pool of 10 threads), one lookup at a time | 1 → 2 | 20.5 → 41.0 ms | +20.5 ms |
| The same, 20 lookups at once | 1 → 2 | 42.2 → 84.1 ms; 471 → 237 lookups per second | each lookup twice as long, half the throughput |
| systemd-resolved (`nameserver 127.0.0.53`), the name in its cache | 0 → 0 | 0.094 → 0.150 ms | +0.06 ms |
| systemd-resolved, the name not in its cache | 1 → 1 | 20.6 → 21.2 ms | +0.1 to +0.6 ms |
| dnsmasq, the name in its cache | 0 → 0 | 0.036 → 0.081 ms | +0.04 ms |
| dnsmasq, the name not in its cache | 1 → 1 | 20.7 → 20.7 ms | +0.04 to +0.07 ms |
| Windows 11, the DNS Client service, `pypi.org` (measured once) | not counted | 0.123 → 0.320 ms | +0.2 ms |

The container rows were measured with tethered 1.0.1 on Python 3.14.8 in `python:3.14-slim` (Debian 13, glibc 2.41), with systemd-resolved 257.13 run without systemd, dnsmasq 2.91 and gevent 26.9.0, in two runs of the benchmark; the medians are from the second, and no median of the first differed from it by more than 1 ms. The Windows row was measured once on Windows 11 (build 26300) with Python 3.14.8, against the real name. A lookup is counted by its A query; each also sends an AAAA query, which went to the upstream with it where nothing caches and was answered from the stub's negative cache otherwise.

- **Without a cache, every lookup of an allowed name costs one more upstream round trip**, whatever that round trip takes, and the upstream receives twice the queries, A and AAAA alike. glibc keeps no cache of its own, so this is the case of every container image whose `/etc/resolv.conf` names a DNS server. Where lookup latency or the upstream's query rate matters, put a caching stub between the process and the upstream. dnsmasq runs in a container as an ordinary process. systemd-resolved, which Ubuntu and Fedora hosts use, runs in one without systemd too, but forwards nothing while no network interface other than loopback is up, and caches nothing that a server on a loopback address answers.
- **With a caching stub the second query is answered locally.** tethered's lookup comes first: when the stub does not have the name, it is tethered's query that goes to the upstream, and CPython's own lookup is answered from the cache it filled. The upstream receives one query per lookup, as without tethered, and the added time is a local round trip, well under a millisecond. On Windows the DNS Client service is such a cache: the added time was 0.2 ms.
- **Under gevent's default resolver** tethered's lookup runs in the same thread of gevent's resolver pool as gevent's own, right before it. The hub is not held up (the longest stall measured was 2.5 ms, with or without tethered), but each lookup occupies a thread of the pool twice as long: with more lookups at once than the pool has threads, each takes twice as long and the pool resolves half as many per second.

### The fallback search

When a connect goes to an address that no name is known for and that no layer allows as an IP, tethered searches the names it has recently let through before it decides ([DNS-divergence fallback](#dns-divergence-fallback)): one lookup per name, newest first, up to 30, and again for every such connect. Measured with the same benchmark and versions, with 30 allowed names looked up first and then 20 connects to an address the policy does not allow:

| Between the process and the upstream | Lookups reaching the upstream per connect | Median connect, deactivated → log-only (goes ahead) / enforcing (refused) |
|---|---|---|
| Nothing | 30 | 0.016 ms → 617 ms / 617 ms |
| The same, through gevent's default resolver | 30 | 0.062 ms → 615 ms / 618 ms, with every greenlet held up as long |
| systemd-resolved | 0 to 0.5 | 0.004 ms → 2.8 ms / 2.7 ms |
| dnsmasq | 0 | 0.020 ms → 1.9 ms / 1.5 ms |

- **Without a cache, each name searched is an upstream round trip.** Under a log-only policy nearly every connection that the policy would refuse is to an address no name is known for (a lookup the policy does not allow records nothing), so each of them goes ahead up to 30 round trips late. Under an enforcing policy the search delays the refusal of an address that no rule allows, and the decision on an address that tethered's own lookup of the name did not return (see [the security model](security.md#known-residual-dns-divergence)).
- **Under gevent the search holds up the whole process.** It runs in the greenlet that connects, in the hub's thread, through `_socket.getaddrinfo`, which gevent does not patch, so no other greenlet runs until it is over.
- An address that an IP or CIDR rule allows is never searched for, and a caching stub answers each name of the search locally. Where neither applies, as in a log-only rollout in an image without a cache, expect each such connect to wait one upstream round trip for every name tethered has let through recently, up to 30.

## What tethered relies on

Besides deciding at the audit events it handles, tethered reaches into the process in a few other ways: it writes into the frame of another function, carries out a call for its caller, recognises code by its code object or a private name, reads state below Python, and refuses imports. Each of these, and the audit events themselves, rests on things that CPython, the standard library or another library does not promise to keep: private names, the layout of a frame, the order of an event's arguments, behaviour nobody documents. When one of them changes, the mechanism built on it breaks in its own way. This section lists them all.

Each entry says what tethered does, and then:

- **Relies on:** the private name or the behaviour, with the Python versions and platforms where it applies.
- **Needed by:** the setup that needs the mechanism, with the evidence: a container suite (`tests_containers/suites/<name>`), a test in `tests/`, or an entry of [the changelog](changelog.md).
- **Pinned by:** the test that checks the assumption. Most are in `tests/test_cpython_internals.py`, which asserts each assumption directly against the interpreter it runs on, names the entry in its failure messages, and runs on every supported version and on the newest pre-release of the next one (the `next-python.yml` workflow).

### Audit events

- **The socket events.** `_audit_hook` decides at `socket.getaddrinfo`, `socket.connect`, `socket.sendto`, `socket.sendmsg`, `socket.gethostbyname` and `socket.gethostbyaddr`, and gives its one-time warnings at `socket.__new__`. The C guardian names the host of the same events in its refusals.
    - Relies on: the arguments as CPython 3.11–3.15 raise them. `socket.getaddrinfo` carries `(host, port, family, type, protocol)` and not the caller's flags; the events that connect or send carry `(socket, address)`, `connect_ex()` raises `socket.connect`, and `sendmsg()` on a connected socket raises `socket.sendmsg` with `None` for the address; the lookups carry `(host,)`, and `gethostbyname_ex()` raises `socket.gethostbyname`. The table of audit events documents the names and the arguments, not these details.
    - Needed by: every client library tethered covers (`tests_containers/suites/clients`). The `None` address by asyncio's selector transports, which write with `sendmsg()` from Python 3.12 (`tests_containers/suites/uvicorn`, a large response; changelog 1.0.0, Security).
    - Pinned by: `TestSocketEvents`; the `sendmsg()` form by `TestAddressShapes::test_a_connected_socket_can_sendmsg_under_a_policy` in `tests/test_core.py`.
- **The import event.** While a policy that is not log-only is active, `_refuse_import` raises `ImportError` at the `import` event of `uvloop`, `uvloop.loop`, `pycares` or `pycares._cares`.
    - Relies on: CPython raising `import` with the absolute name of a module that is not in `sys.modules` yet, before it looks for it; `importlib.import_module("uvloop")` raising no event for the package itself, only for what its `__init__` imports; the names of the extension modules inside uvloop and pycares, which are theirs to change; and what the code that prefers them does with the `ImportError`: uvicorn and its gunicorn worker take the standard event loop, aiohttp its threaded resolver.
    - Needed by: uvicorn, which runs on uvloop whenever it is installed, and aiohttp with aiodns installed (`tests_containers/suites/uvicorn`, `gunicorn_uvicorn`, `fastapi`, `hypercorn`, `granian`, `sanic`, `aiohttp`, `clients`; changelog 1.0.0, Breaking changes).
    - Pinned by: `TestUvloopRefusal` and `TestPycaresRefusal` in `tests/test_core.py`, which import stand-in packages for real; the libraries themselves by the container suites.
- **The end of site's work.** The C guardian lets an interpreter join a locked policy only until that interpreter raises the `import` event for `sitecustomize`.
    - Relies on: `site.main()` importing `sitecustomize` after it has run the import lines of the `.pth` files (and, from Python 3.15, the entry points of the `.start` files), raising the event whether or not the module exists, in every interpreter it starts, a subinterpreter before the call that creates it returns; and on no such event in a process that runs with `-S`.
    - Needed by: interpreters created under a lock: mod_wsgi's application groups, uWSGI's mounted applications, `InterpreterPoolExecutor` (`tests_containers/suites/modwsgi`, `uwsgi`, `stdlib_pools`; changelog 1.0.0, Breaking changes, Locked mode).
    - Pinned by: `TestSiteStartup`; `TestJoinedInterpreter` and `TestAProcessWithoutSite` in `tests/test_subinterpreters.py`.
- **The launch events.** `_handle_subprocess` classifies a launch and establishes the policy in its environment at `subprocess.Popen`, `os.exec`, `os.posix_spawn`, `os.spawn`, `os.system`, `os.startfile`, `_winapi.CreateProcess` and `_posixsubprocess.fork_exec`.
    - Relies on: their arguments. `subprocess.Popen` carries `(executable, args, cwd, env)`; `os.exec` and `os.posix_spawn` carry `(path, args, env)`; `os.spawn`, raised on Windows only, carries `(mode, path, args, env)`; `_winapi.CreateProcess` carries `(application_name, command_line, current_directory)`, without the environment and, on CPython 3.11–3.15, with a command line that arrives garbled; `_posixsubprocess.fork_exec`, raised from Python 3.14, carries `(executables, args, env)`, the environment as `b"NAME=value"` entries. And on `subprocess` raising a second event for its own launches (`_winapi.CreateProcess`, `_posixsubprocess.fork_exec` or `os.posix_spawn`) with `_execute_child` on the stack, which is how such a launch is handled once.
    - Needed by: every launch; the two native events by multiprocessing and `ProcessPoolExecutor`, whose workers raise no `subprocess.Popen` (`tests_containers/suites/stdlib_pools`; changelog 1.0.0, Security).
    - Pinned by: `TestLaunchEvents`; the garbled command line by `test_real_create_process_event_does_not_carry_the_command_line`, and real pools by `test_spawn_worker_is_protected_after_a_whitelist_cleanup`, both in `TestLaunchesThatBypassPopen` in `tests/test_subprocess.py`.
- **The file and environment events.** Under a lock, `_handle_pth_fs_op` and the guardian's pre-filter find the paths of `open`, `os.remove`, `os.rename`, `os.link`, `os.symlink`, `os.chmod`, `os.truncate` and `_winapi.CopyFile2`, and `_handle_env_change` and the guardian the name of `os.putenv` and `os.unsetenv`.
    - Relies on: `open` carrying `(path, mode, flags)`, with `None` for the mode of `os.open()`; `os.remove` carrying `(path, dir_fd)`, and `os.unlink()` raising it; `os.rename` (also raised by `os.replace()`) and `os.link` carrying `(src, dst, src_dir_fd, dst_dir_fd)`; `os.symlink` carrying `(src, dst, dir_fd)`; `os.chmod` `(path, mode, dir_fd)`; `os.truncate` `(path, length)`; `_winapi.CopyFile2` `(existing, new, flags)`, through which `shutil.copy2()` writes on Windows from Python 3.12; `os.putenv` and `os.unsetenv` carrying `(name, value)` and `(name,)`, bytes on POSIX and `str` on Windows, also for a change made through `os.environ`, which raises them before it changes.
    - Needed by: pip, `shutil.rmtree()` and uv's hard links, which reach the hook through names the guard has to recognise (changelog 1.0.0, Security), and every change to the policy variable.
    - Pinned by: `TestFileAndEnvironmentEvents`; the guard on real operations by `TestPthGuardByAnotherName` and `TestStartFileGuard` in `tests/test_guardian.py`.

### Frames, code objects and private names

- **The env of _execute_child.** For a `subprocess.Popen` launch whose environment has to change (an active scope, a missing policy variable), `_inject_launch_env` writes a new mapping into the `env` local of the `_execute_child` frame.
    - Relies on: the event being raised by `subprocess.Popen._execute_child`, a function of that name in the module `subprocess`, which keeps the environment in a local named `env` and reads it after the event; on Python 3.13 and later on the write-through `frame.f_locals` of PEP 667, and on 3.11–3.12 on `ctypes.pythonapi.PyFrame_LocalsToFast`, a C function that PEP 667 deprecates.
    - Needed by: a scope that a Python child has to inherit (`tests_containers/suites/gunicorn`, `uvicorn` and `celery`, `test_scopes.py`; changelog 0.5.0, Added), and an explicit environment without the variable, which ordinary code passes: `ctypes.util.find_library()` runs `ldconfig` with one, which under a lock refused `import trio`, asyncssh and psycopg 3 (`tests_containers/suites/clients`, `modwsgi`, `uwsgi`; changelog 1.0.0, Fixed).
    - Pinned by: `TestLaunchEvents::test_popen_is_raised_in_execute_child_which_reads_env_afterwards`; `TestFrameMutationHelpers` and `TestScopeSubprocessPropagation` in `tests/test_subprocess.py`.
- **An exec carried out for the caller.** For an `os.exec*` of this interpreter whose environment lacks the policy variable or an active scope, `_exec_with_policy` makes the call itself, from inside the hook, with a completed copy of the environment.
    - Relies on: `os.exec*` having converted the environment by the time it raises its event, so that nothing written to the caller's mapping arrives; an `os.execve()` made from inside an audit hook replacing the process like the caller's own call would; and its `OSError`, if it fails, leaving the hook as the caller's own error, which `os.execvp*()` takes to try the next directory of `PATH`.
    - Needed by: gunicorn's binary upgrade (`SIGUSR2`) under `--preload` with a locked policy (`tests_containers/suites/gunicorn`, `test_upgrade.py`), and gevent's `Popen`, which forks and calls `os.exec*` from Python, for a scope (`tests_containers/suites/gunicorn_gevent` and `celery`, `test_scopes.py`; changelog 1.0.0, Fixed).
    - Pinned by: `TestExecWithPolicy` and `TestExecCarriesTheScope` in `tests/test_subprocess.py`, which exec for real in a child process on POSIX; the event by `TestLaunchEvents::test_exec_carries_path_argv_and_environment`.
- **multiprocessing's Windows spawner.** For a `_winapi.CreateProcess` from `multiprocessing.popen_spawn_win32`, `_resolve_winapi_launch` reads the worker's environment from the spawner's frame and completes it in place.
    - Relies on: `Popen.__init__` of that module keeping the environment in a local named `env` and passing it to `_winapi.CreateProcess`, which reads it after its audit event; and on the spawner launching `sys._base_executable`, a private name, with `__PYVENV_LAUNCHER__` set to `sys.executable` inside a virtual environment (bpo-35797). Windows only.
    - Needed by: multiprocessing and `ProcessPoolExecutor` workers on Windows, in a virtual environment under `external_subprocess_policy="block"` (changelog 1.0.0, Security).
    - Pinned by: `TestWindowsSpawner`; real pools by `TestLaunchesThatBypassPopen::test_multiprocessing_pool_keeps_working` in `tests/test_subprocess.py`.
- **Other copies of that spawner.** When the base interpreter is launched from anywhere else, `_find_venv_launcher_env` looks among the locals of the calling frame for a mapping with `__PYVENV_LAUNCHER__` set to `sys.executable`.
    - Relies on: joblib's loky and billiard keeping their copy of the spawner's environment in a local of the frame that calls `_winapi.CreateProcess`, under any name. Windows only, inside a virtual environment.
    - Needed by: joblib's process pools and billiard on Windows, whose workers were refused under `"block"` (checked by hand against joblib 1.6.0; no container suite runs on Windows).
    - Pinned by: `TestLaunchesThatBypassPopen::test_third_party_venv_spawn_is_a_launch_of_sys_executable` in `tests/test_subprocess.py`, with a stand-in for the library.
- **socketpair()'s own connection.** `_is_own_socketpair_connect` lets through the loopback connection with which `socket.socketpair()` joins its two sockets where the platform has no `socketpair()` of its own.
    - Relies on: `socket.socketpair` being CPython's fallback on Windows (`socket._fallback_socketpair`, which older patch releases such as 3.11.9 do not name apart), whose code object tethered takes when it is imported; that function listening on 127.0.0.1 or ::1 in a local named `lsock` and calling `connect()` from its own frame, three frames above `_is_own_socketpair_connect`; and `getsockopt(SO_ACCEPTCONN)`, which Windows and Linux answer and macOS does not.
    - Needed by: every asyncio event loop on Windows under a policy or scope with `allow_localhost=False` (changelog 1.0.1, Fixed).
    - Pinned by: `TestSocketpairFallback`; `TestSocketpairOnLoopback` in `tests/test_core.py`, with the `needs_listening` mark for macOS.
- **The caller of resolve().** The C guardian's `resolve()` serves only `_handle_getaddrinfo` and `_fallback_resolve`, which it recognises by the code object of the frame that calls it.
    - Relies on: `PyEval_GetFrame()`, called in a C function that Python code calls, returning that Python function's frame.
    - Needed by: locked mode's own lookups, which a replaced `_socket.getaddrinfo` or a set reentrancy flag must not take over (changelog 0.5.0, Changed, and 1.0.0, Security).
    - Pinned by: `TestResolverWindow` and `TestContextVarTamperDetection` in `tests/test_guardian.py`.
- **_socket under gevent and eventlet.** tethered resolves names through `_socket.getaddrinfo`, and reads sockets through the methods of `_socket.socket`, never through the `socket` module.
    - Relies on: gevent and eventlet patching the `socket` module and leaving `_socket` alone.
    - Needed by: gunicorn's gevent workers and Celery's gevent and eventlet pools (`tests_containers/suites/gunicorn_gevent`, `celery`; changelog 0.5.0, Fixed).
    - Pinned by: the container suites.
- **Locks after fork.** In a forked child, `_reinit_locks_after_fork` resets tethered's locks in place with `_at_fork_reinit()`, and leaves a re-entrant lock alone when `_is_owned()` says the forking thread holds it.
    - Relies on: those two private methods of the lock types of `_thread`, which `threading` and `logging` use for the same purpose. POSIX only, where they exist.
    - Needed by: a process that forks while another thread holds one of tethered's locks (changelog 1.0.0, Fixed).
    - Pinned by: `test_lock_types_can_be_reset_after_a_fork`; `TestLocksAfterFork` in `tests/test_lifecycle.py`, which forks for real.
- **The fork server's process.** `_warn_if_fork_server_runs` reads `multiprocessing.forkserver._forkserver._forkserver_pid`, a private attribute, to see whether a fork server was started before the policy.
    - Relies on: that attribute being `None` until the fork server runs and its process ID after. POSIX only.
    - Needed by: pools of the `forkserver` start method, the default on Linux from Python 3.14 (`tests_containers/suites/stdlib_pools`; changelog 1.0.0, Added).
    - Pinned by: `test_the_fork_server_keeps_its_pid_where_tethered_reads_it`.
- **The running Proactor loop.** For its warning, `_proactor_loop_running` asks `asyncio._get_running_loop()` whether the loop that runs is an `asyncio.proactor_events.BaseProactorEventLoop`.
    - Relies on: those two names, and on the Proactor loop raising no `socket.connect` / `socket.sendto` event. Windows only.
    - Needed by: asyncio on Windows, whose default loop is the Proactor loop (changelog 1.0.0, Added).
    - Pinned by: `TestProactorLoopWarning` in `tests/test_core.py`.
- **Which interpreter this is.** `_in_subinterpreter`, in the bootstrap, tells a subinterpreter from the main interpreter, so that an inherited locked policy is established unlocked there when no lock is held.
    - Relies on: the private modules `_interpreters` (Python 3.13+) and `_xxsubinterpreters` (3.11–3.12), whose `get_current()` and `get_main()` return an interpreter ID, from 3.13 as an `(id, whence)` pair.
    - Needed by: subinterpreters that inherit a locked policy in a process that holds no lock (changelog 1.0.0, Breaking changes, Child processes).
    - Pinned by: `TestInterpreters`.

### Interpreter startup

- **The .pth import line.** The bootstrap is the one line of `tethered.pth`, `import os; "_TETHERED_CHILD_POLICY" in os.environ and __import__("tethered._autoactivate")`; a child that cannot establish a locked or fail-closed policy raises `SystemExit` there.
    - Relies on: `site.py` executing a line of a `.pth` file that begins with `import` in every site directory it processes, in every interpreter it starts, subinterpreters included, up to Python 3.17 (PEP 829: 3.18 ignores such lines); reporting any other exception from it and going on, while `SystemExit` ends the start of the interpreter; and, up to 3.14, reading a virtual environment's site-packages twice, which runs the line twice, the second time with nothing to import.
    - Needed by: every Python child process and every new interpreter that inherits a policy (changelog 0.5.0, Added; 1.0.0, Breaking changes, Child processes).
    - Pinned by: `TestSiteStartup`; `TestAutoactivateIntegration` and `TestChildStartupFailsClosed` in `tests/test_autoactivate.py`.
- **A .start file beside it.** `_start_file_beside` takes a `tethered.start` beside the hook for a hook that is switched off, and the locked-mode guard refuses to create one.
    - Relies on: PEP 829 as Python 3.15 implements it: the import lines of `<name>.pth` are not run while a `<name>.start` file lies beside it, whatever that file holds. `site.py` passes over a hidden `.start` file and one it cannot read; tethered counts those as switching the hook off.
    - Needed by: a hook that must not be switched off without anyone noticing (changelog 1.0.0, Security).
    - Pinned by: `test_cpython_ignores_a_pth_import_line_beside_a_start_file` in `tests/test_guardian.py`. What a `tethered.start` of tethered's own would rely on, an entry point that can end the start of the interpreter, by `TestSiteStartup::test_system_exit_from_a_start_entry_point_stops_startup`.
- **Where site.py looks.** `_pth_candidates` and `_is_user_site_pth` find the hook where `site.py` would run it, and `_is_bootstrap_file` reads it as `site.py` does.
    - Relies on: `site.getsitepackages()` accepting a list of prefixes (an undocumented parameter), `site.PREFIXES`, `site.ENABLE_USER_SITE`, `site.USER_SITE` and `sys.flags.no_site`, and on `.pth` files being read as UTF-8 with an optional byte-order mark.
    - Needed by: finding the hook, which an editable or `--target` install does not have (changelog 1.0.0, Security).
    - Pinned by: `TestComputePthPath` and `TestBootstrapFile` in `tests/test_subprocess.py`.

### The command line of a child

- **The interpreter's options.** `_interpreter_flags` reads the options of a launch of this interpreter the way CPython does, to find `-S`, `-s` and `-I`. An option it does not know makes the launch an external one.
    - Relies on: the options CPython accepts (`Python/getopt.c`), the same in 3.11–3.15.
    - Needed by: every Python child; a misread option made launches external, or let `-S` through (changelog 1.0.0, Fixed and Security).
    - Pinned by: `test_every_option_the_interpreter_lists_is_one_tethered_parses`.
- **Windows command lines.** `_parse_windows_cmdline` splits a command line the way the Microsoft C runtime does, and `_join_windows_argv` joins the argument list of `os.spawn*` / `os.exec*` the way the C runtime does on Windows.
    - Relies on: the C runtime's rules for splitting, and its joining of those argument lists with spaces, without quoting. Windows only.
    - Needed by: finding `-S` in a Windows launch (changelog 1.0.0, Security).
    - Pinned by: `test_windows_cmdline_split_matches_real_child` in `tests/test_subprocess.py`; `test_windows_spawn_joins_its_arguments_unquoted`.
- **An interpreter that embeds Python.** `_sys_executable_is_python` takes an interpreter whose `sys.orig_argv` is empty and whose `sys.executable` is not named like an interpreter for one that a program embeds.
    - Relies on: an embedded interpreter having no command line in `sys.orig_argv`, and uWSGI leaving the path of its own binary in `sys.executable`.
    - Needed by: uWSGI without `--py-sys-executable` (`tests_containers/suites/uwsgi`; changelog 1.0.0, Security).
    - Pinned by: the uwsgi suite; `TestSysExecutableThatIsNotPython` in `tests/test_subprocess.py`.

### Below Python: the C guardian

- **The process environment.** `process_policy_env()` reads `_TETHERED_CHILD_POLICY` from the environment of the process with `getenv` or `GetEnvironmentVariableW`, for the launch check under a lock and for the bootstrap of a new interpreter.
    - Relies on: that being the environment a child that is given none inherits, and `os.environ` being a copy each interpreter takes when it starts.
    - Needed by: a process with several interpreters, and a change made below Python (changelog 1.0.0, Security).
    - Pinned by: `TestProcessEnvironmentUnderALock` in `tests/test_subprocess.py`; `TestBootstrapTakesItsTurn` in `tests/test_autoactivate.py`.
- **Interpreter IDs and hooks.** The guardian knows the lock holder, the joined interpreters and the startup windows by interpreter ID, and records which interpreters existed when its hook was added.
    - Relies on: `PyInterpreterState_GetID()` giving out IDs in ascending order and never twice; `PyInterpreterState_Head()` / `PyInterpreterState_Next()` listing the interpreters; a hook added with `PySys_AddAuditHook()` being called for the events of every interpreter of the process, while one added with `sys.addaudithook()` belongs to one interpreter.
    - Needed by: a lock in a process with several interpreters (`tests_containers/suites/modwsgi`, `uwsgi`, `stdlib_pools`; changelog 1.0.0, Breaking changes, Locked mode).
    - Pinned by: `TestInterpreters::test_an_interpreter_id_is_never_given_out_twice`; `TestLockedPolicy` and `TestTakingTurns` in `tests/test_subinterpreters.py`.
- **Shutdown.** A thread that waits for the activation claim stops waiting when the runtime shuts down.
    - Relies on: `Py_IsFinalizing()`, public from Python 3.13, and before that `Py_IsInitialized()` turning false in the same step.
    - Needed by: an `activate()` or `deactivate()` that is under way in another thread while Python shuts down.
    - Pinned by: `TestActivationClaim` in `tests/test_lifecycle.py`.
- **A hook that is refused.** `_install_hook()` and the guardian confirm that their audit hook was added with a private probe event.
    - Relies on: `sys.addaudithook()` and `PySys_AddAuditHook()` dropping a new hook without an error when an existing hook raises `RuntimeError` for the `sys.addaudithook` event, as documented.
    - Needed by: a process in which another audit hook refuses new ones (changelog 1.0.0, Breaking changes).
    - Pinned by: `TestHookInstallation` in `tests/test_lifecycle.py` and in `tests/test_guardian.py`, with a refusing hook in a child process.

### Other libraries

- **asyncio's lookups in a thread.** While any scope is active in the process, `_audit_hook` records a lookup that is made in a context with no policy and no scope.
    - Relies on: `loop.getaddrinfo()` of asyncio's selector loop calling `socket.getaddrinfo` in an executor thread that does not carry the caller's context.
    - Needed by: `scope()` under asyncio (`tests_containers/suites/uvicorn`, `test_scopes.py`; changelog 1.0.0, Fixed).
    - Pinned by: `TestScopeUnderAsyncio` and `TestActiveScopeCount` in `tests/test_core.py`.
- **tethered's own lookups.** `_handle_getaddrinfo` resolves an allowed name a second time to learn its addresses, and `_fallback_resolve` resolves recently allowed names again when a connection goes to an address it does not know.
    - Relies on: the two lookups of one name returning the same addresses. A caching stub between the process and the upstream makes them agree for any TTL above 0; without one, a name whose answers change from query to query diverges, and the fallback search repairs only part of it ([measured](security.md#known-residual-dns-divergence)).
    - Needed by: load-balanced hosts (changelog 0.5.0, Fixed).
    - Pinned by: `TestFallbackResolve` in `tests/test_core.py`; measured with `benchmarks/dns_lookups.py`.
