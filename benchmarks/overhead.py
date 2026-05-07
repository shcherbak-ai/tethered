"""tethered overhead benchmark.

Standalone, zero-dependency benchmark measuring practical overhead introduced
by ``tethered.activate()`` and ``tethered.scope()``.

Sections:
    1. socket.connect           — headline workload (TCP connect to a tiny
                                   accept-and-close listener on 127.0.0.1
                                   running in a daemon thread).  The audit
                                   hook fires before the syscall returns,
                                   so this measures the full hook + connect
                                   path.  The listener sleeps in accept(),
                                   so GIL contention is negligible at these
                                   iteration counts.
    2. Per-event microbenchmarks — socket.getaddrinfo and synthetic sys.audit.
    3. Allow-list scaling        — 10/100/1000 IP entries, target IP last,
                                   ``allow_localhost=False`` forces the
                                   linear network-rules scan.
    4. Cold start + memory        — fresh-interpreter import + activate cost
                                   and RSS deltas, in a subprocess.

Usage::

    uv run python benchmarks/overhead.py
    uv run python benchmarks/overhead.py --iterations 50000

Numbers are hardware-, OS-, and Python-version-dependent.  Reproduce twice
and compare; on a quiet laptop variance is typically < 5%.
"""

from __future__ import annotations

import argparse
import os
import platform
import socket
import struct
import subprocess  # nosec B404 — used only to spawn a fresh interpreter for cold-start timing
import sys
import threading
import time
from typing import TYPE_CHECKING

import tethered

if TYPE_CHECKING:
    from collections.abc import Callable


# SO_LINGER with l_onoff=1, l_linger=0 sends RST on close instead of FIN.
# Avoids TIME_WAIT ephemeral-port exhaustion at high connect rates on Windows.
_LINGER_RST = struct.pack("ii", 1, 0)


def _measure(fn: Callable[[], None], iterations: int) -> float:
    for _ in range(min(100, iterations)):
        fn()
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    elapsed = time.perf_counter() - start
    return (elapsed / iterations) * 1_000_000


def _measure_median(fn: Callable[[], None], iterations: int) -> float:
    # Median of 3 independent runs.  Used for the TCP-connect workload, where
    # a ~700 µs Windows baseline drowns the 5-30 µs hook-overhead deltas in
    # correlated noise (background system load) — increasing iteration count
    # alone helps less than 1/sqrt(N) predicts.  Median rejects whichever
    # single run got hit by a load spike instead of averaging it in.
    samples = sorted(_measure(fn, iterations) for _ in range(3))
    return samples[1]


# TCP loopback fixture -------------------------------------------------------


def _start_listener() -> int:
    # Start a TCP listener on a random localhost port and accept-and-close
    # connections in a daemon thread.  This makes connect() return promptly
    # on every OS — Windows in particular returns ECONNREFUSED slowly when
    # the kernel SYN-retransmits to a port with no listener (multi-second
    # per call).  The thread sleeps in accept(), releasing the GIL, so
    # contention is negligible.  Daemon thread => exits with the process;
    # no explicit teardown.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]

    def _serve() -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            conn.close()

    threading.Thread(target=_serve, name="tethered-bench-listener", daemon=True).start()
    return port


def _make_tcp_call(port: int) -> Callable[[], None]:
    addr = ("127.0.0.1", port)

    def call() -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, _LINGER_RST)
            s.connect(addr)
        finally:
            s.close()

    return call


# Per-event workloads --------------------------------------------------------


def _getaddrinfo_call() -> None:
    socket.getaddrinfo("localhost", 0, type=socket.SOCK_DGRAM)


def _audit_noop_call() -> None:
    sys.audit("tethered.bench.noop", None)


# Sections 1 + 2: workloads across activation modes --------------------------


def _bench_modes(port: int, tcp_iter: int, per_event_iter: int) -> dict[str, dict[str, float]]:
    # (name, fn, iterations, supports_scope, measure_func)
    tcp_call = _make_tcp_call(port)
    workloads: list[tuple[str, Callable[[], None], int, bool, Callable[..., float]]] = [
        ("socket.connect (127.0.0.1)", tcp_call, tcp_iter, True, _measure_median),
        ("socket.getaddrinfo (localhost)", _getaddrinfo_call, per_event_iter, True, _measure),
        ("sys.audit (synthetic event)", _audit_noop_call, per_event_iter, False, _measure),
    ]

    results: dict[str, dict[str, float]] = {name: {} for name, *_ in workloads}

    # Phase 1: deactivated.  MUST run first — the audit hook is not yet
    # installed.  Once activate() runs the hook stays installed permanently
    # (no-op after deactivate), and a re-measured deactivated baseline would
    # silently include the hook-dispatch tax.
    print("  phase 1/4: deactivated...", flush=True)
    for name, fn, n, _, measure in workloads:
        results[name]["deactivated"] = measure(fn, n)

    print("  phase 2/4: activated...", flush=True)
    tethered.activate(allow=["127.0.0.1", "localhost"])
    try:
        for name, fn, n, _, measure in workloads:
            results[name]["activated"] = measure(fn, n)
        print("  phase 3/4: activated + scope...", flush=True)
        with tethered.scope(allow=["127.0.0.1", "localhost"]):
            for name, fn, n, supports_scope, measure in workloads:
                if supports_scope:
                    results[name]["activated + scope"] = measure(fn, n)
    finally:
        tethered.deactivate()

    print("  phase 4/4: activated + locked...", flush=True)
    token = object()
    tethered.activate(allow=["127.0.0.1", "localhost"], locked=True, lock_token=token)
    try:
        for name, fn, n, _, measure in workloads:
            results[name]["activated + locked"] = measure(fn, n)
    finally:
        tethered.deactivate(lock_token=token)

    return results


def _bench_scope_enter_exit(iterations: int) -> float:
    cm = tethered.scope(allow=["127.0.0.1"])

    def call() -> None:
        with cm:
            pass

    return _measure(call, iterations)


# Section 3: allow-list scaling ---------------------------------------------


def _bench_allowlist_scaling(port: int, iterations: int) -> dict[int, float]:
    # Single-run measurement is sufficient — the deltas between sizes 10 / 100
    # / 1000 are large (linear in list length), so single-run noise never
    # flips the trend.  Median-of-3 here would just triple runtime.
    call = _make_tcp_call(port)
    results: dict[int, float] = {}
    for size in (10, 100, 1000):
        print(f"  size {size}...", flush=True)
        # (size-1) unique single-host /32 networks in 10.x.x.x range, then
        # 127.0.0.1 last.  With allow_localhost=False the connect-time IP
        # check walks every entry before matching.
        dummies = [f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}" for i in range(size - 1)]
        allow = [*dummies, "127.0.0.1"]
        tethered.activate(allow=allow, allow_localhost=False)
        try:
            results[size] = _measure(call, iterations)
        finally:
            tethered.deactivate()
    return results


# Section 4: cold start + memory --------------------------------------------


_COLD_START_CODE = """
import sys, time, gc

def get_rss_kb():
    try:
        import resource
    except ImportError:
        return None
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss // 1024 if sys.platform == "darwin" else rss

rss_pre = get_rss_kb()
t0 = time.perf_counter()
import tethered
t1 = time.perf_counter()
rss_imported = get_rss_kb()

tethered.activate(allow=["127.0.0.1"])
t2 = time.perf_counter()
rss_activated = get_rss_kb()
tethered.deactivate()
gc.collect()

token = object()
t3 = time.perf_counter()
tethered.activate(allow=["127.0.0.1"], locked=True, lock_token=token)
t4 = time.perf_counter()
rss_locked = get_rss_kb()

print(
    f"{(t1-t0)*1000:.4f} {(t2-t1)*1000:.4f} {(t4-t3)*1000:.4f} "
    f"{rss_pre} {rss_imported} {rss_activated} {rss_locked}"
)
"""


def _bench_cold_start_and_memory() -> dict[str, float | int | None]:
    # Strip _TETHERED_CHILD_POLICY so the child interpreter doesn't auto-
    # activate at startup (which would change what we're measuring).
    env = {k: v for k, v in os.environ.items() if k != "_TETHERED_CHILD_POLICY"}

    # Single run.  The result is a slight over-estimate (cold fs cache, cold
    # bytecode), which is the honest "what users see on first import" number
    # rather than a "warm interpreter" idealization.
    result = subprocess.run(  # nosec B603 — argv is sys.executable + literal benchmark code, no untrusted input
        [sys.executable, "-c", _COLD_START_CODE],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    parts = result.stdout.strip().split()

    def _opt_int(s: str) -> int | None:
        return None if s == "None" else int(s)

    return {
        "import_ms": float(parts[0]),
        "activate_ms": float(parts[1]),
        "activate_locked_ms": float(parts[2]),
        "rss_pre_kb": _opt_int(parts[3]),
        "rss_imported_kb": _opt_int(parts[4]),
        "rss_activated_kb": _opt_int(parts[5]),
        "rss_locked_kb": _opt_int(parts[6]),
    }


# Printing ------------------------------------------------------------------


def _print_header() -> None:
    print("=" * 72)
    print("tethered overhead benchmark")
    print("=" * 72)
    print(f"Python      : {platform.python_implementation()} {platform.python_version()}")
    print(f"Platform    : {platform.platform()}")
    version = getattr(tethered, "__version__", "(unknown)")
    print(f"tethered    : {version}")
    print()


def _print_workload(name: str, modes: dict[str, float]) -> None:
    print(name)
    baseline = modes.get("deactivated")
    width = max(len(m) for m in modes)
    for mode, per_us in modes.items():
        delta = ""
        if baseline is not None and mode != "deactivated":
            diff = per_us - baseline
            sign = "+" if diff >= 0 else ""
            delta = f"  ({sign}{diff:.2f} µs)"
        print(f"  {mode:<{width}} : {per_us:>10.3f} µs/call{delta}")
    print()


def _print_scaling(scaling: dict[int, float]) -> None:
    print("Allow-list scaling — socket.connect, target IP last in list")
    print("(allow_localhost=False; walks _network_rules linearly)")
    print()
    smallest = next(iter(scaling.values()))
    print(f"  {'list size':<12} {'time per call':<22} delta vs size 10")
    print(f"  {'-' * 9:<12} {'-' * 13:<22} {'-' * 16}")
    for size, per_us in scaling.items():
        delta = per_us - smallest
        sign = "+" if delta >= 0 else ""
        print(f"  {size:<12,} {per_us:>10.3f} µs/call      {sign}{delta:>8.2f} µs")
    print()


def _print_cold_memory(data: dict[str, float | int | None]) -> None:
    print("Cold start + memory  (fresh subprocess, single run)")
    print()
    print(f"  import tethered                        : {data['import_ms']:>8.3f} ms")
    print(f"  activate(allow=[...])                  : {data['activate_ms']:>8.3f} ms")
    print(f"  activate(allow=[...], locked=True)     : {data['activate_locked_ms']:>8.3f} ms")
    print()

    rss_pre = data["rss_pre_kb"]
    rss_imp = data["rss_imported_kb"]
    rss_act = data["rss_activated_kb"]
    rss_lck = data["rss_locked_kb"]

    if rss_pre is None or rss_imp is None or rss_act is None or rss_lck is None:
        print("  RSS measurement unavailable (Windows lacks resource.getrusage).")
    else:
        d_imp = rss_imp - rss_pre
        d_act = rss_act - rss_imp
        d_lck = rss_lck - rss_imp
        print(f"  RSS pre-import                         : {rss_pre:>8,} KB")
        print(f"  RSS post-import                        : {rss_imp:>8,} KB  (+{d_imp:,} KB)")
        print(
            f"  RSS post-activate                      : "
            f"{rss_act:>8,} KB  (+{d_act:,} KB vs imported)"
        )
        print(
            f"  RSS post-activate(locked)              : "
            f"{rss_lck:>8,} KB  (+{d_lck:,} KB vs imported)"
        )
    print()


def _print_footer() -> None:
    print("Notes")
    print("-----")
    print("- 'deactivated' is measured before any activate() — the audit hook")
    print("  is not yet installed.  After the first activate() the hook stays")
    print("  installed (no-op after deactivate); a re-measured 'deactivated'")
    print("  would silently include the hook-dispatch tax.")
    print("- 'sys.audit (synthetic)' isolates pure per-event hook-dispatch")
    print("  cost: tethered ignores unknown events, so the delta is the")
    print("  ambient tax paid by every audit event in the process.")
    print("- 'socket.connect (127.0.0.1)' calls connect() against a tiny")
    print("  daemon thread that accept()s and closes.  The audit hook fires")
    print("  before the syscall returns, so this measures the full hook +")
    print("  connect path.  The listener sleeps in accept(), releasing the")
    print("  GIL, so contention is negligible at these iteration counts.")
    print("- 'Allow-list scaling' is a worst-case linear walk through")
    print("  _network_rules.  Real allow lists are typically < 50 entries.")
    print("- Numbers are hardware- and OS-dependent.  Reproduce twice and")
    print("  compare; on a quiet laptop variance is typically < 5%.")


# Main ----------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--iterations",
        type=int,
        default=5_000,
        help="iterations for per-event microbenchmarks (default: 5000). "
        "TCP and scaling iterations are 1/10 of this with a 3,000-iteration "
        "floor (default: 3000).  The floor keeps the noise floor below the "
        "~10 µs deltas the benchmark is trying to resolve.",
    )
    args = parser.parse_args()

    per_event_iter = args.iterations
    tcp_iter = max(args.iterations // 10, 3_000)

    _print_header()

    port = _start_listener()

    print(
        f"[1] socket.connect (TCP, accept+close)  ({tcp_iter:,} iter/mode)",
        flush=True,
    )
    print(
        f"[2] Per-event microbenchmarks          ({per_event_iter:,} iter/mode)",
        flush=True,
    )
    print("    Running modes for sections [1] + [2]...", flush=True)
    modes = _bench_modes(port, tcp_iter, per_event_iter)
    print(flush=True)
    print("Section [1] socket.connect (127.0.0.1)", flush=True)
    print()
    _print_workload("socket.connect (127.0.0.1)", modes["socket.connect (127.0.0.1)"])
    print("Section [2] Per-event microbenchmarks", flush=True)
    print()
    _print_workload("socket.getaddrinfo (localhost)", modes["socket.getaddrinfo (localhost)"])
    _print_workload("sys.audit (synthetic event)", modes["sys.audit (synthetic event)"])

    scope_cost = _bench_scope_enter_exit(per_event_iter)
    print(f"  with tethered.scope(...) enter + exit   : {scope_cost:>10.3f} µs/call")
    print(flush=True)

    print(f"[3] Allow-list scaling  ({tcp_iter:,} iter/size)", flush=True)
    scaling = _bench_allowlist_scaling(port, tcp_iter)
    print(flush=True)
    _print_scaling(scaling)

    print("[4] Cold start + memory  (subprocess)", flush=True)
    cold_memory = _bench_cold_start_and_memory()
    print(flush=True)
    _print_cold_memory(cold_memory)

    _print_footer()


if __name__ == "__main__":
    main()
