"""One measurement of the DNS benchmark, in a process of its own.

Benchmark code: ``inside.py`` runs it in the benchmark's container, and
``benchmarks/dns_lookups.py --host-name`` runs it on the host.  Standard
library and tethered only, plus gevent with ``--gevent``.  It prints one line,
``PROBE-RESULT <json>``.

``lookups``
    Times ``socket.getaddrinfo(name, 443, type=SOCK_STREAM)``, the call
    ``socket.create_connection`` makes, one call at a time (or from
    ``--concurrency`` greenlets at once under gevent), with tethered
    deactivated, activated with an allow list that names the host, or locked.
    With ``--fresh`` every call looks up a name not looked up before, so that
    a cache between the process and the upstream never has the answer.

``divergence``
    Looks the load-balanced name up and connects to the first address it
    returns, as ``socket.create_connection`` does, under
    ``activate(allow=[name], allow_localhost=False)``, and counts the connects
    tethered refuses although the name is allowed.  With ``--fresh-state``
    tethered's address map is emptied before each trial (``deactivate()``
    and ``activate()``), which makes every trial the first connection of a
    process; without it the trials run one after another in one process.

``fallback``
    Looks up ``--candidates`` allowed names once each, then times connects to
    an address that no name is known for and the policy does not allow
    (``--target``), deactivated, under a log-only policy (the connect goes
    ahead) and under an enforcing one (it is refused).  tethered searches the
    names it has let through for the address before it decides
    (``_fallback_resolve``), one lookup per name.

A socket that connects does not block: tethered decides before the system
call, and a connect it lets through is under way (``EINPROGRESS``) when
``connect()`` returns, so nothing has to listen on the addresses.  Under
gevent a greenlet that wakes every millisecond measures the longest time the
other greenlets were held up (``max_hub_stall_ms``).

With ``--handshake`` the probe prints ``PROBE-READY`` when the measured part
is about to start and waits for a line on stdin: the caller reads the
upstream's query counts around the measured part, from outside the process,
where tethered does not see it.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import uuid
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable


def _parse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workload", choices=("lookups", "divergence", "fallback"))
    parser.add_argument("--name", default="api.bench.test")
    parser.add_argument("--fresh", action="store_true", help="a new name under --zone each call")
    parser.add_argument("--zone", default="bench.test")
    parser.add_argument(
        "--mode",
        choices=("deactivated", "activated", "log-only", "locked"),
        default="deactivated",
    )
    parser.add_argument("--allow", default=None, help="the allow-list rule (default: the name)")
    parser.add_argument("--iterations", type=int, default=300)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--gevent", action="store_true")
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--fresh-state", action="store_true")
    parser.add_argument("--candidates", type=int, default=30)
    parser.add_argument("--target", default="198.18.255.254")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--handshake", action="store_true")
    return parser.parse_args()


OPTIONS = _parse()
if OPTIONS.gevent:
    # As a gevent application does it: patch first, import the rest after.
    from gevent import monkey  # ty: ignore[unresolved-import] - in the image only

    monkey.patch_all()

import socket  # noqa: E402

import tethered  # noqa: E402

_LOCK_TOKEN = object()


def _ready() -> None:
    if OPTIONS.handshake:
        print("PROBE-READY", flush=True)
        sys.stdin.readline()


def _activate(allow: list[str], *, allow_localhost: bool = True) -> None:
    if OPTIONS.mode in ("activated", "log-only"):
        log_only = OPTIONS.mode == "log-only"
        tethered.activate(allow=allow, allow_localhost=allow_localhost, log_only=log_only)
    elif OPTIONS.mode == "locked":
        tethered.activate(
            allow=allow, allow_localhost=allow_localhost, locked=True, lock_token=_LOCK_TOKEN
        )


def _deactivate() -> None:
    if OPTIONS.mode in ("activated", "log-only"):
        tethered.deactivate()
    elif OPTIONS.mode == "locked":
        tethered.deactivate(lock_token=_LOCK_TOKEN)


class _HubWatch:
    """Under gevent: the longest time a greenlet that wants to run every 1 ms waited."""

    def __init__(self) -> None:
        self.longest = 0.0
        self.greenlet: Any = None

    def __enter__(self) -> _HubWatch:
        if OPTIONS.gevent:
            import gevent  # ty: ignore[unresolved-import] - in the image only

            def tick() -> None:
                last = time.perf_counter()
                while True:
                    gevent.sleep(0.001)
                    now = time.perf_counter()
                    self.longest = max(self.longest, now - last)
                    last = now

            self.greenlet = gevent.spawn(tick)
            gevent.sleep(0.01)
        return self

    def __exit__(self, *exc_info: object) -> None:
        if self.greenlet is not None:
            self.greenlet.kill()

    def pause(self) -> None:
        """Let the other greenlets run, as an application's next blocking call would."""
        if self.greenlet is not None:
            import gevent  # ty: ignore[unresolved-import] - in the image only

            gevent.sleep(0.002)

    def result(self) -> dict[str, float]:
        """The longest wait, when there was a greenlet to measure it."""
        return {"max_hub_stall_ms": self.longest * 1000} if OPTIONS.gevent else {}


def _percentile(samples: list[float], fraction: float) -> float:
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, round(fraction * (len(ordered) - 1)))]


def _summary(samples_ns: list[int]) -> dict[str, float]:
    ms = [sample / 1e6 for sample in samples_ns]
    return {
        "median_ms": statistics.median(ms),
        "p90_ms": _percentile(ms, 0.9),
        "mean_ms": statistics.fmean(ms),
        "min_ms": min(ms),
        "max_ms": max(ms),
    }


def _connect(address: tuple[Any, ...]) -> bool:
    """Connect without blocking: True if tethered refused it."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setblocking(False)
        sock.connect(address)
    except tethered.EgressBlocked:
        return True
    except OSError:
        return False  # EINPROGRESS: let through
    finally:
        sock.close()
    return False


def _lookups() -> dict[str, object]:
    prefix = f"n{uuid.uuid4().hex[:12]}"
    counter = iter(range(10**9))

    def one() -> int:
        target = f"{prefix}-{next(counter)}.{OPTIONS.zone}" if OPTIONS.fresh else OPTIONS.name
        start = time.perf_counter_ns()
        socket.getaddrinfo(target, OPTIONS.port, type=socket.SOCK_STREAM)
        return time.perf_counter_ns() - start

    allow = [OPTIONS.allow or (f"*.{OPTIONS.zone}" if OPTIONS.fresh else OPTIONS.name)]
    _activate(allow)
    try:
        for _ in range(OPTIONS.warmup):
            one()
        _ready()
        with _HubWatch() as watch:
            started = time.perf_counter_ns()
            if OPTIONS.concurrency > 1:
                samples = _concurrently(one, OPTIONS.iterations, OPTIONS.concurrency)
            else:
                samples = [one() for _ in range(OPTIONS.iterations)]
            wall_ns = time.perf_counter_ns() - started
    finally:
        _deactivate()
    return {
        "calls": len(samples),
        "wall_per_call_ms": wall_ns / 1e6 / len(samples),
        **_summary(samples),
        **watch.result(),
    }


def _concurrently(one: Callable[[], int], iterations: int, concurrency: int) -> list[int]:
    import gevent  # ty: ignore[unresolved-import] - in the image only

    samples: list[int] = []
    share, extra = divmod(iterations, concurrency)

    def worker(count: int) -> None:
        for _ in range(count):
            samples.append(one())

    greenlets = [gevent.spawn(worker, share + (i < extra)) for i in range(concurrency)]
    gevent.joinall(greenlets, raise_error=True)
    return samples


def _trial() -> bool | None:
    """Look the name up and connect to its first address: True if refused, None if no answer."""
    try:
        infos = socket.getaddrinfo(OPTIONS.name, OPTIONS.port, type=socket.SOCK_STREAM)
    except OSError:
        return None
    return _connect(infos[0][4])


def _divergence() -> dict[str, object]:
    allow = [OPTIONS.allow or OPTIONS.name]
    refused_at: list[int] = []
    failed = 0
    _ready()
    if not OPTIONS.fresh_state:
        _activate(allow, allow_localhost=False)
    try:
        with _HubWatch() as watch:
            for trial in range(OPTIONS.iterations):
                if OPTIONS.fresh_state:
                    _activate(allow, allow_localhost=False)
                try:
                    outcome = _trial()
                finally:
                    if OPTIONS.fresh_state:
                        _deactivate()
                if outcome is None:
                    failed += 1
                elif outcome:
                    refused_at.append(trial)
                watch.pause()
    finally:
        if not OPTIONS.fresh_state:
            _deactivate()
    return {
        "trials": OPTIONS.iterations,
        "refused": len(refused_at),
        "lookup_failed": failed,
        "first_refusals": refused_at[:10],
        "last_refusal": refused_at[-1] if refused_at else None,
        **watch.result(),
    }


def _fallback() -> dict[str, object]:
    prefix = f"c{uuid.uuid4().hex[:12]}"
    _activate([f"*.{OPTIONS.zone}"])
    try:
        # The names tethered has let through: the candidates of its search.
        for index in range(OPTIONS.candidates):
            socket.getaddrinfo(f"{prefix}-{index}.{OPTIONS.zone}", 443, type=socket.SOCK_STREAM)
        _ready()
        samples: list[int] = []
        refused = 0
        with _HubWatch() as watch:
            for _ in range(OPTIONS.iterations):
                start = time.perf_counter_ns()
                refused += _connect((OPTIONS.target, OPTIONS.port))
                samples.append(time.perf_counter_ns() - start)
                watch.pause()
    finally:
        _deactivate()
    return {
        "calls": len(samples),
        "candidates": OPTIONS.candidates,
        "refused": refused,
        "wall_per_call_ms": sum(samples) / 1e6 / len(samples),
        **_summary(samples),
        **watch.result(),
    }


def main() -> None:
    """Run the workload and print its result."""
    import logging

    # Refusals are what some workloads count, not something to log.
    logging.getLogger("tethered").setLevel(logging.CRITICAL)
    workloads = {"lookups": _lookups, "divergence": _divergence, "fallback": _fallback}
    result = workloads[OPTIONS.workload]()
    result["python"] = sys.version.split()[0]
    result["tethered"] = tethered.__version__
    if OPTIONS.gevent:
        import gevent  # ty: ignore[unresolved-import] - in the image only

        hub = gevent.get_hub()
        result["gevent"] = gevent.__version__
        result["gevent_resolver"] = type(hub.resolver).__module__
        result["gevent_threadpool_size"] = hub.threadpool.maxsize
    print("PROBE-RESULT " + json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
