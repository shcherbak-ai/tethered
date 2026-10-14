"""The DNS benchmark inside its container: start the resolvers, run the probes.

Benchmark code, the entry point of the image ``benchmarks/dns_lookups.py``
builds.  The container has no network (``--network none``): the upstream
(``upstream.py``) listens on an address of a dummy interface that leads
nowhere, the caching stubs on loopback addresses, and ``/etc/resolv.conf`` is
rewritten for each setup, as the setup's host would have it.  Every
measurement runs in a fresh process (``probe.py``), with a freshly started
stub.  The last line printed is ``DNS-BENCH-RESULT <json>``, which the host
script turns into its table.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess  # nosec B404 - the benchmark starts its resolvers and probes
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
UPSTREAM = ("192.0.2.53", 53)
CONTROL = ("192.0.2.53", 5300)
RESOLVED_STUB = "127.0.0.53"
DNSMASQ_STUB = "127.0.2.53"
RESOLVED_BINARY = "/usr/lib/systemd/systemd-resolved"
RESULT_MARKER = "DNS-BENCH-RESULT "
PROBE_MARKER = "PROBE-RESULT "


def _say(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def _write_resolv_conf(text: str) -> None:
    # /etc/resolv.conf is a file Docker mounts: written in place, not replaced.
    with open("/etc/resolv.conf", "w", encoding="ascii") as handle:
        handle.write(text)


def _add_routable_link() -> None:
    """Give the container a network interface that leads nowhere, and the upstream's address.

    systemd-resolved forwards nothing while no interface other than loopback
    is up with an address and a route: it answers every query with a failure
    ("network-down").  A container started with ``--network none`` has only
    loopback, so a dummy interface (which needs ``NET_ADMIN``) stands in for
    the interface any host has.  The upstream listens on an address of that
    interface and not on loopback, as a real upstream is elsewhere:
    systemd-resolved does not cache what a server on a loopback address
    answers (``CacheFromLocalhost=no``, its default).  Every setup runs with
    this, so that they differ in the resolver only.
    """
    for command in (
        ["ip", "link", "add", "bench0", "type", "dummy"],
        ["ip", "addr", "add", "192.0.2.1/24", "dev", "bench0"],
        ["ip", "addr", "add", f"{UPSTREAM[0]}/24", "dev", "bench0"],
        ["ip", "link", "set", "bench0", "up"],
        ["ip", "route", "add", "default", "dev", "bench0"],
    ):
        subprocess.run(command, check=True)  # nosec B603 - fixed commands


def _wait_for_answer(server: str, timeout: float = 15.0) -> None:
    """Wait until ``server`` answers an A query for a name of the zone with an address."""
    import _socket

    query = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x05probe\x05bench\x04test\x00\x00\x01\x00\x01"
    )
    deadline = time.monotonic() + timeout
    last = "no reply"
    while time.monotonic() < deadline:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        try:
            sock.settimeout(0.5)
            sock.sendto(query, (server, 53))
            reply = sock.recv(512)
            rcode, answers = reply[3] & 0x0F, int.from_bytes(reply[6:8], "big")
            if reply[:2] == b"\x12\x34" and rcode == 0 and answers > 0:
                return
            last = f"rcode {rcode}, {answers} answers"
        except OSError as error:
            last = str(error)
        finally:
            sock.close()
        time.sleep(0.1)
    raise RuntimeError(f"no DNS answer from {server} within {timeout} s ({last})")


def _package_version(package: str) -> str | None:
    try:
        done = subprocess.run(  # nosec B603 B607 - a fixed command
            ["dpkg-query", "-W", "-f", "${Version}", package],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    return done.stdout.strip() or None


class Stub:
    """A caching stub resolver between glibc and the upstream, or none."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.process: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        """Start the stub and point ``/etc/resolv.conf`` at it."""
        if self.kind == "none":
            # A slim image: glibc's stub resolver asks the upstream itself.
            _write_resolv_conf(f"nameserver {UPSTREAM[0]}\n")
            return
        if self.kind == "systemd-resolved":
            Path("/etc/systemd/resolved.conf").write_text(
                "[Resolve]\n"
                f"DNS={UPSTREAM[0]}\n"
                "Domains=~.\n"
                "DNSSEC=no\n"
                "DNSOverTLS=no\n"
                "LLMNR=no\n"
                "MulticastDNS=no\n"
                "Cache=yes\n"
                "DNSStubListener=yes\n",
                encoding="ascii",
            )
            # Without systemd, nobody makes its runtime directory over to its
            # user, and it refuses to start in one that root owns.
            runtime = Path("/run/systemd/resolve")
            runtime.mkdir(parents=True, exist_ok=True)
            shutil.chown(runtime, "systemd-resolve", "systemd-resolve")
            self.process = subprocess.Popen(  # nosec B603 - a fixed command
                [RESOLVED_BINARY],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _wait_for_answer(RESOLVED_STUB)
            # What Ubuntu's /etc/resolv.conf links to: the file resolved writes.
            _write_resolv_conf((runtime / "stub-resolv.conf").read_text(encoding="ascii"))
            return
        if self.kind == "dnsmasq":
            self.process = subprocess.Popen(  # nosec B603 B607 - a fixed command
                [
                    "dnsmasq",
                    "--keep-in-foreground",
                    "--no-resolv",
                    "--no-hosts",
                    f"--server={UPSTREAM[0]}",
                    f"--listen-address={DNSMASQ_STUB}",
                    "--bind-interfaces",
                    "--cache-size=1000",
                    "--pid-file",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _wait_for_answer(DNSMASQ_STUB)
            _write_resolv_conf(f"nameserver {DNSMASQ_STUB}\n")
            return
        raise ValueError(self.kind)

    def stop(self) -> None:
        """Stop the stub; its cache goes with it."""
        if self.process is not None:
            self.process.terminate()
            self.process.wait(timeout=10)
            self.process = None


def _upstream_counts(command: str) -> dict[str, int]:
    """Send ``reset`` or ``stats`` to the upstream's control port; returns its counts."""
    import _socket

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        sock.settimeout(5)
        sock.sendto(command.encode("ascii"), CONTROL)
        return json.loads(sock.recv(65536))
    finally:
        sock.close()


def _probe(arguments: list[str], timeout: float) -> dict[str, object]:
    """Run one probe; its result, with the upstream queries of its measured part."""
    command = [sys.executable, str(HERE / "probe.py"), *arguments, "--handshake"]
    process = subprocess.Popen(  # nosec B603 - the interpreter and the benchmark's own probe
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdin is not None and process.stdout is not None  # nosec B101 - PIPE
    watchdog = threading.Timer(timeout, process.kill)
    watchdog.start()
    output: list[str] = []
    result: dict[str, object] | None = None
    try:
        for line in process.stdout:
            output.append(line)
            if line.startswith("PROBE-READY"):
                # The measured part starts: count from here, from outside the
                # process, where tethered does not see the counter.
                _upstream_counts("reset")
                process.stdin.write("go\n")
                process.stdin.flush()
            elif line.startswith(PROBE_MARKER):
                result = json.loads(line[len(PROBE_MARKER) :])
        process.wait()
    finally:
        watchdog.cancel()
    if result is None or process.returncode != 0:
        raise RuntimeError(
            f"probe {' '.join(arguments)} failed ({process.returncode}):\n{''.join(output)}"
        )
    result["upstream"] = _upstream_counts("stats")
    return result


SETUPS = (
    # (setup, caching stub, gevent)
    ("no cache", "none", False),
    ("gevent, no cache", "none", True),
    ("systemd-resolved", "systemd-resolved", False),
    ("dnsmasq", "dnsmasq", False),
)


def _plan(options: argparse.Namespace) -> list[dict[str, object]]:
    """Every measurement, in order: what it is, and the arguments of its probe."""
    n = str(options.iterations)
    trials = str(options.trials)
    plan: list[dict[str, object]] = []

    def add(setup: str, stub: str, arguments: list[str], **what: object) -> None:
        plan.append({"setup": setup, "stub": stub, "arguments": arguments, **what})

    for setup, stub, gevent in SETUPS:
        green = ["--gevent"] if gevent else []
        modes = ["deactivated", "activated"]
        if stub == "none" and not gevent:
            modes.append("locked")
        # One name, looked up again and again (its TTL is 300 s): a service
        # that calls one API.
        for mode in modes:
            arguments = ["lookups", "--iterations", n, *green, "--mode", mode]
            add(setup, stub, arguments, kind="lookups", workload="one name", mode=mode)
        # A name not looked up before, each time: what a cache sees whenever
        # a name's TTL has run out.  Without a cache it is the same as above.
        if stub != "none":
            for mode in ("deactivated", "activated"):
                arguments = ["lookups", "--fresh", "--iterations", n, "--mode", mode]
                add(setup, stub, arguments, kind="lookups", workload="new name", mode=mode)
        # gevent's resolver is a pool of threads: 20 greenlets look the name
        # up at once, more than the pool has threads.
        if gevent:
            for mode in ("deactivated", "activated"):
                arguments = ["lookups", "--iterations", n, *green, "--concurrency", "20"]
                arguments += ["--mode", mode]
                add(setup, stub, arguments, kind="lookups", workload="20 at once", mode=mode)
        # A connect to an address no name is known for, after 30 allowed names
        # were looked up: tethered searches them before it decides.
        for mode in ("deactivated", "log-only", "activated"):
            arguments = ["fallback", "--iterations", str(options.fallback_iterations), *green]
            arguments += ["--mode", mode]
            add(setup, stub, arguments, kind="fallback", workload="30 candidates", mode=mode)
        # A load-balanced name: (answers, pool, TTL, every trial in a fresh state).
        shapes = [(2, 8, 0, True)]
        if not gevent:
            shapes += [(2, 8, 0, False), (2, 8, 30, True)]
        if stub == "none" and not gevent:
            shapes.append((2, 256, 0, False))
        for answers, pool, ttl, fresh_state in shapes:
            name = f"lb-{answers}-of-{pool}" + (f"-ttl-{ttl}" if ttl else "") + ".bench.test"
            arguments = ["divergence", "--name", name, "--mode", "activated", *green]
            arguments += ["--iterations", trials] + (["--fresh-state"] if fresh_state else [])
            add(
                setup,
                stub,
                arguments,
                kind="divergence",
                answers=answers,
                pool=pool,
                ttl=ttl,
                state="first connection" if fresh_state else "one process",
            )
    return plan


def main() -> None:
    """Run every measurement and print the results as one JSON line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=300)
    parser.add_argument("--trials", type=int, default=1000)
    parser.add_argument("--fallback-iterations", type=int, default=20)
    parser.add_argument("--latency-ms", type=float, default=20.0)
    parser.add_argument("--only", default=None, help="run only the setups whose name has this")
    options = parser.parse_args()

    _add_routable_link()
    upstream = subprocess.Popen(  # nosec B603 - the interpreter and the benchmark's upstream
        [
            sys.executable,
            str(HERE / "upstream.py"),
            "--listen",
            UPSTREAM[0],
            "--control-port",
            str(CONTROL[1]),
            "--latency-ms",
            str(options.latency_ms),
        ],
        stdout=subprocess.DEVNULL,
    )
    results: list[dict[str, object]] = []
    try:
        _wait_for_answer(UPSTREAM[0])
        for measurement in _plan(options):
            setup = str(measurement["setup"])
            if options.only and options.only not in setup:
                continue
            arguments = measurement["arguments"]
            assert isinstance(arguments, list)  # nosec B101 - built by _plan
            # Every measurement starts with an empty cache.
            resolver = Stub(str(measurement["stub"]))
            resolver.start()
            try:
                _say(f"[{setup}] {' '.join(arguments)}")
                result = _probe(arguments, timeout=1800)
            finally:
                resolver.stop()
            _say(f"    {json.dumps(result)}")
            results.append({**measurement, **result})
    finally:
        upstream.terminate()
        upstream.wait(timeout=10)

    environment = {
        "python": platform.python_version(),
        "glibc": platform.libc_ver()[1],
        "debian": Path("/etc/debian_version").read_text(encoding="ascii").strip(),
        "image": os.environ.get("BENCH_IMAGE", "?"),
        "systemd-resolved": _package_version("systemd-resolved"),
        "dnsmasq": _package_version("dnsmasq-base"),
        "latency_ms": options.latency_ms,
    }
    print(RESULT_MARKER + json.dumps({"environment": environment, "results": results}), flush=True)


if __name__ == "__main__":
    main()
