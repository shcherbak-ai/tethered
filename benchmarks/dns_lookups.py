"""tethered DNS benchmark: what the second lookup of an allowed name costs.

Needs Docker (Docker Desktop on Windows and macOS).  Standard library only on
the host.

When an allowed host name is looked up, tethered's audit hook looks it up a
second time itself, to record which addresses belong to the name.  This
benchmark measures that lookup against real resolvers, in a container with no
network: a small DNS server of its own plays the upstream (it adds a fixed
latency to every reply and counts the queries it receives), and the container
is set up as each kind of host is:

    no cache            glibc asks the upstream itself (/etc/resolv.conf names
                        it), as in a slim container image
    gevent, no cache    the same, with gevent's default resolver (a thread pool)
    systemd-resolved    the caching stub of Ubuntu and Fedora hosts
                        (nameserver 127.0.0.53), run without systemd
    dnsmasq             a caching stub as a container would run one

For each it times socket.getaddrinfo() with tethered deactivated and activated
(allow list naming the host) and reports the queries that reached the
upstream.  It times a connect to an address that no name is known for after
30 allowed names were looked up, which makes tethered search those names
(_fallback_resolve) before it decides.  And it measures the divergence of the
two lookups for a load-balanced name (each answer a random subset of a pool,
TTL 0 unless stated): the share of connections tethered refuses although the
name is allowed.  tethered goes into the image as a wheel built from this
working tree.

Usage::

    uv run python benchmarks/dns_lookups.py
    uv run python benchmarks/dns_lookups.py --python 3.13 --iterations 500
    uv run python benchmarks/dns_lookups.py --host-name pypi.org   # also this machine's resolver

A full run takes about a quarter of an hour; ``--only`` runs the setups whose
name contains a text, ``--trials`` sets the connections of the divergence
measurement (default 1000).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess  # nosec B404 - the benchmark drives docker and its own probe
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
ASSETS = HERE / "dns_lookups"
RESULT_MARKER = "DNS-BENCH-RESULT "
PROBE_MARKER = "PROBE-RESULT "


def _docker(arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B603 B607 - docker with arguments of this script
        ["docker", *arguments],
        cwd=REPO,
        env={**os.environ, "DOCKER_BUILDKIT": "1"},
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        **kwargs,
    )


def _check_docker() -> None:
    if shutil.which("docker") is None:
        sys.exit("This benchmark needs Docker: there is no 'docker' command on PATH.")
    done = _docker(["version", "--format", "{{.Server.Version}}"], capture_output=True)
    if done.returncode != 0:
        sys.exit(
            "This benchmark needs Docker, and the docker command reaches no daemon:\n"
            f"{done.stdout}{done.stderr}"
        )


def _build(python: str) -> str:
    print(f"Building the image (python:{python}-slim, tethered from {REPO}) ...", flush=True)
    with tempfile.TemporaryDirectory() as scratch:
        id_file = Path(scratch) / "image-id"
        done = _docker(
            [
                "build",
                "--file",
                str(ASSETS / "Dockerfile"),
                "--build-arg",
                f"PYTHON_TAG={python}",
                "--tag",
                f"tethered-bench-dns:py{python}",
                "--iidfile",
                str(id_file),
                "--progress",
                "plain",
                ".",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if done.returncode != 0:
            sys.exit(f"docker build failed:\n{done.stdout}")
        return id_file.read_text(encoding="utf-8").strip()


def _run(image: str, options: argparse.Namespace) -> dict[str, Any]:
    name = f"tethered-bench-dns-{os.getpid()}"
    # No network: NET_ADMIN lets the benchmark add a dummy interface, which
    # systemd-resolved needs before it forwards anything.
    arguments = ["run", "--rm", "--init", "--name", name, "--network", "none"]
    arguments += ["--cap-add", "NET_ADMIN"]
    if options.cpuset_cpus:
        arguments += ["--cpuset-cpus", options.cpuset_cpus]
    arguments += [image, "--iterations", str(options.iterations), "--trials", str(options.trials)]
    arguments += ["--latency-ms", str(options.latency_ms)]
    arguments += ["--fallback-iterations", str(options.fallback_iterations)]
    if options.only:
        arguments += ["--only", options.only]
    print("Running the measurements (progress below) ...", flush=True)
    try:
        # The container's progress goes to stderr, straight to the terminal.
        done = _docker(arguments, stdout=subprocess.PIPE)
    except KeyboardInterrupt:
        _docker(["kill", name], capture_output=True)
        raise
    for line in reversed(done.stdout.splitlines()):
        if line.startswith(RESULT_MARKER):
            return json.loads(line[len(RESULT_MARKER) :])
    sys.exit(f"The container gave no result (exit status {done.returncode}):\n{done.stdout}")


def _host_lookups(name: str, iterations: int) -> list[dict[str, Any]]:
    """Measure this machine's own resolver with a real name: deactivated, then activated."""
    print(f"Measuring this machine's resolver with {name} ...", flush=True)
    results = []
    for mode in ("deactivated", "activated"):
        done = subprocess.run(  # nosec B603 - this interpreter and the benchmark's own probe
            [
                sys.executable,
                str(ASSETS / "probe.py"),
                "lookups",
                "--name",
                name,
                "--iterations",
                str(iterations),
                "--mode",
                mode,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        for line in reversed(done.stdout.splitlines()):
            if line.startswith(PROBE_MARKER):
                result = json.loads(line[len(PROBE_MARKER) :])
                break
        else:
            sys.exit(f"The probe failed on this machine:\n{done.stdout}{done.stderr}")
        setup = f"this machine ({platform.system()} {platform.release()})"
        results.append(
            {"setup": setup, "kind": "lookups", "workload": name, "mode": mode, **result}
        )
    return results


def _ms(value: float) -> str:
    return f"{float(value):.3f}"


def _per_call(result: dict[str, Any], key: str, calls: int) -> str:
    upstream = result.get("upstream")
    if not isinstance(upstream, dict):
        return "n/a"
    return f"{upstream.get(key, 0) / calls:.2f}"


def _print_timings(results: list[dict[str, Any]], kind: str, title: str) -> None:
    rows = [result for result in results if result.get("kind") == kind]
    if not rows:
        return
    print(title)
    print()
    print(
        "| Setup | Workload | Mode | A queries per call | AAAA queries per call "
        "| Median | p90 | Added (median) | Calls per s | Longest gevent hub stall |"
    )
    print("|---|---|---|---:|---:|---:|---:|---:|---:|---:|")
    baseline: dict[tuple[object, object], float] = {}
    for result in rows:
        key = (result["setup"], result["workload"])
        median = float(result["median_ms"])
        if result["mode"] == "deactivated":
            baseline[key] = median
        added = (
            f"+{median - baseline[key]:.3f}"
            if key in baseline and result["mode"] != "deactivated"
            else ""
        )
        calls = int(result["calls"])
        rate = 1000 / float(result["wall_per_call_ms"])
        stall = result.get("max_hub_stall_ms")
        print(
            f"| {result['setup']} | {result['workload']} | {result['mode']} "
            f"| {_per_call(result, 'A', calls)} | {_per_call(result, 'AAAA', calls)} "
            f"| {_ms(result['median_ms'])} | {_ms(result['p90_ms'])} | {added} | {rate:,.0f} "
            f"| {'' if stall is None else _ms(stall)} |"
        )
    print()


def _print_divergence(results: list[dict[str, Any]]) -> None:
    rows = [result for result in results if result.get("kind") == "divergence"]
    if not rows:
        return
    print("Divergence: a load-balanced name, activate(allow=[name], allow_localhost=False)")
    print()
    print(
        "| Setup | Answer | TTL | Trials | Refused | Refused share "
        "| A queries per connection | Last refusal at | Longest gevent hub stall |"
    )
    print("|---|---|---:|---|---:|---:|---:|---:|---:|")
    for result in rows:
        trials = int(result["trials"])
        refused = int(result["refused"])
        last = result.get("last_refusal")
        stall = result.get("max_hub_stall_ms")
        print(
            f"| {result['setup']} | {result['answers']} of {result['pool']} | {result['ttl']} s "
            f"| {trials} ({result['state']}) | {refused} | {100 * refused / trials:.1f}% "
            f"| {_per_call(result, 'A', trials)} | {'' if last is None else f'trial {last}'} "
            f"| {'' if stall is None else _ms(stall)} |"
        )
    print()


def _print_environment(environment: dict[str, Any], results: list[dict[str, Any]]) -> None:
    gevent = next((r["gevent"] for r in results if "gevent" in r), None)
    tethered = next((r["tethered"] for r in results if "tethered" in r), "?")
    print("=" * 72)
    print("tethered DNS benchmark")
    print("=" * 72)
    print(f"tethered          : {tethered} (wheel built from {REPO})")
    print(f"image             : {environment.get('image')} (Debian {environment.get('debian')})")
    print(f"Python            : {environment.get('python')}, glibc {environment.get('glibc')}")
    print(f"systemd-resolved  : {environment.get('systemd-resolved')}")
    print(f"dnsmasq           : {environment.get('dnsmasq')}")
    print(f"gevent            : {gevent}")
    print(f"upstream latency  : {environment.get('latency_ms')} ms per query")
    print()


def main() -> None:
    """Build the image, run the measurements, print the tables."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--python", default="3.14", help="the Python of the image (default 3.14)")
    parser.add_argument("--iterations", type=int, default=300, help="lookups per measurement")
    parser.add_argument("--trials", type=int, default=1000, help="connections per divergence run")
    parser.add_argument(
        "--fallback-iterations", type=int, default=20, help="connects per fallback-search run"
    )
    parser.add_argument("--latency-ms", type=float, default=20.0, help="the upstream's latency")
    parser.add_argument("--only", default=None, help="run only the setups whose name has this")
    parser.add_argument("--cpuset-cpus", default=None, help="docker run --cpuset-cpus")
    parser.add_argument(
        "--host-name",
        default=None,
        help="also measure this machine's own resolver with this real name (needs a network)",
    )
    parser.add_argument("--json", type=Path, default=None, help="also write the results here")
    options = parser.parse_args()

    _check_docker()
    image = _build(options.python)
    data = _run(image, options)
    environment = data["environment"]
    results = data["results"]
    assert isinstance(environment, dict) and isinstance(results, list)  # nosec B101
    if options.host_name:
        results += _host_lookups(options.host_name, options.iterations)
    if options.json:
        options.json.write_text(
            json.dumps({"environment": environment, "results": results}, indent=2),
            encoding="utf-8",
        )
    print()
    _print_environment(environment, results)
    _print_timings(
        results,
        "lookups",
        "Lookups: socket.getaddrinfo(name, 443, type=SOCK_STREAM), times in ms",
    )
    _print_timings(
        results,
        "fallback",
        "Fallback search: a connect to an address no name is known for and the policy does\n"
        "not allow, after 30 allowed names were looked up (log-only: it goes ahead;\n"
        "activated: it is refused), times in ms",
    )
    _print_divergence(results)
    print("A queries per call: the lookups that reached the upstream.  Each also sends an")
    print("AAAA query, which a caching stub answers from its negative cache.")


if __name__ == "__main__":
    main()
