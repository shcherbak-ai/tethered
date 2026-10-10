"""The pytest plugin of the container harness (loaded with ``-p harness.plugin``).

It provides the ``world`` fixture, resets the world's counters before every
test, stops the servers a test or a fixture started when that test or fixture
is torn down, and attaches server logs and script output to the report of a
failing test.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from harness import helpers
from harness.servers import registry
from harness.world import ADDRESSES, LOOPBACK_ADDR, NAMES

if TYPE_CHECKING:
    from collections.abc import Generator, Iterator

_POLICY_VARIABLE = "_TETHERED_CHILD_POLICY"


def pytest_configure(config: pytest.Config) -> None:
    """Refuse to run anywhere but in a harness container, and never under a policy."""
    if os.environ.get("TC_IN_CONTAINER") != "1":
        raise pytest.UsageError(
            "the container suites run inside their image: use tests_containers/run.py"
        )
    if _POLICY_VARIABLE in os.environ or "tethered" in sys.modules:
        raise pytest.UsageError("the pytest process must not hold a tethered policy")


@dataclass(frozen=True)
class World:
    """The running world: its process id and where its own output goes."""

    pid: int
    log_path: Path


def _run(*command: str) -> None:
    done = subprocess.run(command, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise RuntimeError(
            f"{' '.join(command)} failed ({done.stderr.strip()}): the container needs "
            "--cap-add NET_ADMIN, which tests_containers/run.py passes"
        )


def _prepare_network() -> None:
    """Give ``lo`` the world's addresses and make the two names resolve, by file and by DNS."""
    _run("ip", "link", "set", "lo", "up")
    present = subprocess.run(
        ["ip", "-o", "-4", "addr", "show", "dev", "lo"], capture_output=True, text=True, check=True
    ).stdout
    for address in ADDRESSES:
        if address != LOOPBACK_ADDR and f" {address}/" not in present:
            _run("ip", "addr", "add", f"{address}/32", "dev", "lo")
    # Docker mounts both files into the container: they are written in place, not replaced.
    hosts = Path("/etc/hosts")
    known = hosts.read_text()
    missing = [f"{addr} {name}\n" for name, addr in NAMES.items() if name not in known.split()]
    if missing:
        hosts.write_text(known.rstrip("\n") + "\n" + "".join(missing))
    Path("/etc/resolv.conf").write_text("nameserver 127.0.0.1\noptions timeout:1 attempts:1\n")


@pytest.fixture(scope="session", autouse=True)
def world() -> Iterator[World]:
    """The destinations of the suite: addresses, names, listeners, counters (``harness.world``)."""
    _prepare_network()
    helpers.LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = helpers.LOG_DIR / "world.log"
    env = {key: value for key, value in os.environ.items() if key != _POLICY_VARIABLE}
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(
            [sys.executable, "-m", "harness.world"],
            cwd=helpers.HARNESS_DIR.parent,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    try:
        deadline = time.monotonic() + 15.0
        while True:
            if proc.poll() is not None:
                raise RuntimeError(f"the world did not start:\n{log_path.read_text()}")
            try:
                if helpers.http_get("http://127.0.0.1:9100/health", timeout=2.0).status == 200:
                    break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError(f"the world did not answer:\n{log_path.read_text()}")
            time.sleep(0.05)
        yield World(pid=proc.pid, log_path=log_path)
    finally:
        proc.kill()
        proc.wait()


@pytest.fixture(autouse=True)
def _fresh_counters(world: World) -> None:
    helpers.reset_arrivals()


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    """Note which test is starting, and where each running server's log stands."""
    registry.begin_test(item)


@pytest.hookimpl(hookwrapper=True)
def pytest_fixture_setup(fixturedef: Any, request: Any) -> Generator[None, None, None]:
    """Let ``start_server`` find the fixture that is being set up, to be stopped with it."""
    registry.fixture_requests.append(request)
    try:
        yield
    finally:
        registry.fixture_requests.pop()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: Any) -> Generator[None, Any, None]:
    """Attach the logs of the servers and the output of the scripts to a failed report."""
    outcome = yield
    report = outcome.get_result()
    if report.failed:
        report.sections.extend(registry.sections())


def pytest_sessionfinish(session: pytest.Session) -> None:
    """Stop what no test and no fixture owned."""
    for server in list(registry.live):
        server.stop(5.0, check=False)
