"""What the client suite adds to the harness: names only in DNS, bytecode, and the table.

The harness writes the world's two names into ``/etc/hosts``.  This suite takes
them out again for its session: every lookup is then a query to the world's
DNS responder, which counts it.  "Was the name looked up" is thereby measured
the same way for every resolver: glibc's, c-ares, dnspython.
"""

from __future__ import annotations

import compileall
import json
import re
import sysconfig
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from harness.helpers import APPS_DIR, LOG_DIR, SUITE_DIR
from harness.world import NAMES

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(scope="session", autouse=True)
def names_only_in_dns(world: object) -> Iterator[None]:
    """Remove the world's names from ``/etc/hosts`` while this suite runs."""
    hosts = Path("/etc/hosts")
    original = hosts.read_text()
    kept = [line for line in original.splitlines() if not set(line.split()[1:]) & set(NAMES)]
    # Docker mounts the file into the container: it is written in place.
    hosts.write_text("\n".join(kept) + "\n")
    try:
        yield
    finally:
        hosts.write_text(original)


@pytest.fixture(scope="session", autouse=True)
def compiled_standard_library() -> None:
    """Compile the standard library once, for the processes this suite starts.

    The official Python images ship the standard library without bytecode,
    and the suite image sets ``PYTHONDONTWRITEBYTECODE``.  Every process under
    test therefore compiles each module it imports, about a fifth of a second
    for what the harness's own modules need, and this suite starts about a
    thousand processes.  Compiling everything once takes a few seconds.
    """
    stdlib = sysconfig.get_paths()["stdlib"]
    packages = re.compile(r"[/\\]site-packages[/\\]")
    compileall.compile_dir(stdlib, quiet=2, workers=0, rx=packages)
    for directory in (APPS_DIR, SUITE_DIR):
        compileall.compile_dir(directory, quiet=2)


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    """Print every row that was measured in this run, and keep the details as JSON."""
    import measure
    import report

    rows = measure.measured_rows()
    if not rows:
        return
    terminalreporter.section("client libraries, as measured")
    for line in report.table(rows):
        terminalreporter.write_line(line)
    terminalreporter.section("client libraries, the evidence")
    for line in report.evidence(rows):
        terminalreporter.write_line(line)
    details = LOG_DIR / "clients-measured.json"
    details.write_text(json.dumps(report.details(rows), indent=1, sort_keys=True))
    terminalreporter.write_line(f"details: {details}")
