"""The entry point of a suite image: ``python -m harness [pytest arguments]``.

Runs pytest on the suite the image was built for and ends with one line that
``tests_containers/run.py`` reads: the counts, the duration and the versions.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import platform
import re
import sys
import time
from pathlib import Path

import pytest

#: ``tests_containers/run.py`` looks for the last line that starts with this.
RESULT_MARKER = "TETHERED-CT-RESULT "
ROOT = Path(__file__).resolve().parent.parent


class _Counts:
    """Collects pytest's own totals when it prints its summary."""

    def __init__(self) -> None:
        self.totals: dict[str, int] = {}

    def pytest_terminal_summary(self, terminalreporter: pytest.TerminalReporter) -> None:
        for outcome in ("passed", "failed", "error", "skipped", "xfailed", "xpassed"):
            self.totals[outcome] = len(terminalreporter.stats.get(outcome, []))


def _versions() -> dict[str, str]:
    """The version of every installed distribution, by its normalised name."""
    versions = {}
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata["Name"]
        if name:
            versions[re.sub(r"[-_.]+", "-", name).lower()] = distribution.version
    return dict(sorted(versions.items()))


def main(argv: list[str]) -> int:
    """Run the suite; returns pytest's exit status."""
    suite = os.environ["TC_SUITE"]
    suite_dir = ROOT / "suites" / suite
    print(f"suite {suite} on Python {platform.python_version()} ({platform.machine()})")
    # Everything that is installed, as the image build recorded it.
    frozen = (ROOT / "pip-freeze.txt").read_text().splitlines()
    print(f"installed: {', '.join(frozen)}", flush=True)

    counts = _Counts()
    started = time.monotonic()
    status = pytest.main(
        [
            str(suite_dir),
            f"--rootdir={ROOT}",
            "-p",
            "harness.plugin",
            "-p",
            "no:cacheprovider",
            "-v",
            "-ra",
            "--durations=10",
            "--color=no",
            *argv,
        ],
        plugins=[counts],
    )
    result = {
        "suite": suite,
        "python": platform.python_version(),
        "exit": int(status),
        "seconds": round(time.monotonic() - started, 1),
        "versions": _versions(),
        **counts.totals,
    }
    print(RESULT_MARKER + json.dumps(result), flush=True)
    return int(status)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
