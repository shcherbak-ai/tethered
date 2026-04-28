"""Run every example script as a subprocess and verify it exits cleanly.

Each example runs in its own process because audit hooks (sys.addaudithook)
are irremovable — process isolation is the only way to prevent leakage
between examples.

Blocked calls never hit the network — tethered intercepts at the audit
hook level before any DNS query.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"

EXAMPLE_SCRIPTS = [
    EXAMPLES_DIR / "01_basic_activate.py",
    EXAMPLES_DIR / "02_scope_context_manager.py",
    EXAMPLES_DIR / "03_scope_decorator.py",
    EXAMPLES_DIR / "04_global_with_scope.py",
    EXAMPLES_DIR / "05_global_with_nested_scopes.py",
    EXAMPLES_DIR / "06_locked_mode.py",
    EXAMPLES_DIR / "07_log_only.py",
    EXAMPLES_DIR / "08_scope_in_threads.py",
    EXAMPLES_DIR / "09_async_scope.py",
    EXAMPLES_DIR / "10_package_maintainer.py",
    EXAMPLES_DIR / "11_subprocess_control.py",
    EXAMPLES_DIR / "12_scope_subprocess.py",
]


@pytest.mark.parametrize(
    "script",
    EXAMPLE_SCRIPTS,
    ids=[s.stem for s in EXAMPLE_SCRIPTS],
)
def test_example_runs_cleanly(script: Path) -> None:
    """Each example must exit with code 0 and produce no unexpected errors."""
    assert script.exists(), f"{script.name} not found"

    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"{script.name} failed (exit code {result.returncode}):\n"
        f"--- stdout ---\n{result.stdout}\n"
        f"--- stderr ---\n{result.stderr}"
    )
    # Examples should produce output (they print results)
    assert result.stdout.strip(), f"{script.name} produced no output"
    # "(unexpected)" in output means tethered allowed something it should have blocked
    assert "(unexpected)" not in result.stdout, (
        f"{script.name} produced unexpected output:\n{result.stdout}"
    )
