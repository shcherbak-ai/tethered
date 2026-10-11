"""Fixtures of the mod_wsgi suite; the harness's own come from its plugin.

A test here can pass while a server process died behind it: Apache replaces a
daemon process that crashed, and its parent still exits with status 0, which
is all the stop check of the harness sees.  So the log of every Apache this
suite started is searched for a crash (and for a tamper alert of a locked
policy) after each test, and once more when everything has been stopped.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import apache
import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

#: The wheel of tethered the image was built with (``images/base.Dockerfile``).
WHEELS = Path("/wheels")


@pytest.fixture(autouse=True)
def _no_crash_during_the_test() -> Iterator[None]:
    yield
    apache.check_logs()


@pytest.fixture(scope="session", autouse=True)
def _no_crash_at_the_end() -> Iterator[None]:
    yield
    # The servers of module and class fixtures have been stopped by now.
    apache.check_logs()


def _pip(*arguments: str) -> None:
    """Run the image's pip, which is the system Python's."""
    done = subprocess.run(
        [sys.executable, "-m", "pip", "--disable-pip-version-check", *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, f"pip {' '.join(arguments)}:\n{done.stdout}\n{done.stderr}"


@pytest.fixture(scope="module")
def venv_with_tethered() -> Iterator[Path]:
    """A virtual environment that has tethered, on a system Python that has not.

    That is the usual deployment: mod_wsgi is built for the system Python
    and the application's packages are in a virtual environment.  The image
    has tethered installed system-wide, so it is uninstalled for the module
    and installed again afterwards, both from the wheel the image was built
    with; the network is not needed.  The pytest process never imports
    tethered and does not notice.
    """
    wheel = str(next(WHEELS.glob("tethered-*.whl")))
    venv = apache.WORK / "venv"
    if venv.exists():
        shutil.rmtree(venv)
    apache.WORK.mkdir(parents=True, exist_ok=True)
    # Without a pip of its own, which takes most of the time: the image's pip installs into it.
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True, capture_output=True
    )
    in_venv = ("--python", str(venv / "bin" / "python"))
    _pip(*in_venv, "install", "--no-index", "--no-deps", wheel)
    _pip("uninstall", "--yes", "tethered")
    try:
        yield venv
    finally:
        _pip("install", "--no-index", "--no-deps", wheel)
