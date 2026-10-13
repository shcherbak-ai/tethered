"""Install ``tethered.pth`` into site-packages for the example run.

Examples 11 and 12 launch Python children that are expected to inherit the
parent's policy.  That needs the ``tethered.pth`` bootstrap in a directory
``site`` processes, and an editable install (``uv sync``, ``pip install -e
.``) leaves it only in ``src/``, where Python never runs it.  Without the
hook tethered treats ``sys.executable`` launches as external, so example
11's ``external_subprocess_policy="block"`` section would refuse its own
child.  Same arrangement as ``tests/conftest.py``: hooks and not a session
fixture, so that under pytest-xdist (``-n``) the process that starts the
workers installs the file once and no worker removes it under the others.
"""

from __future__ import annotations

import contextlib
import shutil
import sysconfig
from pathlib import Path

import pytest

# The ``tethered.pth`` this run copied into site-packages, for
# ``pytest_unconfigure`` to take away again.
_INSTALLED_PTH = pytest.StashKey[Path]()


def pytest_configure(config: pytest.Config) -> None:
    """Copy ``src/tethered.pth`` into site-packages for the run, unless it is there."""
    if hasattr(config, "workerinput"):
        return  # a pytest-xdist worker
    pth_dst = Path(sysconfig.get_path("purelib")) / "tethered.pth"
    pth_src = Path(__file__).resolve().parent.parent / "src" / "tethered.pth"
    if not pth_dst.exists() and pth_src.exists():
        shutil.copy(pth_src, pth_dst)
        config.stash[_INSTALLED_PTH] = pth_dst


def pytest_unconfigure(config: pytest.Config) -> None:
    """Remove the ``tethered.pth`` that ``pytest_configure`` installed."""
    pth_dst = config.stash.get(_INSTALLED_PTH, None)
    if pth_dst is not None:
        with contextlib.suppress(OSError):  # best-effort cleanup
            pth_dst.unlink()
