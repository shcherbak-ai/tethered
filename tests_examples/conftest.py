"""Install ``tethered.pth`` into site-packages for the example run.

Examples 11 and 12 launch Python children that are expected to inherit the
parent's policy.  That needs the ``tethered.pth`` bootstrap in a directory
``site`` processes, and an editable install (``uv sync``, ``pip install -e
.``) leaves it only in ``src/``, where Python never runs it.  Without the
hook tethered treats ``sys.executable`` launches as external, so example
11's ``external_subprocess_policy="block"`` section would refuse its own
child.  Same arrangement as ``tests/conftest.py``.
"""

from __future__ import annotations

import shutil
import sysconfig
from pathlib import Path

import pytest


@pytest.fixture(scope="session", autouse=True)
def _ensure_pth_installed():
    """Copy ``src/tethered.pth`` into site-packages for the session, unless it is there."""
    pth_dst = Path(sysconfig.get_path("purelib")) / "tethered.pth"
    pth_src = Path(__file__).resolve().parent.parent / "src" / "tethered.pth"
    installed_by_us = False
    if not pth_dst.exists() and pth_src.exists():
        shutil.copy(pth_src, pth_dst)
        installed_by_us = True
    yield
    if installed_by_us:
        try:
            pth_dst.unlink()
        except OSError:
            pass
