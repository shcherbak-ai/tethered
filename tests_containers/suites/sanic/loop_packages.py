"""Whether a server under test finds uvloop installed.

``pip install sanic`` installs uvloop with it, and sanic then serves on uvloop
unless told otherwise.  A sanic without uvloop is a real arrangement too
(``pip uninstall uvloop``, or an installation made with ``SANIC_NO_UVLOOP``).
The image has uvloop.  For the length of the test session it is moved out of
site-packages into a directory of its own, and a server is given that
directory on ``PYTHONPATH`` when its test asks for uvloop: with the
distribution's metadata, so that uvloop is installed for that server in every
sense the import system knows, and absent for the others.
"""

from __future__ import annotations

import os
import shutil
import sysconfig
from pathlib import Path

from harness import APPS_DIR, SUITE_DIR

PACKAGES = ("uvloop",)
SITE_PACKAGES = Path(sysconfig.get_paths()["platlib"])
STORE = Path("/opt/tc-loop-packages")


def set_aside() -> None:
    """Move the packages (and their ``.dist-info``) out of site-packages."""
    for name in PACKAGES:
        target = STORE / name
        target.mkdir(parents=True, exist_ok=True)
        entries = [*SITE_PACKAGES.glob(name), *SITE_PACKAGES.glob(f"{name}-*.dist-info")]
        if not entries and not (target / name).is_dir():
            raise RuntimeError(f"{name} is not installed in {SITE_PACKAGES}")
        for entry in entries:
            shutil.move(str(entry), str(target / entry.name))


def restore() -> None:
    """Move them back, so that the image's list of installed packages is what was built."""
    for name in PACKAGES:
        for entry in (STORE / name).glob("*"):
            shutil.move(str(entry), str(SITE_PACKAGES / entry.name))


def pythonpath(*installed: str) -> str:
    """``PYTHONPATH`` for a server that finds these packages, and no other of ``PACKAGES``."""
    unknown = set(installed) - set(PACKAGES)
    if unknown:
        raise ValueError(f"not one of {PACKAGES}: {sorted(unknown)}")
    extra = [str(STORE / name) for name in PACKAGES if name in installed]
    return os.pathsep.join([str(APPS_DIR), str(SUITE_DIR), *extra])
