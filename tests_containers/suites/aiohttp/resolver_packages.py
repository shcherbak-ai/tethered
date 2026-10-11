"""Whether a server under test finds aiodns installed.

``pip install aiohttp`` resolves names with ``loop.getaddrinfo``.
``pip install aiohttp[speedups]`` adds aiodns, and aiohttp's client then
resolves names with it (c-ares, through pycares) unless told otherwise.  The
image has aiodns.  For the length of the test session it is moved out of
site-packages, with pycares, into a directory of its own, and a server is
given that directory on ``PYTHONPATH`` when its test asks for aiodns: with
the distributions' metadata, so that it is installed for that server in every
sense the import system knows, and absent for the others.
"""

from __future__ import annotations

import os
import shutil
import sysconfig
from pathlib import Path

from harness import APPS_DIR, SUITE_DIR

PACKAGES = ("aiodns", "pycares")
SITE_PACKAGES = Path(sysconfig.get_paths()["platlib"])
STORE = Path("/opt/tc-resolver-packages")


def set_aside() -> None:
    """Move the packages (and their ``.dist-info``) out of site-packages."""
    STORE.mkdir(parents=True, exist_ok=True)
    for name in PACKAGES:
        entries = [*SITE_PACKAGES.glob(f"{name}*")]
        if not entries and not (STORE / name).is_dir():
            raise RuntimeError(f"{name} is not installed in {SITE_PACKAGES}")
        for entry in entries:
            shutil.move(str(entry), str(STORE / entry.name))


def restore() -> None:
    """Move them back, so that the image's list of installed packages is what was built."""
    for entry in STORE.glob("*"):
        shutil.move(str(entry), str(SITE_PACKAGES / entry.name))


def pythonpath(*, aiodns: bool) -> str:
    """``PYTHONPATH`` for a server that finds aiodns installed, or does not."""
    extra = [str(STORE)] if aiodns else []
    return os.pathsep.join([str(APPS_DIR), str(SUITE_DIR), *extra])
