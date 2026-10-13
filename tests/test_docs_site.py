"""The documentation site names the version of the package it describes.

The footer of every page is the ``copyright`` line of ``zensical.toml``, which
begins with the package name and its version.  ``cz bump`` rewrites that line
together with the other version fields (``version_files`` in
``pyproject.toml``); this test fails when the two no longer agree.
"""

from __future__ import annotations

import pathlib
import tomllib

import pytest

import tethered

CONFIG = pathlib.Path(__file__).resolve().parent.parent / "zensical.toml"

pytestmark = pytest.mark.skipif(
    not CONFIG.is_file(),
    reason="needs the repository's zensical.toml (not part of every source copy)",
)


def test_the_footer_names_the_version() -> None:
    footer = tomllib.loads(CONFIG.read_text(encoding="utf-8"))["project"]["copyright"]
    assert footer.startswith(f"tethered {tethered.__version__} ")
