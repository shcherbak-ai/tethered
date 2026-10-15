"""The documentation site names the version it describes and the picture it is shared with.

The footer of every page is the ``copyright`` line of ``zensical.toml``, which
begins with the package name and its version.  ``cz bump`` rewrites that line
together with the other version fields (``version_files`` in
``pyproject.toml``); a test fails when the two no longer agree.

A link to a page shows the repository's social preview on other sites: the
site's template (``overrides/main.html``) names a copy of it in ``docs/``,
which ``inv social-preview`` writes with the picture in ``social/``; a test
fails when the copy differs or the template names another file.
"""

from __future__ import annotations

import pathlib
import tomllib

import pytest

import tethered

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = ROOT / "zensical.toml"
TEMPLATE = ROOT / "overrides" / "main.html"
SHARE_IMAGE = "assets/social-preview.png"

pytestmark = pytest.mark.skipif(
    not CONFIG.is_file(),
    reason="needs the repository's zensical.toml (not part of every source copy)",
)


def test_the_footer_names_the_version() -> None:
    footer = tomllib.loads(CONFIG.read_text(encoding="utf-8"))["project"]["copyright"]
    assert footer.startswith(f"tethered {tethered.__version__} ")


def test_the_share_image_is_the_social_preview() -> None:
    site_copy = (ROOT / "docs" / SHARE_IMAGE).read_bytes()
    picture = (ROOT / "social" / "github-social-preview.png").read_bytes()
    assert site_copy == picture, "the site's share image is stale: run `uv run inv social-preview`"
    named = f'content="{{{{ config.site_url }}}}{SHARE_IMAGE}"'
    assert named in TEMPLATE.read_text(encoding="utf-8")
