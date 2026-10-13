"""The changelog links every version to its comparison, and CITATION.cff repeats its date.

A version of ``CHANGELOG.md`` without its compare link raises no error
anywhere: the heading just keeps its brackets.  ``CITATION.cff`` names a
version and the day it was released; ``cz bump`` rewrites the version
(``version_files`` in ``pyproject.toml``) and leaves the date alone.  These
tests fail when a link is missing or out of place, and when the date is not
the one the changelog gives that version.
"""

from __future__ import annotations

import itertools
import pathlib
import re

import pytest

import tethered

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
CITATION = ROOT / "CITATION.cff"
COMPARE = "https://github.com/shcherbak-ai/tethered/compare/"

pytestmark = pytest.mark.skipif(
    not (CHANGELOG.is_file() and CITATION.is_file()),
    reason="needs the repository's CHANGELOG.md and CITATION.cff (not part of every source copy)",
)


def _released() -> dict[str, str]:
    """Each version the changelog has a section for, newest first, with its date."""
    return dict(
        re.findall(
            r"^## \[(.+?)\] — (\d{4}-\d{2}-\d{2})$",
            CHANGELOG.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
    )


def test_each_version_links_to_its_comparison_with_the_one_before() -> None:
    changelog = CHANGELOG.read_text(encoding="utf-8")
    versions = re.findall(r"^## \[(.+?)\]", changelog, re.MULTILINE)
    links = dict(re.findall(r"^\[(.+?)\]: (\S+)$", changelog, re.MULTILINE))
    # Every section has a heading of the one form, version and date.
    assert versions == list(_released())
    # The links stand at the end of the file, newest first like the sections:
    # the link of a new version goes on top.
    assert list(links) == versions
    for version, previous in itertools.pairwise(versions):
        assert links[version] == f"{COMPARE}v{previous}...v{version}"
    # The oldest section follows a release that the changelog does not list.
    oldest = versions[-1]
    assert re.fullmatch(rf"{re.escape(COMPARE)}v[\d.]+\.\.\.v{re.escape(oldest)}", links[oldest])


def test_the_citation_file_names_the_package_version_and_its_release_date() -> None:
    citation = CITATION.read_text(encoding="utf-8")
    (version,) = re.findall(r"^version: (\S+)$", citation, re.MULTILINE)
    (date,) = re.findall(r"^date-released: (\S+)$", citation, re.MULTILINE)
    assert version == tethered.__version__
    # The release change writes the day into the changelog heading and here.
    assert date == _released()[version]
