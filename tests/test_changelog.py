"""The changelog links each version to its comparison and gives the notes of its GitHub
release; the version fields and the date agree.

A version of ``CHANGELOG.md`` without its compare link raises no error
anywhere: the heading just keeps its brackets.  ``CITATION.cff`` names a
version and the day it was released; ``cz bump`` rewrites the version
(``version_files`` in ``pyproject.toml``) and leaves the date alone.
``pyproject.toml`` names the version of the distribution and the one
commitizen starts from, and no build compares either with
``tethered.__version__``.  The publish workflow takes the notes of the GitHub
release from the version's section (``scripts/release_notes.py``), and a
version without notes stops its release.  These tests fail when a link is
missing or out of place, when the date is not the one the changelog gives
that version, when a version field names another version, and when a
version's section gives no notes.
"""

from __future__ import annotations

import importlib.util
import itertools
import pathlib
import re
import tomllib
from typing import TYPE_CHECKING

import pytest

import tethered

if TYPE_CHECKING:
    from types import ModuleType

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
CITATION = ROOT / "CITATION.cff"
COMPARE = "https://github.com/shcherbak-ai/tethered/compare/"
RELEASE_NOTES = ROOT / "scripts" / "release_notes.py"

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


def test_pyproject_names_the_package_version() -> None:
    with (ROOT / "pyproject.toml").open("rb") as file:
        pyproject = tomllib.load(file)
    assert pyproject["project"]["version"] == tethered.__version__
    assert pyproject["tool"]["commitizen"]["version"] == tethered.__version__


# ── The notes of the GitHub release ──────────────────────────────────


@pytest.fixture(scope="module")
def release_notes() -> ModuleType:
    """``scripts/release_notes.py``, which the publish workflow runs, loaded by its path."""
    if not RELEASE_NOTES.is_file():
        pytest.skip("needs the repository's scripts/ (not part of every source copy)")
    spec = importlib.util.spec_from_file_location("_tethered_release_notes", RELEASE_NOTES)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_each_release_has_the_notes_of_its_github_release(release_notes: ModuleType) -> None:
    # The publish workflow takes them before it uploads anything, so a version
    # without notes would stop its release; as the last of the
    # ``pre_bump_hooks``, this stops the bump before that.
    changelog = CHANGELOG.read_text(encoding="utf-8")
    for version in _released():
        notes = release_notes.release_notes(changelog, version)
        assert notes in changelog
        assert notes == notes.strip() + "\n"
        assert not re.search(r"^## \[|^\[[^\]]+\]: ", notes, re.MULTILINE)


_RELEASES = (
    "# Changelog\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/).\n\n"
    "## [Unreleased]\n\n- C\n\n"
    "## [1.1.0] — 2026-11-09\n\n### Fixed\n\n- B — not in [1.0.0]\n\n"
    "## [1.0.0] — 2026-11-02\n\nRelative to 0.5.3.\n\n### Added\n\n- A\n\n"
    f"[Unreleased]: {COMPARE}v1.1.0...HEAD\n"
    f"[1.1.0]: {COMPARE}v1.0.0...v1.1.0\n"
    f"[1.0.0]: {COMPARE}v0.5.3...v1.0.0\n"
)


def test_the_notes_of_a_release_are_its_section(release_notes: ModuleType) -> None:
    # Up to the next section, or for the oldest, up to the links; a mention of
    # a section in an entry ends nothing.
    assert release_notes.release_notes(_RELEASES, "1.1.0") == "### Fixed\n\n- B — not in [1.0.0]\n"
    assert release_notes.release_notes(_RELEASES, "1.0.0") == (
        "Relative to 0.5.3.\n\n### Added\n\n- A\n"
    )


@pytest.mark.parametrize(
    ("changelog", "version", "error"),
    [
        # Not released
        (_RELEASES, "1.2.0", "no dated section"),
        # Not yet named and dated for its release
        (_RELEASES, "Unreleased", "no dated section"),
        # Only the start of a version
        (_RELEASES, "1.1", "no dated section"),
        # The dots are dots
        (_RELEASES, "1x1x0", "no dated section"),
        # A hyphen where the changelog has its dash
        (_RELEASES.replace("[1.1.0] — ", "[1.1.0] - "), "1.1.0", "no dated section"),
        # Headings only
        (
            _RELEASES.replace("### Fixed\n\n- B — not in [1.0.0]\n\n", "### Fixed\n\n"),
            "1.1.0",
            "empty",
        ),
    ],
)
def test_a_release_without_notes_stops(
    release_notes: ModuleType, changelog: str, version: str, error: str
) -> None:
    with pytest.raises(ValueError, match=error):
        release_notes.release_notes(changelog, version)


def test_the_script_prints_the_notes_in_utf8_or_says_why_not(
    release_notes: ModuleType,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_bytes(_RELEASES.encode("utf-8"))
    monkeypatch.setattr(release_notes, "_CHANGELOG", changelog)
    assert release_notes.main(["1.1.0"]) == 0
    assert capsysbinary.readouterr() == ("### Fixed\n\n- B — not in [1.0.0]\n".encode(), b"")
    assert release_notes.main(["1.2.0"]) == 1
    out, err = capsysbinary.readouterr()
    assert out == b""
    assert b"no dated section" in err
    assert release_notes.main([]) == 1
    assert b"Usage" in capsysbinary.readouterr().err
