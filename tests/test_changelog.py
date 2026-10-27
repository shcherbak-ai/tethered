"""The changelog links each version to its comparison and gives the notes of its GitHub
release; the version fields and the date agree.

A version of ``CHANGELOG.md`` without its compare link raises no error
anywhere: the heading just keeps its brackets.  ``CITATION.cff`` names a
version and the day it was released; ``cz bump`` rewrites the version
(``version_files`` in ``pyproject.toml``), and ``scripts/date_release.py``,
one of its ``pre_bump_hooks``, names and dates the ``[Unreleased]`` section
and writes the day into the citation file.  ``pyproject.toml`` names the
version of the distribution and the one commitizen starts from, and no build
compares either with ``tethered.__version__``.  The publish workflow takes the
notes of the GitHub release from the version's section
(``scripts/release_notes.py``), and a version without notes stops its release.
These tests fail when a link is missing or out of place, when the date is not
the one the changelog gives that version, when a version field names another
version, and when a version's section gives no notes; the tests of the two
scripts follow.
"""

from __future__ import annotations

import datetime
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
DATE_RELEASE = ROOT / "scripts" / "date_release.py"

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


def _ref(version: str) -> str:
    """What a comparison ends at: the version's tag, or ``HEAD`` for the changes not released."""
    return "HEAD" if version == "Unreleased" else f"v{version}"


def test_each_version_links_to_its_comparison_with_the_one_before() -> None:
    changelog = CHANGELOG.read_text(encoding="utf-8")
    versions = re.findall(r"^## \[(.+?)\]", changelog, re.MULTILINE)
    links = dict(re.findall(r"^\[(.+?)\]: (\S+)$", changelog, re.MULTILINE))
    # Every section has a heading of the one form, version and date, but the
    # changes not released yet, which stand on top.
    released = versions[1:] if versions[0] == "Unreleased" else versions
    assert released == list(_released())
    # The links stand at the end of the file, newest first like the sections:
    # the link of a new version goes on top.
    assert list(links) == versions
    for version, previous in itertools.pairwise(versions):
        assert links[version] == f"{COMPARE}v{previous}...{_ref(version)}"
    # The oldest section follows a release that the changelog does not list.
    oldest = versions[-1]
    assert re.fullmatch(rf"{re.escape(COMPARE)}v[\d.]+\.\.\.v{re.escape(oldest)}", links[oldest])


def test_the_citation_file_names_the_package_version_and_its_release_date() -> None:
    citation = CITATION.read_text(encoding="utf-8")
    (version,) = re.findall(r"^version: (\S+)$", citation, re.MULTILINE)
    (date,) = re.findall(r"^date-released: (\S+)$", citation, re.MULTILINE)
    assert version == tethered.__version__
    # scripts/date_release.py writes the day into the changelog heading and
    # here; as the last of the ``pre_bump_hooks``, this stops a bump whose two
    # dates differ.
    assert date == _released()[version]


def test_pyproject_names_the_package_version() -> None:
    with (ROOT / "pyproject.toml").open("rb") as file:
        pyproject = tomllib.load(file)
    assert pyproject["project"]["version"] == tethered.__version__
    assert pyproject["tool"]["commitizen"]["version"] == tethered.__version__


# ── The notes of the GitHub release ──────────────────────────────────


def _script(path: pathlib.Path) -> ModuleType:
    """A script of ``scripts/``, loaded by its path."""
    if not path.is_file():
        pytest.skip("needs the repository's scripts/ (not part of every source copy)")
    spec = importlib.util.spec_from_file_location(f"_tethered_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def release_notes() -> ModuleType:
    """``scripts/release_notes.py``, which the publish workflow runs."""
    return _script(RELEASE_NOTES)


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


# ── Dating the release ───────────────────────────────────────────────


@pytest.fixture(scope="module")
def date_release() -> ModuleType:
    """``scripts/date_release.py``, one of the ``pre_bump_hooks``."""
    return _script(DATE_RELEASE)


# CITATION.cff as the hook finds it: the version rewritten, the date not yet.
_CITATION = "cff-version: 1.2.0\nversion: 1.2.0\ndate-released: 2026-11-09\n"
_LINK = f"[Unreleased]: {COMPARE}v1.1.0...HEAD"


def test_a_bump_names_and_dates_the_unreleased_section(
    date_release: ModuleType, release_notes: ModuleType
) -> None:
    # A mention of the section in an entry is not its heading.
    entry = "- C, under `## [Unreleased]` until [Unreleased] is out\n"
    changelog = _RELEASES.replace("- C\n", entry)
    dated, cited = date_release.date_release(
        changelog, _CITATION, "1.2.0", "v1.2.0", "2026-11-16", "1.1.0"
    )
    assert dated == changelog.replace("## [Unreleased]\n", "## [1.2.0] — 2026-11-16\n").replace(
        _LINK, f"[1.2.0]: {COMPARE}v1.1.0...v1.2.0"
    )
    assert cited == _CITATION.replace("2026-11-09", "2026-11-16")
    assert release_notes.release_notes(dated, "1.2.0") == entry
    # Run again after a later hook stopped the bump, it names and dates the
    # section again.
    again, cited_again = date_release.date_release(
        dated, cited, "1.2.1", "v1.2.1", "2026-11-17", "1.1.0"
    )
    assert again == dated.replace("1.2.0", "1.2.1").replace("2026-11-16", "2026-11-17")
    assert cited_again == _CITATION.replace("2026-11-09", "2026-11-17")


@pytest.mark.parametrize(
    ("changelog", "citation", "error"),
    [
        # Nothing above the version before
        (
            _RELEASES.replace("## [Unreleased]\n\n- C\n\n", "").replace(f"{_LINK}\n", ""),
            _CITATION,
            "no changes above the section of 1.1.0",
        ),
        # Headings only: nothing to release
        (_RELEASES.replace("- C\n", "### Fixed\n"), _CITATION, "is empty"),
        # The section twice, e.g. after a merge
        (
            _RELEASES.replace("## [Unreleased]\n", "## [Unreleased]\n\n- D\n\n## [Unreleased]\n"),
            _CITATION,
            "more than one",
        ),
        # A line that only looks like the compare link
        (_RELEASES.replace(_LINK, "[Unreleased]: notes...below"), _CITATION, "no compare link"),
        # A citation file without its date
        (_RELEASES, "cff-version: 1.2.0\nversion: 1.2.0\n", "no `date-released`"),
    ],
)
def test_a_bump_stops_on_a_changelog_or_citation_it_cannot_date(
    date_release: ModuleType, changelog: str, citation: str, error: str
) -> None:
    with pytest.raises(ValueError, match=error):
        date_release.date_release(changelog, citation, "1.2.0", "v1.2.0", "2026-11-16", "1.1.0")


def test_the_hook_dates_both_files_or_neither(
    date_release: ModuleType,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    citation = tmp_path / "CITATION.cff"
    # commitizen writes the files it bumps with CRLF on Windows.
    changelog.write_bytes(_RELEASES.replace("\n", "\r\n").encode("utf-8"))
    citation.write_bytes(b"cff-version: 1.2.0\r\nversion: 1.2.0\r\n")
    monkeypatch.setattr(date_release, "_CHANGELOG", changelog)
    monkeypatch.setattr(date_release, "_CITATION", citation)
    for name in ("CZ_PRE_NEW_VERSION", "CZ_PRE_CURRENT_VERSION", "CZ_PRE_NEW_TAG_VERSION"):
        monkeypatch.delenv(name, raising=False)
    assert date_release.main() == 1
    assert "hook of `cz bump`" in capsys.readouterr().err
    monkeypatch.setenv("CZ_PRE_NEW_VERSION", "1.2.0")
    monkeypatch.setenv("CZ_PRE_CURRENT_VERSION", "1.1.0")
    # The changelog could be dated, the citation file not: neither is written.
    before = changelog.read_bytes()
    assert date_release.main() == 1
    assert "no `date-released`" in capsys.readouterr().err
    assert changelog.read_bytes() == before
    citation.write_bytes(_CITATION.replace("\n", "\r\n").encode("utf-8"))
    assert date_release.main() == 0
    day = datetime.date.today().isoformat()
    assert capsys.readouterr().out == f"Dated 1.2.0: {day} (CHANGELOG.md, CITATION.cff)\n"
    # In the repository's line ends, with the tag commitizen would give
    assert changelog.read_bytes() == (
        _RELEASES.replace("## [Unreleased]\n", f"## [1.2.0] — {day}\n")
        .replace(_LINK, f"[1.2.0]: {COMPARE}v1.1.0...v1.2.0")
        .encode("utf-8")
    )
    assert citation.read_bytes() == _CITATION.replace("2026-11-09", day).encode("utf-8")
