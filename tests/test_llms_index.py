"""The llms.txt index in zensical.toml lists every page, as the page describes itself.

The build writes ``llms.txt`` from ``[project.plugins.llmstxt.sections]``: a
link and one line of description for each page.  That list is kept by hand
beside ``nav``.  These tests fail when a page of the navigation is missing
from it or stands at another place, and when a line differs from the
``description`` in the front matter of its page.
"""

from __future__ import annotations

import pathlib
import tomllib

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = ROOT / "zensical.toml"

pytestmark = pytest.mark.skipif(
    not CONFIG.is_file(),
    reason="needs the repository's zensical.toml and docs/ (not part of every source copy)",
)


def _project() -> dict:
    return tomllib.loads(CONFIG.read_text(encoding="utf-8"))["project"]


def _nav_pages(entries: list) -> list[str]:
    """The pages of the navigation in order, those of nested groups included."""
    pages: list[str] = []
    for entry in entries:
        if isinstance(entry, dict):
            for target in entry.values():
                pages += _nav_pages(target if isinstance(target, list) else [target])
        else:
            pages.append(str(entry))
    return pages


def _indexed(project: dict) -> dict[str, str]:
    """Each page the index lists, in order, with its line of description."""
    return {
        page: note
        for entries in project["plugins"]["llmstxt"]["sections"].values()
        for entry in entries
        for page, note in entry.items()
    }


def test_the_index_lists_every_page_but_the_home_page_in_nav_order() -> None:
    # A page added to ``nav`` goes into a section of
    # ``[project.plugins.llmstxt.sections]`` as well, at the same place.
    project = _project()
    assert list(_indexed(project)) == [
        page for page in _nav_pages(project["nav"]) if page != "index.md"
    ]


def test_the_index_describes_each_page_as_its_front_matter_does() -> None:
    project = _project()
    docs = ROOT / project["docs_dir"]
    for page, note in _indexed(project).items():
        _, front_matter, _ = (docs / page).read_text(encoding="utf-8").split("---\n", 2)
        assert note == yaml.safe_load(front_matter)["description"], page
