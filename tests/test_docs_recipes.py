"""The code the cookbook prints is the code the container suites run.

``docs/COOKBOOK.md`` promises that its code blocks work as printed.  The
container suites hold copies of the recipes between two marker lines and run
them under real servers; this test fails when a copy and the block it was
taken from no longer agree, so neither can be changed without the other.
"""

from __future__ import annotations

import pathlib
import re
import textwrap

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
COOKBOOK = ROOT / "docs" / "COOKBOOK.md"
SUITES = ROOT / "tests_containers" / "suites"
#: A copy sits between two marker lines, which may be indented with the code.
MARKED = re.compile(
    r"^[ \t]*# --- docs/COOKBOOK\.md: begin ---\n(.*?)^[ \t]*# --- docs/COOKBOOK\.md: end ---\n",
    re.MULTILINE | re.DOTALL,
)

pytestmark = pytest.mark.skipif(
    not (COOKBOOK.is_file() and SUITES.is_dir()),
    reason="needs the repository's docs/ and tests_containers/ (not part of every source copy)",
)


def _copies() -> list[pathlib.Path]:
    if not SUITES.is_dir():
        return []
    return sorted(
        path for path in SUITES.rglob("*.py") if MARKED.search(path.read_text(encoding="utf-8"))
    )


def _printed_blocks() -> list[str]:
    return re.findall(r"```python\n(.*?)```", COOKBOOK.read_text(encoding="utf-8"), flags=re.S)


def test_the_suites_hold_copies_of_the_recipes() -> None:
    names = {path.relative_to(SUITES).as_posix() for path in _copies()}
    assert {"fastapi/cookbook_recipe.py", "django/djapp/middleware.py"} <= names


@pytest.mark.parametrize("path", _copies(), ids=lambda p: p.relative_to(SUITES).as_posix())
def test_a_copy_is_a_code_block_of_the_cookbook_character_for_character(path) -> None:
    printed = _printed_blocks()
    for copy in MARKED.findall(path.read_text(encoding="utf-8")):
        # A copy inside a function is indented with it; the cookbook prints it flush left.
        assert textwrap.dedent(copy) in printed, (
            f"{path.name}: this copy differs from every python block of the cookbook:\n{copy}"
        )
