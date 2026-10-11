"""Names that exist only in DNS, as in the clients suite.

The harness writes the world's two names into ``/etc/hosts``.  This suite takes
them out again for its session: every lookup is then a query to the world's
DNS responder, which counts it.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from harness.world import NAMES

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(scope="session", autouse=True)
def names_only_in_dns(world: object) -> Iterator[None]:
    """Remove the world's names from ``/etc/hosts`` while this suite runs."""
    hosts = Path("/etc/hosts")
    original = hosts.read_text()
    kept = [line for line in original.splitlines() if not set(line.split()[1:]) & set(NAMES)]
    # Docker mounts the file into the container: it is written in place.
    hosts.write_text("\n".join(kept) + "\n")
    try:
        yield
    finally:
        hosts.write_text(original)
