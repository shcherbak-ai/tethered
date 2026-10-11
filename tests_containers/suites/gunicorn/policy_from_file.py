"""``probe_wsgi`` with an allow list that is read from a file when the application is imported.

``policy_from_file:application`` stands for a deployment whose new release
asks for another policy: a test rewrites the file named by ``TETH_ALLOW_FILE``
(one rule per line) between the start of a server and its upgrade.
"""

from __future__ import annotations

import os
from pathlib import Path

os.environ["TETH_ALLOW"] = ",".join(
    Path(os.environ["TETH_ALLOW_FILE"]).read_text(encoding="utf-8").split()
)

# Importing the probe activates the policy, as the environment now says.
from probe_wsgi import application

__all__ = ["application"]
