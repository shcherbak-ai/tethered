"""The command line of tethered: ``python -m tethered check``.

One command, ``check``: the preflight check of ``_check.py``.  It reports and
changes nothing, so its exit status is 0 whatever it finds; a usage error is
argparse's 2.
"""

from __future__ import annotations

import argparse
import sys

from tethered import _check


def main(argv: list[str] | None = None) -> int:
    """Run the command line with ``argv`` (``sys.argv[1:]`` when None); return the exit status."""
    parser = argparse.ArgumentParser(
        prog="python -m tethered",
        description="tethered: runtime network egress control for Python.",
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    commands.add_parser(
        "check",
        help="report what of tethered's compatibility page applies to this environment",
        description=(
            "Report what tethered would refuse in this environment, what it would not see, "
            "and what needs configuration, with a link to the documentation for each "
            "finding. It reports what is installed, not what the application uses. Nothing "
            "is activated, imported from third parties, written or sent. The exit status is "
            "0 whatever is found."
        ),
    )
    parser.parse_args(argv)
    _check.run(sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
