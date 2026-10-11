"""The command line of the Django project of the suite: ``python manage.py <command>``."""

from __future__ import annotations

import os
import sys


def main() -> None:
    """Run a management command with the settings of ``djsite``."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "djsite.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
