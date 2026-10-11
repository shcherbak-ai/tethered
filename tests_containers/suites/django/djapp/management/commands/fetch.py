"""``python manage.py fetch HOST PORT``: one GET, as the ``/fetch`` view makes it."""

from __future__ import annotations

import json
from typing import Any

import probe_common
from django.core.management.base import BaseCommand, CommandParser

from djapp.views import fetch


class Command(BaseCommand):
    """GET http://HOST:PORT/ and print one line of JSON about it."""

    help = "GET http://HOST:PORT/ and print one line of JSON about it."

    def add_arguments(self, parser: CommandParser) -> None:
        """The destination."""
        parser.add_argument("host")
        parser.add_argument("port", type=int)

    def handle(self, *args: Any, **options: Any) -> None:
        """Try the destination and print the report."""
        host, port = options["host"], options["port"]
        report = {"op": "fetch", "host": host, "port": port, **probe_common.whoami()}
        try:
            report.update(fetch(host, port), outcome="reached")
        except Exception as exc:
            report.update(probe_common.describe_failure(exc))
        self.stdout.write(json.dumps(report))
