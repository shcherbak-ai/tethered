"""The application "a" of the uWSGI suite: activates tethered when uWSGI imports this file."""

from __future__ import annotations

from uwsgi_app import make

application = make("a")
