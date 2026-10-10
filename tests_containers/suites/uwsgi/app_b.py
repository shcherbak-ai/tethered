"""The application "b" of the uWSGI suite, for the tests that mount two applications."""

from __future__ import annotations

from uwsgi_app import make

application = make("b")
