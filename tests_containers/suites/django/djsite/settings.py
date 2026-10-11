"""Settings of the Django project of the suite.  tethered is activated here.

``settings.py`` is the one module every entry point of a Django project
imports first: the WSGI and ASGI applications, every management command, and
both processes of ``runserver`` when its autoreloader is on.  The policy is
activated as ``TETH_ACTIVATE`` says (see ``probe_common``).

    TETH_ALLOW_FILE   a file with the allow list, one rule per line, read when the
                      settings are imported (how a test changes the policy
                      between two reloads)
    TETH_MIDDLEWARE   "printed": the middleware of docs/COOKBOOK.md as printed;
                      "process_exception": one that uses Django's hook for it
"""

from __future__ import annotations

import os
from pathlib import Path

import probe_common

if os.environ.get("TETH_ALLOW_FILE"):
    os.environ["TETH_ALLOW"] = ",".join(
        Path(os.environ["TETH_ALLOW_FILE"]).read_text(encoding="utf-8").split()
    )
probe_common.activate_from_env()

SECRET_KEY = "not a secret: this project only exists inside a test container"  # nosec B105
DEBUG = False
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]
ROOT_URLCONF = "djsite.urls"
WSGI_APPLICATION = "djsite.wsgi.application"
INSTALLED_APPS = ["djapp"]
MIDDLEWARE = {
    "": [],
    "printed": ["djapp.middleware.EgressBlockedMiddleware"],
    "try_except": ["djapp.middleware_try_except.EgressBlockedMiddleware"],
}[os.environ.get("TETH_MIDDLEWARE", "")]
USE_TZ = True
