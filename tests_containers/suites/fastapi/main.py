"""The FastAPI application of this suite: ``main:app``, activation at import.

The policy is activated first, as ``TETH_ACTIVATE`` says (see
``probe_common`` in ``harness/apps``).  The application object and its
exception handler are the cookbook's recipe, untouched (``cookbook_recipe``);
``endpoints`` adds the routes.  The file is called ``main.py`` because that
is the name FastAPI's documentation uses and the first one ``fastapi run``
looks for.
"""

from __future__ import annotations

import probe_common

probe_common.activate_from_env()

from cookbook_recipe import app  # noqa: E402
from endpoints import router  # noqa: E402

app.include_router(router)
