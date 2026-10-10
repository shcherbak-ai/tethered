"""A launcher script: lock the policy first, then let uvicorn start two workers.

This is the arrangement in which the process that starts the server holds the
policy.  uvicorn starts its workers as new Python processes, and those inherit
the policy at startup, before they import anything of the application.

The activation is under the ``__main__`` guard on purpose.  A worker runs this
file again as multiprocessing's ``__mp_main__``; with the guard it does not
call ``activate()`` here, so whatever policy a worker holds with
``TETH_ACTIVATE=none`` it has inherited.  With ``TETH_ACTIVATE=locked`` the
application (``probe_asgi``) asks for the same policy again in each worker.
"""

from __future__ import annotations

import os


def main() -> None:
    """Activate a locked policy, then serve ``probe_asgi:app`` with two workers."""
    import tethered

    tethered.activate(
        allow=["allowed.test:9001"],
        locked=True,
        lock_token=object(),
        external_subprocess_policy=os.environ.get("TETH_ESP", "warn"),
    )

    import uvicorn

    uvicorn.run(
        "probe_asgi:app",
        host="127.0.0.1",
        port=int(os.environ["PORT"]),
        workers=2,
        loop="asyncio",
    )


if __name__ == "__main__":
    main()
