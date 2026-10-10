"""uvicorn started from Python, never with a ``loop`` argument: ``run_from_python.py HOW``.

The loop is uvicorn's own choice in every arrangement here, which with uvloop
installed is uvloop whenever importing it works.  ``HOW`` is one of:

    run             uvicorn.run("probe_asgi:app")
    run-object      import the application, then uvicorn.run(app)
    run-workers     uvicorn.run("probe_asgi:app", workers=2)
    activate-run    tethered.activate(...), then uvicorn.run("probe_asgi:app")
    activate-run-workers
                    tethered.activate(...), then uvicorn.run("probe_asgi:app", workers=2)
    server-run      uvicorn.Server(uvicorn.Config("probe_asgi:app")).run()
    serve           asyncio.run(uvicorn.Server(uvicorn.Config("probe_asgi:app")).serve())

The application activates as ``TETH_ACTIVATE`` says when it is imported.  The
two ``activate-`` arrangements activate here first, as ``LAUNCH_ACTIVATE``
says (``plain`` or ``locked``); with ``TETH_ACTIVATE=none`` the application
then only inherits.  Everything is under the ``__main__`` guard: a worker runs
this file again as multiprocessing's ``__mp_main__``.
"""

from __future__ import annotations

import os
import sys


def _activate() -> None:
    import tethered

    how = os.environ.get("LAUNCH_ACTIVATE", "locked")
    extra = {"locked": True, "lock_token": object()} if how == "locked" else {}
    tethered.activate(allow=["allowed.test:9001"], **extra)
    print(f"launcher: pid {os.getpid()} activated tethered ({how})", file=sys.stderr, flush=True)


def main(how: str) -> None:
    """Start uvicorn the way ``how`` says."""
    address = {"host": "127.0.0.1", "port": int(os.environ["PORT"])}
    if how.startswith("activate-"):
        _activate()
        how = how.removeprefix("activate-")

    import uvicorn

    if how == "run":
        uvicorn.run("probe_asgi:app", **address)
    elif how == "run-object":
        import probe_asgi

        uvicorn.run(probe_asgi.app, **address)
    elif how == "run-workers":
        uvicorn.run("probe_asgi:app", workers=2, **address)
    elif how == "server-run":
        uvicorn.Server(uvicorn.Config("probe_asgi:app", **address)).run()
    elif how == "serve":
        import asyncio

        asyncio.run(uvicorn.Server(uvicorn.Config("probe_asgi:app", **address)).serve())
    else:
        raise SystemExit(f"unknown arrangement: {how}")


if __name__ == "__main__":
    main(sys.argv[1])
