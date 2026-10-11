"""hypercorn's programmatic API: ``python serve_script.py asyncio|trio``.

The arrangement of hypercorn's "API usage" documentation: the script runs the
event loop itself and hands the application to ``serve()``.  There is one
process, no master and no worker, and the application module activates the
policy when it is imported, before the event loop exists.
"""

from __future__ import annotations

import os
import sys

from hypercorn.config import Config


def main(library: str) -> None:
    """Serve the probe application for ``library`` on ``PORT`` until SIGTERM."""
    config = Config()
    config.bind = [f"127.0.0.1:{os.environ['PORT']}"]
    if library == "trio":
        import trio
        from hypercorn.trio import serve
        from probe_trio import app

        trio.run(serve, app, config)
    else:
        import asyncio

        from hypercorn.asyncio import serve
        from probe_asgi import app

        asyncio.run(serve(app, config))


if __name__ == "__main__":
    main(sys.argv[1])
