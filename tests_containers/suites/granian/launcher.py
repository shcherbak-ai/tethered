"""A launcher script: lock the policy first, then let granian start its workers.

    python launcher.py INTERFACE LOOP WORKERS [respawn]

This is the arrangement in which the process that starts the server holds the
policy before granian is imported.  granian imports every event-loop package
it finds when it is imported itself, so this order is the one in which a
policy is in place before uvloop could be loaded: in this process, and in the
workers, which inherit the policy when they start (forked from this process
up to Python 3.13, new interpreters from 3.14 on).

The activation is under the ``__main__`` guard on purpose: a worker that is a
new interpreter runs this file again as multiprocessing's ``__mp_main__``, and
whatever policy it holds with ``TETH_ACTIVATE=none`` it has inherited.

``respawn`` makes granian replace a worker that died (``respawn_failed_workers``).
"""

from __future__ import annotations

import os
import sys

APPLICATIONS = {
    "asgi": "probe_asgi:app",
    "rsgi": "probe_rsgi:app",
    "wsgi": "probe_wsgi:application",
}


def main(interface: str, loop: str, workers: int, respawn: bool) -> None:
    """Activate a locked policy, then serve the probe application of ``interface``."""
    import tethered

    tethered.activate(
        allow=["allowed.test:9001"],
        locked=True,
        lock_token=object(),
        external_subprocess_policy=os.environ.get("TETH_ESP", "warn"),
    )

    from granian import Granian

    Granian(
        APPLICATIONS[interface],
        address="127.0.0.1",
        port=int(os.environ["PORT"]),
        interface=interface,
        loop=loop,
        workers=workers,
        respawn_failed_workers=respawn,
    ).serve()


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4:] == ["respawn"])
