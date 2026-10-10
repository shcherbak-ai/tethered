"""The Python child a probe application launches: ``probe_child.py HOST PORT``.

It never calls ``tethered.activate()``: whatever policy it holds, it inherited
at startup.  It makes one blocking connection to ``HOST:PORT`` and prints one
line of JSON: who it is (``probe_common.whoami``) and how the connection went.
"""

from __future__ import annotations

import json
import sys

import probe_common


def main(host: str, port: int) -> int:
    """Try the destination and print the report."""
    report = {"op": "connect", "host": host, "port": port, **probe_common.whoami()}
    try:
        report.update(probe_common.tcp_connect(host, port), outcome="reached")
    except Exception as exc:
        report.update(probe_common.describe_failure(exc))
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], int(sys.argv[2])))
