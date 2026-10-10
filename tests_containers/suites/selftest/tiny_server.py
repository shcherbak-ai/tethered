"""A server made of the standard library, for the harness's own tests.

    python tiny_server.py PORT [exit-at-once] [ignore-sigterm] [leave-a-child]

It answers every GET with its pid as JSON and has nothing to do with
tethered.  The flags make it misbehave in the ways ``Server.stop`` and
``start_server`` have to notice.
"""

from __future__ import annotations

import http.server
import json
import os
import signal
import subprocess
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    """Answers every GET with ``{"pid": ..., "path": ...}``."""

    def do_GET(self) -> None:
        """Answer one request."""
        body = json.dumps({"pid": os.getpid(), "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Log to stdout, where the harness captures it."""
        print("tiny: " + format % args, flush=True)


def _exit(signum: int, frame: object) -> None:
    raise SystemExit(0)


def main(port: int, flags: set[str]) -> int:
    """Serve until SIGTERM, unless a flag says otherwise."""
    if "exit-at-once" in flags:
        print("tiny: giving up at once", flush=True)
        return 3
    signal.signal(signal.SIGTERM, signal.SIG_IGN if "ignore-sigterm" in flags else _exit)
    if "leave-a-child" in flags:
        # Outlives this process and stays in its session.
        subprocess.Popen(["sleep", "300"])
    server = http.server.HTTPServer(("127.0.0.1", port), Handler)
    print(f"tiny: listening on {port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]), set(sys.argv[2:])))
