"""What a container test asserts with: the destinations, the world's counters, HTTP.

Everything here runs in the pytest process, which never holds a tethered
policy and never imports tethered.  ``harness.servers`` starts the processes
that do.  ``tests_containers/README.md`` documents the functions.
"""

from __future__ import annotations

import http.client
import json
import os
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness.world import (
    ADDRESSES,
    ALLOWED_ADDR,
    ALLOWED_NAME,
    CONTROL_HOST,
    CONTROL_PORT,
    FORBIDDEN_ADDR,
    FORBIDDEN_NAME,
    LOOPBACK_ADDR,
    NAMES,
    PORTS,
)

__all__ = [
    "ALLOWED_ADDR",
    "ALLOWED_NAME",
    "ALLOWED_PORT",
    "APPS_DIR",
    "FORBIDDEN_ADDR",
    "FORBIDDEN_NAME",
    "LOOPBACK_ADDR",
    "OTHER_PORT",
    "PORTS",
    "SUITE_DIR",
    "Response",
    "arrivals",
    "arrived",
    "dns_queries",
    "http_get",
    "probe_path",
    "reset_arrivals",
]

#: The probe applications allow ``allowed.test:9001`` and nothing else.
ALLOWED_PORT = 9001
#: A port that no rule allows, on either destination.
OTHER_PORT = 9002

HARNESS_DIR = Path(__file__).resolve().parent
#: The shared applications under test; on ``PYTHONPATH`` of everything the harness starts.
APPS_DIR = HARNESS_DIR / "apps"
#: The directory of the suite this image was built for; also on that ``PYTHONPATH``.
SUITE_DIR = HARNESS_DIR.parent / "suites" / os.environ.get("TC_SUITE", "")
#: Where the output of the world, of every server and of every script is kept.
LOG_DIR = Path(tempfile.gettempdir()) / "tc-logs"

_CONTROL_URL = f"http://{CONTROL_HOST}:{CONTROL_PORT}"
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# ── HTTP ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Response:
    """An HTTP response; any status is a response, 500 included."""

    status: int
    headers: dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        """The body as text."""
        return self.body.decode("utf-8", "replace")

    def json(self) -> Any:
        """The body parsed as JSON; an ``AssertionError`` that shows the body if it is not."""
        try:
            return json.loads(self.body)
        except ValueError:
            raise AssertionError(f"HTTP {self.status}, not JSON: {self.text[:2000]!r}") from None


def http_get(url: str, timeout: float = 30.0) -> Response:
    """GET ``url`` with the standard library, ignoring proxy settings.

    An HTTP error status is returned like any other response.  When no
    response arrives at all, the exception is an ``OSError``.
    """
    try:
        with _NO_PROXY.open(url, timeout=timeout) as reply:
            return Response(reply.status, dict(reply.headers.items()), reply.read())
    except urllib.error.HTTPError as error:
        with error:
            return Response(error.code, dict(error.headers.items()), error.read())
    except http.client.HTTPException as error:
        raise ConnectionError(f"GET {url}: {type(error).__name__}: {error}") from error


def probe_path(op: str, host: str | None = None, port: int | None = None, **params: object) -> str:
    """The path of one probe: ``probe_path("connect", "forbidden.test", 9002)``.

    Further keyword arguments become query parameters (``uncaught=1``, ``how="no_site"``).
    """
    query = {
        key: str(value)
        for key, value in {"host": host, "port": port, **params}.items()
        if value is not None
    }
    return f"/{op}?{urllib.parse.urlencode(query)}" if query else f"/{op}"


# ── The world's counters ──────────────────────────────────────────────


def _control(request: str) -> dict[str, Any]:
    try:
        reply = http_get(f"{_CONTROL_URL}{request}", timeout=10.0)
    except OSError as error:
        try:
            said = (LOG_DIR / "world.log").read_text(errors="replace")[-4000:]
        except OSError:
            said = "(no output)"
        raise RuntimeError(f"the world does not answer ({error}); its output:\n{said}") from error
    if reply.status != 200:
        raise RuntimeError(f"the world answered {request} with HTTP {reply.status}: {reply.text}")
    return reply.json()


def arrivals() -> dict[str, int]:
    """Every arrival since the last reset, as ``{"10.77.0.20:9002/tcp": 1, ...}``.

    Destinations that nothing reached are absent, so ``arrivals() == {}``
    reads "nothing left the process under test".  Arrivals on loopback count.
    """
    return _control("/arrivals")["arrivals"]


def arrived(destination: str, port: int, proto: str = "tcp") -> int:
    """How many connections (or datagrams, ``proto="udp"``) reached one destination.

    ``destination`` is one of the world's names or addresses.  Anything else
    raises ``ValueError``: a mistyped destination would otherwise read as
    "nothing arrived" and let a "blocked" assertion pass for the wrong reason.
    """
    address = NAMES.get(destination, destination)
    if address not in ADDRESSES:
        raise ValueError(f"{destination!r} is not a destination of the world: {ADDRESSES}")
    if port not in PORTS:
        raise ValueError(f"the world does not listen on port {port}: {PORTS}")
    if proto not in ("tcp", "udp"):
        raise ValueError(f"proto is 'tcp' or 'udp', not {proto!r}")
    return arrivals().get(f"{address}:{port}/{proto}", 0)


def dns_queries() -> dict[str, int]:
    """Queries the world's DNS responder received since the last reset: ``{"name/A": 1}``."""
    return _control("/arrivals")["dns"]


def reset_arrivals() -> None:
    """Set every counter to zero.  The harness does this before each test."""
    _control("/reset")
