"""The world: every destination a process under test can try to reach.

The container has no network (``--network none``).  The ``world`` fixture gives
the loopback interface two more addresses and starts this module as a process
of its own, which never imports tethered and holds no policy:

    10.77.0.10  allowed.test     the probe applications allow ``allowed.test:9001``
    10.77.0.20  forbidden.test   never allowed

On each address, and on 127.0.0.1, ports 9001 to 9003 have a TCP listener that
answers with a minimal HTTP response and a UDP listener that answers with one
datagram.  Every accepted connection and every received datagram is counted
under ``"<address>:<port>/<tcp|udp>"``.  Those counters are the ground truth of
the suites: a destination was reached if its counter moved, and it was not if
the counter stayed where it was, whatever the application under test reports.

A minimal DNS responder on 127.0.0.1:53 knows the two names (an A record each,
an empty answer for AAAA, NXDOMAIN for every other name), for client libraries
that resolve names without reading ``/etc/hosts``.  Queries are counted under
``"<name>/<type>"``.

The control endpoint on 127.0.0.1:9100 speaks just enough HTTP for
``urllib``: ``GET /arrivals``, ``GET /reset``, ``GET /health``.

Everything is counted in one thread, and that thread handles everything that
is already waiting on the listeners before it answers a control request.  A
connection that was established before ``/arrivals`` was asked for is therefore
in the answer; no settling time is needed.
"""

from __future__ import annotations

import json
import selectors
import socket
import struct
import sys
import threading
from collections.abc import Callable

ALLOWED_NAME = "allowed.test"
ALLOWED_ADDR = "10.77.0.10"
FORBIDDEN_NAME = "forbidden.test"
FORBIDDEN_ADDR = "10.77.0.20"
LOOPBACK_ADDR = "127.0.0.1"

#: The names the world answers for.  Loopback has listeners too, and no name.
NAMES = {ALLOWED_NAME: ALLOWED_ADDR, FORBIDDEN_NAME: FORBIDDEN_ADDR}
ADDRESSES = (ALLOWED_ADDR, FORBIDDEN_ADDR, LOOPBACK_ADDR)
PORTS = (9001, 9002, 9003)

CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 9100
DNS_PORT = 53

_QTYPES = {1: "A", 28: "AAAA"}
_Handler = Callable[[socket.socket], None]


def dns_reply(query: bytes) -> tuple[bytes, str] | None:
    """Answer one DNS query; returns the reply and ``"<name>/<type>"``, or ``None`` to drop it."""
    if len(query) < 12:
        return None
    ident, flags, questions = struct.unpack("!HHH", query[:6])
    if flags & 0x8000 or questions != 1:
        return None
    labels: list[bytes] = []
    pos = 12
    while True:
        if pos >= len(query):
            return None
        length = query[pos]
        pos += 1
        if length == 0:
            break
        if length & 0xC0 or pos + length > len(query):
            return None
        labels.append(query[pos : pos + length])
        pos += length
    if pos + 4 > len(query):
        return None
    qtype, qclass = struct.unpack("!HH", query[pos : pos + 4])
    question = query[12 : pos + 4]
    name = b".".join(labels).decode("ascii", "replace").lower()
    address = NAMES.get(name)
    answer = b""
    if address is not None and qtype == 1 and qclass == 1:
        # A pointer to the name in the question, type A, class IN, TTL 60, four bytes.
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
    rcode = 0 if address is not None else 3
    # A response, authoritative, recursion available; "recursion desired" is echoed.
    reply_flags = 0x8000 | 0x0400 | 0x0080 | (flags & 0x0100) | rcode
    header = struct.pack("!HHHHHH", ident, reply_flags, 1, 1 if answer else 0, 0, 0)
    return header + question + answer, f"{name}/{_QTYPES.get(qtype, str(qtype))}"


def _answer_http(conn: socket.socket, label: str) -> None:
    """Read one request head (or give up after two seconds) and answer it."""
    with conn:
        conn.settimeout(2.0)
        head = b""
        try:
            while b"\r\n\r\n" not in head and len(head) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                head += chunk
        except OSError:
            pass
        body = f"reached {label}\n".encode()
        try:
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
        except OSError:
            pass


class World:
    """The listeners, their counters and the loop that serves them."""

    def __init__(self) -> None:
        self.arrivals: dict[str, int] = {}
        self.dns_queries: dict[str, int] = {}
        self._selector = selectors.DefaultSelector()
        self._control: socket.socket | None = None

    def _register(self, sock: socket.socket, handler: _Handler) -> None:
        self._selector.register(sock, selectors.EVENT_READ, handler)

    def _count(self, counters: dict[str, int], key: str) -> None:
        counters[key] = counters.get(key, 0) + 1

    def open(self) -> None:
        """Bind every listener.  Fails if an address is missing or a port is taken."""
        for address in ADDRESSES:
            for port in PORTS:
                tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tcp.bind((address, port))
                tcp.listen(128)
                tcp.setblocking(False)
                self._register(tcp, self._tcp_handler(f"{address}:{port}"))

                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp.bind((address, port))
                udp.setblocking(False)
                self._register(udp, self._udp_handler(f"{address}:{port}"))

        dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns.bind((CONTROL_HOST, DNS_PORT))
        dns.setblocking(False)
        self._register(dns, self._on_dns)

        control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        control.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        control.bind((CONTROL_HOST, CONTROL_PORT))
        control.listen(32)
        control.setblocking(False)
        self._control = control
        self._register(control, self._on_control)

    def _tcp_handler(self, label: str) -> _Handler:
        def on_connection(listener: socket.socket) -> None:
            try:
                conn, _peer = listener.accept()
            except OSError:
                return
            self._count(self.arrivals, f"{label}/tcp")
            threading.Thread(target=_answer_http, args=(conn, label), daemon=True).start()

        return on_connection

    def _udp_handler(self, label: str) -> _Handler:
        def on_datagram(sock: socket.socket) -> None:
            try:
                _data, peer = sock.recvfrom(65535)
            except OSError:
                return
            self._count(self.arrivals, f"{label}/udp")
            try:
                sock.sendto(f"reached {label}\n".encode(), peer)
            except OSError:
                pass

        return on_datagram

    def _on_dns(self, sock: socket.socket) -> None:
        try:
            query, peer = sock.recvfrom(4096)
        except OSError:
            return
        answered = dns_reply(query)
        if answered is None:
            return
        reply, key = answered
        self._count(self.dns_queries, key)
        try:
            sock.sendto(reply, peer)
        except OSError:
            pass

    def _drain(self) -> None:
        """Handle everything that is already waiting on a listener."""
        while True:
            waiting = [
                key
                for key, _ in self._selector.select(timeout=0)
                if key.fileobj is not self._control
            ]
            if not waiting:
                return
            for key in waiting:
                key.data(key.fileobj)

    def _on_control(self, listener: socket.socket) -> None:
        try:
            conn, _peer = listener.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(2.0)
            head = b""
            try:
                while b"\r\n\r\n" not in head and len(head) < 65536:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    head += chunk
            except OSError:
                return
            target = head.split(b" ", 2)[1].decode("ascii", "replace") if b" " in head else ""
            self._drain()
            status = "200 OK"
            if target == "/arrivals":
                answer: dict[str, object] = {"arrivals": self.arrivals, "dns": self.dns_queries}
            elif target == "/reset":
                self.arrivals = {}
                self.dns_queries = {}
                answer = {"reset": True}
            elif target == "/health":
                answer = {"ok": True}
            else:
                status = "404 Not Found"
                answer = {"error": f"no such control request: {target}"}
            body = json.dumps(answer, sort_keys=True).encode()
            try:
                conn.sendall(
                    f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
                    f"Connection: close\r\nContent-Length: {len(body)}\r\n\r\n".encode()
                    + body
                )
            except OSError:
                pass

    def serve_forever(self) -> None:
        """Serve until the process is terminated."""
        while True:
            for key, _ in self._selector.select():
                key.data(key.fileobj)


def main() -> int:
    """Open the world and serve it; prints one line when the listeners are up."""
    world = World()
    world.open()
    print("world: listening", flush=True)
    world.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
