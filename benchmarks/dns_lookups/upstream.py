"""The upstream DNS server of the DNS benchmark: what a real resolver would ask.

Benchmark code, run inside the benchmark's container by ``inside.py``.  It is
a minimal authoritative server for one zone, over UDP and TCP, written with the
standard library:

- every name of the zone has an A record with ``--address``, TTL ``--ttl``;
- a name ``lb-K-of-P.<zone>`` or ``lb-K-of-P-ttl-T.<zone>`` is load-balanced:
  each answer is a random subset of K addresses out of the P addresses that
  start at ``--lb-first``, with TTL T (0 when the name has none), as a DNS
  load balancer hands them out;
- any other type (AAAA among them) gets an empty answer with the zone's SOA,
  whose minimum (``--negative-ttl``) is what a cache keeps that answer for;
- a name outside the zone is refused.

Each reply is sent ``--latency-ms`` after its query arrived, without holding up
the queries that arrive meanwhile, as an upstream round trip would be.  The
server counts the queries it receives by type.  On the control port (UDP) the
datagram ``stats`` returns the counts as JSON and ``reset`` sets them to zero.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import random
import re
import struct
from collections import Counter

_TYPE_A = 1
_TYPE_SOA = 6
_TYPE_AAAA = 28
_TYPE_OPT = 41
_CLASS_IN = 1
_RCODE_REFUSED = 5
_RCODE_FORMERR = 1
_TYPE_NAMES = {_TYPE_A: "A", _TYPE_AAAA: "AAAA"}


class Zone:
    """What the server answers, and the count of what it was asked."""

    def __init__(self, options: argparse.Namespace) -> None:
        self.zone = options.zone.lower().rstrip(".")
        self.address = ipaddress.IPv4Address(options.address).packed
        self.ttl = options.ttl
        self.lb_first = ipaddress.IPv4Address(options.lb_first)
        self.lb_pattern = re.compile(
            r"lb-(\d+)-of-(\d+)(?:-ttl-(\d+))?\." + re.escape(self.zone), re.ASCII
        )
        self.negative_ttl = options.negative_ttl
        self.counts: Counter[str] = Counter()
        self.encoded_zone = _encode_name(self.zone)

    def answer(self, query: bytes) -> bytes | None:
        """The reply to one query, or ``None`` for a datagram that is not one."""
        if len(query) < 12:
            return None
        ident, flags, qdcount, _an, _ns, arcount = struct.unpack("!6H", query[:12])
        if flags & 0x8000 or qdcount != 1:
            return None
        try:
            name, offset = _decode_name(query, 12)
            qtype, qclass = struct.unpack("!2H", query[offset : offset + 4])
        except (IndexError, ValueError, struct.error):
            return _header(ident, flags, _RCODE_FORMERR, 0, 0, 0)
        question = query[12 : offset + 4]
        edns = arcount > 0 and _has_opt(query, offset + 4, arcount)
        name = name.lower()
        in_zone = name == self.zone or name.endswith("." + self.zone)
        self.counts["queries"] += 1
        if not in_zone or qclass != _CLASS_IN:
            self.counts["refused"] += 1
            return _header(ident, flags, _RCODE_REFUSED, 1, 0, 0) + question
        self.counts[_TYPE_NAMES.get(qtype, "other")] += 1
        answers: list[bytes] = []
        authority: list[bytes] = []
        if qtype == _TYPE_A:
            balanced = self.lb_pattern.fullmatch(name)
            if balanced:
                answers_count, pool, ttl = (int(group or 0) for group in balanced.groups())
                chosen = random.sample(range(pool), min(answers_count, pool))  # nosec B311
                answers = [
                    _record(b"\xc0\x0c", _TYPE_A, ttl, (self.lb_first + index).packed)
                    for index in chosen
                ]
            else:
                answers = [_record(b"\xc0\x0c", _TYPE_A, self.ttl, self.address)]
        else:
            authority = [self._soa()]
        additional = [_OPT_RECORD] if edns else []
        reply = _header(ident, flags, 0, 1, len(answers), len(authority), len(additional))
        return reply + question + b"".join(answers + authority + additional)

    def _soa(self) -> bytes:
        rdata = (
            _encode_name("ns." + self.zone)
            + _encode_name("hostmaster." + self.zone)
            + struct.pack("!5I", 1, 3600, 600, 86400, self.negative_ttl)
        )
        return _record(self.encoded_zone, _TYPE_SOA, self.negative_ttl, rdata)


# EDNS: a query that carries an OPT record gets one back (no DO bit), so that
# a resolver which probes for EDNS keeps using it and does not re-ask.
_OPT_RECORD = b"\x00" + struct.pack("!HHIH", _TYPE_OPT, 1232, 0, 0)


def _header(
    ident: int, query_flags: int, rcode: int, qd: int, an: int, ns: int, ar: int = 0
) -> bytes:
    # QR, AA and RA set; RD and the opcode copied from the query.
    flags = 0x8000 | 0x0400 | 0x0080 | (query_flags & 0x7900) | rcode
    return struct.pack("!6H", ident, flags, qd, an, ns, ar)


def _record(name: bytes, rtype: int, ttl: int, rdata: bytes) -> bytes:
    return name + struct.pack("!HHIH", rtype, _CLASS_IN, ttl, len(rdata)) + rdata


def _encode_name(name: str) -> bytes:
    labels = [label.encode("ascii") for label in name.rstrip(".").split(".") if label]
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"


def _decode_name(message: bytes, offset: int) -> tuple[str, int]:
    # Questions are never compressed; a pointer here is a malformed query.
    labels = []
    while True:
        length = message[offset]
        offset += 1
        if length == 0:
            return ".".join(labels), offset
        if length & 0xC0:
            raise ValueError("compressed name in a question")
        labels.append(message[offset : offset + length].decode("ascii"))
        offset += length


def _has_opt(message: bytes, offset: int, count: int) -> bool:
    try:
        for _ in range(count):
            _name, offset = _decode_name(message, offset)
            rtype, _class, _ttl, length = struct.unpack("!HHIH", message[offset : offset + 10])
            if rtype == _TYPE_OPT:
                return True
            offset += 10 + length
    except (IndexError, ValueError, struct.error):
        return False
    return False


class _UdpServer(asyncio.DatagramProtocol):
    def __init__(self, zone: Zone, latency: float) -> None:
        self.zone = zone
        self.latency = latency
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)  # nosec B101 - asyncio's contract
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        reply = self.zone.answer(data)
        if reply is not None and self.transport is not None:
            loop = asyncio.get_running_loop()
            loop.call_later(self.latency, self.transport.sendto, reply, addr)


class _Control(asyncio.DatagramProtocol):
    def __init__(self, zone: Zone) -> None:
        self.zone = zone
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)  # nosec B101 - asyncio's contract
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        command = data.strip().decode("ascii", "replace")
        if command == "reset":
            self.zone.counts.clear()
        reply = json.dumps(dict(self.zone.counts)).encode()
        if self.transport is not None:
            self.transport.sendto(reply, addr)


async def _serve(options: argparse.Namespace) -> None:
    zone = Zone(options)
    latency = options.latency_ms / 1000
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(
        lambda: _UdpServer(zone, latency), local_addr=(options.listen, options.port)
    )
    await loop.create_datagram_endpoint(
        lambda: _Control(zone), local_addr=(options.listen, options.control_port)
    )

    async def tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                (length,) = struct.unpack("!H", await reader.readexactly(2))
                reply = zone.answer(await reader.readexactly(length))
                if reply is None:
                    break
                await asyncio.sleep(latency)
                writer.write(struct.pack("!H", len(reply)) + reply)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(tcp_client, options.listen, options.port)
    print(f"upstream: serving {zone.zone} on {options.listen}:{options.port}", flush=True)
    async with server:
        await server.serve_forever()


def main() -> None:
    """Parse the options and serve until killed."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="192.0.2.53")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--control-port", type=int, default=5300)
    parser.add_argument("--zone", default="bench.test")
    parser.add_argument("--address", default="127.0.0.10")
    parser.add_argument("--ttl", type=int, default=300)
    parser.add_argument("--negative-ttl", type=int, default=300)
    # 198.18.0.0/15 is set aside for benchmarks (RFC 2544).
    parser.add_argument("--lb-first", default="198.18.0.1")
    parser.add_argument("--latency-ms", type=float, default=20.0)
    asyncio.run(_serve(parser.parse_args()))


if __name__ == "__main__":
    main()
