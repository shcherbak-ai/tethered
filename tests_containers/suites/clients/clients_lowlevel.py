"""Sockets, the standard library's protocol clients, SSH, and resolvers of their own.

The ``*_then_connect`` functions are the pattern "look the name up with a DNS
library, connect to the address with a socket": the lookup is the library's,
the connection is Python's.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket

from client_case import note

#: Long enough for a lookup and a connection on a busy machine.
TIMEOUT = 5.0
#: How long a client waits for a server that never speaks first, where that
#: includes the lookup and the connection.
SERVER_FIRST = 1
#: The same where the clock starts only when the connection is there.
AFTER_CONNECTING = 0.3
REQUEST = b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n"


def _is_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _exchange(address: str, port: int) -> None:
    with socket.create_connection((address, port), timeout=TIMEOUT) as sock:
        sock.sendall(REQUEST)
        while sock.recv(4096):
            pass


# ── Sockets ───────────────────────────────────────────────────────────


def socket_create_connection(host: str, port: int) -> None:
    _exchange(host, port)


def asyncio_open_connection(host: str, port: int) -> None:
    async def go() -> None:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), TIMEOUT)
        writer.write(REQUEST)
        await reader.read()
        writer.close()

    asyncio.run(go())


# ── The standard library's protocol clients ───────────────────────────


def smtplib_connect(host: str, port: int) -> None:
    import smtplib

    smtplib.SMTP(host, port, timeout=SERVER_FIRST).close()


def ftplib_connect(host: str, port: int) -> None:
    import ftplib

    client = ftplib.FTP(timeout=SERVER_FIRST)
    try:
        client.connect(host, port)
    finally:
        client.close()


# ── SSH ───────────────────────────────────────────────────────────────


def paramiko_connect(host: str, port: int) -> None:
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username="tc",
            password="tc",
            timeout=TIMEOUT,
            banner_timeout=AFTER_CONNECTING,
            allow_agent=False,
            look_for_keys=False,
        )
    finally:
        client.close()


def asyncssh_connect(host: str, port: int) -> None:
    import asyncssh

    async def go() -> None:
        connecting = asyncssh.connect(
            host, port, known_hosts=None, username="tc", password="tc", config=None
        )
        async with await asyncio.wait_for(connecting, SERVER_FIRST):
            pass

    asyncio.run(go())


# ── A resolver of the library's own, then a Python socket ─────────────


def dnspython_then_connect(host: str, port: int) -> None:
    import dns.resolver

    address = host
    if not _is_address(host):
        address = dns.resolver.resolve(host, "A", lifetime=TIMEOUT)[0].address
    _exchange(address, port)


def _pycares_lookup(host: str, **channel_options: object) -> str:
    """One A lookup with c-ares, which here runs its own event thread."""
    import pycares

    note(c_ares=pycares.ARES_VERSION)
    answer: list[object] = []

    def on_result(result: object, error: object) -> None:
        answer.extend((result, error))

    channel = pycares.Channel(**channel_options)
    try:
        channel.query(host, pycares.QUERY_TYPE_A, callback=on_result)
        if not channel.wait(TIMEOUT) or not answer:
            raise TimeoutError(f"c-ares did not answer for {host}")
    finally:
        channel.close()
    result, error = answer
    if error is not None:
        raise OSError(f"c-ares: {pycares.errno.strerror(error)}")
    return _first_address(result)


def _first_address(result: object) -> str:
    """The address in a pycares / aiodns answer, whatever shape this version gives it."""
    for record in getattr(result, "answer", None) or result:  # type: ignore[union-attr]
        data = getattr(record, "data", record)
        for attribute in ("addr", "host", "address"):
            value = getattr(data, attribute, None)
            if value:
                return value.decode() if isinstance(value, bytes) else str(value)
    raise OSError(f"no address in {result!r}")


def pycares_then_connect(host: str, port: int) -> None:
    address = host if _is_address(host) else _pycares_lookup(host)
    _exchange(address, port)


def aiodns_then_connect(host: str, port: int) -> None:
    import aiodns

    async def go() -> None:
        address = host
        if not _is_address(host):
            resolver = aiodns.DNSResolver()
            address = _first_address(await asyncio.wait_for(resolver.query_dns(host, "A"), TIMEOUT))
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), TIMEOUT)
        writer.write(REQUEST)
        await reader.read()
        writer.close()

    asyncio.run(go())


# ── A DNS query sent to HOST:PORT as the name server ──────────────────


def dnspython_query_server(host: str, port: int) -> None:
    """One query over UDP to ``host:port`` with dnspython, which uses Python's sockets."""
    import dns.message
    import dns.query

    dns.query.udp(dns.message.make_query("allowed.test", "A"), host, port=port, timeout=0.5)


def pycares_query_server(host: str, port: int) -> None:
    """One query over UDP to ``host:port`` with c-ares, which has sockets of its own."""
    _pycares_lookup("allowed.test", servers=[host], udp_port=port, timeout=0.5, tries=1)
