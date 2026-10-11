"""HTTP clients: one GET to ``http://HOST:PORT/`` each.

Every function here is one row of ``catalog.VARIANTS``.  It makes one attempt,
with no retries and no proxy, and raises when the attempt fails.
"""

from __future__ import annotations

import asyncio
import io
import sys

from client_case import note

#: Long enough for a lookup and a connection on a busy machine; nothing here waits it out.
TIMEOUT = 5.0


def _url(host: str, port: int) -> str:
    return f"http://{host}:{port}/"


# ── The standard library ──────────────────────────────────────────────


def urllib_request(host: str, port: int) -> None:
    import urllib.request

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(_url(host, port), timeout=TIMEOUT) as reply:
        reply.read()


def http_client(host: str, port: int) -> None:
    import http.client

    connection = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
    try:
        connection.request("GET", "/")
        connection.getresponse().read()
    finally:
        connection.close()


# ── requests, urllib3, httplib2 ───────────────────────────────────────


def requests_get(host: str, port: int) -> None:
    import requests

    with requests.Session() as session:
        session.trust_env = False
        session.get(_url(host, port), timeout=TIMEOUT)


def urllib3_request(host: str, port: int) -> None:
    import urllib3

    with urllib3.PoolManager(retries=False, timeout=TIMEOUT) as pool:
        pool.request("GET", _url(host, port))


def httplib2_request(host: str, port: int) -> None:
    import httplib2

    httplib2.Http(timeout=TIMEOUT).request(_url(host, port), "GET")


# ── httpx ─────────────────────────────────────────────────────────────


def httpx_sync(host: str, port: int) -> None:
    import httpx

    with httpx.Client(trust_env=False, timeout=TIMEOUT) as client:
        client.get(_url(host, port))


async def _httpx_get(host: str, port: int) -> None:
    import httpx

    async with httpx.AsyncClient(trust_env=False, timeout=TIMEOUT) as client:
        await client.get(_url(host, port))


def httpx_asyncio(host: str, port: int) -> None:
    asyncio.run(_httpx_get(host, port))


def httpx_trio(host: str, port: int) -> None:
    import trio

    trio.run(_httpx_get, host, port)


# ── aiohttp ───────────────────────────────────────────────────────────


async def _aiohttp_get(host: str, port: int, connector_options: dict) -> None:
    import aiohttp

    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
    connector = aiohttp.TCPConnector(**connector_options)
    resolver = type(connector._resolver)
    note(
        resolver=f"{resolver.__module__}.{resolver.__name__}",
        aiodns_imported=sys.modules.get("aiodns") is not None,
    )
    session = aiohttp.ClientSession(connector=connector, timeout=timeout)
    async with session, session.get(_url(host, port)) as reply:
        await reply.read()


def aiohttp_get(host: str, port: int) -> None:
    """The default connector: its resolver depends on whether aiodns can be imported."""
    asyncio.run(_aiohttp_get(host, port, {}))


def aiohttp_threaded_resolver(host: str, port: int) -> None:
    """The resolver that asks ``loop.getaddrinfo``, chosen explicitly."""

    async def go() -> None:
        from aiohttp.resolver import ThreadedResolver

        await _aiohttp_get(host, port, {"resolver": ThreadedResolver()})

    asyncio.run(go())


# ── libcurl ───────────────────────────────────────────────────────────


def pycurl_get(host: str, port: int) -> None:
    import pycurl

    note(libcurl=pycurl.version)
    curl = pycurl.Curl()
    try:
        curl.setopt(pycurl.URL, _url(host, port))
        curl.setopt(pycurl.WRITEDATA, io.BytesIO())
        curl.setopt(pycurl.NOPROXY, "*")
        curl.setopt(pycurl.CONNECTTIMEOUT, int(TIMEOUT))
        curl.setopt(pycurl.TIMEOUT, int(TIMEOUT))
        curl.perform()
    finally:
        curl.close()


def curl_cffi_get(host: str, port: int) -> None:
    import curl_cffi

    curl_cffi.get(_url(host, port), timeout=TIMEOUT)


# ── tornado ───────────────────────────────────────────────────────────


def _tornado_fetch(client_class: str, host: str, port: int) -> None:
    import importlib

    module, _, name = client_class.rpartition(".")

    async def go() -> None:
        client = getattr(importlib.import_module(module), name)(force_instance=True)
        try:
            await client.fetch(_url(host, port), connect_timeout=TIMEOUT, request_timeout=TIMEOUT)
        finally:
            client.close()

    asyncio.run(go())


def tornado_simple(host: str, port: int) -> None:
    _tornado_fetch("tornado.simple_httpclient.SimpleAsyncHTTPClient", host, port)


def tornado_curl(host: str, port: int) -> None:
    _tornado_fetch("tornado.curl_httpclient.CurlAsyncHTTPClient", host, port)


# ── websockets ────────────────────────────────────────────────────────


def websockets_asyncio(host: str, port: int) -> None:
    from websockets.asyncio.client import connect

    async def go() -> None:
        async with connect(f"ws://{host}:{port}/", open_timeout=TIMEOUT, proxy=None):
            pass

    asyncio.run(go())


def websockets_sync(host: str, port: int) -> None:
    from websockets.sync.client import connect

    with connect(f"ws://{host}:{port}/", open_timeout=TIMEOUT, proxy=None):
        pass
