"""Database clients: one connection attempt to ``HOST:PORT`` each.

The destinations answer every connection with an HTTP response, so each of
these fails its handshake after it has connected.  That is what the suite
needs: whether a TCP connection arrived is the fact that is measured.

The world answers as soon as it has read an empty line.  Where a protocol lets
the client speak first, the functions put ``MARK`` into a field the client
sends (a database or application name), so that the answer, and with it the
client's protocol error, comes at once.  Where the server speaks first the
client's own timeout ends the attempt, a second or less after the connection.
"""

from __future__ import annotations

import asyncio
import glob
import os
from typing import Any

from client_case import note

#: Long enough for a lookup and a connection on a busy machine.
TIMEOUT = 5.0
#: How long a client waits for a server that never speaks first, where that
#: includes the lookup and the connection (and where the library takes whole seconds).
SERVER_FIRST = 1
#: The same where the clock starts only when the connection is there.
AFTER_CONNECTING = 0.3
#: An empty line inside a name: the world answers when it has read one.
MARK = "tc\r\n\r\n"


# ── PostgreSQL ────────────────────────────────────────────────────────


def psycopg2_connect(host: str, port: int) -> None:
    import psycopg2

    note(libpq=psycopg2.__libpq_version__)
    psycopg2.connect(
        host=host,
        port=port,
        user="tc",
        dbname=MARK,
        sslmode="disable",
        gssencmode="disable",
        connect_timeout=int(TIMEOUT),
    ).close()


def _psycopg_arguments(host: str, port: int) -> dict[str, object]:
    import psycopg

    note(implementation=psycopg.pq.__impl__, libpq=psycopg.pq.version())
    wanted = os.environ.get("PSYCOPG_IMPL")
    if wanted and psycopg.pq.__impl__ != wanted:
        raise RuntimeError(f"psycopg runs on {psycopg.pq.__impl__!r}, not on {wanted!r}")
    return {
        "host": host,
        "port": port,
        "user": "tc",
        "dbname": MARK,
        "sslmode": "disable",
        "gssencmode": "disable",
        "connect_timeout": int(TIMEOUT),
    }


def psycopg_sync(host: str, port: int) -> None:
    import psycopg

    psycopg.connect(**_psycopg_arguments(host, port)).close()


def psycopg_async(host: str, port: int) -> None:
    import psycopg

    async def go() -> None:
        connection = await psycopg.AsyncConnection.connect(**_psycopg_arguments(host, port))
        await connection.close()

    asyncio.run(go())


def asyncpg_connect(host: str, port: int) -> None:
    import asyncpg

    async def go() -> None:
        connection = await asyncpg.connect(
            host=host, port=port, user="tc", database=MARK, ssl=False, timeout=TIMEOUT
        )
        await connection.close()

    asyncio.run(go())


def pg8000_connect(host: str, port: int) -> None:
    import pg8000.dbapi

    pg8000.dbapi.connect(
        user="tc", host=host, port=port, database=MARK, ssl_context=False, timeout=TIMEOUT
    ).close()


# ── MySQL ─────────────────────────────────────────────────────────────


def pymysql_connect(host: str, port: int) -> None:
    import pymysql

    pymysql.connect(
        host=host,
        port=port,
        user="tc",
        password="tc",
        connect_timeout=TIMEOUT,
        read_timeout=AFTER_CONNECTING,
    ).close()


def aiomysql_connect(host: str, port: int) -> None:
    import aiomysql

    async def go() -> None:
        connecting = aiomysql.connect(
            host=host, port=port, user="tc", password="tc", connect_timeout=TIMEOUT
        )
        # aiomysql has no timeout for the greeting it then waits for.
        connection = await asyncio.wait_for(connecting, SERVER_FIRST)
        connection.close()

    asyncio.run(go())


def mysqlclient_connect(host: str, port: int) -> None:
    import MySQLdb

    note(client_library=MySQLdb.get_client_info())
    MySQLdb.connect(
        host=host, port=port, user="tc", passwd="tc", connect_timeout=SERVER_FIRST
    ).close()


def _mysql_connector(host: str, port: int, **arguments: object) -> None:
    import mysql.connector

    note(have_cext=mysql.connector.HAVE_CEXT)
    mysql.connector.connect(
        host=host,
        port=port,
        user="tc",
        password="tc",
        connection_timeout=SERVER_FIRST,
        ssl_disabled=True,
        **arguments,
    ).close()


def mysql_connector_pure(host: str, port: int) -> None:
    _mysql_connector(host, port, use_pure=True)


def mysql_connector_default(host: str, port: int) -> None:
    """No ``use_pure``: the C extension when it can be imported, pure Python otherwise."""
    _mysql_connector(host, port)


def mysql_connector_c(host: str, port: int) -> None:
    """The default again, on the condition that it is the C extension."""
    import mysql.connector

    if not mysql.connector.HAVE_CEXT:
        raise RuntimeError("mysql-connector-python has no C extension here")
    _mysql_connector(host, port)


# ── SQL Server ────────────────────────────────────────────────────────


def pymssql_connect(host: str, port: int) -> None:
    import pymssql

    note(freetds=pymssql.get_dbversion())
    pymssql.connect(
        server=host,
        port=str(port),
        user="tc",
        password="tc",
        database="tc",
        # A fixed protocol version: FreeTDS otherwise tries one after the other.
        tds_version="7.4",
        login_timeout=SERVER_FIRST,
        timeout=SERVER_FIRST,
    ).close()


def pyodbc_freetds(host: str, port: int) -> None:
    """pyodbc with the FreeTDS driver of Debian's ``tdsodbc``, named by its path."""
    import pyodbc

    drivers = glob.glob("/usr/lib/*/odbc/libtdsodbc.so")
    if not drivers:
        raise RuntimeError("the FreeTDS ODBC driver (tdsodbc) is not installed")
    note(driver=drivers[0])
    pyodbc.connect(
        f"DRIVER={drivers[0]};SERVER={host};PORT={port};UID=tc;PWD=tc;TDS_Version=7.4",
        timeout=SERVER_FIRST,
    ).close()


# ── Oracle ────────────────────────────────────────────────────────────


def _oracledb_arguments(host: str, port: int) -> dict[str, object]:
    import oracledb

    note(thin=oracledb.is_thin_mode())
    return {
        "user": "tc",
        "password": "tc",
        "host": host,
        "port": port,
        "service_name": MARK,
        "tcp_connect_timeout": TIMEOUT,
        "retry_count": 0,
    }


def oracledb_thin(host: str, port: int) -> None:
    import oracledb

    oracledb.connect(**_oracledb_arguments(host, port)).close()


def oracledb_thin_async(host: str, port: int) -> None:
    import oracledb

    async def go() -> None:
        connection = await oracledb.connect_async(**_oracledb_arguments(host, port))
        await connection.close()

    asyncio.run(go())


# ── Redis, MongoDB, memcached ─────────────────────────────────────────


def _redis_arguments(host: str, port: int, retry_module: Any) -> dict[str, object]:
    import redis.backoff
    import redis.utils

    note(hiredis=redis.utils.HIREDIS_AVAILABLE)
    return {
        "host": host,
        "port": port,
        # The first command the client sends is AUTH with this name.
        "username": MARK,
        "password": "tc",
        "socket_connect_timeout": TIMEOUT,
        "socket_timeout": TIMEOUT,
        "retry": retry_module.Retry(redis.backoff.NoBackoff(), 0),
    }


def redis_sync(host: str, port: int) -> None:
    import redis
    import redis.retry

    client = redis.Redis(**_redis_arguments(host, port, redis.retry))
    try:
        client.ping()
    finally:
        client.close()


def redis_asyncio(host: str, port: int) -> None:
    import redis.asyncio
    import redis.asyncio.retry

    async def go() -> None:
        client = redis.asyncio.Redis(**_redis_arguments(host, port, redis.asyncio.retry))
        try:
            await client.ping()
        finally:
            await client.aclose()

    asyncio.run(go())


def _mongo_arguments(host: str, port: int) -> dict[str, object]:
    import pymongo

    note(c_extension=pymongo.has_c())
    return {
        "host": host,
        "port": port,
        "appname": MARK,
        "directConnection": True,
        "serverSelectionTimeoutMS": 700,
        "connectTimeoutMS": int(TIMEOUT * 1000),
        "socketTimeoutMS": int(TIMEOUT * 1000),
    }


def pymongo_sync(host: str, port: int) -> None:
    import pymongo

    client = pymongo.MongoClient(**_mongo_arguments(host, port))
    try:
        client.admin.command("ping")
    finally:
        client.close()


def pymongo_async(host: str, port: int) -> None:
    import pymongo

    async def go() -> None:
        client = pymongo.AsyncMongoClient(**_mongo_arguments(host, port))
        try:
            await client.admin.command("ping")
        finally:
            await client.close()

    asyncio.run(go())


def pymemcache_get(host: str, port: int) -> None:
    from pymemcache.client.base import Client

    client = Client((host, port), connect_timeout=TIMEOUT, timeout=TIMEOUT)
    try:
        client.set("tc", MARK.encode(), noreply=False)
    finally:
        client.close()
