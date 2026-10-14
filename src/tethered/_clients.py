"""The client-library arrangements of the compatibility page that are not enforced.

Data for ``python -m tethered check`` (``_check.py``).  A row is a library in
one arrangement (an implementation, a resolver, a runtime), as the ``clients``
container suite measures it; ``packages`` are the distributions the row
names.  The rows are copied from ``tests_containers/suites/clients/catalog.py``
(``TABLE``), every row whose result is not "enforced" and nothing else, in the
order of the catalogue.  That directory is not part of the package, so the
package carries this copy; ``tests/test_check.py`` fails when the two differ.
"""

from __future__ import annotations

from typing import NamedTuple

NOT_SEEN = "not seen"
ALLOWED_REFUSED = "allowed host refused"
PARTLY = "partly enforced"


class Row(NamedTuple):
    """One measured arrangement whose result is not "enforced"."""

    id: str
    title: str
    result: str
    packages: tuple[str, ...]
    mechanism: str


_LIBCURL = "libcurl resolves and connects in C"
_LIBPQ = "socket.getaddrinfo in Python, then libpq connects to the address in C"
_GRPC = "the gRPC core resolves and connects in C"
_CARES = "c-ares resolves in C; the connection is a Python socket's"

ROWS: tuple[Row, ...] = (
    Row(
        "aiohttp-aiodns-imported-first",
        "aiohttp, aiodns installed, imported before the policy (its resolver is then c-ares)",
        ALLOWED_REFUSED,
        ("aiohttp", "aiodns", "pycares"),
        _CARES,
    ),
    Row("pycurl", "pycurl", NOT_SEEN, ("pycurl",), _LIBCURL),
    Row("curl-cffi", "curl_cffi", NOT_SEEN, ("curl_cffi",), _LIBCURL),
    Row("tornado-curl", "tornado, CurlAsyncHTTPClient", NOT_SEEN, ("tornado", "pycurl"), _LIBCURL),
    Row(
        "psycopg2",
        "psycopg2 (psycopg2-binary)",
        NOT_SEEN,
        ("psycopg2-binary",),
        "libpq resolves and connects in C",
    ),
    Row(
        "psycopg-binary-sync",
        "psycopg 3, binary implementation, sync",
        PARTLY,
        ("psycopg", "psycopg-binary"),
        _LIBPQ,
    ),
    Row(
        "psycopg-binary-async",
        "psycopg 3, binary implementation, async",
        PARTLY,
        ("psycopg", "psycopg-binary"),
        _LIBPQ,
    ),
    Row(
        "psycopg-python-sync",
        "psycopg 3, Python implementation (libpq through ctypes), sync",
        PARTLY,
        ("psycopg",),
        _LIBPQ,
    ),
    Row(
        "psycopg-python-async",
        "psycopg 3, Python implementation (libpq through ctypes), async",
        PARTLY,
        ("psycopg",),
        _LIBPQ,
    ),
    Row(
        "mysqlclient",
        "mysqlclient (MySQLdb)",
        NOT_SEEN,
        ("mysqlclient",),
        "the MariaDB / MySQL client library resolves and connects in C",
    ),
    Row(
        "mysql-connector-c",
        "mysql-connector-python, C extension (its default when the extension is there)",
        NOT_SEEN,
        ("mysql-connector-python",),
        "the bundled MySQL client library resolves and connects in C",
    ),
    Row("pymssql", "pymssql", NOT_SEEN, ("pymssql",), "FreeTDS resolves and connects in C"),
    Row(
        "pyodbc-freetds",
        "pyodbc with the FreeTDS ODBC driver",
        NOT_SEEN,
        ("pyodbc",),
        "the ODBC driver resolves and connects in C",
    ),
    Row("grpcio", "grpcio", NOT_SEEN, ("grpcio",), _GRPC),
    Row("grpcio-aio", "grpcio, grpc.aio", NOT_SEEN, ("grpcio",), _GRPC),
    Row(
        "confluent-kafka",
        "confluent-kafka",
        NOT_SEEN,
        ("confluent-kafka",),
        "librdkafka resolves and connects in C",
    ),
    Row("pyzmq", "pyzmq", NOT_SEEN, ("pyzmq",), "libzmq resolves and connects in C"),
    Row(
        "awscrt-http",
        "awscrt (awscrt.http), the transport of boto3's optional CRT transfer manager",
        NOT_SEEN,
        ("awscrt",),
        "the AWS Common Runtime resolves and connects in C",
    ),
    Row(
        "dnspython-then-connect",
        "dnspython lookup (dns.resolver), then a socket connection to the address",
        ALLOWED_REFUSED,
        ("dnspython",),
        "its own DNS client: socket.sendto to the name server, no socket.getaddrinfo",
    ),
    Row(
        "pycares-then-connect",
        "pycares imported before the policy: a lookup, then a socket connection to the address",
        ALLOWED_REFUSED,
        ("pycares",),
        _CARES,
    ),
    Row(
        "aiodns-then-connect",
        "aiodns imported before the policy: a lookup, then asyncio.open_connection to the address",
        ALLOWED_REFUSED,
        ("aiodns", "pycares"),
        _CARES,
    ),
    Row(
        "gevent-ares",
        "gevent, monkey.patch_all(), GEVENT_RESOLVER=ares",
        ALLOWED_REFUSED,
        ("gevent",),
        "c-ares resolves in C; the green socket calls socket.connect",
    ),
    Row(
        "eventlet",
        "eventlet, monkey_patch(), urllib.request (greendns, its default)",
        ALLOWED_REFUSED,
        ("eventlet", "dnspython"),
        "greendns (dnspython): socket.sendto to the name server, no socket.getaddrinfo "
        "for the name; the green socket calls socket.connect",
    ),
)
