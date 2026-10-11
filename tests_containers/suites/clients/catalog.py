"""The client libraries of the suite, and what was measured for each.

One ``Variant`` is one row of the compatibility table: a library in one
arrangement (an implementation, a resolver, a runtime).  ``expect`` is the row
as it was measured; ``test_clients.py`` measures it again and fails when
anything differs.  This module is imported by the pytest process and by the
processes under test, and imports no client library itself.

How to read a row (``Expect``), for the allow list ``allowed.test:9001``:

* ``lookup_event`` / ``connect_event``: without tethered, did the library raise
  a ``socket.getaddrinfo`` (or ``gethostbyname``) event for the name, and a
  ``socket.connect`` (or ``sendto``) event for the destination?  That is why
  tethered does or does not see it.
* ``forbidden_name``: under the policy, a connection to ``forbidden.test:9002``
  was ``blocked`` or ``ARRIVED``.  ``name_leaked``: the world's DNS responder
  was asked about ``forbidden.test`` all the same.
* ``forbidden_address``: the same for the raw address ``10.77.0.20:9003``.
* ``allowed``: ``allowed.test:9001`` ``arrived`` or was ``REFUSED``.
* ``other_port``: ``allowed.test:9003``, a port the rule does not cover.
* ``surface``: how the refusal of the forbidden name reached the caller of the
  library: ``raised`` (``EgressBlocked`` itself), ``chained`` (the library's
  exception, with ``EgressBlocked`` as its cause, context or member),
  ``message`` (the library's exception, only the text of the refusal in it),
  ``hidden`` (an error that does not mention tethered), ``never returns``.

Not in the table, with the reason:

* gevent's ``dnspython`` resolver: with gevent 26.9.0 and dnspython 2.9.0 it
  resolves nothing, tethered or not (``AttributeError: '_DualResolver' object
  has no attribute 'resolve_name'``).
* boto3's CRT transfer manager (``TransferConfig(preferred_transfer_client=
  "crt")``): s3transfer puts ``host:port`` into the Host header and awscrt
  takes that for a host name, so it cannot be pointed at a port of the world.
  Its transport is the ``awscrt`` row.
* psycopg 3's ``c`` implementation: the same code as ``binary``, built against
  the system's libpq.
* niquests: its urllib3-future replaces urllib3 in site-packages; it is
  measured in the ``clients_niquests`` suite.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

ENFORCED = "enforced"
NOT_SEEN = "not seen"
ALLOWED_REFUSED = "allowed host refused"
PARTLY = "partly enforced"


@dataclass(frozen=True)
class Expect:
    """One measured row.  Capitals mark what a user would not expect."""

    lookup_event: bool
    connect_event: bool
    forbidden_name: str
    name_leaked: bool
    forbidden_address: str
    allowed: str
    other_port: str
    surface: str = "raised"

    @property
    def verdict(self) -> str:
        """The row in a few words."""
        got_out = [self.forbidden_name, self.forbidden_address, self.other_port].count("ARRIVED")
        if self.allowed == "REFUSED":
            return ALLOWED_REFUSED
        if got_out == 3:
            return NOT_SEEN
        if got_out or self.name_leaked:
            return PARTLY
        return ENFORCED


#: Lookup and connection go through Python's socket module.
SEEN = Expect(True, True, "blocked", False, "blocked", "arrived", "blocked")
#: Lookup and connection are made by a C library: no audit event at all.
UNSEEN = Expect(False, False, "ARRIVED", True, "ARRIVED", "arrived", "ARRIVED", surface="-")
#: The library resolves the name itself and connects through Python: tethered
#: sees a connection to an address it has no name for.
OWN_LOOKUP = Expect(False, True, "blocked", True, "blocked", "REFUSED", "blocked")
#: The library looks the name up through Python and hands the address to a C
#: library that connects: the name is checked, the address and the port are not.
LOOKUP_ONLY = Expect(True, False, "blocked", False, "ARRIVED", "arrived", "ARRIVED")


@dataclass(frozen=True)
class Variant:
    """A client library in one arrangement."""

    id: str
    #: The row's label in the table.
    title: str
    #: ``module:function`` in this directory; called with ``(host, port)``.
    call: str
    #: The distributions whose versions the row reports.
    packages: tuple[str, ...]
    expect: Expect
    #: Why, in a few words.
    mechanism: str
    #: Extra environment of the process under test.
    env: dict[str, str] = field(default_factory=dict)
    #: Modules made unimportable before anything else, as if not installed.
    without: tuple[str, ...] = ()
    #: ``gevent`` or ``eventlet``: monkey-patch first, then activate the policy.
    patch: str = ""
    #: Modules imported before the policy is activated.
    import_first: tuple[str, ...] = ()
    proto: str = "tcp"
    #: Python versions on which the variant cannot run, each with the reason.
    missing_on: dict[str, str] = field(default_factory=dict)
    #: Set when the library cannot be used at all under a locked policy: the
    #: module whose import calls ``ctypes.util.find_library``.
    lock_breaks_import_of: str = ""


def _variants(*variants: Variant) -> dict[str, Variant]:
    by_id = {variant.id: variant for variant in variants}
    if len(by_id) != len(variants):
        raise ValueError("two variants share an id")
    return by_id


# ── Mechanisms ────────────────────────────────────────────────────────

PY = "socket.getaddrinfo and socket.connect"
LOOP = "asyncio: socket.getaddrinfo in the loop's executor, socket.connect on its sockets"
TRIO = "trio: socket.getaddrinfo in a worker thread, socket.connect on its sockets"
LIBCURL = "libcurl resolves and connects in C"
LIBPQ = "socket.getaddrinfo in Python, then libpq connects to the address in C"
GRPC = "the gRPC core resolves and connects in C"
CARES = "c-ares resolves in C; the connection is a Python socket's"
TWISTED = "socket.getaddrinfo in the reactor's thread pool, socket.connect_ex on its sockets"

# ── Why a library cannot be used under a locked policy ────────────────

#: trio looks for libpthread when it is imported.
TRIO_IMPORT = "trio._core._thread_cache"
#: psycopg's Python implementation looks for libpq when it is imported.
PSYCOPG_IMPORT = "psycopg.pq._pq_ctypes"
#: asyncssh looks for liboqs when it is imported.
ASYNCSSH_IMPORT = "asyncssh.crypto.pq"

# ── Why a library is missing on a Python version ──────────────────────

NO_CONFLUENT_KAFKA = (
    "confluent-kafka 2.16.0 has no cp315 wheel, and its source build needs librdkafka 2.16 "
    "(Debian 13 has 2.8.0)"
)
NO_MYSQL_CEXT = (
    "mysql-connector-python 26.7.0 has no cp315 wheel; the pure-Python wheel that pip "
    "installs instead has no C extension"
)

#: The rows of the compatibility table.
TABLE = _variants(
    # ── HTTP ──────────────────────────────────────────────────────────
    Variant("urllib-request", "urllib.request", "clients_http:urllib_request", (), SEEN, PY),
    Variant("http-client", "http.client", "clients_http:http_client", (), SEEN, PY),
    Variant("requests", "requests", "clients_http:requests_get", ("requests", "urllib3"), SEEN, PY),
    Variant("urllib3", "urllib3", "clients_http:urllib3_request", ("urllib3",), SEEN, PY),
    Variant(
        "httplib2",
        "httplib2",
        "clients_http:httplib2_request",
        ("httplib2",),
        SEEN,
        "socket.getaddrinfo, then socket.connect with the host name",
    ),
    Variant(
        "httpx-sync",
        "httpx, sync",
        "clients_http:httpx_sync",
        ("httpx", "httpcore"),
        SEEN,
        PY,
        lock_breaks_import_of=TRIO_IMPORT,
    ),
    Variant(
        "httpx-asyncio",
        "httpx, async on asyncio",
        "clients_http:httpx_asyncio",
        ("httpx", "httpcore", "anyio"),
        SEEN,
        LOOP,
        lock_breaks_import_of=TRIO_IMPORT,
    ),
    Variant(
        "httpx-trio",
        "httpx, async on trio",
        "clients_http:httpx_trio",
        ("httpx", "httpcore", "trio"),
        SEEN,
        TRIO,
        lock_breaks_import_of=TRIO_IMPORT,
    ),
    Variant(
        "aiohttp-aiodns",
        "aiohttp, aiodns installed (its default resolver is then c-ares)",
        "clients_http:aiohttp_get",
        ("aiohttp", "aiodns", "pycares"),
        OWN_LOOKUP,
        CARES,
    ),
    Variant(
        "aiohttp-no-aiodns",
        "aiohttp, aiodns not installed",
        "clients_http:aiohttp_get",
        ("aiohttp",),
        SEEN,
        LOOP,
        without=("aiodns",),
    ),
    Variant(
        "aiohttp-aiodns-threaded-resolver",
        "aiohttp, aiodns installed, TCPConnector(resolver=ThreadedResolver())",
        "clients_http:aiohttp_threaded_resolver",
        ("aiohttp", "aiodns"),
        SEEN,
        LOOP,
    ),
    Variant("pycurl", "pycurl", "clients_http:pycurl_get", ("pycurl",), UNSEEN, LIBCURL),
    Variant(
        "curl-cffi", "curl_cffi", "clients_http:curl_cffi_get", ("curl_cffi",), UNSEEN, LIBCURL
    ),
    Variant(
        "tornado-simple",
        "tornado, SimpleAsyncHTTPClient (its default)",
        "clients_http:tornado_simple",
        ("tornado",),
        SEEN,
        LOOP,
    ),
    Variant(
        "tornado-curl",
        "tornado, CurlAsyncHTTPClient",
        "clients_http:tornado_curl",
        ("tornado", "pycurl"),
        UNSEEN,
        LIBCURL,
    ),
    Variant(
        "websockets-asyncio",
        "websockets, asyncio client",
        "clients_http:websockets_asyncio",
        ("websockets",),
        SEEN,
        LOOP,
    ),
    Variant(
        "websockets-sync",
        "websockets, sync client",
        "clients_http:websockets_sync",
        ("websockets",),
        SEEN,
        PY,
    ),
    # ── PostgreSQL ────────────────────────────────────────────────────
    Variant(
        "psycopg2",
        "psycopg2 (psycopg2-binary)",
        "clients_db:psycopg2_connect",
        ("psycopg2-binary",),
        UNSEEN,
        "libpq resolves and connects in C",
    ),
    Variant(
        "psycopg-binary-sync",
        "psycopg 3, binary implementation, sync",
        "clients_db:psycopg_sync",
        ("psycopg", "psycopg-binary"),
        LOOKUP_ONLY,
        LIBPQ,
        env={"PSYCOPG_IMPL": "binary"},
    ),
    Variant(
        "psycopg-binary-async",
        "psycopg 3, binary implementation, async",
        "clients_db:psycopg_async",
        ("psycopg", "psycopg-binary"),
        LOOKUP_ONLY,
        LIBPQ,
        env={"PSYCOPG_IMPL": "binary"},
    ),
    Variant(
        "psycopg-python-sync",
        "psycopg 3, Python implementation (libpq through ctypes), sync",
        "clients_db:psycopg_sync",
        ("psycopg",),
        LOOKUP_ONLY,
        LIBPQ,
        env={"PSYCOPG_IMPL": "python"},
        lock_breaks_import_of=PSYCOPG_IMPORT,
    ),
    Variant(
        "psycopg-python-async",
        "psycopg 3, Python implementation (libpq through ctypes), async",
        "clients_db:psycopg_async",
        ("psycopg",),
        LOOKUP_ONLY,
        LIBPQ,
        env={"PSYCOPG_IMPL": "python"},
        lock_breaks_import_of=PSYCOPG_IMPORT,
    ),
    Variant("asyncpg", "asyncpg", "clients_db:asyncpg_connect", ("asyncpg",), SEEN, LOOP),
    Variant("pg8000", "pg8000", "clients_db:pg8000_connect", ("pg8000",), SEEN, PY),
    # ── MySQL ─────────────────────────────────────────────────────────
    Variant("pymysql", "PyMySQL", "clients_db:pymysql_connect", ("PyMySQL",), SEEN, PY),
    Variant("aiomysql", "aiomysql", "clients_db:aiomysql_connect", ("aiomysql",), SEEN, LOOP),
    Variant(
        "mysqlclient",
        "mysqlclient (MySQLdb)",
        "clients_db:mysqlclient_connect",
        ("mysqlclient",),
        UNSEEN,
        "the MariaDB / MySQL client library resolves and connects in C",
    ),
    Variant(
        "mysql-connector-pure",
        "mysql-connector-python, use_pure=True",
        "clients_db:mysql_connector_pure",
        ("mysql-connector-python",),
        SEEN,
        PY,
    ),
    Variant(
        "mysql-connector-c",
        "mysql-connector-python, C extension (its default when the extension is there)",
        "clients_db:mysql_connector_c",
        ("mysql-connector-python",),
        UNSEEN,
        "the bundled MySQL client library resolves and connects in C",
        missing_on={"3.15": NO_MYSQL_CEXT},
    ),
    # ── SQL Server, Oracle ────────────────────────────────────────────
    Variant(
        "pymssql",
        "pymssql",
        "clients_db:pymssql_connect",
        ("pymssql",),
        UNSEEN,
        "FreeTDS resolves and connects in C",
    ),
    Variant(
        "pyodbc-freetds",
        "pyodbc with the FreeTDS ODBC driver",
        "clients_db:pyodbc_freetds",
        ("pyodbc",),
        UNSEEN,
        "the ODBC driver resolves and connects in C",
    ),
    Variant(
        "oracledb-thin", "oracledb, thin mode", "clients_db:oracledb_thin", ("oracledb",), SEEN, PY
    ),
    Variant(
        "oracledb-thin-async",
        "oracledb, thin mode, async",
        "clients_db:oracledb_thin_async",
        ("oracledb",),
        SEEN,
        LOOP,
    ),
    # ── Redis, MongoDB, memcached ─────────────────────────────────────
    Variant(
        "redis-hiredis",
        "redis-py, hiredis installed",
        "clients_db:redis_sync",
        ("redis", "hiredis"),
        SEEN,
        PY + "; hiredis only parses replies",
    ),
    Variant(
        "redis-no-hiredis",
        "redis-py, hiredis not installed",
        "clients_db:redis_sync",
        ("redis",),
        SEEN,
        PY,
        without=("hiredis",),
    ),
    Variant(
        "redis-asyncio-hiredis",
        "redis-py asyncio, hiredis installed",
        "clients_db:redis_asyncio",
        ("redis", "hiredis"),
        replace(SEEN, surface="chained"),
        LOOP + "; hiredis only parses replies",
    ),
    Variant(
        "redis-asyncio-no-hiredis",
        "redis-py asyncio, hiredis not installed",
        "clients_db:redis_asyncio",
        ("redis",),
        replace(SEEN, surface="chained"),
        LOOP,
        without=("hiredis",),
    ),
    Variant(
        "pymongo",
        "pymongo, MongoClient",
        "clients_db:pymongo_sync",
        ("pymongo",),
        replace(SEEN, surface="message"),
        PY,
    ),
    Variant(
        "pymongo-async",
        "pymongo, AsyncMongoClient",
        "clients_db:pymongo_async",
        ("pymongo",),
        replace(SEEN, surface="message"),
        LOOP,
    ),
    Variant("pymemcache", "pymemcache", "clients_db:pymemcache_get", ("pymemcache",), SEEN, PY),
    # ── Messaging and RPC ─────────────────────────────────────────────
    Variant("grpcio", "grpcio", "clients_messaging:grpc_call", ("grpcio",), UNSEEN, GRPC),
    Variant(
        "grpcio-aio",
        "grpcio, grpc.aio",
        "clients_messaging:grpc_aio_call",
        ("grpcio",),
        UNSEEN,
        GRPC,
    ),
    Variant("pika", "pika", "clients_messaging:pika_blocking", ("pika",), SEEN, PY),
    Variant(
        "amqp",
        "amqp (py-amqp, the transport of kombu and Celery)",
        "clients_messaging:amqp_connect",
        ("amqp",),
        SEEN,
        PY,
    ),
    Variant(
        "kafka-python",
        "kafka-python",
        "clients_messaging:kafka_python_consumer",
        ("kafka-python",),
        replace(SEEN, surface="hidden"),
        PY,
    ),
    Variant(
        "confluent-kafka",
        "confluent-kafka",
        "clients_messaging:confluent_kafka_producer",
        ("confluent-kafka",),
        UNSEEN,
        "librdkafka resolves and connects in C",
        missing_on={"3.15": NO_CONFLUENT_KAFKA},
    ),
    Variant(
        "nats-py",
        "nats-py",
        "clients_messaging:nats_connect",
        ("nats-py",),
        replace(SEEN, surface="hidden"),
        LOOP,
    ),
    Variant(
        "pyzmq",
        "pyzmq",
        "clients_messaging:pyzmq_connect",
        ("pyzmq",),
        UNSEEN,
        "libzmq resolves and connects in C",
    ),
    # ── Cloud SDKs ────────────────────────────────────────────────────
    Variant(
        "boto3",
        "boto3 / botocore, awscrt installed",
        "clients_messaging:boto3_s3",
        ("boto3", "botocore", "urllib3", "awscrt"),
        replace(SEEN, surface="chained"),
        "urllib3: " + PY,
    ),
    Variant(
        "awscrt-http",
        "awscrt (awscrt.http), the transport of boto3's optional CRT transfer manager",
        "clients_messaging:awscrt_http",
        ("awscrt",),
        UNSEEN,
        "the AWS Common Runtime resolves and connects in C",
    ),
    Variant(
        "google-cloud-storage",
        "google-cloud-storage",
        "clients_messaging:google_cloud_storage",
        ("google-cloud-storage", "requests"),
        SEEN,
        "requests: " + PY,
    ),
    # ── Sockets, the standard library's protocol clients, SSH ─────────
    Variant(
        "socket",
        "socket.create_connection",
        "clients_lowlevel:socket_create_connection",
        (),
        SEEN,
        PY,
    ),
    Variant(
        "asyncio-streams",
        "asyncio.open_connection",
        "clients_lowlevel:asyncio_open_connection",
        (),
        SEEN,
        LOOP,
    ),
    Variant("smtplib", "smtplib", "clients_lowlevel:smtplib_connect", (), SEEN, PY),
    Variant("ftplib", "ftplib", "clients_lowlevel:ftplib_connect", (), SEEN, PY),
    Variant("paramiko", "paramiko", "clients_lowlevel:paramiko_connect", ("paramiko",), SEEN, PY),
    Variant(
        "asyncssh",
        "asyncssh",
        "clients_lowlevel:asyncssh_connect",
        ("asyncssh",),
        SEEN,
        LOOP,
        lock_breaks_import_of=ASYNCSSH_IMPORT,
    ),
    # ── A resolver of the library's own, then a Python socket ─────────
    Variant(
        "dnspython-then-connect",
        "dnspython lookup (dns.resolver), then a socket connection to the address",
        "clients_lowlevel:dnspython_then_connect",
        ("dnspython",),
        OWN_LOOKUP,
        "its own DNS client: socket.sendto to the name server, no socket.getaddrinfo",
    ),
    Variant(
        "pycares-then-connect",
        "pycares lookup, then a socket connection to the address",
        "clients_lowlevel:pycares_then_connect",
        ("pycares",),
        OWN_LOOKUP,
        CARES,
    ),
    Variant(
        "aiodns-then-connect",
        "aiodns lookup, then asyncio.open_connection to the address",
        "clients_lowlevel:aiodns_then_connect",
        ("aiodns", "pycares"),
        OWN_LOOKUP,
        CARES,
    ),
    # ── Other runtimes ────────────────────────────────────────────────
    Variant(
        "trio",
        "trio.open_tcp_stream",
        "clients_runtimes:trio_open_tcp_stream",
        ("trio",),
        SEEN,
        TRIO,
        lock_breaks_import_of=TRIO_IMPORT,
    ),
    Variant(
        "anyio-asyncio",
        "anyio.connect_tcp on asyncio",
        "clients_runtimes:anyio_on_asyncio",
        ("anyio",),
        SEEN,
        LOOP,
    ),
    Variant(
        "anyio-trio",
        "anyio.connect_tcp on trio",
        "clients_runtimes:anyio_on_trio",
        ("anyio", "trio"),
        SEEN,
        TRIO,
        lock_breaks_import_of=TRIO_IMPORT,
    ),
    Variant(
        "gevent",
        "gevent, monkey.patch_all(), urllib.request (its default resolver, a thread pool)",
        "clients_runtimes:gevent_urlopen",
        ("gevent",),
        SEEN,
        "socket.getaddrinfo in gevent's thread pool; the green socket calls socket.connect",
        patch="gevent",
    ),
    Variant(
        "gevent-ares",
        "gevent, monkey.patch_all(), GEVENT_RESOLVER=ares",
        "clients_runtimes:gevent_urlopen",
        ("gevent",),
        OWN_LOOKUP,
        "c-ares resolves in C; the green socket calls socket.connect",
        env={"GEVENT_RESOLVER": "ares"},
        patch="gevent",
    ),
    Variant(
        "eventlet",
        "eventlet, monkey_patch(), urllib.request (greendns, its default)",
        "clients_runtimes:eventlet_urlopen",
        ("eventlet", "dnspython"),
        OWN_LOOKUP,
        "greendns (dnspython): socket.sendto to the name server, no socket.getaddrinfo "
        "for the name; the green socket calls socket.connect",
        patch="eventlet",
    ),
    Variant(
        "eventlet-no-greendns",
        "eventlet, monkey_patch(), EVENTLET_NO_GREENDNS=yes",
        "clients_runtimes:eventlet_urlopen",
        ("eventlet",),
        SEEN,
        "socket.getaddrinfo itself; the green socket calls socket.connect",
        env={"EVENTLET_NO_GREENDNS": "yes"},
        patch="eventlet",
    ),
    Variant(
        "twisted-connecttcp",
        "Twisted, reactor.connectTCP (TCP4ClientEndpoint)",
        "clients_runtimes:twisted_connect_tcp",
        ("Twisted",),
        replace(SEEN, surface="hidden"),
        TWISTED,
    ),
    Variant(
        "twisted-agent",
        "Twisted, twisted.web.client.Agent (HostnameEndpoint)",
        "clients_runtimes:twisted_agent",
        ("Twisted",),
        replace(SEEN, surface="never returns"),
        TWISTED,
    ),
)

#: What a library does when the C module it prefers cannot be imported, which
#: is what refusing that import under a policy would amount to.  Not rows of
#: the table: ``test_clients.py`` measures them like rows.  eventlet is not
#: among them: eventlet 0.41.2 cannot be imported without its greendns module
#: (``from eventlet.support import greendns`` in ``eventlet.green.socket``).
FALLBACKS = _variants(
    Variant(
        "aiohttp-pycares-unimportable",
        "aiohttp, aiodns installed, pycares cannot be imported",
        "clients_http:aiohttp_get",
        ("aiohttp", "aiodns"),
        SEEN,
        LOOP,
        without=("pycares",),
    ),
    Variant(
        "mysql-connector-cext-unimportable",
        "mysql-connector-python, its C extension cannot be imported",
        "clients_db:mysql_connector_default",
        ("mysql-connector-python",),
        SEEN,
        PY,
        without=("_mysql_connector",),
    ),
    Variant(
        "boto3-awscrt-unimportable",
        "boto3 / botocore, awscrt cannot be imported",
        "clients_messaging:boto3_s3",
        ("boto3", "botocore", "urllib3"),
        replace(SEEN, surface="chained"),
        "urllib3: " + PY,
        without=("awscrt",),
    ),
)

#: httpx where trio is not installed.  httpcore imports trio when it can, and
#: importing trio is what a locked policy breaks: without it httpx is usable.
HTTPX_WITHOUT_TRIO = Variant(
    "httpx-without-trio",
    "httpx, sync, trio not installed",
    "clients_http:httpx_sync",
    ("httpx", "httpcore"),
    SEEN,
    PY,
    without=("trio",),
)

#: httpx where httpcore, and with it trio, was imported before the policy was
#: locked: trio has then looked for libpthread already.  Importing httpx is
#: not enough: it imports httpcore only when a client is created.
HTTPCORE_IMPORTED_FIRST = Variant(
    "httpcore-imported-first",
    "httpx, sync, httpcore imported before the policy is activated",
    "clients_http:httpx_sync",
    ("httpx", "httpcore"),
    SEEN,
    PY,
    import_first=("httpcore",),
)

#: A DNS query sent to a name server at the forbidden address: the two ways a
#: Python process makes one.  Not rows of the table either.
DNS_SERVER_VARIANTS = _variants(
    Variant(
        "dnspython-query-server",
        "dnspython, a query to a name server",
        "clients_lowlevel:dnspython_query_server",
        ("dnspython",),
        SEEN,
        "socket.sendto",
        proto="udp",
    ),
    Variant(
        "pycares-query-server",
        "pycares, a query to a name server",
        "clients_lowlevel:pycares_query_server",
        ("pycares",),
        UNSEEN,
        "c-ares sends in C",
        proto="udp",
    ),
)

#: Everything ``client_case.py`` can be asked for, by id.
VARIANTS = {
    **TABLE,
    **FALLBACKS,
    **DNS_SERVER_VARIANTS,
    HTTPX_WITHOUT_TRIO.id: HTTPX_WITHOUT_TRIO,
    HTTPCORE_IMPORTED_FIRST.id: HTTPCORE_IMPORTED_FIRST,
}
