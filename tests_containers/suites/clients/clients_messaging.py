"""Messaging, RPC and cloud clients: one connection attempt to ``HOST:PORT`` each.

As with the database clients, the destinations answer with HTTP and every
handshake here fails after the connection: see ``clients_db``.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

from client_case import note

#: Long enough for a lookup and a connection on a busy machine.
TIMEOUT = 5.0
#: How long a client waits for a server that never speaks first.
SERVER_FIRST = 1
#: An empty line inside a name: the world answers when it has read one.
MARK = "tc\r\n\r\n"


# ── gRPC ──────────────────────────────────────────────────────────────


def grpc_call(host: str, port: int) -> None:
    import grpc

    with grpc.insecure_channel(f"{host}:{port}") as channel:
        channel.unary_unary("/tc.Probe/Ping")(b"", timeout=TIMEOUT)


def grpc_aio_call(host: str, port: int) -> None:
    import grpc.aio

    async def go() -> None:
        async with grpc.aio.insecure_channel(f"{host}:{port}") as channel:
            await channel.unary_unary("/tc.Probe/Ping")(b"", timeout=TIMEOUT)

    asyncio.run(go())


# ── AMQP ──────────────────────────────────────────────────────────────


def pika_blocking(host: str, port: int) -> None:
    import pika

    parameters = pika.ConnectionParameters(
        host=host,
        port=port,
        connection_attempts=1,
        retry_delay=0,
        socket_timeout=TIMEOUT,
        stack_timeout=SERVER_FIRST,
    )
    pika.BlockingConnection(parameters).close()


def amqp_connect(host: str, port: int) -> None:
    """py-amqp, the transport of kombu and Celery."""
    import amqp

    connection = amqp.Connection(host=f"{host}:{port}", connect_timeout=SERVER_FIRST)
    try:
        connection.connect()
    finally:
        connection.collect()


# ── Kafka ─────────────────────────────────────────────────────────────


def kafka_python_consumer(host: str, port: int) -> None:
    import kafka

    kafka.KafkaConsumer(
        bootstrap_servers=[f"{host}:{port}"],
        client_id=MARK,
        bootstrap_timeout_ms=800,
        reconnect_backoff_ms=200,
    ).close()


def confluent_kafka_producer(host: str, port: int) -> None:
    import confluent_kafka

    note(librdkafka=confluent_kafka.libversion()[0])
    producer = confluent_kafka.Producer(
        {"bootstrap.servers": f"{host}:{port}", "client.id": MARK, "log_level": 0}
    )
    producer.list_topics(timeout=1.0)


# ── NATS, ZeroMQ ──────────────────────────────────────────────────────


def nats_connect(host: str, port: int) -> None:
    import nats

    async def go() -> None:
        client = await nats.connect(
            f"nats://{host}:{port}",
            connect_timeout=SERVER_FIRST,
            allow_reconnect=False,
            max_reconnect_attempts=1,
            reconnect_time_wait=0,
        )
        await client.close()

    asyncio.run(go())


def pyzmq_connect(host: str, port: int) -> None:
    """A ZeroMQ socket connects in the background; its monitor says when it has."""
    import zmq
    from zmq.utils.monitor import recv_monitor_message

    note(libzmq=zmq.zmq_version())
    context = zmq.Context()
    try:
        socket = context.socket(zmq.REQ)
        socket.setsockopt(zmq.LINGER, 0)
        monitor = socket.get_monitor_socket(zmq.EVENT_CONNECTED)
        socket.connect(f"tcp://{host}:{port}")
        if not monitor.poll(int(TIMEOUT * 1000)):
            raise TimeoutError("the ZeroMQ socket did not connect")
        note(monitor=str(recv_monitor_message(monitor)["event"]))
    finally:
        context.destroy(linger=0)


# ── AWS, Google Cloud ─────────────────────────────────────────────────


def _s3_client(host: str, port: int) -> Any:
    import boto3
    import botocore.config

    return boto3.client(
        "s3",
        endpoint_url=f"http://{host}:{port}",
        region_name="us-east-1",
        aws_access_key_id="tc",
        aws_secret_access_key="tc",
        config=botocore.config.Config(
            retries={"total_max_attempts": 1, "mode": "standard"},
            connect_timeout=TIMEOUT,
            read_timeout=TIMEOUT,
            s3={"addressing_style": "path"},
        ),
    )


def boto3_s3(host: str, port: int) -> None:
    client = _s3_client(host, port)
    note(
        awscrt_imported="awscrt" in sys.modules,
        http_session=type(client._endpoint.http_session).__name__,
    )
    client.list_buckets()


def awscrt_http(host: str, port: int) -> None:
    """The AWS Common Runtime's own HTTP client, the transport under its S3 client.

    boto3 builds its transfer manager on that S3 client when it is asked to
    (``TransferConfig(preferred_transfer_client="crt")``).  That one cannot be
    pointed at a port of the world, so the transport is measured directly:
    see ``catalog``.
    """
    import awscrt.http
    import awscrt.io

    event_loops = awscrt.io.EventLoopGroup(1)
    bootstrap = awscrt.io.ClientBootstrap(event_loops, awscrt.io.DefaultHostResolver(event_loops))
    connection = awscrt.http.HttpClientConnection.new(
        host_name=host, port=port, bootstrap=bootstrap
    ).result(TIMEOUT)
    connection.close()


def google_cloud_storage(host: str, port: int) -> None:
    from google.auth.credentials import AnonymousCredentials
    from google.cloud import storage

    client = storage.Client(
        project="tc",
        credentials=AnonymousCredentials(),
        client_options={"api_endpoint": f"http://{host}:{port}"},
    )
    client.get_bucket("tc", timeout=TIMEOUT, retry=None)
