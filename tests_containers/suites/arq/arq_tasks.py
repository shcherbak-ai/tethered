"""The arq worker under test: ``arq arq_tasks.WorkerSettings``.

One process, one asyncio event loop: jobs are coroutines that run in the
loop.  ``TETH_WHERE`` says where the policy is activated (``TETH_ACTIVATE``
says which one):

    import      when this module is imported, before the event loop exists
                (the default)
    on_startup  in the ``on_startup`` coroutine of the worker settings, which arq
                awaits in the running loop before it takes the first job

The job ``probe(op, params)`` knows the blocking operations of every worker
suite (``taskprobe``; they run in the event loop itself) and three of its own:

    open_connection  ``asyncio.open_connection``
    to_thread        a blocking connection in ``asyncio.to_thread``
    child_exec       ``asyncio.create_subprocess_exec`` of a Python child that tries
                     the destination itself

With ``CRON_TARGET=host:port`` a cron job connects there every second.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

import probe_common
import taskprobe
from arq import cron
from arq.connections import RedisSettings

WHERE = os.environ.get("TETH_WHERE", "import")
if WHERE == "import":
    probe_common.activate_from_env()
elif WHERE != "on_startup":
    raise RuntimeError(f"TETH_WHERE={WHERE!r}: import or on_startup")


async def _open_connection(host: str, port: int) -> dict[str, Any]:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 5.0)
    try:
        writer.write(probe_common.REQUEST)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), 5.0)
    finally:
        writer.close()
    return {"reply": probe_common.last_line(data)}


async def _to_thread(host: str, port: int) -> dict[str, Any]:
    return await asyncio.to_thread(probe_common.tcp_connect, host, port)


async def _child_exec(host: str, port: int) -> dict[str, Any]:
    child = await asyncio.create_subprocess_exec(
        sys.executable,
        probe_common.CHILD_SCRIPT,
        host,
        str(port),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(child.communicate(), 60.0)
    return probe_common.launch_report(child.returncode, stdout.decode(), stderr.decode())


ASYNC_OPERATIONS = {
    "open_connection": _open_connection,
    "to_thread": _to_thread,
    "child_exec": _child_exec,
}


def _loop_class() -> str:
    loop = type(asyncio.get_running_loop())
    return f"{loop.__module__}.{loop.__qualname__}"


async def probe(ctx: dict[str, Any], op: str, params: dict[str, str]) -> dict[str, Any]:
    """One operation; the report is the result of the job."""
    if op not in ASYNC_OPERATIONS:
        return {**taskprobe.perform(op, params), "loop": _loop_class()}
    host, port = params["host"], int(params["port"])
    report = {"op": op, "host": host, "port": port, **probe_common.whoami(_loop_class())}
    if params.get("uncaught"):
        report.update(await ASYNC_OPERATIONS[op](host, port), outcome="reached")
    else:
        try:
            report.update(await ASYNC_OPERATIONS[op](host, port), outcome="reached")
        except Exception as exc:
            report.update(probe_common.describe_failure(exc))
    return report


async def tick(ctx: dict[str, Any]) -> None:
    """The cron job: one connection attempt, recorded in the file ``TC_RECORD`` names."""
    host, _, port = os.environ["CRON_TARGET"].rpartition(":")
    taskprobe.perform("connect", {"host": host, "port": port, "record": "1"})


async def startup(ctx: dict[str, Any]) -> None:
    """arq awaits this once, in the running loop, before the worker takes jobs."""
    if WHERE == "on_startup":
        probe_common.activate_from_env()


FUNCTIONS = (probe,)
CRON_JOBS = (cron(tick, second=set(range(60))),) if os.environ.get("CRON_TARGET") else ()


class WorkerSettings:
    """What ``arq arq_tasks.WorkerSettings`` runs."""

    functions = FUNCTIONS
    cron_jobs = CRON_JOBS
    on_startup = startup
    redis_settings = RedisSettings(host="127.0.0.1", port=int(os.environ["REDIS_PORT"]))
    #: How often the worker looks for new jobs (0.5 s by default).
    poll_delay = 0.05
