"""``python -m tethered check``: which rows of the compatibility page apply here.

A preflight check for the owner of an application, run in the environment in
which the application runs, before anything is enforced.  It reports what
tethered would refuse there, what it would not see and what needs
configuration, each as a finding: what is there, what it means, what to do,
and the page of the documentation that says so.  It reports what is
installed and how this interpreter is set up, not what the application uses.

It changes nothing.  It activates no policy and installs no audit hook, makes
no network call, imports no third-party module (distributions are found with
``importlib.metadata``, modules with ``importlib.util.find_spec``) and writes
nothing but its report.  What it reads: the metadata of the installed
distributions, the ``tethered.pth`` candidates of this interpreter (through
``_core``'s helpers, which open the files for reading and log nothing),
environment variables, and facts about the interpreter.

Every statement here is one that ``docs/COMPATIBILITY.md``,
``docs/security.md`` or another page of the documentation makes, in the same
terms; change them together.  The client-library rows are data
(``_clients.py``), a copy of the catalogue of the ``clients`` container suite.
"""

from __future__ import annotations

import importlib.metadata
import multiprocessing
import os
import re
import shutil
import sys
import sysconfig
import textwrap
from typing import TYPE_CHECKING, NamedTuple

import tethered
from tethered import _core
from tethered._clients import ALLOWED_REFUSED, NOT_SEEN, PARTLY, ROWS

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from typing import TextIO

    from tethered._clients import Row

# Facts about this interpreter, read once.  Tests flip them, so that every
# branch runs on every platform.
_WINDOWS = sys.platform == "win32"
_MACOS = sys.platform == "darwin"
_POSIX = os.name == "posix"
_PYTHON = sys.version_info[:2]
_FREE_THREADED = bool(sysconfig.get_config_var("Py_GIL_DISABLED"))

#: Where the installed distributions come from (tests put stand-ins here).
_distributions = importlib.metadata.distributions

_SITE = "https://tethered.shcherbak.ai/"


def _doc(page: str, anchor: str) -> str:
    """The address of a heading of the documentation site (a GitHub-style anchor)."""
    return f"{_SITE}{page}/#{anchor}"


class Finding(NamedTuple):
    """One thing the check found: what is there, what it means, what to do, and where to read."""

    group: str
    what: str
    means: str
    do: str
    links: tuple[str, ...]


EVENT_LOOPS = "Event loops"
NAME_RESOLUTION = "Name resolution"
CLIENT_LIBRARIES = "Client libraries"
CHILD_PROCESSES = "Child processes"
INTERPRETER = "Interpreter"

#: The groups of the report, in the order they are printed.
GROUPS = (EVENT_LOOPS, NAME_RESOLUTION, CLIENT_LIBRARIES, CHILD_PROCESSES, INTERPRETER)

_GROUP_NOTES = {
    CLIENT_LIBRARIES: (
        "A row of the compatibility page is a library in one arrangement. That a library "
        "is installed, or even loaded, does not mean the application uses it in that "
        "arrangement."
    ),
}

# ── Client libraries ──────────────────────────────────────────────────

#: What each result means, in the words of the compatibility page.
_RESULT_MEANS = {
    NOT_SEEN: (
        "Under any policy the name is looked up and the address and the port are reached, "
        "and nothing is reported: locked=True, fail_closed=True and log_only change nothing."
    ),
    PARTLY: (
        "The name is checked; the connection is made in C, so a raw address or a port "
        "outside the rule is reached."
    ),
    ALLOWED_REFUSED: (
        "Nothing forbidden is reached, but a host the allow list names is refused as well, "
        "because the library looked the name up where tethered could not see it. The "
        "forbidden name is still sent to the name server."
    ),
}

_BELOW_PYTHON = "a control below Python: a network policy, a firewall rule, seccomp"
_NOTHING_IN_TETHERED = f"No setting of tethered changes this. Use {_BELOW_PYTHON}."
_POSTGRES_DRIVER = (
    f"Use a pure-Python driver, pg8000 or asyncpg, which are enforced, or {_BELOW_PYTHON}."
)

#: For each client-library row that is not about a resolver: what to do, and
#: the section of the compatibility page that holds the row.
_CLIENT_ADVICE = {
    "pycurl": (_NOTHING_IN_TETHERED, "http-and-websocket-clients"),
    "curl-cffi": (_NOTHING_IN_TETHERED, "http-and-websocket-clients"),
    "tornado-curl": (
        "Use tornado's default AsyncHTTPClient (simple_httpclient), which is enforced, "
        f"or {_BELOW_PYTHON}.",
        "http-and-websocket-clients",
    ),
    "psycopg2": (_POSTGRES_DRIVER, "postgresql"),
    "psycopg-binary-sync": (_POSTGRES_DRIVER, "postgresql"),
    "psycopg-binary-async": (_POSTGRES_DRIVER, "postgresql"),
    "psycopg-python-sync": (_POSTGRES_DRIVER, "postgresql"),
    "psycopg-python-async": (_POSTGRES_DRIVER, "postgresql"),
    "mysqlclient": (
        "Use a pure-Python driver, PyMySQL, aiomysql, or mysql-connector-python with "
        f"use_pure=True, which are enforced, or {_BELOW_PYTHON}.",
        "mysql",
    ),
    "mysql-connector-c": (
        "Connect with use_pure=True: mysql-connector-python's pure-Python implementation is "
        "enforced.",
        "mysql",
    ),
    "pymssql": (_NOTHING_IN_TETHERED, "sql-server-and-oracle"),
    "pyodbc-freetds": (_NOTHING_IN_TETHERED, "sql-server-and-oracle"),
    "grpcio": (_NOTHING_IN_TETHERED, "messaging-and-rpc"),
    "grpcio-aio": (_NOTHING_IN_TETHERED, "messaging-and-rpc"),
    "confluent-kafka": (
        f"Use kafka-python, which is enforced, or {_BELOW_PYTHON}.",
        "messaging-and-rpc",
    ),
    "pyzmq": (_NOTHING_IN_TETHERED, "messaging-and-rpc"),
    "awscrt-http": (
        "boto3 and botocore connect through urllib3, which is enforced with awscrt "
        "installed. For what goes through awscrt.http, boto3's CRT transfer manager "
        f"included, use {_BELOW_PYTHON}.",
        "cloud-sdks",
    ),
}

#: The rows about a resolver of the library's own, which the name-resolution
#: findings report.
_CARES_ROWS = ("aiohttp-aiodns-imported-first", "pycares-then-connect", "aiodns-then-connect")
_DNSPYTHON_ROWS = ("dnspython-then-connect",)
_GEVENT_ROWS = ("gevent-ares",)
_EVENTLET_ROWS = ("eventlet",)
RESOLVER_ROWS = (*_CARES_ROWS, *_DNSPYTHON_ROWS, *_GEVENT_ROWS, *_EVENTLET_ROWS)

# ── Reading the environment ───────────────────────────────────────────


def _canonical(name: str) -> str:
    """A distribution name as PyPI compares names (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _installed() -> dict[str, str]:
    """Map the canonical name of each installed distribution to its version.

    The first of a name on ``sys.path`` wins, as for an import.  A
    distribution whose metadata cannot be read, or names nothing, is passed
    over.
    """
    versions: dict[str, str] = {}
    for dist in _distributions():
        name, version = _name_and_version(dist)
        if name:
            versions.setdefault(_canonical(name), version)
    return versions


def _name_and_version(dist: importlib.metadata.Distribution) -> tuple[str, str]:
    """The name and the version a distribution's metadata gives, ``""`` for what it lacks.

    Asked with ``in`` first: a missing key read with ``[]`` warns on Python
    3.12 to 3.14 and raises ``KeyError`` from 3.15, and the
    ``PackageMetadata`` protocol has no ``get()``.
    """
    try:
        metadata = dist.metadata
        name = metadata["Name"] if "Name" in metadata else ""  # noqa: SIM401
        version = metadata["Version"] if "Version" in metadata else ""  # noqa: SIM401
    except Exception:  # a broken installation: unreadable or undecodable metadata
        return "", ""
    return name or "", version or ""


def _importable(name: str) -> bool:
    """Whether ``import name`` finds a module, as tethered's import refusal asks it.

    ``find_spec`` of a top-level name imports nothing; of a submodule of
    tethered, nothing but tethered.
    """
    return _core._is_installed(name)


def _default_start_method() -> str:
    """multiprocessing's default start method here, without fixing it or writing a file.

    From Python 3.14 it is forkserver on POSIX where that start method is
    available, macOS excepted, as multiprocessing's documentation says.  From
    3.14.9 and 3.15.1 multiprocessing makes sure of it by creating a file in
    the temporary directory and removing it, and takes spawn where it cannot
    (gh-155717), so the check does not ask it there: it says forkserver even
    where the temporary directory is not writable.  Elsewhere
    ``get_all_start_methods()`` lists the default first and writes nothing.
    ``get_start_method()`` would fix the context of this process, and
    ``allow_none=True`` only says that none was fixed.
    """
    if _POSIX and not _MACOS and _PYTHON >= (3, 14):
        try:
            multiprocessing.get_context("forkserver")
        except ValueError:  # no passing of file descriptors over Unix pipes here
            return "spawn"
        return "forkserver"
    return multiprocessing.get_all_start_methods()[0]


def _gevent_resolver_is_ares() -> bool:
    """Whether ``GEVENT_RESOLVER`` makes gevent take its c-ares resolver.

    gevent reads the variable as a comma-separated list and takes the first
    entry that it can import; c-ares is bundled with gevent.
    """
    first = os.environ.get("GEVENT_RESOLVER", "").split(",")[0]
    return first in ("ares", "gevent.resolver.ares.Resolver")


def _eventlet_uses_greendns() -> bool:
    """Whether eventlet's green socket module resolves through greendns.

    It does unless ``EVENTLET_NO_GREENDNS`` is ``yes`` (in any case).
    """
    return os.environ.get("EVENTLET_NO_GREENDNS", "").lower() != "yes"


# ── Wording ───────────────────────────────────────────────────────────


def _join(items: Sequence[str]) -> str:
    """'a', 'a and b', 'a, b and c'."""
    if len(items) < 2:
        return "".join(items)
    return f"{', '.join(items[:-1])} and {items[-1]}"


def _named(names: Iterable[str], installed: dict[str, str]) -> str:
    """'uvloop 0.23.0 is installed.', each name with its version where one is known."""
    parts = [f"{name} {installed.get(_canonical(name), '')}".rstrip() for name in names]
    return f"{_join(parts)} {'is' if len(parts) == 1 else 'are'} installed."


def _applicable(ids: Iterable[str], installed: dict[str, str]) -> list[Row]:
    """The rows of ``ids`` all of whose distributions are installed, in table order."""
    wanted = set(ids)
    return [
        row
        for row in ROWS
        if row.id in wanted and all(_canonical(p) in installed for p in row.packages)
    ]


def _measured(rows: Sequence[Row]) -> str:
    """What the compatibility page says of ``rows``, which share a result and a mechanism."""
    if not rows:
        return ""
    titles = _join([f'"{row.title}"' for row in rows])
    noun = "arrangement" if len(rows) == 1 else "arrangements"
    return (
        f"Measured {noun} {titles}: {rows[0].result} ({rows[0].mechanism}). "
        f"{_RESULT_MEANS[rows[0].result]}"
    )


def _sentences(*parts: str) -> str:
    return " ".join(part for part in parts if part)


# ── Findings ──────────────────────────────────────────────────────────


def _event_loop_findings(installed: dict[str, str]) -> list[Finding]:
    found = []
    if _importable("uvloop"):
        found.append(
            Finding(
                EVENT_LOOPS,
                _named(["uvloop"], installed),
                "A uvloop event loop does its networking outside Python's socket module and "
                "raises no audit event. While a policy that is not log_only is active, "
                "import uvloop raises ImportError, and a server that takes uvloop only when "
                "the import works runs on the standard asyncio event loop. When uvloop is "
                "already loaded, activate() of such a policy raises RuntimeError. A log_only "
                "policy refuses nothing and reports nothing that goes through a uvloop loop.",
                "Name the standard loop in the server's configuration (uvicorn --loop "
                "asyncio), or call activate() in a launcher script before the server is "
                "imported, or uninstall uvloop where nothing needs it. Which servers fall "
                "back, which do not start, and where a process still ends on uvloop is on "
                "the compatibility page.",
                (
                    _doc("COMPATIBILITY", "event-loops-and-green-threads"),
                    _doc("COOKBOOK", "servers-and-interpreter-pools"),
                ),
            )
        )
    if _WINDOWS:
        found.append(
            Finding(
                EVENT_LOOPS,
                "This is Windows, where asyncio's default event loop is ProactorEventLoop.",
                "It connects and sends datagrams through overlapped I/O calls that raise no "
                "socket.connect / socket.sendto audit event. On it, raw-IP destinations, "
                "port rules and scope() connect checks are not enforced; only the global "
                "policy's DNS-time hostname check applies. Synchronous code is not affected.",
                "Run the loop as asyncio.SelectorEventLoop (asyncio.run(main(), "
                "loop_factory=asyncio.SelectorEventLoop) on Python 3.12+).",
                (_doc("security", "event-loops"),),
            )
        )
    return found


def _resolver_findings(installed: dict[str, str]) -> list[Finding]:
    found = []
    if _importable("pycares"):
        names = ["pycares"] + [n for n in ("aiodns", "aiohttp") if n in installed]
        found.append(
            Finding(
                NAME_RESOLUTION,
                _named(names, installed),
                _sentences(
                    "c-ares resolves names in C. While a policy that is not log_only is "
                    "active, import pycares raises ImportError, and so does import aiodns: "
                    "code that requires them fails, and aiohttp falls back to its threaded "
                    "resolver, which is enforced. A pycares that was imported before "
                    "activate() is left alone.",
                    _measured(_applicable(_CARES_ROWS, installed)),
                ),
                "Call activate() before aiohttp, aiodns or pycares is imported (python -m "
                "aiohttp.web and gunicorn's aiohttp worker import aiohttp before the "
                "application), or pass aiohttp.TCPConnector(resolver=aiohttp."
                "ThreadedResolver()), or uninstall aiodns, or add a rule for the address.",
                (_doc("COMPATIBILITY", "notes-on-the-table"),),
            )
        )
    rows = _applicable(_DNSPYTHON_ROWS, installed)
    if rows:
        found.append(
            Finding(
                NAME_RESOLUTION,
                _named(["dnspython"], installed),
                _sentences(
                    _measured(rows),
                    "Its query to a name server is a socket.sendto and is checked like any "
                    "datagram.",
                ),
                "Resolve through the system resolver (socket.getaddrinfo), or add a rule for "
                "the address; dnspython then still sends the name to the name server.",
                (_doc("COMPATIBILITY", "notes-on-the-table"),),
            )
        )
    rows = _applicable(_GEVENT_ROWS, installed)
    if rows and _gevent_resolver_is_ares():
        found.append(
            Finding(
                NAME_RESOLUTION,
                _sentences(
                    _named(["gevent"], installed),
                    "GEVENT_RESOLVER selects its c-ares resolver in this environment.",
                ),
                _measured(rows),
                "Use gevent's default resolver (leave GEVENT_RESOLVER unset) or "
                "GEVENT_RESOLVER=block.",
                (_doc("COMPATIBILITY", "event-loops-and-green-threads"),),
            )
        )
    rows = _applicable(_EVENTLET_ROWS, installed)
    if rows and _eventlet_uses_greendns():
        found.append(
            Finding(
                NAME_RESOLUTION,
                _sentences(
                    _named(["eventlet"], installed),
                    "EVENTLET_NO_GREENDNS is not set to yes in this environment.",
                ),
                _sentences(
                    _measured(rows),
                    "The same holds for Celery's eventlet pool.",
                ),
                "Set EVENTLET_NO_GREENDNS=yes in the environment of the application.",
                (_doc("COMPATIBILITY", "event-loops-and-green-threads"),),
            )
        )
    return found


def _client_findings(installed: dict[str, str]) -> list[Finding]:
    """One finding for the rows that share a result, a mechanism and the advice."""
    groups: dict[tuple[str, str, str, str], list[Row]] = {}
    for row in _applicable(_CLIENT_ADVICE, installed):
        groups.setdefault((row.result, row.mechanism, *_CLIENT_ADVICE[row.id]), []).append(row)
    found = []
    for (_result, _mechanism, do, section), rows in groups.items():
        packages = dict.fromkeys(package for row in rows for package in row.packages)
        found.append(
            Finding(
                CLIENT_LIBRARIES,
                _named(packages, installed),
                _measured(rows),
                do,
                (_doc("COMPATIBILITY", section),),
            )
        )
    return found


def _bootstrap_findings() -> list[Finding]:
    """What is wrong with ``tethered.pth`` for this interpreter, if anything.

    The three helpers of ``_core`` that ``activate()`` asks for its warning,
    in the same order.  They read the candidate files and log nothing.
    """
    if _core._compute_pth_path():
        return []
    link = (_doc("SUBPROCESS", "auto-propagation-to-python-child-processes"),)
    unprotected = (
        "Python child processes will not inherit the policy: activate() logs a warning, "
        "and every launch of sys.executable is treated as external (warned about under "
        'the default external_subprocess_policy="warn", refused under "block").'
    )
    stand_in = _core._stand_in_pth_path()
    if stand_in:
        return [
            Finding(
                CHILD_PROCESSES,
                f"{stand_in} is not the file tethered installs under that name: it does not "
                "hold tethered's bootstrap line.",
                _sentences(
                    "Another distribution that ships a top-level tethered.pth replaces "
                    "tethered's when it is installed, and neither pip nor uv says so; or the "
                    "file was changed. tethered does not take it for its bootstrap.",
                    unprotected,
                ),
                "Reinstall tethered. Uninstalling the distribution that ships the other file "
                "removes tethered.pth altogether; reinstall tethered after that too.",
                link,
            )
        ]
    silenced = _core._silenced_pth_path()
    if silenced:
        return [
            Finding(
                CHILD_PROCESSES,
                f"{_core._start_file_beside(silenced)} lies beside tethered's {silenced}.",
                _sentences(
                    "From Python 3.15, site.py does not run the import line of a .pth file "
                    "that has a .start file of its name beside it (PEP 829).",
                    unprotected,
                ),
                "Remove it: tethered ships no such file.",
                link,
            )
        ]
    return [
        Finding(
            CHILD_PROCESSES,
            "No tethered.pth is in a site directory this interpreter processes.",
            _sentences(
                unprotected,
                "A subinterpreter created while a policy is locked cannot join the lock: "
                "under an enforcing policy it gets no network. Typical causes: an editable "
                "install (-e), a --target install used through PYTHONPATH, or an interpreter "
                "started with -S.",
            ),
            "Install tethered into site-packages with a regular install (uv add tethered, "
            "pip install tethered), not editable and not --target.",
            link,
        )
    ]


def _child_process_findings(installed: dict[str, str]) -> list[Finding]:
    found = _bootstrap_findings()
    if not _core._SYS_EXECUTABLE_IS_PYTHON:
        found.append(
            Finding(
                CHILD_PROCESSES,
                f"sys.executable is {sys.executable}, which tethered takes for a program "
                "that embeds Python, not for an interpreter.",
                "tethered recognizes a Python child by sys.executable, so it recognizes none: "
                "activate() logs a warning, and every launch counts as external (warned "
                'about, refused under external_subprocess_policy="block"), a launch of the '
                "real interpreter included, although that child does inherit the policy.",
                "Give the server the interpreter's path (uWSGI: --py-sys-executable "
                "/path/to/python).",
                (_doc("SUBPROCESS", "when-sysexecutable-is-not-python"),),
            )
        )
    elif "uwsgi" in installed:
        found.append(
            Finding(
                CHILD_PROCESSES,
                _named(["uWSGI"], installed),
                "Under uWSGI, sys.executable is the uwsgi binary, not a Python interpreter: "
                "subprocess.run([sys.executable, ...]) starts uWSGI, activate() logs a "
                "warning, and every launch counts as external (warned about, refused under "
                'external_subprocess_policy="block"), a launch of the real interpreter '
                "included, although that child does inherit the policy.",
                "Start uWSGI with --py-sys-executable /path/to/python.",
                (_doc("COMPATIBILITY", "uwsgi"), _doc("COOKBOOK", "uwsgi")),
            )
        )
    if _POSIX and _PYTHON < (3, 14):
        found.append(
            Finding(
                CHILD_PROCESSES,
                "multiprocessing's spawn and forkserver launches raise no audit event here "
                "(POSIX, Python 3.11 to 3.13).",
                "tethered sees neither the launch nor its environment: no "
                "external_subprocess_policy, no locked-mode payload check, and no repair of "
                "a cleaned os.environ. Workers still inherit the policy while "
                "_TETHERED_CHILD_POLICY is intact in the environment of the process.",
                "Leave _TETHERED_CHILD_POLICY in the environment of the process. From "
                "Python 3.14 these launches are handled.",
                (_doc("security", "child-processes"),),
            )
        )
    if _default_start_method() == "forkserver":
        found.append(
            Finding(
                CHILD_PROCESSES,
                "multiprocessing's default start method here is forkserver.",
                "A forkserver worker is a copy of the fork server process. A fork server "
                "that was started before activate() holds no policy, and neither does any "
                "worker it produces from then on, under a locked policy too: asking it for a "
                "worker raises no launch event. activate() logs one warning when it finds a "
                "fork server already running.",
                "Call activate() before the first pool or process is started.",
                (_doc("COOKBOOK", "process-pools-and-the-fork-server"),),
            )
        )
    return found


def _interpreter_findings() -> list[Finding]:
    found = []
    if _FREE_THREADED:
        found.append(
            Finding(
                INTERPRETER,
                "This is a free-threaded build of Python.",
                "tethered's C extension does not declare free-threading support: CPython "
                "re-enables the GIL when it is imported, and a process that activates "
                "tethered imports it. tethered has not been validated on free-threaded "
                "Python, and no free-threaded wheels are published.",
                "Expect the GIL to be enabled in a process that activates tethered.",
                (_doc("ARCHITECTURE", "thread-safety"),),
            )
        )
    if not _importable("tethered._guardian"):
        found.append(
            Finding(
                INTERPRETER,
                "tethered's C extension (tethered._guardian) is missing from this installation.",
                "Locked mode requires it: activate(locked=True) raises RuntimeError.",
                "Reinstall tethered. Wheels are prebuilt; a source install needs a C compiler.",
                (_doc("security", "locked-mode--what-it-does-and-does-not-do"),),
            )
        )
    return found


def findings() -> list[Finding]:
    """Return what the check finds in this interpreter and its environment, by group."""
    installed = _installed()
    return [
        *_event_loop_findings(installed),
        *_resolver_findings(installed),
        *_client_findings(installed),
        *_child_process_findings(installed),
        *_interpreter_findings(),
    ]


# ── The report ────────────────────────────────────────────────────────


def _wrap(text: str, width: int, indent: str, first: str = "") -> list[str]:
    # An address or a path is never broken, however long.
    return textwrap.wrap(
        text,
        width,
        initial_indent=first or indent,
        subsequent_indent=indent,
        break_long_words=False,
        break_on_hyphens=False,
    )


def render(found: Sequence[Finding], width: int) -> str:
    """Return the report on ``found`` as plain text, wrapped at ``width`` columns."""
    lines = [
        f"tethered {tethered.__version__} check: Python {sys.version.split()[0]} "
        f"({sys.implementation.name}) on {sys.platform}",
        f"Interpreter: {sys.executable}",
        *_wrap(
            "Nothing was activated or changed. The findings say what is installed here and "
            "how this interpreter is set up, not what the application uses.",
            width,
            "",
        ),
    ]
    for group in GROUPS:
        members = [finding for finding in found if finding.group == group]
        if not members:
            continue
        lines += ["", group]
        if group in _GROUP_NOTES:
            lines += _wrap(_GROUP_NOTES[group], width, "  ")
        for finding in members:
            lines.append("")
            lines += _wrap(finding.what, width, "    ", "  - ")
            lines += _wrap(finding.means, width, "    ")
            lines += _wrap(f"What to do: {finding.do}", width, "    ")
            lines += [f"    See {link}" for link in finding.links]
    count = len(found)
    lines += ["", f"{count} finding{'' if count == 1 else 's'}."]
    return "\n".join(lines) + "\n"


def run(out: TextIO) -> int:
    """Write the report on this environment to ``out``; return the number of findings."""
    found = findings()
    width = max(60, min(100, shutil.get_terminal_size((88, 24)).columns - 1))
    text = render(found, width)
    # A path in the report may hold a character the stream cannot encode.
    encoding = getattr(out, "encoding", None) or "utf-8"
    out.write(text.encode(encoding, "backslashreplace").decode(encoding))
    return len(found)
