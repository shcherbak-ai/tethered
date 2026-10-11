"""Apache with mod_wsgi for the tests of this suite: a site, its WSGI scripts, a server.

    site = Site()
    shop = site.script("shop", activate="locked")
    server = site.start(f'''
        WSGIDaemonProcess shop processes=2 threads=1
        WSGIScriptAlias /shop {shop}
        <Location /shop>
            WSGIProcessGroup shop
        </Location>
    ''')
    report = ask(server, "/shop", "connect", FORBIDDEN_NAME, OTHER_PORT)

``Site.start`` writes a complete ``httpd.conf`` around the directives it is
given and runs ``apache2 -DFOREGROUND`` through ``harness.start_server``, so
the server is stopped, and its stop is checked, like every other server of the
container suites.  Starting a site never requests an application: when an
application is loaded, and so when its interpreter is created, is what many of
the tests here are about, and it is the test that decides.

Runs in the pytest process, which holds no policy and never imports tethered.
"""

from __future__ import annotations

import functools
import re
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any

from harness import Server, probe_path, start_server

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

#: Where the sites of a run are written; each is a directory of its own.
WORK = Path(tempfile.gettempdir()) / "tc-modwsgi"
APACHE_MODULES = "/usr/lib/apache2/modules"
#: The user Apache's child processes and mod_wsgi's daemon processes run as.
RUN_AS = "www-data"

#: One Apache child process with enough threads for the requests a test makes at once.
#: In daemon mode the Apache children only pass requests on to the daemon processes.
EVENT_PROXY = """
    StartServers 1
    ServerLimit 2
    ThreadsPerChild 32
    MaxRequestWorkers 32
    MinSpareThreads 1
    MaxSpareThreads 32
"""

#: Embedded mode: the application runs in Apache's own child processes.  Two of them,
#: one request at a time each, so that overlapping requests reach both.
PREFORK_TWO = """
    StartServers 2
    ServerLimit 2
    MinSpareServers 2
    MaxSpareServers 2
    MaxRequestWorkers 2
"""
#: The threaded MPM: one child process with four worker threads.  Not two processes: a
#: child of the event MPM accepts more connections than it has threads, so overlapping
#: requests cannot be made to reach both (with two children of one thread each, one
#: child served every request of a test run).  ServerLimit leaves room for the child
#: that is still finishing while a graceful restart starts its successor.
EVENT_ONE = """
    StartServers 1
    ServerLimit 2
    ThreadsPerChild 4
    MaxRequestWorkers 4
    MinSpareThreads 1
    MaxSpareThreads 4
"""

#: What mod_wsgi writes, at LogLevel debug, when a daemon process is ready to serve.
DAEMON_STARTED = re.compile(r"Starting \d+ threads in daemon process '([^']+)'")
#: A server process that died instead of exiting, or a locked policy that was tampered with.
#: "exit signal" is how Apache's parent reports a child that a signal ended (AH00052).
CRASH = re.compile(r"Fatal Python error|Segmentation fault|exit signal|TAMPER DETECTED")

#: Every server a ``Site`` started and whose log has not had its last check yet.
_unchecked: list[Server] = []


@functools.cache
def module_location() -> str:
    """The path of the mod_wsgi Apache module that pip built for this Python."""
    done = subprocess.run(
        ["mod_wsgi-express", "module-location"], capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


@functools.cache
def apache_version() -> str:
    """``Apache/2.4.x (Debian)``, as ``apache2 -v`` says."""
    done = subprocess.run(["apache2", "-v"], capture_output=True, text=True, check=True)
    match = re.search(r"Server version: (\S+)", done.stdout)
    return match.group(1) if match else done.stdout.strip()


class Site:
    """A directory with WSGI scripts and the Apache configuration that serves them."""

    def __init__(self) -> None:
        WORK.mkdir(parents=True, exist_ok=True)
        #: The ServerRoot: ``apps/`` (the scripts), ``run/`` (sockets, pid file), ``htdocs/``.
        self.root = Path(tempfile.mkdtemp(prefix="site-", dir=WORK))
        # mkdtemp makes it private; Apache's processes run as another user.
        self.root.chmod(0o755)
        for name in ("apps", "run", "htdocs"):
            (self.root / name).mkdir()
        (self.root / "htdocs" / "ready").write_text("ready\n", encoding="utf-8")
        self.conf = self.root / "httpd.conf"

    def script(self, name: str, **settings: Any) -> Path:
        """Write ``apps/<name>.wsgi``; ``settings`` are the arguments of ``mw_app.build``."""
        arguments = "".join(f", {key}={value!r}" for key, value in settings.items())
        return self.write(
            name, f"import mw_app\n\napplication = mw_app.build({name!r}{arguments})\n"
        )

    def write(self, name: str, source: str) -> Path:
        """Write ``apps/<name>.wsgi`` with the given source."""
        path = self.root / "apps" / f"{name}.wsgi"
        path.write_text(textwrap.dedent(source), encoding="utf-8")
        return path

    def configuration(
        self, directives: str, *, mpm: str = "event", mpm_settings: str = EVENT_PROXY
    ) -> str:
        """The whole ``httpd.conf``: what every site needs, then ``directives``."""
        head = f"""
            ServerRoot "{self.root}"
            ServerName localhost
            PidFile "{self.root}/run/httpd.pid"
            DefaultRuntimeDir "{self.root}/run"
            User {RUN_AS}
            Group {RUN_AS}
            LoadModule mpm_{mpm}_module {APACHE_MODULES}/mod_mpm_{mpm}.so
            LoadModule authz_core_module {APACHE_MODULES}/mod_authz_core.so
            LoadModule wsgi_module "{module_location()}"
            WSGIPythonHome "{sys.base_prefix}"
            WSGISocketPrefix "{self.root}/run/wsgi"
            ErrorLog /dev/stderr
            LogLevel info wsgi:debug
            DocumentRoot "{self.root}/htdocs"
            <Directory "{self.root}">
                Require all granted
            </Directory>
        """
        parts = [textwrap.dedent(part).strip() for part in (head, mpm_settings, directives)]
        return "\n\n".join(parts) + "\n"

    def start(
        self,
        directives: str,
        *,
        mpm: str = "event",
        mpm_settings: str = EVENT_PROXY,
        env: Mapping[str, str] | None = None,
        launcher: Sequence[str] = ("apache2",),
        timeout: float = 30.0,
    ) -> Server:
        """Start Apache with ``directives`` and wait until it is ready, loading no application.

        Ready means that Apache answers a static file and that every process
        of every daemon process group in the configuration has started its
        threads.  ``WSGIImportScript`` has run by then: mod_wsgi imports
        those scripts before it starts the threads of a process.

        ``launcher`` is the command that is given Apache's arguments: Apache
        itself, or a program that ends by executing it.
        """
        self.conf.write_text(
            self.configuration(directives, mpm=mpm, mpm_settings=mpm_settings), encoding="utf-8"
        )
        daemons = {}
        for name, options in re.findall(
            r"^\s*WSGIDaemonProcess\s+(\S+)(.*)$", directives, re.MULTILINE
        ):
            processes = re.search(r"\bprocesses=(\d+)", options)
            daemons[name] = int(processes.group(1)) if processes else 1
        command = [*launcher, "-f", str(self.conf), "-DFOREGROUND"]
        command += ["-c", "Listen 127.0.0.1:{port}"]
        return started(
            start_server(
                command,
                env=env,
                ready=lambda server: is_up(server, daemons),
                timeout=timeout,
                cwd=self.root,
            )
        )


def start_express(site: Site, script: Path, *options: str) -> Server:
    """Start ``mod_wsgi-express start-server`` for one script; the application is at ``/``.

    The options given here are the ones that running it as root in a
    container takes (the user of the processes, where it writes its
    generated configuration, the log on the terminal); everything about the
    application is mod_wsgi-express's default.  It replaces itself with
    Apache, so the server's process is Apache's parent as in ``Site.start``.
    Ready means that the application answers: mod_wsgi-express loads it when
    a process starts.
    """
    command = ["mod_wsgi-express", "start-server", str(script), "--port", "{port}"]
    command += ["--user", RUN_AS, "--group", RUN_AS, "--server-root", str(site.root / "express")]
    command += ["--log-to-terminal", "--log-level", "info", *options]
    return started(start_server(command, ready="/whoami", cwd=site.root))


def is_up(server: Server, daemons: Mapping[str, int]) -> bool:
    """Whether Apache answers and each daemon process group has started all its processes.

    ``daemons`` maps the name of a daemon process group to its number of processes.
    """
    if server.get("/ready", timeout=5.0).status != 200:
        return False
    running = Counter(DAEMON_STARTED.findall(server.log))
    return all(running[name] >= processes for name, processes in daemons.items())


def restart_gracefully(server: Server, daemons: int = 1, timeout: float = 30.0) -> None:
    """Do what ``apachectl graceful`` does and wait until the server runs on new processes.

    That is SIGUSR1 to Apache's parent.  Afterwards every process but the
    parent is a new one, ``daemons`` daemon processes have started their
    threads, and Apache answers.  Tests that go on with ``each_worker`` and
    ``exclude`` need no such wait; tests whose next requests must find the
    new processes ready do.
    """
    old = set(server.pids()) - {server.pid}
    already = len(DAEMON_STARTED.findall(server.log))
    server.send_signal(signal.SIGUSR1)
    deadline = time.monotonic() + timeout
    while True:
        left = old & set(server.pids())
        new = len(DAEMON_STARTED.findall(server.log)) - already
        try:
            if not left and new >= daemons and server.get("/ready", timeout=5.0).status == 200:
                return
        except OSError:
            pass
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{server.name}: no clean graceful restart in {timeout} s "
                f"(old processes left: {sorted(left)}, new daemon processes: {new})"
            )
        time.sleep(0.05)


def started(server: Server) -> Server:
    """Note a server for the crash check that follows every test (``conftest.py``)."""
    _unchecked.append(server)
    return server


def check_logs() -> None:
    """Fail if a server of this suite logged a crash, or a tamper alert, so far.

    A stopped server is checked one last time, with its complete log.  The
    stop check of the harness looks at Apache's parent process only: a daemon
    process that dies at shutdown does not change the parent's exit status.
    """
    problems = []
    for server in list(_unchecked):
        found = sorted({match.group(0) for match in CRASH.finditer(server.log)})
        if found:
            problems.append(f"{server.name}: {', '.join(found)}")
        if found or server.returncode is not None:
            _unchecked.remove(server)
    assert not problems, "the log of a server shows a crash: " + "; ".join(problems)


def ask(
    server: Server,
    mount: str,
    op: str,
    host: str | None = None,
    port: int | None = None,
    **params: object,
) -> dict[str, Any]:
    """One operation of the application mounted at ``mount``; its JSON report.

    ``Server.probe`` for an application that is not at the root of the server.
    """
    path = mount.rstrip("/") + probe_path(op, host, port, **params)
    reply = server.get(path)
    if reply.status != 200:
        raise AssertionError(f"GET {path}: HTTP {reply.status}: {reply.text[:2000]}")
    return reply.json()


def standing(report: dict[str, Any]) -> str:
    """Where the interpreter that answered stands with a locked policy of its process.

    ``holder`` took the lock; ``joined`` got a locked copy of the holder's
    policy when it started; ``unlocked`` has a policy that is not locked;
    ``none`` has no policy of its own (in a locked process: it is outside the lock).
    """
    if not report["active"]:
        return "none"
    if not report["locked"]:
        return "unlocked"
    return "holder" if report["holds_lock"] else "joined"
