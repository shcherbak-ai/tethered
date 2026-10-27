"""``python -m tethered check``: the preflight check (``_check.py``, ``__main__.py``).

Each finding is shown to appear when its condition holds and not otherwise,
with stand-ins for what is installed (``_check._distributions``), what can be
imported (``_check._importable``), the bootstrap candidates
(``_core._pth_candidates``) and the facts about the interpreter (module
constants), so that every branch runs on every platform.  The check itself
is run in a child process to show that it changes nothing.  The rows it
ships (``_clients.py``) are compared with the catalogue of the ``clients``
container suite, and its links with the headings of the documentation.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import io
import json
import multiprocessing
import os
import re
import runpy
import subprocess
import sys
import sysconfig
import warnings
from pathlib import Path

import pytest

from tethered import __main__ as cli
from tethered import _check, _clients, _core
from tethered._check import (
    CHILD_PROCESSES,
    CLIENT_LIBRARIES,
    EVENT_LOOPS,
    INTERPRETER,
    NAME_RESOLUTION,
    Finding,
)

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "tests_containers" / "suites" / "clients" / "catalog.py"
DOCS = ROOT / "docs"
ROWS = {row.id: row for row in _clients.ROWS}


class _Dist:
    """A stand-in for an ``importlib.metadata`` distribution."""

    def __init__(self, metadata: dict[str, str] | Exception) -> None:
        self._metadata = metadata

    @property
    def metadata(self) -> dict[str, str]:
        if isinstance(self._metadata, Exception):
            raise self._metadata
        return self._metadata


class Stage:
    """An environment in which the check finds nothing; a test changes one thing at a time."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self.monkeypatch = monkeypatch
        self.dists: list[_Dist] = []
        self.modules = {"tethered._guardian"}
        self.site = tmp_path / "site-packages"
        self.site.mkdir()
        self.hook = self.site / "tethered.pth"
        self.hook.write_text(_core._PTH_BOOTSTRAP + "\n", encoding="utf-8")
        monkeypatch.setattr(_check, "_distributions", lambda: list(self.dists))
        monkeypatch.setattr(_check, "_importable", lambda name: name in self.modules)
        monkeypatch.setattr(_core, "_pth_candidates", lambda: [str(self.hook)])
        monkeypatch.setattr(_core, "_START_FILE_SILENCES_PTH", False)
        monkeypatch.setattr(_core, "_SYS_EXECUTABLE_IS_PYTHON", True)
        monkeypatch.setattr(_check, "_WINDOWS", False)
        monkeypatch.setattr(_check, "_POSIX", True)
        monkeypatch.setattr(_check, "_PYTHON", (3, 14))
        monkeypatch.setattr(_check, "_FREE_THREADED", False)
        monkeypatch.setattr(_check, "_default_start_method", lambda: "spawn")
        monkeypatch.delenv("GEVENT_RESOLVER", raising=False)
        monkeypatch.delenv("EVENTLET_NO_GREENDNS", raising=False)

    def install(self, *names: str, version: str = "1.0") -> None:
        for name in names:
            self.dists.append(_Dist({"Name": name, "Version": version}))

    def everything(self) -> None:
        """Make every condition true that can be true at once."""
        self.install(*{p for row in _clients.ROWS for p in row.packages}, "uWSGI")
        self.modules = {"uvloop", "pycares"}
        self.monkeypatch.setattr(_check, "_WINDOWS", True)
        self.monkeypatch.setattr(_check, "_PYTHON", (3, 13))
        self.monkeypatch.setattr(_check, "_FREE_THREADED", True)
        self.monkeypatch.setattr(_check, "_default_start_method", lambda: "forkserver")
        self.monkeypatch.setenv("GEVENT_RESOLVER", "ares")


@pytest.fixture
def stage(monkeypatch, tmp_path) -> Stage:
    return Stage(monkeypatch, tmp_path)


def _in(group: str, found: list[Finding]) -> list[Finding]:
    return [finding for finding in found if finding.group == group]


def _text(found: list[Finding]) -> str:
    return " ".join(" ".join((f.what, f.means, f.do, *f.links)) for f in found)


def test_nothing_to_report(stage):
    assert _check.findings() == []
    assert _check.render([], 80).endswith("\n0 findings.\n")


# ── Event loops ───────────────────────────────────────────────────────


class TestUvloop:
    def test_installed(self, stage):
        stage.modules.add("uvloop")
        stage.install("uvloop", version="0.23.0")
        (finding,) = _check.findings()
        assert finding.group == EVENT_LOOPS
        assert finding.what == "uvloop 0.23.0 is installed."
        assert "import uvloop raises ImportError" in finding.means
        assert "activate() of such a policy raises RuntimeError" in finding.means
        assert "--loop asyncio" in finding.do

    def test_importable_without_metadata(self, stage):
        stage.modules.add("uvloop")
        (finding,) = _check.findings()
        assert finding.what == "uvloop is installed."

    def test_a_distribution_alone_is_not_the_module(self, stage):
        stage.install("uvloop")
        assert _check.findings() == []


class TestProactorLoop:
    def test_windows(self, stage, monkeypatch):
        monkeypatch.setattr(_check, "_WINDOWS", True)
        (finding,) = _check.findings()
        assert finding.group == EVENT_LOOPS
        assert "ProactorEventLoop" in finding.what
        assert "asyncio.SelectorEventLoop" in finding.do

    def test_the_constant_is_the_platform(self):
        assert _check._WINDOWS is (sys.platform == "win32")


# ── Name resolution ───────────────────────────────────────────────────


class TestCares:
    def test_pycares_aiodns_and_aiohttp(self, stage):
        stage.modules.add("pycares")
        stage.install("pycares", "aiodns", "aiohttp", version="5.1.0")
        (finding,) = _check.findings()
        assert finding.group == NAME_RESOLUTION
        assert finding.what == "pycares 5.1.0, aiodns 5.1.0 and aiohttp 5.1.0 are installed."
        assert "import pycares raises ImportError, and so does import aiodns" in finding.means
        for row in _check._CARES_ROWS:
            assert f'"{ROWS[row].title}"' in finding.means
        assert "allowed host refused" in finding.means
        assert "ThreadedResolver" in finding.do

    def test_pycares_alone(self, stage):
        stage.modules.add("pycares")
        stage.install("pycares")
        (finding,) = _check.findings()
        assert finding.what == "pycares 1.0 is installed."
        assert f'arrangement "{ROWS["pycares-then-connect"].title}"' in finding.means
        assert ROWS["aiodns-then-connect"].title not in finding.means

    def test_importable_without_metadata(self, stage):
        stage.modules.add("pycares")
        (finding,) = _check.findings()
        assert finding.what == "pycares is installed."
        assert "Measured" not in finding.means

    def test_not_importable(self, stage):
        stage.install("aiodns", "aiohttp")
        assert _check.findings() == []


class TestDnspython:
    def test_installed(self, stage):
        stage.install("dnspython", version="2.9.0")
        (finding,) = _check.findings()
        assert finding.group == NAME_RESOLUTION
        assert finding.what == "dnspython 2.9.0 is installed."
        assert ROWS["dnspython-then-connect"].title in finding.means


class TestGevent:
    @pytest.mark.parametrize("value", ["ares", "ares,thread", "gevent.resolver.ares.Resolver"])
    def test_ares(self, stage, monkeypatch, value):
        stage.install("gevent", version="26.9.0")
        monkeypatch.setenv("GEVENT_RESOLVER", value)
        (finding,) = _check.findings()
        assert finding.group == NAME_RESOLUTION
        assert finding.what.startswith("gevent 26.9.0 is installed. GEVENT_RESOLVER selects")
        assert ROWS["gevent-ares"].title in finding.means

    @pytest.mark.parametrize("value", [None, "thread", "block", "thread,ares", "dnspython"])
    def test_other_resolvers(self, stage, monkeypatch, value):
        stage.install("gevent")
        if value is not None:
            monkeypatch.setenv("GEVENT_RESOLVER", value)
        assert _check.findings() == []

    def test_the_variable_without_gevent(self, stage, monkeypatch):
        monkeypatch.setenv("GEVENT_RESOLVER", "ares")
        assert _check.findings() == []


class TestEventlet:
    """eventlet installs dnspython, which greendns is built on; the row names both."""

    GREENDNS = (
        "eventlet 1.0 is installed. EVENTLET_NO_GREENDNS is not set to yes in this environment."
    )

    @pytest.mark.parametrize("value", [None, "", "no", "1", "true"])
    def test_greendns(self, stage, monkeypatch, value):
        stage.install("eventlet", "dnspython")
        if value is not None:
            monkeypatch.setenv("EVENTLET_NO_GREENDNS", value)
        found = _in(NAME_RESOLUTION, _check.findings())
        assert [f.what for f in found] == ["dnspython 1.0 is installed.", self.GREENDNS]
        assert ROWS["eventlet"].title in found[1].means
        assert found[1].do == "Set EVENTLET_NO_GREENDNS=yes in the environment of the application."

    @pytest.mark.parametrize("value", ["yes", "YES", "Yes"])
    def test_switched_off(self, stage, monkeypatch, value):
        stage.install("eventlet", "dnspython")
        monkeypatch.setenv("EVENTLET_NO_GREENDNS", value)
        assert [f.what for f in _check.findings()] == ["dnspython 1.0 is installed."]

    def test_the_variable_without_eventlet(self, stage):
        assert _check.findings() == []


# ── Client libraries ──────────────────────────────────────────────────


class TestClientLibraries:
    @pytest.mark.parametrize("row_id", sorted(_check._CLIENT_ADVICE))
    def test_each_row(self, stage, row_id):
        row = ROWS[row_id]
        stage.install(*row.packages)
        found = _check.findings()
        assert {f.group for f in found} == {CLIENT_LIBRARIES}
        (finding,) = [f for f in found if f'"{row.title}"' in f.means]
        assert f'": {row.result} ({row.mechanism}).' in finding.means
        assert _check._RESULT_MEANS[row.result] in finding.means
        do, section = _check._CLIENT_ADVICE[row_id]
        assert finding.do == do
        assert finding.links == (f"https://tethered.shcherbak.ai/COMPATIBILITY/#{section}",)

    def test_a_row_needs_all_its_distributions(self, stage):
        stage.install("tornado")
        assert _check.findings() == []

    def test_rows_with_the_same_result_mechanism_and_advice_are_one_finding(self, stage):
        stage.install("psycopg", "psycopg-binary", "grpcio")
        found = _check.findings()
        assert [f.what for f in found] == [
            "psycopg 1.0 and psycopg-binary 1.0 are installed.",
            "grpcio 1.0 is installed.",
        ]
        assert found[0].means.startswith("Measured arrangements ")
        for row in ("psycopg-binary-sync", "psycopg-python-async", "psycopg-binary-async"):
            assert ROWS[row].title in found[0].means

    def test_other_advice_is_another_finding(self, stage):
        stage.install("tornado", "pycurl")
        found = _check.findings()
        assert [f.what for f in found] == [
            "pycurl 1.0 is installed.",
            "tornado 1.0 and pycurl 1.0 are installed.",
        ]

    def test_names_are_compared_as_pypi_compares_them(self, stage):
        stage.install("Psycopg2_Binary", version="2.9.13")
        (finding,) = _check.findings()
        assert finding.what == "psycopg2-binary 2.9.13 is installed."

    def test_every_shipped_row_is_reported_once(self):
        advice, resolvers = set(_check._CLIENT_ADVICE), set(_check.RESOLVER_ROWS)
        assert not advice & resolvers
        assert advice | resolvers == set(ROWS)
        assert len(_check.RESOLVER_ROWS) == len(resolvers)


class TestInstalledDistributions:
    def test_unreadable_and_nameless_metadata_is_passed_over(self, stage):
        stage.dists = [
            _Dist(UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")),
            _Dist({"Version": "1.0"}),
            _Dist({"Name": "grpcio"}),
            _Dist({"Name": "grpcio", "Version": "9.9"}),
        ]
        assert _check._installed() == {"grpcio": ""}
        (finding,) = _check.findings()
        assert finding.what == "grpcio is installed."

    def test_real_metadata_that_lacks_a_field(self, stage, tmp_path, monkeypatch):
        # A missing key read with [] warns on 3.12 to 3.14 and raises from 3.15.
        dists = tmp_path / "dists"
        for name, metadata in [("grpcio-0", "Name: grpcio\n"), ("nameless-0", "Version: 1\n")]:
            (dists / f"{name}.dist-info").mkdir(parents=True)
            (dists / f"{name}.dist-info" / "METADATA").write_text(
                f"Metadata-Version: 2.1\n{metadata}", encoding="utf-8"
            )
        monkeypatch.setattr(
            _check, "_distributions", lambda: importlib.metadata.distributions(path=[str(dists)])
        )
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            assert _check._installed() == {"grpcio": ""}

    def test_this_environment(self):
        assert "pytest" in _check._installed()

    def test_the_real_lookup(self):
        assert _check._importable("tethered._guardian") is True
        assert _check._importable("tethered_check_no_such_module") is False


# ── Child processes ───────────────────────────────────────────────────


class TestBootstrap:
    def test_tethereds_own_hook(self, stage):
        assert _check._bootstrap_findings() == []

    def test_another_file_of_that_name(self, stage):
        stage.hook.write_text("import another_package\n", encoding="utf-8")
        (finding,) = _check.findings()
        assert finding.group == CHILD_PROCESSES
        assert finding.what.startswith(f"{stage.hook} is not the file tethered installs")
        assert "Reinstall tethered" in finding.do

    def test_a_start_file_beside_it(self, stage, monkeypatch):
        monkeypatch.setattr(_core, "_START_FILE_SILENCES_PTH", True)
        start = stage.site / "tethered.start"
        start.write_text("", encoding="utf-8")
        (finding,) = _check.findings()
        assert finding.what == f"{start} lies beside tethered's {stage.hook}."
        assert "PEP 829" in finding.means
        assert finding.do == "Remove it: tethered ships no such file."

    def test_a_start_file_before_3_15(self, stage):
        (stage.site / "tethered.start").write_text("", encoding="utf-8")
        assert _check.findings() == []

    def test_no_file(self, stage):
        stage.hook.unlink()
        (finding,) = _check.findings()
        assert finding.what == "No tethered.pth is in a site directory this interpreter processes."
        assert "editable install" in finding.means
        assert "regular install" in finding.do

    def test_no_site_directory(self, stage, monkeypatch):
        monkeypatch.setattr(_core, "_pth_candidates", lambda: [])
        (finding,) = _check.findings()
        assert finding.what.startswith("No tethered.pth")

    def test_this_environment(self):
        # conftest.py puts tethered's hook into site-packages for the run.
        assert _check._bootstrap_findings() == []


class TestSysExecutable:
    def test_a_program_that_embeds_python(self, stage, monkeypatch):
        monkeypatch.setattr(_core, "_SYS_EXECUTABLE_IS_PYTHON", False)
        (finding,) = _check.findings()
        assert finding.group == CHILD_PROCESSES
        assert finding.what.startswith(f"sys.executable is {sys.executable}, ")
        assert "--py-sys-executable" in finding.do

    def test_uwsgi_installed(self, stage):
        stage.install("uWSGI", version="2.0.31")
        (finding,) = _check.findings()
        assert finding.what == "uWSGI 2.0.31 is installed."
        assert finding.do == "Start uWSGI with --py-sys-executable /path/to/python."

    def test_under_uwsgi_the_executable_is_what_counts(self, stage, monkeypatch):
        stage.install("uWSGI")
        monkeypatch.setattr(_core, "_SYS_EXECUTABLE_IS_PYTHON", False)
        (finding,) = _check.findings()
        assert finding.what.startswith("sys.executable is ")


class TestMultiprocessing:
    @pytest.mark.parametrize("version", [(3, 11), (3, 12), (3, 13)])
    def test_posix_before_3_14(self, stage, monkeypatch, version):
        monkeypatch.setattr(_check, "_PYTHON", version)
        (finding,) = _check.findings()
        assert finding.group == CHILD_PROCESSES
        assert "raise no audit event here" in finding.what

    def test_windows_before_3_14(self, stage, monkeypatch):
        monkeypatch.setattr(_check, "_POSIX", False)
        monkeypatch.setattr(_check, "_PYTHON", (3, 13))
        assert _check.findings() == []

    def test_forkserver_by_default(self, stage, monkeypatch):
        monkeypatch.setattr(_check, "_default_start_method", lambda: "forkserver")
        (finding,) = _check.findings()
        assert finding.what == "multiprocessing's default start method here is forkserver."
        assert finding.do == "Call activate() before the first pool or process is started."

    @pytest.mark.parametrize("method", ["fork", "spawn"])
    def test_other_start_methods(self, stage, monkeypatch, method):
        monkeypatch.setattr(_check, "_default_start_method", lambda: method)
        assert _check.findings() == []

    def test_the_default_is_read_without_fixing_it(self):
        fixed = multiprocessing.get_start_method(allow_none=True)
        method = _check._default_start_method()
        assert multiprocessing.get_start_method(allow_none=True) == fixed
        if sys.platform in ("win32", "darwin"):
            assert method == "spawn"
        elif sys.platform.startswith("linux"):
            assert method == ("forkserver" if sys.version_info >= (3, 14) else "fork")
        # multiprocessing's own answer (which may create a file in a test).
        assert method == multiprocessing.get_all_start_methods()[0]

    @staticmethod
    def platform(monkeypatch, *, posix=True, macos=False, python=(3, 14)):
        monkeypatch.setattr(_check, "_POSIX", posix)
        monkeypatch.setattr(_check, "_MACOS", macos)
        monkeypatch.setattr(_check, "_PYTHON", python)

    @staticmethod
    def creates_a_file():
        pytest.fail("from Python 3.14.9 this creates a file in the temporary directory here")

    @pytest.mark.parametrize("python", [(3, 14), (3, 15)])
    def test_forkserver_from_3_14(self, monkeypatch, python):
        self.platform(monkeypatch, python=python)
        monkeypatch.setattr(multiprocessing, "get_context", lambda method: method)
        monkeypatch.setattr(multiprocessing, "get_all_start_methods", self.creates_a_file)
        assert _check._default_start_method() == "forkserver"

    def test_spawn_where_forkserver_is_not_available(self, monkeypatch):
        def get_context(method):
            raise ValueError(f"{method} start method not available")

        self.platform(monkeypatch)
        monkeypatch.setattr(multiprocessing, "get_context", get_context)
        monkeypatch.setattr(multiprocessing, "get_all_start_methods", self.creates_a_file)
        assert _check._default_start_method() == "spawn"

    @pytest.mark.parametrize(
        ("posix", "macos", "python"),
        [(False, False, (3, 14)), (True, True, (3, 14)), (True, False, (3, 13))],
        ids=["windows", "macos", "posix-3.13"],
    )
    def test_elsewhere_multiprocessing_is_asked(self, monkeypatch, posix, macos, python):
        self.platform(monkeypatch, posix=posix, macos=macos, python=python)
        monkeypatch.setattr(multiprocessing, "get_all_start_methods", lambda: ["fork", "spawn"])
        assert _check._default_start_method() == "fork"

    def test_the_constants_are_this_interpreter(self):
        assert _check._POSIX is (os.name == "posix")
        assert _check._MACOS is (sys.platform == "darwin")
        assert sys.version_info[:2] == _check._PYTHON


# ── Interpreter ───────────────────────────────────────────────────────


class TestInterpreter:
    def test_free_threaded(self, stage, monkeypatch):
        monkeypatch.setattr(_check, "_FREE_THREADED", True)
        (finding,) = _check.findings()
        assert finding.group == INTERPRETER
        assert "re-enables the GIL" in finding.means

    def test_the_constant_is_the_build(self):
        assert _check._FREE_THREADED is bool(sysconfig.get_config_var("Py_GIL_DISABLED"))

    def test_no_c_extension(self, stage):
        stage.modules.discard("tethered._guardian")
        (finding,) = _check.findings()
        assert finding.group == INTERPRETER
        assert "activate(locked=True) raises RuntimeError" in finding.means


# ── The report ────────────────────────────────────────────────────────


class TestReport:
    def test_groups_in_order_with_their_findings(self, stage):
        stage.everything()
        found = _check.findings()
        assert [f.group for f in found] == sorted((f.group for f in found), key=_check.GROUPS.index)
        assert {f.group for f in found} == set(_check.GROUPS)
        text = _check.render(found, 80)
        headings = [line for line in text.splitlines() if line in _check.GROUPS]
        assert headings == list(_check.GROUPS)
        assert text.endswith(f"\n{len(found)} findings.\n")
        assert "That a library is installed, or even loaded" in " ".join(text.split())
        for finding in found:
            for link in finding.links:
                assert f"    See {link}\n" in text

    def test_lines_fit_the_width(self, stage):
        stage.everything()
        for line in _check.render(_check.findings(), 70).splitlines():
            if len(line) > 70:
                # An address, a path or one word too long for any line.
                assert line.startswith(("    See ", "Interpreter: ")) or " " not in line.strip()

    def test_one_finding(self):
        finding = Finding(INTERPRETER, "what", "means", "do", ("https://example.test/",))
        text = _check.render([finding], 80)
        assert "\nInterpreter\n\n  - what\n    means\n    What to do: do\n" in text
        assert text.endswith("\n1 finding.\n")

    def test_run_writes_the_report_and_counts(self):
        out = io.StringIO()
        count = _check.run(out)
        assert count == len(_check.findings())
        assert out.getvalue().endswith(f"{count} finding{'' if count == 1 else 's'}.\n")

    def test_what_the_stream_cannot_encode_is_escaped(self, monkeypatch):
        finding = Finding(INTERPRETER, "café", "m", "d", ())
        monkeypatch.setattr(_check, "findings", lambda: [finding])
        raw = io.BytesIO()
        out = io.TextIOWrapper(raw, encoding="ascii")
        assert _check.run(out) == 1
        out.flush()
        assert b"caf\\xe9" in raw.getvalue()


class TestTheLinksLeadToHeadings:
    """Every address a finding prints is a heading of the documentation site."""

    pytestmark = pytest.mark.skipif(
        not DOCS.is_dir(), reason="needs the repository's docs/ (not part of every source copy)"
    )

    @staticmethod
    def _anchors(page: Path) -> set[str]:
        """The anchors of a page's headings, made the way ``toc.slugify`` makes them."""
        anchors, fenced = set(), False
        for line in page.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("```"):
                fenced = not fenced
            elif not fenced and (match := re.match(r"#{1,6} (.*)", line)):
                text = re.sub(r"[^\w\- ]", "", match.group(1).replace("`", "").strip().lower())
                anchors.add(text.replace(" ", "-"))
        return anchors

    def _links(self, stage: Stage, monkeypatch: pytest.MonkeyPatch) -> set[str]:
        stage.everything()
        links = {link for f in _check.findings() for link in f.links}
        stage.hook.write_text("import another_package\n", encoding="utf-8")
        monkeypatch.setattr(_core, "_SYS_EXECUTABLE_IS_PYTHON", False)
        stage.modules.discard("tethered._guardian")
        links |= {link for f in _check.findings() for link in f.links}
        return links

    def test_every_link(self, stage, monkeypatch):
        links = self._links(stage, monkeypatch)
        assert len(links) > 10
        for link in links:
            match = re.fullmatch(r"https://tethered\.shcherbak\.ai/(\w+)/#([\w-]+)", link)
            assert match, link
            page = DOCS / f"{match.group(1)}.md"
            assert page.is_file(), link
            assert match.group(2) in self._anchors(page), link


# ── The command line ──────────────────────────────────────────────────


class TestCommandLine:
    def test_check(self, capsys):
        assert cli.main(["check"]) == 0
        out = capsys.readouterr().out
        assert out.startswith("tethered ")
        assert re.search(r"\n\d+ findings?\.\n\Z", out)

    @pytest.mark.parametrize("argv", [[], ["status"], ["check", "--json"], ["check", "x"]])
    def test_usage_errors(self, capsys, argv):
        with pytest.raises(SystemExit) as exit_info:
            cli.main(argv)
        assert exit_info.value.code == 2
        assert "usage: python -m tethered" in capsys.readouterr().err

    def test_help(self, capsys):
        with pytest.raises(SystemExit) as exit_info:
            cli.main(["check", "--help"])
        assert exit_info.value.code == 0
        assert "not what the application uses" in " ".join(capsys.readouterr().out.split())

    def test_run_as_a_module(self, capsys, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["python -m tethered", "check"])
        monkeypatch.delitem(sys.modules, "tethered.__main__", raising=False)
        with pytest.raises(SystemExit) as exit_info:
            runpy.run_module("tethered", run_name="__main__")
        assert exit_info.value.code == 0
        assert re.search(r"\n\d+ findings?\.\n\Z", capsys.readouterr().out)


# ── It changes nothing ────────────────────────────────────────────────

# Run in a child process: an audit hook that records what would be a change,
# installed before tethered is imported, and the command run as
# ``python -m tethered check`` runs it.  Prints its own result last, as JSON.
_RECORDER = r"""
import json, os, runpy, sys, sysconfig

WRITE = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
CHANGES = {
    "sys.addaudithook", "os.putenv", "os.unsetenv",
    "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.startfile",
    "os.fork", "os.forkpty", "_winapi.CreateProcess", "_posixsubprocess.fork_exec",
    "os.remove", "os.rename", "os.mkdir", "os.rmdir", "os.chmod", "os.chown", "os.truncate",
    "os.link", "os.symlink", "os.utime", "shutil.copyfile", "shutil.copymode",
    "shutil.copystat", "shutil.copytree", "shutil.move", "shutil.rmtree", "_winapi.CopyFile2",
}
events = []

def record(event, args):
    if event.startswith("socket.") or event in CHANGES:
        events.append(event)
    elif event == "open" and len(args) > 2 and isinstance(args[2], int) and args[2] & WRITE:
        events.append("open for writing: %r" % (args[0],))

sys.addaudithook(record)
before = set(sys.modules)
sys.argv = ["python -m tethered", "check"]
try:
    runpy.run_module("tethered", run_name="__main__", alter_sys=True)
except SystemExit as exit:
    status = exit.code
else:
    status = "no exit"

paths = sysconfig.get_paths()
stdlib = tuple(os.path.normcase(paths[k]) for k in ("stdlib", "platstdlib"))
site = tuple(os.path.normcase(paths[k]) for k in ("purelib", "platlib"))

def third_party(name):
    top = name.partition(".")[0]
    # (__mp_main__ is the name multiprocessing gives __main__.)
    if top in sys.stdlib_module_names or top in ("tethered", "__mp_main__"):
        return False
    path = os.path.normcase(getattr(sys.modules.get(name), "__file__", None) or "")
    return not (path.startswith(stdlib) and not path.startswith(site))

from tethered import _core

answers = []
sys.audit(_core._HOOK_PROBE_EVENT, answers)
guardian = sys.modules.get("tethered._guardian")
print(json.dumps({
    "status": status,
    "events": events,
    "third_party": sorted(n for n in set(sys.modules) - before if third_party(n)),
    "hook_answers": answers,
    "config": repr(_core._config),
    "hook_installed": _core._hook_installed,
    "guardian_active": bool(guardian is not None and guardian.is_active()),
    "policy_variable": _core._CHILD_POLICY_ENV in os.environ,
}))
"""


def _fake_site(directory: Path) -> Path:
    """Distributions and modules on a path of their own; importing a module fails the run."""
    for name, version, module in [
        ("uvloop", "0.23.0", "uvloop"),
        ("pycares", "5.1.0", "pycares"),
        ("dnspython", "2.9.0", "dns"),
        ("psycopg2-binary", "2.9.13", "psycopg2"),
    ]:
        info = directory / f"{name.replace('-', '_')}-{version}.dist-info"
        info.mkdir(parents=True)
        (info / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8"
        )
        package = directory / module
        package.mkdir()
        (package / "__init__.py").write_text(
            f"raise AssertionError('the check imported {module}')\n", encoding="utf-8"
        )
    return directory


def _child_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != _core._CHILD_POLICY_ENV}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.update(extra)
    return env


class TestItChangesNothing:
    def test_in_a_child_process(self, tmp_path):
        site = _fake_site(tmp_path / "fake-site")
        result = subprocess.run(
            [sys.executable, "-B", "-c", _RECORDER],
            capture_output=True,
            text=True,
            cwd=tmp_path,
            env=_child_env(PYTHONPATH=str(site)),
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        report, _, last = result.stdout.rstrip("\n").rpartition("\n")
        probe = json.loads(last)
        assert probe["status"] == 0
        assert probe["events"] == []
        assert probe["third_party"] == []
        assert probe["hook_answers"] == []
        assert probe["config"] == "None"
        assert probe["hook_installed"] is False
        assert probe["guardian_active"] is False
        assert probe["policy_variable"] is False
        for line in (
            "uvloop 0.23.0 is installed.",
            "pycares 5.1.0 is installed.",
            "dnspython 2.9.0 is installed.",
            "psycopg2-binary 2.9.13 is installed.",
        ):
            assert f"  - {line}\n" in report
        assert result.stderr == ""

    def test_the_command(self, tmp_path):
        result = subprocess.run(
            [sys.executable, "-m", "tethered", "check"],
            capture_output=True,
            text=True,
            cwd=tmp_path,
            env=_child_env(),
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        assert re.search(r"\n\d+ findings?\.\n\Z", result.stdout)
        assert result.stderr == ""

    def test_a_usage_error(self, tmp_path):
        result = subprocess.run(
            [sys.executable, "-m", "tethered"],
            capture_output=True,
            text=True,
            cwd=tmp_path,
            env=_child_env(),
            timeout=120,
        )
        assert result.returncode == 2
        assert "usage: python -m tethered" in result.stderr


# ── The shipped rows are the catalogue's ──────────────────────────────


@pytest.fixture(scope="module")
def catalog():
    """``tests_containers/suites/clients/catalog.py``, loaded by its path."""
    if not CATALOG.is_file():
        pytest.skip("needs the repository's tests_containers/ (not part of every source copy)")
    spec = importlib.util.spec_from_file_location("_tethered_clients_catalog", CATALOG)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses looks the module up by name while it builds the classes.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    return module


class TestTheShippedRowsAreTheCatalogues:
    """``_clients.ROWS`` is the catalogue's table without its enforced rows.

    The container suites measure each row again on every run; the check
    reports from the copy the package carries.  A row added, changed or
    removed in the catalogue fails here until the copy follows.
    """

    def test_the_rows(self, catalog):
        expected = [
            (variant.id, variant.title, variant.expect.verdict, variant.packages, variant.mechanism)
            for variant in catalog.TABLE.values()
            if variant.expect.verdict != catalog.ENFORCED
        ]
        assert [tuple(row) for row in _clients.ROWS] == expected

    def test_the_results(self, catalog):
        assert (_clients.NOT_SEEN, _clients.PARTLY, _clients.ALLOWED_REFUSED) == (
            catalog.NOT_SEEN,
            catalog.PARTLY,
            catalog.ALLOWED_REFUSED,
        )

    def test_the_ids_are_unique(self):
        assert len(ROWS) == len(_clients.ROWS)
