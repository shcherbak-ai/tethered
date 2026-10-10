"""Build the suite images and run the container suites.

    python tests_containers/run.py                       every suite on every Python
    python tests_containers/run.py --suite uvicorn --python 3.13 -k workers
    python tests_containers/run.py --list

Standard library only; needs Python 3.11+ and the ``docker`` command.  Each
suite is a directory under ``suites/``; for each selected suite and Python
version the runner builds an image (the build context is the repository root)
and runs it with ``--network none --cap-add NET_ADMIN``; pytest runs inside.
The exit status is 0 when every run passed, 1 when one did not, and 2 when
the request could not be carried out (no Docker, an unknown suite).
``tests_containers/README.md`` has the details.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SUITES_DIR = HERE / "suites"
IMAGES_DIR = HERE / "images"

#: The supported Python versions and the tag of the official image each one is
#: tested on (``python:<tag>`` to build tethered, ``python:<tag>-slim`` to run).
#: This is the only place that knows them.  3.15 is a release candidate until
#: it is released: change its tag to "3.15" then.
PYTHON_IMAGE_TAGS = {
    "3.11": "3.11",
    "3.12": "3.12",
    "3.13": "3.13",
    "3.14": "3.14",
    "3.15": "3.15-rc",
}

#: The last line of a container's output that starts with this carries the
#: result as JSON (written by ``harness/__main__.py``).
RESULT_MARKER = "TETHERED-CT-RESULT "
#: pytest's exit status when no test was collected or selected.
NO_TESTS = 5
_SUITE_KEYS = {"description", "image", "apt", "compiler", "key_packages", "unsupported_python"}
_print_lock = threading.Lock()


class UsageError(Exception):
    """The request cannot be carried out; the message goes to stderr and the exit status is 2."""


@dataclass(frozen=True)
class Suite:
    """One directory under ``suites/``, as its ``suite.toml`` describes it."""

    name: str
    description: str
    image: str
    apt: tuple[str, ...]
    compiler: bool
    key_packages: tuple[str, ...]
    unsupported_python: dict[str, str]

    def pythons(self) -> list[str]:
        """The supported Python versions this suite runs on."""
        return [version for version in PYTHON_IMAGE_TAGS if version not in self.unsupported_python]


@dataclass
class Run:
    """One suite on one Python version, and how it went."""

    suite: Suite
    python: str
    unpinned: bool = False
    status: str = "not run"
    ok: bool = False
    build_seconds: float = 0.0
    run_seconds: float = 0.0
    result: dict = field(default_factory=dict)
    image_id: str = ""
    build_output: str = ""
    test_output: str = ""

    @property
    def label(self) -> str:
        return f"{self.suite.name} / Python {self.python}"

    @property
    def image(self) -> str:
        """The tag of the image; an unpinned build does not replace the pinned one."""
        suffix = "-unpinned" if self.unpinned else ""
        return f"tethered-ct/{self.suite.name}:py{self.python}{suffix}"


def _requirement_names(path: Path) -> list[str]:
    names = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if match:
            names.append(match.group(1))
    return names


def load_suites() -> dict[str, Suite]:
    """Every suite, by name: the directories under ``suites/`` that have a ``suite.toml``."""
    suites = {}
    for path in sorted(SUITES_DIR.glob("*/suite.toml")):
        directory = path.parent
        name = directory.name
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
        problems = []
        unknown = sorted(set(data) - _SUITE_KEYS)
        if unknown:
            problems.append(f"unknown keys {unknown}")
        if not data.get("description"):
            problems.append("no description")
        image = data.get("image", "base")
        if not (IMAGES_DIR / f"{image}.Dockerfile").is_file():
            problems.append(f"images/{image}.Dockerfile does not exist")
        if not (directory / "requirements.txt").is_file():
            problems.append("no requirements.txt")
        if not list(directory.glob("test_*.py")):
            problems.append("no test_*.py")
        unsupported = data.get("unsupported_python", {})
        for version, reason in unsupported.items():
            if version not in PYTHON_IMAGE_TAGS:
                problems.append(f"unsupported_python names {version!r}, which is not tested at all")
            if not isinstance(reason, str) or not reason.strip():
                problems.append(f"unsupported_python gives no reason for {version}")
        if problems:
            raise UsageError(f"{path.relative_to(REPO)}: {'; '.join(problems)}")
        suites[name] = Suite(
            name=name,
            description=data["description"],
            image=image,
            apt=tuple(data.get("apt", ())),
            compiler=bool(data.get("compiler", False)),
            key_packages=tuple(
                data.get("key_packages") or _requirement_names(directory / "requirements.txt")
            ),
            unsupported_python=dict(unsupported),
        )
    if not suites:
        raise UsageError(f"no suite found under {SUITES_DIR.relative_to(REPO)}")
    return suites


def select(
    suites: dict[str, Suite], names: list[str], pythons: list[str], unpinned: bool = False
) -> list[Run]:
    """The runs a command line asks for, in suite and version order."""
    for name in names:
        if name not in suites:
            raise UsageError(f"no such suite: {name} (there are: {', '.join(suites)})")
    for version in pythons:
        if version not in PYTHON_IMAGE_TAGS:
            raise UsageError(
                f"Python {version} is not a supported version: {', '.join(PYTHON_IMAGE_TAGS)}"
            )
    runs = []
    for name in names or list(suites):
        for version in pythons or list(PYTHON_IMAGE_TAGS):
            runs.append(Run(suites[name], version, unpinned))
    return runs


def _say(text: str) -> None:
    with _print_lock:
        print(text, flush=True)


def _docker(arguments: list[str], timeout: float | None = None) -> tuple[int, str]:
    """Run one docker command from the repository root; returns its status and its output."""
    done = subprocess.run(
        ["docker", *arguments],
        cwd=REPO,
        env={**os.environ, "DOCKER_BUILDKIT": "1"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    return done.returncode, done.stdout.decode("utf-8", "replace")


def check_docker() -> None:
    """Raise ``UsageError`` unless the docker command can reach a daemon."""
    if shutil.which("docker") is None:
        raise UsageError(
            "Docker is not available: there is no 'docker' command on PATH. "
            "The container suites need Docker (Docker Desktop on Windows and macOS)."
        )
    try:
        status, output = _docker(["version", "--format", "{{.Server.Version}}"], timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise UsageError(f"Docker is not available: {error}") from error
    if status != 0:
        detail = (output.strip().splitlines() or ["no output"])[-1]
        raise UsageError(
            f"Docker is not available: the docker command cannot reach a daemon ({detail}). "
            "Start Docker and run this again."
        )


class Runner:
    """Builds and runs the selected combinations, a few at a time."""

    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options
        self.containers: set[str] = set()
        self.stamp = datetime.date.today().isoformat()

    def _build(self, run: Run) -> tuple[int, str]:
        suite = run.suite
        arguments = [
            "build",
            "--file",
            f"tests_containers/images/{suite.image}.Dockerfile",
            "--build-arg",
            f"PYTHON_TAG={PYTHON_IMAGE_TAGS[run.python]}",
            "--build-arg",
            f"SUITE={suite.name}",
            "--build-arg",
            f"APT_PACKAGES={' '.join(suite.apt)}",
            "--build-arg",
            f"COMPILER={int(suite.compiler)}",
            "--tag",
            run.image,
            "--progress",
            "plain",
        ]
        if self.options.unpinned:
            arguments += [
                "--build-arg",
                "UNPINNED=1",
                "--build-arg",
                f"UNPINNED_STAMP={self.stamp}",
            ]
        if self.options.no_cache:
            arguments.append("--no-cache")
        # The container is started from the image's id, not from its tag: another
        # checkout that builds the same suite at the same time moves the tag.
        with tempfile.TemporaryDirectory() as scratch:
            id_file = Path(scratch) / "image-id"
            status, output = _docker([*arguments, "--iidfile", str(id_file), "."])
            if status == 0:
                run.image_id = id_file.read_text(encoding="utf-8").strip()
        return status, f"$ docker {' '.join(arguments)} .\n{output}"

    def _test(self, run: Run) -> tuple[int | None, str]:
        name = f"tethered-ct-{run.suite.name}-py{run.python}-{os.getpid()}"
        pytest_arguments = list(self.options.pytest_arguments)
        if self.options.k:
            pytest_arguments = ["-k", self.options.k, *pytest_arguments]
        # No network at all; NET_ADMIN lets the harness add its addresses to "lo".
        arguments = ["run", "--rm", "--init", "--name", name, "--network", "none"]
        arguments += ["--cap-add", "NET_ADMIN", run.image_id or run.image, *pytest_arguments]
        self.containers.add(name)
        try:
            status, output = _docker(arguments, timeout=self.options.timeout)
        except subprocess.TimeoutExpired as expired:
            _docker(["kill", name])
            output = (expired.stdout or b"").decode("utf-8", "replace")
            output += f"\n[run.py] killed: no result within {self.options.timeout} s\n"
            status = None
        finally:
            self.containers.discard(name)
        return status, f"$ docker {' '.join(arguments)}\n{output}"

    def execute(self, run: Run) -> None:
        """Build the image of one run and run it; never raises for a failing run."""
        _say(f"  {run.label}: building {run.image}")
        started = time.monotonic()
        status, run.build_output = self._build(run)
        run.build_seconds = time.monotonic() - started
        if status != 0:
            run.status = "build failed"
        else:
            started = time.monotonic()
            exit_status, run.test_output = self._test(run)
            run.run_seconds = time.monotonic() - started
            markers = [
                line for line in run.test_output.splitlines() if line.startswith(RESULT_MARKER)
            ]
            if markers:
                run.result = json.loads(markers[-1][len(RESULT_MARKER) :])
            if exit_status is None:
                run.status = "timed out"
            elif not run.result:
                run.status = "no result"
            elif exit_status == 0:
                run.status, run.ok = "passed", True
            elif exit_status == NO_TESTS and self.options.k:
                run.status, run.ok = "no tests", True
            else:
                run.status = "failed"
        if self.options.logs:
            directory = Path(self.options.logs)
            directory.mkdir(parents=True, exist_ok=True)
            log = directory / f"{run.suite.name}-py{run.python}.log"
            log.write_text(f"{run.build_output}\n{run.test_output}", encoding="utf-8")
        counts = ", ".join(
            f"{run.result[key]} {key}"
            for key in ("passed", "failed", "error", "skipped")
            if run.result.get(key)
        )
        seconds = f"build {run.build_seconds:.0f} s, tests {run.run_seconds:.0f} s"
        lines = [f"  {run.label}: {run.status.upper()} ({counts or 'no counts'}; {seconds})"]
        # A failing run is shown in full, but not the build that went well before it.
        shown = []
        if self.options.verbose or run.status == "build failed":
            shown.append(run.build_output.rstrip())
        if self.options.verbose or not run.ok:
            shown.append(run.test_output.rstrip())
        if any(shown):
            lines += [f"----- output of {run.label} -----", *filter(None, shown), "-" * 70]
        _say("\n".join(lines))

    def run_all(self, runs: list[Run]) -> None:
        """Execute every run, ``--jobs`` at a time; Ctrl-C kills the running containers."""
        pool = ThreadPoolExecutor(max_workers=self.options.jobs)
        try:
            futures = [pool.submit(self.execute, run) for run in runs]
            for future in futures:
                future.result()
        except KeyboardInterrupt:
            pool.shutdown(wait=False, cancel_futures=True)
            for name in list(self.containers):
                _docker(["kill", name])
            raise
        finally:
            pool.shutdown(wait=True)


def _table(rows: list[list[str]], right: frozenset[int] = frozenset()) -> list[str]:
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]))]
    lines = []
    for index, row in enumerate(rows):
        cells = [
            cell.rjust(widths[column]) if column in right else cell.ljust(widths[column])
            for column, cell in enumerate(row)
        ]
        lines.append("  ".join(cells).rstrip())
        if index == 0:
            lines.append("  ".join("-" * width for width in widths))
    return lines


def summary(runs: list[Run], skipped: list[tuple[Suite, str]]) -> list[str]:
    """The table that ends a run: one line per suite and Python version."""
    counts = {"passed": "passed", "failed": "failed", "errors": "error", "skipped": "skipped"}
    rows = [["suite", "python", "result", *counts, "build", "tests", "versions"]]
    for run in runs:
        # The container reports every installed distribution by its normalised name.
        installed = run.result.get("versions", {})
        packages = [
            f"{name} {installed.get(re.sub(r'[-_.]+', '-', name).lower(), 'is not installed')}"
            for name in run.suite.key_packages
            if run.result
        ]
        rows.append(
            [
                run.suite.name,
                run.result.get("python", run.python),
                run.status,
                *(str(run.result.get(key, "-")) for key in counts.values()),
                f"{run.build_seconds:.0f} s",
                f"{run.run_seconds:.0f} s",
                ", ".join(packages),
            ]
        )
    lines = _table(rows, right=frozenset({3, 4, 5, 6, 7, 8}))
    for suite, version in skipped:
        lines.append(
            f"not run: {suite.name} on Python {version}: {suite.unsupported_python[version]}"
        )
    tethered = sorted({run.result["versions"]["tethered"] for run in runs if run.result})
    if tethered:
        lines.append(f"tethered {', '.join(tethered)}, built from the working tree")
    return lines


def list_suites(suites: dict[str, Suite], runs: list[Run], as_json: bool) -> None:
    """``--list``: what there is to run; with ``--json``, a matrix for GitHub Actions."""
    wanted = [run for run in runs if run.python in run.suite.pythons()]
    if as_json:
        if not wanted:
            raise UsageError("the selection is empty")
        print(
            json.dumps({"include": [{"suite": r.suite.name, "python": r.python} for r in wanted]})
        )
        return
    rows = [["suite", "python", "image", "description"]]
    for name in dict.fromkeys(run.suite.name for run in runs):
        versions = [run.python for run in wanted if run.suite.name == name]
        rows.append([name, " ".join(versions) or "-", suites[name].image, suites[name].description])
    print("\n".join(_table(rows)))
    for run in runs:
        if run not in wanted:
            reason = run.suite.unsupported_python[run.python]
            print(f"not run: {run.suite.name} on Python {run.python}: {reason}")


def parse(arguments: list[str]) -> argparse.Namespace:
    """The command line."""
    parser = argparse.ArgumentParser(
        prog="tests_containers/run.py",
        description="Run tethered's container suites: real servers, in Docker, with no network.",
        epilog="Arguments after '--' are passed to pytest in the container, e.g. '-- -x'.",
    )
    parser.add_argument(
        "--python",
        action="append",
        default=[],
        metavar="X.Y",
        help=f"a Python version, repeatable (default: {' '.join(PYTHON_IMAGE_TAGS)})",
    )
    parser.add_argument(
        "--suite", action="append", default=[], metavar="NAME", help="a suite, repeatable"
    )
    parser.add_argument("-k", metavar="EXPR", help="only the tests pytest's -k EXPR selects")
    parser.add_argument(
        "--jobs",
        type=int,
        default=max(1, min(4, (os.cpu_count() or 2) // 2)),
        metavar="N",
        help="how many suite and Python combinations run at once (default: %(default)s)",
    )
    parser.add_argument(
        "--unpinned",
        action="store_true",
        help="install the latest release of every requirement, not the pinned one",
    )
    parser.add_argument("--list", action="store_true", help="list the suites and stop")
    parser.add_argument(
        "--json", action="store_true", help="with --list: print a GitHub Actions matrix"
    )
    parser.add_argument("--logs", metavar="DIR", help="write the full output of every run there")
    parser.add_argument("--no-cache", action="store_true", help="build the images without cache")
    parser.add_argument(
        "--timeout",
        type=float,
        default=1800.0,
        metavar="SECONDS",
        help="kill a container that has not finished by then (default: %(default)s)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="print the output of passing runs too"
    )
    parser.add_argument("pytest_arguments", nargs="*", help=argparse.SUPPRESS)
    options = parser.parse_args(arguments)
    if options.json and not options.list:
        parser.error("--json goes with --list")
    if options.jobs < 1:
        parser.error("--jobs is at least 1")
    return options


def main(arguments: list[str]) -> int:
    """Run the command line; returns the exit status."""
    for stream in (sys.stdout, sys.stderr):
        # Container output is UTF-8; a Windows console may not be.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")
    options = parse(arguments)
    try:
        suites = load_suites()
        runs = select(suites, options.suite, options.python, options.unpinned)
        if options.list:
            list_suites(suites, runs, options.json)
            return 0
        skipped = [(r.suite, r.python) for r in runs if r.python not in r.suite.pythons()]
        runs = [run for run in runs if run.python in run.suite.pythons()]
        if not runs:
            raise UsageError("the selection is empty")
        check_docker()
    except UsageError as error:
        print(f"run.py: {error}", file=sys.stderr)
        return 2

    pins = "the latest release of every requirement" if options.unpinned else "pinned requirements"
    print(f"{len(runs)} run(s), {options.jobs} at a time, {pins}", flush=True)
    started = time.monotonic()
    try:
        Runner(options).run_all(runs)
    except KeyboardInterrupt:
        print("run.py: interrupted", file=sys.stderr)
        return 130
    lines = summary(runs, skipped)
    failed = [run for run in runs if not run.ok]
    verdict = f"{len(failed)} of {len(runs)} run(s) failed" if failed else f"all {len(runs)} passed"
    lines.append(f"{verdict} in {time.monotonic() - started:.0f} s")
    print("\n" + "\n".join(lines), flush=True)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write("```text\n" + "\n".join(lines) + "\n```\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
