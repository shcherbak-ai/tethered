"""Checks that new releases are held back for a week, and that no version tethered
installs has an advisory.

A release enters ``uv.lock`` and ``package-lock.json`` only a week after its upload
(``COOLDOWN_DAYS``), when a compromised one has been found and removed: a release of
litellm that stole credentials was on PyPI for two hours on 2026-10-21.  uv takes the
cutoff from ``[tool.uv] exclude-newer`` of ``pyproject.toml``, and applies it to the
build requirements of ``uv build`` and ``uv sync`` as well; npm takes it from
``min-release-age`` of ``.npmrc``.  The check fails when either is missing or is another
span.

``[tool.uv] exclude-newer-package`` lets a security fix in before its week is up, by
decision of the maintainer.  Each entry is a date, just after the upload of the fix, and
names a package of ``uv.lock``.  Once the week has passed the span admits the same, and
the entry would hold the package back from then on: the check then fails until it is
removed, and warns of it until then.

It asks osv.dev for the advisories of each version that ``uv.lock``,
``package-lock.json`` and ``.github/docs-constraints.txt`` hold, and fails on a known
vulnerability or a report of a malicious package, but for the advisories of
``ACCEPTED_ADVISORIES``, with their reasons.  An advisory whose fix is younger than the
cooldown is accepted until the cooldown admits the fix, as tethered has no check that
says when a newer release is admitted: the check fails from then on, until the package
is upgraded.  A report of a malicious package (``MAL-``) is never accepted, and an
accepted advisory of no version fails the check.  The pins of
the images (``IMAGE_REQUIREMENTS``) are checked for reports of malicious packages only:
they are installed with a network, but run in containers without one, where a known
vulnerability has nothing to reach.

Runs as a pre-commit hook at each commit, as an advisory can come out between two
commits.  CI skips it, where its result would depend on the day rather than on the
commit.  Offline, commit with ``SKIP=advisories git commit``.

    uv run python scripts/check_advisories.py
"""

from __future__ import annotations

import datetime
import json
import re
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# How many days a release stays out of the lockfiles after its upload:
# `[tool.uv] exclude-newer` of pyproject.toml and `min-release-age` of .npmrc
COOLDOWN_DAYS = 7

_MARKDOWNLINT_CLI2_0_24 = (
    "markdown-it and smol-toml, which markdownlint-cli2 0.23.3 pins: fixed in "
    "markdownlint-cli2 0.24.0, uploaded on 2026-10-21, which the cooldown admits from "
    "2026-10-28; at worst a slow lint of a Markdown file"
)

_VIRTUALENV_21_14_9 = (
    "virtualenv 21.14.7, of pre-commit: fixed in 21.14.9, uploaded on 2026-10-17, which "
    "the cooldown admits from 2026-10-24; every hook is a `language: system` one, for "
    "which pre-commit creates no virtualenv"
)

# The advisories that the check accepts, by their IDs at osv.dev: the reason, and the
# time (UTC) from which the acceptance runs out, or None.  A vulnerability that no
# version the ranges admit fixes, or whose fix is younger than the cooldown: then the
# time the cooldown admits the fix, from which the check fails until it is upgraded.
# A report of a malicious package (MAL-) is never accepted.
ACCEPTED_ADVISORIES: dict[str, tuple[str, str | None]] = {
    **{
        advisory: (_MARKDOWNLINT_CLI2_0_24, "2026-10-28T07:00:00Z")
        for advisory in (
            "GHSA-gfr2-rv44-r23c",
            "GHSA-r4xh-jqrq-34v2",
            "GHSA-r7fv-28h4-cvq7",
            "GHSA-vfgh-jcmw-g37q",
        )
    },
    **{
        advisory: (_VIRTUALENV_21_14_9, "2026-10-24T16:10:00Z")
        for advisory in (
            "GHSA-43mp-35q3-x3fq",
            "GHSA-c978-59m8-c77v",
            "GHSA-cw65-gx24-rc82",
        )
    },
    "GHSA-238p-pmpm-9mq7": (
        "katex 0.16, which markdownlint's math parser allows (^0.16): fixed in 0.18 only; "
        "markdownlint parses math and renders none",
        None,
    ),
    "GHSA-vfj7-8cjw-p6xm": (
        "braces 3.0.3, of micromatch, of markdownlint-cli2: no release fixes it; a stack "
        "overflow on a deeply nested glob, and the globs are the project's own",
        None,
    ),
}

# The pins that tethered installs on its own machines and in CI, all advisories counted
PINNED = (".github/docs-constraints.txt",)

# The pins of the images, below these directories: reports of malicious packages only
IMAGE_REQUIREMENTS = ("tests_containers", "benchmarks/dns_lookups")

# The batch query of osv.dev, for the advisories of many versions at once
_OSV_QUERY_BATCH = "https://api.osv.dev/v1/querybatch"
_OSV_BATCH_LIMIT = 1000

# A pinned requirement, e.g. `uvicorn[standard]==0.38.0`: its name and version
_PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s;#]+)")

# A version of a package, as osv.dev is asked about it: ecosystem, name, version
_Version = tuple[str, str, str]


class _CheckError(Exception):
    """The check cannot run: a file cannot be read, or osv.dev cannot be asked."""


def _normalize(name: str) -> str:
    """The name of a Python package as PyPI compares names (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _date(value: object) -> datetime.datetime | None:
    """The time of a date or a timestamp of uv's settings, in UTC; None for anything else."""
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=datetime.UTC)


def _cooldown(
    pyproject: dict, locked: set[str], now: datetime.datetime
) -> tuple[list[str], list[str]]:
    """What fails the check in the cooldown's settings, and what it warns of."""
    span = f"{COOLDOWN_DAYS} days"
    week = datetime.timedelta(days=COOLDOWN_DAYS)
    findings = []
    warnings = []
    uv = pyproject.get("tool", {}).get("uv", {})
    cutoff = uv.get("exclude-newer")
    if cutoff != span:
        now_set = "is missing" if cutoff is None else f"is {json.dumps(cutoff)}"
        findings.append(f'pyproject.toml: [tool.uv] exclude-newer {now_set}: set it to "{span}"')
    for name, value in sorted(uv.get("exclude-newer-package", {}).items()):
        entry = f"pyproject.toml: [tool.uv] exclude-newer-package {name} = {json.dumps(value)}"
        until = _date(value)
        if until is None:
            findings.append(f"{entry}: an exception is a date, just after the upload of the fix")
        elif _normalize(name) not in locked:
            findings.append(f"{entry}: names no package of uv.lock, remove it")
        elif now - week >= until:
            findings.append(f"{entry}: the {span} have passed, remove it")
        else:
            warnings.append(f"{entry}: remove it from {until + week:%Y-%m-%d %H:%M} UTC")
    npmrc = ROOT / ".npmrc"
    text = npmrc.read_text(encoding="utf-8") if npmrc.is_file() else ""
    match = re.search(r"^\s*min-release-age\s*=\s*(\d+)\s*$", text, re.MULTILINE)
    if match is None or int(match[1]) != COOLDOWN_DAYS:
        findings.append(f".npmrc: set min-release-age={COOLDOWN_DAYS}")
    return findings, warnings


def _pins(path: Path) -> set[_Version]:
    """The pinned versions of a requirements or constraints file."""
    pins = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _PIN.match(line.strip())
        if match:
            pins.add(("PyPI", match[1], match[2]))
    return pins


def _versions(lock: dict) -> tuple[set[_Version], set[_Version]]:
    """The versions whose advisories all count, and the pins of the images."""
    versions = {
        ("PyPI", package["name"], package["version"])
        for package in lock["package"]
        if "registry" in package.get("source", {})
    }
    npm_lock = ROOT / "package-lock.json"
    if npm_lock.is_file():
        entries = json.loads(npm_lock.read_text(encoding="utf-8"))["packages"]
        versions |= {
            ("npm", path.rsplit("node_modules/", 1)[-1], entry["version"])
            for path, entry in entries.items()
            if path and "version" in entry and not entry.get("link")
        }
    for name in PINNED:
        versions |= _pins(ROOT / name)
    images = set()
    for directory in IMAGE_REQUIREMENTS:
        for path in sorted((ROOT / directory).rglob("requirements.txt")):
            images |= _pins(path)
    return versions, images - versions


def _advisories(versions: list[_Version]) -> list[tuple[list[str], bool]]:
    """Ask osv.dev for the advisories of each version: their IDs, and whether there are more."""
    results = []
    for start in range(0, len(versions), _OSV_BATCH_LIMIT):
        queries = [
            {"package": {"ecosystem": ecosystem, "name": name}, "version": version}
            for ecosystem, name, version in versions[start : start + _OSV_BATCH_LIMIT]
        ]
        request = urllib.request.Request(
            _OSV_QUERY_BATCH,
            data=json.dumps({"queries": queries}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            # A fixed https URL of osv.dev, not one that comes from the files
            with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310
                answers = json.load(response)["results"]
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as error:
            raise _CheckError(f"Cannot ask osv.dev for advisories: {error}") from None
        if len(answers) != len(queries):
            raise _CheckError("osv.dev did not answer for each version.")
        # osv.dev sends the advisories of a version in pages
        results += [
            ([vuln["id"] for vuln in answer.get("vulns", [])], bool(answer.get("next_page_token")))
            for answer in answers
        ]
    return results


def main() -> int:
    """Check the cooldown's settings and the advisories; 0 when both pass, else 1."""
    now = datetime.datetime.now(datetime.UTC)
    try:
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
        locked = {_normalize(package["name"]) for package in lock["package"]}
        cooldown, warnings = _cooldown(pyproject, locked, now)
        versions, images = _versions(lock)
        asked = sorted(versions) + sorted(images)
        results = _advisories(asked)
    except (_CheckError, OSError, KeyError, tomllib.TOMLDecodeError) as error:
        print(error)
        print("Offline, commit without the check: SKIP=advisories git commit")
        return 1

    expired = {
        advisory: until
        for advisory, (_, until) in ACCEPTED_ADVISORIES.items()
        if until is not None and now >= (_date(until) or now)
    }
    advisories = []
    malicious = []
    seen: set[str] = set()
    for (ecosystem, name, version), (ids, more) in zip(asked, results, strict=True):
        if (ecosystem, name, version) in images:
            listed = [advisory for advisory in ids if advisory.startswith("MAL-")]
            if listed:
                malicious.append(f"{name} {version} ({ecosystem}): {', '.join(listed)}")
            continue
        seen.update(ids)
        listed = [
            f"{advisory} (accepted until {expired[advisory]})" if advisory in expired else advisory
            for advisory in ids
            if advisory.startswith("MAL-")
            or advisory not in ACCEPTED_ADVISORIES
            or advisory in expired
        ]
        if more:
            listed.append("and more, at osv.dev")
        if listed:
            advisories.append(f"{name} {version} ({ecosystem}): {', '.join(listed)}")

    findings = {
        f"The cooldown: a release enters the lockfiles {COOLDOWN_DAYS} days after its upload": (
            cooldown
        ),
        "Advisories of uv.lock, package-lock.json and the pins (osv.dev)": advisories,
        "Reports of malicious packages among the pins of the images (osv.dev)": malicious,
        "ACCEPTED_ADVISORIES: advisories of no version, to remove": sorted(
            ACCEPTED_ADVISORIES.keys() - seen
        ),
    }
    for title, lines in findings.items():
        if lines:
            print(title)
            for line in lines:
                print(f"  {line}")
            print()
    for line in warnings:
        print(f"Warning: {line}")
        print()
    if advisories:
        print(
            "An advisory: upgrade past it, or accept it in ACCEPTED_ADVISORIES with the reason, "
            "where no version that the ranges admit fixes it.  A fix younger than the cooldown "
            "goes in through [tool.uv] exclude-newer-package, by decision of the maintainer."
        )
        print()
    if any("MAL-" in line for line in advisories + malicious):
        print(
            "A malicious package (MAL-): remove it, and treat each machine that installed it as "
            "compromised: rotate every credential it could reach."
        )
        print()
    if any(findings.values()):
        print("To commit without the check: SKIP=advisories git commit")
        return 1
    print(
        f"New releases are held back for {COOLDOWN_DAYS} days, no version of uv.lock, "
        "package-lock.json or the pins has an advisory"
        + (", but for those accepted" if ACCEPTED_ADVISORIES else "")
        + ", and no pin of the images is a malicious package."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
