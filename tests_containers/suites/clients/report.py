"""The measured rows as a table and as JSON: what ``conftest.py`` prints after a run."""

from __future__ import annotations

import os
from dataclasses import asdict
from typing import Any

import measure

HEADER = (
    "library",
    "verdict",
    "forbidden name",
    "forbidden address",
    "allowed name",
    "allowed name, other port",
    "lookup event",
    "connect event",
    "forbidden name reached DNS",
    "the refusal reaches the caller",
    "under a locked policy",
    "mechanism",
    "version",
)


def _versions(row: measure.Row) -> str:
    return ", ".join(f"{name} {version}" for name, version in row.versions.items()) or "stdlib"


def _yes(flag: bool) -> str:
    return "yes" if flag else "no"


def table(rows: list[measure.Row]) -> list[str]:
    """One line per row, as a Markdown table."""
    lines = ["| " + " | ".join(HEADER) + " |", "|" + " --- |" * len(HEADER)]
    for row in rows:
        got = row.measured
        cells = [
            row.variant.title,
            got.verdict,
            got.forbidden_name,
            got.forbidden_address,
            got.allowed,
            got.other_port,
            _yes(got.lookup_event),
            _yes(got.connect_event),
            _yes(got.name_leaked),
            got.surface,
            measure.under_lock.get(row.variant.id, "not measured in this run"),
            row.variant.mechanism,
            _versions(row),
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def _attempt(batch: measure.Batch, case: str) -> dict[str, Any]:
    said = batch.reports[case]
    kept = ("outcome", "surface", "exception", "message", "chain", "seconds", "events")
    return {
        "arrived": batch.arrived(case),
        **{key: said[key] for key in kept if said.get(key) is not None},
    }


def details(rows: list[measure.Row]) -> dict[str, Any]:
    """Everything that was measured, by variant id."""
    return {
        row.variant.id: {
            "title": row.variant.title,
            "mechanism": row.variant.mechanism,
            "verdict": row.measured.verdict,
            "measured": asdict(row.measured),
            "under_a_locked_policy": measure.under_lock.get(row.variant.id),
            "problems": row.problems,
            "versions": row.versions,
            "notes": row.notes,
            "extensions": row.extensions,
            "dlopen": row.dlopen,
            "attempts": {case: _attempt(row.batch, case) for case in row.batch.reports},
            "arrivals": row.batch.arrivals,
            "dns": row.batch.dns,
        }
        for row in rows
    }


def evidence(rows: list[measure.Row]) -> list[str]:
    """Per row: the events the library raised without tethered, and what each attempt reported."""
    lines = []
    for row in rows:
        lines.append(f"{row.variant.id}: {_versions(row)}")
        lines.append(f"    mechanism: {row.variant.mechanism}")
        if row.notes:
            lines.append(f"    notes: {row.notes}")
        lines.append(f"    events without tethered, by name: {row.events}")
        lines.append(f"    extension modules loaded: {row.extensions}")
        if row.dlopen:
            lines.append(f"    ctypes.dlopen: {row.dlopen}")
        lines.append(f"    DNS queries: {row.batch.dns}")
        for case, said in row.batch.reports.items():
            arrived = "arrived" if row.batch.arrived(case) else "did not arrive"
            failure = ""
            if said["outcome"] != "completed":
                failure = f": {said['exception']}: {said['message'][:160]!r} chain={said['chain']}"
            lines.append(
                f"    {case}: {arrived}; {said['outcome']} in {said['seconds']} s{failure}"
            )
        if os.environ.get("CLIENTS_STDERR"):
            for case, text in row.batch.stderr.items():
                lines.append(f"    stderr, {case}:")
                lines += [f"        {line}" for line in text.splitlines()[-40:]]
    return lines
