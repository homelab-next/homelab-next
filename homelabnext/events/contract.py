# SPDX-License-Identifier: Apache-2.0
"""Discovery for the generated contract tests (checklist T-07, Q-05).

Every per-type schema under ``schemas/events/`` is an event type, every OCSF subset under
``schemas/ocsf/`` is a shared lake table.  The contract tests in ``tests/events/test_contracts.py``
and ``tests/lake/test_table_contracts.py`` are parametrized from these functions, so a new type or
table is covered the moment its schema lands; ``tools/contract_coverage.py`` fails the build when
one of them has no passing publisher and consumer test.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from homelabnext import paths

PREFIX = "homelabnext."


def events_dir() -> Path:
    return paths.schemas_dir() / "events"


def event_type_stems(directory: Path | None = None) -> list[str]:
    """``alert.created``, ``task.queued``, ... (every ``<stem>.schema.json`` but the envelope)."""
    d = directory or events_dir()
    return sorted(
        p.name.removesuffix(".schema.json")
        for p in d.glob("*.schema.json")
        if p.name != "envelope.schema.json"
    )


def event_type(stem: str) -> str:
    return PREFIX + stem


def _instances(stem: str, kind: str, directory: Path | None) -> list[Path]:
    d = (directory or events_dir()) / kind
    return sorted(p for p in d.glob(f"{stem}.*.json") if p.name.count(".") == stem.count(".") + 2)


def samples(stem: str, directory: Path | None = None) -> list[dict[str, Any]]:
    """The schema's examples: what a publisher of the type sends."""
    return [
        json.loads(p.read_text(encoding="utf-8")) for p in _instances(stem, "examples", directory)
    ]


def negatives(stem: str, directory: Path | None = None) -> list[tuple[str, Any]]:
    """``(file name, instance)`` for every negative of the type: what a consumer must refuse."""
    return [
        (p.name, json.loads(p.read_text(encoding="utf-8")))
        for p in _instances(stem, "negative", directory)
    ]


def data_required(stem: str, directory: Path | None = None) -> list[str]:
    """The ``data`` fields the type schema requires (each one's absence must be refused)."""
    doc = json.loads(((directory or events_dir()) / f"{stem}.schema.json").read_text("utf-8"))
    for part in doc.get("allOf", []):
        data = part.get("properties", {}).get("data", {})
        if "required" in data:
            return list(data["required"])
    return []


# ---------------------------------------------------------------- shared lake tables
def tables_dir() -> Path:
    return paths.schemas_dir() / "ocsf"


def table_names(directory: Path | None = None) -> list[str]:
    """Every shared table with a schema (``schemas/ocsf/<table>.v<major>.json``)."""
    d = directory or tables_dir()
    return sorted(p.name.split(".v", 1)[0] for p in d.glob("*.v*.json"))


def _table_instances(table: str, kind: str, directory: Path | None) -> list[Path]:
    d = (directory or tables_dir()) / kind
    return sorted(p for p in d.glob(f"{table}.v*.json") if p.name.split(".v", 1)[0] == table)


def table_schema_doc(table: str, directory: Path | None = None) -> dict[str, Any]:
    d = directory or tables_dir()
    (p,) = sorted(d.glob(f"{table}.v*.json"))
    return json.loads(p.read_text(encoding="utf-8"))


def table_samples(table: str, directory: Path | None = None) -> list[dict[str, Any]]:
    """The table's example rows: what a writer (publisher) of the table sends."""
    return [
        json.loads(p.read_text(encoding="utf-8"))
        for p in _table_instances(table, "examples", directory)
    ]


def table_negatives(table: str, directory: Path | None = None) -> list[tuple[str, Any]]:
    return [
        (p.name, json.loads(p.read_text(encoding="utf-8")))
        for p in _table_instances(table, "negative", directory)
    ]
