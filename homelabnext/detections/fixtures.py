# SPDX-License-Identifier: Apache-2.0
"""Fixture schema (homelabnext.detections.fixture/v1) and loader.

Layout: ``fixtures/<slug>/{must_fire,must_not_fire,evasion}/*.json``.
Each file is one synthetic event wrapped in metadata. Evasion fixtures are
*known-hard variants*: the runner reports whether the rule caught them but a
miss never fails the run (it is a documented gap, not a regression).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

SCHEMA_ID = "homelabnext.detections.fixture/v1"
KINDS = ("must_fire", "must_not_fire", "evasion")


class FixtureError(ValueError):
    pass


@dataclass(frozen=True)
class Fixture:
    slug: str
    kind: str
    name: str
    path: Path
    description: str
    event: dict
    note: str = ""


def validate_fixture_doc(doc: object, kind: str, where: str) -> None:
    if not isinstance(doc, dict):
        raise FixtureError(f"{where}: fixture must be a JSON object")
    allowed = {"schema", "spdx", "name", "description", "event", "note"}
    extra = set(doc) - allowed
    if extra:
        raise FixtureError(f"{where}: unknown keys {sorted(extra)}")
    if doc.get("schema") != SCHEMA_ID:
        raise FixtureError(f"{where}: schema must be {SCHEMA_ID!r}")
    for k in ("name", "description"):
        if not isinstance(doc.get(k), str) or not doc[k].strip():
            raise FixtureError(f"{where}: {k!r} must be a non-empty string")
    if not isinstance(doc.get("event"), dict) or not doc["event"]:
        raise FixtureError(f"{where}: 'event' must be a non-empty object")
    if kind == "evasion" and not (isinstance(doc.get("note"), str) and doc["note"].strip()):
        raise FixtureError(f"{where}: evasion fixtures need a 'note' saying what is evaded")


def load_fixtures(root: Path, slug: str) -> list[Fixture]:
    base = Path(root, "fixtures", slug)
    out: list[Fixture] = []
    if not base.is_dir():
        return out
    for kind_dir in sorted(p for p in base.iterdir() if p.is_dir()):
        if kind_dir.name not in KINDS:
            raise FixtureError(f"{kind_dir}: unknown fixture kind (allowed: {KINDS})")
        for f in sorted(kind_dir.glob("*.json")):
            try:
                doc = json.loads(f.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise FixtureError(f"{f}: invalid JSON: {exc}") from exc
            validate_fixture_doc(doc, kind_dir.name, str(f))
            out.append(
                Fixture(
                    slug,
                    kind_dir.name,
                    doc["name"],
                    f,
                    doc["description"],
                    doc["event"],
                    doc.get("note", ""),
                )
            )
    return out
