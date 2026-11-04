# SPDX-License-Identifier: Apache-2.0
"""The novelty spec (ADR-0035 decision 2): what is learned, declared rather than inferred.

:func:`load_spec` reads a spec file (YAML or JSON), validates it against
``schemas/platform/novelty_spec.schema.json`` and then checks what the schema cannot state
against the lake's table schemas (:func:`check_spec`): the table exists, the entity and every
value is a scalar column path of it that is not a timestamp, every ``where`` key is such a
column path and its value has the column's type, ``time_column`` is a timestamp, profile ids are unique and ``min_history_days`` is
at most ``learn_days``.  A spec that fails any of these raises :class:`SpecError` naming every
problem; nothing is half-loaded.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from homelabnext.lake.ceiling import KEY_TYPES
from homelabnext.lake.tables import TableSchema, iter_columns

__all__ = ["Profile", "Spec", "SpecError", "check_spec", "digest", "load_spec", "parse_spec"]


class SpecError(ValueError):
    """A novelty spec that does not validate; the message names every problem."""


def digest(doc: Any) -> str:
    """``sha256:<hex>`` of ``doc`` as canonical JSON (sorted keys, no spaces)."""
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Profile:
    """One profile with its defaults applied (``time_column`` ``time``, ``where`` empty,
    ``min_history_days`` = ``learn_days``).  ``digest`` covers every field, so a finding names
    the exact parameters that produced it."""

    id: str
    table: str
    entity_kind: str
    entity: str
    values: tuple[str, ...]
    where: Mapping[str, Any]
    time_column: str
    learn_days: int
    half_life_days: float
    score_hours: int
    min_support: float
    entity_min_samples: float
    max_values_per_entity: int
    emit_at: float
    max_findings: int
    min_history_days: int
    description: str = ""

    @property
    def digest(self) -> str:
        return digest(self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "table": self.table,
            "entity_kind": self.entity_kind,
            "entity": self.entity,
            "values": list(self.values),
            "where": dict(self.where),
            "time_column": self.time_column,
            "learn_days": self.learn_days,
            "half_life_days": self.half_life_days,
            "score_hours": self.score_hours,
            "min_support": self.min_support,
            "entity_min_samples": self.entity_min_samples,
            "max_values_per_entity": self.max_values_per_entity,
            "emit_at": self.emit_at,
            "max_findings": self.max_findings,
            "min_history_days": self.min_history_days,
        }


@dataclass(frozen=True)
class Spec:
    profiles: tuple[Profile, ...]
    digest: str
    description: str = ""


def _profile(p: Mapping[str, Any]) -> Profile:
    return Profile(
        id=p["id"],
        table=p["table"],
        entity_kind=p["entity_kind"],
        entity=p["entity"],
        values=tuple(p["values"]),
        where=dict(p.get("where") or {}),
        time_column=p.get("time_column", "time"),
        learn_days=p["learn_days"],
        half_life_days=p["half_life_days"],
        score_hours=p["score_hours"],
        min_support=p["min_support"],
        entity_min_samples=p["entity_min_samples"],
        max_values_per_entity=p["max_values_per_entity"],
        emit_at=p["emit_at"],
        max_findings=p["max_findings"],
        min_history_days=p.get("min_history_days", p["learn_days"]),
        description=p.get("description", ""),
    )


def _column_problems(p: Profile, table: TableSchema) -> list[str]:
    cols = dict(iter_columns(table.columns))
    out: list[str] = []

    def want(path: str, types: tuple[str, ...], what: str) -> None:
        col = cols.get(path)
        if col is None:
            out.append(f"profile {p.id}: {what} {path!r} is not a column of {table.name}")
        elif col.type not in types:
            out.append(f"profile {p.id}: {what} {path!r} is a {col.type}")

    want(p.entity, KEY_TYPES, "entity")
    for v in p.values:
        want(v, KEY_TYPES, "value")
    if p.entity in p.values:
        out.append(f"profile {p.id}: the entity {p.entity!r} is also a value")
    for w, value in p.where.items():
        want(w, KEY_TYPES, "where column")
        col = cols.get(w)
        if col is not None and col.type in KEY_TYPES and not _fits(value, col.type):
            out.append(
                f"profile {p.id}: where {w!r} = {value!r} is not a {col.type} (it would match nothing)"
            )
    want(p.time_column, ("timestamp",), "time_column")
    return out


def _fits(value: Any, column_type: str) -> bool:
    if column_type == "boolean":
        return type(value) is bool
    if column_type == "long":
        return type(value) is int
    if column_type == "double":
        return type(value) in (int, float)
    return type(value) is str


def check_spec(spec: Spec, schemas: Mapping[str, TableSchema]) -> list[str]:
    """The problems of ``spec`` against the lake's table ``schemas`` (empty: none)."""
    problems: list[str] = []
    seen: set[str] = set()
    for p in spec.profiles:
        if p.id in seen:
            problems.append(f"profile {p.id}: listed twice")
        seen.add(p.id)
        if p.min_history_days > p.learn_days:
            problems.append(
                f"profile {p.id}: min_history_days {p.min_history_days} > learn_days "
                f"{p.learn_days} (the learning window cannot hold that much history)"
            )
        table = schemas.get(p.table)
        if table is None:
            problems.append(f"profile {p.id}: unknown table {p.table!r}")
            continue
        problems += _column_problems(p, table)
    return problems


def parse_spec(doc: Any, schemas: Mapping[str, TableSchema]) -> Spec:
    """A :class:`Spec` from a parsed document: schema-valid and checked against ``schemas``."""
    from homelabnext.schema_registry import validator

    errors = sorted(
        validator("platform", "novelty_spec.schema.json").iter_errors(doc),
        key=lambda e: list(e.absolute_path),
    )
    if errors:
        where = ["/".join(map(str, e.absolute_path)) or "(root)" for e in errors]
        raise SpecError(
            "novelty spec: "
            + "; ".join(f"{w}: {e.message}" for w, e in zip(where, errors, strict=True))
        )
    spec = Spec(
        tuple(_profile(p) for p in doc["profiles"]), digest(doc), doc.get("description", "")
    )
    problems = check_spec(spec, schemas)
    if problems:
        raise SpecError("novelty spec: " + "; ".join(problems))
    return spec


def load_spec(path: str | Path, schemas: Mapping[str, TableSchema]) -> Spec:
    """Read, validate and check the spec at ``path`` (``.json``, or YAML with unique keys)."""
    p = Path(path)
    if p.suffix == ".json":
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise SpecError(f"cannot read {p}: {exc}") from exc
    else:
        from homelabnext._yaml import load_unique

        doc = load_unique(p, SpecError)
    return parse_spec(doc, schemas)
