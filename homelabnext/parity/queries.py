# SPDX-License-Identifier: Apache-2.0
"""Parity between two lake implementations: query results and whole tables.

Written against ``LakeQuery`` / ``LakeClient`` only, so it compares any two implementations:
the in-memory fake, DuckDB/Iceberg, Trino, a recorded cassette.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from homelabnext.lake.errors import LakeError

from .report import Check, ParityReport
from .rows import RowRules, Sample, diff_rows
from .schema import schema_drift

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")


@dataclass(frozen=True)
class ParityQuery:
    """One query to run on both sides. Give ``sql`` or ``named``, not both."""

    name: str
    sql: str | None = None
    named: str | None = None
    params: Mapping[str, Any] = field(default_factory=dict)
    rules: RowRules = field(default_factory=RowRules)
    min_rows: int = 0  # a parity pass on two empty results proves nothing

    def __post_init__(self) -> None:
        if bool(self.sql) == bool(self.named):
            raise ValueError(f"query {self.name!r}: give exactly one of sql / named")


def _run(client: Any, q: ParityQuery) -> list[dict[str, Any]]:
    if q.sql:
        return client.query(q.sql, q.params or None)
    return client.named(q.named, q.params or None)


def compare_queries(
    left: Any, right: Any, queries: Sequence[ParityQuery], *, kind: str = "query"
) -> ParityReport:
    report = ParityReport(kind, meta={"left_queries": len(queries)})
    for q in queries:
        try:
            lrows, rrows = _run(left, q), _run(right, q)
        except LakeError as exc:
            report.add(Check(f"query:{q.name}", False, f"query failed: {exc}", {"error": str(exc)}))
            continue
        d = diff_rows(lrows, rrows, q.rules)
        report.sampled = report.sampled or d.sampled
        ok = d.ok and d.left_count >= q.min_rows
        summary = d.summary() if d.ok is False else f"{d.left_count} rows identical"
        if d.ok and d.left_count < q.min_rows:
            summary = f"only {d.left_count} rows, need >= {q.min_rows} for a meaningful comparison"
        report.add(Check(f"query:{q.name}", ok, summary, d.to_dict()))
    return report


def compare_tables(
    left: Any,
    right: Any,
    tables: Sequence[str],
    *,
    sample: Sample | None = None,
    rules: Mapping[str, RowRules] | None = None,
    min_rows: int = 0,
) -> ParityReport:
    """Per table: schema drift, row count, then full (or sampled) content by the table key."""
    report = ParityReport("tables")
    rules = rules or {}
    for t in tables:
        if not _IDENT.match(t):
            raise ValueError(f"not a table identifier: {t!r}")
        try:
            li, ri = left.describe(t), right.describe(t)
        except LakeError as exc:
            report.add(Check(f"table:{t}:describe", False, f"describe failed: {exc}"))
            continue
        drift = schema_drift(li, ri)
        report.add(
            Check(
                f"table:{t}:schema",
                not drift,
                "schemas identical" if not drift else f"{len(drift)} schema differences",
                {"drift": [d.to_dict() for d in drift]},
            )
        )
        r = rules.get(t) or RowRules(key=tuple(li.key), sample=sample)
        try:
            lrows = left.query(f"SELECT * FROM {li.name}")
            rrows = right.query(f"SELECT * FROM {ri.name}")
        except LakeError as exc:
            report.add(Check(f"table:{t}:rows", False, f"read failed: {exc}"))
            continue
        d = diff_rows(lrows, rrows, r)
        report.sampled = report.sampled or d.sampled
        ok = d.ok and d.left_count >= min_rows
        summary = d.summary() if not d.ok else f"{d.left_count} rows identical"
        if d.ok and d.left_count < min_rows:
            summary = f"only {d.left_count} rows, need >= {min_rows}"
        report.add(Check(f"table:{t}:rows", ok, summary, d.to_dict()))
    return report
