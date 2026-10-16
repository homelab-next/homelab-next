# SPDX-License-Identifier: Apache-2.0
"""Recorded query results ("cassettes") and a client that replays them.

A cassette is a JSON file of ``{name, sql, params, rows}`` entries recorded from a reference
engine. :class:`CassetteLake` answers only the recorded questions, so a consumer test needs no
engine at all, and :func:`compare` is the parity primitive: run the same queries on any
:class:`LakeQuery` and report every difference (the swap kit uses the same shape).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .base import AdapterBase, normalize_rows
from .errors import CassetteMiss, LakeError, WriteNotSupported
from .protocol import LakeQuery, TableInfo, WriteResult

CASSETTE_VERSION = 1


def _sig(sql: str, params: Mapping[str, Any] | None) -> str:
    return json.dumps([" ".join(sql.split()), dict(params or {})], sort_keys=True, default=str)


@dataclass(frozen=True)
class Recording:
    name: str
    sql: str
    params: Mapping[str, Any]
    rows: list[dict[str, Any]]


def record(client: LakeQuery, queries: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Run ``queries`` (each ``{name, sql, params?}``) and return a cassette document."""
    out = []
    for q in queries:
        rows = normalize_rows(client.query(q["sql"], q.get("params")))
        out.append(
            {"name": q["name"], "sql": q["sql"], "params": q.get("params", {}), "rows": rows}
        )
    return {"version": CASSETTE_VERSION, "recordings": out}


def dump(doc: Mapping[str, Any]) -> str:
    return json.dumps(doc, indent=1, sort_keys=False) + "\n"


class CassetteLake(AdapterBase):
    """Read-only replay client. Unknown queries raise :class:`CassetteMiss`."""

    def __init__(self, doc: Mapping[str, Any]):
        if doc.get("version") != CASSETTE_VERSION:
            raise LakeError("unsupported cassette version")
        self._rec = {
            _sig(r["sql"], r.get("params")): Recording(
                r["name"], r["sql"], r.get("params", {}), r["rows"]
            )
            for r in doc["recordings"]
        }
        self._named = {r.name: r.sql for r in self._rec.values()}

    @classmethod
    def load(cls, path: str | Path) -> CassetteLake:
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def query(self, sql: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        try:
            return json.loads(json.dumps(self._rec[_sig(sql, params)].rows))
        except KeyError:
            raise CassetteMiss(f"no recording for query: {' '.join(sql.split())[:120]}") from None

    def list_tables(self) -> list[str]:
        return []

    def describe(self, table: str) -> TableInfo:
        raise CassetteMiss("a cassette records query results, not tables")

    def write_batch(
        self,
        table: str,
        rows: Sequence[Mapping[str, Any]],
        *,
        idempotency_key: str,
        source: str | None = None,
        high_water: str | None = None,
    ) -> WriteResult:
        raise WriteNotSupported("cassettes are read-only")


def compare(
    reference_doc: Mapping[str, Any],
    client: LakeQuery,
    *,
    ordered_names: Sequence[str] | None = None,
) -> list[str]:
    """Replay every recording against ``client``; return human-readable differences."""
    diffs = []
    for r in reference_doc["recordings"]:
        if ordered_names is not None and r["name"] not in ordered_names:
            continue
        try:
            got = normalize_rows(client.query(r["sql"], r.get("params")))
        except LakeError as e:
            diffs.append(f"{r['name']}: query failed: {e}")
            continue
        if got != r["rows"]:
            diffs.append(
                f"{r['name']}: expected {r['rows'][:3]}... got {got[:3]}... ({len(r['rows'])} vs {len(got)} rows)"
            )
    return diffs
