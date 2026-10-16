# SPDX-License-Identifier: Apache-2.0
"""Two seeded fake lakes and helpers that inject drift into the second one."""

from __future__ import annotations

import copy
from dataclasses import replace
from typing import Any

import synthetic

from homelabnext.lake import FakeLake, load_schemas

TABLES = ("authentication", "dns_activity")


def rows_for(table: str) -> list[dict[str, Any]]:
    return copy.deepcopy(getattr(synthetic, table)())


def seeded(rows: dict[str, list[dict[str, Any]]] | None = None, schemas=None) -> FakeLake:
    lake = FakeLake(schemas)
    for t in TABLES:
        data = (rows or {}).get(t) or rows_for(t)
        if schemas is not None:
            cols = set(schemas[t].column_names)
            data = [{k: v for k, v in r.items() if k in cols} for r in data]
        lake.write_batch(t, data, idempotency_key=f"seed-{t}")
    return lake


def pair() -> tuple[FakeLake, FakeLake]:
    return seeded(), seeded()


def schemas_without_column(table: str, column: str):
    schemas = load_schemas()
    s = schemas[table]
    schemas[table] = replace(s, columns=tuple(c for c in s.columns if c.name != column))
    return schemas
