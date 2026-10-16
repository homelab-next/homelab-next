# SPDX-License-Identifier: Apache-2.0
"""Behaviour shared by every adapter: named queries, the ``write`` alias, result normalisation."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from .errors import LakeError
from .protocol import WriteResult

_TS_TEXT = re.compile(r"^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:?\d\d)?$")


def normalize_value(v: Any) -> Any:
    """Canonical JSON-able form used to compare results across engines and in cassettes."""
    if isinstance(v, datetime):
        v = v.replace(tzinfo=UTC) if v.tzinfo is None else v.astimezone(UTC)
        text = v.strftime("%Y-%m-%dT%H:%M:%S")
        if v.microsecond:
            text += f".{v.microsecond:06d}"
        return text + "Z"
    if isinstance(v, date):
        return v.isoformat()
    if isinstance(v, str) and _TS_TEXT.match(v):
        s = v.replace(" ", "T")
        if not re.search(r"(Z|[+-]\d\d:?\d\d)$", s):
            s += "+00:00"
        return normalize_value(datetime.fromisoformat(s))
    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, float):
        return round(v, 9)
    if isinstance(v, Mapping):
        return {k: normalize_value(x) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [normalize_value(x) for x in v]
    return v


def normalize_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [{k: normalize_value(v) for k, v in r.items()} for r in rows]


class AdapterBase:
    """Mixin: needs ``query`` and ``write_batch``."""

    _named: Mapping[str, str]

    def named(self, name: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        try:
            sql = self._named[name]
        except (AttributeError, KeyError):
            raise LakeError(f"no named query {name!r}") from None
        return self.query(sql, params)  # type: ignore[attr-defined]

    def write(self, table: str, rows: Sequence[Mapping[str, Any]], *, batch_id: str) -> int:
        """``LakeWriter`` alias for :meth:`write_batch`; returns rows actually written."""
        res: WriteResult = self.write_batch(table, rows, idempotency_key=batch_id)  # type: ignore[attr-defined]
        return res.rows_written
