# SPDX-License-Identifier: Apache-2.0
"""Row-set comparison: the primitive under query, table and event parity.

Both sides are first normalised with the lake library's ``normalize_value`` (timestamps to UTC
text, decimals to floats, floats rounded to nine places), then compared under explicit rules:

* **identity**: with ``key`` columns rows are paired by key and compared column by column;
  without a key the comparison is an exact multiset of whole rows.
* **ordering**: unordered by default; ``ordered=True`` also requires the same sequence, and
  ``order_by`` sorts both sides on those columns first (the common case of a query with no
  ``ORDER BY`` whose engines return different physical order).
* **tolerances**: per-column absolute/relative numeric tolerance and a timestamp skew in seconds.
  Tolerances need a key (without one there is no way to know which rows to pair).
* **nulls**: a column that is null on one side and absent on the other is equal by default.
* **sampling**: a deterministic, key-hashed sample selects the *same* rows on both sides, so a
  sampled run can still detect drift in the rows it looks at. Sampled reports say so.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from homelabnext.lake.base import normalize_value

MAX_EXAMPLES = 10


@dataclass(frozen=True)
class Tolerance:
    abs: float = 0.0
    rel: float = 0.0
    seconds: float = 0.0  # timestamp skew allowed (RFC 3339 text values)

    def __post_init__(self) -> None:
        if min(self.abs, self.rel, self.seconds) < 0:
            raise ValueError("tolerances must be >= 0")


@dataclass(frozen=True)
class Sample:
    """Keep rows whose key hashes into the first ``fraction`` of the space (deterministic)."""

    fraction: float
    salt: str = "hnx-parity"

    def __post_init__(self) -> None:
        if not 0 < self.fraction <= 1:
            raise ValueError("sample fraction must be in (0, 1]")

    def keep(self, key_text: str) -> bool:
        if self.fraction >= 1:
            return True
        h = hashlib.sha256(f"{self.salt}|{key_text}".encode()).digest()
        return int.from_bytes(h[:8], "big") / 2**64 < self.fraction


@dataclass(frozen=True)
class RowRules:
    key: tuple[str, ...] = ()
    ordered: bool = False
    order_by: tuple[str, ...] = ()
    ignore: frozenset[str] = frozenset()
    tolerances: Mapping[str, Tolerance] = field(default_factory=dict)
    nulls_as_missing: bool = True
    sample: Sample | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "key", tuple(self.key))
        object.__setattr__(self, "order_by", tuple(self.order_by))
        object.__setattr__(self, "ignore", frozenset(self.ignore))
        if self.tolerances and not self.key:
            raise ValueError("tolerances need key columns to pair rows")
        if self.sample and not self.key:
            raise ValueError("sampling needs key columns so both sides keep the same rows")


@dataclass
class RowDiff:
    left_count: int
    right_count: int
    only_left: list[dict[str, Any]] = field(default_factory=list)
    only_right: list[dict[str, Any]] = field(default_factory=list)
    changed: list[dict[str, Any]] = field(default_factory=list)
    only_left_total: int = 0
    only_right_total: int = 0
    changed_total: int = 0
    order_violations: int = 0
    columns_only_left: list[str] = field(default_factory=list)
    columns_only_right: list[str] = field(default_factory=list)
    sampled: bool = False

    @property
    def ok(self) -> bool:
        return not (
            self.only_left_total
            or self.only_right_total
            or self.changed_total
            or self.order_violations
            or self.columns_only_left
            or self.columns_only_right
        )

    @property
    def column_drift(self) -> bool:
        return bool(self.columns_only_left or self.columns_only_right)

    def summary(self) -> str:
        if self.ok:
            return f"{self.left_count} rows identical"
        parts = []
        if self.only_left_total:
            parts.append(f"{self.only_left_total} only on left")
        if self.only_right_total:
            parts.append(f"{self.only_right_total} only on right")
        if self.changed_total:
            parts.append(f"{self.changed_total} changed cells")
        if self.order_violations:
            parts.append(f"{self.order_violations} out of order")
        if self.column_drift:
            parts.append(
                f"column drift (left-only {self.columns_only_left}, "
                f"right-only {self.columns_only_right})"
            )
        return f"{self.left_count} vs {self.right_count} rows: " + ", ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "left_count": self.left_count,
            "right_count": self.right_count,
            "only_left": self.only_left,
            "only_right": self.only_right,
            "only_left_total": self.only_left_total,
            "only_right_total": self.only_right_total,
            "changed": self.changed,
            "changed_total": self.changed_total,
            "order_violations": self.order_violations,
            "columns_only_left": self.columns_only_left,
            "columns_only_right": self.columns_only_right,
            "sampled": self.sampled,
        }


def canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), default=str)


def _strip_nulls(v: Any) -> Any:
    if isinstance(v, Mapping):
        return {k: _strip_nulls(x) for k, x in v.items() if x is not None}
    if isinstance(v, list):
        return [_strip_nulls(x) for x in v]
    return v


def prepare(rows: Iterable[Mapping[str, Any]], rules: RowRules) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        n = {k: normalize_value(v) for k, v in r.items() if k not in rules.ignore}
        out.append(_strip_nulls(n) if rules.nulls_as_missing else n)
    return out


def _parse_ts(v: Any) -> datetime | None:
    if isinstance(v, str) and len(v) >= 19 and v[4] == "-" and v[10] in "T ":
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def values_equal(a: Any, b: Any, tol: Tolerance | None) -> bool:
    if isinstance(a, Mapping) and isinstance(b, Mapping):
        if set(a) != set(b):
            return False
        return all(values_equal(a[k], b[k], tol) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(values_equal(x, y, tol) for x, y in zip(a, b, strict=True))
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if a == b:
        return True
    if tol is None:
        return False
    num = (int, float)
    if (
        isinstance(a, num)
        and isinstance(b, num)
        and not isinstance(a, bool)
        and not isinstance(b, bool)
    ):
        if math.isnan(a) and math.isnan(b):
            return True
        return abs(a - b) <= tol.abs + tol.rel * max(abs(a), abs(b))
    if tol.seconds:
        ta, tb = _parse_ts(a), _parse_ts(b)
        if ta and tb:
            return abs((ta - tb).total_seconds()) <= tol.seconds
    return False


def _key_of(row: Mapping[str, Any], key: Sequence[str]) -> str:
    return canon([row.get(k) for k in key])


def _sort_key(row: Mapping[str, Any], cols: Sequence[str]) -> tuple[Any, ...]:
    out = []
    for c in cols:
        v = row.get(c)
        out.append((v is None, canon(v) if not isinstance(v, int | float) else "", v or 0))
    return tuple(out)


def _example(row: Mapping[str, Any]) -> dict[str, Any]:
    return dict(row)


def diff_rows(
    left: Iterable[Mapping[str, Any]],
    right: Iterable[Mapping[str, Any]],
    rules: RowRules | None = None,
) -> RowDiff:
    rules = rules or RowRules()
    L = prepare(left, rules)
    R = prepare(right, rules)
    sampled = False
    if rules.sample is not None and rules.sample.fraction < 1:
        sampled = True
        L = [r for r in L if rules.sample.keep(_key_of(r, rules.key))]
        R = [r for r in R if rules.sample.keep(_key_of(r, rules.key))]
    d = RowDiff(len(L), len(R), sampled=sampled)

    cols_l = {c for r in L for c in r}
    cols_r = {c for r in R for c in r}
    d.columns_only_left = sorted(cols_l - cols_r) if R else []
    d.columns_only_right = sorted(cols_r - cols_l) if L else []

    if rules.order_by:
        L = sorted(L, key=lambda r: _sort_key(r, rules.order_by))
        R = sorted(R, key=lambda r: _sort_key(r, rules.order_by))
    ordered = rules.ordered or bool(rules.order_by)

    if rules.key:
        _diff_keyed(d, L, R, rules, ordered)
    else:
        _diff_multiset(d, L, R, ordered)
    return d


def _push(lst: list[dict[str, Any]], row: Mapping[str, Any]) -> None:
    if len(lst) < MAX_EXAMPLES:
        lst.append(_example(row))


def _diff_multiset(d: RowDiff, L: list[dict], R: list[dict], ordered: bool) -> None:
    cl = [canon(r) for r in L]
    cr = [canon(r) for r in R]
    bag: dict[str, int] = {}
    for c in cr:
        bag[c] = bag.get(c, 0) + 1
    rest_l = []
    for r, c in zip(L, cl, strict=True):
        if bag.get(c, 0) > 0:
            bag[c] -= 1
        else:
            rest_l.append(r)
    seen: dict[str, int] = {}
    for c in cl:
        seen[c] = seen.get(c, 0) + 1
    rest_r = []
    for r, c in zip(R, cr, strict=True):
        if seen.get(c, 0) > 0:
            seen[c] -= 1
        else:
            rest_r.append(r)
    d.only_left_total, d.only_right_total = len(rest_l), len(rest_r)
    for r in rest_l:
        _push(d.only_left, r)
    for r in rest_r:
        _push(d.only_right, r)
    if ordered and not (rest_l or rest_r):
        d.order_violations = sum(1 for a, b in zip(cl, cr, strict=True) if a != b)


def _diff_keyed(d: RowDiff, L: list[dict], R: list[dict], rules: RowRules, ordered: bool) -> None:
    def group(rows: list[dict]) -> dict[str, list[dict]]:
        g: dict[str, list[dict]] = {}
        for r in rows:
            g.setdefault(_key_of(r, rules.key), []).append(r)
        return g

    gl, gr = group(L), group(R)
    for k in gl:
        a_rows, b_rows = gl[k], gr.get(k, [])
        a_rows = sorted(a_rows, key=canon)
        b_rows = sorted(b_rows, key=canon)
        n = min(len(a_rows), len(b_rows))
        for a, b in zip(a_rows[:n], b_rows[:n], strict=True):
            for col in sorted(set(a) | set(b)):
                if not values_equal(a.get(col), b.get(col), rules.tolerances.get(col)):
                    d.changed_total += 1
                    if len(d.changed) < MAX_EXAMPLES:
                        d.changed.append(
                            {
                                "key": json.loads(k),
                                "column": col,
                                "left": a.get(col),
                                "right": b.get(col),
                            }
                        )
        for a in a_rows[n:]:
            d.only_left_total += 1
            _push(d.only_left, a)
        for b in b_rows[n:]:
            d.only_right_total += 1
            _push(d.only_right, b)
    for k, rows in gr.items():
        if k not in gl:
            for b in rows:
                d.only_right_total += 1
                _push(d.only_right, b)
    if ordered and not (d.only_left_total or d.only_right_total):
        kl = [_key_of(r, rules.key) for r in L]
        kr = [_key_of(r, rules.key) for r in R]
        d.order_violations = sum(1 for a, b in zip(kl, kr, strict=True) if a != b)
