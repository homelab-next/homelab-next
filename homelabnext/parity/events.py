# SPDX-License-Identifier: Apache-2.0
"""Event-stream parity: the same input must yield the same envelopes on the old and new bus path.

Events are CloudEvents-style mappings (see ``schemas/events/envelope.schema.json``). ``id`` is the
idempotency key. Checks: malformed envelopes, per-type counts, missing / extra ids, duplicate ids
(new duplicating where old did not means idempotency broke), payload equality, order within a
partition (``subject`` by default), and optional delivery lag between the two paths.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .report import Check, ParityReport
from .rows import RowRules, Tolerance, diff_rows

REQUIRED = ("id", "source", "type")


@dataclass(frozen=True)
class EventRules:
    ignore: frozenset[str] = frozenset({"time"})  # top-level attributes that may differ
    partition: str | None = "subject"  # order must match inside each value; None = global order
    check_order: bool = True
    max_lag_s: float | None = None  # |time_new - time_old| allowed per id


def _bad(events: Sequence[Mapping[str, Any]]) -> list[int]:
    return [i for i, e in enumerate(events) if any(not e.get(k) for k in REQUIRED)]


def compare_event_streams(
    old: Sequence[Mapping[str, Any]],
    new: Sequence[Mapping[str, Any]],
    rules: EventRules | None = None,
) -> ParityReport:
    rules = rules or EventRules()
    rep = ParityReport("events", meta={"old": len(old), "new": len(new)})

    bad_o, bad_n = _bad(old), _bad(new)
    rep.add(
        Check(
            "envelopes",
            not (bad_o or bad_n),
            "all events carry id, source, type"
            if not (bad_o or bad_n)
            else f"malformed events (old {bad_o[:5]}, new {bad_n[:5]})",
            {"old": bad_o, "new": bad_n},
        )
    )
    old = [e for e in old if e.get("id")]
    new = [e for e in new if e.get("id")]

    def counts(evs: Sequence[Mapping[str, Any]]) -> dict[str, int]:
        c: dict[str, int] = {}
        for e in evs:
            c[str(e.get("type"))] = c.get(str(e.get("type")), 0) + 1
        return dict(sorted(c.items()))

    co, cn = counts(old), counts(new)
    rep.add(
        Check(
            "counts-by-type",
            co == cn,
            "per-type counts equal" if co == cn else "counts differ",
            {"old": co, "new": cn},
        )
    )

    def dup_ids(evs: Sequence[Mapping[str, Any]]) -> list[str]:
        seen: set[str] = set()
        dups: list[str] = []
        for e in evs:
            i = str(e["id"])
            if i in seen and i not in dups:
                dups.append(i)
            seen.add(i)
        return dups

    do, dn = dup_ids(old), dup_ids(new)
    new_only_dups = sorted(set(dn) - set(do))
    rep.add(
        Check(
            "duplicates",
            not new_only_dups,
            "no new duplicate ids"
            if not new_only_dups
            else f"{len(new_only_dups)} ids duplicated only on the new path",
            {"old": do[:10], "new": dn[:10]},
        )
    )

    def first_by_id(evs: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
        out: dict[str, Mapping[str, Any]] = {}
        for e in evs:
            out.setdefault(str(e["id"]), e)
        return out

    mo, mn = first_by_id(old), first_by_id(new)
    missing, extra = sorted(set(mo) - set(mn)), sorted(set(mn) - set(mo))
    rep.add(
        Check(
            "membership",
            not (missing or extra),
            "same event ids on both paths"
            if not (missing or extra)
            else f"{len(missing)} missing from new, {len(extra)} extra on new",
            {
                "missing": missing[:20],
                "extra": extra[:20],
                "missing_total": len(missing),
                "extra_total": len(extra),
            },
        )
    )

    both = sorted(set(mo) & set(mn))
    d = diff_rows(
        [mo[i] for i in both],
        [mn[i] for i in both],
        RowRules(key=("id",), ignore=rules.ignore),
    )
    rep.add(Check("payloads", d.ok, "payloads identical" if d.ok else d.summary(), d.to_dict()))

    if rules.check_order:
        viol = _order_violations(old, new, set(both), rules.partition)
        rep.add(
            Check(
                "ordering",
                not viol,
                "order preserved" if not viol else f"{len(viol)} partitions reordered",
                {"partitions": viol[:10]},
            )
        )
    if rules.max_lag_s is not None:
        tol = Tolerance(seconds=rules.max_lag_s)
        late = []
        from .rows import values_equal

        for i in both:
            if not values_equal(mo[i].get("time"), mn[i].get("time"), tol):
                late.append(i)
        rep.add(
            Check(
                "lag",
                not late,
                f"all within {rules.max_lag_s}s"
                if not late
                else f"{len(late)} events beyond {rules.max_lag_s}s",
                {"ids": late[:20]},
            )
        )
    return rep


def _order_violations(
    old: Sequence[Mapping[str, Any]],
    new: Sequence[Mapping[str, Any]],
    ids: set[str],
    partition: str | None,
) -> list[str]:
    def seqs(evs: Sequence[Mapping[str, Any]]) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        seen: set[str] = set()
        for e in evs:
            i = str(e["id"])
            if i not in ids or i in seen:
                continue
            seen.add(i)
            p = "*" if partition is None else str(e.get(partition))
            out.setdefault(p, []).append(i)
        return out

    so, sn = seqs(old), seqs(new)
    return sorted(p for p in so if so[p] != sn.get(p))
