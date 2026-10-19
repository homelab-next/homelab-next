# SPDX-License-Identifier: Apache-2.0
"""Batch classification at ingest: the cascade annotates records, it never removes them (K-13).

:func:`annotate` runs every record through a cascade and returns **every** record, in order,
with its original fields untouched and the decision added as annotation columns (``decide_*`` by
default).  Nothing a classifier says can drop, merge, reorder or rewrite a record:

* records in == records out, by count, order and content (the original columns are copied, never
  edited);
* an annotation column that would overwrite an existing column is refused up front
  (:class:`AnnotationCollision`), before any record is classified;
* a record the cascade cannot classify (a missing or non-string text field, a cascade fault) is
  still emitted, annotated ``verdict: human`` with the reason in ``<prefix>error``.

Filtering on the annotations is a downstream query's choice, made on data that is all still there.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from typing import Any

from .cascade import Cascade
from .tiers import Item

#: the annotation columns, without their prefix
COLUMNS = (
    "spec",
    "spec_version",
    "verdict",
    "tier",
    "confidence",
    "impact",
    "escalated",
    "audit",
    "corroboration",
    "error",
)


class AnnotationCollision(ValueError):
    """An annotation column already exists in the input records."""


def columns(prefix: str = "decide_") -> tuple[str, ...]:
    return tuple(prefix + c for c in COLUMNS)


def _annotation(cascade: Cascade, row: Mapping[str, Any], n: int, text_field: str,
                id_field: str | None, prefix: str) -> dict[str, Any]:  # fmt: skip
    spec = cascade.spec
    out: dict[str, Any] = dict.fromkeys(columns(prefix))
    out[prefix + "spec"] = spec.id
    out[prefix + "spec_version"] = spec.version
    text = row.get(text_field)
    rid = row.get(id_field) if id_field else None
    item_id = str(rid) if rid not in (None, "") else f"row-{n}"
    if not isinstance(text, str):
        reason = f"field {text_field!r} missing or not text"
    else:
        impact = row.get("impact") if isinstance(row.get("impact"), str) else "low"
        try:
            d = cascade.decide(Item(item_id, text, impact))
        except Exception as exc:  # the cascade is exception-safe; never lose the row if not
            reason = f"cascade failed: {type(exc).__name__}"
        else:
            out.update(
                {
                    prefix + "verdict": d.verdict,
                    prefix + "tier": d.tier,
                    prefix + "confidence": round(d.confidence, 4),
                    prefix + "impact": d.impact,
                    prefix + "escalated": d.escalated,
                    prefix + "audit": d.audit,
                    prefix + "corroboration": d.corroboration,
                }
            )
            return out
    out.update({prefix + "verdict": "human", prefix + "tier": "human",
                prefix + "escalated": True, prefix + "error": reason})  # fmt: skip
    return out


def iter_annotate(
    records: Iterable[Mapping[str, Any]],
    cascade: Cascade,
    *,
    text_field: str = "text",
    id_field: str | None = "id",
    prefix: str = "decide_",
) -> Iterator[dict[str, Any]]:
    """Yield each record (a new dict: original columns first, then the annotations)."""
    cols = set(columns(prefix))
    for n, row in enumerate(records):
        clash = sorted(cols & set(row))
        if clash:
            raise AnnotationCollision(
                f"record {n} already has annotation column(s) {clash}; choose another prefix"
            )
        yield {**row, **_annotation(cascade, row, n, text_field, id_field, prefix)}


def annotate(
    records: Iterable[Mapping[str, Any]],
    cascade: Cascade,
    *,
    text_field: str = "text",
    id_field: str | None = "id",
    prefix: str = "decide_",
) -> list[dict[str, Any]]:
    """Every record, in order, with annotation columns added (all-or-nothing on a collision)."""
    rows = list(records)
    cols = set(columns(prefix))
    for n, row in enumerate(rows):
        clash = sorted(cols & set(row))
        if clash:
            raise AnnotationCollision(
                f"record {n} already has annotation column(s) {clash}; choose another prefix"
            )
    out = list(
        iter_annotate(rows, cascade, text_field=text_field, id_field=id_field, prefix=prefix)
    )
    if len(out) != len(rows):  # pragma: no cover - structural guarantee, asserted by the tests
        raise AssertionError("annotate changed the record count")
    return out
