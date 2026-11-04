# SPDX-License-Identifier: Apache-2.0
"""The novelty scoring engine (ADR-0035 decisions 1, 3, 5 and 6).

:func:`score_profile` is a pure function of a profile, ``as_of`` and three lists of
:class:`~homelabnext.lake.ceiling.GroupCount` (the learning window's counts, the scoring window's
counts and the table's per-day history in the learning window).  It makes no model call, reads
no clock and keeps no state, so the same lake contents, spec and ``as_of`` always give the same
rows.  :func:`run` reads those counts through a :class:`~homelabnext.lake.ceiling.CeilingReader`
(``count_by``) and writes the rows, per profile, idempotently.

The rule, for a profile with scoring window ``[S, as_of)``, ``S = as_of - score_hours``:

* the learning window is ``[S - learn_days, S)``; the scoring window is never learned from;
* a day's age is whole UTC days from the scoring window's start day, ``age = date(S) - day``,
  and its weight ``0.5 ** (age / half_life_days)``;
* support ``s(e, v)`` is the weighted count of (entity, value) in the learning window, and the
  entity total ``T(e)`` the sum of the entity's support over all its values;
* cold start: the history is ``date(S) - oldest day`` the table holds in the learning window (as
  the reader sees it; 0 with none).  Below ``min_history_days`` the profile is **warming** and
  emits nothing;
* an entity with more than ``max_values_per_entity`` distinct learned values is reported once
  as **high_cardinality** (when it is seen in the scoring window) and not scored;
* a pair whose entity has ``T(e) == 0`` is **unlearned**: reported with no score;
* otherwise ``surprise = 0 if s >= min_support else 1 - s / min_support``, ``confidence =
  min(1, T(e) / entity_min_samples)``, ``score = surprise * confidence``, and the pair is a
  **finding** when ``score >= emit_at``;
* at most ``max_findings`` rows are emitted: findings by score (highest first), then
  high-cardinality entities, then unlearned pairs, each by entity and value; the rest are
  counted as dropped, by status;
* a row's label is the strictest label among the rows that produced it: the pair's
  scoring-window rows and, for a scored or high-cardinality row, every learning-window row of
  its entity (they make ``T(e)``, and so the confidence).
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from homelabnext import tlp
from homelabnext.lake.ceiling import MAX_GROUPS, CeilingError, CeilingReader, GroupCount
from homelabnext.lake.errors import LakeError

from .spec import Profile, Spec

__all__ = [
    "SOURCE",
    "TABLE",
    "ProfileResult",
    "Windows",
    "batch_id",
    "run",
    "score_profile",
    "windows",
]

#: the ``source`` of every row this analyzer writes; a host sensor writes its own
SOURCE = "lake-novelty"
SOURCE_KIND = "heuristic"
TABLE = "novelty_finding"
#: the order rows are emitted (and so kept under the cap) by status
ORDER = ("finding", "high_cardinality", "unlearned")


@dataclass(frozen=True)
class Windows:
    learn_since: datetime
    learn_until: datetime  # = score_since
    score_until: datetime  # = as_of

    @property
    def score_since(self) -> datetime:
        return self.learn_until


def _aware(as_of: datetime) -> datetime:
    if not isinstance(as_of, datetime) or as_of.utcoffset() is None:
        raise ValueError("as_of must be a timezone-aware datetime")
    return as_of.astimezone(UTC)


def windows(profile: Profile, as_of: datetime) -> Windows:
    """The learning and scoring windows of ``profile`` for ``as_of``."""
    end = _aware(as_of)
    start = end - timedelta(hours=profile.score_hours)
    return Windows(start - timedelta(days=profile.learn_days), start, end)


def _text(v: Any) -> str:
    """A key as text: a string as is, anything else as JSON (``22``, ``true``)."""
    return v if isinstance(v, str) else json.dumps(v)


def _value_text(values: Sequence[Any]) -> str:
    if len(values) == 1:
        return _text(values[0])
    return json.dumps(list(values), separators=(",", ":"), ensure_ascii=False)


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _sha(*parts: Any) -> str:
    text = json.dumps(parts, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def batch_id(profile: Profile, spec_digest: str, as_of: datetime) -> str:
    """The idempotency key of one profile's write: a digest of the profile, the spec and
    ``as_of`` (decision 5), so a re-run of the same window writes nothing new."""
    return f"novelty:{profile.id}:{_sha(profile.id, spec_digest, _iso(_aware(as_of)))[:32]}"


@dataclass
class ProfileResult:
    """One profile's run: its status (``ok``, ``warming``, ``failed``), the emitted rows and
    the summary the run reports."""

    profile: str
    status: str
    windows: Windows | None = None
    oldest_day: date | None = None
    history_days: int = 0
    min_history_days: int = 0
    rows: list[dict[str, Any]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    dropped: dict[str, int] = field(default_factory=dict)
    error: str | None = None
    batch_id: str | None = None
    written: int | None = None
    replayed: bool | None = None

    def summary(self) -> dict[str, Any]:
        out: dict[str, Any] = {"profile": self.profile, "status": self.status}
        if self.error is not None:
            out["error"] = self.error
        if self.windows is not None:
            w = self.windows
            out["learn_window"] = [_iso(w.learn_since), _iso(w.learn_until)]
            out["score_window"] = [_iso(w.score_since), _iso(w.score_until)]
        if self.status != "failed":
            out["oldest_day"] = None if self.oldest_day is None else self.oldest_day.isoformat()
            out["history_days"] = self.history_days
        if self.status == "warming":
            out["min_history_days"] = self.min_history_days
            out["days_remaining"] = self.min_history_days - self.history_days
        if self.status == "ok":
            out["emitted"] = {s: sum(r["status"] == s for r in self.rows) for s in ORDER}
            out["candidates"] = {s: self.counts.get(s, 0) for s in ORDER}
            out["dropped"] = sum(self.dropped.values())
            out["dropped_by_status"] = {s: self.dropped.get(s, 0) for s in ORDER}
        if self.batch_id is not None and self.status == "ok":
            out["batch_id"] = self.batch_id
        if self.written is not None:
            out["written"] = self.written
            out["replayed"] = self.replayed
        return out


def _weight(profile: Profile, start_day: date, day: date) -> float:
    return 0.5 ** ((start_day - day).days / profile.half_life_days)


def score_profile(
    profile: Profile,
    as_of: datetime,
    learn: Iterable[GroupCount],
    scoring: Iterable[GroupCount],
    history: Iterable[GroupCount],
    *,
    spec_digest: str = "",
) -> ProfileResult:
    """Score one profile (the module docstring states the rule).  ``learn`` and ``scoring`` are
    ``count_by`` groups of the profile's entity and values over the learning and scoring windows,
    ``history`` the table's per-day groups (no entity) over the learning window."""
    w = windows(profile, as_of)
    start_day = w.learn_until.date()
    days = [g.day for g in history]
    oldest = min(days) if days else None
    history_days = (start_day - oldest).days if oldest is not None else 0
    result = ProfileResult(
        profile.id,
        "ok",
        w,
        oldest,
        history_days,
        profile.min_history_days,
        batch_id=batch_id(profile, spec_digest, as_of),
    )
    if history_days < profile.min_history_days:
        result.status = "warming"
        return result

    support: dict[tuple[Any, tuple], float] = defaultdict(float)
    total: dict[Any, float] = defaultdict(float)
    learned: dict[Any, set[tuple]] = defaultdict(set)
    entity_labels: dict[Any, set[tlp.Label]] = defaultdict(set)
    # sorted, so the float sums are taken in one order whatever order the engine returned
    for g in sorted(learn, key=_key):
        wt = g.count * _weight(profile, start_day, g.day)
        support[(g.entity, g.values)] += wt
        total[g.entity] += wt
        learned[g.entity].add(g.values)
        entity_labels[g.entity].add(g.label)

    seen: dict[tuple[Any, tuple], int] = defaultdict(int)
    pair_labels: dict[tuple[Any, tuple], set[tlp.Label]] = defaultdict(set)
    for g in sorted(scoring, key=_key):
        seen[(g.entity, g.values)] += g.count
        pair_labels[(g.entity, g.values)].add(g.label)

    candidates: list[dict[str, Any]] = []
    high: dict[Any, list[tuple[Any, tuple]]] = defaultdict(list)
    for (e, v), n in sorted(seen.items(), key=lambda kv: _key_of(*kv[0])):
        if len(learned.get(e, ())) > profile.max_values_per_entity:
            high[e].append((e, v))
            continue
        t = total.get(e, 0.0)
        s = support.get((e, v), 0.0)
        if t == 0:
            label = tlp.strictest(pair_labels[(e, v)])
            candidates.append(_row(profile, w, "unlearned", e, v, n, s, t, None, None, label))
            continue
        surprise = 0.0 if s >= profile.min_support else 1.0 - s / profile.min_support
        confidence = min(1.0, t / profile.entity_min_samples)
        score = surprise * confidence
        if score >= profile.emit_at:
            label = tlp.strictest(pair_labels[(e, v)] | entity_labels[e])
            row = _row(profile, w, "finding", e, v, n, s, t, score, confidence, label)
            candidates.append(row)
    for e, pairs in high.items():
        labels = set(entity_labels[e])
        for p in pairs:
            labels |= pair_labels[p]
        n = sum(seen[p] for p in pairs)
        label = tlp.strictest(labels)
        row = _row(profile, w, "high_cardinality", e, None, n, None, total[e], None, None, label)
        row["reasons"].append(
            f"{len(learned[e])} distinct learned values > max_values_per_entity "
            f"{profile.max_values_per_entity}: not scored"
        )
        candidates.append(row)

    candidates.sort(key=_emit_order)
    result.counts = {s: sum(r["status"] == s for r in candidates) for s in ORDER}
    kept = candidates[: profile.max_findings]
    for r in candidates[profile.max_findings :]:
        result.dropped[r["status"]] = result.dropped.get(r["status"], 0) + 1
    for r in kept:
        r["uid"] = _uid(profile, as_of, r)
        r["spec_digest"] = profile.digest
    result.rows = kept
    return result


def _orderable(v: Any) -> tuple:
    return (isinstance(v, str), int(v) if isinstance(v, bool) else v)


def _key_of(entity: Any, values: tuple) -> tuple:
    return (_orderable(entity), tuple(_orderable(x) for x in values))


def _key(g: GroupCount) -> tuple:
    return (*_key_of(g.entity, g.values), g.day, g.label.value)


def _emit_order(r: Mapping[str, Any]) -> tuple:
    score = r["score"] if r["score"] is not None else 0.0
    return (ORDER.index(r["status"]), -score, r["entity"], r.get("value") or "")


def _uid(profile: Profile, as_of: datetime, r: Mapping[str, Any]) -> str:
    return (
        "nov-"
        + _sha(
            SOURCE, profile.digest, _iso(_aware(as_of)), r["status"], r["entity"], r.get("value")
        )[:40]
    )


def _num(x: float | None) -> float | None:
    return None if x is None else round(x, 9)


def _row(
    profile: Profile,
    w: Windows,
    status: str,
    entity: Any,
    values: tuple | None,
    count: int,
    support: float | None,
    entity_total: float,
    score: float | None,
    confidence: float | None,
    label: tlp.Label,
) -> dict[str, Any]:
    e = _text(entity)
    v = None if values is None else _value_text(values)
    cols = ", ".join(profile.values)
    reasons = [f"entity_total {entity_total:.6g} over the learning window"]
    if status == "unlearned":
        message = f"{e}: {cols} {v} seen {count}x; the entity has no learned history (unlearned)"
    elif status == "high_cardinality":
        message = f"{e}: too many distinct {cols} values to baseline (high cardinality)"
    else:
        assert support is not None and score is not None and confidence is not None
        message = (
            f"{e}: {cols} {v} is rare for this entity (support {support:.6g} < min_support "
            f"{profile.min_support:g}; score {score:.3f} >= emit_at {profile.emit_at:g})"
        )
        reasons = [
            f"support {support:.6g} vs min_support {profile.min_support:g}",
            reasons[0],
            f"surprise {score / confidence if confidence else 0:.6g} x confidence "
            f"{confidence:.6g} = score {score:.6g} >= emit_at {profile.emit_at:g}",
        ]
    return {
        "uid": "",
        "time": w.score_until,
        "as_of": w.score_until,
        "source": SOURCE,
        "source_kind": SOURCE_KIND,
        "profile": profile.id,
        "entity": e,
        "entity_column": profile.entity,
        "value": v,
        "value_columns": list(profile.values),
        "status": status,
        "score": _num(score),
        "confidence": _num(confidence),
        "support": _num(support),
        "entity_total": _num(entity_total),
        "count": count,
        "learn_since": w.learn_since,
        "learn_until": w.learn_until,
        "score_since": w.score_since,
        "score_until": w.score_until,
        "spec_digest": "",
        "message": message,
        "reasons": reasons,
        "tlp": label.value,
    }


def run(
    reader: CeilingReader,
    spec: Spec,
    as_of: datetime,
    *,
    writer: Any = None,
    limit: int = MAX_GROUPS,
) -> list[ProfileResult]:
    """Score every profile of ``spec`` for ``as_of`` through ``reader`` and, with ``writer`` (a
    ``LakeClient``), write each profile's rows to ``novelty_finding`` under its batch id.  Without
    ``writer`` nothing is written (a dry run).  A profile whose read fails (too many groups, a
    column its reader may not read) is reported ``failed``; the others still run."""
    as_of = _aware(as_of)
    out = []
    for p in spec.profiles:
        w = windows(p, as_of)
        common = {"time_column": p.time_column, "limit": limit}
        try:
            history = reader.count_by(
                p.table, None, [], since=w.learn_since, until=w.learn_until, **common
            )
            args = (p.table, p.entity, list(p.values))
            where = dict(p.where) or None
            learn = reader.count_by(
                *args, since=w.learn_since, until=w.learn_until, where=where, **common
            )
            scoring = reader.count_by(
                *args, since=w.score_since, until=w.score_until, where=where, **common
            )
        except (CeilingError, LakeError) as exc:
            out.append(ProfileResult(p.id, "failed", w, error=f"{type(exc).__name__}: {exc}"))
            continue
        result = score_profile(p, as_of, learn, scoring, history, spec_digest=spec.digest)
        if writer is not None and result.status == "ok" and result.rows:
            res = writer.write_batch(
                TABLE,
                result.rows,
                idempotency_key=result.batch_id,
                source=f"novelty:{p.id}",
                high_water=_iso(as_of),
            )
            result.written, result.replayed = res.rows_written, res.replayed
        elif writer is not None and result.status == "ok":
            result.written, result.replayed = 0, False
        out.append(result)
    return out
