# SPDX-License-Identifier: Apache-2.0
"""The source census: is every source still arriving, judged by its own cadence?

The lab's single best "is the telemetry flowing" check (ADR-0049 decision 9), rebuilt generic.  It
groups one event table by its **source columns** and the UTC hour over a window (8 days by
default) through the lake-query contract, learns each source's own cadence from when it arrived,
and flags a source whose silence is longer than a multiple of that cadence.  One blanket "must
have fired in 24 hours" rule is the mistake this avoids: a weekly scan is not broken for being
quiet on Tuesday.

Statuses of one source:

``OK``                 arrived within its cadence.
``STALE``              silent longer than ``multiple`` times its learned cadence (and longer than
                       ``min_silence_hours``); fails.
``MISSING``            a *declared* source (``expected``) with no row in the window; fails.
``LEARNING``           less history than the window: passes, but the criterion reads ``warn`` and the
                       evidence names it, so a young lake is visible rather than silently green.
``LEARNING-STALE``     still learning, but it had arrived ``learning_min_arrivals`` times and is now
                       silent past the absolute floor (``floor_hours``): fails, so the cutover
                       period is not blind.
``ACKNOWLEDGED``       would fail, and an acknowledgement (owner, reason, expiry) covers it; an
                       expired one covers nothing and the evidence says so.

A source may be *declared* (``expected``: a match on the source columns, its own cadence and a
grace multiple), which replaces learning for it: the old audit's per-source table, as data.  A
match value is a string (equality) or a mapping of ``equals`` / ``prefix`` / ``suffix`` /
``contains`` that all must hold, so a source is identified by what survives a producer
restructuring its layout (its file name and a path fragment), not by one exact path.

``all-classes-dark`` (:func:`dark`) never learns: it fails when none of the tables has one row in
its window.  A census that cannot read the table at all is an error (exit 100), never a pass.

The queries are the portable SQL subset plus :func:`~homelabnext.lake.dialect.hour_expr`; column
and table names are validated identifiers, every value is a bound parameter.  ``run`` is the
caller's read path (the CLI hands in a red-granted raw read: the census reads counts and times
only, never a row's content).
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from .dialect import dialect_of, hour_expr
from .errors import LakeError

__all__ = [
    "Ack",
    "CensusConfig",
    "CensusError",
    "Expected",
    "Report",
    "SourceResult",
    "census",
    "classify",
    "config_from",
    "dark",
]

HOUR = timedelta(hours=1)
FAILING = ("STALE", "MISSING", "LEARNING-STALE")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_OPS = ("equals", "prefix", "suffix", "contains")


class CensusError(LakeError):
    """The census could not be measured (a bad setting, an unreadable table, too many groups)."""


@dataclass(frozen=True)
class Expected:
    """A declared source: ``match`` names source columns, the source arrives every
    ``cadence_hours`` and is flagged after ``grace`` of them in silence."""

    name: str
    match: Mapping[str, Any]
    cadence_hours: float
    grace: float


@dataclass(frozen=True)
class Ack:
    """Leave to be quiet: ``name`` (a declared source) or ``match`` (source columns), who owns it,
    why, and the day it stops covering anything."""

    owner: str
    reason: str
    expires: date
    name: str | None = None
    match: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class CensusConfig:
    table: str = "raw_archive"
    source_columns: tuple[str, ...] = ("location", "decoder_name")
    time_column: str = "time"
    window_days: int = 8
    multiple: float = 3.0
    min_silence_hours: float = 2.0
    floor_hours: float = 24.0
    learning_min_arrivals: int = 3
    max_groups: int = 100_000
    expected: tuple[Expected, ...] = ()
    acknowledged: tuple[Ack, ...] = ()

    def __post_init__(self) -> None:
        for name in (self.table, self.time_column, *self.source_columns):
            if not _IDENT.match(name):
                raise CensusError(f"not a plain table or column name: {name!r}")
        if not self.source_columns:
            raise CensusError("at least one source column")
        if self.window_days < 2:
            raise CensusError("window_days is at least 2 (a source's cadence needs history)")
        if self.multiple < 1 or self.min_silence_hours < 1 or self.floor_hours < 1:
            raise CensusError("multiple, min_silence_hours and floor_hours are at least 1")
        if self.learning_min_arrivals < 1 or self.max_groups < 1:
            raise CensusError("learning_min_arrivals and max_groups are at least 1")
        for e in self.expected:
            _check_match(e.match, self.source_columns, f"expected {e.name!r}")
            if e.cadence_hours <= 0 or e.grace <= 0:
                raise CensusError(f"expected {e.name!r}: cadence_hours and grace are positive")
        for a in self.acknowledged:
            if (a.name is None) == (a.match is None):
                raise CensusError("an acknowledgement names a declared source or a match, not both")
            if not a.owner.strip() or not a.reason.strip():
                raise CensusError("an acknowledgement carries an owner and a reason")
            if a.match is not None:
                _check_match(a.match, self.source_columns, "acknowledgement")
            elif a.name not in {e.name for e in self.expected}:
                raise CensusError(
                    f"acknowledgement names {a.name!r}, which is not a declared source"
                )


def _check_match(match: Mapping[str, Any], columns: Sequence[str], who: str) -> None:
    if not isinstance(match, Mapping) or not match:
        raise CensusError(f"{who}: a match names at least one source column")
    for col, cond in match.items():
        if col not in columns:
            raise CensusError(f"{who}: {col!r} is not a source column ({', '.join(columns)})")
        if isinstance(cond, str):
            continue
        if not isinstance(cond, Mapping) or not cond or set(cond) - set(_OPS):
            raise CensusError(f"{who}: {col!r} is a string or a mapping of {', '.join(_OPS)}")
        if not all(isinstance(v, str) and v for v in cond.values()):
            raise CensusError(f"{who}: {col!r} conditions are non-empty text")


def config_from(doc: Mapping[str, Any]) -> CensusConfig:
    """A :class:`CensusConfig` from a parsed settings mapping (unknown keys are refused)."""
    allowed = {
        "table", "source_columns", "time_column", "window_days", "multiple", "min_silence_hours",
        "floor_hours", "learning_min_arrivals", "max_groups", "expected", "acknowledged",
    }  # fmt: skip
    unknown = sorted(set(doc) - allowed)
    if unknown:
        raise CensusError(f"unknown census setting(s): {', '.join(unknown)}")
    kw: dict[str, Any] = {k: v for k, v in doc.items() if k not in ("expected", "acknowledged")}
    if "source_columns" in kw:
        kw["source_columns"] = tuple(kw["source_columns"])
    try:
        kw["expected"] = tuple(
            Expected(e["name"], e["match"], float(e["cadence_hours"]), float(e.get("grace", 3)))
            for e in doc.get("expected", [])
        )
        acks = []
        for a in doc.get("acknowledged", []):
            exp = a["expires"]
            exp = exp if isinstance(exp, date) else date.fromisoformat(str(exp))
            acks.append(Ack(a["owner"], a["reason"], exp, a.get("name"), a.get("match")))
        kw["acknowledged"] = tuple(acks)
    except (KeyError, TypeError, ValueError) as exc:
        raise CensusError(f"census settings: {type(exc).__name__}: {exc}") from None
    return CensusConfig(**kw)


@dataclass(frozen=True)
class SourceResult:
    name: str
    status: str
    arrivals: int
    first_seen: datetime | None
    last_seen: datetime | None  # the start of the last hour it arrived in
    cadence_hours: float | None
    silence_hours: float | None
    detail: str

    @property
    def failing(self) -> bool:
        return self.status in FAILING

    @property
    def key(self) -> str:
        return f"source:{self.name}"


@dataclass(frozen=True)
class Report:
    now: datetime
    window_days: int
    results: tuple[SourceResult, ...]

    @property
    def flagged(self) -> list[SourceResult]:
        return [r for r in self.results if r.failing]

    @property
    def learning(self) -> list[SourceResult]:
        return [r for r in self.results if r.status == "LEARNING"]

    @property
    def status(self) -> str:
        """``fail`` (a source is flagged, or none arrived at all), ``warn`` (passing, but a source
        is still learning) or ``pass``."""
        if not self.results or self.flagged:
            return "fail"
        return "warn" if self.learning else "pass"

    def evidence(self, limit: int = 12) -> str:
        if not self.results:
            return f"no source arrived in the last {self.window_days} days"
        ok = sum(1 for r in self.results if not r.failing)
        head = f"{ok}/{len(self.results)} sources within their own cadence"
        if self.flagged:
            head += f", {len(self.flagged)} flagged"
        if self.learning:
            head += f", {len(self.learning)} still learning (history shorter than {self.window_days} days)"
        lines = [head]
        for r in self.flagged[:limit]:
            lines.append(f"  [{r.status}] {r.name}: {r.detail}")
        if len(self.flagged) > limit:
            lines.append(f"  ... and {len(self.flagged) - limit} more")
        for r in self.learning[:limit]:
            lines.append(f"  [LEARNING] {r.name}: {r.detail}")
        for r in self.results:
            if r.status == "ACKNOWLEDGED":
                lines.append(f"  [ACKNOWLEDGED] {r.name}: {r.detail}")
        return "\n".join(lines)


# ----------------------------------------------------------------------------- the query
def _hour(text: Any) -> datetime:
    s = str(text)[:13]
    try:
        return datetime.strptime(s, "%Y-%m-%d %H").replace(tzinfo=UTC)
    except ValueError:
        raise CensusError(
            f"the engine returned an hour bucket {text!r}, not 'YYYY-MM-DD HH'"
        ) from None


def census(
    run: Callable[[str, Mapping[str, Any]], list[dict[str, Any]]],
    lake: Any,
    cfg: CensusConfig,
    *,
    now: datetime,
) -> Report:
    """Read the window through ``run(sql, params)`` and classify every source.  ``lake`` only
    declares the SQL dialect."""
    if now.tzinfo is None:
        raise CensusError("now is timezone-aware (UTC)")
    since = (now - timedelta(days=cfg.window_days)).replace(minute=0, second=0, microsecond=0)
    q = lambda c: '"' + c + '"'  # noqa: E731 - the names are validated identifiers
    hr = hour_expr(dialect_of(lake), q(cfg.time_column))
    cols = ", ".join(q(c) for c in cfg.source_columns)
    sql = (
        f"SELECT {cols}, {hr} AS h, count(*) AS n FROM {q(cfg.table)} "
        f"WHERE {q(cfg.time_column)} >= :since AND {q(cfg.time_column)} < :until "
        f"GROUP BY {cols}, {hr} LIMIT {cfg.max_groups + 1}"
    )
    try:
        rows = run(sql, {"since": since, "until": now})
    except LakeError as exc:
        raise CensusError(f"cannot read {cfg.table}: {exc}") from exc
    if len(rows) > cfg.max_groups:
        raise CensusError(
            f"more than {cfg.max_groups} (source, hour) groups: a source column that is not a "
            "source (a unique id) would make every row its own source; the census is refused"
        )
    return classify(rows, cfg, now=now)


# ----------------------------------------------------------------------------- the judgement
def _matches(match: Mapping[str, Any], key: Mapping[str, Any]) -> bool:
    for col, cond in match.items():
        val = key.get(col)
        val = "" if val is None else str(val)
        if isinstance(cond, str):
            if val != cond:
                return False
            continue
        if "equals" in cond and val != cond["equals"]:
            return False
        if "prefix" in cond and not val.startswith(cond["prefix"]):
            return False
        if "suffix" in cond and not val.endswith(cond["suffix"]):
            return False
        if "contains" in cond and cond["contains"].lower() not in val.lower():
            return False
    return True


def _label(key: Mapping[str, Any]) -> str:
    return " / ".join("(none)" if v is None else str(v) for v in key.values())


def _p90(gaps: list[float]) -> float:
    ordered = sorted(gaps)
    return ordered[max(0, -(-len(ordered) * 9 // 10) - 1)]


def _facts(
    hours: dict[datetime, int], now: datetime
) -> tuple[int, datetime, datetime, float | None, float]:
    ordered = sorted(hours)
    first, last = ordered[0], ordered[-1]
    gaps = [(b - a) / HOUR for a, b in itertools.pairwise(ordered)]
    cadence = max(1.0, _p90(gaps)) if gaps else None
    silence = max(0.0, (now - (last + HOUR)) / HOUR)
    return sum(hours.values()), first, last, cadence, silence


def _ack_for(cfg: CensusConfig, *, name: str | None, key: Mapping[str, Any] | None, today: date):
    """``(covering ack | None, expired ack | None)``."""
    expired = None
    for a in cfg.acknowledged:
        hit = (
            a.name == name
            if a.name is not None
            else key is not None and _matches(a.match or {}, key)
        )
        if not hit:
            continue
        if a.expires >= today:
            return a, None
        expired = a
    return None, expired


def classify(rows: Sequence[Mapping[str, Any]], cfg: CensusConfig, *, now: datetime) -> Report:
    window_start = (now - timedelta(days=cfg.window_days)).replace(
        minute=0, second=0, microsecond=0
    )
    today = now.date()
    sources: dict[tuple, dict[datetime, int]] = {}
    for r in rows:
        key = tuple(r.get(c) for c in cfg.source_columns)
        h = _hour(r["h"])
        sources.setdefault(key, {})
        sources[key][h] = sources[key].get(h, 0) + int(r["n"])

    results: list[SourceResult] = []
    claimed: set[tuple] = set()

    def finish(
        name,
        status,
        arrivals,
        first,
        last,
        cadence,
        silence,
        detail,
        *,
        ack_name=None,
        ack_key=None,
    ):
        if status in FAILING:
            ack, expired = _ack_for(cfg, name=ack_name, key=ack_key, today=today)
            if ack:
                status = "ACKNOWLEDGED"
                detail = f"{detail}; acknowledged by {ack.owner} until {ack.expires.isoformat()}: {ack.reason}"
            elif expired:
                detail = f"{detail}; the acknowledgement by {expired.owner} expired {expired.expires.isoformat()}"
        results.append(SourceResult(name, status, arrivals, first, last, cadence, silence, detail))

    for e in cfg.expected:
        hours: dict[datetime, int] = {}
        for key, hs in sources.items():
            if _matches(e.match, dict(zip(cfg.source_columns, key, strict=True))):
                claimed.add(key)
                for h, n in hs.items():
                    hours[h] = hours.get(h, 0) + n
        if not hours:
            finish(
                e.name,
                "MISSING",
                0,
                None,
                None,
                e.cadence_hours,
                None,
                f"never seen in the last {cfg.window_days} days",
                ack_name=e.name,
            )
            continue
        n, first, last, _c, silence = _facts(hours, now)
        threshold = e.cadence_hours * e.grace
        if silence <= threshold:
            finish(
                e.name,
                "OK",
                n,
                first,
                last,
                e.cadence_hours,
                silence,
                f"last seen {silence:.1f}h ago (expected within {threshold:.0f}h)",
                ack_name=e.name,
            )
        else:
            finish(
                e.name,
                "STALE",
                n,
                first,
                last,
                e.cadence_hours,
                silence,
                f"last seen {silence:.1f}h ago (expected within {threshold:.0f}h)",
                ack_name=e.name,
            )

    for key in sorted(sources, key=lambda k: tuple("" if v is None else str(v) for v in k)):
        if key in claimed:
            continue
        keymap = dict(zip(cfg.source_columns, key, strict=True))
        name = _label(keymap)
        n, first, last, cadence, silence = _facts(sources[key], now)
        slack = max(HOUR, timedelta(hours=cadence or 1.0))
        learning = first > window_start + slack
        if learning:
            if n >= cfg.learning_min_arrivals and silence > cfg.floor_hours:
                finish(
                    name,
                    "LEARNING-STALE",
                    n,
                    first,
                    last,
                    cadence,
                    silence,
                    f"{n} arrivals, silent {silence:.1f}h (floor {cfg.floor_hours:.0f}h) while learning",
                    ack_key=keymap,
                )
            else:
                finish(
                    name,
                    "LEARNING",
                    n,
                    first,
                    last,
                    cadence,
                    silence,
                    f"first seen {(now - first) / timedelta(days=1):.1f} days ago, {n} arrival(s)",
                )
            continue
        threshold = (
            max(cfg.multiple * cadence, cfg.min_silence_hours) if cadence else cfg.floor_hours
        )
        basis = f"cadence ~{cadence:.0f}h" if cadence else "cadence unknown"
        if silence > threshold:
            finish(
                name,
                "STALE",
                n,
                first,
                last,
                cadence,
                silence,
                f"silent {silence:.1f}h; {basis}, flagged past {threshold:.0f}h",
                ack_key=keymap,
            )
        else:
            finish(
                name,
                "OK",
                n,
                first,
                last,
                cadence,
                silence,
                f"silent {silence:.1f}h; {basis}, flagged past {threshold:.0f}h",
            )
    return Report(now, cfg.window_days, tuple(results))


# ----------------------------------------------------------------------------- all classes dark
@dataclass(frozen=True)
class Dark:
    dark: bool
    tables: tuple[tuple[str, bool], ...] = field(default=())  # (table, has a row in the window)
    hours: float = 24.0

    def evidence(self) -> str:
        if self.dark:
            return f"no event in any of {', '.join(t for t, _ in self.tables)} in the last {self.hours:g}h"
        live = [t for t, has in self.tables if has]
        return f"events in {len(live)}/{len(self.tables)} table(s) in the last {self.hours:g}h"


def dark(
    run: Callable[[str, Mapping[str, Any]], list[dict[str, Any]]],
    tables: Sequence[str],
    *,
    now: datetime,
    hours: float = 24.0,
    time_column: str = "time",
) -> Dark:
    """Fail-state of ``all-classes-dark``: no table of ``tables`` has one row in the last ``hours``.
    Never learns: a young lake that has received nothing is dark."""
    if not tables:
        raise CensusError("all-classes-dark needs at least one table")
    if hours <= 0:
        raise CensusError("hours is positive")
    for name in (*tables, time_column):
        if not _IDENT.match(name):
            raise CensusError(f"not a plain table or column name: {name!r}")
    since = now - timedelta(hours=hours)
    seen: list[tuple[str, bool]] = []
    for t in tables:
        sql = (
            f'SELECT "{time_column}" AS t FROM "{t}" WHERE "{time_column}" >= :since '
            f'AND "{time_column}" < :until LIMIT 1'
        )
        try:
            seen.append((t, bool(run(sql, {"since": since, "until": now}))))
        except LakeError as exc:
            raise CensusError(f"cannot read {t}: {exc}") from exc
    return Dark(not any(has for _, has in seen), tuple(seen), hours)
