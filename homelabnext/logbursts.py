# SPDX-License-Identifier: Apache-2.0
"""Cluster error lines in time into bursts, and say whether a burst is still running.

A raw count of error lines over a day cannot tell "fifteen lines spread across the day, still
happening" from "fifteen lines inside one 38-second network blip that recovered half a day ago".
The two need opposite responses, and only the first is worth waking anyone for.  This library
reads timestamped lines, drops the lines a reviewed benign list names, groups the rest into
bursts (a gap wider than ``gap`` starts a new one), collapses each burst to its distinct message
shapes (numbers, addresses and long hex ids masked) and returns a verdict:

* ``ONGOING`` (needs attention): the last line is no older than the quiet period, or a message
  shape came back on ``recur_days`` or more distinct UTC days within the lookback (a burst that
  recurs on three days is one standing fault, not three recoveries);
* ``RECOVERED`` (no action): there were lines, they all stopped more than the quiet period ago and
  nothing recurs;
* ``CLEAN``: no line at all.

Only ``ONGOING`` fails (exit 1 from :func:`main`).  A line whose timestamp cannot be read is
counted and reported, never silently dropped, and a log that cannot be read at all is exit 100
(could not measure), which is neither a pass nor a fail.

The benign list is data (``--benign FILE``): each entry is ``{match, reason}``.  ``match`` is a
literal substring of the message (never a regular expression), may name ``{variables}`` that the
site supplies (``--var NAME=VALUE``: a scanner's address belongs to the site, never to this
code), and a missing variable, a blank reason, a duplicate match or an entry that would match
every line is refused whole: a list that cannot be read is never a list that hides nothing.

``hnx logbursts --log FILE [--log FILE ...] [--benign FILE] [--var K=V] [--since-hours 24]``
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

__all__ = [
    "Assessment",
    "Benign",
    "BenignError",
    "Burst",
    "Line",
    "Shape",
    "assess",
    "cluster",
    "load_benign",
    "main",
    "parse_lines",
    "render",
    "shape_of",
]

GAP = timedelta(minutes=10)
QUIET = timedelta(minutes=120)
RECUR_DAYS = 3
LOOKBACK_DAYS = 7
VERDICT_WINDOW = timedelta(hours=24)

#: ``2026/07/31 10:22:01`` (the manager log) or ISO 8601 ``2026-07-31T10:22:01Z`` / space separated
_TS = re.compile(
    r"^\s*(\d{4})[/-](\d{2})[/-](\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?\s*"
)
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b")
_HEX = re.compile(r"\b(?:0x)?[0-9a-fA-F]{12,}\b")
_NUM = re.compile(r"\d+")
_VAR = re.compile(r"\{([a-z][a-z0-9_]*)\}")
_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")


class BenignError(ValueError):
    """The benign list cannot be read as a reviewed list."""


@dataclass(frozen=True)
class Line:
    ts: datetime
    text: str  # the message, timestamp prefix removed


@dataclass(frozen=True)
class Shape:
    shape: str
    count: int
    example: str


@dataclass(frozen=True)
class Burst:
    lines: tuple[Line, ...]

    @property
    def start(self) -> datetime:
        return self.lines[0].ts

    @property
    def end(self) -> datetime:
        return self.lines[-1].ts

    @property
    def seconds(self) -> int:
        return int((self.end - self.start).total_seconds())

    def shapes(self) -> list[Shape]:
        """Distinct message shapes, most frequent first, each with one real unmasked example (the
        shape alone says a class of thing happened N times, never WHICH agent or address)."""
        seen: dict[str, tuple[int, str]] = {}
        for ln in self.lines:
            s = shape_of(ln.text)
            n, ex = seen.get(s, (0, ln.text))
            seen[s] = (n + 1, ex)
        return [
            Shape(s, n, ex)
            for s, (n, ex) in sorted(seen.items(), key=lambda kv: (-kv[1][0], kv[0]))
        ]


@dataclass(frozen=True)
class Benign:
    match: str
    reason: str


@dataclass(frozen=True)
class Assessment:
    verdict: str  # ONGOING | RECOVERED | CLEAN
    bursts: tuple[Burst, ...]
    last: datetime | None
    age: timedelta | None
    count: int
    dropped_benign: int
    unparsed: int
    recurring: tuple[tuple[str, int], ...] = field(default=())  # (shape, distinct days)

    @property
    def ongoing(self) -> bool:
        return self.verdict == "ONGOING"


def shape_of(text: str) -> str:
    """``text`` with the parts that vary per occurrence masked: UUIDs, long hex ids, IPv4
    addresses, then every other run of digits."""
    t = _UUID.sub("<uuid>", text)
    t = _HEX.sub("<hex>", t)
    t = _IPV4.sub("<ip>", t)
    return _NUM.sub("#", t)


def _when(m: re.Match[str]) -> datetime | None:
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    try:
        ts = datetime(y, mo, d, h, mi, s, tzinfo=UTC)
    except ValueError:
        return None
    off = m.group(7)
    if off and off != "Z":
        sign = 1 if off[0] == "+" else -1
        digits = off[1:].replace(":", "")
        ts -= sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    return ts


def parse_lines(lines: Iterable[str]) -> tuple[list[Line], int]:
    """``(lines with a readable timestamp, count of lines without one)``.  Blank lines are not
    counted; a continuation line without a timestamp is."""
    out: list[Line] = []
    bad = 0
    for raw in lines:
        raw = raw.rstrip("\n")
        if not raw.strip():
            continue
        m = _TS.match(raw)
        ts = _when(m) if m else None
        if ts is None:
            bad += 1
            continue
        out.append(Line(ts, raw[m.end() :].strip()))
    out.sort(key=lambda ln: ln.ts)
    return out, bad


def load_benign(source: Any, variables: Mapping[str, str] | None = None) -> list[Benign]:
    """The reviewed benign list from a parsed document (``{"benign": [{match, reason}]}``) or a
    path to one; ``variables`` fill the ``{names}`` an entry's match carries."""
    doc = source
    if isinstance(source, (str, Path)):
        from homelabnext._yaml import safe_load

        try:
            doc = safe_load(Path(source).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise BenignError(f"{source}: cannot be read: {exc}") from exc
    entries = doc.get("benign") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        raise BenignError("the benign list is a mapping with a `benign:` list")
    variables = dict(variables or {})
    out: list[Benign] = []
    seen: set[str] = set()
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or set(e) != {"match", "reason"}:
            raise BenignError(f"benign[{i}]: exactly the keys match and reason")
        match, reason = e["match"], e["reason"]
        if not isinstance(match, str) or not isinstance(reason, str):
            raise BenignError(f"benign[{i}]: match and reason are text")
        if not reason.strip():
            raise BenignError(f"benign[{i}] ({match!r}): a benign shape carries a reason")
        names = _VAR.findall(match)
        missing = sorted({n for n in names if n not in variables})
        if missing:
            raise BenignError(f"benign[{i}] ({match!r}): no value for {', '.join(missing)} (--var)")
        text = _VAR.sub(lambda m: variables[m.group(1)], match)
        if len(text.strip()) < 8:
            raise BenignError(
                f"benign[{i}] ({match!r}): a match shorter than 8 characters would hide real errors"
            )
        if text in seen:
            raise BenignError(f"benign[{i}] ({match!r}): listed twice")
        seen.add(text)
        out.append(Benign(text, reason))
    return out


def cluster(lines: Sequence[Line], gap: timedelta = GAP) -> list[Burst]:
    """``lines`` (any order) grouped in time: a gap wider than ``gap`` starts a new burst."""
    ordered = sorted(lines, key=lambda ln: ln.ts)
    bursts: list[list[Line]] = []
    for ln in ordered:
        if bursts and ln.ts - bursts[-1][-1].ts <= gap:
            bursts[-1].append(ln)
        else:
            bursts.append([ln])
    return [Burst(tuple(b)) for b in bursts]


def assess(
    lines: Sequence[Line],
    *,
    now: datetime,
    benign: Sequence[Benign] = (),
    gap: timedelta = GAP,
    quiet: timedelta = QUIET,
    window: timedelta = VERDICT_WINDOW,
    recur_days: int = RECUR_DAYS,
    lookback_days: int = LOOKBACK_DAYS,
    unparsed: int = 0,
) -> Assessment:
    """The verdict over ``lines``.  Bursts and the count cover the last ``window``; recurrence
    looks at the whole ``lookback_days`` the caller supplied."""
    if now.tzinfo is None:
        raise ValueError("now is timezone-aware (UTC)")
    kept: list[Line] = []
    dropped = 0
    for ln in lines:
        if any(b.match in ln.text for b in benign):
            dropped += 1
        else:
            kept.append(ln)
    floor = now - timedelta(days=lookback_days)
    kept = [ln for ln in kept if floor <= ln.ts <= now]
    days_of: dict[str, set[str]] = {}
    for ln in kept:
        days_of.setdefault(shape_of(ln.text), set()).add(ln.ts.strftime("%Y-%m-%d"))
    recurring = tuple(sorted((s, len(d)) for s, d in days_of.items() if len(d) >= recur_days))
    recent = [ln for ln in kept if ln.ts >= now - window]
    bursts = tuple(cluster(recent, gap))
    last = recent[-1].ts if recent else None
    age = now - last if last else None
    if not recent and not recurring:
        verdict = "CLEAN"
    elif recurring or (age is not None and age <= quiet):
        verdict = "ONGOING"
    else:
        verdict = "RECOVERED"
    return Assessment(verdict, bursts, last, age, len(recent), dropped, unparsed, recurring)


def _age(delta: timedelta) -> str:
    mins = int(delta.total_seconds() // 60)
    if mins < 60:
        return f"{mins}m ago"
    if mins < 1440:
        return f"{mins // 60}h{mins % 60:02d}m ago"
    return f"{mins // 1440}d{(mins % 1440) // 60}h ago"


def render(a: Assessment, *, now: datetime, max_shapes: int = 5) -> str:
    """The digest text: the verdict line first, then each burst with its distinct shapes."""
    if a.verdict == "CLEAN":
        head = "No error lines in the window."
    else:
        word = "ONGOING (needs attention)" if a.ongoing else "RECOVERED (no action)"
        last = _age(a.age) if a.age is not None else "outside the window"
        head = f"{a.count} error line(s) in {len(a.bursts)} burst(s), last {last}: {word}."
    out = [head]
    if a.recurring:
        out.append("Recurring (a shape on 3 or more distinct days is one standing fault):")
        out += [f"  {days} days  {s}" for s, days in a.recurring]
    for i, b in enumerate(a.bursts, 1):
        out.append(
            f"Burst {i}/{len(a.bursts)}: {len(b.lines)} line(s) over {b.seconds}s from "
            f"{b.start.strftime('%Y-%m-%d %H:%M:%S')}Z ({_age(now - b.end)})"
        )
        for s in b.shapes()[:max_shapes]:
            out.append(f"    x{s.count:<3} {s.shape[:140]}")
            out.append(f"         e.g.: {s.example[:140]}")
    if a.dropped_benign:
        out.append(f"{a.dropped_benign} line(s) matched the benign list and were dropped.")
    if a.unparsed:
        out.append(f"{a.unparsed} line(s) without a readable timestamp were not clustered.")
    if a.verdict == "RECOVERED":
        out.append(
            "All of the above stopped and nothing recurs: treat as transient unless it repeats."
        )
    return "\n".join(out)


def _read(path: Path) -> list[str]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:  # type: ignore[operator]
        return fh.read().splitlines()


#: the words an error line carries (the old audit's grep, case-insensitive)
SEVERITY = re.compile(r"error|fail|crit|warn", re.IGNORECASE)


def main(argv: Sequence[str] | None = None, *, now: datetime | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hnx logbursts", description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--log",
        action="append",
        required=True,
        metavar="FILE",
        help="a log (.gz read too); repeatable",
    )
    ap.add_argument("--benign", metavar="FILE", help="the reviewed benign list (YAML)")
    ap.add_argument(
        "--var",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="a value for a placeholder the benign list names",
    )
    ap.add_argument(
        "--match",
        default=SEVERITY.pattern,
        help="regular expression selecting error lines (default: error|fail|crit|warn, case-insensitive)",
    )
    ap.add_argument("--since-hours", type=float, default=VERDICT_WINDOW.total_seconds() / 3600)
    ap.add_argument("--gap-minutes", type=float, default=GAP.total_seconds() / 60)
    ap.add_argument("--quiet-minutes", type=float, default=QUIET.total_seconds() / 60)
    ap.add_argument("--recur-days", type=int, default=RECUR_DAYS)
    ap.add_argument("--lookback-days", type=int, default=LOOKBACK_DAYS)
    ap.add_argument("--json", action="store_true", help="print the verdict as JSON")
    ns = ap.parse_args(argv)
    now = now or datetime.now(UTC)
    variables: dict[str, str] = {}
    for item in ns.var:
        name, sep, value = item.partition("=")
        if not sep or not _NAME.match(name):
            print(f"hnx logbursts: --var wants NAME=VALUE, got {item!r}", file=sys.stderr)
            return 2
        variables[name] = value
    try:
        benign = load_benign(ns.benign, variables) if ns.benign else []
        pattern = re.compile(ns.match, re.IGNORECASE)
    except (BenignError, re.error) as exc:
        print(f"hnx logbursts: {exc}", file=sys.stderr)
        return 2
    raw: list[str] = []
    for p in ns.log:
        try:
            raw += _read(Path(p))
        except (OSError, EOFError) as exc:
            print(f"hnx logbursts: cannot read {p}: {exc}", file=sys.stderr)
            return 100
    lines, bad = parse_lines(ln for ln in raw if pattern.search(ln))
    a = assess(
        lines,
        now=now,
        benign=benign,
        gap=timedelta(minutes=ns.gap_minutes),
        quiet=timedelta(minutes=ns.quiet_minutes),
        window=timedelta(hours=ns.since_hours),
        recur_days=ns.recur_days,
        lookback_days=ns.lookback_days,
        unparsed=bad,
    )
    if ns.json:
        print(
            json.dumps(
                {
                    "verdict": a.verdict,
                    "count": a.count,
                    "bursts": len(a.bursts),
                    "recurring": [list(r) for r in a.recurring],
                    "dropped_benign": a.dropped_benign,
                    "unparsed": a.unparsed,
                },
                sort_keys=True,
            )
        )
    else:
        print(render(a, now=now))
    return 1 if a.ongoing else 0


if __name__ == "__main__":
    sys.exit(main())
