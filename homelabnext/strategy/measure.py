# SPDX-License-Identifier: Apache-2.0
"""Measures: read each binding, grade the readings, roll the grades up the cascade.

A measure's ``source`` is a typed binding, read by :func:`read`:

=============================== ===================================================================
``invariant:<id>``              the invariants results file (``hnx invariants run --out``): 1 pass,
                                0 fail, ``checked_at`` the time; error/skip/missing is a finding
``status:<source>[/<item>]``    the status hub's state (``hnx status collect``): an item's value
                                (else 1 ok / 0 not), or the share of a source's items that are ok
``records:<lane>[?type=<t>]``   the number of notes in a records lane (``homelabnext.records``)
``manual``                      nothing is read: a person writes the ``value`` event (with evidence)
``none``                        not measurable: a finding (the record's Not measurable section)
=============================== ===================================================================

Each reading becomes a ``value`` event on the measure (append-only, so a trend exists;
:func:`value_event`), unless it repeats the latest one.  :func:`grade` turns a measure's readings
into a :class:`Grade` -- green / amber / red against the target, ``baseline`` for a cold start,
``unmeasured`` for a finding, ``pending`` before the first reading -- applying the doctrine:
the self-measured MOE cap, cold start, trends only on an unchanged definition, thinness.
:func:`rollup` folds grades up the cascade: an objective is the worst of its MOEs and of its
child objectives (its MOPs when none of those has a grade), so a red MOP shows where the work is
behind while the effect still says whether it is working.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

from .doctrine import Doctrine
from .records import Tree, definition_digest
from .rules import _active, self_measured

__all__ = [
    "Context",
    "Grade",
    "Reading",
    "grade",
    "grade_all",
    "read",
    "rollup",
    "value_event",
]

GRADED = ("green", "amber", "red")
#: rollup order: worst first wins; neutral states never hide a grade
SEVERITY = {"red": 5, "unmeasured": 5, "amber": 4, "green": 3, "baseline": 2, "pending": 1}
_RECORDS = re.compile(r"^(?P<lane>[a-z/]+)(?:\?type=(?P<type>[a-z-]+))?$")


@dataclass(frozen=True)
class Reading:
    """What one binding read: a value or a finding, when, how many data points, from where."""

    value: float | None
    finding: str | None
    observed_at: str
    sample: int
    evidence: str


@dataclass
class Context:
    """Where the bindings read from (every part optional; a missing one is a finding)."""

    now: dt.datetime
    results: Mapping[str, Any] | None = None  # invariants results document
    results_name: str = "the invariants results"
    snapshot: Mapping[str, Any] | None = None  # status hub snapshot
    records_root: pathlib.Path | None = None


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(ts: Any) -> dt.datetime | None:
    try:
        t = dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=dt.UTC)


def read(measure: Mapping[str, Any], ctx: Context) -> Reading | None:
    """One reading of ``measure``'s binding; None for ``manual`` (a person records it)."""
    src = str(measure.get("source") or "none")
    kind, _, arg = src.partition(":")
    now = _iso(ctx.now)
    if kind == "manual":
        return None
    if kind == "none":
        why = str(measure.get("not_measurable") or "not measurable").strip().split("\n\n")[0]
        return Reading(None, why, now, 0, src)
    if kind == "invariant":
        return _invariant(arg, src, ctx, now)
    if kind == "status":
        return _status(arg, src, ctx, now)
    return _records(arg, src, ctx, now)


def _invariant(ident: str, src: str, ctx: Context, now: str) -> Reading:
    res = ((ctx.results or {}).get("results") or {}).get(ident)
    if ctx.results is None:
        return Reading(None, "no invariants results to read", now, 0, src)
    if not isinstance(res, Mapping):
        return Reading(None, f"no result for invariant {ident} in {ctx.results_name}", now, 0, src)
    at = str(res.get("checked_at") or now)
    status = res.get("status")
    if status in ("pass", "fail"):
        return Reading(1.0 if status == "pass" else 0.0, None, at, 1, f"{src} {status} at {at}")
    return Reading(None, f"invariant {ident} is {status}, not pass or fail", at, 0, src)


def _status(arg: str, src: str, ctx: Context, now: str) -> Reading:
    if ctx.snapshot is None:
        return Reading(None, "no status hub state to read", now, 0, src)
    source, _, item = arg.partition("/")
    obs = [
        o
        for o in ctx.snapshot.get("observations") or ()
        if o.get("source") == source and (not item or o.get("item") == item)
    ]
    if not obs:
        st = next((s for s in ctx.snapshot.get("sources") or () if s.get("id") == source), {})
        why = f"status source {source} has no reading" + (f" of {item}" if item else "")
        state = st.get("state")
        return Reading(None, why + (f" (source {state})" if state else ""), now, 0, src)
    at = max(str(o.get("observed_at") or now) for o in obs)
    stale = [o for o in obs if o.get("state") in ("stale", "unknown")]
    if item:
        o = obs[0]
        v = o.get("value")
        value = float(v) if isinstance(v, int | float) else float(o.get("state") == "ok")
        return Reading(value, None, at, 0 if stale else 1, f"{src} {o.get('state')} at {at}")
    ok = sum(1 for o in obs if o.get("state") == "ok")
    return Reading(ok / len(obs), None, at, len(obs) - len(stale), f"{src}: {ok}/{len(obs)} ok")


def _records(arg: str, src: str, ctx: Context, now: str) -> Reading:
    from homelabnext.records import ALL_LANES
    from homelabnext.records.notes import NoteError, parse_note

    m = _RECORDS.match(arg)
    if ctx.records_root is None:
        return Reading(None, "no records root to count", now, 0, src)
    if not m or m["lane"] not in ALL_LANES:
        return Reading(None, f"{arg} is not a records lane", now, 0, src)
    d = ctx.records_root / m["lane"]
    n = 0
    for p in sorted(d.glob("*.md")) if d.is_dir() else ():
        try:
            fm, _ = parse_note(p.read_text(encoding="utf-8"))
        except (OSError, NoteError):
            continue
        n += m["type"] is None or fm.get("type") == m["type"]
    return Reading(float(n), None, now, 1, f"{src}: {n} note(s) at {now}")


def value_event(
    measure: Mapping[str, Any], reading: Reading, by: str, now: dt.datetime
) -> dict[str, Any] | None:
    """The ``value`` event for ``reading``, or None when it repeats the latest one (same data,
    same definition: re-running a measurement adds nothing)."""
    ev: dict[str, Any] = {"event": "value", "by": by, "date": now.astimezone(dt.UTC).date()}
    ev["value" if reading.finding is None else "finding"] = (
        reading.value if reading.finding is None else reading.finding
    )
    ev.update(
        observed_at=reading.observed_at,
        sample=reading.sample,
        definition_digest=definition_digest(measure),
        definition_version=measure.get("definition_version"),
        evidence=reading.evidence,
    )
    last = (measure.get("values") or [None])[-1]
    # the same data under the same definition adds nothing; nor does a finding repeated
    keys = ("value", "finding", "definition_digest")
    keys += ("observed_at",) if reading.finding is None else ()
    if last and all(_same(last.get(k), ev.get(k)) for k in keys):
        return None
    return ev


def _same(a: Any, b: Any) -> bool:
    if isinstance(a, int | float) and isinstance(b, int | float):
        return float(a) == float(b)
    return str(a) == str(b) if a is not None and b is not None else a is b


# --- grading ------------------------------------------------------------------------------------


@dataclass
class Grade:
    measure: str
    state: str  # green | amber | red | baseline | unmeasured | pending
    value: float | None = None
    observed_at: str | None = None
    finding: str | None = None
    confidence: str | None = None
    thin: str | None = None  # why the reading is thin, else None
    trend: str | None = None  # up | down | flat | re-baseline
    capped: bool = False  # a self-measured MOE held at the cap
    readings: int = 0

    def as_json(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


def _target(v: float, target: Mapping[str, Any]) -> str:
    ops: dict[str, Callable[[float, float], bool]] = {
        ">=": lambda a, b: a >= b,
        "<=": lambda a, b: a <= b,
        "==": lambda a, b: a == b,
    }
    op = ops[str(target.get("op"))]
    if op(v, float(target["green"])):
        return "green"
    if "amber" in target and op(v, float(target["amber"])):
        return "amber"
    return "red"


def grade(measure: Mapping[str, Any], tree: Tree, doctrine: Doctrine, now: dt.datetime) -> Grade:
    """The measure's current grade from its recorded readings (and the doctrine)."""
    ident = str(measure.get("id"))
    values = list(measure.get("values") or ())
    conf = measure.get("confidence")
    if measure.get("source") == "none":
        why = read(measure, Context(now)).finding  # type: ignore[union-attr]
        return Grade(ident, "unmeasured", finding=why, confidence="low", readings=len(values))
    if not values:
        return Grade(ident, "pending", confidence=conf, readings=0)
    last = values[-1]
    out = Grade(ident, "pending", observed_at=str(last.get("observed_at")), confidence=conf)
    out.readings = len(values)
    if "value" not in last:
        out.state, out.finding, out.confidence = "unmeasured", str(last.get("finding")), "low"
        return out
    out.value = float(last["value"])
    digest = definition_digest(measure)
    same = [v for v in values if v.get("definition_digest") == digest and "value" in v]
    out.thin = _thin(measure, last, now)
    if out.thin:
        out.confidence = "low"
    if doctrine.on("trend_same_definition"):
        prior = [v for v in values[:-1] if "value" in v]
        if prior and prior[-1].get("definition_digest") != last.get("definition_digest"):
            out.trend = "re-baseline"
        elif len(same) >= 2:
            a, b = float(same[-2]["value"]), float(same[-1]["value"])
            out.trend = "up" if b > a else "down" if b < a else "flat"
    cold = doctrine.opt("cold_start_baseline", "readings")
    if last.get("definition_digest") != digest:
        out.state = "baseline"  # read under an older definition: the new one has no grade yet
        return out
    if doctrine.on("cold_start_baseline") and len(same) <= cold:
        out.state = "baseline"
        return out
    out.state = _target(out.value, measure.get("target") or {})
    if (
        doctrine.on("self_measured_moe_cap")
        and str(ident).startswith("MOE")
        and self_measured(measure, tree)
    ):
        cap = doctrine.opt("self_measured_moe_cap", "cap")
        if GRADED.index(out.state) < GRADED.index(cap):
            out.state, out.capped = cap, True
    return out


def _thin(measure: Mapping[str, Any], last: Mapping[str, Any], now: dt.datetime) -> str | None:
    th = measure.get("thinness") or {}
    sample = int(last.get("sample") or 0)
    if sample < int(th.get("min_sample", 1)):
        return f"{sample} data point(s) < {th.get('min_sample', 1)}"
    at = _parse(last.get("observed_at"))
    age = (now - at).total_seconds() / 3600 if at else None
    if th.get("max_age_h") and age is not None and age > float(th["max_age_h"]):
        return f"{age:.0f} h old > {th['max_age_h']} h"
    return None


def grade_all(tree: Tree, doctrine: Doctrine, now: dt.datetime) -> dict[str, Grade]:
    """Every active measure's grade, by measure key."""
    return {k: grade(m, tree, doctrine, now) for k, m in tree.of("measures").items() if _active(m)}


def worst(states: Sequence[str]) -> str:
    return max(states, key=lambda s: SEVERITY[s]) if states else "pending"


def rollup(tree: Tree, grades: Mapping[str, Grade]) -> dict[str, dict[str, Any]]:
    """Per active objective: ``state`` (the rollup), ``effect`` (its MOEs and children),
    ``performance`` (its MOPs) and ``children`` -- every SO's subtree, from the leaves up."""
    objectives = {k: o for k, o in tree.of("objectives").items() if _active(o)}
    kids: dict[str, list[str]] = {}
    for k, o in objectives.items():
        if o.get("parent"):
            kids.setdefault(str(o["parent"]), []).append(k)
    out: dict[str, dict[str, Any]] = {}

    def visit(k: str) -> str:
        if k in out:
            return out[k]["state"]
        o = objectives[k]
        ms = [str(m) for m in o.get("measures") or () if str(m) in grades]
        moe = [grades[m].state for m in ms if m.startswith("MOE")]
        mop = [grades[m].state for m in ms if m.startswith("MOP")]
        children = sorted(kids.get(k, ()))
        child_states = [visit(c) for c in children]
        effect = worst(moe + child_states)
        performance = worst(mop)
        state = effect if SEVERITY[effect] >= SEVERITY["green"] else worst([effect, performance])
        out[k] = {
            "state": "red" if state == "unmeasured" else state,
            "effect": effect,
            "performance": performance,
            "children": children,
            "measures": ms,
        }
        return out[k]["state"]

    for k in sorted(objectives):
        visit(k)
    return out


def load_results(path) -> tuple[dict[str, Any] | None, str]:
    p = pathlib.Path(path)
    if not p.is_file():
        return None, str(p)
    return json.loads(p.read_text(encoding="utf-8")), str(p)


def measure_all(
    root, ctx: Context, *, by: str, write: bool = True
) -> tuple[dict[str, dict[str, Any] | None], Tree]:
    """Read every active bound measure of the tree at ``root``; append the new readings as
    ``value`` events (one validated batch) unless ``write`` is false.  Returns {measure key:
    the event written, or None (manual, or a repeat of the latest reading)} and the tree as it
    is afterwards."""
    from .records import load_tree, write_events

    tree = load_tree(root)
    out: dict[str, dict[str, Any] | None] = {}
    batch: dict[pathlib.Path, list[tuple[dict[str, Any], dt.datetime]]] = {}
    for k, m in tree.of("measures").items():
        if not _active(m):
            continue
        r = read(m, ctx)
        e = value_event(m, r, by, ctx.now) if r is not None and m.get("source") != "none" else None
        out[k] = e
        if e is not None:
            batch[tree.paths[k]] = [(e, ctx.now)]
    if write and batch:
        write_events(root, batch)
        tree = load_tree(root)
    elif batch:
        tree = load_tree(root, new_events={_relpath(tree, p): v for p, v in batch.items()})
    return out, tree


def _relpath(tree: Tree, p: pathlib.Path) -> str:
    return p.resolve().relative_to(tree.root.resolve()).as_posix()
