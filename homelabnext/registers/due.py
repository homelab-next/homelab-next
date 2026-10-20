# SPDX-License-Identifier: Apache-2.0
"""``hnx registers review``: what the lesson review should do today.

An active lesson of either kind is backlog: knowledge not yet built into the system.  Pitfalls
graduate into mechanisms (an invariant, a test, a gate: ``retired_by``); practices graduate
into procedures (a runbook step or a system page: ``incorporated_into``).  The review drains that
backlog, and this module says what is due, grouped by action, for a given ``today``:

  review       the record's status needs reviews it lacks (by tier: agent check, challenge
               agent, human approve), e.g. after an edit made its reviews stale
  retire       a controlled pitfall whose ``retired_by`` candidate already holds (every invariant
               it names passes in the results file, every path exists)
  incorporate  a due active practice, with the active runbooks sharing its systems/applies_to
               tags as candidate destinations
  supersede    a due active practice with a newer active practice for the same technology
  update       a due active practice with nowhere to go yet, or a due runbook (methods change)
  keep         a due pitfall that cannot graduate yet: work it, or bump ``review_by``

Each graduating suggestion names the review tiers the target status will need.  Warnings: a
practice incorporated into a runbook that does not cite it back (``from_lessons``).  Output is
deterministic for a fixed ``today``: actions in the order above, records by id.
"""

from __future__ import annotations

import datetime as dt
import pathlib
from dataclasses import dataclass, field

from homelabnext.reviews import evaluate

from .schema import (
    CRIT_REF,
    is_active,
    record_digest_of,
    sync_warnings,
    validate_lessons,
    validate_runbooks,
)

__all__ = ["ACTIONS", "Due", "Report", "review"]

ACTIONS = ("review", "retire", "incorporate", "supersede", "update", "keep")


@dataclass(frozen=True)
class Due:
    action: str
    id: str
    title: str
    reason: str


@dataclass
class Report:
    today: dt.date
    items: list[Due] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def by_action(self) -> dict[str, list[Due]]:
        return {
            a: sorted((d for d in self.items if d.action == a), key=lambda d: d.id) for a in ACTIONS
        }

    def lines(self) -> list[str]:
        out = [f"lesson review as of {self.today}: {len(self.items)} item(s) due"]
        for action, rows in self.by_action().items():
            if rows:
                out.append(f"{action}:")
                out += [f"  {d.id} {d.title}: {d.reason}" for d in rows]
        if self.warnings:
            out.append("warnings:")
            out += [f"  {w}" for w in self.warnings]
        return out

    def as_json(self) -> dict:
        return {
            "today": self.today.isoformat(),
            "due": {a: [d.__dict__ for d in rows] for a, rows in self.by_action().items()},
            "warnings": self.warnings,
        }


def _d(v) -> dt.date | None:
    if isinstance(v, dt.date):
        return v
    try:
        return dt.date.fromisoformat(str(v))
    except ValueError:
        return None


def _due(e, today) -> bool:
    rb = _d(e.get("review_by"))
    return rb is not None and rb <= today


def _eval(e, artefact, state, policy):
    return evaluate(
        e.get("reviews"),
        author=e.get("author"),
        digest=record_digest_of(e),
        artefact=artefact,
        state=state,
        policy=policy,
    )


def _needs(e, artefact, state, policy) -> str:
    if policy is None:
        return ""
    missing = _eval(e, artefact, state, policy).missing
    return f"; {state} will need {', '.join(missing)}" if missing else ""


def _mechanism_holds(refs, results, root: pathlib.Path) -> bool:
    res = (results or {}).get("results", {})
    for ref in refs:
        if CRIT_REF.match(ref):
            if res.get(ref, {}).get("status") != "pass":
                return False
        elif not ref.startswith("make:") and not (root / ref).is_file():
            return False
    return bool(refs)


def review(sources: dict, today: dt.date | None = None) -> Report:
    """The due list for ``sources`` (:func:`homelabnext.registers.render.load_sources`) as of
    ``today`` (default: the local date).

    Structure is validated fatally; missing reviews are reported here rather than raised, so a
    register whose reviews went stale can still be reviewed.
    """
    today = today or dt.date.today()
    policy, root = sources.get("policy"), pathlib.Path(sources.get("root") or ".")
    ll = validate_lessons(sources["lessons"]) if sources.get("lessons") else []
    rb = validate_runbooks(sources["runbooks"]) if sources.get("runbooks") else []
    rep = Report(today)
    add = rep.items.append
    active_rb = [r for r in rb if is_active(r, "runbooks")]
    for e in ll:
        art = f"lesson.{e['kind']}"
        if policy is not None:
            missing = _eval(e, art, e["status"], policy).missing
            if missing:
                add(Due("review", e["id"], e["title"], "missing " + ", ".join(missing)))
        if not is_active(e):
            continue
        if e["kind"] == "pitfall":
            cand = e.get("retired_by") or []
            if e["status"] == "controlled" and _mechanism_holds(cand, sources.get("results"), root):
                why = f"retired_by {', '.join(cand)} already holds"
                add(Due("retire", e["id"], e["title"], why + _needs(e, art, "retired", policy)))
            elif _due(e, today):
                hint = (
                    "name the mechanism that would retire it in `retired_by`"
                    if e["status"] == "controlled"
                    else "still unsolved: work it"
                )
                add(
                    Due(
                        "keep",
                        e["id"],
                        e["title"],
                        f"review_by {e['review_by']}; {hint}, or bump review_by",
                    )
                )
            continue
        if not _due(e, today):
            continue
        tags = set(e["systems"]) | set(e["applies_to"])
        newer = sorted(
            o["id"]
            for o in ll
            if o is not e
            and o["kind"] == "practice"
            and o["status"] == "active"
            and set(o["applies_to"]) & set(e["applies_to"])
            and _d(o["date"]) > _d(e["date"])
        )
        homes = sorted(r["id"] for r in active_rb if set(r["systems"]) & tags)
        if newer:
            why = f"newer practice {', '.join(newer)} covers {', '.join(sorted(e['applies_to']))}"
            add(Due("supersede", e["id"], e["title"], why + _needs(e, art, "superseded", policy)))
        elif homes:
            why = f"candidate runbook(s) {', '.join(homes)}"
            add(
                Due(
                    "incorporate", e["id"], e["title"], why + _needs(e, art, "incorporated", policy)
                )
            )
        else:
            add(
                Due(
                    "update",
                    e["id"],
                    e["title"],
                    f"review_by {e['review_by']}; no runbook shares its tags",
                )
            )
    for r in rb:
        state = "active" if is_active(r, "runbooks") else "superseded"
        if policy is not None:
            missing = _eval(r, "runbook", state, policy).missing
            if missing:
                add(Due("review", r["id"], r["title"], "missing " + ", ".join(missing)))
        if state == "active" and _due(r, today):
            add(
                Due(
                    "update",
                    r["id"],
                    r["title"],
                    f"review_by {r['review_by']}; methods and tools change",
                )
            )
    rep.warnings = sync_warnings(ll, rb)
    return rep
