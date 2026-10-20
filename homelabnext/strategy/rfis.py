# SPDX-License-Identifier: Apache-2.0
"""RFIs from gaps, and the decider of the strategy records' intents.

A gap raises an RFI: a measure graded red or not measurable, or an unmet requirement (one whose
supported objectives roll up red, or whose dated LTIOV has passed while it is still active).
:func:`gaps` lists the candidates that no open RFI (and no pending intent) already covers, with
a mechanical triage suggestion: a finding (no data) is a **collection** requirement, a red grade
(the data is there, the answer is not) a **production** requirement.  :func:`raise_intents`
files them as ``strategy-rfi`` notes through the records library -- the inbox is an agent's only
lane -- exactly as a lesson's status change is a ``register-transition`` note.

:class:`StrategyDecider` (``hnx strategy decide``) is the registers' transition decider
(:class:`homelabnext.registers.transitions.TransitionDecider`) over the strategy tree, deciding
two intent types under the same lock, with the same outcomes (applied, denied, waiting,
invalid) and the same crash recovery:

* ``strategy-rfi`` -- the raised_by record must exist and have no open RFI already; applied,
  it creates ``rfis/RFI-NEW-<slug>.md`` (status open, the triage, the LTIOV: the note's, else
  the doctrine's ``rfi_default_ltiov_days`` after it was filed; ``hnx ids resolve`` numbers it);
* ``strategy-transition`` -- ``from`` must be current and ``to`` a status the record's lifecycle
  reaches from it (:data:`homelabnext.strategy.rules.LIFECYCLE`); applied, a ``transition``
  event whose ``set.resolution`` is the intent's reason, once the review policy's tiers for the
  target are met by current reviews of the prospective content (else waiting).

:func:`sweep` is the LTIOV expiry: every open RFI (and active requirement) whose dated LTIOV is
before ``today`` gets a ``strategy-transition`` intent to ``expired``, filed by the sweep's own
identity and decided at once.  A no-find is a valid closed outcome (``to: no-find``, the search
being the reason), not a failure.
"""

from __future__ import annotations

import datetime as dt
import pathlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from homelabnext.records import Records, RecordsReader, check_filename, slugify
from homelabnext.records.decider import APPROVED
from homelabnext.registers.records import render_record
from homelabnext.registers.schema import RegisterError
from homelabnext.registers.transitions import Outcome, TransitionDecider

from .doctrine import Doctrine, load_doctrine
from .measure import Grade, rollup
from .records import (
    ARTEFACT,
    Tree,
    dir_for,
    load_tree,
    record_digest,
    write_events,
    write_new_record,
)
from .rules import LIFECYCLE, _active, validate

__all__ = [
    "RAISE_TYPE",
    "SWEEP_AGENT",
    "TRANSITION_TYPE",
    "Gap",
    "StrategyDecider",
    "expiring",
    "gaps",
    "raise_intents",
    "sweep",
]

RAISE_TYPE = "strategy-rfi"
TRANSITION_TYPE = "strategy-transition"
SWEEP_AGENT = "profile:ltiov-sweep"


@dataclass(frozen=True)
class Gap:
    raised_by: str
    triage: str  # collection | production
    title: str
    question: str
    why: str


def _date(v: Any) -> dt.date | None:
    if isinstance(v, dt.date):
        return v
    try:
        return dt.date.fromisoformat(str(v))
    except ValueError:
        return None


def _pending(records_root, note_type: str, field: str) -> set[str]:
    """``field`` of every ``note_type`` intent still in the inbox or approved lane (read
    leniently: a malformed note is the decider's to report, never a reason to stop)."""
    if records_root is None:
        return set()
    reader = RecordsReader(records_root)
    out = set()
    for lane in ("inbox", APPROVED):
        for name in reader.list(lane):
            try:
                note = reader.read(lane, name)
            except (OSError, ValueError):
                continue
            if note.type == note_type:
                out.add(str(note.frontmatter.get(field)))
    return out


def gaps(tree: Tree, grades: Mapping[str, Grade], today: dt.date, records_root=None) -> list[Gap]:
    """The gaps no open RFI or pending ``strategy-rfi`` intent covers yet."""
    covered = {str(r.get("raised_by")) for r in tree.of("rfis").values() if _active(r)}
    covered |= _pending(records_root, RAISE_TYPE, "raised_by")
    out: list[Gap] = []
    for k, g in sorted(grades.items()):
        m = tree.of("measures")[k]
        if g.state not in ("red", "unmeasured") or k in covered:
            continue
        if g.state == "unmeasured":
            out.append(
                Gap(
                    k,
                    "collection",
                    f"Make {k} measurable",
                    f"What data would let {k} ({m.get('title')}) be measured, and where can it be collected?",
                    g.finding or "not measurable",
                )
            )
        else:
            out.append(
                Gap(
                    k,
                    "production",
                    f"Why is {k} red",
                    f"Why is {k} ({m.get('title')}) at {g.value:g} against its target, and what would move it?",
                    f"red at {g.observed_at}",
                )
            )
    states = rollup(tree, grades)
    for k, r in sorted(tree.of("requirements").items()):
        if not _active(r) or k in covered:
            continue
        red = [s for s in r.get("supports") or () if states.get(str(s), {}).get("state") == "red"]
        lt = _date(r.get("ltiov"))
        if red or (lt and lt < today):
            why = f"supports {', '.join(red)} (red)" if red else f"LTIOV {lt} passed"
            q = str(r.get("question") or r.get("title")).strip().split("\n")[0]
            out.append(Gap(k, "production", f"{k} is unmet", f"{q} (unmet: {why})", why))
    return out


def raise_intents(
    gaps_: list[Gap], records_root, *, agent: str, clock: Callable[[], dt.datetime]
) -> list[pathlib.Path]:
    """File one ``strategy-rfi`` note per gap in the records inbox, as ``agent``."""
    rec = Records(records_root, clock, agent=agent)
    paths = []
    for g in gaps_:
        note = {
            "type": RAISE_TYPE,
            "title": g.title,
            "raised_by": g.raised_by,
            "question": g.question,
            "triage": g.triage,
        }
        paths.append(rec.submit(note, body=f"Gap: {g.why}\n", slug=slugify(g.title)))
    return paths


def expiring(tree: Tree, today: dt.date, within_days: int) -> list[tuple[str, dt.date]]:
    """Open RFIs whose LTIOV falls within ``within_days`` of ``today`` (or has passed)."""
    out = []
    for k, r in sorted(tree.of("rfis").items()):
        lt = _date(r.get("ltiov"))
        if _active(r) and lt and (lt - today).days <= within_days:
            out.append((k, lt))
    return sorted(out, key=lambda kv: (kv[1], kv[0]))


class StrategyDecider(TransitionDecider):
    """The registers' decider, over a strategy tree (see the module docstring)."""

    INTENT_TYPES = (TRANSITION_TYPE, RAISE_TYPE)

    def __init__(self, strategy_root, records_root, *, doctrine: Doctrine | None = None, **kw):
        super().__init__(strategy_root, records_root, **kw)
        self.doctrine = doctrine or load_doctrine(strategy_root)

    def _record_path(self, ident: str) -> pathlib.Path:
        return self.register_root / str(dir_for(ident) or "unknown") / f"{ident}.md"

    def _decide_note(self, name: str, note, dry_run: bool) -> Outcome:
        fm = note.frontmatter
        bad = check_filename(name, fm)
        if bad:
            return self._deny(name, str(fm.get("record", "?")), "; ".join(bad), dry_run)
        if note.type == RAISE_TYPE:
            return self._raise(name, note, dry_run)
        return self._transition(name, fm, dry_run)

    # --- strategy-rfi ---------------------------------------------------------------------------

    def _raised(self, tree: Tree, name: str) -> str | None:
        ref = f"decided/completed/{name}"
        return next((k for k, r in tree.of("rfis").items() if r.get("intent") == ref), None)

    def _raise(self, name: str, note, dry_run: bool) -> Outcome:
        fm = note.frontmatter
        src = str(fm["raised_by"])
        tree = load_tree(self.register_root)
        if done := self._raised(tree, name):  # created before a crash; finish the move
            if not dry_run:
                self.movers.fulfil(name, reason=f"raised: {done}")
            return Outcome(name, done, "applied", "already raised")
        target = tree.get(src)
        if target is None or not _active(target):
            return self._deny(name, src, f"{src} is not an active measure or requirement", dry_run)
        dup = next(
            (k for k, r in tree.of("rfis").items() if _active(r) and r.get("raised_by") == src),
            None,
        )
        if dup:
            return self._deny(name, src, f"{dup} is already open for {src}", dry_run)
        created = str(fm["created"])[:10]
        ltiov = fm.get("ltiov") or (
            dt.date.fromisoformat(created) + dt.timedelta(days=self.doctrine.rfi_default_ltiov_days)
        )
        entry: dict[str, Any] = {
            "id": "RFI-NEW",
            "title": str(fm["title"]),
            "status": "open",
            "date": dt.date.fromisoformat(created),
            "author": str(fm["requesting_agent"]),
            "raised_by": src,
            "triage": str(fm["triage"]),
            "ltiov": _date(ltiov),
            "intent": f"decided/completed/{name}",
            "question": str(fm["question"]).strip(),
        }
        if fm.get("tasked_to"):
            entry["tasked_to"] = list(fm["tasked_to"])
        taken = {p.name for p in (self.register_root / "rfis").glob("*.md")}
        rel = f"rfis/{_new_name(entry, taken)}"
        if dry_run:
            return Outcome(name, src, "applied", f"would create {rel} (dry run)")
        try:
            write_new_record(self.register_root, rel, render_record(entry, "rfis"))
        except RegisterError as ex:
            return self._deny(name, src, "; ".join(ex.problems), dry_run)
        self.movers.fulfil(name, reason=f"raised: {rel}")
        return Outcome(name, src, "applied", f"raised {rel} ({entry['triage']})")

    def _finish(self, name: str, ident: str, dry_run: bool) -> Outcome:
        try:
            note = self.reader.read(APPROVED, name)
        except (OSError, ValueError):
            note = None
        if note is not None and note.type == RAISE_TYPE:
            done = self._raised(load_tree(self.register_root), name)
            if not done:
                return Outcome(name, "?", "gone", "approved outside the decider; nothing raised")
            if not dry_run:
                self.movers.fulfil(name, reason=f"raised: {done}")
            return Outcome(name, done, "applied", "already raised")
        return super()._finish(name, ident, dry_run)

    # --- strategy-transition --------------------------------------------------------------------

    def _transition(self, name: str, fm: Mapping[str, Any], dry_run: bool) -> Outcome:
        ident = str(fm["record"])
        path = self._record_path(ident)
        if not path.is_file():
            return self._deny(name, ident, f"no record {ident} in {path.parent.name}/", dry_run)
        intent_ref = f"decided/completed/{name}"
        if done := self._applied_before(name, ident, path, dry_run):
            return done
        tree = load_tree(self.register_root)
        kind = path.parent.name
        entry = tree.of(kind).get(ident) or {}
        cur = entry.get("status")
        if fm["from"] != cur:
            return self._deny(
                name, ident, f"`from: {fm['from']}` is no longer current: {ident} is {cur}", dry_run
            )
        reach = LIFECYCLE[kind].get(str(cur), ())
        if fm["to"] not in reach:
            what = ", ".join(reach) or "nothing (it is closed)"
            return self._deny(
                name, ident, f"{ident} goes from {cur} to {what}, not {fm['to']}", dry_run
            )
        now = self.clock()
        event = {
            "event": "transition",
            "by": self.decided_by,
            "date": now.astimezone(dt.UTC).date(),
            "from": cur,
            "to": fm["to"],
            "set": {"resolution": str(fm["reason"]).strip()},
            "intent": intent_ref,
            "requested_by": fm["requesting_agent"],
            "reason": str(fm["reason"]).strip(),
        }
        rel = f"{kind}/{path.name}"
        try:
            after = load_tree(self.register_root, new_events={rel: [(event, now)]})
        except RegisterError as ex:
            return self._deny(name, ident, "; ".join(ex.problems), dry_run)
        prospective = after.of(kind)[ident]
        digest = record_digest(prospective)
        report = validate(
            after, doctrine=self.doctrine, policy=self.policy or False, require_reviews=False
        )
        if report.errors:
            return self._deny(name, ident, "; ".join(report.errors), dry_run, digest)
        missing = self._missing_tiers(prospective, kind, str(fm["to"]), digest)
        if missing:
            why = f"needs {', '.join(missing)} review(s) of the prospective content {digest}"
            return Outcome(name, ident, "waiting", why, digest)
        if dry_run:
            return Outcome(name, ident, "applied", "would apply (dry run)", digest)
        written = write_events(self.register_root, {path: [(event, now)]}, _decider=True)
        self.movers.fulfil(name, reason=f"applied: {written[0].name}")
        return Outcome(name, ident, "applied", f"{cur} -> {fm['to']}", digest, written[0].name)

    def _missing_tiers(self, entry: Mapping[str, Any], kind: str, state: str, digest: str):
        from homelabnext.reviews import evaluate

        if self.policy is None:
            return []
        res = evaluate(
            entry.get("reviews"),
            author=entry.get("author"),
            digest=digest,
            artefact=ARTEFACT[kind],
            state=state,
            policy=self.policy,
        )
        return res.missing


def _new_name(entry: Mapping[str, Any], taken: set[str]) -> str:
    from homelabnext.registers.records import record_name

    return record_name(entry, "rfis", taken)


def sweep(
    strategy_root,
    records_root,
    *,
    today: dt.date,
    decided_by: str,
    clock: Callable[[], dt.datetime],
) -> tuple[list[pathlib.Path], list[Outcome], list[str]]:
    """The LTIOV sweep: an expiry intent for every open RFI and active requirement whose dated
    LTIOV is before ``today`` (filed as :data:`SWEEP_AGENT`), then every pending intent decided.
    Returns (intents filed, outcomes, placeholders skipped: an unnumbered record cannot be
    named by an intent until ``hnx ids resolve`` numbers it)."""
    tree = load_tree(strategy_root)
    rec = Records(records_root, clock, agent=SWEEP_AGENT)
    pending = _pending(records_root, TRANSITION_TYPE, "record")
    filed, skipped = [], []
    for kind, initial in (("rfis", "open"), ("requirements", "active")):
        for k, r in sorted(tree.of(kind).items()):
            lt = _date(r.get("ltiov"))
            if r.get("status") != initial or lt is None or lt >= today or k in pending:
                continue
            if str(r.get("id")).endswith("-NEW"):
                skipped.append(k)
                continue
            note = {
                "type": TRANSITION_TYPE,
                "title": f"Expire {k}: LTIOV {lt} passed",
                "record": k,
                "from": initial,
                "to": "expired",
                "reason": f"LTIOV {lt} passed on {today} without an answer",
            }
            filed.append(rec.submit(note, body="Filed by the LTIOV sweep.\n"))
    decider = StrategyDecider(strategy_root, records_root, decided_by=decided_by, clock=clock)
    return filed, decider.decide_all(), skipped
