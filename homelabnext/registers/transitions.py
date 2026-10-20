# SPDX-License-Identifier: Apache-2.0
"""Lifecycle transitions: agents file intents, one decider applies them.

Nobody edits a record's ``status`` to move it through its lifecycle.  An agent files an intent
through the records library (``homelabnext.records``: the inbox is the only lane an agent
writes), a note of type ``register-transition``::

    type: register-transition
    title: Retire LL-001, M-17 holds
    requesting_agent: profile:example-checker
    created: 2026-10-19T09:30:00Z
    record: LL-001
    from: controlled             # the status the agent saw
    to: retired
    retired_by: [M-17]           # or incorporated_into: [...] / superseded_by: LL-007
    on: 2026-10-19               # retired_on (default: the day the intent was created)
    reason: M-17 has held in every run since the control shipped

:class:`TransitionDecider` (``hnx registers decide``) evaluates each one, under a lock, against
the record as it is *now* and the review policy:

* ``from`` is not the record's current status (another intent got there first, or the agent
  read a stale copy): **denied**, with the reason, into ``decided/denied/``;
* the transition would leave an invalid record (a retired_by that does not resolve, a field the
  target status does not take): **denied**, naming the problems;
* the policy's tiers for the target status are not met by current reviews of the *prospective*
  content (the record as it will be once the transition applies; its digest is printed, so a
  reviewer can stamp it): **waiting**, the note stays in the inbox;
* otherwise **applied**: a ``transition`` event (the only writer of those) in the record's
  sidecar, then the note is approved and completed (``decided/completed/``), each move with its
  audit sidecar.  A transition the policy lets agents make (no human tier) therefore applies as
  soon as its agent reviews exist, and one that needs a human approve waits for a current human
  ``approve`` review event.

Two conflicting intents for one record (both retiring it with a different ``retired_by``, or one
holding a stale ``from``): the first decided applies, and the second is denied because its
``from`` is no longer current.  Applying is idempotent: a crash after the event was written and
before the note moved is finished, not re-decided, on the next run.

This is a library and a command, not a service: run it when convenient (by hand, from CI, from
a timer).  Like ``homelabnext.records.decider`` it is the decision maker's tool, and its
enforcement is filesystem ownership of the records ``decided/`` lanes and of the register files.
"""

from __future__ import annotations

import datetime as dt
import pathlib
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

from homelabnext.records import RecordsReader, check_filename
from homelabnext.records.decider import Decider
from homelabnext.state import file_lock

from . import events as ev
from .records import load_register
from .schema import RegisterError, record_digest_of

__all__ = ["INTENT_TYPE", "Outcome", "TransitionDecider", "prospective"]

INTENT_TYPE = "register-transition"
LOCK_NAME = ".register-transitions.lock"  # in the records root: serializes every apply
_SET_FIELDS = ("retired_by", "incorporated_into", "superseded_by")


@dataclass
class Outcome:
    note: str
    record: str
    result: str  # applied | denied | waiting | gone
    reason: str
    digest: str | None = None
    event: str | None = None

    def line(self) -> str:
        d = f" [{self.digest[:19]}]" if self.digest and self.result == "waiting" else ""
        return f"{self.result:8} {self.record} {self.note}: {self.reason}{d}"

    def as_json(self) -> dict[str, Any]:
        return asdict(self)


def _set_of(fm: Mapping[str, Any], entry: Mapping[str, Any], register: str) -> tuple[dict, list]:
    """The lifecycle fields the intent sets, and what is wrong with them."""
    to, problems, out = fm["to"], [], {}
    given = {k: fm[k] for k in _SET_FIELDS if k in fm}
    if register == "runbooks":
        wanted = {"superseded": ("superseded_by",)}.get(to)
    elif entry.get("kind") == "practice":
        wanted = {
            "incorporated": ("incorporated_into",),
            "superseded": ("superseded_by",),
            "retired": (),
        }.get(to, ())
    else:
        wanted = {"retired": ("retired_by",)}.get(to, ())
    if wanted is None:
        return {}, [f"a runbook transitions only to superseded, not {to}"]
    for k in given:
        if k not in wanted:
            problems.append(f"`{k}` does not belong to a transition to {to}")
    for k in wanted:
        if k not in given:
            problems.append(f"a transition to {to} needs `{k}`")
        else:
            out[k] = given[k]
    if to == "retired" and register == "lessons":
        on = fm.get("on") or str(fm["created"])[:10]
        out["retired_on"] = on if isinstance(on, dt.date) else dt.date.fromisoformat(str(on))
        if entry.get("kind") == "practice":
            out["retired_reason"] = str(fm["reason"]).strip()
    elif "on" in fm:
        problems.append("`on` (retired_on) belongs to a retirement only")
    return out, problems


def prospective(entry: Mapping[str, Any], event: Mapping[str, Any], register: str) -> dict:
    """The record as it will load once ``event`` (a transition) applies."""
    out = dict(entry)
    ev.apply_transition(out, event, register)
    return out


class TransitionDecider:
    def __init__(
        self,
        register_root,
        records_root,
        *,
        decided_by: str,
        policy=None,
        clock: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.UTC),
    ):
        from homelabnext.reviews import identity

        if identity(decided_by) is None:
            raise ValueError("decided_by is an issuer-qualified identity (human:operator)")
        self.register_root = pathlib.Path(register_root)
        self.records_root = pathlib.Path(records_root)
        self.decided_by = decided_by
        self.clock = clock
        self.reader = RecordsReader(self.records_root)
        self.movers = Decider(self.records_root, decided_by=decided_by, clock=clock)
        self._policy = policy

    @property
    def policy(self):
        if self._policy is None:
            from homelabnext.reviews import load_policy

            from .render import find_policy

            pp = find_policy(self.register_root)
            self._policy = load_policy(pp) if pp else False
        return self._policy or None

    def pending(self) -> list[str]:
        return [n.name for n in self.reader.iter_notes("inbox", type=INTENT_TYPE)]

    def decide_all(self, *, dry_run: bool = False) -> list[Outcome]:
        return [self.decide(n, dry_run=dry_run) for n in self.pending()]

    def _record_path(self, ident: str) -> pathlib.Path:
        kind = "lessons" if ident.startswith("LL-") else "runbooks"
        return self.register_root / kind / f"{ident}.md"

    def decide(self, name: str, *, dry_run: bool = False) -> Outcome:
        self.records_root.mkdir(parents=True, exist_ok=True)
        with file_lock(self.records_root / LOCK_NAME):
            return self._decide(name, dry_run)

    def _decide(self, name: str, dry_run: bool) -> Outcome:
        if name not in self.reader.list("inbox"):
            return Outcome(name, "?", "gone", "no longer in the inbox (decided elsewhere)")
        note = self.reader.read("inbox", name)
        fm = note.frontmatter
        ident = str(fm.get("record", "?"))
        if note.type != INTENT_TYPE:
            return Outcome(name, ident, "gone", f"a {note.type} note, not a {INTENT_TYPE}")
        bad = check_filename(name, fm)
        if bad:
            return self._deny(name, ident, "; ".join(bad), dry_run)
        path = self._record_path(ident)
        register = path.parent.name
        if not path.is_file():
            return self._deny(name, ident, f"no record {ident} in {path.parent}", dry_run)
        intent_ref = f"decided/completed/{name}"
        problems: list[str] = []
        done = [
            e
            for e in ev.read_events(ev.events_dir(path), problems, path.name)
            if e.kind == "transition" and e.data.get("intent") == intent_ref
        ]
        if done:  # applied before a crash; finish the move
            if not dry_run:
                self.movers.fulfil(name, reason=f"applied: {done[0].name}")
            return Outcome(name, ident, "applied", "already applied", event=done[0].name)
        doc = load_register(path.parent, register)
        entry = next((e for e in doc[register] if str(e.get("id")) == ident), None)
        if entry is None:
            return self._deny(name, ident, f"{ident} is a tombstone", dry_run)
        cur = ev.current_status(entry, register)
        if fm["from"] != cur:
            why = f"`from: {fm['from']}` is no longer current: {ident} is {cur}"
            return self._deny(name, ident, why, dry_run)
        if fm["to"] == cur:
            return self._deny(name, ident, f"{ident} is already {cur}", dry_run)
        fields, problems = _set_of(fm, entry, register)
        if problems:
            return self._deny(name, ident, "; ".join(problems), dry_run)
        now = self.clock()
        event = {
            "event": "transition",
            "by": self.decided_by,
            "date": now.astimezone(dt.UTC).date(),
            "from": cur,
            "to": fm["to"],
            "intent": intent_ref,
            "requested_by": fm["requesting_agent"],
            "reason": str(fm["reason"]).strip(),
        }
        if fields:
            event["set"] = fields
        after = prospective(entry, event, register)
        digest = record_digest_of(after)
        from .write import check_register, write_events

        try:  # structure first: an invalid target is denied, not left waiting for reviews
            check_register(path, new_events=[(event, now)], policy=self.policy or False)
        except RegisterError as ex:
            return self._deny(name, ident, "; ".join(ex.problems), dry_run, digest)
        missing = self._missing(after, register, fm["to"], digest)
        if missing:
            why = f"needs {', '.join(missing)} review(s) of the prospective content {digest}"
            return Outcome(name, ident, "waiting", why, digest)
        if dry_run:
            return Outcome(name, ident, "applied", "would apply (dry run)", digest)
        try:
            written = write_events(path, [(event, now)], policy=self.policy or False, _decider=True)
        except RegisterError as ex:
            return self._deny(name, ident, "; ".join(ex.problems), dry_run, digest)
        self.movers.fulfil(name, reason=f"applied: {written[0].name}")
        return Outcome(name, ident, "applied", f"{cur} -> {fm['to']}", digest, written[0].name)

    def _missing(self, after: Mapping, register: str, state: str, digest: str) -> list[str]:
        from homelabnext.reviews import evaluate

        if self.policy is None:
            return []
        artefact = "runbook" if register == "runbooks" else f"lesson.{after.get('kind')}"
        res = evaluate(
            after.get("reviews"),
            author=after.get("author"),
            digest=digest,
            artefact=artefact,
            state=state,
            policy=self.policy,
        )
        return res.missing

    def _deny(self, name, ident, reason, dry_run, digest=None) -> Outcome:
        if not dry_run:
            self.movers.deny(name, reason)
        return Outcome(name, ident, "denied", reason, digest)
