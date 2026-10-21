# SPDX-License-Identifier: Apache-2.0
"""Lifecycle transitions: agents file intents, one decider applies them.

Nobody edits a record's ``status`` to move it through its lifecycle.  An agent files an intent
through the records library (``homelabnext.records``: the inbox is the only lane an agent
writes), a note of type ``register-transition``::

    type: register-transition
    title: Retire the stale-certificate lesson, M-17 holds
    requesting_agent: profile:example-checker
    created: 2026-10-19T09:30:00Z
    record: 0199d5a0-...         # the record's uid (a legacy code such as LL-001 still resolves
    from: controlled             # through the tree's aliases.yml, with a deprecation warning)
    to: retired
    retired_by: [M-17]           # or incorporated_into: [...] / superseded_by: <uid>
    retired_on: 2026-10-19       # optional (default: the day the intent was created)
    reason: M-17 has held in every run since the control shipped

(Not ``on:`` -- YAML 1.1 reads it as the boolean ``true``; a note with a non-string key is
invalid.)

:class:`TransitionDecider` (``hnx registers decide``) evaluates each one, under a lock, against
the record as it is *now* and the review policy:

* ``from`` is not the record's current status (another intent got there first, or the agent
  read a stale copy): **denied**, with the reason, into ``decided/denied/``;
* the transition would leave an invalid record (a retired_by that does not resolve, a field the
  target status does not take): **denied**, naming the problems;
* the policy's tiers for the target status are not met by current reviews of the *prospective*
  content (the record as it will be once the transition applies; its digest is printed, so a
  reviewer can stamp it): **waiting**, the note stays in the inbox;
* the note does not validate (a missing field, a boolean key): **invalid**, it stays in the
  inbox for its agent to fix or withdraw, and the other intents are decided as usual;
* otherwise **applied**: a ``transition`` event (the only writer of those) in the record's
  sidecar, then the note is approved and completed (``decided/completed/``), each move with its
  audit sidecar.  A transition the policy lets agents make (no human tier) therefore applies as
  soon as its agent reviews exist, and one that needs a human approve waits for a current human
  ``approve`` review event.

Two conflicting intents for one record (both retiring it with a different ``retired_by``, or one
holding a stale ``from``): the first decided applies, and the second is denied because its
``from`` is no longer current.  Applying is idempotent: a crash after the event was written and
before the note moved -- or between its two moves, approved and completed -- is finished, not
re-decided, on the next run (an intent found in ``decided/approved/`` whose event exists).

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

from homelabnext.identity.uid import is_uid
from homelabnext.records import RecordsReader, check_filename
from homelabnext.records.decider import APPROVED, Decider
from homelabnext.records.notes import NoteError, parse_note
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
    result: str  # applied | denied | waiting | invalid | error | gone
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
    if "on" in fm:  # only a quoted 'on' gets here (the 1.1 schema still lists it)
        problems.append("`on` is not read (YAML 1.1 makes it a boolean): use `retired_on`")
    if to == "retired" and register == "lessons":
        on = fm.get("retired_on") or str(fm["created"])[:10]
        try:
            out["retired_on"] = on if isinstance(on, dt.date) else dt.date.fromisoformat(str(on))
        except ValueError:
            problems.append(f"retired_on {on!r} is not a date")
        if entry.get("kind") == "practice":
            out["retired_reason"] = str(fm["reason"]).strip()
    elif "retired_on" in fm:
        problems.append("`retired_on` belongs to a retirement only")
    return out, problems


def prospective(entry: Mapping[str, Any], event: Mapping[str, Any], register: str) -> dict:
    """The record as it will load once ``event`` (a transition) applies."""
    out = dict(entry)
    ev.apply_transition(out, event, register)
    return out


class TransitionDecider:
    #: the note types this decider takes from the inbox (a subclass decides others:
    #: :class:`homelabnext.strategy.rfis.StrategyDecider`)
    INTENT_TYPES: tuple[str, ...] = (INTENT_TYPE,)

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

    def _intents(self, lane: str) -> list[str]:
        """The ``register-transition`` notes of ``lane``, by a lenient read of their ``type``
        only: another note, valid or not, is not the decider's to validate (one malformed note
        must never stop the others)."""
        out = []
        for name in self.reader.list(lane):
            try:
                fm, _ = parse_note((self.records_root / lane / name).read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, NoteError):
                continue
            if fm.get("type") in self.INTENT_TYPES:
                out.append(name)
        return out

    def pending(self) -> list[str]:
        """The intents to decide: the inbox's, then any left in ``decided/approved/`` by a crash
        between the two moves of an applied one."""
        return self._intents("inbox") + self._intents(APPROVED)

    def decide_all(self, *, dry_run: bool = False) -> list[Outcome]:
        """Every pending intent; one that fails to decide is its own ``error`` outcome, never
        the end of the run (a broken register is: :class:`RegisterError` propagates)."""
        out = []
        for n in self.pending():
            try:
                out.append(self.decide(n, dry_run=dry_run))
            except RegisterError:
                raise
            except (OSError, ValueError) as ex:
                why = f"{type(ex).__name__}: {ex}".replace("\n", " ")
                out.append(Outcome(n, "?", "error", why))
        return out

    def _resolve(self, ident: str) -> str:
        """A uid as is; a legacy code (``LL-001``) through the tree's alias map, with a
        :class:`~homelabnext.identity.aliases.LegacyRecordCode` warning (an intent filed
        before the uid migration still decides)."""
        from homelabnext.identity.aliases import load_aliases, resolve

        if is_uid(ident):
            return ident
        return resolve(ident, load_aliases(self.register_root), "register-transition record")

    def _record_path(self, ident: str) -> pathlib.Path:
        """The record file of a uid: ``lessons/<uid>.md`` or ``runbooks/<uid>.md``."""
        for kind in ("lessons", "runbooks"):
            if (p := self.register_root / kind / f"{ident}.md").is_file():
                return p
        return self.register_root / "lessons" / f"{ident}.md"

    def decide(self, name: str, *, dry_run: bool = False) -> Outcome:
        self.records_root.mkdir(parents=True, exist_ok=True)
        with file_lock(self.records_root / LOCK_NAME):
            return self._decide(name, dry_run)

    def _decide(self, name: str, dry_run: bool) -> Outcome:
        if name in self.reader.list("inbox"):
            lane = "inbox"
        elif name in self.reader.list(APPROVED):
            lane = APPROVED
        else:
            return Outcome(name, "?", "gone", "no longer in the inbox (decided elsewhere)")
        try:
            note = self.reader.read(lane, name)
        except (OSError, UnicodeDecodeError, ValueError) as ex:  # NoteError is a ValueError
            why = f"the note does not validate ({ex}); its agent must fix or withdraw it"
            return Outcome(name, "?", "invalid", why.replace("\n", " "))
        fm = note.frontmatter
        ident = str(fm.get("record", "?"))
        if note.type not in self.INTENT_TYPES:
            want = " or ".join(self.INTENT_TYPES)
            return Outcome(name, ident, "gone", f"a {note.type} note, not a {want}")
        if lane == APPROVED:
            return self._finish(name, ident, dry_run)
        return self._decide_note(name, note, dry_run)

    def _decide_note(self, name: str, note, dry_run: bool) -> Outcome:
        """An inbox intent of :attr:`INTENT_TYPES`, its file read and its type checked."""
        fm = note.frontmatter
        ident = self._resolve(str(fm.get("record", "?")))
        bad = check_filename(name, fm)
        if bad:
            return self._deny(name, ident, "; ".join(bad), dry_run)
        path = self._record_path(ident)
        register = path.parent.name
        if not path.is_file():
            return self._deny(name, ident, f"no record {ident} in {path.parent}", dry_run)
        intent_ref = f"decided/completed/{name}"
        if done := self._applied_before(name, ident, path, dry_run):
            return done
        doc = load_register(path.parent, register)
        entry = next((e for e in doc[register] if str(e.get("uid")) == ident), None)
        if entry is None:
            return self._deny(name, ident, f"no record {ident} in {path.parent}", dry_run)
        cur = ev.current_status(entry, register)
        if fm["from"] != cur:
            why = f"`from: {fm['from']}` is no longer current: {ident} is {cur}"
            return self._deny(name, ident, why, dry_run)
        if fm["to"] == cur:
            return self._deny(name, ident, f"{ident} is already {cur}", dry_run)
        fields, problems = _set_of(fm, entry, register)
        if problems:
            return self._deny(name, ident, "; ".join(problems), dry_run)
        if "superseded_by" in fields:  # an intent may still name the record by its legacy code
            fields["superseded_by"] = self._resolve(str(fields["superseded_by"]))
        if isinstance(fields.get("incorporated_into"), list):
            fields["incorporated_into"] = [
                self._resolve(r.partition("#")[0]) + "".join(r.partition("#")[1:])
                if not str(r).startswith("docs/")
                else r
                for r in map(str, fields["incorporated_into"])
            ]
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

    def _applied_before(self, name: str, ident: str, path: pathlib.Path, dry_run: bool):
        """The outcome for an intent whose transition event ``path`` already has (applied
        before a crash: finish the move, never apply twice), else None."""
        problems: list[str] = []
        ref = f"decided/completed/{name}"
        done = [
            e
            for e in ev.read_events(ev.events_dir(path), problems, path.name)
            if e.kind == "transition" and e.data.get("intent") == ref
        ]
        if not done:
            return None
        if not dry_run:
            self.movers.fulfil(name, reason=f"applied: {done[0].name}")
        return Outcome(name, ident, "applied", "already applied", event=done[0].name)

    def _finish(self, name: str, ident: str, dry_run: bool) -> Outcome:
        """An intent in ``decided/approved/``: complete it when its transition event exists (a
        crash between the moves of :meth:`Decider.fulfil`); one approved by hand is left."""
        ident = self._resolve(ident)
        path = self._record_path(ident)
        problems: list[str] = []
        ref = f"decided/completed/{name}"
        done = [
            e
            for e in (
                ev.read_events(ev.events_dir(path), problems, path.name) if path.is_file() else []
            )
            if e.kind == "transition" and e.data.get("intent") == ref
        ]
        if not done:
            return Outcome(name, ident, "gone", "approved outside the decider; nothing applied")
        if not dry_run:
            self.movers.fulfil(name, reason=f"applied: {done[0].name}")
        return Outcome(name, ident, "applied", "already applied", event=done[0].name)

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
