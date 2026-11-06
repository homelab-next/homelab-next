# SPDX-License-Identifier: Apache-2.0
"""``MemoryAdmin``: the operator's retraction tool over agent memory (ADR-0037 decisions 12 to 14).

It lives outside :mod:`homelabnext.agent`, and nothing in ``homelabnext.agent``,
``homelabnext.broker`` or ``homelabnext.orchestration`` imports it (a test holds that); no broker
action reaches it (``hnx broker validate`` refuses the names ``memory.retract``, ``memory.lift``,
``memory.purge`` and ``memory.dependents``).  Every method takes ``by=``, an
:class:`~homelabnext.memory_admin.principal.OperatorPrincipal` that only ``hnx agent memory``
builds; a ``VerifiedProfile`` or a string raises ``TypeError``.

* :meth:`MemoryAdmin.dependents` is the dry run.  The **alias set** of a source comes only from
  platform-issued pairings, the ``pairs`` of stored pack exposures (a knowledge node's graph id,
  record uid and digests; an input item's uid and digest), closed transitively; never from
  anything a model or a feed wrote.  **Cited**: records whose closure reaches a denied name.
  **Exposed**: records that did not cite one, but whose pack rendered one, whose pack's memory
  block showed a revision already reached, or that cite such a revision; the walk repeats until a
  pass finds nothing new.  A truncated range record (its pack list cut at 256) is flagged, since
  the packs it no longer lists cannot be checked one by one.  It lists the affected owners,
  scopes and keys, and ``confirm``, a digest of the whole listing.
* :meth:`MemoryAdmin.retract` refuses a ``confirm`` that no longer matches the dry run, then
  appends one deny record per alias (``revision="all"``; ``"this"`` denies the one content
  digest) in its own transaction, **before anything else**; walks the exposure references,
  appending each reached revision to the denied-reach index until a pass adds nothing; then
  retires every live cited entry (and, with ``include_exposed``, every live exposed one), owner by
  owner, each with ``reason: retracted:<source>``.  A rerun finds the active retraction by source
  and revision and completes it without ``confirm``; a retraction that is complete changes
  nothing.
* :meth:`MemoryAdmin.lift` appends a lift record: the retraction's names and marks stop counting
  at once.  Nothing retired is restored.
* :meth:`MemoryAdmin.purge` retires the entry first if the purged revision is current, blanks the
  value in every record holding that digest (keeping ``value_digest``, ``sources`` and ``tlp``)
  and the cached entry, marks them ``purged``, and appends a ``purge`` record per key.
* :meth:`MemoryAdmin.restamp` recovers a log stamped in the future (decision 3): records stamped
  after now are re-stamped to now (the old stamp kept as ``restamped_from``), so writes resume.

Operator records are written in any scope, a platform scope included (ADR-0035 decision 10, as
ADR-0037 decision 17 amends it: ``fleet-ledger``'s sole writer is the fold, and the operator's
``retract`` and ``purge``).  They are not held to the scope caps, and a platform key retired here
compacts on its scope's next platform write.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from typing import Any

from homelabnext import tlp
from homelabnext.agent.deny import MEM_REF, active_retractions, parse_mem_ref
from homelabnext.agent.digest import digest_of
from homelabnext.agent.memory import (
    CLOCK_SKEW,
    EVENT_OPS,
    MemoryBackend,
    MemoryClockError,
    Record,
    Stored,
    _owner_key,
    _parse,
    _record,
    _stamp,
    _step,
    _stored,
    _union,
    _utcnow,
    fold,
    secret_types,
)
from homelabnext.agent.resolved import DIGEST, UID

from .principal import MemoryAdminError, require_operator

__all__ = ["MemoryAdmin"]

#: a graph node id (``lesson:<uid>``, ``doc:<slug>``): a knowledge item's platform-issued name
_GRAPH_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}:[^\s]{1,240}")
_REV_TARGET = re.compile(
    r"([a-z][a-z0-9]*(?:-[a-z0-9]+)*)/([a-z][a-z0-9]*(?:-[a-z0-9]+)*)@([1-9][0-9]{0,15})"
)
_REVISIONS = ("all", "this")
Mark = tuple[str, str, str, int, int]  # owner, scope, key, rev_from, rev


def _source(source: Any, revision: str) -> str:
    if revision not in _REVISIONS:
        raise MemoryAdminError(f"revision must be one of {list(_REVISIONS)}")
    if not isinstance(source, str) or not (
        DIGEST.fullmatch(source)
        or UID.fullmatch(source)
        or MEM_REF.fullmatch(source)
        or _GRAPH_ID.fullmatch(source)
    ):
        raise MemoryAdminError(
            "a source is a sha256 content digest, a record uid, a graph id or a mem: revision"
        )
    if revision == "this" and not DIGEST.fullmatch(source):
        raise MemoryAdminError("revision='this' denies one content digest: give a sha256 digest")
    return source


def _reason(reason: Any) -> str:
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
        raise MemoryAdminError("a reason is a non-empty line of at most 500 characters")
    if "\n" in reason or "\r" in reason:
        raise MemoryAdminError("a reason is one line")
    found = secret_types(reason)
    if found:
        raise MemoryAdminError(f"the reason holds a secret ({', '.join(found)}); nothing was done")
    return reason


def _state(stored: Stored) -> list[Record]:
    return [r for r in stored["log"] if r["op"] not in EVENT_OPS]


def _mark(owner: str, rec: Mapping[str, Any]) -> Mark:
    return (owner, rec["scope"], rec["key"], int(rec.get("rev_from", rec["rev"])), int(rec["rev"]))


def _marks(owner: str, rec: Mapping[str, Any]) -> list[Mark]:
    """The ``denied_reach`` mark of a reached record: none for a ``retire`` (a retired revision
    is in no memory block), so a completed retraction's own retirements add nothing."""
    return [] if rec["op"] == "retire" and not rec.get("compacted") else [_mark(owner, rec)]


class _Reached:
    """The revisions a walk has reached, by key (each a rev range)."""

    def __init__(self, marks: Iterable[Mark] = ()) -> None:
        self._by: dict[tuple[str, str, str], list[tuple[int, int]]] = {}
        self.update(marks)

    def update(self, marks: Iterable[Mark]) -> None:
        for o, s, k, lo, hi in marks:
            self._by.setdefault((o, s, k), []).append((lo, hi))

    def holds(self, owner: str, scope: str, key: str, rev: int) -> bool:
        return any(lo <= rev <= hi for lo, hi in self._by.get((owner, scope, key), ()))


def _exposure_names(ex: Mapping[str, Any]) -> tuple[set[str], list[set[str]]]:
    """What a stored exposure rendered (its identifiers and graph ids) and its pairings."""
    rendered = list(ex.get("rendered") or ())
    groups = []
    for g in ex.get("pairs") or ():
        names = set()
        for x in g:
            if isinstance(x, int) and 0 <= x < len(rendered):
                names.add(rendered[x])
            elif isinstance(x, str):
                names.add(x)
        groups.append(names)
    return set(rendered).union(*groups), groups


class MemoryAdmin:
    """Operator retraction, lift, purge and re-stamp over a
    :class:`~homelabnext.agent.memory.MemoryBackend`, across owners.  ``now`` is the clock (an
    aware UTC ``datetime``), as for ``MemoryStore``.  Never constructed by the agent runtime."""

    def __init__(
        self, backend: MemoryBackend, *, now: Callable[[], datetime] | None = None
    ) -> None:
        self._backend = backend
        self._now = now if now is not None else _utcnow

    # ------------------------------------------------------------ reading
    def _snapshot(self) -> dict[str, Stored]:
        at = _stamp(self._now())
        return {o: _stored(self._backend.load(o), at)[0] for o in self._backend.owners()}

    @staticmethod
    def _aliases(source: str, revision: str, snap: Mapping[str, Stored]) -> list[str]:
        """The alias set of ``source``: platform-issued pairings only (decision 13)."""
        names = {source}
        if revision == "this":
            return [source]
        groups = [g for st in snap.values() for ex in st["exposure"].values()
                  for g in _exposure_names(ex)[1]]  # fmt: skip
        grew = True
        while grew:
            grew = False
            for g in groups:
                if g & names and not g <= names:
                    names |= g
                    grew = True
        return sorted(names)

    @staticmethod
    def _walk(
        names: Iterable[str], snap: Mapping[str, Stored], marks: Iterable[Mark] = ()
    ) -> tuple[list[tuple[str, Record]], list[tuple[str, Record]]]:
        """``(cited, exposed)`` records across owners for the denied ``names``, walking exposure
        and memory references until a pass finds nothing new (``marks`` seeds the reached set)."""
        denied = set(names)
        cited: list[tuple[str, Record]] = []
        reached = _Reached(marks)
        rest: list[tuple[str, Record]] = []
        for owner, st in snap.items():
            for r in _state(st):
                if denied & set(r.get("closure") or ()):
                    cited.append((owner, r))
                    reached.update(_marks(owner, r))
                else:
                    rest.append((owner, r))
        shown: dict[tuple[str, str], tuple[set[str], list[str]]] = {}
        for owner, st in snap.items():
            for pid, ex in st["exposure"].items():
                shown[(owner, pid)] = (_exposure_names(ex)[0], list(ex.get("memory") or ()))
        exposed: list[tuple[str, Record]] = []
        found = True
        while found:  # until a pass finds nothing new
            found = False
            left = []
            for owner, r in rest:
                refs = [parse_mem_ref(c) for c in r.get("closure") or () if c.startswith("mem:")]
                hit = any(ref and reached.holds(*ref) for ref in refs)
                for pid in [r.get("pack_id"), *(r.get("pack_ids") or ())]:
                    rendered, memory = shown.get((owner, pid), (set(), []))
                    hit = hit or bool(denied & rendered)
                    for m in memory if not hit else ():
                        ref = parse_mem_ref(m)
                        hit = hit or bool(ref and reached.holds(*ref))
                if hit:
                    exposed.append((owner, r))
                    reached.update(_marks(owner, r))
                    found = True
                else:
                    left.append((owner, r))
            rest = left
        return cited, exposed

    @staticmethod
    def _row(owner: str, r: Mapping[str, Any], live: Mapping[tuple[str, str, str], int]) -> dict:
        row = {
            "owner": owner,
            "scope": r["scope"],
            "key": r["key"],
            "rev": r["rev"],
            "checked": bool(r.get("checked")),
            "live": live.get((owner, r["scope"], r["key"])) == r["rev"],
        }
        if "rev_from" in r:
            row["rev_from"] = r["rev_from"]
        if r.get("truncated"):
            row["truncated"] = True  # its unlisted packs could not be checked
        return row

    def dependents(self, source: str, *, by: Any, revision: str = "all") -> dict[str, Any]:
        """The dry run of ``retract(source, revision=)`` (see the module doc)."""
        require_operator(by)
        source = _source(source, revision)
        snap = self._snapshot()
        return self._listing(source, revision, snap, self._aliases(source, revision, snap))

    def _listing(
        self, source: str, revision: str, snap: Mapping[str, Stored], names: list[str]
    ) -> dict[str, Any]:
        cited, exposed = self._walk(names, snap)
        live = {
            (o, s, k): e["rev"]
            for o, st in snap.items()
            for s, keys in st["entries"].items()
            for k, e in keys.items()
            if e.get("status") == "live"
        }
        rows_c = [self._row(o, r, live) for o, r in cited]
        rows_e = [self._row(o, r, live) for o, r in exposed]
        listing = {
            "source": source,
            "revision": revision,
            "aliases": names,
            "cited": rows_c,
            "exposed": rows_e,
            "owners": sorted({r["owner"] for r in rows_c + rows_e}),
            "affected": {
                "cited": sorted({(r["owner"], r["scope"], r["key"]) for r in rows_c}),
                "exposed": sorted({(r["owner"], r["scope"], r["key"]) for r in rows_e}),
            },
        }
        listing["affected"] = {
            k: [{"owner": o, "scope": s, "key": key} for o, s, key in v]
            for k, v in listing["affected"].items()
        }
        listing["confirm"] = digest_of(listing)
        return listing

    # ------------------------------------------------------------ retract
    def retract(
        self,
        source: str,
        reason: str,
        *,
        by: Any,
        confirm: str | None = None,
        revision: str = "all",
        include_exposed: bool = False,
    ) -> dict[str, Any]:
        """Retract ``source`` (see the module doc).  Returns ``{deny_id, aliases, marks,
        retired: [{owner, scope, key, rev}], resumed}``."""
        who = require_operator(by)
        source = _source(source, revision)
        reason = _reason(reason)
        if not isinstance(include_exposed, bool):
            raise TypeError("include_exposed must be True or False")

        def active(log: list[dict]) -> str | None:
            for deny_id, recs in active_retractions(log).items():
                if (recs[0].get("source"), recs[0].get("revision")) == (source, revision):
                    return deny_id
            return None

        deny_id = active(self._backend.load_deny()["log"])
        resumed = deny_id is not None
        if deny_id is None:
            snap = self._snapshot()
            names = self._aliases(source, revision, snap)
            plan = self._listing(source, revision, snap, names)
            if confirm != plan["confirm"]:
                raise MemoryAdminError(
                    "confirm does not match what dependents returns now: run the dry run again "
                    "and pass its confirm digest; nothing was done"
                )
            at = _stamp(self._now())
            got: list[str] = []

            def add(deny: dict[str, list[dict]]) -> dict[str, list[dict]]:
                got.clear()
                existing = active(deny["log"])  # a concurrent run got there first
                if existing is not None:
                    got.append(existing)
                    return deny
                seed = f"{source}\0{revision}\0{len(deny['log'])}\0{at}"
                new_id = "deny:" + hashlib.sha256(seed.encode()).hexdigest()[:16]
                got.append(new_id)
                deny["log"] += [
                    {"op": "retract", "deny_id": new_id, "at": at, "source": source,
                     "revision": revision, "name": name, "reason": reason, "by": who.user}
                    for name in names
                ]  # fmt: skip
                return deny

            self._backend.transact_deny(add)  # the deny records first, in their own transaction
            deny_id = got[0]
        records = active_retractions(self._backend.load_deny()["log"])[deny_id]
        names = sorted({r["name"] for r in records})
        marks = self._reach(deny_id, names)
        retired = self._retire_all(deny_id, names, f"retracted:{source}", who.user, include_exposed)
        return {
            "deny_id": deny_id,
            "aliases": names,
            "marks": marks,
            "retired": retired,
            "resumed": resumed,
        }

    def _reach(self, deny_id: str, names: list[str]) -> int:
        """Record every revision the retraction reaches in the denied-reach index, until a pass
        adds nothing new (a write that lands meanwhile is caught by the next pass)."""
        while True:
            deny = self._backend.load_deny()
            have = {_tuple(m) for m in deny["reach"] if m.get("deny_id") == deny_id}
            cited, exposed = self._walk(names, self._snapshot(), have)
            new = sorted({m for o, r in cited + exposed for m in _marks(o, r)} - have)
            if not new:
                return len(have)

            def add(d: dict[str, list[dict]], new: list[Mark] = new) -> dict[str, list[dict]]:
                there = {_tuple(m) for m in d["reach"] if m.get("deny_id") == deny_id}
                d["reach"] += [
                    {"deny_id": deny_id, "owner": o, "scope": s, "key": k, "rev_from": lo,
                     "rev": hi}
                    for o, s, k, lo, hi in new
                    if (o, s, k, lo, hi) not in there
                ]  # fmt: skip
                return d

            self._backend.transact_deny(add)

    def _retire_all(
        self, deny_id: str, names: list[str], reason: str, user: str, include_exposed: bool
    ) -> list[dict[str, Any]]:
        """Retire, owner by owner, every live entry built on the denied names (decision 13)."""
        retired: list[dict[str, Any]] = []
        for owner in self._backend.owners():

            def fn(raw: Any, deny: dict[str, list[dict]], owner: str = owner) -> Stored:
                now = _stamp(self._now())
                stored, _ = _stored(raw, now)
                marks = {_tuple(m) for m in deny["reach"] if m.get("deny_id") == deny_id}
                cited, exposed = self._walk(names, {owner: stored}, marks)
                hit = cited + (exposed if include_exposed else [])
                targets = _since_add(stored, {(r["scope"], r["key"], id(r)) for _, r in hit})
                out = _retire(stored, sorted(targets), now, reason, user, owner)
                if not out:  # nothing live left to retire: leave the owner as it was
                    raise _NoChange
                retired.extend({"owner": owner, **t} for t in out)
                return stored

            with contextlib.suppress(_NoChange):
                self._backend.transact(owner, fn)
        return retired

    # ------------------------------------------------------------ lift
    def lift(self, source: str, reason: str, *, by: Any, dry_run: bool = False) -> dict[str, Any]:
        """Lift every active retraction of ``source``: a lift record each; their marks stop
        counting at once, and nothing retired is restored."""
        who = require_operator(by)
        reason = _reason(reason)
        if not isinstance(source, str):
            raise MemoryAdminError("a source is a string")
        ids = [d for d, recs in active_retractions(self._backend.load_deny()["log"]).items()
               if recs[0].get("source") == source]  # fmt: skip
        if dry_run or not ids:
            return {"lifted": [], "active": ids, "dry_run": dry_run}
        at = _stamp(self._now())
        got: list[str] = []

        def add(deny: dict[str, list[dict]]) -> dict[str, list[dict]]:
            live = active_retractions(deny["log"])
            got[:] = [d for d in ids if d in live]
            deny["log"] += [
                {"op": "lift", "deny_id": d, "at": at, "source": source, "reason": reason,
                 "by": who.user}
                for d in got
            ]  # fmt: skip
            return deny

        self._backend.transact_deny(add)
        return {"lifted": list(got), "active": [], "dry_run": False}

    # ------------------------------------------------------------ purge
    def purge(
        self, owner: str, target: str, reason: str, *, by: Any, dry_run: bool = False
    ) -> dict[str, Any]:
        """Purge a value from ``owner``'s memory (``"*"`` with a digest: every owner holding it).
        ``target`` is a ``value_digest`` or ``<scope>/<key>@<rev>``.  Returns ``{purged: [{owner,
        scope, key, revs, retired}], dry_run}``."""
        who = require_operator(by)
        reason = _reason(reason)
        rev_target = _REV_TARGET.fullmatch(target) if isinstance(target, str) else None
        if not rev_target and not (isinstance(target, str) and DIGEST.fullmatch(target)):
            raise MemoryAdminError("a purge target is a sha256 value digest or <scope>/<key>@<rev>")
        if owner == "*":
            if rev_target:
                raise MemoryAdminError('owner "*" takes a value digest, not <scope>/<key>@<rev>')
            owners = self._backend.owners()
        else:
            _owner_key(owner)
            if owner not in self._backend.owners():
                raise MemoryAdminError(f"{owner} holds no memory")
            owners = [owner]
        done: list[dict[str, Any]] = []
        for o in owners:

            def fn(raw: Any, deny: Any, o: str = o) -> Stored:
                now = _stamp(self._now())
                stored, _ = _stored(raw, now)
                hits = _purge(stored, target, rev_target, now, reason, who.user, o, dry_run)
                done.extend({"owner": o, **h} for h in hits)
                if dry_run or not hits:
                    raise _NoChange
                return stored

            with contextlib.suppress(_NoChange):
                self._backend.transact(o, fn)
        return {"purged": done, "dry_run": dry_run}

    # ------------------------------------------------------------ restamp
    def restamp(self, owner: str, reason: str, *, by: Any, dry_run: bool = False) -> dict[str, Any]:
        """Re-stamp ``owner``'s records stamped after now (a host clock that was wrong forward
        and has been corrected, ADR-0037 decision 3), so its writes resume: each such ``at`` (and
        a folded record's ``since``) becomes now, the old stamp kept in ``restamped_from``, and a
        ``restamp`` record says who did it and why.  Returns ``{restamped: n, dry_run}``."""
        who = require_operator(by)
        reason = _reason(reason)
        _owner_key(owner)
        count: list[int] = []

        def fn(raw: Any, deny: Any) -> Stored:
            now = _stamp(self._now())
            stored, _ = _stored(raw, now)
            n = 0
            for r in stored["log"]:
                moved = {
                    f: r[f] for f in ("at", "since") if isinstance(r.get(f), str) and r[f] > now
                }
                if moved:
                    n += 1
                    r.setdefault("restamped_from", {}).update(moved)
                    r.update(dict.fromkeys(moved, now))
            count.append(n)
            if dry_run or not n:
                raise _NoChange
            stored["log"].append(
                {"at": now, "scope": None, "key": None, "op": "restamp", "rev": 0, "count": n,
                 "reason": reason, "by": who.user, "pack_id": None, "sources": [],
                 "checked": False, "tlp": "red", "closure": []}
            )  # fmt: skip
            stored["entries"] = fold(stored["log"])
            return stored

        with contextlib.suppress(_NoChange):
            self._backend.transact(owner, fn)
        return {"restamped": count[-1] if count else 0, "dry_run": dry_run}


class _NoChange(Exception):
    """Raised inside a transaction to leave the owner's memory as it was (a dry run)."""


def _tuple(m: Mapping[str, Any]) -> Mark:
    return (m["owner"], m["scope"], m["key"], int(m.get("rev_from", m["rev"])), int(m["rev"]))


def _since_add(stored: Stored, hit: set[tuple[str, str, int]]) -> set[tuple[str, str]]:
    """The live keys of ``stored`` with a hit record since their last ``add``."""
    out: set[tuple[str, str]] = set()
    seen: dict[tuple[str, str], bool] = {}
    for r in _state(stored):
        k = (r["scope"], r["key"])
        if r["op"] == "add" and not r.get("compacted"):
            seen[k] = False
        if (r["scope"], r["key"], id(r)) in hit:
            seen[k] = True
    for (scope, key), was in seen.items():
        if was and (stored["entries"].get(scope, {}).get(key) or {}).get("status") == "live":
            out.add((scope, key))
    return out


def _clock(stored: Stored, now: str, owner: str) -> tuple[str, dict[str, int]]:
    latest, high = "", {}
    for r in stored["log"]:
        latest = max(latest, r["at"])
        if r["op"] == "aged":
            high[r["scope"]] = r["rev"]
    if latest > now and _parse(latest) - _parse(now) > CLOCK_SKEW:
        raise MemoryClockError(owner, _parse(latest) - _parse(now))
    return max(now, latest), high


def _last(stored: Stored, scope: str, key: str) -> Record | None:
    found = None
    for r in _state(stored):
        if (r["scope"], r["key"]) == (scope, key):
            found = r
    return found


def _retire(
    stored: Stored, keys: list[tuple[str, str]], now: str, reason: str, user: str, owner: str
) -> list[dict[str, Any]]:
    """Append an operator ``retire`` record (``reason``, ``by``) for each live key; returns what
    it retired.  The label stays the entry's, and the closure carries over."""
    if not keys:
        return []
    at, high = _clock(stored, now, owner)
    out = []
    for scope, key in keys:
        cur = stored["entries"][scope][key]
        if cur.get("status") != "live":
            continue  # idempotent: already retired
        last = _last(stored, scope, key)
        rev = max(cur["rev"], high.get(scope, 0)) + 1
        rec = _record(at, scope, key, "retire", rev, cur.get("value"), None, keep_value=False)
        rec.update(tlp=cur.get("tlp", "red"), reason=reason, by=user)
        entry = _step(cur, rec)
        rec["closure"] = _union((last or {}).get("closure") or (), entry["sources"])
        stored["log"].append(rec)
        stored["entries"][scope][key] = entry
        out.append({"scope": scope, "key": key, "rev": rev})
    return out


def _purge(
    stored: Stored,
    target: str,
    rev_target: re.Match[str] | None,
    now: str,
    reason: str,
    user: str,
    owner: str,
    dry_run: bool,
) -> list[dict[str, Any]]:
    """Purge ``target`` from ``stored`` in place (see :meth:`MemoryAdmin.purge`)."""
    state = _state(stored)
    if rev_target:
        scope, key, rev = rev_target.group(1), rev_target.group(2), int(rev_target.group(3))
        held = [r for r in state if (r["scope"], r["key"]) == (scope, key)
                and r.get("rev_from", r["rev"]) <= rev <= r["rev"]]  # fmt: skip
        if not held:
            return []
        digest = held[0].get("value_digest") if not held[0].get("compacted") else None
        match = [r for r in state if r is held[0] or (digest and r.get("value_digest") == digest)]
    else:
        digest = target
        match = [r for r in state if r.get("value_digest") == digest
                 or digest in (r.get("value_digests") or ())]  # fmt: skip
    if not match:
        return []
    keys = sorted({(r["scope"], r["key"]) for r in match})
    hits = []
    for scope, key in keys:
        cur = stored["entries"].get(scope, {}).get(key) or {}
        last = _last(stored, scope, key)
        current = cur.get("status") == "live" and last is not None and any(r is last for r in match)
        hits.append({
            "scope": scope, "key": key,
            "revs": sorted(r["rev"] for r in match if (r["scope"], r["key"]) == (scope, key)),
            "retired": current,
        })  # fmt: skip
    if dry_run:
        return hits
    for h in hits:  # a current revision is retired first
        if h["retired"]:
            _retire(stored, [(h["scope"], h["key"])], now, f"purged:{reason}", user, owner)
    at, _ = _clock(stored, now, owner)
    for r in match:
        r.pop("value", None)  # the value goes; value_digest, sources and tlp stay
        r["purged"] = True
    for h in hits:
        recs = [r for r in match if (r["scope"], r["key"]) == (h["scope"], h["key"])]
        rec: Record = {
            "at": at, "scope": h["scope"], "key": h["key"], "op": "purge", "rev": max(h["revs"]),
            "pack_id": None, "sources": [], "checked": False,
            "tlp": str(tlp.strictest(r["tlp"] for r in recs)), "closure": [],
            "reason": reason, "by": user,
        }  # fmt: skip
        if digest:
            rec["value_digest"] = digest
        stored["log"].append(rec)
        key_log = [r for r in stored["log"] if (r["scope"], r["key"]) == (h["scope"], h["key"])]
        folded = fold(key_log).get(h["scope"], {}).get(h["key"])
        if folded is not None:
            stored["entries"].setdefault(h["scope"], {})[h["key"]] = folded
    return hits
