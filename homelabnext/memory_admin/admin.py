# SPDX-License-Identifier: Apache-2.0
"""``MemoryAdmin``: the operator's retraction tool over agent memory (ADR-0037 decisions 12 to 14,
amended 2026-11-06).

It lives outside :mod:`homelabnext.agent`, and nothing in ``homelabnext.agent``,
``homelabnext.broker`` or ``homelabnext.orchestration`` imports it (a test holds that); no broker
action reaches it (``hnx broker validate`` refuses the ``memory.*`` operator names).  Every method
takes ``by=``, an :class:`~homelabnext.memory_admin.principal.OperatorPrincipal` that only ``hnx
agent memory`` builds and that is re-checked against this process's uids on every call; a
``VerifiedProfile`` or a string raises ``TypeError``.  It writes only through the operator seam of
:mod:`homelabnext.agent.memory`.

* :meth:`MemoryAdmin.dependents` is the dry run.  The **alias set** comes only from
  platform-issued pairings, the ``pairs`` of stored pack exposures, and closes narrowly: a graph
  id to its uid (``node_uid``), a uid to its own digests (and its graph ids), a digest to the one
  uid it is paired with.  It never crosses from a digest to another uid: a digest paired with
  more than one uid anywhere in the store is listed under ``ambiguous`` and joins only with an
  explicit ``include_alias`` of each foreign uid, and a uid's digest that another uid shares is
  left out the same way.  A digest that resolves to no uid at all is a lone digest (``warnings``).
  **Cited**: records whose closure reaches a denied name, and, for a ``mem:`` source, the record
  holding that revision.  **Exposed**: records that did not cite one, but whose checked pack
  rendered one, whose pack's memory block showed a revision already reached, or that cite such a
  revision; repeated until a pass finds nothing new.  A ``truncated`` range record its sources
  reach is cited (its closure holds them) and listed once, flagged.  ``confirm`` is a digest
  of the whole listing, settings included.
* :meth:`MemoryAdmin.retract` refuses a ``confirm`` that no longer matches the dry run, then
  appends one deny record per alias (with the retraction's ``revision``, ``include_exposed`` and
  ``include_alias``) in its own transaction, **before anything else**; walks, appending each
  reached revision to the denied-reach index until a pass adds nothing; then retires every live
  cited entry (and, with ``include_exposed``, every live exposed one), owner by owner.  A rerun
  with the same settings completes it without ``confirm``; one that asks for other settings
  needs a fresh ``confirm``.  A lift that lands meanwhile stops it (:class:`MemoryAdminError`).
* :meth:`MemoryAdmin.lift` appends a lift record: names and marks stop counting.  Nothing
  retired is restored.
* :meth:`MemoryAdmin.purge` retires the entry first if the purged revision is current, blanks the
  value in every record holding it and in the cached entry, and replaces every digest of it
  (``value_digest``, a range's ``value_digests``, the purge record's) with one random
  ``purged:<hex>`` token, so no plaintext digest of a low-entropy value stays to be guessed; the
  dry run alone shows the digest.  A rerun finds nothing and appends nothing.
* :meth:`MemoryAdmin.restamp` recovers a log stamped in the future (decision 3); the dry run lists
  each from -> to, and applying it needs ``expect_now`` within the clock skew allowance.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
import secrets
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from typing import Any

from homelabnext import tlp
from homelabnext.agent.deny import (
    MEM_REF,
    Mark,
    active_retractions,
    parse_mem_ref,
    retraction_settings,
)
from homelabnext.agent.digest import digest_of
from homelabnext.agent.memory import (
    CLOCK_SKEW,
    MemoryBackend,
    Record,
    Stored,
    fold,
    last_record,
    log_clock,
    operator_retire,
    owner_key,
    secret_types,
    stamp,
    state_records,
    stored_of,
    utcnow,
)
from homelabnext.agent.pack import node_uid
from homelabnext.agent.resolved import DIGEST, UID

from .principal import MemoryAdminError, OperatorPrincipal, require_operator

__all__ = ["MemoryAdmin"]

#: a graph node id (``lesson:<uid>``, ``doc:<slug>``): a knowledge item's platform-issued name
_GRAPH_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}:[^\s]{1,240}")
_REV_TARGET = re.compile(
    r"([a-z][a-z0-9]*(?:-[a-z0-9]+)*)/([a-z][a-z0-9]*(?:-[a-z0-9]+)*)@([1-9][0-9]{0,15})"
)
_REVISIONS = ("all", "this")
_PURGED = "purged:"


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


def _uids(include_alias: Iterable[str] | None) -> list[str]:
    out = sorted(set(include_alias or ()))
    if any(not isinstance(u, str) or not UID.fullmatch(u) for u in out):
        raise MemoryAdminError("include_alias takes record uids")
    return out


def _reason(reason: Any) -> str:
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
        raise MemoryAdminError("a reason is a non-empty line of at most 500 characters")
    if "\n" in reason or "\r" in reason:
        raise MemoryAdminError("a reason is one line")
    found = secret_types(reason)
    if found:
        raise MemoryAdminError(f"the reason holds a secret ({', '.join(found)}); nothing was done")
    return reason


def _mark(owner: str, rec: Mapping[str, Any]) -> Mark:
    return (owner, rec["scope"], rec["key"], int(rec.get("rev_from", rec["rev"])), int(rec["rev"]))


def _marks(owner: str, rec: Mapping[str, Any]) -> list[Mark]:
    """The ``denied_reach`` mark of a reached record: none for a ``retire`` (a retired revision
    is in no memory block), so a completed retraction's own retirements add nothing."""
    return [] if rec["op"] == "retire" and not rec.get("compacted") else [_mark(owner, rec)]


def _tuple(m: Mapping[str, Any]) -> Mark:
    return (m["owner"], m["scope"], m["key"], int(m.get("rev_from", m["rev"])), int(m["rev"]))


def _holds(rec: Mapping[str, Any], rev: int) -> bool:
    return int(rec.get("rev_from", rec["rev"])) <= rev <= int(rec["rev"])


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


def _is_graph_id(x: str) -> bool:
    return bool(_GRAPH_ID.fullmatch(x)) and not DIGEST.fullmatch(x) and not x.startswith("mem:")


class _Pairings:
    """The store's platform-issued pairings: each item's anchor (its uid, else its graph id),
    its digests and its graph ids (ADR-0037 decision 13, amended)."""

    def __init__(self, snap: Mapping[str, Stored]) -> None:
        self.digest_anchors: dict[str, set[str]] = {}
        self.anchor_digests: dict[str, set[str]] = {}
        self.anchor_gids: dict[str, set[str]] = {}
        self.gid_anchor: dict[str, str] = {}
        for st in snap.values():
            for ex in st["exposure"].values():
                for g in _exposure_names(ex)[1]:
                    gids = {x for x in g if _is_graph_id(x)}
                    uids = {x for x in g if UID.fullmatch(x)}
                    uids |= {u for u in (node_uid(x) for x in gids) if u}
                    digests = {x for x in g if DIGEST.fullmatch(x)}
                    anchors = uids or gids
                    for a in anchors:
                        self.anchor_digests.setdefault(a, set()).update(digests)
                        self.anchor_gids.setdefault(a, set()).update(gids)
                    for d in digests:
                        self.digest_anchors.setdefault(d, set()).update(anchors)
                    for gid in gids:
                        self.gid_anchor[gid] = node_uid(gid) or gid

    def aliases(
        self, source: str, include: Iterable[str]
    ) -> tuple[list[str], list[dict[str, Any]], list[str]]:
        """``(names, ambiguous, warnings)`` for ``source`` under ``revision="all"``."""
        extra = set(include)
        warnings: list[str] = []
        ambiguous: list[dict[str, Any]] = []
        if MEM_REF.fullmatch(source):
            return [source], [], []
        if DIGEST.fullmatch(source):
            found = self.digest_anchors.get(source, set())
            if len(found) > 1:
                ambiguous.append({"digest": source, "uids": sorted(found)})
                anchors = found & extra
            else:
                anchors = set(found)
            if not found:
                warnings.append(
                    "revision='all' resolved this digest to no uid or graph id (a lone digest): "
                    "only the digest itself is denied"
                )
        elif UID.fullmatch(source):
            anchors = {source}
        else:  # a graph id: its uid, else itself
            anchors = {self.gid_anchor.get(source, node_uid(source) or source)}
        anchors |= extra
        names = {source, *anchors}
        for a in sorted(anchors):
            names |= self.anchor_gids.get(a, set())
            for d in self.anchor_digests.get(a, set()):
                foreign = self.digest_anchors.get(d, set()) - anchors
                if foreign:  # shared with a uid not in the set: never crossed silently
                    if not any(x["digest"] == d for x in ambiguous):
                        ambiguous.append({"digest": d, "uids": sorted(foreign)})
                else:
                    names.add(d)
        return sorted(names), sorted(ambiguous, key=lambda x: x["digest"]), warnings


class _NoChange(Exception):
    """Raised inside a transaction to leave the owner's memory as it was (a dry run)."""


class _Lifted(Exception):
    """The retraction was lifted while it ran."""


class MemoryAdmin:
    """Operator retraction, lift, purge and re-stamp over a
    :class:`~homelabnext.agent.memory.MemoryBackend`, across owners.  ``now`` is the clock (an
    aware UTC ``datetime``), as for ``MemoryStore``.  Never constructed by the agent runtime."""

    def __init__(
        self, backend: MemoryBackend, *, now: Callable[[], datetime] | None = None
    ) -> None:
        self._backend = backend
        self._now = now if now is not None else utcnow

    # ------------------------------------------------------------ reading
    def _snapshot(self) -> dict[str, Stored]:
        at = stamp(self._now())
        return {o: stored_of(self._backend.load(o), at) for o in self._backend.owners()}

    @staticmethod
    def _aliases(
        source: str, revision: str, snap: Mapping[str, Stored], include: Iterable[str] = ()
    ) -> tuple[list[str], list[dict[str, Any]], list[str]]:
        if revision == "this":
            return [source], [], []
        return _Pairings(snap).aliases(source, include)

    @staticmethod
    def _walk(
        names: Iterable[str], snap: Mapping[str, Stored], marks: Iterable[Mark] = ()
    ) -> tuple[list[tuple[str, Record]], list[tuple[str, Record]]]:
        """``(cited, exposed)`` records across owners for the denied ``names``, walking exposure
        and memory references until a pass finds nothing new (``marks`` seeds the reached set;
        a denied ``mem:`` revision seeds it too, and its own record is cited)."""
        denied = set(names)
        own = [ref for ref in (parse_mem_ref(n) for n in denied) if ref]
        reached = _Reached(marks)
        reached.update((o, s, k, r, r) for o, s, k, r in own)
        cited: list[tuple[str, Record]] = []
        rest: list[tuple[str, Record]] = []
        for owner, st in snap.items():
            for r in state_records(st):
                holds = any(
                    (o, s, k) == (owner, r["scope"], r["key"]) and _holds(r, rev)
                    for o, s, k, rev in own
                )
                if holds or denied & set(r.get("closure") or ()):
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
                # an unchecked (platform) record exposes nothing: its pack ids are provenance
                for pid in [r.get("pack_id"), *(r.get("pack_ids") or ())] if r["checked"] else ():
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
            row["truncated"] = True  # its unlisted pack ids could not be checked one by one
        return row

    def dependents(
        self,
        source: str,
        *,
        by: Any,
        revision: str = "all",
        include_exposed: bool = False,
        include_alias: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """The dry run of ``retract(source, revision=, include_exposed=, include_alias=)``."""
        require_operator(by)
        source = _source(source, revision)
        include = _uids(include_alias)
        snap = self._snapshot()
        return self._listing(source, revision, snap, include_exposed, include)

    def _listing(
        self,
        source: str,
        revision: str,
        snap: Mapping[str, Stored],
        include_exposed: bool,
        include: list[str],
    ) -> dict[str, Any]:
        names, ambiguous, warnings = self._aliases(source, revision, snap, include)
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

        def affected(rows: list[dict]) -> list[dict[str, str]]:
            keys = sorted({(r["owner"], r["scope"], r["key"]) for r in rows})
            return [{"owner": o, "scope": s, "key": k} for o, s, k in keys]

        listing = {
            "source": source,
            "revision": revision,
            "include_exposed": bool(include_exposed),
            "include_alias": include,
            "aliases": names,
            "ambiguous": ambiguous,
            "warnings": warnings,
            "cited": rows_c,
            "exposed": rows_e,
            "owners": sorted({r["owner"] for r in rows_c + rows_e}),
            "affected": {"cited": affected(rows_c), "exposed": affected(rows_e)},
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
        include_alias: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """Retract ``source`` (see the module doc).  Returns ``{deny_id, aliases, marks,
        retired: [{owner, scope, key, rev}], resumed}``."""
        who = require_operator(by)
        source = _source(source, revision)
        reason = _reason(reason)
        include = _uids(include_alias)
        if not isinstance(include_exposed, bool):
            raise TypeError("include_exposed must be True or False")
        wanted = {"include_exposed": include_exposed, "include_alias": include}

        def active(log: list[dict]) -> str | None:
            for deny_id, recs in active_retractions(log).items():
                if (recs[0].get("source"), recs[0].get("revision")) == (source, revision):
                    return deny_id
            return None

        log = self._backend.load_deny()["log"]
        deny_id = active(log)
        resumed = deny_id is not None
        if deny_id is None or retraction_settings(log, deny_id) != wanted:
            snap = self._snapshot()
            plan = self._listing(source, revision, snap, include_exposed, include)
            if confirm != plan["confirm"]:
                raise MemoryAdminError(
                    "confirm does not match what dependents returns now (with these settings): "
                    "run the dry run again and pass its confirm digest; nothing was done"
                )
            at = stamp(self._now())
            got: list[str] = []

            def add(deny: dict[str, list[dict]]) -> dict[str, list[dict]]:
                got.clear()
                existing = active(deny["log"])
                if existing is None:
                    seed = f"{source}\0{revision}\0{len(deny['log'])}\0{at}"
                    existing = "deny:" + hashlib.sha256(seed.encode()).hexdigest()[:16]
                    have: set[str] = set()
                else:
                    have = {r["name"] for r in active_retractions(deny["log"])[existing]}
                got.append(existing)
                common = {"deny_id": existing, "at": at, "source": source, "reason": reason,
                          "by": who.user, "by_sudo": who.by_sudo, **wanted}  # fmt: skip
                deny["log"] += [
                    {"op": "retract", "revision": revision, "name": n, **common}
                    for n in plan["aliases"]
                    if n not in have
                ]
                if have:  # a rerun that changed the settings (with a fresh confirm)
                    deny["log"].append({"op": "settings", **common})
                return deny

            self._backend.transact_deny(add)  # the deny records first, in their own transaction
            deny_id = got[0]
        try:
            records = active_retractions(self._backend.load_deny()["log"]).get(deny_id)
            if records is None:
                raise _Lifted
            names = sorted({r["name"] for r in records})
            marks = self._reach(deny_id, names)
            retired = self._retire_all(deny_id, names, f"retracted:{source}", who, include_exposed)
        except _Lifted:
            raise MemoryAdminError(
                f"retraction {deny_id} was lifted while it ran: it stopped there"
            ) from None
        return {
            "deny_id": deny_id,
            "aliases": names,
            "marks": marks,
            "retired": retired,
            "resumed": resumed,
        }

    def _reach(self, deny_id: str, names: list[str]) -> int:
        """Record every revision the retraction reaches in the denied-reach index, until a pass
        adds nothing new (a write that lands meanwhile is caught by the next pass).  Each pass
        reads every owner once."""
        while True:
            deny = self._backend.load_deny()
            if deny_id not in active_retractions(deny["log"]):
                raise _Lifted
            have = {_tuple(m) for m in deny["reach"] if m.get("deny_id") == deny_id}
            cited, exposed = self._walk(names, self._snapshot(), have)
            new = sorted({m for o, r in cited + exposed for m in _marks(o, r)} - have)
            if not new:
                return len(have)

            def add(d: dict[str, list[dict]], new: list[Mark] = new) -> dict[str, list[dict]]:
                if deny_id not in active_retractions(d["log"]):
                    raise _Lifted
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
        self,
        deny_id: str,
        names: list[str],
        reason: str,
        who: OperatorPrincipal,
        include_exposed: bool,
    ) -> list[dict[str, Any]]:
        """Retire, owner by owner, every live entry built on the denied names (decision 13),
        re-checking inside each transaction that the retraction is still active."""
        retired: list[dict[str, Any]] = []
        own = [ref for ref in (parse_mem_ref(n) for n in names) if ref]
        for owner in self._backend.owners():

            def fn(raw: Any, deny: dict[str, list[dict]], owner: str = owner) -> Stored:
                if deny_id not in active_retractions(deny["log"]):
                    raise _Lifted
                now = stamp(self._now())
                stored = stored_of(raw, now)
                marks = {_tuple(m) for m in deny["reach"] if m.get("deny_id") == deny_id}
                cited, exposed = self._walk(names, {owner: stored}, marks)
                hit = cited + (exposed if include_exposed else [])
                targets = _since_add(stored, {id(r) for _, r in hit}, owner, own)
                out = operator_retire(
                    stored, sorted(targets), now, reason=reason, by=who.user, owner=owner,
                    by_sudo=who.by_sudo,
                )  # fmt: skip
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
        at = stamp(self._now())
        got: list[str] = []

        def add(deny: dict[str, list[dict]]) -> dict[str, list[dict]]:
            live = active_retractions(deny["log"])
            got[:] = [d for d in ids if d in live]
            deny["log"] += [
                {"op": "lift", "deny_id": d, "at": at, "source": source, "reason": reason,
                 "by": who.user, "by_sudo": who.by_sudo}
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
        scope, key, revs, retired, digest?}], dry_run}`` (``digest`` only in a dry run)."""
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
            owner_key(owner)
            if owner not in self._backend.owners():
                raise MemoryAdminError(f"{owner} holds no memory")
            owners = [owner]
        token = _PURGED + secrets.token_hex(16)  # one token per purged value, never its digest
        done: list[dict[str, Any]] = []
        for o in owners:

            def fn(raw: Any, deny: Any, o: str = o) -> Stored:
                now = stamp(self._now())
                stored = stored_of(raw, now)
                hits = _purge(stored, target, rev_target, now, reason, who, o, dry_run, token)
                done.extend({"owner": o, **h} for h in hits)
                if dry_run or not hits:
                    raise _NoChange
                return stored

            with contextlib.suppress(_NoChange):
                self._backend.transact(o, fn)
        return {"purged": done, "dry_run": dry_run}

    # ------------------------------------------------------------ restamp
    def restamp(
        self,
        owner: str,
        reason: str,
        *,
        by: Any,
        dry_run: bool = False,
        expect_now: datetime | None = None,
    ) -> dict[str, Any]:
        """Re-stamp ``owner``'s records stamped after now (a host clock that was wrong forward
        and has been corrected, ADR-0037 decision 3): each such ``at`` (and a folded record's
        ``since``) becomes now, the old stamp kept in ``restamped_from``, with a ``restamp``
        record.  The dry run lists ``{from, to}`` per record; applying it needs ``expect_now``
        (what the operator believes the time is) within the clock skew allowance of the clock.
        Returns ``{restamped: n, changes: [...], dry_run}``."""
        who = require_operator(by)
        reason = _reason(reason)
        owner_key(owner)
        if not dry_run:
            if not isinstance(expect_now, datetime) or expect_now.tzinfo is None:
                raise MemoryAdminError("a restamp needs expect_now, the time you believe it is")
            off = abs(self._now() - expect_now)
            if off > CLOCK_SKEW:
                raise MemoryAdminError(
                    f"the clock is {off} away from expect_now (more than {CLOCK_SKEW}): fix the "
                    "clock before re-stamping"
                )
        changes: list[dict[str, str]] = []
        count: list[int] = [0]

        def fn(raw: Any, deny: Any) -> Stored:
            now = stamp(self._now())
            stored = stored_of(raw, now)
            changes.clear()
            count[0] = 0
            for r in stored["log"]:
                moved = {
                    f: r[f] for f in ("at", "since") if isinstance(r.get(f), str) and r[f] > now
                }
                if moved:
                    count[0] += 1
                    changes.extend({"field": f, "from": v, "to": now} for f, v in moved.items())
                    r.setdefault("restamped_from", {}).update(moved)
                    r.update(dict.fromkeys(moved, now))
            if dry_run or not changes:
                raise _NoChange
            stored["log"].append(
                {"at": now, "scope": None, "key": None, "op": "restamp", "rev": 0,
                 "count": count[0], "reason": reason, "by": who.user, "by_sudo": who.by_sudo,
                 "pack_id": None, "sources": [], "checked": False, "tlp": "red", "closure": []}
            )  # fmt: skip
            stored["entries"] = fold(stored["log"])
            return stored

        with contextlib.suppress(_NoChange):
            self._backend.transact(owner, fn)
        return {
            "restamped": count[0],
            "changes": changes,
            "dry_run": dry_run,
        }


def _since_add(
    stored: Stored, hit: set[int], owner: str, own: list[tuple[str, str, str, int]]
) -> set[tuple[str, str]]:
    """The live keys of ``stored`` with a hit record since their last ``add``; a key whose own
    revision is a denied ``mem:`` source only when that revision is current."""
    out: set[tuple[str, str]] = set()
    seen: dict[tuple[str, str], bool] = {}
    for r in state_records(stored):
        k = (r["scope"], r["key"])
        if r["op"] == "add" and not r.get("compacted"):
            seen[k] = False
        if id(r) in hit:
            seen[k] = True
    for (scope, key), was in seen.items():
        entry = stored["entries"].get(scope, {}).get(key) or {}
        if entry.get("status") != "live":
            continue
        last = last_record(stored, scope, key)
        is_own = [rev for o, s, k, rev in own if (o, s, k) == (owner, scope, key)]
        if is_own:  # the revision itself: retire it only while it is current
            if last is not None and any(_holds(last, rev) for rev in is_own):
                out.add((scope, key))
            continue
        if was:
            out.add((scope, key))
    return out


def _purge(
    stored: Stored,
    target: str,
    rev_target: re.Match[str] | None,
    now: str,
    reason: str,
    who: OperatorPrincipal,
    owner: str,
    dry_run: bool,
    token: str,
) -> list[dict[str, Any]]:
    """Purge ``target`` from ``stored`` in place (see :meth:`MemoryAdmin.purge`)."""

    def matches(r: Mapping[str, Any], digest: str | None) -> bool:
        return bool(digest) and (
            r.get("value_digest") == digest or digest in (r.get("value_digests") or ())
        )

    state = state_records(stored)
    if rev_target:
        scope, key, rev = rev_target.group(1), rev_target.group(2), int(rev_target.group(3))
        held = [r for r in state if (r["scope"], r["key"]) == (scope, key) and _holds(r, rev)]
        if not held or held[0].get("purged"):
            return []  # nothing there, or already purged: a rerun appends nothing
        digest = held[0].get("value_digest") if not held[0].get("compacted") else None
        match = [r for r in state if r is held[0] or matches(r, digest)]
    else:
        digest = target
        match = [r for r in state if matches(r, digest)]
    if not match:
        return []
    keys = sorted({(r["scope"], r["key"]) for r in match})
    hits = []
    for scope, key in keys:
        cur = stored["entries"].get(scope, {}).get(key) or {}
        last = last_record(stored, scope, key)
        current = cur.get("status") == "live" and last is not None and any(r is last for r in match)
        hit = {
            "scope": scope, "key": key,
            "revs": sorted(r["rev"] for r in match if (r["scope"], r["key"]) == (scope, key)),
            "retired": current,
        }  # fmt: skip
        if dry_run and digest:
            hit["digest"] = digest  # the plaintext digest is shown to the operator only here
        hits.append(hit)
    if dry_run:
        return hits
    for h in hits:  # a current revision is retired first
        if h["retired"]:
            operator_retire(
                stored, [(h["scope"], h["key"])], now, reason=f"purged:{reason}", by=who.user,
                owner=owner, by_sudo=who.by_sudo,
            )  # fmt: skip
    at, _ = log_clock(stored, now, owner)
    # the retire just written carries the value's digest too: blank every record holding it
    for r in state_records(stored):
        if any(r is m for m in match) or matches(r, digest):
            r.pop("value", None)  # the value goes; sources and tlp stay
            r["purged"] = True
            if digest and r.get("value_digest") == digest:
                r["value_digest"] = token
            if r.get("value_digests"):
                r["value_digests"] = [token if d == digest else d for d in r["value_digests"]]
            if not digest and not r.get("value_digests"):
                r.pop("value_digest", None)
    for h in hits:
        recs = [
            r for r in state_records(stored) if (r["scope"], r["key"]) == (h["scope"], h["key"])
        ]
        rec: Record = {
            "at": at, "scope": h["scope"], "key": h["key"], "op": "purge", "rev": max(h["revs"]),
            "pack_id": None, "sources": [], "checked": False,
            "tlp": str(tlp.strictest(r["tlp"] for r in recs)), "closure": [],
            "reason": reason, "by": who.user, "value_digest": token,
        }  # fmt: skip
        if who.by_sudo:
            rec["by_sudo"] = who.by_sudo
        stored["log"].append(rec)
        key_log = [r for r in stored["log"] if (r["scope"], r["key"]) == (h["scope"], h["key"])]
        folded = fold(key_log).get(h["scope"], {}).get(h["key"])
        if folded is not None:
            stored["entries"].setdefault(h["scope"], {})[h["key"]] = folded
    return hits
