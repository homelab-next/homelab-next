# SPDX-License-Identifier: Apache-2.0
"""Agent memory (checklist M-09): written only through validated memory updates, read only by
its owner, and historied (ADR-0037, PR 1).

An agent does not get a writable store.  It hands back ``memory_updates`` in its
``report_result`` (``{scope, op: add|replace|retire, key, value}``) and the platform applies
them here, after validating them exactly as the report schema does.  Reads are scoped to the
agent profile that owns the memory.

* **One write path** (for this store: the broker's ``memory.write`` lane writes free-form note
  files elsewhere and carries none of these guarantees).  :meth:`MemoryStore.apply_report` (a
  whole report, optionally checked against the pack it ran on with
  :func:`~homelabnext.agent.report.validate_report`) and :meth:`MemoryStore.apply_updates` are the
  only mutators.  A batch is all-or-nothing: one bad update refuses the whole report and nothing
  is stored.  There is no ``put``.
* **Semantics.**  ``add`` needs a value and a key that is not live; ``replace`` needs a value and
  a live key; ``retire`` needs a live key and no value (the entry is kept as a tombstone, so a
  retired fact cannot quietly come back as the same key without an ``add``).
* **Owner and scope.**  Memory belongs to a compiled profile's ``id`` and is partitioned by the
  profile's ``memory_scopes``.  A write or read in a scope the profile does not hold is refused,
  and so is a read of another profile's memory (``owner=``): two profiles that both list a scope
  named ``analyst`` still have two separate memories.  The profile must be a
  :class:`~homelabnext.agent.compiler.VerifiedProfile` (verified against the ceiling policy and
  the lock of reviewed digests): a dict is refused, since whoever holds one can change its ``id``
  or ``memory_scopes`` and recompute its digest.

History (ADR-0037 decisions 1 to 6):

* **A change log.**  Per owner the stored value is ``{entries, log}``.  Every applied update
  appends one record to ``log`` (:data:`RECORD_FIELDS`) in the **same backend transaction** as
  the entry, so a refused batch writes neither.  ``entries`` is a cache of the log:
  :func:`fold` rebuilds it, and the store refolds every key a batch touches.  An entry carries
  ``rev`` (1 on a key's first ``add``, one more on every record of the key, never restarted,
  even by ``retire`` and a later ``add``), ``updated_at`` and ``reasserted_at`` (set by ``add``
  and ``replace``).  Until sources and labels ship (ADR-0037 PR 2) every record is
  ``sources: []``, ``checked: false``, ``tlp: red`` with an empty closure.  Memory stored before
  the log existed migrates once, on its owner's next write, to one ``migrated`` record per entry
  (``rev: 1``); before that record's time its history is unknown and :meth:`MemoryStore.as_of`
  answers ``compacted`` for it.
* **An injected clock.**  ``MemoryStore(now=...)`` (a callable returning an aware UTC
  ``datetime``) is read once per batch, inside the transaction; :func:`_apply` reads no clock.
* **No secret enters the log.**  Every key and value is run through the platform screen's secret
  types (:data:`homelabnext.agent.screen.SECRET_TYPES`) and the leak scanner's credential shapes
  (:mod:`homelabnext.shapes`) before anything else, the schema check included (its messages
  quote values).  A match refuses the whole batch; the refusal names the update's position, the
  field and the type, never the value.
* **History reads.**  :meth:`MemoryStore.history` and :meth:`MemoryStore.as_of` are owner-scoped
  like :meth:`MemoryStore.read`.  Both return ``withheld: 0`` today: the reader's TLP ceiling is
  applied in :func:`_readable` once records carry labels (PR 2).
* **Bounded per scope.**  A profile's ``memory_limits.records`` caps each scope's records
  (default :data:`DEFAULT_RECORDS`, :data:`DEFAULT_PLATFORM_RECORDS` for a scope in its
  ``platform_scopes``).  A batch that would take a scope past its cap is refused whole
  (:class:`MemoryLimitError`) and the operator is paged through the state-diffed notifier, once
  per crossing (its recovery when a write to the scope is accepted again).  In a platform scope,
  ``memory_limits.keep_last`` drops the values of a key's records beyond its last N, and a key
  that is retired is compacted whole to one tombstone record (:func:`_compact`).
"""

from __future__ import annotations

import copy
import fnmatch
import hashlib
import logging
import re
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from homelabnext import shapes, tlp
from homelabnext.notify.core_pairs import AGENT_MEMORY_CAP

from .compiler import VerifiedProfile, require_verified
from .errors import AgentError
from .report import validate_report
from .schemas import schema_errors
from .screen import SECRET_TYPES, Screener

OPS = ("add", "replace", "retire")
_PLACEHOLDER_HASH = "sha256:" + "0" * 64
log = logging.getLogger("homelabnext.agent.memory")

#: record caps of a profile without ``memory_limits.records`` for the scope (ADR-0037 decision 6)
DEFAULT_RECORDS = 10_000
DEFAULT_PLATFORM_RECORDS = 100_000

#: the fields of a change record (ADR-0037 decision 1); ``value`` is absent on ``retire`` and on
#: a compacted record, ``reason`` only on a record an operator causes (none yet)
RECORD_FIELDS = (
    "at",
    "scope",
    "key",
    "op",
    "rev",
    "value",
    "value_digest",
    "pack_id",
    "sources",
    "checked",
    "tlp",
    "closure",
    "reason",
)
#: the label every record carries until packs carry labels (ADR-0037 decision 8, PR 2)
UNLABELLED = "red"

#: the notifier pair the record cap pages with (its titles live in ``core_pairs``)
CAP_TITLE, CAP_CLEARED = AGENT_MEMORY_CAP

#: the leak scanner's credential shapes, by its pattern names (``tools/leak_scan.py``)
_SHAPES = tuple(
    (name, re.compile(rx))
    for name, rx in (
        ("private-key-block", shapes.PRIVATE_KEY_HEADER),
        ("aws-access-key", shapes.AWS_ACCESS_KEY),
        ("github-token", shapes.GITHUB_TOKEN),
        ("slack-token", shapes.SLACK_TOKEN),
        ("google-api-key", shapes.GOOGLE_KEY),
        ("jwt", shapes.JWT),
    )
)


class MemoryAccessError(AgentError):
    """A read or write outside the caller's own memory (another profile, or a scope it lacks)."""


class MemoryUpdateError(AgentError):
    """Memory updates that fail validation; nothing from the batch was applied."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        super().__init__("memory updates refused: " + "; ".join(self.problems))


class MemoryLimitError(MemoryUpdateError):
    """A batch that would take a scope past its record cap; nothing from it was applied.
    ``scopes`` maps each such scope to ``(records it would hold, cap)``."""

    def __init__(self, owner: str, scopes: Mapping[str, tuple[int, int]]) -> None:
        self.owner = owner
        self.scopes = dict(scopes)
        super().__init__(
            [
                f"scope {s!r} of {owner} is at its record cap ({n} records would exceed {cap}); "
                "writes to it are refused until memory_limits.records is raised or it is compacted"
                for s, (n, cap) in sorted(self.scopes.items())
            ]
        )


Memory = dict[str, dict[str, dict[str, Any]]]  # scope -> key -> entry
Stored = dict[str, Any]  # {"entries": Memory, "log": [record, ...]}


class MemoryBackend(Protocol):
    def load(self, owner: str) -> Any: ...

    def transact(self, owner: str, fn: Callable[[Any], Any]) -> Any: ...


class InMemoryBackend:
    """Process-local backend (the fake)."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    def load(self, owner: str) -> Any:
        return copy.deepcopy(self._data.get(owner, {}))

    def transact(self, owner: str, fn: Callable[[Any], Any]) -> Any:
        new = fn(copy.deepcopy(self._data.get(owner, {})))  # raises before anything is stored
        self._data[owner] = copy.deepcopy(new)
        return new


class FileBackend:
    """Durable backend: one ``homelabnext.state`` file, one key per owning profile."""

    def __init__(self, path: str | Path, **state_kwargs: Any) -> None:
        from homelabnext.state import StateStore

        self._store = StateStore(path, **state_kwargs)

    def load(self, owner: str) -> Any:
        return self._store.get(owner, {}) or {}

    def transact(self, owner: str, fn: Callable[[Any], Any]) -> Any:
        # StateStore.update writes only after fn returns: a raising fn leaves the file as it was
        return self._store.update(owner, lambda cur: fn(copy.deepcopy(cur or {})), default={})


# ---------------------------------------------------------------- identity and limits
def _identity(profile: VerifiedProfile) -> tuple[str, frozenset[str]]:
    """The owner id and scopes of a verified profile."""
    require_verified(profile, "agent memory")
    scopes = profile.get("memory_scopes") or []
    return profile["id"], frozenset(scopes)


def _platform_scopes(profile: VerifiedProfile) -> frozenset[str]:
    return frozenset(profile.get("platform_scopes") or [])


def record_cap(profile: VerifiedProfile, scope: str) -> int:
    """The record cap of ``scope`` for ``profile``: its ``memory_limits.records`` entry, else the
    code-constant default (higher for a platform scope)."""
    limits = (profile.get("memory_limits") or {}).get("records") or {}
    if scope in limits:
        return int(limits[scope])
    return DEFAULT_PLATFORM_RECORDS if scope in _platform_scopes(profile) else DEFAULT_RECORDS


def _keep_last(profile: VerifiedProfile, scope: str, key: str) -> int | None:
    """How many of ``key``'s records keep their values (platform scopes only): the largest N of
    the ``keep_last`` patterns (shell-style globs) that match the key, or None."""
    if scope not in _platform_scopes(profile):
        return None
    pats = ((profile.get("memory_limits") or {}).get("keep_last") or {}).get(scope) or {}
    hits = [int(n) for pat, n in pats.items() if fnmatch.fnmatchcase(key, pat)]
    return max(hits) if hits else None


# ---------------------------------------------------------------- validation
def update_errors(updates: Any, profile_id: str = "profile:memory-check") -> list[str]:
    """Schema problems of a ``memory_updates`` list, validated exactly as inside a report."""
    doc = {
        "pack_id": _PLACEHOLDER_HASH,
        "profile": profile_id,
        "status": "partial",
        "summary": "memory update validation",
        "cites": [],
        "unknowns": [],
        "memory_updates": updates,
    }
    return [e for e in schema_errors("agent", "report_result", doc) if e.startswith("memory")]


def secret_types(text: str) -> list[str]:
    """The secret types found in ``text``: the platform screen's secret types and the leak
    scanner's credential shapes.  Names only, never the matched value."""
    found = {t for _, _, t, _ in Screener(types=SECRET_TYPES).find(text)}
    found.update(name for name, rx in _SHAPES if rx.search(text))
    return sorted(found)


def secret_problems(updates: Any) -> list[str]:
    """One problem per key or value of ``updates`` that holds a secret, naming the update's
    position, the field and the types (never the value).  Runs on whatever is there, before the
    schema check, whose messages would quote the value."""
    if not isinstance(updates, list):
        return []
    problems: list[str] = []
    for n, u in enumerate(updates):
        if not isinstance(u, Mapping):
            continue
        for field in ("key", "value"):
            text = u.get(field)
            if isinstance(text, str):
                types = secret_types(text)
                if types:
                    problems.append(
                        f"memory_updates/{n} {field}: holds a secret ({', '.join(types)}); "
                        "a secret may never enter memory or its log"
                    )
    return problems


# ---------------------------------------------------------------- time
def _stamp(t: datetime) -> str:
    """Fixed-width UTC stamp, so stamps order as strings."""
    if not isinstance(t, datetime) or t.tzinfo is None or t.utcoffset() is None:
        raise ValueError(f"memory clock must give an aware UTC datetime, got {t!r}")
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- the log and its fold
def _stored(raw: Any, at: str) -> Stored:
    """``raw`` in the ``{entries, log}`` shape; memory stored before the log migrates to one
    ``migrated`` record per entry, stamped ``at`` (ADR-0037 decision 2)."""
    if not raw:
        return {"entries": {}, "log": []}
    if set(raw) == {"entries", "log"} and isinstance(raw["log"], list):
        return raw
    # pre-log memory: {scope: {key: {status, op, value, pack_id?}}} (a scope is a dict, never a
    # list, so a legacy scope named "log" cannot be mistaken for the new shape)
    out: list[dict[str, Any]] = []
    for scope in sorted(raw):
        for key in sorted(raw[scope]):
            e = raw[scope][key]
            value = e.get("value")
            rec = _record(
                at,
                scope,
                key,
                e.get("op") or ("retire" if e.get("status") == "retired" else "add"),
                1,
                value,
                e.get("pack_id"),
                keep_value=True,
            )
            rec["migrated"] = True
            out.append(rec)
    return {"entries": fold(out), "log": out}


def _record(
    at: str,
    scope: str,
    key: str,
    op: str,
    rev: int,
    value: str | None,
    pack_id: str | None,
    *,
    keep_value: bool,
) -> dict[str, Any]:
    rec: dict[str, Any] = {"at": at, "scope": scope, "key": key, "op": op, "rev": rev}
    if keep_value and value is not None:
        rec["value"] = value
    if value is not None:
        rec["value_digest"] = _digest(value)  # on a retire, the digest of the value it retires
    rec.update(
        {
            "pack_id": pack_id,
            "sources": [],  # ADR-0037 PR 2 fills these from the pack
            "checked": False,
            "tlp": UNLABELLED,
            "closure": [],
        }
    )
    return rec


def _union(*lists: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(x for xs in lists for x in xs))


def _step(entry: dict[str, Any] | None, rec: Mapping[str, Any]) -> dict[str, Any]:
    """The entry after ``rec`` (one step of the fold)."""
    op = rec["op"]
    if rec.get("compacted") == "whole":  # a retired key compacted to its tombstone
        value, sources, reasserted = None, list(rec["sources"]), rec.get("reasserted_at")
    elif rec.get("migrated"):
        value, sources, reasserted = rec.get("value"), list(rec["sources"]), None
    elif op == "add":
        value, sources, reasserted = rec.get("value"), list(rec["sources"]), rec["at"]
    elif op == "replace":
        prior = entry["sources"] if entry else []
        value, sources, reasserted = rec.get("value"), _union(prior, rec["sources"]), rec["at"]
    else:  # retire keeps the value it retires (when its record still holds it)
        value = entry.get("value") if entry else None
        sources = _union(entry["sources"] if entry else [], rec["sources"])
        reasserted = entry.get("reasserted_at") if entry else None
    out: dict[str, Any] = {
        "status": "retired" if op == "retire" else "live",
        "op": op,
        "value": value,
        "rev": rec["rev"],
        "updated_at": rec["at"],
        "reasserted_at": reasserted,
        "sources": sources,
        "checked": rec["checked"],
        "tlp": rec["tlp"],
    }
    if rec.get("pack_id"):
        out["pack_id"] = rec["pack_id"]
    return out


def fold(records: Iterable[Mapping[str, Any]]) -> Memory:
    """The entries a log describes (``entries`` is a cache of exactly this)."""
    entries: Memory = {}
    for rec in records:
        scope = entries.setdefault(rec["scope"], {})
        scope[rec["key"]] = _step(scope.get(rec["key"]), rec)
    return entries


def _compact(
    records: list[dict[str, Any]], scope: str, key: str, keep_last: int | None, whole: bool
) -> list[dict[str, Any]]:
    """``records`` with ``scope/key`` compacted (ADR-0037 decision 6).

    ``whole`` (a retired key in a platform scope) replaces the key's records with one tombstone
    at the place of the last: the last ``rev``, the union of their sources and closures, their
    ``pack_id`` and value digests, the strictest label, and ``since`` (the first record's time,
    None when one was migrated and so had unknown history before it).  Otherwise the values of
    the key's records beyond the last ``keep_last`` are dropped, every other field kept."""
    mine = [i for i, r in enumerate(records) if r["scope"] == scope and r["key"] == key]
    if not mine:
        return records
    if whole:
        old = [records[i] for i in mine]
        if len(old) == 1 and old[0].get("compacted") == "whole":
            return records
        last = old[-1]
        firsts = [
            r.get("since", r["at"]) if r.get("compacted") == "whole" else r["at"] for r in old
        ]
        unknown = any(
            r.get("migrated") or (r.get("compacted") == "whole" and r.get("since") is None)
            for r in old
        )
        packs = _union(*((r.get("pack_ids") or [r.get("pack_id")]) for r in old))
        tomb: dict[str, Any] = {
            "at": last["at"],
            "scope": scope,
            "key": key,
            "op": "retire",
            "rev": last["rev"],
            "compacted": "whole",
            "since": None if unknown else min(firsts),
            "value_digests": _union(
                *((r.get("value_digests") or [r.get("value_digest")]) for r in old)
            ),
            "pack_id": last.get("pack_id"),
            "pack_ids": [p for p in packs if p],
            "sources": _union(*(r["sources"] for r in old)),
            "checked": all(r["checked"] for r in old),
            "tlp": str(tlp.strictest(r["tlp"] for r in old)),
            "closure": _union(*(r["closure"] for r in old)),
            "reasserted_at": fold(old)[scope][key]["reasserted_at"],
        }
        tomb["value_digests"] = [d for d in tomb["value_digests"] if d]
        drop = set(mine[:-1])
        out = [r for i, r in enumerate(records) if i not in drop]
        out[mine[-1] - len(drop)] = tomb
        return out
    if keep_last is None:
        return records
    for i in mine[: max(0, len(mine) - keep_last)]:
        if "value" in records[i]:
            records[i] = {k: v for k, v in records[i].items() if k != "value"}
            records[i]["compacted"] = True
    return records


def _apply(
    stored: Stored,
    updates: Iterable[Mapping[str, Any]],
    pack_id: str | None,
    at: str,
    profile: VerifiedProfile,
) -> Stored:
    """Apply ``updates`` at time ``at``: append their records, compact, refold the touched keys
    and check the record caps.  Raises on any problem, so the backend stores nothing."""
    entries: Memory = stored["entries"]
    records: list[dict[str, Any]] = stored["log"]
    problems: list[str] = []
    touched: dict[tuple[str, str], None] = {}
    for n, u in enumerate(updates):
        where = f"memory_updates/{n} ({u['scope']}/{u['key']})"
        scope = entries.setdefault(u["scope"], {})
        cur = scope.get(u["key"])
        live = cur is not None and cur.get("status") == "live"
        has_value = "value" in u
        if u["op"] == "add" and live:
            problems.append(f"{where}: add of a key that is already live (use replace)")
        elif u["op"] == "replace" and not live:
            problems.append(f"{where}: replace of a key that is not live (use add)")
        elif u["op"] == "retire" and not live:
            problems.append(f"{where}: retire of a key that is not live")
        elif u["op"] in ("add", "replace") and not has_value:
            problems.append(f"{where}: {u['op']} needs a value")
        elif u["op"] == "retire" and has_value:
            problems.append(f"{where}: retire takes no value")
        else:
            rev = (cur["rev"] if cur else 0) + 1
            value = u["value"] if has_value else (cur or {}).get("value")
            rec = _record(
                at, u["scope"], u["key"], u["op"], rev, value, pack_id, keep_value=has_value
            )
            records.append(rec)
            scope[u["key"]] = _step(cur, rec)
            touched[(u["scope"], u["key"])] = None
    if problems:
        raise MemoryUpdateError(problems)
    platform = _platform_scopes(profile)
    for scope, key in touched:
        whole = scope in platform and entries[scope][key]["status"] == "retired"
        records = _compact(records, scope, key, _keep_last(profile, scope, key), whole)
    # refold the touched keys from the log (compaction may have dropped a value the cache held),
    # so the cache is the fold by construction; one pass over the log
    counts: dict[str, int] = {}
    refolded: dict[tuple[str, str], dict[str, Any] | None] = dict.fromkeys(touched)
    for r in records:
        counts[r["scope"]] = counts.get(r["scope"], 0) + 1
        k = (r["scope"], r["key"])
        if k in refolded:
            refolded[k] = _step(refolded[k], r)
    for (scope, key), entry in refolded.items():
        entries[scope][key] = entry  # type: ignore[assignment]
    over = {
        s: (counts[s], record_cap(profile, s))
        for s in sorted({s for s, _ in touched})
        if counts[s] > record_cap(profile, s)
    }
    if over:
        raise MemoryLimitError(profile["id"], over)
    return {"entries": entries, "log": records}


def _readable(
    profile: VerifiedProfile, records: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], int]:
    """The records ``profile`` may read and how many it may not.  The hook for the reader's TLP
    ceiling (ADR-0037 decision 8, PR 2): until records carry labels, an owner reads all of its
    own records and nothing is withheld."""
    return records, 0


# ---------------------------------------------------------------- the store
class MemoryStore:
    """Validated writes and owner-scoped reads over a :class:`MemoryBackend`.

    ``now`` is the clock (an aware UTC ``datetime``); ``notifier`` (a
    :class:`~homelabnext.notify.Notifier`) pages a scope reaching its record cap, once per
    crossing, on ``topic``.  Without a notifier the crossing is logged once per process."""

    def __init__(
        self,
        backend: MemoryBackend | None = None,
        *,
        now: Callable[[], datetime] | None = None,
        notifier: Any | None = None,
        topic: str | None = None,
    ) -> None:
        self._backend = backend if backend is not None else InMemoryBackend()
        self._now = now if now is not None else _utcnow
        self._notifier = notifier
        self._topic = topic
        self._logged: set[str] = set()
        if notifier is not None:
            notifier.register_pair(CAP_TITLE, CAP_CLEARED)

    def apply_updates(
        self,
        profile: VerifiedProfile,
        updates: Any,
        *,
        pack_id: str | None = None,
    ) -> Memory:
        """Validate and apply ``updates`` for ``profile``; all or nothing.  Returns the new
        entries."""
        owner, scopes = _identity(profile)
        secrets = secret_problems(updates)
        if secrets:
            raise MemoryUpdateError(secrets)
        errs = update_errors(updates, owner)
        if errs:
            raise MemoryUpdateError(errs)
        foreign = sorted({u["scope"] for u in updates} - scopes)
        if foreign:
            raise MemoryAccessError(
                f"{owner}: memory scopes {foreign} are not in the profile's memory_scopes "
                f"{sorted(scopes)}"
            )
        if not updates:
            return self._load(owner)["entries"]

        def fn(raw: Any) -> Stored:
            at = _stamp(self._now())  # read under the backend's lock, so the log stays in order
            return _apply(_stored(raw, at), updates, pack_id, at, profile)

        try:
            new = self._backend.transact(owner, fn)
        except MemoryLimitError as exc:
            for scope, (n, cap) in exc.scopes.items():
                self._page(owner, scope, f"{n} records would exceed the cap of {cap}")
            raise
        for scope in sorted({u["scope"] for u in updates}):
            self._page(owner, scope, None)
        return new["entries"]

    def apply_report(
        self,
        profile: VerifiedProfile,
        report: Mapping[str, Any],
        *,
        pack: Mapping[str, Any] | None = None,
        pack_hash: str | None = None,
        manifest: Mapping[str, Any] | None = None,
    ) -> Memory:
        """Apply a report's ``memory_updates`` after validating the report.

        With ``pack`` and ``pack_hash`` the report is checked against the pack it ran on
        (:func:`validate_report`); otherwise against its schema.  The report must be the
        profile's own, and a ``deferred`` report (no work done) may not change memory.
        """
        owner, _ = _identity(profile)
        secrets = secret_problems(report.get("memory_updates"))
        if secrets:
            raise MemoryUpdateError(secrets)
        if pack is not None and pack_hash is not None:
            problems = validate_report(report, pack, pack_hash, manifest)
        else:
            problems = schema_errors("agent", "report_result", report)
        if problems:
            raise MemoryUpdateError(problems)
        if report["profile"] != owner:
            raise MemoryAccessError(
                f"report belongs to {report['profile']}, not {owner}; a report may only update "
                "its own agent's memory"
            )
        if report["status"] == "deferred" and report["memory_updates"]:
            raise MemoryUpdateError(["a deferred report did no work and may not update memory"])
        return self.apply_updates(profile, report["memory_updates"], pack_id=report["pack_id"])

    def read(
        self,
        profile: VerifiedProfile,
        scope: str,
        *,
        owner: str | None = None,
        include_retired: bool = False,
    ) -> dict[str, str]:
        """Live ``{key: value}`` of one scope of the caller's own memory.

        ``owner`` other than the caller's own profile id is a cross-agent read and is refused.
        """
        me = self._reader(profile, scope, owner)
        entries = self._load(me)["entries"].get(scope, {})
        return {
            k: e["value"]
            for k, e in sorted(entries.items())
            if e.get("status") == "live" or include_retired
        }

    def history(
        self, profile: VerifiedProfile, scope: str, key: str, *, owner: str | None = None
    ) -> dict[str, Any]:
        """``{"records": [...], "withheld": n}``: the change records of ``scope/key`` in order
        (a compacted record has no ``value``; a key compacted whole is one tombstone record)."""
        me = self._reader(profile, scope, owner)
        mine = [r for r in self._load(me)["log"] if r["scope"] == scope and r["key"] == key]
        shown, withheld = _readable(profile, mine)
        return {"records": shown, "withheld": withheld}

    def as_of(
        self, profile: VerifiedProfile, scope: str, t: datetime, *, owner: str | None = None
    ) -> dict[str, Any]:
        """What ``profile`` believed in ``scope`` at ``t`` (an aware datetime), rebuilt from the
        log: ``{"at", "entries": {key: value}, "compacted": [keys], "withheld": n}``.

        A key whose state at ``t`` lies in compacted records (a value dropped by ``keep_last``,
        a key compacted whole, or history from before the migration) is listed in ``compacted``,
        never given a value."""
        me = self._reader(profile, scope, owner)
        when = _stamp(t)
        mine = [r for r in self._load(me)["log"] if r["scope"] == scope]
        shown, withheld = _readable(profile, mine)
        state: dict[str, dict[str, Any]] = {}
        held: dict[str, bool] = {}  # key -> the value in effect at t was dropped
        unknown: set[str] = set()
        for rec in shown:
            k = rec["key"]
            if rec["at"] > when:
                whole = rec.get("compacted") == "whole"
                since = rec.get("since")
                if (rec.get("migrated") or (whole and (since is None or since <= when))) and (
                    k not in state
                ):
                    unknown.add(k)
                continue
            state[k] = _step(state.get(k), rec)
            if rec["op"] in ("add", "replace") or rec.get("migrated"):
                held[k] = "value" not in rec
        live = {k for k, e in state.items() if e["status"] == "live"}
        compacted = sorted(unknown | {k for k in live if held.get(k)})
        return {
            "at": when,
            "entries": {k: state[k]["value"] for k in sorted(live) if k not in compacted},
            "compacted": compacted,
            "withheld": withheld,
        }

    # ------------------------------------------------------------ internals
    def _reader(self, profile: VerifiedProfile, scope: str, owner: str | None) -> str:
        me, scopes = _identity(profile)
        if owner is not None and owner != me:
            raise MemoryAccessError(f"{me} may not read the memory of {owner} (cross-agent read)")
        if scope not in scopes:
            raise MemoryAccessError(f"{me}: scope {scope!r} is not in its memory_scopes")
        return me

    def _load(self, owner: str) -> Stored:
        raw = self._backend.load(owner)
        if raw and not (set(raw) == {"entries", "log"} and isinstance(raw["log"], list)):
            # not yet migrated (that happens on the owner's next write): read it as migrated now
            return _stored(raw, _stamp(self._now()))
        return _stored(raw, "")

    def _page(self, owner: str, scope: str, problem: str | None) -> None:
        """Report ``owner/scope`` at its cap (``problem``) or not (None), state-diffed."""
        key = "agent-memory-cap-" + re.sub(r"[^a-z0-9-]+", "-", f"{owner}-{scope}".lower())
        if self._notifier is None:
            if problem is None:
                self._logged.discard(key)
            elif key not in self._logged:
                self._logged.add(key)
                log.warning("%s: memory scope %s refuses writes: %s", owner, scope, problem)
            return
        from homelabnext.notify import Message

        try:
            if problem is None:
                body = f"{owner}'s memory scope {scope} accepts writes again"
                self._notifier.report(key, "ok", Message(key, CAP_CLEARED, body), scope=owner)
            else:
                body = (
                    f"{owner}'s memory scope {scope} refuses writes: {problem}. Raise "
                    "memory_limits.records in the profile spec, or retire and compact keys."
                )
                msg = Message(key, CAP_TITLE, body, level="warn", topic=self._topic,
                              tags=("agent", "memory"))  # fmt: skip
                self._notifier.report(key, "at-cap", msg, scope=owner)
        except Exception:  # the write's outcome stands; a failed page is retried next time
            log.exception("memory cap page for %s/%s not sent", owner, scope)
