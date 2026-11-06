# SPDX-License-Identifier: Apache-2.0
"""The retraction deny set (ADR-0037 decisions 13 and 14): what new packs and new memory leave out.

An operator retracts a source with ``MemoryAdmin.retract`` (``homelabnext.memory_admin``, outside
the agent's reach).  That appends deny records to the **deny log**, and the revisions the
retraction reached to the **denied-reach index**.  Both live in the backend's deny state, apart
from the owners' memory (for the file backend, in a deny file the runtime may only read).  This
module only reads them: :func:`deny_set` folds the two into a :class:`DenySet`, the active state,
which

* the memory store re-checks inside every write's transaction, read under the deny state's own
  lock, and
* the caller passes as ``retracted=`` to :func:`~homelabnext.agent.knowledge.select_knowledge`
  and :func:`~homelabnext.agent.pack.assemble_pack`, which leave denied items out.  Neither
  function reads the store.

A deny record names one alias of the retracted source; a lift record names a ``deny_id`` and makes
that retraction's names and marks stop counting at once, without rewriting anything.  A mark is
``{deny_id, owner, scope, key, rev_from, rev}``: a memory revision (or a folded range of them)
the retraction reached, which a pack's ``memory`` block may no longer show and no closure may
cite.  A ``settings`` record holds a retraction's ``include_exposed`` and ``include_alias`` when
an operator widened them on a rerun (with a fresh confirm).

Shapes (append-only, both)::

    deny log:  [{"op": "retract", "deny_id", "at", "source", "revision": "all"|"this",
                 "include_exposed", "include_alias", "name", "reason", "by", "by_sudo"}, ...,
                {"op": "settings", "deny_id", "include_exposed", "include_alias", ...},
                {"op": "lift", "deny_id", "at", "source", "reason", "by", "by_sudo"}]
    reach:     [{"deny_id", "owner", "scope", "key", "rev_from", "rev"}, ...]
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "MEM_REF",
    "RESERVED_PREFIX",
    "DenySet",
    "active_retractions",
    "deny_set",
    "mem_ref",
    "parse_mem_ref",
    "retraction_settings",
]

#: owner names no profile id can take (a profile id is ``profile:<slug>``): refused as owners
RESERVED_PREFIX = "@"

_SLUG = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"
#: a memory revision, ``mem:<profile id>/<scope>/<key>@<rev>`` (report_result 1.2)
MEM_REF = re.compile(rf"mem:(profile:{_SLUG})/({_SLUG})/({_SLUG})@([1-9][0-9]{{0,15}})")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def mem_ref(owner: str, scope: str, key: str, rev: int) -> str:
    return f"mem:{owner}/{scope}/{key}@{rev}"


def parse_mem_ref(ref: Any) -> tuple[str, str, str, int] | None:
    """``(owner, scope, key, rev)`` of a ``mem:`` revision, or None when ``ref`` is not one."""
    m = MEM_REF.fullmatch(ref) if isinstance(ref, str) else None
    return (m.group(1), m.group(2), m.group(3), int(m.group(4))) if m else None


Mark = tuple[str, str, str, int, int]  # owner, scope, key, rev_from, rev


@dataclass(frozen=True)
class DenySet:
    """The active retractions: ``names`` (every denied alias), ``this`` (the content digests
    denied by a ``revision="this"`` retraction) and ``marks`` (``(owner, scope, key, rev_from,
    rev)`` of each revision range a retraction reached).  Empty by default; an empty set denies
    nothing.  It only ever takes things out, so building one by hand cannot widen what a pack or
    a write may carry.  :meth:`marked` looks a key up in an index, so its cost is the number of
    marks on that one key, not the size of memory."""

    names: frozenset[str] = frozenset()
    marks: frozenset[Mark] = frozenset()
    this: frozenset[str] = frozenset()
    _by_key: Mapping[tuple[str, str, str], tuple[tuple[int, int], ...]] = field(
        default_factory=dict, compare=False, repr=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "names", frozenset(self.names))
        object.__setattr__(self, "marks", frozenset(self.marks))
        object.__setattr__(self, "this", frozenset(self.this))
        index: dict[tuple[str, str, str], list[tuple[int, int]]] = {}
        for o, s, k, lo, hi in self.marks:
            index.setdefault((o, s, k), []).append((lo, hi))
        object.__setattr__(self, "_by_key", {k: tuple(v) for k, v in index.items()})

    def __bool__(self) -> bool:
        return bool(self.names or self.marks)

    def denies(self, names: Iterable[str]) -> bool:
        """True when any of ``names`` is denied."""
        return not self.names.isdisjoint(names)

    def denies_input(self, uid: str, digest: str) -> bool:
        """True when an input item is denied: by its uid, or by its digest only where a
        ``revision="this"`` retraction denied that digest (a feed item that merely carries a
        denied digest under another uid is not censored by it)."""
        return uid in self.names or digest in self.this

    def marked(self, owner: str, scope: str, key: str, rev: int) -> bool:
        """True when revision ``rev`` of ``owner/scope/key`` carries an active mark."""
        return any(lo <= rev <= hi for lo, hi in self._by_key.get((owner, scope, key), ()))

    def marked_ref(self, ref: str) -> bool:
        """True when ``ref`` is a ``mem:`` revision carrying an active mark."""
        parsed = parse_mem_ref(ref)
        return parsed is not None and self.marked(*parsed)

    def reaches(self, closure: Iterable[str]) -> bool:
        """True when a closure reaches a denied name or cites a marked revision (the cited
        lineage, ADR-0037 decision 14 as amended)."""
        items = list(closure)
        return self.denies(items) or any(c.startswith("mem:") and self.marked_ref(c) for c in items)


def _split(log: Iterable[Mapping[str, Any]]) -> tuple[list[Mapping[str, Any]], set[str]]:
    records = [r for r in log if isinstance(r, Mapping)]
    lifted = {r.get("deny_id") for r in records if r.get("op") == "lift"}
    return [r for r in records if r.get("op") == "retract"], {x for x in lifted if x}


def deny_set(
    log: Iterable[Mapping[str, Any]] = (), reach: Iterable[Mapping[str, Any]] = ()
) -> DenySet:
    """The :class:`DenySet` the deny ``log`` and the denied-reach index ``reach`` describe: every
    name and mark of a retraction that has not been lifted."""
    retracts, lifted = _split(log)
    live = [r for r in retracts if r.get("deny_id") not in lifted and r.get("name")]
    names = {r["name"] for r in live}
    this = {
        r["name"] for r in live if r.get("revision") == "this" and _DIGEST.fullmatch(str(r["name"]))
    }
    marks = {
        (m["owner"], m["scope"], m["key"], int(m.get("rev_from", m["rev"])), int(m["rev"]))
        for m in reach
        if isinstance(m, Mapping) and m.get("deny_id") not in lifted
    }
    return DenySet(frozenset(names), frozenset(marks), frozenset(this))


def active_retractions(log: Iterable[Mapping[str, Any]]) -> dict[str, list[Mapping[str, Any]]]:
    """``{deny_id: [its deny records]}`` for every retraction not lifted, in log order."""
    retracts, lifted = _split(log)
    out: dict[str, list[Mapping[str, Any]]] = {}
    for r in retracts:
        if r.get("deny_id") not in lifted:
            out.setdefault(r["deny_id"], []).append(r)
    return out


def retraction_settings(log: Iterable[Mapping[str, Any]], deny_id: str) -> dict[str, Any]:
    """``{include_exposed, include_alias}`` in effect for ``deny_id``: its first deny record's,
    as any later ``settings`` record changed them."""
    out: dict[str, Any] = {}
    for r in log:
        if not isinstance(r, Mapping) or r.get("deny_id") != deny_id:
            continue
        if (r.get("op") == "retract" and not out) or r.get("op") == "settings":
            out = {
                "include_exposed": bool(r.get("include_exposed", False)),
                "include_alias": sorted(r.get("include_alias") or ()),
            }
    return out or {"include_exposed": False, "include_alias": []}
