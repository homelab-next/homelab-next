# SPDX-License-Identifier: Apache-2.0
"""The retraction deny set (ADR-0037 decisions 13 and 14): what new packs and new memory leave out.

An operator retracts a source with ``MemoryAdmin.retract`` (``homelabnext.memory_admin``, outside
the agent's reach).  That appends deny records to the **deny log**, and the revisions the
retraction reached to the **denied-reach index**; both are kept by the memory backend under
reserved keys no profile id can take.  This module only reads them: :func:`deny_set` folds the
two into a :class:`DenySet`, the active state, which

* the memory store re-checks inside every write's transaction (``MemoryStore`` reads the deny
  log under the same lock as the owner's memory), and
* the caller passes as ``retracted=`` to :func:`~homelabnext.agent.knowledge.select_knowledge`
  and :func:`~homelabnext.agent.pack.assemble_pack`, which leave denied items out.  Neither
  function reads the store.

A deny record names one alias of the retracted source; a lift record names a ``deny_id`` and makes
that retraction's names and marks stop counting at once, without rewriting anything.  A mark is
``{deny_id, owner, scope, key, rev_from, rev}``: a memory revision (or a folded range of them)
the retraction reached through exposure, which a pack's ``memory`` block may no longer show.

Shapes (append-only, both)::

    deny log:  [{"op": "retract", "deny_id", "at", "source", "revision": "all"|"this", "name",
                 "reason", "by"}, ..., {"op": "lift", "deny_id", "at", "source", "reason", "by"}]
    reach:     [{"deny_id", "owner", "scope", "key", "rev_from", "rev"}, ...]
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

__all__ = [
    "DENY_KEY",
    "MEM_REF",
    "REACH_KEY",
    "RESERVED_PREFIX",
    "DenySet",
    "deny_set",
    "mem_ref",
    "parse_mem_ref",
]

#: backend keys no profile id can take (a profile id is ``profile:<slug>``)
RESERVED_PREFIX = "@"
DENY_KEY = "@memory-deny-log"
REACH_KEY = "@memory-denied-reach"

_SLUG = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"
#: a memory revision, ``mem:<profile id>/<scope>/<key>@<rev>`` (report_result 1.2)
MEM_REF = re.compile(rf"mem:(profile:{_SLUG})/({_SLUG})/({_SLUG})@([1-9][0-9]{{0,15}})")


def mem_ref(owner: str, scope: str, key: str, rev: int) -> str:
    return f"mem:{owner}/{scope}/{key}@{rev}"


def parse_mem_ref(ref: Any) -> tuple[str, str, str, int] | None:
    """``(owner, scope, key, rev)`` of a ``mem:`` revision, or None when ``ref`` is not one."""
    m = MEM_REF.fullmatch(ref) if isinstance(ref, str) else None
    return (m.group(1), m.group(2), m.group(3), int(m.group(4))) if m else None


@dataclass(frozen=True)
class DenySet:
    """The active retractions: ``names`` (every denied alias) and ``marks`` (``(owner, scope,
    key, rev_from, rev)`` of each revision range a retraction reached).  Empty by default; an
    empty set denies nothing.  It only ever takes things out, so building one by hand cannot
    widen what a pack or a write may carry."""

    names: frozenset[str] = frozenset()
    marks: frozenset[tuple[str, str, str, int, int]] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "names", frozenset(self.names))
        object.__setattr__(self, "marks", frozenset(self.marks))

    def __bool__(self) -> bool:
        return bool(self.names or self.marks)

    def denies(self, names: Iterable[str]) -> bool:
        """True when any of ``names`` is denied."""
        return not self.names.isdisjoint(names)

    def marked(self, owner: str, scope: str, key: str, rev: int) -> bool:
        """True when revision ``rev`` of ``owner/scope/key`` carries an active mark."""
        return any(
            (o, s, k) == (owner, scope, key) and lo <= rev <= hi for o, s, k, lo, hi in self.marks
        )


def _active(log: Iterable[Mapping[str, Any]]) -> tuple[list[Mapping[str, Any]], set[str]]:
    records = [r for r in log if isinstance(r, Mapping)]
    lifted = {r.get("deny_id") for r in records if r.get("op") == "lift"}
    return [r for r in records if r.get("op") == "retract"], {x for x in lifted if x}


def deny_set(
    log: Iterable[Mapping[str, Any]] = (), reach: Iterable[Mapping[str, Any]] = ()
) -> DenySet:
    """The :class:`DenySet` the deny ``log`` and the denied-reach index ``reach`` describe: every
    name and mark of a retraction that has not been lifted."""
    retracts, lifted = _active(log)
    names = {r["name"] for r in retracts if r.get("deny_id") not in lifted and r.get("name")}
    marks = {
        (m["owner"], m["scope"], m["key"], int(m.get("rev_from", m["rev"])), int(m["rev"]))
        for m in reach
        if isinstance(m, Mapping) and m.get("deny_id") not in lifted
    }
    return DenySet(frozenset(names), frozenset(marks))


def active_retractions(log: Iterable[Mapping[str, Any]]) -> dict[str, list[Mapping[str, Any]]]:
    """``{deny_id: [its deny records]}`` for every retraction not lifted, in log order."""
    retracts, lifted = _active(log)
    out: dict[str, list[Mapping[str, Any]]] = {}
    for r in retracts:
        if r.get("deny_id") not in lifted:
            out.setdefault(r["deny_id"], []).append(r)
    return out
