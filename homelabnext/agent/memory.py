# SPDX-License-Identifier: Apache-2.0
"""Agent memory (checklist M-09): written only through validated memory updates, read only by
its owner.

An agent does not get a writable store.  It hands back ``memory_updates`` in its
``report_result`` (``{scope, op: add|replace|retire, key, value}``) and the platform applies
them here, after validating them exactly as the report schema does.  Reads are scoped to the
agent profile that owns the memory.

* **One write path.**  :meth:`MemoryStore.apply_report` (a whole report, optionally checked
  against the pack it ran on with :func:`~homelabnext.agent.report.validate_report`) and
  :meth:`MemoryStore.apply_updates` are the only mutators.  A batch is all-or-nothing: one bad
  update refuses the whole report and nothing is stored.  There is no ``put``.
* **Semantics.**  ``add`` needs a value and a key that is not live; ``replace`` needs a value and
  a live key; ``retire`` needs a live key and no value (the entry is kept as a tombstone, so a
  retired fact cannot quietly come back as the same key without an ``add``).
* **Owner and scope.**  Memory belongs to a compiled profile's ``id`` and is partitioned by the
  profile's ``memory_scopes``.  A write or read in a scope the profile does not hold is refused,
  and so is a read of another profile's memory (``owner=``): two profiles that both list a scope
  named ``analyst`` still have two separate memories.  The profile must carry its ``digest`` and
  match it, so widening ``memory_scopes`` on the dict in hand does not widen access.

Backends only store bytes: :class:`InMemoryBackend` (tests, one process) and
:class:`FileBackend` (one crash-safe, locked :class:`~homelabnext.state.StateStore` file keyed by
profile id).  Neither is reachable through the store's public API.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any, Protocol

from .compiler import profile_digest
from .errors import AgentError
from .report import validate_report
from .schemas import schema_errors

OPS = ("add", "replace", "retire")
_PLACEHOLDER_HASH = "sha256:" + "0" * 64


class MemoryAccessError(AgentError):
    """A read or write outside the caller's own memory (another profile, or a scope it lacks)."""


class MemoryUpdateError(AgentError):
    """Memory updates that fail validation; nothing from the batch was applied."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        super().__init__("memory updates refused: " + "; ".join(self.problems))


Memory = dict[str, dict[str, dict[str, Any]]]  # scope -> key -> entry


class MemoryBackend(Protocol):
    def load(self, owner: str) -> Memory: ...

    def transact(self, owner: str, fn: Callable[[Memory], Memory]) -> Memory: ...


class InMemoryBackend:
    """Process-local backend (the fake)."""

    def __init__(self) -> None:
        self._data: dict[str, Memory] = {}

    def load(self, owner: str) -> Memory:
        return copy.deepcopy(self._data.get(owner, {}))

    def transact(self, owner: str, fn: Callable[[Memory], Memory]) -> Memory:
        new = fn(copy.deepcopy(self._data.get(owner, {})))
        self._data[owner] = copy.deepcopy(new)
        return new


class FileBackend:
    """Durable backend: one ``homelabnext.state`` file, one key per owning profile."""

    def __init__(self, path: str | Path, **state_kwargs: Any) -> None:
        from homelabnext.state import StateStore

        self._store = StateStore(path, **state_kwargs)

    def load(self, owner: str) -> Memory:
        return self._store.get(owner, {}) or {}

    def transact(self, owner: str, fn: Callable[[Memory], Memory]) -> Memory:
        return self._store.update(owner, lambda cur: fn(copy.deepcopy(cur or {})), default={})


def _identity(profile: Mapping[str, Any]) -> tuple[str, frozenset[str]]:
    """The owner id and scopes of a compiled profile whose digest checks out."""
    if not isinstance(profile, Mapping) or not isinstance(profile.get("id"), str):
        raise MemoryAccessError("memory needs a compiled agent profile (with an 'id')")
    digest = profile.get("digest")
    if not digest:
        raise MemoryAccessError(f"{profile['id']}: profile has no digest; compile it first")
    if profile_digest(profile) != digest:
        raise MemoryAccessError(
            f"{profile['id']}: profile digest does not match its content (edited after compile?)"
        )
    scopes = profile.get("memory_scopes") or []
    return profile["id"], frozenset(scopes)


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


def _apply(memory: Memory, updates: Iterable[Mapping[str, Any]], pack_id: str | None) -> Memory:
    problems: list[str] = []
    for n, u in enumerate(updates):
        where = f"memory_updates/{n} ({u['scope']}/{u['key']})"
        scope = memory.setdefault(u["scope"], {})
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
            entry: dict[str, Any] = {
                "status": "retired" if u["op"] == "retire" else "live",
                "op": u["op"],
                "value": u.get("value", cur.get("value") if cur else None),
            }
            if pack_id:
                entry["pack_id"] = pack_id
            scope[u["key"]] = entry
    if problems:
        raise MemoryUpdateError(problems)
    return memory


class MemoryStore:
    """Validated writes and owner-scoped reads over a :class:`MemoryBackend`."""

    def __init__(self, backend: MemoryBackend | None = None) -> None:
        self._backend = backend if backend is not None else InMemoryBackend()

    def apply_updates(
        self,
        profile: Mapping[str, Any],
        updates: Any,
        *,
        pack_id: str | None = None,
    ) -> Memory:
        """Validate and apply ``updates`` for ``profile``; all or nothing.  Returns the new memory."""
        owner, scopes = _identity(profile)
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
            return self._backend.load(owner)
        return self._backend.transact(owner, lambda mem: _apply(mem, updates, pack_id))

    def apply_report(
        self,
        profile: Mapping[str, Any],
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
        profile: Mapping[str, Any],
        scope: str,
        *,
        owner: str | None = None,
        include_retired: bool = False,
    ) -> dict[str, str]:
        """Live ``{key: value}`` of one scope of the caller's own memory.

        ``owner`` other than the caller's own profile id is a cross-agent read and is refused.
        """
        me, scopes = _identity(profile)
        if owner is not None and owner != me:
            raise MemoryAccessError(f"{me} may not read the memory of {owner} (cross-agent read)")
        if scope not in scopes:
            raise MemoryAccessError(f"{me}: scope {scope!r} is not in its memory_scopes")
        entries = self._backend.load(me).get(scope, {})
        return {
            k: e["value"]
            for k, e in sorted(entries.items())
            if e.get("status") == "live" or include_retired
        }
