# SPDX-License-Identifier: Apache-2.0
"""Agent memory (checklist M-09): written only through validated memory updates, read only by
its owner, historied (ADR-0037 PR 1), and sourced and labelled (PR 2).

An agent does not get a writable store.  It hands back ``memory_updates`` in its
``report_result`` (``{scope, op: add|replace|retire, key, value, sources}``) and the platform
applies them here, after validating them exactly as the report schema does.  Reads are scoped to the
agent profile that owns the memory.

* **One write path** (for this store: the broker's ``memory.write`` lane writes free-form note
  files elsewhere and carries none of these guarantees).  :meth:`MemoryStore.apply_report` (a
  whole report, checked against the pack it ran on with
  :func:`~homelabnext.agent.report.validate_report`) and :meth:`MemoryStore.apply_updates` are the
  only mutators.  A batch is all-or-nothing: one bad update refuses the whole report and nothing
  is stored.  There is no ``put``.  A batch holds at most :data:`MAX_UPDATES` updates.
* **Semantics.**  ``add`` needs a value and a key that is not live; ``replace`` needs a value and
  a live key; ``retire`` needs a live key and no value (the entry is kept as a tombstone, so a
  retired fact cannot quietly come back as the same key without an ``add``).
* **Owner and scope.**  Memory belongs to a compiled profile's ``id`` and is partitioned by the
  profile's ``memory_scopes``.  A write or read in a scope the profile does not hold is refused,
  and so is a read of another profile's memory (``owner=``): two profiles that both list a scope
  named ``analyst`` still have two separate memories.  The profile must be a
  :class:`~homelabnext.agent.compiler.VerifiedProfile` (verified against the ceiling policy and
  the lock of reviewed digests): a dict is refused, since whoever holds one can change its ``id``
  or ``memory_scopes`` and recompute its digest.  A report may not write one of the profile's
  ``platform_scopes``: only platform code does, through :meth:`MemoryStore.apply_updates` with
  ``unchecked=True``.

History (ADR-0037 decisions 1 to 6, decision 6 as amended):

* **A change log.**  Per owner the stored value is ``{entries, log}``.  Every applied update
  appends one record to ``log`` (:data:`RECORD_FIELDS`) in the **same backend transaction** as
  the entry, so a refused batch writes neither.  ``entries`` is a cache of the log:
  :func:`fold` rebuilds it, and the store refolds every key a batch touches.  An entry carries
  ``rev`` (1 on a key's first ``add``, one more on every record of the key, never restarted or
  reused), ``updated_at`` and ``reasserted_at`` (set by ``add`` and ``replace``).  A record's
  ``sources``, ``checked``, ``tlp`` and ``closure`` are set as below (PR 2); per owner the stored
  value also holds ``exposure`` (decision 9).  Memory stored before the log existed migrates
  once, on its owner's next write, to one ``migrated`` record per entry (``rev: 1``); before that record's
  time its history is unknown and :meth:`MemoryStore.as_of` answers ``compacted`` for it.  A
  legacy key or value that holds a secret is migrated as a ``purged`` marker only: no value and
  no digest.
* **An injected clock.**  ``MemoryStore(now=...)`` (a callable returning an aware UTC
  ``datetime``) is read once per batch, inside the transaction.  The log's time never goes
  backwards: a clock up to :data:`CLOCK_SKEW` behind the latest record is stamped at the log's
  time, and one further behind refuses the batch (:class:`MemoryClockError`) and pages once.
  :func:`_apply` reads no clock.
* **No secret enters the log, or an error message.**  Every string of the batch (of the whole
  report, for :meth:`MemoryStore.apply_report`), property names included, is run through the
  platform screen's secret types (:data:`homelabnext.agent.screen.SECRET_TYPES`) and the leak
  scanner's credential shapes (:mod:`homelabnext.shapes`) before anything else.  A match refuses
  the whole batch naming the position and the type.  Schema problems are reported by path and
  keyword only, never by the validator's message, which quotes values.  The screen is
  shape-based: an encoded (base64, hex), disguised (confusables) or split secret passes it.
* **History reads.**  :meth:`MemoryStore.history` and :meth:`MemoryStore.as_of` are owner-scoped
  like :meth:`MemoryStore.read`, and all three apply the reader's TLP ceiling (below).  Every read
  loads the owner's whole stored value, log included (the file backend reads its whole file on
  every call anyway).
* **Bounded per scope.**  A profile's ``memory_limits.records`` caps each scope's records
  (default :data:`DEFAULT_RECORDS`, :data:`DEFAULT_PLATFORM_RECORDS` for a scope in its
  ``platform_scopes``).  A batch that would take a scope past its cap is refused whole
  (:class:`MemoryLimitError`) and the operator is paged through the state-diffed notifier, once
  per crossing (its recovery when a write to the scope is accepted again).  A platform scope
  compacts (:func:`_compact_key`): ``memory_limits.keep_last`` folds a key's records beyond its
  last N into one range record, a retired key folds whole into one tombstone, and tombstones
  beyond the scope's budget (``memory_limits.tombstones``, default a tenth of the record cap)
  age out oldest first into the scope's one ``aged`` record, which keeps the scope's high-water
  ``rev`` so a key added again later continues above it.
* **Byte caps (decision 6, amended 2026-11-06).**  Closures (up to :data:`MAX_CLOSURE`
  identifiers) and pack exposures (up to :data:`~homelabnext.agent.pack.MAX_RENDERED`) make the
  record cap no bound on bytes (see :data:`BYTES_PER_RECORD` for the measured sizes).  Each
  scope has a byte cap over its **records only** (``memory_limits.bytes``, default
  :data:`BYTES_PER_RECORD` times its record cap), and the owner an exposure budget charged once
  across scopes (``memory_limits.exposure_bytes``, default :data:`DEFAULT_EXPOSURE_BYTES`).
  Crossing either is refused and paged as the record cap is; at the exposure budget the owner
  writes only from packs it already holds (an intended, paged lockout).  A byte refusal reports
  the cap, never a total, which would count records the writer may not read.  A range record
  keeps at most :data:`MAX_RANGE_LIST` value digests and pack ids (``truncated`` past that) and
  its folded state's own ``effective`` sources beside the union.

Sources and labels (ADR-0037 decisions 7 to 10, PR 2):

* **A checked write needs its pack.**  :meth:`MemoryStore.apply_report` and
  :meth:`MemoryStore.apply_updates` take ``pack=`` and ``pack_hash=`` (the hash must be the
  pack's own, and the pack bound to this profile: ``pack["profile"]``); without them the write is
  refused.  The runner passes the session's own pack, never one looked up by a report's
  ``pack_id``.  Every source of every update must equal an
  identifier the pack assembler recorded for something the pack rendered
  (:func:`~homelabnext.agent.report.source_problems`); text never is one, and every ``mem:``
  source is refused until packs carry a memory block (PR 3).  Records written so are
  ``checked: true``.  An update without sources is stored with ``sources: []`` and reported in
  the result's ``unsourced``.  A write returns only what it touched, filtered by the writer's own
  ceiling (``{revs, unsourced, withheld, dropped}``), and a refusal names an update's position,
  never its key.
* **Unchecked platform writes.**  ``apply_updates(..., unchecked=True)`` writes the profile's
  ``platform_scopes`` and nothing else, takes no pack, and its records are ``checked: false`` and
  ``red``.  A checked write, a report included, may not name a platform scope.
* **Labels.**  A record's ``tlp`` is the strictest of the pack's label, each source's label and
  the entry's current label, for every op; the store takes no label from a caller, so a label is
  never lowered.  Until packs carry labels (a pre-gate or an unlabelled static section is
  ``red``), memory stays ``red``.
* **Withheld reads.**  The reader's ceiling comes from the :class:`VerifiedProfile` (its attested
  ``tlp_ceiling``, else what its ``data_tier`` receives:
  :func:`~homelabnext.registry.model_tlp.receive_ceiling`).  An entry or record above it is never
  returned, nor is its key; the read says only how many it withheld (``withheld``).
  ``read``, ``history`` and ``as_of`` all return plain dicts with ``withheld``; ``history`` of a
  key with no visible record answers like a missing key, and ``as_of`` says ``aged_out`` only
  when the aged record is within the ceiling.
* **Exposure.**  A checked batch stores its pack's exposure once per owner, keyed by the pack id,
  as ``{rendered: [identifiers], memory: []}``; records point at it by ``pack_id`` (and a folded
  record by its ``pack_ids``), and an exposure no record points at any longer is dropped.
* **Closure.**  An entry's effective sources are the union of its records' sources since its
  last ``add``; each record stores them as its ``closure`` (no ``mem:`` revisions or aliases
  yet), at most :data:`MAX_CLOSURE`.  A checked update past that refuses its batch (retire the
  key and add it again); an unchecked platform update past it is dropped and reported in
  ``dropped`` (decision 10, amended), so it cannot stall the platform's fold.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import re
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from homelabnext import shapes, tlp
from homelabnext.notify.core_pairs import AGENT_MEMORY_CAP, AGENT_MEMORY_CLOCK
from homelabnext.registry.model_tlp import receive_ceiling

from .compiler import VerifiedProfile, require_verified
from .digest import digest_of
from .errors import AgentError
from .pack import MAX_RENDERED, pack_label, pack_profile, rendered_identifiers
from .report import (
    MAX_MEMORY_UPDATES,
    MEM_PREFIX,
    MEM_REFUSAL,
    limit_problems,
    source_problems,
    validate_report,
)
from .schemas import schema_error_shapes, schema_property_names
from .screen import SECRET_TYPES, Screener

#: the ops the store applies; ``verify`` is in report_result 1.2 but applied only from ADR-0037
#: PR 4 (decision 15)
OPS = ("add", "replace", "retire")
#: updates in one batch (ADR-0037 decision 7 keeps list limits in code)
MAX_UPDATES = MAX_MEMORY_UPDATES
#: identifiers in one record's base-source closure (ADR-0037 decision 10)
MAX_CLOSURE = 256
#: a scope's default byte cap per record of its record cap.  Measured (compact JSON): a typical
#: record (a 200-character value, three sources, a ten-identifier closure) is about 1 kB; the
#: largest model record (2,000 characters, 16 sources, a full 256-identifier closure) 22.5 kB in
#: ASCII and 26.5 kB in CJK text; a range record at its list caps about 95 kB.  So the record cap
#: binds first for ordinary memory, and the byte cap only once closures grow fat.
BYTES_PER_RECORD = 2_000
#: an owner's default exposure budget: every scope's pack exposures together.  One exposure is
#: 1.5 kB at 20 rendered identifiers and 75.8 kB at the 1,024 cap, so 50 MB holds about 33,000
#: ordinary packs or 660 full ones
DEFAULT_EXPOSURE_BYTES = 50_000_000
#: how many value digests and pack ids a range record keeps (the newest); past it the record is
#: ``truncated`` (ADR-0037 decision 6, amended 2026-11-06)
MAX_RANGE_LIST = 256
_PLACEHOLDER_HASH = "sha256:" + "0" * 64
#: a pack id: a pack's hash
_PACK_ID = re.compile(r"sha256:[0-9a-f]{64}")
log = logging.getLogger("homelabnext.agent.memory")

#: record caps of a profile without ``memory_limits.records`` for the scope (ADR-0037 decision 6)
DEFAULT_RECORDS = 10_000
DEFAULT_PLATFORM_RECORDS = 100_000
#: a platform scope's default tombstone budget: this share of its record cap (decision 6, amended)
TOMBSTONE_SHARE = 0.1

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
#: the label of a record with nothing to lower it: a migrated or unchecked record, and every
#: record while packs carry no labels (ADR-0037 decision 8)
UNLABELLED = "red"

#: the notifier pair the record cap pages with (its titles live in ``core_pairs``)
CAP_TITLE, CAP_CLEARED = AGENT_MEMORY_CAP
CLOCK_TITLE, CLOCK_CLEARED = AGENT_MEMORY_CLOCK
#: how far behind its log's latest record the clock may be: within it the batch is stamped at
#: the log's time; beyond it the batch is refused and the operator paged
CLOCK_SKEW = timedelta(minutes=5)

#: the leak scanner's credential shapes, by its pattern names (``tools/leak_scan.py``)
_SHAPES = tuple(
    (name, re.compile(rx))
    for name, rx in (
        ("private-key-block", shapes.PRIVATE_KEY_HEADER),
        ("aws-access-key", shapes.AWS_ACCESS_KEY),
        ("aws-secret-key", shapes.AWS_SECRET_KEY),
        ("github-token", shapes.GITHUB_TOKEN),
        ("slack-token", shapes.SLACK_TOKEN),
        ("google-api-key", shapes.GOOGLE_KEY),
        ("jwt", shapes.JWT),
        ("age-secret-key", shapes.AGE_SECRET_KEY),
        ("vault-blob", shapes.VAULT_BLOB),
    )
)
#: the property names a report defines: the only ones echoed in a refusal's path
_KNOWN = schema_property_names("agent", "report_result")
#: a name safe to echo in a message once it has passed the screen
_SHOWN = re.compile(r"[a-z_][a-z0-9_:-]{0,63}")


def _name(text: Any) -> str:
    """``text`` quoted when it is a plain name that holds no secret, else a placeholder."""
    if isinstance(text, str) and _SHOWN.fullmatch(text) and not secret_types(text):
        return repr(text)
    return "<a name not shown>"


class MemoryAccessError(AgentError):
    """A read or write outside the caller's own memory (another profile, or a scope it lacks)."""


class MemoryUpdateError(AgentError):
    """Memory updates that fail validation; nothing from the batch was applied."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        super().__init__("memory updates refused: " + "; ".join(self.problems))


def _cap_advice(platform: bool, unit: str = "records") -> str:
    """What actually frees a cap.  A model-written scope never shrinks (only an operator purge,
    ADR-0037 PR 3, removes records), so its advice is the reviewed profile or a purge; a platform
    scope compacts once its finished keys are retired."""
    if unit == "exposure":
        return (
            "raise memory_limits.exposure_bytes in the reviewed profile (or an operator purge, "
            "ADR-0037 PR 3): until then every checked write of this profile is refused"
        )
    name = "memory_limits.bytes" if unit == "bytes" else "memory_limits.records"
    if platform and unit == "bytes":
        return (
            "retire finished keys and set memory_limits.keep_last so the scope compacts, or "
            f"raise {name} in the reviewed profile"
        )
    if unit == "bytes":
        return f"raise {name} in the reviewed profile (or an operator purge, ADR-0037 PR 3)"
    if platform:
        return (
            "set memory_limits.keep_last for keys that are replaced and retire finished keys so "
            "the scope compacts, or raise memory_limits.records in the reviewed profile"
        )
    return (
        "raise memory_limits.records in the reviewed profile (or an operator purge, ADR-0037 PR 3)"
    )


class MemoryLimitError(MemoryUpdateError):
    """A batch that would take a scope past its record cap (``unit`` ``records``) or its byte cap
    (``bytes``), or the owner past its exposure budget (``exposure``, scope ``*``); nothing from
    it was applied.  ``scopes`` maps each to ``(what it would hold, cap)``; for ``bytes`` and
    ``exposure`` what it would hold is ``None``, since a byte total would count records the
    reader may not see (ADR-0037 decision 8).  ``platform`` names the platform scopes."""

    def __init__(
        self,
        owner: str,
        scopes: Mapping[str, tuple[int, int]],
        platform: Iterable[str] = (),
        unit: str = "records",
    ) -> None:
        self.owner = owner
        self.scopes = dict(scopes)
        self.platform = frozenset(platform)
        self.unit = unit
        super().__init__([_cap_line(owner, s, n, cap, unit, s in self.platform)
                          for s, (n, cap) in sorted(self.scopes.items())])  # fmt: skip


def _cap_line(owner: str, scope: str, n: int | None, cap: int, unit: str, platform: bool) -> str:
    advice = _cap_advice(platform, unit)
    if unit == "exposure":
        return (
            f"{owner}'s pack exposures would exceed its exposure budget of {cap} bytes; "
            f"its checked writes are refused: {advice}"
        )
    if unit == "bytes":
        return (
            f"scope {scope!r} of {owner} would exceed its byte cap of {cap} bytes; its writes "
            f"are refused: {advice}"
        )
    return (
        f"scope {scope!r} of {owner} is at its record cap ({n} records would exceed {cap}); "
        f"its writes are refused: {advice}"
    )


class MemoryClockError(MemoryUpdateError):
    """The clock is more than :data:`CLOCK_SKEW` behind the log's latest record; nothing from
    the batch was applied (a smaller lag is absorbed by stamping the batch at the log's time)."""

    def __init__(self, owner: str, behind: timedelta) -> None:
        self.owner = owner
        self.behind = behind
        super().__init__(
            [
                f"the clock is behind {owner}'s memory log by {behind} (more than {CLOCK_SKEW}); "
                "fix the host clock, or, if it is right, the log holds a record stamped in the "
                "future (an operator re-stamp, ADR-0037 PR 3): the log's time never goes backwards"
            ]
        )


Memory = dict[str, dict[str, dict[str, Any]]]  # scope -> key -> entry
Stored = dict[str, Any]  # {"entries": Memory, "log": [record, ...], "exposure": {pack_id: ...}}
Record = dict[str, Any]


@dataclass(frozen=True)
class _Check:
    """How a batch was checked: ``checked`` (against ``pack_id``'s pack), the pack's label, each
    rendered identifier's label, and the exposure to store (None for an unchecked write)."""

    checked: bool
    pack_id: str | None
    pack_tlp: str
    labels: Mapping[str, str]
    rendered: tuple[str, ...] | None


class MemoryBackend(Protocol):
    def load(self, owner: str) -> Any: ...

    def transact(self, owner: str, fn: Callable[[Any], Any]) -> Any: ...


class InMemoryBackend:
    """Process-local backend (the fake); one lock around every read and transaction."""

    def __init__(self) -> None:
        import copy

        self._copy = copy.deepcopy
        self._data: dict[str, Any] = {}
        self._lock = threading.Lock()

    def load(self, owner: str) -> Any:
        with self._lock:
            return self._copy(self._data.get(owner, {}))

    def transact(self, owner: str, fn: Callable[[Any], Any]) -> Any:
        with self._lock:
            new = fn(self._copy(self._data.get(owner, {})))  # raises before anything is stored
            self._data[owner] = self._copy(new)
            return new


class FileBackend:
    """Durable backend: one ``homelabnext.state`` file, one key per owning profile."""

    def __init__(self, path: str | Path, **state_kwargs: Any) -> None:
        from homelabnext.state import StateStore

        self._store = StateStore(path, **state_kwargs)

    def load(self, owner: str) -> Any:
        return self._store.get(owner, {}) or {}

    def transact(self, owner: str, fn: Callable[[Any], Any]) -> Any:
        # StateStore.update loads a fresh copy under its lock and writes only after fn returns,
        # so a raising fn leaves the file as it was
        return self._store.update(owner, lambda cur: fn(cur or {}), default={})


# ---------------------------------------------------------------- identity and limits
def _identity(profile: VerifiedProfile) -> tuple[str, frozenset[str]]:
    """The owner id and scopes of a verified profile."""
    require_verified(profile, "agent memory")
    scopes = profile.get("memory_scopes") or []
    return profile["id"], frozenset(scopes)


def _platform_scopes(profile: VerifiedProfile) -> frozenset[str]:
    return frozenset(profile.get("platform_scopes") or [])


def _limits(profile: VerifiedProfile, name: str) -> Mapping[str, Any]:
    return (profile.get("memory_limits") or {}).get(name) or {}


def record_cap(profile: VerifiedProfile, scope: str) -> int:
    """The record cap of ``scope`` for ``profile``: its ``memory_limits.records`` entry, else the
    code-constant default (higher for a platform scope)."""
    limits = _limits(profile, "records")
    if scope in limits:
        return int(limits[scope])
    return DEFAULT_PLATFORM_RECORDS if scope in _platform_scopes(profile) else DEFAULT_RECORDS


def byte_cap(profile: VerifiedProfile, scope: str) -> int:
    """The byte cap of ``scope`` for ``profile``: its ``memory_limits.bytes`` entry, else
    :data:`BYTES_PER_RECORD` times its record cap.  It counts the scope's records only; pack
    exposures are charged once per owner against :func:`exposure_budget`."""
    limits = _limits(profile, "bytes")
    if scope in limits:
        return int(limits[scope])
    return BYTES_PER_RECORD * record_cap(profile, scope)


def exposure_budget(profile: VerifiedProfile) -> int:
    """The bytes ``profile``'s pack exposures may take together, charged once per owner:
    ``memory_limits.exposure_bytes``, else :data:`DEFAULT_EXPOSURE_BYTES`."""
    value = (profile.get("memory_limits") or {}).get("exposure_bytes")
    return int(value) if isinstance(value, int) else DEFAULT_EXPOSURE_BYTES


def read_ceiling(profile: VerifiedProfile) -> tlp.Label:
    """The TLP ceiling ``profile`` reads its memory at (ADR-0037 decision 8): its attested
    ``tlp_ceiling``, else the ceiling its ``data_tier`` receives at, never a caller's argument."""
    require_verified(profile, "agent memory")
    return receive_ceiling(profile.get("tlp_ceiling"), profile.get("data_tier"))


def tombstone_budget(profile: VerifiedProfile, scope: str) -> int:
    """How many whole-key tombstones a platform scope keeps before the oldest age out: its
    ``memory_limits.tombstones`` entry, else a tenth of its record cap (at least 1)."""
    limits = _limits(profile, "tombstones")
    if scope in limits:
        return int(limits[scope])
    return max(1, int(record_cap(profile, scope) * TOMBSTONE_SHARE))


def _keep_last(profile: VerifiedProfile, scope: str, key: str) -> int | None:
    """How many of ``key``'s records stay whole (platform scopes only): the largest N of the
    ``keep_last`` patterns (shell-style globs) that match the key, or None."""
    if scope not in _platform_scopes(profile):
        return None
    pats = _limits(profile, "keep_last").get(scope) or {}
    hits = [int(n) for pat, n in pats.items() if fnmatch.fnmatchcase(key, pat)]
    return max(hits) if hits else None


# ---------------------------------------------------------------- the secret screen
def secret_types(text: str) -> list[str]:
    """The secret types found in ``text``: the platform screen's secret types and the leak
    scanner's credential shapes.  Names only, never the matched value."""
    found = {t for _, _, t, _ in Screener(types=SECRET_TYPES).find(text)}
    found.update(name for name, rx in _SHAPES if rx.search(text))
    return sorted(found)


def secret_problems(doc: Any, root: str = "") -> list[str]:
    """One problem per string of ``doc`` (every leaf and every property name, at any depth) that
    holds a secret, naming its position and the types, never the value.  Run before anything
    that could echo the document."""
    problems: list[str] = []

    def at(path: str, part: str) -> str:
        return f"{path}/{part}" if path else part

    def walk(node: Any, path: str) -> None:
        if isinstance(node, str):
            types = secret_types(node)
            if types:
                problems.append(f"{path or '$'}: holds a secret ({', '.join(types)})")
        elif isinstance(node, Mapping):
            for i, (k, v) in enumerate(node.items()):
                name = k if isinstance(k, str) else str(k)
                types = secret_types(name)
                if types:
                    problems.append(
                        f"{path or '$'}: property #{i} name holds a secret ({', '.join(types)})"
                    )
                part = k if isinstance(k, str) and k in _KNOWN and not types else f"#{i}"
                walk(v, at(path, part))
        elif isinstance(node, (list, tuple)):
            for i, v in enumerate(node):
                walk(v, at(path, str(i)))

    walk(doc, root)
    return problems


def _refuse_secrets(doc: Any, root: str) -> None:
    problems = secret_problems(doc, root)
    if problems:
        raise MemoryUpdateError(
            [*problems, "a secret may never enter memory or its log; nothing was applied"]
        )


# ---------------------------------------------------------------- validation
def _report_doc(updates: Any, profile_id: str) -> dict[str, Any]:
    return {
        "pack_id": _PLACEHOLDER_HASH,
        "profile": profile_id,
        "status": "partial",
        "summary": "memory update validation",
        "cites": [],
        "unknowns": [],
        "memory_updates": updates,
    }


def update_errors(updates: Any, profile_id: str = "profile:memory-check") -> list[str]:
    """Schema problems of a ``memory_updates`` list, validated exactly as inside a report, by
    path and keyword only (never quoting a value)."""
    doc = _report_doc(updates, profile_id)
    return [e for e in schema_error_shapes("agent", "report_result", doc) if e.startswith("memory")]


def _too_many(updates: Any) -> None:
    if isinstance(updates, list) and len(updates) > MAX_UPDATES:
        raise MemoryUpdateError(
            [f"memory_updates: {len(updates)} updates; at most {MAX_UPDATES} in one batch"]
        )


# ---------------------------------------------------------------- time
def _stamp(t: datetime) -> str:
    """Fixed-width UTC stamp, so stamps order as strings."""
    if not isinstance(t, datetime) or t.tzinfo is None or t.utcoffset() is None:
        raise ValueError("memory clock must give an aware UTC datetime")
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(stamp: str) -> datetime:
    return datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- the log and its fold
def _is_logged(raw: Any) -> bool:
    return (
        isinstance(raw, Mapping)
        and set(raw) in ({"entries", "log"}, {"entries", "log", "exposure"})
        and isinstance(raw["log"], list)
    )


def _stored(raw: Any, at: str) -> tuple[Stored, list[str]]:
    """``raw`` in the ``{entries, log}`` shape, and the positions of legacy secrets purged.

    Memory stored before the log migrates to one ``migrated`` record per entry, stamped ``at``
    (ADR-0037 decision 2).  A legacy key or value that holds a secret is migrated as
    the ``purged`` marker: no value and no digest of it (an unsalted digest of a low-entropy
    secret confirms a guess offline), and a secret key is renamed ``purged-<its position>``.
    The positions are returned, never the values."""
    if not raw:
        return {"entries": {}, "log": [], "exposure": {}}, []
    if _is_logged(raw):  # PR 1 stored no exposure
        return {"exposure": {}, **raw}, []
    # pre-log memory: {scope: {key: {status, op, value, pack_id?}}} (a scope is a dict, never a
    # list, so a legacy scope named "log" cannot be mistaken for the new shape)
    out: list[Record] = []
    purged: list[str] = []
    for si, scope in enumerate(sorted(raw)):
        block = raw[scope]
        if not isinstance(block, Mapping):
            continue
        for ki, key in enumerate(sorted(block)):
            e = block[key] if isinstance(block[key], Mapping) else {}
            value = e.get("value") if isinstance(e.get("value"), str) else None
            bad_key = bool(secret_types(key))
            bad_value = value is not None and bool(secret_types(value))
            name = key
            if bad_key:  # named by position, never by anything derived from the secret
                n = 0
                while (name := f"purged-{ki}" + (f"-{n}" if n else "")) in block:
                    n += 1
            rec = _record(
                at,
                scope,
                name,
                e.get("op") or ("retire" if e.get("status") == "retired" else "add"),
                1,
                value,
                e.get("pack_id"),
                keep_value=not (bad_key or bad_value),
            )
            rec["migrated"] = True
            if bad_key or bad_value:
                # no digest either: an unsalted digest of a low-entropy secret confirms a guess
                rec.pop("value_digest", None)
                rec["purged"] = True
                where = " and ".join(w for w, b in (("key", bad_key), ("value", bad_value)) if b)
                purged.append(f"scope #{si} entry #{ki} ({where})")
            out.append(rec)
    return {"entries": fold(out), "log": out, "exposure": {}}, purged


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
) -> Record:
    rec: Record = {"at": at, "scope": scope, "key": key, "op": op, "rev": rev}
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


def _union(*lists: Iterable[Any]) -> list[Any]:
    return list(dict.fromkeys(x for xs in lists for x in xs))


def _step(entry: dict[str, Any] | None, rec: Mapping[str, Any]) -> dict[str, Any]:
    """The entry after ``rec`` (one step of the fold)."""
    op = rec["op"]
    status = "retired" if op == "retire" else "live"
    if rec.get("compacted") in ("whole", "range"):  # folded records: their state, no value
        # the entry's effective sources are the folded state's own, not the union across the
        # adds the range spans (``sources`` keeps that union, for dependents)
        effective = rec.get("effective", rec["sources"])
        value, sources, reasserted = None, list(effective), rec.get("reasserted_at")
        status = rec["status"]
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
        "status": status,
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
    """The entries a log describes (``entries`` is a cache of exactly this).  The scope's
    ``aged`` record names no key and adds no entry."""
    entries: Memory = {}
    for rec in records:
        if rec["op"] == "aged":
            continue
        scope = entries.setdefault(rec["scope"], {})
        scope[rec["key"]] = _step(scope.get(rec["key"]), rec)
    return entries


def _start(rec: Mapping[str, Any]) -> str | None:
    """When ``rec``'s history starts: its own time, a folded record's ``since`` (None: unknown,
    because it holds a migrated record whose earlier history was never logged)."""
    if rec.get("migrated"):
        return None
    if rec.get("compacted"):
        return rec.get("since")
    return rec["at"]


def _squash(recs: list[Record], kind: str) -> Record:
    """One record standing for ``recs`` (one key's, in order): ``whole`` (a retired key's
    tombstone) or ``range`` (records beyond ``keep_last``).  It keeps the rev range, the value
    digests, the union of sources, closures and pack ids, the strictest label, when the range
    starts (``since``), and the state the records leave the entry in: its status, and its own
    effective sources (``effective``: those since its last add, which a range that spans a retire
    and a later add must not take from the union).  It keeps at most :data:`MAX_RANGE_LIST`
    value digests and pack ids, the newest; past that it is marked ``truncated``, and a retraction
    treats it as exposed to everything its sources reach."""
    first, last = recs[0], recs[-1]
    starts = [_start(r) for r in recs]
    state = fold(recs)[last["scope"]][last["key"]]
    digests = [
        d for d in _union(*(r.get("value_digests") or [r.get("value_digest")] for r in recs)) if d
    ]
    packs = [p for p in _union(*(r.get("pack_ids") or [r.get("pack_id")] for r in recs)) if p]
    truncated = (
        any(r.get("truncated") for r in recs)
        or len(digests) > MAX_RANGE_LIST
        or len(packs) > MAX_RANGE_LIST
    )
    out = {
        "at": last["at"],
        "scope": last["scope"],
        "key": last["key"],
        "op": "retire" if kind == "whole" else last["op"],
        "rev": last["rev"],
        "rev_from": first.get("rev_from", first["rev"]),
        "compacted": kind,
        "status": "retired" if kind == "whole" else state["status"],
        "since": None if any(s is None for s in starts) else min(starts),  # type: ignore[type-var]
        "value_digests": digests[-MAX_RANGE_LIST:],
        "pack_id": last.get("pack_id"),
        "pack_ids": packs[-MAX_RANGE_LIST:],
        "sources": _union(*(r["sources"] for r in recs)),
        "effective": list(state["sources"]),
        "checked": all(r["checked"] for r in recs),
        "tlp": str(tlp.strictest(r["tlp"] for r in recs)),
        "closure": _union(*(r["closure"] for r in recs)),
        "reasserted_at": state["reasserted_at"],
    }
    if truncated:
        out["truncated"] = True
    if any(r.get("purged") for r in recs):
        out["purged"] = True
    return out


def _compact_key(recs: list[Record], keep_last: int | None, whole: bool) -> list[Record] | None:
    """One key's records compacted (ADR-0037 decision 6, amended), or None when there is
    nothing to do: ``whole`` folds them all into a tombstone; otherwise every record beyond the
    last ``keep_last`` folds into one range record."""
    if whole:
        if len(recs) == 1 and recs[0].get("compacted") == "whole":
            return None
        return [_squash(recs, "whole")]
    if keep_last is None or len(recs) <= keep_last:
        return None
    older = recs[:-keep_last]
    if len(older) == 1 and older[0].get("compacted"):
        return None
    return [_squash(older, "range"), *recs[-keep_last:]]


def _age(records: list[Record], scope: str, budget: int, entries: Memory) -> list[Record]:
    """Age out a platform scope's oldest tombstones beyond ``budget`` into its one ``aged``
    record (the scope's high-water ``rev``, how many aged out, and the time range they cover);
    their keys leave ``entries``.

    Only a key's **last** record can be its tombstone: a key retired and then added again keeps
    its old tombstone as an earlier record, and that key is live, so it never ages out."""
    last: dict[str, int] = {}
    for i, r in enumerate(records):
        if r["scope"] == scope and r["op"] != "aged":
            last[r["key"]] = i
    live = entries.get(scope, {})
    tombs = [
        (records[i]["at"], i)
        for key, i in last.items()
        if records[i].get("compacted") == "whole"
        and (live.get(key) or {}).get("status", "retired") == "retired"
    ]
    if len(tombs) <= budget:
        return records
    victims = {i for _, i in sorted(tombs)[: len(tombs) - budget]}
    old = next((r for r in records if r["scope"] == scope and r["op"] == "aged"), None)
    gone = [records[i] for i in sorted(victims)] + ([old] if old else [])
    starts = [r.get("since") for r in gone]
    aged: Record = {
        "at": max(r["at"] for r in gone),
        "scope": scope,
        "key": None,
        "op": "aged",
        "rev": max(r["rev"] for r in gone),
        "compacted": "aged",
        "since": None if any(s is None for s in starts) else min(starts),  # type: ignore[type-var]
        "count": len(victims) + (old["count"] if old else 0),
        "pack_id": None,
        "sources": [],
        "checked": all(r["checked"] for r in gone),
        "tlp": str(tlp.strictest(r["tlp"] for r in gone)),
        "closure": [],
    }
    for i in victims:
        key = records[i]["key"]
        if (live.get(key) or {}).get("status") == "retired":  # never a live entry
            live.pop(key, None)
    out = [r for i, r in enumerate(records) if i not in victims and r is not old]
    out.append(aged)
    return out


def _size(doc: Any) -> int:
    """Bytes ``doc`` takes serialised (compact JSON, UTF-8): what the byte cap counts."""
    return len(json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _pack_ids(rec: Mapping[str, Any]) -> list[str]:
    """The pack ids ``rec`` points at: its own and, for a folded record, every one it folded."""
    return [p for p in [rec.get("pack_id"), *(rec.get("pack_ids") or ())] if p]


def _label(check: _Check, sources: Iterable[str], cur: Mapping[str, Any] | None) -> str:
    """A record's label (ADR-0037 decision 8): the strictest of the pack's label, each source's
    label and the entry's current label.  Nothing a caller passes can lower it."""
    labels = [check.pack_tlp, *(check.labels.get(s, UNLABELLED) for s in sources)]
    if cur is not None:
        labels.append(cur.get("tlp", UNLABELLED))
    return str(tlp.strictest(labels))


def _apply(
    stored: Stored,
    updates: Iterable[Mapping[str, Any]],
    check: _Check,
    now: str,
    profile: VerifiedProfile,
    result: dict[str, Any] | None = None,
) -> Stored:
    """Apply ``updates`` stamped no earlier than ``now`` or the log's latest record: append
    their records (sources, label and closure set from ``check``), store the pack's exposure,
    compact, refold the touched keys, drop exposures nothing points at, and check the record and
    byte caps and the owner's exposure budget.  Raises on any problem, so the backend stores
    nothing.  Refusals name an update by its position only, never its key (keys are
    model-chosen, and a refusal is read where the key's label may not allow it).

    An unchecked (platform) update whose closure would pass :data:`MAX_CLOSURE` is dropped, not
    fatal, and named in ``result["dropped"]``, so a long-lived platform key cannot stall its
    writer's fold (ADR-0037 decision 10, amended); in a checked batch it refuses the batch.
    ``result["touched"]`` gets each applied ``(scope, key)``."""
    entries: Memory = stored["entries"]
    records: list[Record] = stored["log"]
    exposure: dict[str, Any] = dict(stored.get("exposure") or {})
    high: dict[str, int] = {}  # scope -> high-water rev of its aged-out keys
    latest = ""
    for r in records:
        latest = max(latest, r["at"])
        if r["op"] == "aged":
            high[r["scope"]] = r["rev"]
    if latest > now:  # the log's time never goes backwards
        behind = _parse(latest) - _parse(now)
        if behind > CLOCK_SKEW:
            raise MemoryClockError(profile["id"], behind)
    at = max(now, latest)
    problems: list[str] = []
    dropped: list[str] = []
    touched: dict[tuple[str, str], None] = {}
    for n, u in enumerate(updates):
        where = f"memory_updates/{n}"
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
            rev = max(cur["rev"] if cur else 0, high.get(u["scope"], 0)) + 1
            value = u["value"] if has_value else (cur or {}).get("value")
            rec = _record(
                at, u["scope"], u["key"], u["op"], rev, value, check.pack_id, keep_value=has_value
            )
            sources = list(u.get("sources") or ())
            rec.update(sources=sources, checked=check.checked, tlp=_label(check, sources, cur))
            entry = _step(cur, rec)
            if len(entry["sources"]) > MAX_CLOSURE:
                why = (
                    f"{where}: its sources since the key's last add would number "
                    f"{len(entry['sources'])}, over the closure cap of {MAX_CLOSURE}; retire the "
                    "key and add it again"
                )
                if check.checked:
                    problems.append(why)
                else:
                    dropped.append(why + " (dropped; the rest of the batch applies)")
                continue
            rec["closure"] = list(entry["sources"])  # no mem: closures or aliases yet (PR 3)
            records.append(rec)
            scope[u["key"]] = entry
            touched[(u["scope"], u["key"])] = None
    if problems:
        raise MemoryUpdateError(problems)
    new_exposure = (
        check.rendered is not None
        and bool(check.pack_id)
        and bool(touched)
        and check.pack_id not in exposure
    )
    if new_exposure:
        exposure[check.pack_id] = {"rendered": list(check.rendered), "memory": []}

    platform = _platform_scopes(profile)
    hot = {k for k in touched if k[0] in platform}
    if hot:  # compaction: one pass to index the touched keys, one to rebuild the log
        where_at: dict[tuple[str, str], list[int]] = {k: [] for k in hot}
        for i, r in enumerate(records):
            k = (r["scope"], r["key"])
            if k in where_at:
                where_at[k].append(i)
        swap: dict[int, list[Record]] = {}
        drop: set[int] = set()
        for (scope, key), pos in where_at.items():
            new = _compact_key(
                [records[i] for i in pos],
                _keep_last(profile, scope, key),
                entries[scope][key]["status"] == "retired",
            )
            if new is not None:
                swap[pos[-1]] = new
                drop.update(pos[:-1])
        if swap:
            records = [x for i, r in enumerate(records) if i not in drop for x in swap.get(i, [r])]
        for scope in sorted({s for s, _ in hot}):
            records = _age(records, scope, tombstone_budget(profile, scope), entries)

    # refold the touched keys from the log (compaction may have dropped a value the cache held),
    # so the cache is the fold by construction; one pass, which also counts each scope's records
    # and record bytes and finds the exposures still pointed at
    hot_scopes = {s for s, _ in touched}
    counts: dict[str, int] = {}
    sizes: dict[str, int] = {}
    pointed: set[str] = set()
    refolded: dict[tuple[str, str], dict[str, Any] | None] = {
        k: None for k in touched if k[1] in entries.get(k[0], {})
    }
    for r in records:
        counts[r["scope"]] = counts.get(r["scope"], 0) + 1
        ids = _pack_ids(r)
        pointed.update(ids)
        if r["scope"] in hot_scopes:  # a scope's byte cap counts its records only
            sizes[r["scope"]] = sizes.get(r["scope"], 0) + _size(r)
        k = (r["scope"], r["key"])
        if k in refolded:
            refolded[k] = _step(refolded[k], r)
    for (scope, key), entry in refolded.items():
        entries[scope][key] = entry  # type: ignore[assignment]
    exposure = {p: e for p, e in exposure.items() if p in pointed}
    over = {
        s: (counts[s], record_cap(profile, s))
        for s in sorted(hot_scopes)
        if counts.get(s, 0) > record_cap(profile, s)
    }
    if over:
        raise MemoryLimitError(profile["id"], over, platform & set(over))
    heavy = {
        s: (None, byte_cap(profile, s))
        for s in sorted(hot_scopes)
        if sizes.get(s, 0) > byte_cap(profile, s)
    }
    if heavy:
        raise MemoryLimitError(profile["id"], heavy, platform & set(heavy), unit="bytes")
    # exposures are charged once per owner; only a batch that adds one can cross the budget, so
    # an owner at it keeps writing from packs it already holds and is refused (and paged) for any
    # new one: the self-lockout is intended, and ends when the operator raises the budget
    if new_exposure and sum(_size(e) for e in exposure.values()) > exposure_budget(profile):
        raise MemoryLimitError(
            profile["id"], {"*": (None, exposure_budget(profile))}, (), unit="exposure"
        )
    if result is not None:
        result["dropped"] = dropped
        result["touched"] = list(touched)
    return {"entries": entries, "log": records, "exposure": exposure}


def _readable(profile: VerifiedProfile, records: list[Record]) -> tuple[list[Record], int]:
    """The records ``profile`` may read and how many it may not: those labelled above its
    ceiling (:func:`read_ceiling`) are withheld, counted and never returned (ADR-0037 decision
    8)."""
    ceiling = read_ceiling(profile)
    shown = [r for r in records if tlp.allows(ceiling, r.get("tlp"))]
    return shown, len(records) - len(shown)


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
            notifier.register_pair(CLOCK_TITLE, CLOCK_CLEARED)

    def apply_updates(
        self,
        profile: VerifiedProfile,
        updates: Any,
        *,
        pack: Mapping[str, Any] | None = None,
        pack_hash: str | None = None,
        pack_id: str | None = None,
        unchecked: bool = False,
    ) -> dict[str, Any]:
        """Validate and apply ``updates`` for ``profile``; all or nothing (but see ``dropped``).

        Returns only what the batch touched, filtered by the writer's own ceiling
        (:func:`read_ceiling`), so a write result is never a way round a withheld read:
        ``{"revs": {"<scope>/<key>": rev}, "unsourced": ["<scope>/<key>", ...], "withheld": n,
        "dropped": [problem, ...]}``.  ``revs`` and ``unsourced`` name only keys whose new record
        the writer may read; ``withheld`` counts the touched keys it may not.  ``dropped`` lists,
        by position, the unchecked platform updates dropped at the closure cap.

        A **checked** write passes the ``pack`` the updates came from and its ``pack_hash`` (the
        pack's own hash; ``pack_id``, if given, must equal it), and every source must be an
        identifier that pack rendered (ADR-0037 decision 7).  It may not name a platform scope.
        An **unchecked** write (``unchecked=True``, platform code only) takes no pack, writes the
        profile's ``platform_scopes`` and nothing else, and its records are ``checked: false``
        and ``red``; ``pack_id`` may name the pack it acted for.  Without either, the write is
        refused.  A report goes through :meth:`apply_report`."""
        owner, scopes = _identity(profile)
        _too_many(updates)
        _refuse_secrets(updates, "memory_updates")
        errs = update_errors(updates, owner)
        if errs:
            raise MemoryUpdateError(errs)
        foreign = sorted({u["scope"] for u in updates} - scopes)
        if foreign:
            raise MemoryAccessError(
                f"{owner}: memory scopes {foreign} are not in the profile's memory_scopes "
                f"{sorted(scopes)}"
            )
        verify = [
            f"memory_updates/{n}: op 'verify' is in report_result 1.2, but the store applies it "
            "only from ADR-0037 PR 4 (decision 15: a verifier, not a model, verifies a fact)"
            for n, u in enumerate(updates)
            if u["op"] == "verify"
        ]
        if verify:
            raise MemoryUpdateError([*verify, "nothing was applied"])
        check = self._check(profile, updates, pack, pack_hash, pack_id, unchecked)
        unsourced = {(u["scope"], u["key"]) for u in updates if not u.get("sources")}
        if not updates:
            return {"revs": {}, "unsourced": [], "withheld": 0, "dropped": []}
        result: dict[str, Any] = {}

        def fn(raw: Any) -> Stored:
            now = _stamp(self._now())  # read under the backend's lock, inside the transaction
            stored, purged = _stored(raw, now)
            self._purged(owner, purged)
            result.clear()
            return _apply(stored, updates, check, now, profile, result)

        try:
            new = self._backend.transact(owner, fn)
        except MemoryClockError as exc:
            self._clock_page(owner, exc.behind)
            raise
        except MemoryLimitError as exc:
            for scope, (n, cap) in exc.scopes.items():
                held = f"{n} {exc.unit}" if n is not None else "its contents"
                self._page(
                    owner,
                    scope,
                    f"{held} would exceed the cap of {cap}",
                    scope in exc.platform,
                    exc.unit,
                )
            raise
        self._clock_page(owner, None)
        for scope in sorted({u["scope"] for u in updates}):
            self._page(owner, scope, None, False)
        if check.checked:
            self._page(owner, "*", None, False, "exposure")
        ceiling = read_ceiling(profile)
        revs: dict[str, int] = {}
        withheld = 0
        shown: set[tuple[str, str]] = set()
        for scope, key in result.get("touched", ()):
            entry = new["entries"].get(scope, {}).get(key)
            if entry is None:
                continue
            if tlp.allows(ceiling, entry.get("tlp")):
                revs[f"{scope}/{key}"] = entry["rev"]
                shown.add((scope, key))
            else:
                withheld += 1
        return {
            "revs": revs,
            "unsourced": sorted(f"{s}/{k}" for s, k in unsourced & shown),
            "withheld": withheld,
            "dropped": list(result.get("dropped", ())),
        }

    def _check(
        self,
        profile: VerifiedProfile,
        updates: list[Mapping[str, Any]],
        pack: Mapping[str, Any] | None,
        pack_hash: str | None,
        pack_id: str | None,
        unchecked: bool,
    ) -> _Check:
        """How ``updates`` are checked (ADR-0037 decision 7); raises when they may not be
        written that way.  Sources are named by position only, never echoed."""
        owner = profile["id"]
        platform = _platform_scopes(profile)
        mem = [
            f"memory_updates/{n}/sources/{i}: {MEM_REFUSAL}"
            for n, u in enumerate(updates)
            for i, s in enumerate(u.get("sources") or ())
            if s.startswith(MEM_PREFIX)
        ]
        if unchecked is True:
            if pack is not None or pack_hash is not None:
                raise MemoryUpdateError(
                    ["an unchecked write takes no pack: pass pack= and pack_hash= for a checked "
                     "write, or unchecked=True alone for a platform scope"]
                )  # fmt: skip
            outside = sorted({u["scope"] for u in updates} - platform)
            if outside:
                raise MemoryAccessError(
                    f"{owner}: an unchecked write may write only the profile's platform_scopes "
                    f"{sorted(platform)}; {outside} must be written checked, with their pack"
                )
            if mem:
                raise MemoryUpdateError([*mem, "nothing was applied"])
            if pack_id is not None and not (
                isinstance(pack_id, str) and _PACK_ID.fullmatch(pack_id)
            ):
                raise MemoryUpdateError(["pack_id must be sha256:<64 hex>, a pack's hash"])
            return _Check(False, pack_id, UNLABELLED, {}, None)
        if unchecked is not False:
            raise TypeError("unchecked must be True or False")
        if pack is None or pack_hash is None:
            raise MemoryUpdateError(
                ["a checked write needs the pack its updates came from: pass pack= and "
                 "pack_hash= (or, for a platform scope only, unchecked=True); nothing was "
                 "applied"]
            )  # fmt: skip
        if not isinstance(pack, Mapping) or digest_of(dict(pack)) != pack_hash:
            raise MemoryUpdateError(["pack_hash is not the hash of the pack passed"])
        if pack_id is not None and pack_id != pack_hash:
            raise MemoryUpdateError(["pack_id does not equal the hash of the pack passed"])
        if pack_profile(pack) != (owner, profile["digest"]):
            # the runner passes the session's own pack, never one looked up by the report's
            # pack_id; a pack assembled for another profile (or for none) is not that
            raise MemoryUpdateError(
                ["the pack was not assembled for this profile (assemble_pack(..., profile=) or "
                 "start_session binds a pack to the verified profile it serves)"]
            )  # fmt: skip
        if pack.get("status") == "deferred" and updates:
            raise MemoryUpdateError(["the pack was deferred: no work was done on it, so it may "
                                     "not update memory"])  # fmt: skip
        reserved = [
            f"memory_updates/{n}: scope {u['scope']!r} is a platform scope; only an unchecked "
            "platform write writes it"
            for n, u in enumerate(updates)
            if u["scope"] in platform
        ]
        if reserved:
            raise MemoryUpdateError(reserved)
        labels = rendered_identifiers(pack)
        if len(labels) > MAX_RENDERED:
            raise MemoryUpdateError(
                [f"the pack rendered {len(labels)} identifiers, over the cap of {MAX_RENDERED}"]
            )
        problems = source_problems(updates, pack)
        if problems:
            raise MemoryUpdateError([*problems, "nothing was applied"])
        return _Check(True, pack_hash, pack_label(pack), labels, tuple(sorted(labels)))

    def apply_report(
        self,
        profile: VerifiedProfile,
        report: Mapping[str, Any],
        *,
        pack: Mapping[str, Any] | None = None,
        pack_hash: str | None = None,
        manifest: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Apply a report's ``memory_updates`` after validating the report against its pack.

        A report is applied only with the ``pack`` it ran on and that pack's ``pack_hash``;
        without them it is refused.  The whole report is screened for secrets first, then
        checked against its schema (by path and keyword only) and against the pack
        (:func:`validate_report`: its ``pack_id``, its cites and every memory update's sources).
        The report must be the profile's own, a ``deferred`` report (no work done) may not change
        memory, and no update may name a platform scope.
        """
        owner, _ = _identity(profile)
        if not isinstance(report, Mapping):
            raise MemoryUpdateError(["$: a report is a mapping"])
        problems = limit_problems(report)
        if problems:
            raise MemoryUpdateError(problems)
        _refuse_secrets(report, "")
        if pack is None or pack_hash is None:
            raise MemoryUpdateError(
                ["a report is applied only with its pack: pass the pack it ran on as pack= and "
                 "its hash as pack_hash=; nothing was applied"]
            )  # fmt: skip
        problems = schema_error_shapes("agent", "report_result", report)
        if not problems:
            problems = validate_report(report, pack, pack_hash, manifest)
        if problems:
            raise MemoryUpdateError(problems)
        if report["profile"] != owner:
            raise MemoryAccessError(
                f"report belongs to {report['profile']}, not {owner}; a report may only update "
                "its own agent's memory"
            )
        if report["status"] == "deferred" and report["memory_updates"]:
            raise MemoryUpdateError(["a deferred report did no work and may not update memory"])
        platform = _platform_scopes(profile)
        reserved = [
            f"memory_updates/{n}: scope {u['scope']!r} is a platform scope; only the platform "
            "writes it"
            for n, u in enumerate(report["memory_updates"])
            if u["scope"] in platform
        ]
        if reserved:
            raise MemoryUpdateError(reserved)
        return self.apply_updates(profile, report["memory_updates"], pack=pack, pack_hash=pack_hash)

    def read(
        self,
        profile: VerifiedProfile,
        scope: str,
        *,
        owner: str | None = None,
        include_retired: bool = False,
    ) -> dict[str, Any]:
        """``{"entries": {key: value}, "withheld": n}``: the live entries of one scope of the
        caller's own memory that its ceiling (:func:`read_ceiling`) allows, and how many it does
        not.  A withheld entry is never returned, and neither is its key.  The shape matches
        :meth:`history` and :meth:`as_of` (a plain dict, so no operation drops ``withheld``).

        ``owner`` other than the caller's own profile id is a cross-agent read and is refused.
        """
        me = self._reader(profile, scope, owner)
        ceiling = read_ceiling(profile)
        entries = self._load(me)["entries"].get(scope, {})
        shown, withheld = {}, 0
        for k, e in sorted(entries.items()):
            if e.get("status") != "live" and not include_retired:
                continue
            if tlp.allows(ceiling, e.get("tlp")):
                shown[k] = e["value"]
            else:
                withheld += 1
        return {"entries": shown, "withheld": withheld}

    def history(
        self, profile: VerifiedProfile, scope: str, key: str, *, owner: str | None = None
    ) -> dict[str, Any]:
        """``{"records": [...], "withheld": n}``: the change records of ``scope/key`` in order
        that the reader's ceiling allows, and how many it does not (folded records have no
        ``value``; a key compacted whole is one tombstone record, and a key whose tombstone aged
        out has none).

        A key with no record the reader may see answers ``records: []`` and the **scope's**
        withheld count, whether the key exists or not, so ``history`` is no existence oracle for
        a withheld key (ADR-0037 decision 8)."""
        me = self._reader(profile, scope, owner)
        log_ = [r for r in self._load(me)["log"] if r["scope"] == scope and r["op"] != "aged"]
        shown, withheld = _readable(profile, [r for r in log_ if r["key"] == key])
        if not shown:
            return {"records": [], "withheld": _readable(profile, log_)[1]}
        return {"records": shown, "withheld": withheld}

    def as_of(
        self, profile: VerifiedProfile, scope: str, t: datetime, *, owner: str | None = None
    ) -> dict[str, Any]:
        """What ``profile`` believed in ``scope`` at ``t`` (an aware datetime), rebuilt from the
        log: ``{"at", "entries": {key: value}, "compacted": [keys], "aged_out": bool,
        "withheld": n}``.

        A key whose state at ``t`` lies in folded records (a range, a tombstone, or history
        from before the migration) is listed in ``compacted``, never given a value.
        ``aged_out`` is true when ``t`` falls in the time range of keys whose tombstones aged
        out: their names are gone, so any key not listed must then be read as compacted.

        The reader's ceiling applies to the state at ``t``: a key whose label then (or, for a
        compacted key, its folded record's label) is above it is counted in ``withheld`` and
        named nowhere.  The state is folded from every record first, so a withheld later record
        never makes an earlier value look current."""
        me = self._reader(profile, scope, owner)
        ceiling = read_ceiling(profile)
        when = _stamp(t)
        mine = [r for r in self._load(me)["log"] if r["scope"] == scope]
        state: dict[str, dict[str, Any]] = {}
        held: dict[str, bool] = {}  # key -> the value in effect at t is not in the log
        unknown: dict[str, str] = {}  # key -> the label of the folded record that hides it
        aged_out = False
        for rec in mine:
            if rec["op"] == "aged":  # said only when the reader may see the aged record
                since = rec.get("since")
                aged_out = (
                    (since is None or since <= when)
                    and when <= rec["at"]
                    and tlp.allows(ceiling, rec.get("tlp"))
                )
                continue
            k = rec["key"]
            if rec["at"] > when:
                start = _start(rec)
                folded = rec.get("migrated") or rec.get("compacted")
                if folded and (start is None or start <= when) and k not in state:
                    unknown.setdefault(k, rec.get("tlp", UNLABELLED))
                continue
            state[k] = _step(state.get(k), rec)
            if rec.get("compacted") or rec["op"] in ("add", "replace") or rec.get("migrated"):
                held[k] = bool(rec.get("compacted")) or "value" not in rec
        live = {k for k, e in state.items() if e["status"] == "live"}
        label = {k: state[k]["tlp"] for k in live} | {
            k: v for k, v in unknown.items() if k not in live
        }
        hidden = {k for k, v in label.items() if not tlp.allows(ceiling, v)}
        compacted = sorted((set(unknown) | {k for k in live if held.get(k)}) - hidden)
        return {
            "at": when,
            "entries": {k: state[k]["value"] for k in sorted(live - hidden) if k not in compacted},
            "compacted": compacted,
            "aged_out": aged_out,
            "withheld": len(hidden),
        }

    # ------------------------------------------------------------ internals
    def _reader(self, profile: VerifiedProfile, scope: str, owner: str | None) -> str:
        me, scopes = _identity(profile)
        if owner is not None and owner != me:
            raise MemoryAccessError(
                f"{me} may not read the memory of {_name(owner)} (cross-agent read)"
            )
        if scope not in scopes:
            raise MemoryAccessError(f"{me}: scope {_name(scope)} is not in its memory_scopes")
        return me

    def _load(self, owner: str) -> Stored:
        raw = self._backend.load(owner)
        if raw and not _is_logged(raw):
            # not yet migrated (that happens on the owner's next write): read it as migrated now
            stored, purged = _stored(raw, _stamp(self._now()))
            self._purged(owner, purged)
            return stored
        return _stored(raw, "")[0]

    def _purged(self, owner: str, positions: list[str]) -> None:
        """Say, once per process and owner, that migration kept legacy secrets as digests."""
        if positions and f"purged:{owner}" not in self._logged:
            self._logged.add(f"purged:{owner}")
            log.warning(
                "memory of %s: migration kept only the purged marker (no value, no digest) of secrets at %s",
                owner,
                ", ".join(positions),
            )

    def _page(
        self, owner: str, scope: str, problem: str | None, platform: bool, unit: str = "records"
    ) -> None:
        """Report ``owner/scope`` at its cap (``problem``) or not (None), state-diffed.  The key
        is a digest of the pair, so no two pairs share one."""
        pair = hashlib.sha256(f"{owner}\0{scope}".encode()).hexdigest()[:16]
        advice = _cap_advice(platform, unit)
        what = "pack exposures" if scope == "*" else f"memory scope {scope}"
        self._report(
            f"agent-memory-cap-{pair}",
            owner,
            "at-cap",
            CAP_TITLE if problem is not None else CAP_CLEARED,
            None
            if problem is None
            else f"{owner}'s {what} refuses writes: {problem}. {advice[0].upper()}{advice[1:]}.",
            f"{owner}'s {what} accepts writes again",
        )

    def _clock_page(self, owner: str, behind: timedelta | None) -> None:
        """Report that the clock is behind ``owner``'s log (``behind``) or not (None)."""
        key = "agent-memory-clock-" + hashlib.sha256(owner.encode()).hexdigest()[:16]
        self._report(
            key,
            owner,
            "clock-behind",
            CLOCK_TITLE if behind is not None else CLOCK_CLEARED,
            None
            if behind is None
            else f"{owner}'s memory refuses writes: the clock is behind its log by {behind}. "
            "Fix the host clock; if it is already right, the log holds a record stamped in the "
            "future and needs an operator re-stamp (ADR-0037 PR 3). Nothing is written until the "
            f"clock is within {CLOCK_SKEW} of the log.",
            f"{owner}'s memory clock is within {CLOCK_SKEW} of its log again",
        )

    def _report(
        self, key: str, owner: str, state: str, title: str, problem: str | None, cleared: str
    ) -> None:
        """One state-diffed page: ``problem`` (its body) or None for the recovery.  Without a
        notifier, a problem is logged once per process until it clears."""
        if self._notifier is None:
            if problem is None:
                self._logged.discard(key)
            elif key not in self._logged:
                self._logged.add(key)
                log.warning("%s", problem)
            return
        from homelabnext.notify import Message

        try:
            if problem is None:
                self._notifier.report(key, "ok", Message(key, title, cleared), scope=owner)
            else:
                msg = Message(key, title, problem, level="warn", topic=self._topic,
                              tags=("agent", "memory"))  # fmt: skip
                self._notifier.report(key, state, msg, scope=owner)
        except Exception:  # the write's outcome stands; a failed page is retried next time
            log.exception("memory page %s for %s not sent", key, owner)
