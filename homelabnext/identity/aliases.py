# SPDX-License-Identifier: Apache-2.0
"""The legacy alias map: the numbered code a record carried before uids -> its uid.

``hnx records assign-uids`` writes ``aliases.yml`` at the root of each tree it migrates
(``examples/strategy/aliases.yml``, ``examples/registers/aliases.yml``)::

    aliases_version: 1
    aliases:
      LL-001: 0199...   # the lesson once numbered LL-001

It is history, never an identity: no record in the tree may name a code (the validation
refuses one), and no new code is ever added except by the migration.  What it is for is the
references *outside* the tree that nobody can rewrite -- an intent an agent filed last month
(``record: LL-001``), a node id typed into ``hnx graph related``, an MCP ``context_for`` call, a
link in an operator's notes.  Those resolve on READ through :func:`resolve`, which returns the
uid and warns with :class:`LegacyRecordCode`; a code the map does not hold is returned as is,
for the caller to report as unresolved.

A numbered code that was itself retired before uids (a tombstone: a record file holding only
``id:`` and ``retired: {reason, replaced_by}``) never becomes a record: a uid is never reused,
so there is nothing left to guard.  The migration moves it here, under ``retired:``, with its
successor's uid (when it named one)::

    retired:
      LL-006:
        reason: a duplicate of LL-001, filed twice in one week
        replaced_by: 0199...   # the successor's uid (optional)

A retired code resolves to its successor (with the same warning) and is otherwise unresolved;
``hnx ids check-lost`` counts it as accounted for.
"""

from __future__ import annotations

import pathlib
import warnings
from collections.abc import Mapping
from dataclasses import dataclass, field

from .types import LEGACY_CODE_RE
from .uid import is_uid

__all__ = [
    "ALIASES_FILE",
    "AliasMap",
    "LegacyRecordCode",
    "find_aliases",
    "load_aliases",
    "read_aliases",
    "render_aliases",
    "resolve",
    "resolve_node_id",
]

ALIASES_FILE = "aliases.yml"
HEADER = (
    "# SPDX-License-Identifier: Apache-2.0\n"
    "# Legacy record codes -> uids, written by `hnx records assign-uids` (docs/adr/0019).\n"
    "# History only: records refer to each other by uid; a legacy code met in an intent, a\n"
    "# query or an old note resolves through this map on read, with a deprecation warning.\n"
)


class LegacyRecordCode(FutureWarning):
    """A reference used a legacy record code (``LL-001``) where a uid belongs."""


@dataclass
class AliasMap:
    """``codes``: legacy code -> uid; ``retired``: a code tombstoned before uids -> its
    ``{reason, replaced_by}`` (``replaced_by`` the successor's uid, or absent)."""

    codes: dict[str, str] = field(default_factory=dict)
    paths: tuple[pathlib.Path, ...] = ()
    retired: dict[str, dict[str, str]] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.codes or self.retired)

    def code_of(self, uid: str) -> str | None:
        return next((c for c, u in self.codes.items() if u == uid), None)

    def merged(self, other: AliasMap) -> AliasMap:
        return AliasMap(
            {**self.codes, **other.codes},
            (*self.paths, *other.paths),
            {**self.retired, **other.retired},
        )

    def successor(self, code: str) -> str | None:
        """The uid ``code`` resolves to: its own, or a retired code's successor (else None)."""
        return self.codes.get(code) or (self.retired.get(code) or {}).get("replaced_by")


def _numbered(code) -> bool:
    return bool(LEGACY_CODE_RE.fullmatch(str(code))) and not str(code).endswith("-NEW")


def read_aliases(path: pathlib.Path) -> AliasMap:
    """One ``aliases.yml``, validated (``ValueError`` on anything malformed)."""
    import yaml

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw = data.get("aliases") if isinstance(data, dict) else None
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: needs an `aliases:` mapping of legacy code -> uid")
    bad = [f"{k}: {v}" for k, v in raw.items() if not (_numbered(k) and is_uid(v))]
    if bad:
        raise ValueError(f"{path}: not a legacy code -> uid entry: {', '.join(bad[:5])}")
    codes = {str(k): str(v) for k, v in raw.items()}
    ret = data.get("retired") or {}
    if not isinstance(ret, dict):
        raise ValueError(f"{path}: `retired:` must map a legacy code -> {{reason, replaced_by}}")
    retired: dict[str, dict[str, str]] = {}
    for k, v in ret.items():
        ok = (
            _numbered(k)
            and str(k) not in codes
            and isinstance(v, dict)
            and set(v) <= {"reason", "replaced_by"}
            and isinstance(v.get("reason"), str)
            and v["reason"].strip()
            and ("replaced_by" not in v or is_uid(v["replaced_by"]))
        )
        if not ok:
            raise ValueError(
                f"{path}: retired {k}: needs a `reason` (and the successor's uid as "
                "`replaced_by`), and may not also be an alias"
            )
        retired[str(k)] = {kk: str(vv) for kk, vv in v.items()}
    return AliasMap(codes, (path,), retired)


def _read(path: pathlib.Path) -> dict[str, str]:
    return read_aliases(path).codes


def find_aliases(root) -> list[pathlib.Path]:
    """``aliases.yml`` in ``root`` or its parent (a register directory sits one level below)."""
    r = pathlib.Path(root)
    return [p for p in (r / ALIASES_FILE, r.parent / ALIASES_FILE) if p.is_file()]


def load_aliases(*roots) -> AliasMap:
    """Every alias map found for ``roots`` (see :func:`find_aliases`), merged."""
    out = AliasMap()
    seen: set[pathlib.Path] = set()
    for root in roots:
        for p in find_aliases(root):
            if p.resolve() in seen:
                continue
            seen.add(p.resolve())
            out = out.merged(read_aliases(p))
    return out


def resolve(ref: str, aliases: AliasMap | Mapping[str, str] | None, where: str = "") -> str:
    """``ref`` as a uid: a uid is returned unchanged; a legacy code the map holds resolves to
    its uid (a retired code to its successor's) with a :class:`LegacyRecordCode` warning;
    anything else is returned unchanged."""
    ref = str(ref)
    if is_uid(ref):
        return ref
    amap = aliases if isinstance(aliases, AliasMap) else AliasMap(dict(aliases or {}))
    uid = amap.successor(ref)
    if uid is None:
        return ref
    at = f"{where}: " if where else ""
    what = "a legacy" if ref in amap.codes else "a retired legacy"
    warnings.warn(
        f"{at}{ref} is {what} record code; refer to the record by its uid {uid}",
        LegacyRecordCode,
        stacklevel=2,
    )
    return uid


def resolve_node_id(nid: str, aliases: AliasMap | Mapping[str, str] | None, where="") -> str:
    """``lesson:LL-001`` -> ``lesson:<uid>`` (a graph or context node id), else unchanged."""
    kind, sep, body = str(nid).partition(":")
    if not sep or not LEGACY_CODE_RE.fullmatch(body):
        return str(nid)
    return f"{kind}:{resolve(body, aliases, where)}"


def render_aliases(
    codes: Mapping[str, str],
    comments: Mapping[str, str] | None = None,
    retired: Mapping[str, Mapping[str, str]] | None = None,
) -> str:
    """The ``aliases.yml`` text: codes in order, each optionally commented with its title, then
    the codes retired before uids (if any)."""
    import json

    def key(code: str) -> tuple[str, int]:
        prefix, _, num = code.rpartition("-")
        return prefix, int(num) if num.isdigit() else 0

    lines = [HEADER.rstrip("\n"), "aliases_version: 1", "aliases:"]
    for code in sorted(codes, key=key):
        note = (comments or {}).get(code)
        lines.append(f"  {code}: {codes[code]}" + (f"  # {note}" if note else ""))
    if retired:
        lines.append("retired:")
        for code in sorted(retired, key=key):
            lines.append(f"  {code}:")
            lines.append(f"    reason: {json.dumps(' '.join(retired[code]['reason'].split()))}")
            if retired[code].get("replaced_by"):
                lines.append(f"    replaced_by: {retired[code]['replaced_by']}")
    return "\n".join(lines) + "\n"
