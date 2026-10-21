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
    codes: dict[str, str] = field(default_factory=dict)
    paths: tuple[pathlib.Path, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.codes)

    def code_of(self, uid: str) -> str | None:
        return next((c for c, u in self.codes.items() if u == uid), None)

    def merged(self, other: AliasMap) -> AliasMap:
        return AliasMap({**self.codes, **other.codes}, (*self.paths, *other.paths))


def _read(path: pathlib.Path) -> dict[str, str]:
    import yaml

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw = data.get("aliases") if isinstance(data, dict) else None
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: needs an `aliases:` mapping of legacy code -> uid")
    bad = [
        f"{k}: {v}"
        for k, v in raw.items()
        if not (LEGACY_CODE_RE.fullmatch(str(k)) and is_uid(v) and not str(k).endswith("-NEW"))
    ]
    if bad:
        raise ValueError(f"{path}: not a legacy code -> uid entry: {', '.join(bad[:5])}")
    return {str(k): str(v) for k, v in raw.items()}


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
            out = out.merged(AliasMap(_read(p), (p,)))
    return out


def resolve(ref: str, aliases: AliasMap | Mapping[str, str] | None, where: str = "") -> str:
    """``ref`` as a uid: a uid is returned unchanged; a legacy code the map holds resolves to
    its uid with a :class:`LegacyRecordCode` warning; anything else is returned unchanged."""
    ref = str(ref)
    if is_uid(ref):
        return ref
    codes = aliases.codes if isinstance(aliases, AliasMap) else (aliases or {})
    uid = codes.get(ref)
    if uid is None:
        return ref
    at = f"{where}: " if where else ""
    warnings.warn(
        f"{at}{ref} is a legacy record code; refer to the record by its uid {uid}",
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


def render_aliases(codes: Mapping[str, str], comments: Mapping[str, str] | None = None) -> str:
    """The ``aliases.yml`` text: codes in order, each optionally commented with its title."""

    def key(code: str) -> tuple[str, int]:
        prefix, _, num = code.rpartition("-")
        return prefix, int(num) if num.isdigit() else 0

    lines = [HEADER.rstrip("\n"), "aliases_version: 1", "aliases:"]
    for code in sorted(codes, key=key):
        note = (comments or {}).get(code)
        lines.append(f"  {code}: {codes[code]}" + (f"  # {note}" if note else ""))
    return "\n".join(lines) + "\n"
