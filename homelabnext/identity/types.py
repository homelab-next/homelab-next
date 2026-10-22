# SPDX-License-Identifier: Apache-2.0
"""Record types: which directory holds each, how its display number is prefixed, and the
legacy code prefixes the uid migration reads.

A record's stored ``type`` is one of :data:`TYPE_DIR`.  The directory is ``<type-dir>/`` under
its tree (``objectives/``, ``lessons/``); the one strategy record is ``strategy.md`` at the
tree's root.  The display prefix is the type itself (``PIR 2.1``), except that a lesson shows
as ``LL`` and a runbook as ``RB`` (the spellings readers know).
"""

from __future__ import annotations

import re

__all__ = [
    "LEGACY_CODE_RE",
    "LEGACY_PREFIX",
    "REGISTER_TYPES",
    "STRATEGY_TYPES",
    "TYPE_DIR",
    "TYPE_ORDER",
    "label_prefix",
    "legacy_type",
]

#: strategy record type -> its directory (homelabnext.strategy)
STRATEGY_TYPES: dict[str, str] = {
    "SO": "objectives",
    "OO": "objectives",
    "TO": "objectives",
    "TT": "objectives",
    "MOP": "measures",
    "MOE": "measures",
    "CCIR": "requirements",
    "FFIR": "requirements",
    "PIR": "requirements",
    "RFI": "rfis",
}
#: register record type -> its directory (homelabnext.registers)
REGISTER_TYPES: dict[str, str] = {"lesson": "lessons", "runbook": "runbooks"}
#: the doctrine's order of the strategy types: the objective cascade from the top (so a parent's
#: type precedes its children's), then measures, requirements and RFIs.  Lists sort by it.
TYPE_ORDER: tuple[str, ...] = ("SO", "OO", "TO", "TT", "MOE", "MOP", "CCIR", "FFIR", "PIR", "RFI")
TYPE_DIR: dict[str, str] = {"strategy": ".", **STRATEGY_TYPES, **REGISTER_TYPES}
_PREFIX = {"lesson": "LL", "runbook": "RB", "strategy": "Strategy"}

#: the numbered code prefixes records carried before uids (``LL-001``) -> the record type
LEGACY_PREFIX: dict[str, str] = {
    "LL": "lesson",
    "RB": "runbook",
    **{t: t for t in STRATEGY_TYPES},
}
#: a legacy record code: an allocated number, or the ``XX-NEW`` placeholder of an unmerged one
LEGACY_CODE_RE = re.compile(
    r"(?:" + "|".join(sorted(LEGACY_PREFIX, key=len, reverse=True)) + r")-(?:\d{3,}|NEW)"
)


def label_prefix(rtype: str) -> str:
    """``PIR`` -> ``PIR``, ``lesson`` -> ``LL``: what a display number is prefixed with."""
    return _PREFIX.get(rtype, rtype)


def legacy_type(code: str) -> str | None:
    """The record type a legacy code names (``MOE-004`` -> ``MOE``), or None."""
    if not LEGACY_CODE_RE.fullmatch(str(code)):
        return None
    return LEGACY_PREFIX[str(code).rsplit("-", 1)[0]]
