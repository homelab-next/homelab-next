# SPDX-License-Identifier: Apache-2.0
"""A customization's ``links``: the lesson and runbook it cites, by uid (ADR-0019).

``links: {lesson: <uid>, runbook: <uid>}`` names register records by uid.  A legacy numbered
code (``LL-003``, ``RB-001``) is still accepted for files written before uids: it resolves
through the registers' ``aliases.yml`` to the record's uid, and each one costs a
:class:`~homelabnext.identity.aliases.LegacyRecordCode` warning naming the uid to write
instead.  A code the alias map does not hold, or one it lists under ``retired:``, is an
error: unlike a stray citation in an old note, a customization is a maintained file whose link
says which record it relies on, and silently swapping in a retired code's successor would
change that claim without anyone reading it.

This is the one resolver every consumer uses -- the knowledge graph's ``custom -links->``
edges (and so ``hnx graph related`` and the MCP ``related`` / ``context_for`` tools that read
the graph), ``hnx custom check`` (CU016 / CU017) and the customizations register (which shows
each link by its computed display number, ``LL 3``).  ``hnx records assign-uids`` rewrites the
codes in place (:func:`rewrite_links`), so a migrated tree carries uids only.
"""

from __future__ import annotations

import re
import warnings
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from homelabnext.identity.aliases import AliasMap, LegacyRecordCode
from homelabnext.identity.uid import is_uid

__all__ = ["LINK_KEYS", "Link", "resolve_links", "rewrite_links", "warn_legacy"]

#: link key -> (record kind, the legacy code prefix it accepts)
LINK_KEYS: dict[str, str] = {"lesson": "LL", "runbook": "RB"}


@dataclass(frozen=True)
class Link:
    """One link as written (``ref``) and what it resolves to: ``uid`` (None: unresolved, and
    ``problem`` says why), ``legacy`` when a numbered code stood in for the uid."""

    key: str
    ref: str
    uid: str | None
    legacy: bool = False
    problem: str = ""


def _refs(doc: Mapping[str, Any]) -> list[tuple[str, str]]:
    links = doc.get("links") if isinstance(doc, Mapping) else None
    if not isinstance(links, Mapping):
        return []
    out = []
    for key in LINK_KEYS:
        vals = links.get(key)
        for v in [vals] if isinstance(vals, str) else vals or ():
            out.append((key, str(v)))
    return out


def _resolve(key: str, ref: str, aliases: AliasMap | None, records) -> Link:
    if is_uid(ref):
        uid, legacy = ref, False
    else:
        prefix = LINK_KEYS[key]
        if not ref.startswith(f"{prefix}-"):
            return Link(key, ref, None, problem=f"{ref} is not a {key} uid or {prefix}- code")
        amap = aliases or AliasMap()
        if ref in amap.retired:
            succ = amap.retired[ref].get("replaced_by")
            hint = f"; link its successor by uid ({succ})" if succ else ""
            return Link(
                key,
                ref,
                None,
                problem=f"{ref} is a retired legacy code in aliases.yml "
                f"({amap.retired[ref].get('reason', '')}){hint}",
            )
        uid = amap.codes.get(ref)
        if uid is None:
            return Link(
                key, ref, None, problem=f"{ref} is not in aliases.yml; link the {key} by its uid"
            )
        legacy = True
    if records is not None:
        got = records.get(uid)
        if got is None:
            return Link(key, ref, None, legacy, f"{uid}: no {key} in the registers has this uid")
        if got[0] != key:
            return Link(key, ref, None, legacy, f"{uid} is a {got[0]}, not a {key}")
    return Link(key, ref, uid, legacy)


def resolve_links(
    doc: Mapping[str, Any],
    aliases: AliasMap | None,
    records: Mapping[str, tuple[str, str]] | None = None,
) -> list[Link]:
    """Every link of a customization document, resolved.  ``records`` (uid -> (kind, display
    label)), when given, also checks that the uid names a record of the right kind."""
    return [_resolve(k, r, aliases, records) for k, r in _refs(doc)]


def warn_legacy(link: Link, where: str = "") -> None:
    """The one deprecation warning for a link written as a legacy code."""
    if link.legacy and link.uid:
        at = f"{where}: " if where else ""
        warnings.warn(
            f"{at}{link.ref} is a legacy record code; refer to the {link.key} by its uid "
            f"{link.uid}",
            LegacyRecordCode,
            stacklevel=2,
        )


_LINK_VALUE = re.compile(
    r"""(?P<lead>(?<![\w-])["']?(?P<key>lesson|runbook)["']?[ \t]*:[ \t]*(?P<q>["']?))"""
    r"""(?P<code>(?:LL|RB)-\d{3,})(?![\w-])"""
)


def rewrite_links(text: str, codes: Mapping[str, str]) -> str:
    """``text`` (a customization file, YAML or JSON) with each ``lesson:``/``runbook:`` value
    that is a code in ``codes`` replaced by its uid; nothing else changes (a code in the
    ``reason`` is prose and stays).  Idempotent: a uid is not a code."""

    def one(m: re.Match) -> str:
        uid = codes.get(m["code"])
        if uid is None or not m["code"].startswith(LINK_KEYS[m["key"]] + "-"):
            return m[0]
        return m["lead"] + uid

    return _LINK_VALUE.sub(one, text)
