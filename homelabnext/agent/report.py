# SPDX-License-Identifier: Apache-2.0
"""``report_result`` validation: the cross-checks JSON Schema cannot express.

Sources (ADR-0037 decision 7).  A memory update's ``sources`` must each equal an identifier the
pack assembler recorded for something the pack **rendered** (:func:`~homelabnext.agent.pack.
rendered_identifiers`): a knowledge item's ``digest``, ``file_digest`` or record uid, or an input
item's ``digest`` or ``uid``.  Text is never a source: a digest written in a cite's ``ref``, a
section body or the summary counts for nothing, and neither does an item the budget dropped.  A
``mem:`` source names a revision of the pack's ``memory`` block, which no pack carries until
ADR-0037 PR 3, so every ``mem:`` source is refused, with one message whoever's memory it names
(decision 11: the check is no existence oracle).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .pack import PREGATE_PREFIX, rendered_identifiers
from .schemas import schema_errors

#: list limits kept in code, not in the schema (tightening a list is not additive; ADR-0037
#: decision 7)
MAX_MEMORY_UPDATES = 64
MAX_CITES = 128
MEM_PREFIX = "mem:"
#: the one refusal of a ``mem:`` source, whoever's memory it names and whether or not it exists
MEM_REFUSAL = (
    "a mem: source must name a revision in the pack's memory block, and this pack shows none "
    "(memory blocks arrive with ADR-0037 PR 3)"
)


def limit_problems(report: Mapping[str, Any]) -> list[str]:
    """The list limits of a report: at most :data:`MAX_MEMORY_UPDATES` memory updates and
    :data:`MAX_CITES` cites."""
    problems = []
    for name, cap in (("memory_updates", MAX_MEMORY_UPDATES), ("cites", MAX_CITES)):
        value = report.get(name)
        if isinstance(value, list) and len(value) > cap:
            problems.append(f"{name}: {len(value)} items; at most {cap}")
    return problems


def source_problems(updates: Any, pack: Mapping[str, Any]) -> list[str]:
    """Every source of ``updates`` that is not an identifier ``pack`` rendered, by position only
    (a source is never echoed).  ``updates`` is assumed schema-valid."""
    known = rendered_identifiers(pack)
    problems = []
    for n, u in enumerate(updates if isinstance(updates, list) else []):
        for i, src in enumerate((u.get("sources") or ()) if isinstance(u, Mapping) else ()):
            where = f"memory_updates/{n}/sources/{i}"
            if isinstance(src, str) and src.startswith(MEM_PREFIX):
                problems.append(f"{where}: {MEM_REFUSAL}")
            elif src not in known:
                problems.append(
                    f"{where}: not an identifier this pack rendered (a source is the digest or "
                    "uid the assembler recorded for a rendered knowledge or input item, never "
                    "text)"
                )
    return problems


def validate_report(
    report: Mapping[str, Any],
    pack: Mapping[str, Any],
    pack_hash: str,
    manifest: Mapping[str, Any] | None = None,
) -> list[str]:
    """Problems with ``report`` against the pack it claims to have run on (empty = valid).

    * schema (``schemas/agent/report_result``);
    * at most :data:`MAX_MEMORY_UPDATES` memory updates and :data:`MAX_CITES` cites;
    * ``pack_id`` equals the pack hash, so a report cannot be attached to the wrong context;
    * a deferred pack can only produce a ``deferred`` report (no work on guessed context);
    * every cite names a source present in the pack;
    * every memory update's source is an identifier the pack rendered (:func:`source_problems`);
    * for an ``ok`` report, every ``must_cite`` source of the manifest is cited.
    """
    problems = limit_problems(report)
    if problems:
        return problems
    problems = schema_errors("agent", "report_result", report)
    if problems:
        return problems
    if report["pack_id"] != pack_hash:
        problems.append("pack_id does not equal the hash of the pack the agent was given")
    if pack.get("status") == "deferred" and report["status"] != "deferred":
        problems.append("pack was deferred; the report must have status 'deferred'")
    known = {s["name"] for s in pack.get("sections", [])}
    known |= {n[len(PREGATE_PREFIX) :] for n in known if n.startswith(PREGATE_PREFIX)}
    cited = {c["source"] for c in report["cites"]}
    unknown = sorted(cited - known)
    if unknown:
        problems.append(f"cites sources that are not in the pack: {unknown}")
    problems += source_problems(report["memory_updates"], pack)
    if manifest and report["status"] == "ok":
        missing = sorted(set(manifest.get("must_cite", [])) - cited)
        if missing:
            problems.append(f"must_cite sources not cited: {missing}")
    return problems
