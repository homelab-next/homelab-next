# SPDX-License-Identifier: Apache-2.0
"""``report_result`` validation: the cross-checks JSON Schema cannot express.

Sources (ADR-0037 decision 7).  A memory update's ``sources`` must each equal an identifier the
pack assembler recorded for something the pack **rendered** (:func:`~homelabnext.agent.pack.
rendered_identifiers`): a knowledge item's ``digest``, ``file_digest`` or record uid, or an input
item's ``digest`` or ``uid``.  Text is never a source: a digest written in a cite's ``ref``, a
section body or the summary counts for nothing, and neither does an item the budget dropped.  A
``mem:`` source must name a revision of the pack's ``memory`` block (decision 11): the block
platform code rendered into the pack from the profile's own store.  A ``mem:`` source naming
another owner is refused first, before anything is looked up, with the same message as one the
block does not show, so the check is no existence oracle.  No update may cite any revision of its
own key.

Verify (decision 15).  An update with ``op: verify`` reasserts a live fact: it takes no ``value``
and must cite at least one source that is not a ``mem:`` revision (:func:`verify_problems`), and
that source, like every other, must be one the pack rendered.  A model's ``verify`` sets the
entry's ``reasserted_at``, never its ``verified_at`` (only a ``Verifier`` does).

Served reports (decision 18).  A report served to a profile other than its author carries its
``memory_updates`` as ``{"count": n}`` only (:func:`served_report`): otherwise the report would be
a cross-agent read of memory.  Every place that hands a report to another profile calls it: the
ADR-0035 renderer and the context store's level reads by digest once they serve reports.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

from .compiler import VerifiedProfile, require_verified
from .deny import parse_mem_ref
from .pack import PREGATE_PREFIX, pack_memory, pack_profile, rendered_identifiers
from .schemas import schema_errors

#: list limits kept in code, not in the schema (tightening a list is not additive; ADR-0037
#: decision 7)
MAX_MEMORY_UPDATES = 64
MAX_CITES = 128
MEM_PREFIX = "mem:"
#: the one refusal of a ``mem:`` source the pack's memory block does not show: whoever's memory
#: it names and whether or not the revision exists (ADR-0037 decision 11)
MEM_REFUSAL = (
    "a mem: source must name a revision of this profile's own memory that the pack's memory "
    "block shows"
)
#: the refusal of an update citing a revision of the key it writes
MEM_OWN_KEY = "an update may not cite any revision of its own key"


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
    bound = pack_profile(pack)
    shown = {(e.get("scope"), e.get("key"), e.get("rev")) for e in pack_memory(pack)}
    problems = []
    for n, u in enumerate(updates if isinstance(updates, list) else []):
        for i, src in enumerate((u.get("sources") or ()) if isinstance(u, Mapping) else ()):
            where = f"memory_updates/{n}/sources/{i}"
            if isinstance(src, str) and src.startswith(MEM_PREFIX):
                problems += [f"{where}: {p}" for p in mem_problems(src, u, bound, shown)]
            elif src not in known:
                problems.append(
                    f"{where}: not an identifier this pack rendered (a source is the digest or "
                    "uid the assembler recorded for a rendered knowledge or input item, never "
                    "text)"
                )
    return problems


def verify_problems(updates: Any) -> list[str]:
    """Why each ``op: verify`` of ``updates`` is malformed, by position only (ADR-0037 decision
    15): a verify takes no ``value``, and it cites at least one source that is not a ``mem:``
    revision (whether the pack rendered it is :func:`source_problems`' check).  ``updates`` is
    assumed schema-valid."""
    problems = []
    for n, u in enumerate(updates if isinstance(updates, list) else []):
        if not isinstance(u, Mapping) or u.get("op") != "verify":
            continue
        where = f"memory_updates/{n}"
        if "value" in u:
            problems.append(f"{where}: verify takes no value (it reasserts the live value)")
        sources = [s for s in u.get("sources") or () if isinstance(s, str)]
        if not any(not s.startswith(MEM_PREFIX) for s in sources):
            problems.append(
                f"{where}: verify must cite at least one source the pack rendered that is not a "
                "mem: revision (memory cannot vouch for memory)"
            )
    return problems


def mem_problems(
    src: str,
    update: Mapping[str, Any],
    bound: tuple[str, str] | None,
    shown: set[tuple[Any, Any, Any]],
) -> list[str]:
    """Why the ``mem:`` source ``src`` of ``update`` may not be cited from a pack bound to
    ``bound`` whose memory block shows ``shown`` (``(scope, key, rev)``).  The owner is checked
    first and refused with the same message as an unshown revision, before anything is looked up
    (ADR-0037 decision 11)."""
    ref = parse_mem_ref(src)
    if ref is None or bound is None or ref[0] != bound[0]:
        return [MEM_REFUSAL]
    _, scope, key, rev = ref
    if (scope, key, rev) not in shown:
        return [MEM_REFUSAL]
    if (scope, key) == (update.get("scope"), update.get("key")):
        return [MEM_OWN_KEY]
    return []


def served_report(
    report: Mapping[str, Any], *, reader: VerifiedProfile, author: str
) -> dict[str, Any]:
    """``report`` as it may be served to ``reader`` (ADR-0037 decision 18): unchanged for its own
    author, and with ``memory_updates`` replaced by ``{"count": n}`` for any other profile, so no
    key, value or source of the author's memory reaches it.

    ``author`` is the author the caller validated (the profile the report's pack was bound to,
    :func:`validate_report`), never the report's own ``profile`` field, which the model wrote; a
    report whose ``profile`` is not ``author`` is refused (``ValueError``), since it was not
    validated as that author's.  The result is a served view, not a ``report_result`` (it does
    not validate as one).  Call it wherever a report is handed to a profile other than its
    author: the ADR-0035 renderer, and the context store's level reads by digest once they serve
    reports."""
    require_verified(reader, "served_report")
    if not isinstance(author, str) or report.get("profile") != author:
        raise ValueError("served_report serves only a report validated as author's own")
    out = copy.deepcopy(dict(report))
    if author != reader["id"]:
        updates = out.get("memory_updates")
        out["memory_updates"] = {"count": len(updates) if isinstance(updates, list) else 0}
    return out


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
    * ``profile`` is the profile the pack was assembled for, when it is bound to one;
    * every cite names a source present in the pack;
    * every memory update's source is an identifier the pack rendered (:func:`source_problems`);
    * every ``verify`` takes no value and cites a non-``mem:`` source (:func:`verify_problems`);
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
    bound = pack_profile(pack)
    if bound is not None and report["profile"] != bound[0]:
        # the author is the profile the pack was assembled for, never what the report claims
        problems.append("profile is not the profile the pack was assembled for")
    if pack.get("status") == "deferred" and report["status"] != "deferred":
        problems.append("pack was deferred; the report must have status 'deferred'")
    known = {s["name"] for s in pack.get("sections", [])}
    known |= {n[len(PREGATE_PREFIX) :] for n in known if n.startswith(PREGATE_PREFIX)}
    cited = {c["source"] for c in report["cites"]}
    unknown = sorted(cited - known)
    if unknown:
        problems.append(f"cites sources that are not in the pack: {unknown}")
    problems += verify_problems(report["memory_updates"])
    problems += source_problems(report["memory_updates"], pack)
    if manifest and report["status"] == "ok":
        missing = sorted(set(manifest.get("must_cite", [])) - cited)
        if missing:
            problems.append(f"must_cite sources not cited: {missing}")
    return problems
