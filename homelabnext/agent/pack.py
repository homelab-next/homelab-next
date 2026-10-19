# SPDX-License-Identifier: Apache-2.0
"""Context-pack assembler: ``(manifest, inputs) -> (pack, hash)``, a pure function.

Ordering is stable before volatile: sections are emitted by tier (``stable``, ``session``,
``volatile``) and, within a tier, by name, so the byte-identical prefix is as long as possible
(cache friendly) and identical inputs always give an identical pack and hash, whatever order the
caller built its dicts in.

There is no silent truncation.  A section over its own ``max_chars`` and a pack over
``budget_chars`` are both cut, and every cut is listed in ``truncations`` / ``budget`` with the
tier it came from.  Volatile content is cut first, then session; stable content is never cut --
if the stable tier alone does not fit, the pack is ``deferred``.

A required pre-gate that is missing, ``stale`` or ``failed`` also yields a ``deferred`` pack with
the reason, so the agent does not run on guessed context.

Fencing.  Stable sections are fenced ``<delim> <name> [stable] <delim>``; their text comes from
the manifest.  Session and volatile sections carry untrusted input, so they are fenced with a
per-pack nonce, ``<delim> <name> [<tier>] <nonce> <delim>`` ... ``<delim> end <name> <nonce>
<delim>``, where the nonce is derived from the digest of the fenced content (deterministic, so the
pack stays a pure function, but not knowable to whoever wrote that content).  Any line of
session or volatile text that starts with the delimiter (or the default one) is escaped with
:data:`ESCAPE_PREFIX`, so input cannot open a fake section, stable or otherwise.

``inputs`` shape::

    {"sections": {<section name>: <text>}, "pregates": {<gate id>: <pregate_output dict>}}
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .digest import canonical_json, digest_of, sha256_text
from .errors import SpecError

TIERS = ("stable", "session", "volatile")
_RANK = {t: i for i, t in enumerate(TIERS)}
DEFAULT_DELIMITER = "====="
PREGATE_PREFIX = "pregate-"
ESCAPE_PREFIX = "[escaped] "


def _escape(text: str, delims: tuple[str, ...]) -> str:
    """Prefix every line that looks like a fence so it reads as data, not structure."""
    lines = text.split("\n")
    return "\n".join(
        ESCAPE_PREFIX + ln if ln.lstrip().startswith(delims) or ln.startswith(ESCAPE_PREFIX) else ln
        for ln in lines
    )


def _marker(n: int) -> str:
    return f"\n[TRUNCATED: {n} chars omitted]"


def assemble_pack(manifest: Mapping[str, Any], inputs: Mapping[str, Any]) -> tuple[dict, str]:
    """Return ``(pack, hash)``.  Does no I/O and does not mutate its arguments."""
    if not isinstance(manifest, Mapping) or not manifest.get("sections"):
        raise SpecError("manifest must be a mapping with a non-empty 'sections' list")
    names = [s.get("name") for s in manifest["sections"]]
    if len(set(names)) != len(names):
        raise SpecError("manifest sections must have unique names")
    for s in manifest["sections"]:
        if s.get("tier") not in _RANK:
            raise SpecError(f"section {s.get('name')!r}: tier must be one of {list(TIERS)}")
    supplied = dict(inputs.get("sections", {}))
    gates_in = dict(inputs.get("pregates", {}))
    deferred: list[str] = []
    omitted: list[str] = []
    truncations: list[dict] = []

    # pre-gates: each becomes a volatile section carrying the verdict itself
    gate_sections: list[dict] = []
    for g in sorted(manifest.get("pregates", []), key=lambda g: g["id"]):
        out = gates_in.get(g["id"])
        if out is None:
            if g["required"]:
                deferred.append(f"required pre-gate {g['id']!r} has no output")
            continue
        if g["required"] and out.get("status") in ("stale", "failed"):
            deferred.append(f"required pre-gate {g['id']!r} is {out.get('status')}")
        gate_sections.append(
            {
                "name": PREGATE_PREFIX + g["id"],
                "tier": "volatile",
                "text": canonical_json(out),
                "max_chars": 1 << 30,
                "required": bool(g["required"]),
            }
        )

    # filled sections
    items: list[dict] = list(gate_sections)
    for s in manifest["sections"]:
        text = s.get("text") if s["source"] == "static" else supplied.get(s["name"])
        if text is None:
            if s["required"]:
                deferred.append(f"required section {s['name']!r} has no input")
            else:
                omitted.append(s["name"])
            continue
        items.append({**{k: s[k] for k in ("name", "tier", "max_chars", "required")}, "text": text})
    items.sort(key=lambda i: (_RANK[i["tier"]], i["name"]))
    delim = manifest.get("delimiter", DEFAULT_DELIMITER)
    delims = tuple(sorted({delim, DEFAULT_DELIMITER}))
    for i in items:
        if i["tier"] != "stable":
            i["text"] = _escape(i["text"], delims)

    # per-section cap
    for i in items:
        i["truncated"] = False
        if len(i["text"]) > i["max_chars"]:
            cut = len(i["text"]) - i["max_chars"]
            truncations.append(
                {"section": i["name"], "tier": i["tier"], "reason": "section-cap", "chars_cut": cut}
            )
            i["text"] = i["text"][: i["max_chars"]] + _marker(cut)
            i["truncated"] = True

    # whole-pack budget: cut volatile first, then session, never stable
    limit = int(manifest["budget_chars"])
    total = sum(len(i["text"]) for i in items)
    for i in sorted(items, key=lambda i: (_RANK[i["tier"]], i["name"]), reverse=True):
        if total <= limit:
            break
        if i["tier"] == "stable":
            break
        excess = total - limit
        if not i["required"]:
            truncations.append(
                {
                    "section": i["name"],
                    "tier": i["tier"],
                    "reason": "budget-drop",
                    "chars_cut": len(i["text"]),
                }
            )
            total -= len(i["text"])
            i["text"], i["truncated"] = "", True
        else:
            keep = max(len(i["text"]) - excess - len(_marker(excess)), 0)
            cut = len(i["text"]) - keep
            truncations.append(
                {"section": i["name"], "tier": i["tier"], "reason": "budget-trim", "chars_cut": cut}
            )
            total -= len(i["text"])
            i["text"] = i["text"][:keep] + _marker(cut)
            i["truncated"] = True
            total += len(i["text"])
    if total > limit:
        deferred.append(f"stable context ({total} chars) exceeds budget_chars={limit}")
    items = [i for i in items if i["text"] or not i["truncated"]]
    touched = sorted({t["tier"] for t in truncations}, key=_RANK.get)

    sections = [
        {
            "name": i["name"],
            "tier": i["tier"],
            "chars": len(i["text"]),
            "truncated": i["truncated"],
            "text": i["text"],
        }
        for i in items
    ]
    fenced = [(s["name"], s["tier"], s["text"]) for s in sections if s["tier"] != "stable"]
    nonce = digest_of([delim, fenced]).split(":", 1)[1][:16]

    def fence(s: Mapping[str, Any]) -> str:
        if s["tier"] == "stable":
            return f"{delim} {s['name']} [stable] {delim}\n{s['text']}\n"
        return (
            f"{delim} {s['name']} [{s['tier']}] {nonce} {delim}\n{s['text']}\n"
            f"{delim} end {s['name']} {nonce} {delim}\n"
        )

    rendered = "".join(fence(s) for s in sections)
    stable_prefix = "".join(fence(s) for s in sections if s["tier"] == "stable")
    pack = {
        "manifest": manifest["id"],
        "persona": manifest["persona"],
        "skills": sorted(manifest.get("skills", [])),
        "tools": sorted(manifest.get("tools", [])),
        "memory_scopes": sorted(manifest.get("memory_scopes", [])),
        "status": "deferred" if deferred else "ready",
        "deferred_reasons": sorted(set(deferred)),
        "sections": sections,
        "omitted": sorted(omitted),
        "truncations": sorted(truncations, key=lambda t: (_RANK[t["tier"]], t["section"])),
        "budget": {"limit_chars": limit, "used_chars": total, "tiers_cut": touched},
        "stable_prefix_digest": sha256_text(stable_prefix),
        "text": rendered,
    }
    return pack, digest_of(pack)
