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
:data:`ESCAPE_PREFIX`, so input cannot open a fake section, stable or otherwise.  A line is what
any Unicode line boundary ends (CR, VT, FF, NEL, LS and PS as well as LF), and leading
whitespace and format characters (zero-width space, BOM) do not hide a delimiter.

Screening.  Before fencing, every section filled from input (``source: input``) is passed through
:class:`~homelabnext.agent.screen.Screener`, which replaces secrets and PII with typed labels that
are stable across the pack (``[REDACTED:email:1]`` is the same address in every section).  It is
on unless the manifest says ``screen: {redact: false, reason: ...}``; either way the pack's
``screen`` block records what happened (settings and counts, never a value).  A caller's
``denylist`` (deny-list lines: literal terms or ``re:`` regexes) is applied even when the manifest
opts out of the rest.  Static sections and pre-gate verdicts are platform-authored and are not
screened.

Knowledge.  ``knowledge=`` takes a :class:`~homelabnext.agent.knowledge.Selection` (the
profile's ``include:`` rules run over the repository graph): each included node becomes an
optional volatile section named ``knowledge-<rank>-<id>`` whose text is the record or page itself
under a header with its id, path, review tiers and content digest.  It is repository content, not
input, so it is not screened, but it is fenced and escaped like every volatile section.  When the
pack is over budget, knowledge goes first, lowest rank first, before any other section; the
pack's ``knowledge`` block lists the included ids and digests and every exclusion with its
reason.  The ``knowledge-`` section prefix is reserved.

``inputs`` shape::

    {"sections": {<section name>: <text>}, "pregates": {<gate id>: <pregate_output dict>}}
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Any

from .digest import canonical_json, digest_of, sha256_text
from .errors import SpecError
from .screen import Screener, screen_config

TIERS = ("stable", "session", "volatile")
_RANK = {t: i for i, t in enumerate(TIERS)}
DEFAULT_DELIMITER = "====="
PREGATE_PREFIX = "pregate-"
KNOWLEDGE_PREFIX = "knowledge-"
ESCAPE_PREFIX = "[escaped] "


#: every line boundary ``str.splitlines`` knows (CR, LF, CRLF, VT, FF, FS/GS/RS, NEL, LS, PS):
#: a renderer or tokenizer that breaks a line on any of them must not see a fence escaping missed
LINE_BREAK = re.compile("(\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029])")


#: characters a reader does not see as ink: format characters (zero width space, BOM, joiners,
#: bidi controls, tags), combining marks (a mark or variation selector before or inside a
#: delimiter), and the blank letters and symbols that render as nothing (Hangul fillers, the
#: braille blank)
_INVISIBLE_CATEGORIES = frozenset({"Cf", "Mn", "Me"})
_BLANK_FILLERS = frozenset("\u115f\u1160\u3164\uffa0\u2800")


def fence_key(line: str, width: int | None = None) -> str:
    """What a fence test must look at: ``line`` as a reader sees it.  Every character is
    NFKC-folded (a full-width delimiter reads as the ASCII one), invisible characters are
    dropped wherever they are (:data:`_INVISIBLE_CATEGORIES`, :data:`_BLANK_FILLERS`), and
    leading whitespace is skipped.  With ``width``, folding stops once that many characters are kept, so a very long
    line costs no more than its start."""
    out: list[str] = []
    for ch in line:
        for c in ch if ch.isascii() else unicodedata.normalize("NFKC", ch):
            if not c.isascii() and (
                c in _BLANK_FILLERS or unicodedata.category(c) in _INVISIBLE_CATEGORIES
            ):
                continue
            if not out and c.isspace():
                continue
            out.append(c)
        if width is not None and len(out) >= width:
            break
    return "".join(out)


def looks_like_fence(line: str, delims: tuple[str, ...]) -> bool:
    """True when ``line`` would read as a fence (or as the escape prefix) to a model."""
    escape = ESCAPE_PREFIX.rstrip()
    key = fence_key(line, max([len(escape), *map(len, delims)]))
    return key.startswith(delims) or key.startswith(escape)


def split_lines(text: str) -> list[str]:
    """``text`` split on every line boundary (:data:`LINE_BREAK`), without the breaks."""
    return LINE_BREAK.split(text)[::2]


def _escape(text: str, delims: tuple[str, ...]) -> str:
    """Prefix every line that looks like a fence so it reads as data, not structure.  A line is
    what any line boundary ends (not only LF), and the test looks at the line as a reader sees it
    (:func:`fence_key`); the text's own line breaks are kept."""
    parts = LINE_BREAK.split(text)  # line, break, line, break, ..., line
    for i in range(0, len(parts), 2):
        if looks_like_fence(parts[i], delims):
            parts[i] = ESCAPE_PREFIX + parts[i]
    return "".join(parts)


def _marker(n: int) -> str:
    return f"\n[TRUNCATED: {n} chars omitted]"


def assemble_pack(
    manifest: Mapping[str, Any],
    inputs: Mapping[str, Any],
    *,
    denylist: Iterable[str] | None = None,
    knowledge: Any = None,
    screener: Screener | None = None,
) -> tuple[dict, str]:
    """Return ``(pack, hash)``.  Does no I/O and does not mutate its arguments.

    ``denylist``: deny-list lines whose terms are redacted from input sections (see module doc).
    ``knowledge``: a :class:`~homelabnext.agent.knowledge.Selection` to add (see module doc).
    ``screener``: the :class:`~homelabnext.agent.screen.Screener` to redact with, kept by the
    caller across packs so its labels stay stable over them (the same value, the same label,
    the screener's own contract); by default each pack gets a fresh one, built from the
    manifest's ``screen`` block and ``denylist`` (which a passed screener already carries).
    """
    if not isinstance(manifest, Mapping) or not manifest.get("sections"):
        raise SpecError("manifest must be a mapping with a non-empty 'sections' list")
    names = [s.get("name") for s in manifest["sections"]]
    if len(set(names)) != len(names):
        raise SpecError("manifest sections must have unique names")
    for s in manifest["sections"]:
        if str(s.get("name", "")).startswith(KNOWLEDGE_PREFIX):
            raise SpecError(
                f"section {s.get('name')!r}: the {KNOWLEDGE_PREFIX!r} prefix is reserved"
            )
        if s.get("tier") not in _RANK:
            raise SpecError(f"section {s.get('name')!r}: tier must be one of {list(TIERS)}")
    try:
        screen_cfg = screen_config(manifest)
        deny = list(denylist or [])
        if screener is None:
            screener = Screener(
                redact_private_ips=screen_cfg["redact_private_ips"],
                denylist=deny,
                types=None if screen_cfg["redact"] else ("denylist",),
            )
    except ValueError as exc:
        raise SpecError(str(exc)) from None
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
                "source": "pregate",
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
        keep = ("name", "tier", "max_chars", "required", "source")
        items.append({**{k: s[k] for k in keep}, "text": text})
    if knowledge is not None:
        items += [dict(k) for k in knowledge.sections()]
    items.sort(key=lambda i: (_RANK[i["tier"]], i["name"]))

    # screening: untrusted input only, in pack order so label numbers follow first appearance
    screened = []
    for i in items:
        if i["source"] == "input" and screener.types:
            i["text"] = screener.screen(i["text"])[0]
            screened.append(i["name"])
    screen_record = {**screener.summary(), "sections": screened}
    if not screen_cfg["redact"]:
        screen_record.update(enabled=False, reason=screen_cfg["reason"])

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

    # whole-pack budget: cut knowledge (lowest rank first), then volatile, then session, never
    # stable
    limit = int(manifest["budget_chars"])
    total = sum(len(i["text"]) for i in items)

    def cut_order(i: Mapping[str, Any]) -> tuple:
        return (_RANK[i["tier"]], i["source"] == "knowledge", i["name"])

    for i in sorted(items, key=cut_order, reverse=True):
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
        "screen": screen_record,
        "text": rendered,
    }
    if knowledge is not None:
        pack["knowledge"] = knowledge.record()
    return pack, digest_of(pack)
