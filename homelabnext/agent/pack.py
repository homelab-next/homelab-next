# SPDX-License-Identifier: Apache-2.0
"""Context-pack assembler: ``(manifest, inputs, now) -> (pack, hash)``, a pure function.

The only clock is ``now=`` (default: the current UTC time), and it is read only to age a
pre-gate output whose gate sets ``max_age_s``.  Replaying a pack by its hash therefore needs the
same ``now`` as well as the same manifest and inputs: the same inputs assembled later can defer.

Ordering is stable before volatile: sections are emitted by tier (``stable``, ``session``,
``volatile``) and, within a tier, by name, so the byte-identical prefix is as long as possible
(cache friendly) and identical inputs always give an identical pack and hash, whatever order the
caller built its dicts in.

There is no silent truncation.  A section over its own ``max_chars`` and a pack over
``budget_chars`` are both cut, and every cut is listed in ``truncations`` / ``budget`` with the
tier it came from.  Volatile content is cut first, then session; stable content is never cut --
if the stable tier alone does not fit, the pack is ``deferred``.

Pre-gates.  Each output in ``inputs["pregates"]`` is checked before it is used: it must match
``agent/pregate_output``, its ``gate`` must be the id it is filed under, and, when the manifest
gives the gate a ``max_age_s``, its ``observed_at`` must be no older than that (and no more than
:data:`MAX_CLOCK_SKEW_S` in the future) at ``now`` (default: the current UTC time; pass ``now=``
to assemble against a fixed clock).  An output that fails a check is not rendered: a required
gate's defers the pack with the reason, an optional gate's is listed in ``omitted``.  A required
pre-gate that is missing, ``stale`` or ``failed`` also yields a ``deferred`` pack with the reason,
so the agent does not run on guessed context; any status the schema does not list fails the
schema check and so defers too.

Fencing.  Stable sections are fenced ``<delim> <name> [stable] <delim>``; their text comes from
the manifest, so a ``source: input`` section may never be ``tier: stable``
(:func:`~homelabnext.agent.readers.stable_input_problems`; refused at assembly).  Session and
volatile sections carry untrusted input, so they are fenced with a per-pack nonce,
``<delim> <name> [<tier>] <nonce> <delim>`` ... ``<delim> end <name> <nonce> <delim>``, where the nonce is derived from the digest of the fenced content (deterministic, so the
pack stays a pure function, but not knowable to whoever wrote that content).  Any line of
session or volatile text that starts with the delimiter (or the default one) is escaped with
:data:`ESCAPE_PREFIX`, so input cannot open a fake section, stable or otherwise.  A line is what
any Unicode line boundary ends (CR, VT, FF, NEL, LS and PS as well as LF), and leading
whitespace and format characters (zero-width space, BOM) do not hide a delimiter.  The
delimiters are read the same way (:func:`fence_key`), so a full-width, space-led,
zero-width-laced or accented (precomposed or decomposed) custom delimiter is matched as a reader
sees it too.  A delimiter that holds a line break, or that a reader sees as fewer than
:data:`MIN_VISIBLE_DELIMITER` characters, is refused (:func:`delimiter_problems`).

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

Identities and labels (ADR-0037 decisions 7 and 8).  The pack's ``provenance`` block records,
for what the pack **rendered** (a section that survived the budget) and nothing else:

* each knowledge item's ``id``, its record ``uid`` (``lesson:<uid>`` gives ``<uid>``; a node id
  whose suffix is not a canonical UUIDv7 has none), ``digest``, ``file_digest`` when it has one,
  and ``tlp``: the record's or page's declared label (the selection's ``tlp``), ``red`` when it
  declares none;
* each input item the caller declares for an input section (``inputs["items"]``), with its
  ``uid``, ``digest`` and ``tlp``.  The uid must be platform-issued: the caller resolves every
  input uid through the records or lake reader and passes ``resolved_uids`` (a sealed
  :class:`~homelabnext.agent.resolved.ResolvedUids`, ``{uid: {digest, tlp}}`` as stored), and an
  item whose uid is not in it, or whose digest is not the stored one, is refused, so the
  assembler stays a pure function with no I/O.  The item's label is the strictest of the stored
  label (read as stored data: a non-canonical one is ``red``) and the caller's, so a
  caller can raise a label and never lower it; an item with neither is ``red``;
* each rendered section's ``tlp``: a static section's is the manifest's declared label (``red``
  when absent), a pre-gate section is ``red`` (lab data), an input section is the strictest of its
  items (``red`` with none), and a knowledge section is its item's;
* and ``tlp``, the pack's own label: the strictest of every rendered section's.

An input section's label is also raised by any TLP marker in its text (:func:`homelabnext.tlp.
markers`): text can only raise a label, never lower one.  A section the budget **trimmed** (cut
short, not dropped) still counts every item declared for it as rendered: the assembler cannot
tell which item a cut fell in, and counting them errs toward retracting more, never less.  A
pack assembled with ``profile=`` records ``profile: {id, digest}``; without, ``profile: null``.

These identifiers are the only things a memory update may cite as a source
(:func:`homelabnext.agent.report.source_problems`).  A pack in which an input item's uid is also
a knowledge item's uid with a different digest, or two input items pair one uid with two digests,
is refused at assembly (decision 13).  A pack may render at most :data:`MAX_RENDERED` identifiers
(decision 9); :func:`rendered_count` lets a caller check before it assembles, and the assembler
refuses a pack over it.

Memory (ADR-0037 decisions 9, 11 and 14).  ``memory=`` takes the entries platform code renders
into the pack from the profile's own store (``homelabnext.agent.memory.memory_block_input``):
each ``{scope, key, rev, value_digest, tlp, closure}``.  It needs ``profile=``, every scope must
be one of the profile's ``memory_scopes``, and the pack records them as its ``memory`` block,
``{scope, key, rev, value_digest, tlp}`` each (the closure is not recorded).  An entry from
``memory_block_input(..., stale_after=)`` also carries ``stale``, ``reasserted_at`` and, when a
verifier set it, ``verified_at`` (decision 15), and the block records them: staleness is
reported in the pack, and the renderer decides how a stale entry ranks.  The block is what a
``mem:`` source may name, and each entry's label counts toward the pack's.  A pack assembled
without ``memory=`` has no block (and its hash is what it was).

Retraction (ADR-0037 decision 14).  ``retracted=`` takes the active
:class:`~homelabnext.agent.deny.DenySet` (the caller reads it from the store's deny log; the
assembler does no I/O).  A memory entry whose closure reaches a denied name, or that carries an
active ``denied_reach`` mark, is left out of the block.  An input section that declares a denied
item is left out whole, listed in ``omitted`` (a required one defers the pack): the assembler
cannot cut one item's text out of a section, so it errs toward leaving more out.  A knowledge item
naming a denied identifier is dropped too (``select_knowledge(..., retracted=)`` already excludes
it).  What was left out is listed in the pack's ``retracted`` block (input items by section and
uid, knowledge by id, memory entries by count only), present only when something was.

``inputs`` shape::

    {"sections": {<section name>: <text>}, "pregates": {<gate id>: <pregate_output dict>},
     "items": {<input section name>: [{"uid": <UUIDv7>, "digest": "sha256:...", "tlp": <label>}]}}
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from homelabnext import tlp
from homelabnext.notify.core_pairs import AGENT_PACK_QUARANTINED

from .compiler import VerifiedProfile, require_verified
from .deny import DenySet, mem_ref
from .digest import canonical_json, digest_of, sha256_text
from .errors import SpecError
from .readers import stable_input_problems
from .resolved import DIGEST, UID, ResolvedUids
from .schemas import schema_error_shapes
from .screen import Screener, screen_config

TIERS = ("stable", "session", "volatile")
_RANK = {t: i for i, t in enumerate(TIERS)}
DEFAULT_DELIMITER = "====="
PREGATE_PREFIX = "pregate-"
KNOWLEDGE_PREFIX = "knowledge-"
ESCAPE_PREFIX = "[escaped] "

#: the pair a quarantined required section pages with (:func:`quarantine_page`)
QUARANTINE_TITLE, QUARANTINE_CLEARED = AGENT_PACK_QUARANTINED
#: the most identifiers one pack may render (ADR-0037 decision 9)
MAX_RENDERED = 1024
#: how far in the future a pre-gate's ``observed_at`` may be before the output is refused
MAX_CLOCK_SKEW_S = 300
#: the fewest characters a custom delimiter must keep once read as a reader sees it
#: (:func:`fence_key`): a fence a reader cannot see does not separate data from instructions
MIN_VISIBLE_DELIMITER = 4
_RED = str(tlp.Label.RED)


def _now() -> datetime:
    """The clock ``assemble_pack`` reads when no ``now=`` is passed (tests replace it)."""
    return datetime.now(UTC)


def _parse_time(value: str) -> datetime | None:
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo is not None else None


def _gate_problem(gate: Mapping[str, Any], out: Any, now: Any) -> str | None:
    """Why the output ``out`` filed for ``gate`` may not be used (None: it may).  Messages name
    schema paths and keywords, never a value (:func:`~homelabnext.agent.schemas.
    schema_error_shapes`)."""
    shapes = schema_error_shapes("agent", "pregate_output", out)
    if shapes:
        return f"does not match agent/pregate_output ({'; '.join(shapes[:3])})"
    if out["gate"] != gate["id"]:
        return "is filed under this gate but names another gate"
    max_age = gate.get("max_age_s")
    if max_age is None:
        return None
    observed = _parse_time(out["observed_at"])
    if observed is None:
        return "has an observed_at that is not an RFC 3339 time with an offset"
    clock = now() if now is not None else _now()
    if not isinstance(clock, datetime) or clock.tzinfo is None:
        raise SpecError("now must return a timezone-aware datetime")
    age = (clock - observed).total_seconds()
    if age > max_age:
        return f"is {int(age)}s old, over max_age_s={max_age}"
    if age < -MAX_CLOCK_SKEW_S:
        return f"was observed {int(-age)}s in the future (over {MAX_CLOCK_SKEW_S}s of skew)"
    return None


def node_uid(node_id: str) -> str | None:
    """The record uid a knowledge node id carries (``lesson:<uid>`` gives ``<uid>``), or None."""
    suffix = node_id.split(":", 1)[1] if ":" in node_id else ""
    return suffix if UID.fullmatch(suffix) else None


def _knowledge_ids(item: Mapping[str, Any]) -> list[str]:
    uid = node_uid(str(item.get("id", "")))
    return [x for x in (item.get("digest"), item.get("file_digest"), uid) if x]


def rendered_count(inputs: Mapping[str, Any], knowledge: Any = None) -> int:
    """How many distinct identifiers a pack of ``inputs`` and ``knowledge`` could render at most
    (every input item and every included knowledge item surviving the budget): the number the
    caller checks against :data:`MAX_RENDERED` before it assembles (ADR-0037 decision 9)."""
    found: set[str] = set()
    items = inputs.get("items") if isinstance(inputs, Mapping) else None
    for group in (items or {}).values() if isinstance(items, Mapping) else ():
        for it in group if isinstance(group, list) else ():
            if isinstance(it, Mapping):
                found.update(str(it[k]) for k in ("uid", "digest") if it.get(k))
    for k in knowledge.included if knowledge is not None else ():
        found.update(_knowledge_ids(k))
    return len(found)


def _input_items(
    manifest: Mapping[str, Any],
    inputs: Mapping[str, Any],
    resolved: ResolvedUids | None,
    knowledge: Any,
) -> dict[str, list[dict[str, str]]]:
    """The caller's input items by section, each ``{uid, digest, tlp}`` with its label clamped to
    the stored one (see the module doc).  Raises :class:`SpecError` for a malformed item, one whose
    uid the platform did not issue or whose digest is not the stored one, and a uid paired with
    two digests or a digest with two uids (knowledge items included)."""
    raw = inputs.get("items")
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise SpecError("inputs.items must map input section names to lists of items")
    if type(resolved) is not ResolvedUids:  # the exact sealed type, never a subclass
        raise SpecError(
            "input items need resolved_uids, a ResolvedUids made by resolve_input_uids from the "
            f"rows a records or lake reader stored (not a {type(resolved).__name__})"
        )
    kinds = {s["name"]: s["source"] for s in manifest["sections"]}
    pairs: dict[str, set[str]] = {}
    owner: dict[str, str] = {}  # digest -> the one uid it may be paired with
    for k in knowledge.included if knowledge is not None else ():
        uid = node_uid(str(k.get("id", "")))
        if uid:
            pairs[uid] = {d for d in (k.get("digest"), k.get("file_digest")) if d}
            owner.update(dict.fromkeys(pairs[uid], uid))
    out: dict[str, list[dict[str, str]]] = {}
    for name in sorted(raw):
        if kinds.get(name) != "input":
            raise SpecError(f"inputs.items: {name!r} is not an input section of the manifest")
        group = raw[name]
        if not isinstance(group, list):
            raise SpecError(f"inputs.items.{name}: expected a list of items")
        items = []
        for n, it in enumerate(group):
            where = f"inputs.items.{name}[{n}]"
            if not isinstance(it, Mapping) or not set(it) <= {"uid", "digest", "tlp"}:
                raise SpecError(f"{where}: an item is {{uid, digest, tlp}}")
            uid, digest = it.get("uid"), it.get("digest")
            if not isinstance(uid, str) or not UID.fullmatch(uid):
                raise SpecError(f"{where}: uid must be a canonical record uid (a UUIDv7)")
            if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
                raise SpecError(f"{where}: digest must be sha256:<64 hex>")
            if uid not in resolved:
                raise SpecError(
                    f"{where}: uid {uid} is not in the resolved uid map: an input item's uid "
                    "must be platform-issued (resolved through the records or lake reader), "
                    "never taken from feed content"
                )
            if resolved[uid].get("digest") != digest:
                raise SpecError(
                    f"{where}: digest is not the one {resolved.source} stored for uid {uid}"
                )
            if uid in pairs and digest not in pairs[uid]:
                raise SpecError(
                    f"{where}: uid {uid} is also a knowledge item's uid with a different digest; "
                    "a uid names one content (ADR-0037 decision 13)"
                )
            if owner.setdefault(digest, uid) != uid:
                raise SpecError(f"{where}: digest {digest} is paired with two uids in one pack")
            labels = [tlp.read_stored(resolved[uid].get("tlp"))]
            if "tlp" in it:  # a caller's label may raise the stored one, never lower it
                labels.append(tlp.read_stored(it["tlp"]))
            items.append({"uid": uid, "digest": digest, "tlp": str(max(labels))})
        out[name] = items
    return out


_SLUG = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_MEMORY_FIELDS = frozenset({"scope", "key", "rev", "value_digest", "tlp", "closure"})
#: the staleness fields a memory entry may carry (ADR-0037 decision 15), all or none of the
#: first two: ``memory_block_input(..., stale_after=)`` adds them
_STALE_FIELDS = frozenset({"stale", "reasserted_at"})
_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")


def _memory_block(
    memory: Any, profile: VerifiedProfile | None, retracted: DenySet
) -> tuple[list[dict[str, Any]], int]:
    """The pack's ``memory`` block from the caller's entries (see the module doc), and how many
    entries the deny set left out.  Raises :class:`SpecError` for a malformed entry, a scope the
    profile lacks, a key listed twice, and a block without ``profile=``."""
    if profile is None:
        raise SpecError(
            "memory= needs profile=: a memory block shows the bound profile's own revisions"
        )
    if not isinstance(memory, (list, tuple)):
        raise SpecError("memory must be a list of {scope, key, rev, value_digest, tlp, closure}")
    scopes = set(profile.get("memory_scopes") or ())
    owner = profile["id"]
    block: dict[tuple[str, str], dict[str, Any]] = {}
    left_out = 0
    for n, e in enumerate(memory):
        where = f"memory[{n}]"
        extra = set(e) - _MEMORY_FIELDS if isinstance(e, Mapping) else set()
        if (
            not isinstance(e, Mapping)
            or not set(e) >= _MEMORY_FIELDS
            or not extra <= _STALE_FIELDS | {"verified_at"}
            or (extra and not extra >= _STALE_FIELDS)
        ):
            raise SpecError(
                f"{where}: an entry is {{scope, key, rev, value_digest, tlp, closure}}, with "
                "{stale, reasserted_at, verified_at?} when staleness is reported"
            )
        scope, key, rev = e["scope"], e["key"], e["rev"]
        if not (isinstance(scope, str) and _SLUG.fullmatch(scope) and scope in scopes):
            raise SpecError(f"{where}: scope is not one of the profile's memory_scopes")
        if not (isinstance(key, str) and _SLUG.fullmatch(key)):
            raise SpecError(f"{where}: key must be a slug")
        if type(rev) is not int or rev < 1:
            raise SpecError(f"{where}: rev must be a positive integer")
        if not (isinstance(e["value_digest"], str) and DIGEST.fullmatch(e["value_digest"])):
            raise SpecError(f"{where}: value_digest must be sha256:<64 hex>")
        closure = e["closure"]
        if not isinstance(closure, (list, tuple)) or not all(isinstance(c, str) for c in closure):
            raise SpecError(f"{where}: closure must be a list of identifiers")
        if extra and (
            type(e["stale"]) is not bool
            or not (e["reasserted_at"] is None or _is_stamp(e["reasserted_at"]))
            or not _is_stamp(e.get("verified_at", "1970-01-01T00:00:00.000000Z"))
        ):
            raise SpecError(
                f"{where}: stale is a boolean, reasserted_at a memory stamp or null, verified_at "
                "a memory stamp"
            )
        if (scope, key) in block:
            raise SpecError(f"{where}: a key appears in the memory block once")
        # its closure reaches a denied name or cites a marked revision (the cited lineage), or
        # the revision itself is marked
        if retracted.reaches(closure) or retracted.marked(owner, scope, key, rev):
            left_out += 1
            continue
        block[(scope, key)] = {
            "scope": scope,
            "key": key,
            "rev": rev,
            "value_digest": e["value_digest"],
            # the store's label, read as stored data (a non-canonical one is red)
            "tlp": str(tlp.read_stored(e["tlp"])),
        }
        if extra:  # reported, not ranked (ADR-0037 decision 15; the renderer decides rank)
            block[(scope, key)].update({f: e[f] for f in sorted(extra)})
    return [block[k] for k in sorted(block)], left_out


def _is_stamp(value: Any) -> bool:
    return isinstance(value, str) and _STAMP.fullmatch(value) is not None


def _static_label(section: Mapping[str, Any]) -> str:
    """The declared label of a manifest section: a static section's ``tlp``, else ``red``."""
    if "tlp" not in section:
        return _RED
    if section["source"] != "static":
        raise SpecError(
            f"section {section['name']!r}: tlp is declared on static sections only; an input "
            "section's label comes from the items the caller declares for it"
        )
    try:
        return str(tlp.parse_stored(section["tlp"]))
    except ValueError as exc:
        raise SpecError(f"section {section['name']!r}: {exc}") from None


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
    NFKD-folded (a full-width delimiter reads as the ASCII one, and a precomposed accented
    letter decomposes, so it and its base letter plus a combining mark read the same), invisible
    characters, combining marks included, are dropped wherever they are
    (:data:`_INVISIBLE_CATEGORIES`, :data:`_BLANK_FILLERS`), and leading whitespace is skipped.
    With ``width``, folding stops once that many characters are kept, so a very long line costs
    no more than its start."""
    out: list[str] = []
    for ch in line:
        for c in ch if ch.isascii() else unicodedata.normalize("NFKD", ch):
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


def delimiter_problems(doc: Mapping[str, Any]) -> list[str]:
    """Why the ``delimiter`` of a manifest or prompt template cannot fence untrusted input (empty
    = it can, or none is set).  A delimiter holding a line break cannot be matched against any
    one line of input, so input could forge a fence line by line; one a reader sees as fewer than
    :data:`MIN_VISIBLE_DELIMITER` characters (:func:`fence_key`, trailing whitespace dropped) is
    a fence nobody can see, and would make every input line look like one.  The messages never
    quote the delimiter."""
    delim = doc.get("delimiter") if isinstance(doc, Mapping) else None
    if not isinstance(delim, str):
        return []
    if LINE_BREAK.search(delim):
        return ["delimiter holds a line break, so a fence could be forged line by line"]
    if len(fence_key(delim).rstrip()) < MIN_VISIBLE_DELIMITER:
        return [
            f"delimiter reads as fewer than {MIN_VISIBLE_DELIMITER} visible characters "
            "(whitespace, invisible characters and combining marks do not count)"
        ]
    return []


@lru_cache(maxsize=64)
def _folded(delims: tuple[str, ...]) -> tuple[tuple[str, ...], int]:
    """``delims`` read as a reader sees them (:func:`fence_key`, trailing whitespace dropped, so
    a line that differs only in the spaces after the delimiter still matches), and how many
    characters of a line a fence test must fold to compare them and the escape prefix."""
    escape = ESCAPE_PREFIX.rstrip()
    keys = tuple(sorted({fence_key(d).rstrip() for d in delims}))
    return keys, max([len(escape), *map(len, keys)])


def looks_like_fence(line: str, delims: tuple[str, ...]) -> bool:
    """True when ``line`` would read as a fence (or as the escape prefix) to a model.  The line
    and the delimiters are both folded (:func:`fence_key`): a delimiter spelled with full-width
    characters, a leading space, a zero-width space or an accent matches its plain-looking
    forgery."""
    keys, width = _folded(tuple(delims))
    key = fence_key(line, width)
    return key.startswith(keys) or key.startswith(ESCAPE_PREFIX.rstrip())


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
    resolved_uids: ResolvedUids | None = None,
    profile: VerifiedProfile | None = None,
    memory: Any = None,
    retracted: DenySet | None = None,
    now: Any = None,
) -> tuple[dict, str]:
    """Return ``(pack, hash)``.  Does no I/O and does not mutate its arguments; the only clock
    is ``now`` (below).

    ``denylist``: deny-list lines whose terms are redacted from input sections (see module doc).
    ``knowledge``: a :class:`~homelabnext.agent.knowledge.Selection` to add (see module doc).
    ``resolved_uids``: a :class:`~homelabnext.agent.resolved.ResolvedUids`, the stored
    ``{digest, tlp}`` of each input item's uid as a records or lake reader resolved it; needed
    whenever ``inputs`` declares ``items``.
    ``profile``: the :class:`~homelabnext.agent.compiler.VerifiedProfile` the pack is assembled
    for; the pack records its ``id`` and ``digest`` (``pack["profile"]``), and the memory store
    applies a report only with a pack bound to the reporting profile.
    ``screener``: the :class:`~homelabnext.agent.screen.Screener` to redact with, kept by the
    caller across packs so its labels stay stable over them (the same value, the same label,
    the screener's own contract); by default each pack gets a fresh one, built from the
    manifest's ``screen`` block and ``denylist`` (which a passed screener already carries).
    ``memory``: the memory entries platform code renders into the pack (see the module doc);
    the pack gains a ``memory`` block.  Needs ``profile``.
    ``retracted``: the active :class:`~homelabnext.agent.deny.DenySet`; denied input sections,
    knowledge items and memory entries are left out (see the module doc).  Wherever a memory
    store is wired in, pass ``homelabnext.agent.memory.denied(backend)``; when that raises
    ``DenyFileProblem``, do not assemble a pack at all (omitting ``retracted`` would serve
    retracted content: the default is no deny set).
    ``now``: a zero-argument callable returning a timezone-aware :class:`~datetime.datetime`,
    the clock a pre-gate's ``max_age_s`` is checked against (default: the current UTC time).  It
    is called only when a gate with ``max_age_s`` has an output; a value that is not an aware
    datetime raises :class:`SpecError`.
    """
    if now is not None and not callable(now):
        raise SpecError("now must be a callable returning a timezone-aware datetime")
    if retracted is not None and type(retracted) is not DenySet:
        raise SpecError("retracted must be a DenySet (homelabnext.agent.deny.deny_set)")
    denyset = retracted if retracted is not None else DenySet()
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
    unfenceable = stable_input_problems(manifest) + delimiter_problems(manifest)
    if unfenceable:
        raise SpecError("; ".join(unfenceable))
    bound = None
    if profile is not None:
        require_verified(profile, "assemble_pack")
        bound = {"id": profile["id"], "digest": profile["digest"]}
    static_labels = {s["name"]: _static_label(s) for s in manifest["sections"]}
    count = rendered_count(inputs, knowledge)
    if count > MAX_RENDERED:
        raise SpecError(
            f"the pack would render {count} identifiers, over the cap of {MAX_RENDERED} "
            "(ADR-0037 decision 9): select fewer knowledge or input items"
        )
    input_items = _input_items(manifest, inputs, resolved_uids, knowledge)
    block, memory_left_out = (None, 0)
    if memory is not None:
        block, memory_left_out = _memory_block(memory, profile, denyset)
    denied_inputs = [
        {"section": name, "uid": it["uid"]}
        for name, group in sorted(input_items.items())
        for it in group
        if denyset.denies_input(it["uid"], it["digest"])
    ]
    denied_sections = {d["section"] for d in denied_inputs}
    quarantined: list[str] = []
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
        problem = _gate_problem(g, out, now)
        if problem is not None:
            if g["required"]:
                deferred.append(f"required pre-gate {g['id']!r} output {problem}")
            else:
                omitted.append(PREGATE_PREFIX + g["id"])
            continue
        if g["required"] and out["status"] in ("stale", "failed"):
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
        if s["name"] in denied_sections:  # one item's text cannot be cut out: leave it all out
            omitted.append(s["name"])
            if s["required"]:  # quarantined: the caller pages (quarantine_page), not deferred
                quarantined.append(s["name"])
            continue
        if text is None:
            if s["required"]:
                deferred.append(f"required section {s['name']!r} has no input")
            else:
                omitted.append(s["name"])
            continue
        keep = ("name", "tier", "max_chars", "required", "source")
        items.append({**{k: s[k] for k in keep}, "text": text})
    denied_knowledge: list[str] = []
    if knowledge is not None:
        dropped = {
            k["section"]: k["id"]
            for k in knowledge.included
            if denyset.denies([k["id"], *_knowledge_ids(k)])
        }
        denied_knowledge = sorted(dropped.values())
        items += [dict(k) for k in knowledge.sections() if k["name"] not in dropped]
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
    provenance = _provenance(items, static_labels, input_items, knowledge, supplied)
    if block:  # what the block shows is rendered into the pack: its labels count (decision 8)
        provenance["tlp"] = str(tlp.strictest([provenance["tlp"], *(e["tlp"] for e in block)]))
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
        "profile": bound,
        "provenance": provenance,
        "text": rendered,
    }
    if knowledge is not None:
        record = knowledge.record()
        if denied_knowledge:  # a dropped item is no longer listed as included
            gone = set(denied_knowledge)
            record["included"] = [i for i in record["included"] if i["id"] not in gone]
            record["excluded"] = sorted(
                [*record["excluded"], *({"id": i, "reason": "retracted"} for i in gone)],
                key=lambda e: e["id"],
            )
        pack["knowledge"] = record
    if block is not None:
        pack["memory"] = block
    if denied_inputs or denied_knowledge or memory_left_out:
        pack["retracted"] = {
            "inputs": denied_inputs,
            "knowledge": denied_knowledge,
            "memory": memory_left_out,
            "quarantined": sorted(quarantined),
        }
    return pack, digest_of(pack)


def _provenance(
    rendered: list[dict],
    static_labels: Mapping[str, str],
    input_items: Mapping[str, list[dict[str, str]]],
    knowledge: Any,
    supplied: Mapping[str, Any],
) -> dict[str, Any]:
    """The pack's ``provenance`` block over the ``rendered`` sections only (see the module doc).
    An input section's label is raised, never lowered, by any TLP marker in its supplied text."""
    by_section = {k["section"]: k for k in (knowledge.included if knowledge is not None else ())}
    sections, known, inputs = [], [], []
    for i in rendered:
        name, source = i["name"], i["source"]
        if source == "knowledge":
            k = by_section[name]
            label = str(tlp.read_stored(k["tlp"])) if "tlp" in k else _RED
            entry = {"section": name, "id": k["id"]}
            uid = node_uid(str(k["id"]))
            if uid:
                entry["uid"] = uid
            entry["digest"] = k["digest"]
            if k.get("file_digest"):
                entry["file_digest"] = k["file_digest"]
            known.append({**entry, "tlp": label})
        elif source == "input":
            items = input_items.get(name, [])
            inputs += [{"section": name, **it} for it in items]
            found = [tlp.read_stored(it["tlp"]) for it in items]
            if found:  # markers in the text can only raise it (decision 8)
                found += tlp.markers(supplied.get(name) or "")
            label = str(max(found)) if found else _RED
        elif source == "static":
            label = static_labels[name]
        else:  # a pre-gate verdict is lab data (ADR-0033 decision 2)
            label = _RED
        sections.append({"name": name, "tlp": label})
    return {
        "tlp": str(tlp.strictest(s["tlp"] for s in sections)),
        "sections": sections,
        "knowledge": known,
        "inputs": inputs,
    }


def rendered_identifiers(pack: Mapping[str, Any]) -> dict[str, str]:
    """``{identifier: label}`` for every identifier the assembler recorded for something ``pack``
    rendered (ADR-0037 decision 7): a knowledge item's ``digest``, ``file_digest`` and ``uid``, and
    an input item's ``digest`` and ``uid``.  An identifier recorded twice takes the stricter label.
    A pack without a ``provenance`` block rendered nothing that can be cited."""
    prov = pack.get("provenance")
    out: dict[str, str] = {}
    if not isinstance(prov, Mapping):
        return out
    for group, keys in (
        ("knowledge", ("digest", "file_digest", "uid")),
        ("inputs", ("digest", "uid")),
    ):
        for item in prov.get(group) or ():
            for k in keys:
                ident = item.get(k)
                if isinstance(ident, str) and ident:
                    prev = out.get(ident)
                    label = str(tlp.read_stored(item.get("tlp")))
                    out[ident] = label if prev is None else str(tlp.strictest([prev, label]))
    return out


def pack_label(pack: Mapping[str, Any]) -> str:
    """The pack's label (its ``provenance.tlp``); ``red`` for a pack that carries none."""
    prov = pack.get("provenance")
    if isinstance(prov, Mapping) and "tlp" in prov:
        return str(tlp.read_stored(prov.get("tlp")))
    return _RED


def pack_profile(pack: Mapping[str, Any]) -> tuple[str, str] | None:
    """``(id, digest)`` of the profile ``pack`` was assembled for, or None when it names none."""
    bound = pack.get("profile")
    if isinstance(bound, Mapping) and isinstance(bound.get("id"), str):
        return bound["id"], str(bound.get("digest"))
    return None


def pack_pairs(pack: Mapping[str, Any]) -> list[list[str]]:
    """The platform-issued pairings of what ``pack`` rendered (ADR-0037 decision 13), one group
    per item: a knowledge item's graph id, record uid and digests, and an input item's uid and
    digest.  These, and nothing a model or a feed wrote, are what ``retract`` calls aliases."""
    prov = pack.get("provenance")
    out: list[list[str]] = []
    if not isinstance(prov, Mapping):
        return out
    for group, keys in (
        ("knowledge", ("id", "uid", "digest", "file_digest")),
        ("inputs", ("uid", "digest")),
    ):
        for item in prov.get(group) or ():
            names = [item[k] for k in keys if isinstance(item.get(k), str) and item.get(k)]
            if names:
                out.append(names)
    return out


def knowledge_names(pack: Mapping[str, Any]) -> frozenset[str]:
    """Every name of the knowledge items ``pack`` rendered: graph id, record uid and digests.  A
    write whose pack names a denied one is refused (ADR-0037 decision 14); input items are
    matched by uid, or by digest under ``revision="this"`` only
    (:meth:`~homelabnext.agent.deny.DenySet.denies_input`)."""
    prov = pack.get("provenance")
    out: set[str] = set()
    for item in (prov.get("knowledge") or ()) if isinstance(prov, Mapping) else ():
        out.update(
            item[k] for k in ("id", "uid", "digest", "file_digest") if isinstance(item.get(k), str)
        )
    return frozenset(out)


def pack_memory(pack: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The pack's ``memory`` block (empty for a pack without one)."""
    block = pack.get("memory")
    return [dict(e) for e in block if isinstance(e, Mapping)] if isinstance(block, list) else []


def memory_refs(pack: Mapping[str, Any]) -> list[str]:
    """``mem:<owner>/<scope>/<key>@<rev>`` of each entry of the pack's ``memory`` block, the
    owner being the profile the pack is bound to (none without one)."""
    bound = pack_profile(pack)
    if bound is None:
        return []
    return [mem_ref(bound[0], e["scope"], e["key"], e["rev"]) for e in pack_memory(pack)]


def quarantine_page(
    notifier: Any, pack: Mapping[str, Any], owner: str, *, topic: Any = None
) -> None:
    """Page (state-diffed, pair ``AGENT_PACK_QUARANTINED``) that ``pack`` left out a required
    section because it declared a retracted input item, or send the recovery when it left out
    none.  The assembler is pure, so the caller that assembled the pack calls this (ADR-0037
    decision 14, amended): a quarantined section is never left out silently."""
    import hashlib

    from homelabnext.notify import Message

    title, cleared = QUARANTINE_TITLE, QUARANTINE_CLEARED
    notifier.register_pair(QUARANTINE_TITLE, QUARANTINE_CLEARED)
    key = (
        "agent-pack-quarantined-"
        + hashlib.sha256(f"{owner}\0{pack.get('manifest')}".encode()).hexdigest()[:16]
    )
    held = list((pack.get("retracted") or {}).get("quarantined") or ())
    if not held:
        notifier.report(
            key,
            "ok",
            Message(key, cleared, f"{owner}'s packs render every required section"),
            scope=owner,
        )
        return
    body = (
        f"{owner}'s pack of {pack.get('manifest')} left out required section(s) "
        f"{', '.join(held)}: each declares an input item an operator retracted. Filter retracted "
        "items before rendering the section text, or lift the retraction."
    )
    msg = Message(key, title, body, level="warn", topic=topic, tags=("agent", "memory"))
    notifier.report(key, "quarantined", msg, scope=owner)
