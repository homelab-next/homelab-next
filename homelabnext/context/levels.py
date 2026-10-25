# SPDX-License-Identifier: Apache-2.0
"""Authored Markdown served in levels: a summary, an outline, one section (ADR-0032).

A context document is read in three levels, so a caller pays only for what it opens:

* **L0, the summary.**  The front-matter ``summary:`` an author wrote and a review covered
  (``summary_source: authored``); without one, a derived line (``first-paragraph``, or
  ``synthesized`` for a node whose content the indexer built from its attributes); else nothing
  (``none``).  No model writes a summary: what is served is what git holds.
* **L1, the outline.**  The ATX headings (``#`` to ``######``) with their level, title, a slug,
  the heading path (``Decision/Consequences``) and the size of the section each opens.
* **L2, one section.**  A heading's own line and everything up to the next heading of the same or
  a higher level (its subsections included), named by its slug or its full heading path.

Parsing is small, deterministic (same text, same answer) and linear in the text it reads:

* **Bounds.**  At most :data:`MAX_PARSE_CHARS` characters and :data:`MAX_PARSE_LINES` lines are
  parsed.  Past either, the outline is cut there and says so (``parse_truncated``); a section
  still open at the cut ends at it.  A heading title is read from at most
  :data:`MAX_TITLE_CHARS` characters of its line.  Results are memoised per content digest.
* **Lines** end at ``\\n`` only (a ``\\r`` before it is dropped).  Every other separator Python's
  ``str.splitlines`` knows (``\\r``, ``\\v``, ``\\f``, ``\\x1c``-``\\x1e``, ``\\x85``, U+2028,
  U+2029) is ordinary text inside a line, so it can never start a hidden heading.
* **Front-matter.**  A UTF-8 byte-order mark is skipped, then a YAML block (``---`` on the first
  line to the next ``---`` line) is never a heading or a paragraph; a block that does not parse
  (any parser failure, deep nesting included, or a block over :data:`MAX_FRONT_CHARS`) gives no
  ``summary`` and is still skipped.
* **Hidden blocks** hold no heading and no paragraph: fenced code (`````` ``` `````` or ``~~~``,
  at most three spaces of indent, closed by a fence of the same character at least as long; an
  unclosed fence runs to the end); an HTML comment (``<!--`` to ``-->``, over any lines); and a
  raw ``<pre>``, ``<script>``, ``<style>`` or ``<details>`` block, from its opening tag at the
  start of a line to the first line holding its closing tag (no nesting is tracked).  Other raw
  HTML is not interpreted.  An indented line (four spaces or more) is never a heading.
* **Setext headings** (a line underlined with ``===`` or ``---``) **are not headings here**:
  their text is ordinary paragraph text.  The repository writes ATX headings only.
* **An empty heading** (``#`` alone) is not listed (nothing names it) but still ends the section
  before it.  **The preamble** (text before the first heading) is not a section; it is reached
  through ``context_for`` with ``detail: "full"``.
* **Titles** are the heading's visible text: links become their text, wiki-links their label,
  code spans, emphasis markers and HTML tags are dropped, and :func:`clean` removes invisible and
  control characters.  Slugs, paths and summaries are built from that text.
* **Slugs.**  The title lower-cased, each run of characters other than letters, digits and ``_``
  made one ``-``, trimmed (``heading`` when nothing is left).  A repeated slug is qualified by its
  parent's slug (``unreleased/added``), and only when that is taken too gets a counter
  (``added~2``).  A plain slug never holds ``/`` or ``~``, so a qualified one never collides with
  a literal title (``Added 2`` is ``added-2``).
* **Paths.**  The titles from the top down joined by ``/``, a ``/``, ``~`` or ``\\`` inside a
  title escaped with ``\\``.  A document's sole leading H1 is its title, not a path segment: its
  sections read ``Context``, not ``ADR-0032: .../Context``.  A repeated path gets ``~2``, ``~3``
  ... on its last segment (an escaped ``~`` cannot produce one), and subsections inherit it.
* **A slug or a path is valid only for the outline it came from**: an edit can change both.
  ``section`` takes the outline's ``digest`` to refuse a stale name instead of serving the wrong
  section.

:func:`check_summary` is the authoring rule the register validation, the schemas and
``hnx registers summaries`` share: one line of at most :data:`MAX_SUMMARY_CHARS` characters
with no character of the :data:`REFUSED_CATEGORIES` (ordinary spaces such as U+00A0 are fine).
"""

from __future__ import annotations

import hashlib
import re
import sys
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

__all__ = [
    "MAX_FRONT_CHARS",
    "MAX_PARSE_CHARS",
    "MAX_PARSE_LINES",
    "MAX_SUMMARY_CHARS",
    "MAX_TITLE_CHARS",
    "REFUSED_CATEGORIES",
    "SUMMARY_SOURCES",
    "Heading",
    "Parsed",
    "check_summary",
    "clean",
    "clear_memo",
    "cut",
    "find_section",
    "first_paragraph",
    "front_matter",
    "headings",
    "is_markdown",
    "memo_bytes",
    "parse",
    "summary_of",
    "visible",
]

#: the longest summary, authored or derived
MAX_SUMMARY_CHARS = 160
#: the most characters and lines of one document the parser reads (1 MiB, 100,000 lines)
MAX_PARSE_CHARS = 1 << 20
MAX_PARSE_LINES = 100_000
#: the most characters of a heading line read for its title
MAX_TITLE_CHARS = 512
#: the most characters of raw text reduced to visible text (a title's line, a paragraph): markup
#: removal stays cheap on a hostile line
_RAW_CHARS = 4 * MAX_TITLE_CHARS
#: a front-matter block longer than this is not parsed (PyYAML is pure Python): no mapping
MAX_FRONT_CHARS = 64 * 1024
#: where a served summary came from
SUMMARY_SOURCES = ("authored", "first-paragraph", "synthesized", "none")
#: Unicode categories no model-facing line may hold: control, format (bidi overrides, zero-width
#: characters, the byte-order mark), line and paragraph separators, surrogates
REFUSED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})

_FRONT = re.compile(r"---[ \t]*\r?\n(?:(?P<fm>.*?)\r?\n)?---[ \t]*(?:\r?\n|\Z)", re.DOTALL)
# no overlapping optional groups: the closing ``#`` run is stripped in code (_atx)
_ATX = re.compile(r" {0,3}(#{1,6})(?:[ \t](.*))?")
_FENCE = re.compile(r" {0,3}(`{3,}|~{3,})(.*)")
_RAW_OPEN = re.compile(r" {0,3}<(pre|script|style|details)(?=[\s>]|$)", re.IGNORECASE)
_SLUG_DROP = re.compile(r"[^\w]+")
_WIKI = re.compile(r"\[\[([^\]|\n]*)(?:\|([^\]\n]*))?\]\]")
_LINK = re.compile(r"!?\[([^\]\n]*)\]\([^)\n]*\)")
_TAG = re.compile(r"<[^<>\n]*>")
_EMPHASIS = re.compile(r"\*+|~~|(?<!\w)_+|_+(?!\w)")
_SENTENCE_END = re.compile(r"[.!?](?=\s|$)")
#: a derived summary skips blocks that are not prose: quotes, lists, tables, HTML, images
_NOT_PROSE = (">", "- ", "* ", "+ ", "|", "<", "!")
#: the parse memo: at most this many documents and about this many bytes of parses.  It keeps
#: headings and the derived paragraph, never the document's lines or text.
_MEMO_SIZE = 128
_MEMO_BYTES = 64 << 20
_MEMO: OrderedDict[str, Parsed] = OrderedDict()
_memo_bytes = 0


@dataclass(frozen=True)
class Heading:
    """One ATX heading and the section it opens (``start``/``end``: character offsets)."""

    level: int
    title: str
    slug: str
    path: str
    start: int
    end: int

    @property
    def chars(self) -> int:
        return self.end - self.start

    def as_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "title": self.title,
            "slug": self.slug,
            "path": self.path,
            "chars": self.chars,
        }


@dataclass(frozen=True)
class Parsed:
    """One document's parse: its headings, where its body starts and how much was read."""

    headings: tuple[Heading, ...]
    body: int  # offset after the BOM and front-matter
    parsed_chars: int  # offset where parsing stopped (len(text) unless truncated)
    truncated: bool  # MAX_PARSE_CHARS or MAX_PARSE_LINES cut the parse
    first_paragraph: str  # the derived summary (first_paragraph), already cut

    @property
    def size(self) -> int:
        """Approximate bytes this parse holds (what the memo bound counts)."""
        n = sys.getsizeof(self) + sys.getsizeof(self.headings) + sys.getsizeof(self.first_paragraph)
        for h in self.headings:
            n += sys.getsizeof(h) + sum(sys.getsizeof(x) for x in (h.title, h.slug, h.path))
            n += 3 * 32  # level, start, end
        return n


# --------------------------------------------------------------------------- text helpers


def clean(text: str) -> str:
    """``text`` as one model-facing line: a control or separator character (Cc, Zl, Zp) becomes a
    space, an invisible one (Cf: bidi overrides, zero-width characters, the BOM; Cs) is dropped,
    and whitespace runs collapse to one space."""
    out = []
    for c in text:
        cat = unicodedata.category(c)
        if cat in ("Cc", "Zl", "Zp"):
            out.append(" ")
        elif cat not in ("Cf", "Cs"):
            out.append(c)
    return " ".join("".join(out).split())


def visible(text: str) -> str:
    """Inline Markdown reduced to the text a reader sees: ``[t](u)`` -> ``t``, ``[[a|b]]`` ->
    ``b``, ``[[a]]`` -> ``a``, code spans, emphasis markers and HTML tags dropped; then
    :func:`clean`."""
    text = _WIKI.sub(lambda m: m[2] if m[2] is not None else m[1], text)
    text = _LINK.sub(r"\1", text)
    text = _TAG.sub("", text).replace("`", "")
    return clean(_EMPHASIS.sub("", text))


def cut(text: str, limit: int = MAX_SUMMARY_CHARS) -> str:
    """``text`` within ``limit`` characters: whole when it fits, else up to the last sentence end
    that fits (when that keeps at least a third of the room), else at a word with ``…``."""
    if len(text) <= limit:
        return text
    ends = [m.end() for m in _SENTENCE_END.finditer(text, 0, limit)]
    if ends and ends[-1] >= limit // 3:
        return text[: ends[-1]]
    room = limit - 1
    head = text[: room + 1]
    word = head.rsplit(" ", 1)[0] if " " in head else head[:room]
    return word[:room].rstrip() + "…"


def is_markdown(path: str) -> bool:
    """Levels apply to Markdown sources only: a ``#`` line in a script is a comment."""
    return path.lower().endswith(".md")


# --------------------------------------------------------------------------- parsing


def _skip_bom(text: str) -> int:
    return 1 if text.startswith("\ufeff") else 0


def front_matter(text: str) -> tuple[dict[str, Any] | None, int]:
    """``(mapping or None, offset where the body starts)``.  No block: ``(None, after the BOM)``;
    a block that is not a YAML mapping, or does not parse at all: ``(None, its end)``."""
    bom = _skip_bom(text)
    m = _FRONT.match(text, bom)
    if not m:
        return None, bom
    if len(m["fm"] or "") > MAX_FRONT_CHARS:
        return None, m.end()
    import yaml

    from homelabnext._yaml import UniqueKeyStrDateLoader

    try:
        data = yaml.load(m["fm"] or "", Loader=UniqueKeyStrDateLoader)  # a safe loader
    except Exception:  # any parser failure (a YAMLError, RecursionError on deep nesting, ...)
        data = None
    return (data if isinstance(data, dict) else None), m.end()


def _scan(text: str, start: int) -> tuple[list[tuple[int, str, bool]], int, bool]:
    """``(lines, parsed_end, truncated)``: ``(offset, line, hidden)`` for every body line up to
    the parse bounds, lines split on ``\\n`` only.  ``hidden``: inside fenced code, an HTML
    comment or a raw pre/script/style/details block."""
    limit = min(len(text), MAX_PARSE_CHARS)
    out: list[tuple[int, str, bool]] = []
    fence, close = "", ""  # an open fence; an open HTML block's closing marker
    pos = start
    while pos < limit:
        if len(out) >= MAX_PARSE_LINES:
            return out, pos, True
        nl = text.find("\n", pos, limit)
        end = limit if nl < 0 else nl + 1
        if nl < 0 and limit < len(text):
            return out, pos, True  # a line the bound cuts is not parsed
        line = text[pos:end].removesuffix("\n").removesuffix("\r")
        if fence:
            m = _FENCE.fullmatch(line)
            if m and m[1][0] == fence[0] and len(m[1]) >= len(fence) and not m[2].strip():
                fence = ""
            out.append((pos, line, True))
        elif close:
            if close in line.lower():
                close = ""
            out.append((pos, line, True))
        elif (m := _FENCE.fullmatch(line)) and not (m[1][0] == "`" and "`" in m[2]):
            fence = m[1]
            out.append((pos, line, True))
        elif line.lstrip(" ").startswith("<!--") and len(line) - len(line.lstrip(" ")) <= 3:
            if "-->" not in line.lstrip(" ")[4:]:
                close = "-->"
            out.append((pos, line, True))
        elif m := _RAW_OPEN.match(line):
            tag = f"</{m[1].lower()}"
            if tag not in line.lower()[m.end() :]:
                close = tag
            out.append((pos, line, True))
        else:
            out.append((pos, line, False))
        pos = end
    return out, pos, limit < len(text)


def _atx(line: str) -> tuple[int, str] | None:
    """``(level, raw title)`` of an ATX heading line, its closing ``#`` run stripped; else None."""
    m = _ATX.match(line)
    if not m or (m.end() != len(line) and m[2] is None):
        return None
    rest = (m[2] or "")[:_RAW_CHARS].rstrip(" \t")
    bare = rest.rstrip("#")
    if not bare.strip(" \t"):
        rest = ""  # only a closing run: an empty heading
    elif bare != rest and bare[-1] in " \t":
        rest = bare  # a closing run after a space
    return len(m[1]), rest.strip(" \t")


def _segment(title: str) -> str:
    return title.replace("\\", "\\\\").replace("/", "\\/").replace("~", "\\~")


def _slug(title: str) -> str:
    return _SLUG_DROP.sub("-", title.lower()).strip("-") or "heading"


def parse(text: str) -> Parsed:
    """The parse of ``text`` (memoised per content digest)."""
    key = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
    hit = _MEMO.get(key)
    if hit is not None:
        _MEMO.move_to_end(key)
        return hit
    _, body = front_matter(text)
    lines, parsed_end, truncated = _scan(text, body)
    raw: list[tuple[int, int, str]] = []  # (offset, level, visible title)
    for pos, line, hidden in lines:
        if not hidden and (h := _atx(line)):
            raw.append((pos, h[0], visible(h[1])[:MAX_TITLE_CHARS]))
    # section ends in one pass: a heading closes every open one of the same or a deeper level
    ends = [parsed_end] * len(raw)
    open_: list[int] = []
    for i, (pos, level, _) in enumerate(raw):
        while open_ and raw[open_[-1]][1] >= level:
            ends[open_.pop()] = pos
        open_.append(i)
    named = [i for i, r in enumerate(raw) if r[2]]
    h1 = [i for i in named if raw[i][1] == 1]
    doc_title = h1[0] if len(h1) == 1 and named and named[0] == h1[0] else None
    out: list[Heading] = []
    slugs: set[str] = set()
    paths: set[str] = set()
    slug_n: dict[str, int] = {}
    path_n: dict[str, int] = {}
    stack: list[tuple[int, str, str]] = []  # (level, path segment, slug) of the open ancestors
    for i, (pos, level, title) in enumerate(raw):
        while stack and stack[-1][0] >= level:
            stack.pop()
        if not title:
            continue
        ancestors = [s for s in stack if s[1] is not None]
        segment = _segment(title)
        path = "/".join([a[1] for a in ancestors] + [segment])
        if path in paths:
            path_n[path] = n = path_n.get(path, 1) + 1
            segment, path = f"{segment}~{n}", f"{path}~{n}"
        slug = _slug(title)
        if slug in slugs:
            parent = f"{stack[-1][2]}/{slug}" if stack else ""
            if parent and parent not in slugs:
                slug = parent
            else:
                base = parent or slug
                slug_n[base] = n = slug_n.get(base, 1) + 1
                slug = f"{base}~{n}"
        slugs.add(slug)
        paths.add(path)
        # the sole leading H1 is the document's title: it names no segment of the paths below
        stack.append((level, None if i == doc_title else segment, slug))  # type: ignore[arg-type]
        out.append(Heading(level, title, slug, path, pos, ends[i]))
    parsed = Parsed(tuple(out), body, parsed_end, truncated, _first_paragraph(lines))
    _remember(key, parsed)
    return parsed


def _remember(key: str, parsed: Parsed) -> None:
    """Memoise ``parsed`` within :data:`_MEMO_SIZE` entries and :data:`_MEMO_BYTES` bytes, oldest
    out first; a parse larger than the whole bound is not kept at all."""
    global _memo_bytes
    size = parsed.size
    if size > _MEMO_BYTES:
        return
    _MEMO[key] = parsed
    _memo_bytes += size
    while len(_MEMO) > _MEMO_SIZE or _memo_bytes > _MEMO_BYTES:
        _, old = _MEMO.popitem(last=False)
        _memo_bytes -= old.size


def memo_bytes() -> int:
    """Approximate bytes the parse memo holds now."""
    return _memo_bytes


def clear_memo() -> None:
    """Empty the parse memo (tests; a server never needs to)."""
    global _memo_bytes
    _MEMO.clear()
    _memo_bytes = 0


def headings(text: str) -> list[Heading]:
    """Every named ATX heading of ``text`` in document order (:func:`parse`)."""
    return list(parse(text).headings)


def find_section(hs: list[Heading] | tuple[Heading, ...], name: str) -> list[Heading]:
    """The headings ``name`` names exactly, by slug or by full heading path (never fuzzily).
    One is a match; none is unknown; two (a slug of one heading equal to another's path) is
    ambiguous."""
    return [h for h in hs if name in (h.slug, h.path)]


# --------------------------------------------------------------------------- summaries


def first_paragraph(text: str) -> str:
    """A derived summary: the first prose paragraph before the first H2 (a block that starts as
    a quote, a list, a table, HTML or an image is not prose); else the first after a
    ``## Context`` heading (an ADR's); else the first anywhere.  Reduced to visible text, made one
    line and :func:`cut`; ``""`` when the document has no prose.  Computed with the parse."""
    return parse(text).first_paragraph


def _first_paragraph(lines: list[tuple[int, str, bool]]) -> str:
    blocks: list[tuple[bool, bool, list[str]]] = []  # (before any H2, under Context, lines)
    h2_seen = context = False
    current: list[str] = []

    def flush():
        prose = current and not current[0].lstrip(" ").startswith(_NOT_PROSE)
        # only candidates are kept: the first block, and the first under Context
        if prose and (not blocks or (context and not any(b[1] for b in blocks))):
            blocks.append((not h2_seen, context, list(current)))
        current.clear()

    for _, line, hidden in lines:
        h = None if hidden else _atx(line)
        if hidden or h or not line.strip():
            flush()
            if blocks and blocks[0][0]:
                break  # prose before the first H2: nothing later can beat it
            if h and h[0] >= 2:
                h2_seen = True
            if h and h[0] <= 2:  # an H3 under Context stays under it
                context = h[0] == 2 and visible(h[1]).lower() == "context"
            continue
        current.append(line)
    flush()
    if not blocks:
        return ""
    pick = next((b for b in blocks if b[0]), None) or next((b for b in blocks if b[1]), blocks[0])
    raw, n = [], 0
    for ln in pick[2]:  # only what a summary can use is reduced to visible text
        raw.append(ln[: _RAW_CHARS - n])
        n += len(raw[-1]) + 1
        if n >= _RAW_CHARS:
            break
    return cut(visible(" ".join(raw)))


def _synthesized(content: str) -> str:
    """The summary of an indexer-built node (``<title>\\nid: ...\\nkind: ...\\n<attr>: <json>``,
    :func:`homelabnext.context.repo.documents_from_graph`): its first line, and when that is
    short (a bare name), its plain attributes."""
    import json

    lines = content.split("\n")
    head = clean(lines[0])
    if len(head) >= 40:
        return cut(head)
    extra = []
    for ln in lines[1:]:
        k, sep, v = ln.partition(": ")
        if not sep or k in ("id", "kind", "path", "declared_in"):
            continue
        try:
            val = json.loads(v)
        except ValueError:
            val = v
        if isinstance(val, list):
            val = ", ".join(str(x) for x in val)
        extra.append(f"{k} {val}")
    return cut(clean(head + (": " + "; ".join(extra) if extra else "")))


def is_synthesized(content: str, doc_id: str) -> bool:
    """True for content the indexer built from a node's attributes (its second line is
    ``id: <doc_id>``), not a file's text."""
    return bool(doc_id) and content.split("\n", 2)[1:2] == [f"id: {doc_id}"]


def summary_of(text: str, path: str, doc_id: str = "") -> tuple[str, str]:
    """``(summary, summary_source)``: the authored front-matter ``summary`` of a Markdown
    document; else its first paragraph; for an indexer-built node (``doc_id`` given) its
    synthesized line; else ``("", "none")``.  An authored summary that breaks
    :func:`check_summary` is not served as authored (the lints report it)."""
    if is_synthesized(text, doc_id):
        s = _synthesized(text)
        return (s, "synthesized") if s else ("", "none")
    if not is_markdown(path):
        return "", "none"
    front, _ = front_matter(text)
    authored = (front or {}).get("summary")
    if authored is not None and check_summary(authored) is None:
        return authored, "authored"
    para = first_paragraph(text)
    return (para, "first-paragraph") if para else ("", "none")


def check_summary(value: Any) -> str | None:
    """Why ``value`` is not a valid authored summary, or ``None``: a non-empty string, one line,
    no character of :data:`REFUSED_CATEGORIES`, at most :data:`MAX_SUMMARY_CHARS` characters, no
    surrounding whitespace."""
    if not isinstance(value, str) or not value.strip():
        return "summary must be a non-empty string"
    if (
        "\n" in value
        or "\r" in value
        or any(unicodedata.category(c) in ("Zl", "Zp") for c in value)
    ):
        return "summary must be a single line"
    if any(unicodedata.category(c) in REFUSED_CATEGORIES for c in value):
        return "summary may not contain control or invisible formatting characters"
    if len(value) > MAX_SUMMARY_CHARS:
        return f"summary is {len(value)} characters (at most {MAX_SUMMARY_CHARS})"
    if value != value.strip():
        return "summary may not start or end with whitespace"
    return None
