# SPDX-License-Identifier: Apache-2.0
"""Authored Markdown served in levels: a summary, an outline, one section (ADR-0032).

A context document is read in three levels, so a caller pays only for what it opens:

* **L0, the summary.**  The front-matter ``summary:`` an author wrote and a review covered
  (``summary_source: authored``); without one, the document's first paragraph, collapsed to one
  line and cut to :data:`MAX_SUMMARY_CHARS` (``first-paragraph``); else nothing (``none``).  No
  model writes a summary: what is served is what git holds.
* **L1, the outline.**  The ATX headings (``#`` to ``######``) with their level, title, a slug,
  the heading path (``Decision/Consequences``) and the size of the section each opens.
* **L2, one section.**  A heading's own line and everything up to the next heading of the same or
  a higher level (its subsections included), named by its slug or its full heading path.

Parsing is deliberately small and deterministic (same text, same answer; no dependency beyond
PyYAML):

* A YAML front-matter block (``---`` on the first line to the next ``---`` line) is never a
  heading or a paragraph; a block that does not parse gives no ``summary`` but is still skipped.
* Fenced code (`````` ``` `````` or ``~~~``, at most three spaces of indent, closed by a fence of
  the same character at least as long; an unclosed fence runs to the end) holds no heading and no
  paragraph.  An indented line (four spaces or more) is never a heading, as in CommonMark.
* **Setext headings** (a line underlined with ``===`` or ``---``) **are not headings here**:
  their text is ordinary paragraph text.  The repository writes ATX headings only, and an
  underline is easy to misread (a ``---`` under a paragraph is also a thematic break).
* A slug is the title lower-cased, every run of characters other than letters, digits, ``_``
  and ``-`` replaced by one ``-``, trimmed of ``-`` (``heading`` when nothing is left).  A slug
  already taken earlier in the document gets ``-2``, ``-3`` ... (the first free one), so slugs
  are unique in document order.  A heading path is the titles from the top level down joined by
  ``/`` (a ``/`` inside a title is written ``\\/``); a path already taken gets `` (2)``,
  `` (3)`` ... on its last segment, and its subsections inherit that segment, so paths are
  unique too.

:func:`check_summary` is the authoring rule the register validation, the schemas and
``hnx registers summaries`` share: a summary is one line of at most :data:`MAX_SUMMARY_CHARS`
characters with no control character.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

__all__ = [
    "MAX_SUMMARY_CHARS",
    "SUMMARY_SOURCES",
    "Heading",
    "check_summary",
    "find_section",
    "first_paragraph",
    "front_matter",
    "headings",
    "is_markdown",
    "summary_of",
]

#: the longest summary, authored or derived
MAX_SUMMARY_CHARS = 160
#: where a served summary came from
SUMMARY_SOURCES = ("authored", "first-paragraph", "none")

_FRONT = re.compile(r"\A---[ \t]*\r?\n(?:(?P<fm>.*?)\r?\n)?---[ \t]*(?:\r?\n|\Z)", re.DOTALL)
_ATX = re.compile(r"^ {0,3}(?P<hashes>#{1,6})(?:[ \t]+(?P<title>.*?))?(?:[ \t]+#+)?[ \t]*$")
_FENCE = re.compile(r"^ {0,3}(?P<fence>`{3,}|~{3,})(?P<info>.*)$")
_COMMENT = re.compile(r"^\s*<!--.*-->\s*$")
_SLUG_DROP = re.compile(r"[^\w-]+")


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


def is_markdown(path: str) -> bool:
    """Levels apply to Markdown sources only: a ``#`` line in a script is a comment."""
    return path.lower().endswith(".md")


def front_matter(text: str) -> tuple[dict[str, Any] | None, int]:
    """``(mapping or None, offset where the body starts)``.  No block: ``(None, 0)``; a block
    that is not a YAML mapping: ``(None, its end)`` (it is still not body text)."""
    m = _FRONT.match(text)
    if not m:
        return None, 0
    import yaml

    from homelabnext._yaml import UniqueKeyStrDateLoader

    try:
        data = yaml.load(m["fm"] or "", Loader=UniqueKeyStrDateLoader)  # a safe loader
    except yaml.YAMLError:
        data = None
    return (data if isinstance(data, dict) else None), m.end()


def _lines(text: str, start: int) -> list[tuple[int, str, bool]]:
    """``(offset, line without its newline, inside fenced code)`` for every body line."""
    out: list[tuple[int, str, bool]] = []
    fence = ""
    pos = start
    for raw in text[start:].splitlines(keepends=True):
        line = raw.rstrip("\r\n")
        m = _FENCE.match(line)
        if fence:
            closing = (
                m is not None
                and m["fence"][0] == fence[0]
                and len(m["fence"]) >= len(fence)
                and not m["info"].strip()
            )
            out.append((pos, line, True))
            if closing:
                fence = ""
        elif m is not None and not (m["fence"][0] == "`" and "`" in m["info"]):
            fence = m["fence"]
            out.append((pos, line, True))
        else:
            out.append((pos, line, False))
        pos += len(raw)
    return out


def _slug(title: str) -> str:
    return _SLUG_DROP.sub("-", title.lower()).strip("-") or "heading"


def _unique(base: str, taken: set[str], fmt: str) -> str:
    if base not in taken:
        return base
    n = 2
    while fmt.format(base, n) in taken:
        n += 1
    return fmt.format(base, n)


def headings(text: str) -> list[Heading]:
    """Every ATX heading outside front-matter and fenced code, in document order, with a unique
    slug, a unique heading path and the extent of its section.  An empty heading (``#`` alone)
    has no title to name it by and is not listed (it still ends the section before it)."""
    _, body = front_matter(text)
    found: list[tuple[int, int, str]] = []  # (offset, level, title)
    for pos, line, fenced in _lines(text, body):
        if fenced:
            continue
        m = _ATX.match(line)
        if m:
            found.append((pos, len(m["hashes"]), (m["title"] or "").strip()))
    out: list[Heading] = []
    slugs: set[str] = set()
    paths: set[str] = set()
    stack: list[tuple[int, str]] = []  # (level, path segment) of the open ancestors
    for i, (pos, level, title) in enumerate(found):
        end = next((p for p, lv, _ in found[i + 1 :] if lv <= level), len(text))
        while stack and stack[-1][0] >= level:
            stack.pop()
        if not title:
            continue
        segment = title.replace("/", "\\/")
        path = "/".join([s for _, s in stack] + [segment])
        if path in paths:
            n = 2
            while f"{path} ({n})" in paths:
                n += 1
            segment, path = f"{segment} ({n})", f"{path} ({n})"
        slug = _unique(_slug(title), slugs, "{}-{}")
        slugs.add(slug)
        paths.add(path)
        stack.append((level, segment))
        out.append(Heading(level, title, slug, path, pos, end))
    return out


def find_section(hs: list[Heading], name: str) -> list[Heading]:
    """The headings ``name`` names exactly, by slug or by full heading path (never fuzzily).
    One is a match; none is unknown; two (a slug of one heading equal to another's path) is
    ambiguous."""
    return [h for h in hs if name in (h.slug, h.path)]


def _one_line(text: str) -> str:
    """Whitespace collapsed; cut at a word to at most :data:`MAX_SUMMARY_CHARS`, ``...`` marking
    the cut."""
    flat = " ".join(text.split())
    if len(flat) <= MAX_SUMMARY_CHARS:
        return flat
    room = MAX_SUMMARY_CHARS - 3
    cut = flat[: room + 1].rsplit(" ", 1)[0] if " " in flat[: room + 1] else flat[:room]
    return cut[:room].rstrip() + "..."


def first_paragraph(text: str) -> str:
    """The first block of consecutive text lines after the front-matter, ignoring headings,
    fenced code and single-line HTML comments (the SPDX line), as one line; ``""`` when none."""
    _, body = front_matter(text)
    block: list[str] = []
    for _, line, fenced in _lines(text, body):
        if fenced or _ATX.match(line) or not line.strip() or _COMMENT.match(line):
            if block:
                break
            continue
        block.append(line)
    return _one_line(" ".join(block)) if block else ""


def summary_of(text: str, path: str) -> tuple[str, str]:
    """``(summary, summary_source)`` of a document: the authored front-matter ``summary``, else
    its first paragraph, else ``("", "none")``.  A non-Markdown source has no levels and gives
    ``("", "none")``.  An authored summary that breaks :func:`check_summary` is not served as
    authored (the lints report it); the first paragraph stands in."""
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
    no control character, at most :data:`MAX_SUMMARY_CHARS` characters, no surrounding space."""
    if not isinstance(value, str) or not value.strip():
        return "summary must be a non-empty string"
    if "\n" in value or "\r" in value:
        return "summary must be a single line"
    if any(not c.isprintable() for c in value):
        return "summary may not contain control characters"
    if len(value) > MAX_SUMMARY_CHARS:
        return f"summary is {len(value)} characters (at most {MAX_SUMMARY_CHARS})"
    if value != value.strip():
        return "summary may not start or end with whitespace"
    return None
