# SPDX-License-Identifier: Apache-2.0
"""``hnx docs index generate|check [FILE...]``: the descriptions in a docs index (``docs/README.md``,
and the "One line" column of ``docs/adr/README.md``) come from the linked pages' front-matter
``summary:`` (ADR-0032), so an index cannot drift from its pages.

The sections, headings, order, grouping and links of the index are authored.  The description
after a link is a generated span, the same ``hnx:gen`` comment family the system pages use,
written on one line::

    - [MCP server](mcp.md) ([[mcp]]): <!-- hnx:gen:summary:mcp.md -->the summary<!-- /hnx:gen -->
    | [0001](0001-slug.md) | slug | <!-- hnx:gen:summary:0001-slug.md -->the summary<!-- /hnx:gen --> |

``generate`` rewrites only the text between each marker pair, from the target page's summary
(path relative to the index file's directory); everything outside a span is left byte for byte.
``check`` exits 1 when a span is stale or its target is missing or has no usable summary, when any
``hnx:gen`` marker is malformed or unmatched (no space before ``-->``, an open marker with no
close on its line, a stray close), when a list entry that starts ``- [`` or a table row whose first
cell is a link names a page and has no span or a span for a different page, when a span in a table
row holds a ``|`` (it would split the row), and when a top-level page of the directory is not
listed.
Text after a closing marker (a status note such as "proposed (ADR-0031)") is authored and kept.
Line endings are preserved and the file is replaced atomically.  Markers render as nothing on
GitHub and in Obsidian.
"""

from __future__ import annotations

import re
from pathlib import Path

from homelabnext.registers.summaries import atomic_write_text, read_text_exact

__all__ = ["SPAN", "check", "generate", "refresh"]

_LIST_LINK = re.compile(r"- \[[^\]]*\]\((?P<target>[^)\s#]+\.md)(?:#[^)\s]*)?\)")
_ROW_LINK = re.compile(r"\| *\[[^\]]*\]\((?P<target>[^)\s#]+\.md)(?:#[^)\s]*)?\) *\|")
_ANY_MARKER = re.compile(r"hnx:gen")

SPAN = re.compile(
    r"(?P<open><!-- hnx:gen:summary:(?P<path>[^\s>]+) -->)(?P<body>[^\n]*?)(?P<close><!-- /hnx:gen -->)"
)


def _summary(base: Path, rel: str) -> tuple[str | None, str | None]:
    """``(summary, problem)`` for the page ``rel`` under ``base``."""
    from homelabnext.context.levels import check_summary, front_matter

    target = (base / rel).resolve()
    if not target.is_relative_to(base.resolve()) or target.suffix != ".md":
        return None, f"{rel}: not a Markdown page under {base.name}/"
    if not target.is_file():
        return None, f"{rel}: no such page"
    front, _ = front_matter(target.read_text(encoding="utf-8", errors="replace"))
    value = (front or {}).get("summary")
    if value is None:
        return None, f"{rel}: the page has no summary"
    why = check_summary(value)
    if why:
        return None, f"{rel}: {why}"
    if "<!--" in value or "-->" in value:
        return None, f"{rel}: the summary holds an HTML comment marker"
    return value, None


def refresh(text: str, base: Path) -> tuple[str, list[str], list[str]]:
    """``(new text, stale paths, problems)``: ``text`` with every span set to its page's summary."""
    stale: list[str] = []
    problems: list[str] = []

    def one(m: re.Match[str]) -> str:
        summary, problem = _summary(base, m["path"])
        if problem:
            problems.append(problem)
            return m[0]
        if m["body"] != summary:
            stale.append(m["path"])
        return f"{m['open']}{summary}{m['close']}"

    return SPAN.sub(one, text), stale, problems


def generate(index: Path) -> tuple[bool, list[str]]:
    """Rewrite the spans of ``index``.  ``(changed, problems)``; with a problem nothing is written."""
    text = read_text_exact(index)
    new, _, problems = refresh(text, index.parent)
    if problems or new == text:
        return False, problems
    atomic_write_text(index, new)
    return True, problems


def _marker_problems(text: str, index: Path) -> list[str]:
    """Malformed or unmatched markers, and list entries without (or with the wrong) span."""
    out: list[str] = []
    listed = set()
    for n, line in enumerate(text.split("\n"), 1):
        line = line.rstrip("\r")
        spans = list(SPAN.finditer(line))
        listed.update(m["path"] for m in spans)
        rest = SPAN.sub("", line)
        if _ANY_MARKER.search(rest):
            out.append(
                f"{index.name}:{n}: malformed or unmatched hnx:gen marker (expected "
                "`<!-- hnx:gen:summary:PATH -->text<!-- /hnx:gen -->` on one line)"
            )
        row = _ROW_LINK.match(line)
        if row and any("|" in s["body"] for s in spans):
            out.append(
                f"{index.name}:{n}: a summary in a table row holds `|`, which splits the row"
            )
        if m := _LIST_LINK.match(line) or row:
            if not spans:
                out.append(f"{index.name}:{n}: entry links {m['target']} but has no summary span")
            elif spans[0]["path"] != m["target"]:
                out.append(
                    f"{index.name}:{n}: entry links {m['target']} but its span is for "
                    f"{spans[0]['path']}"
                )
    for page in sorted(index.parent.glob("*.md")):
        if page.name != index.name and not page.name.startswith("_") and page.name not in listed:
            out.append(f"{page.name}: page is not listed in {index.name}")
    return out


def check(index: Path) -> list[str]:
    """One line per stale span or unusable target of ``index``; empty when it is current."""
    text = read_text_exact(index)
    _, stale, problems = refresh(text, index.parent)
    if not SPAN.search(text):
        problems.append(f"{index.name}: no generated summary span at all")
    return [f"stale: {p}" for p in stale] + problems + _marker_problems(text, index)
