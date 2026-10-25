# SPDX-License-Identifier: Apache-2.0
"""``hnx docs index generate|check [FILE]``: the descriptions in ``docs/README.md`` come from the
linked pages' front-matter ``summary:`` (ADR-0032), so the index cannot drift from the pages.

The sections, headings, order, grouping and links of the index are authored.  The description
after a link is a generated span, the same ``hnx:gen`` comment family the system pages use,
written on one line::

    - [MCP server](mcp.md) ([[mcp]]): <!-- hnx:gen:summary:mcp.md -->the summary<!-- /hnx:gen -->

``generate`` rewrites only the text between each marker pair, from the target page's summary
(path relative to the index file's directory); everything outside a span is left byte for byte.
``check`` exits 1 when a span is stale or its target is missing or has no usable summary.
Markers render as nothing on GitHub and in Obsidian.
"""

from __future__ import annotations

import re
from pathlib import Path

__all__ = ["SPAN", "check", "generate", "refresh"]

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
    text = index.read_text(encoding="utf-8")
    new, _, problems = refresh(text, index.parent)
    if problems or new == text:
        return False, problems
    index.write_text(new, encoding="utf-8")
    return True, problems


def check(index: Path) -> list[str]:
    """One line per stale span or unusable target of ``index``; empty when it is current."""
    text = index.read_text(encoding="utf-8")
    _, stale, problems = refresh(text, index.parent)
    if not SPAN.search(text):
        problems.append(f"{index.name}: no generated summary span at all")
    return [f"stale: {p}" for p in stale] + problems
