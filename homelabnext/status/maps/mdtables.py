# SPDX-License-Identifier: Apache-2.0
"""A small reader of GitHub-flavoured Markdown pipe tables (the roadmap's source of truth).

Only what ``docs/build-order.md`` and ``docs/checklist.md`` use: a header row, a delimiter row
(``|---|:--:|``), body rows until the first line that is not a row.  A cell may hold ``\\|`` (an
escaped pipe) and a code span with pipes inside it.  Tables inside fenced code blocks are not
tables.  Each table carries the heading path it sits under, so a caller can tell the PUBLIC-NOW
phase table from the SERVER one without a copy of either.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_DELIM = re.compile(r"^\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")


@dataclass(frozen=True)
class Table:
    headings: tuple[str, ...]  # the heading path, outermost first
    header: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    line: int  # 1-based line of the header row

    @property
    def heading(self) -> str:
        return self.headings[-1] if self.headings else ""

    def records(self) -> list[dict[str, str]]:
        """Each row as ``{header: cell}``."""
        return [dict(zip(self.header, r, strict=True)) for r in self.rows]


def split_row(line: str) -> list[str]:
    """The cells of one table row, stripped; ``\\|`` and pipes inside a code span are text."""
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    cells, cur, i, tick = [], [], 0, 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] == "|":
            cur.append("|")
            i += 2
            continue
        if c == "`":
            n = len(s[i:]) - len(s[i:].lstrip("`"))
            tick = 0 if tick == n else (tick or n)
            cur.append(s[i : i + n])
            i += n
            continue
        if c == "|" and not tick:
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    tail = "".join(cur).strip()
    if tail or not s.rstrip().endswith("|"):
        cells.append(tail)
    return cells


def _is_row(line: str) -> bool:
    return line.lstrip().startswith("|")


def parse_tables(text: str) -> list[Table]:
    """Every pipe table in ``text``, in order.  Short rows are padded with empty cells and long
    rows cut to the header's width, so ``records()`` always has every column."""
    lines = text.splitlines()
    out: list[Table] = []
    path: list[tuple[int, str]] = []
    fenced = False
    i = 0
    while i < len(lines):
        line = lines[i]
        if _FENCE.match(line):
            fenced = not fenced
            i += 1
            continue
        if fenced:
            i += 1
            continue
        m = _HEADING.match(line)
        if m:
            level = len(m.group(1))
            path = [(lv, t) for lv, t in path if lv < level] + [(level, m.group(2))]
            i += 1
            continue
        if _is_row(line) and i + 1 < len(lines) and _DELIM.match(lines[i + 1].strip()):
            header = split_row(line)
            rows = []
            j = i + 2
            while j < len(lines) and _is_row(lines[j]):
                cells = split_row(lines[j])
                cells = (cells + [""] * len(header))[: len(header)]
                rows.append(tuple(cells))
                j += 1
            out.append(Table(tuple(t for _, t in path), tuple(header), tuple(rows), i + 1))
            i = j
            continue
        i += 1
    return out
