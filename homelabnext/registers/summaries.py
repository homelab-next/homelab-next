# SPDX-License-Identifier: Apache-2.0
"""``hnx registers summaries``: the level-0 lint of authored Markdown (ADR-0032).

A lesson, a runbook or a docs page carries a front-matter ``summary:`` -- one reviewed line of
at most 160 characters that ``context_for`` serves instead of the content.  This lint **fails**
on:

* a record or page **without** a summary (authored, or generated and marked
  ``summary_generated: true``);
* a summary that breaks :func:`homelabnext.context.levels.check_summary` (too long, multi-line, a
  control or invisible formatting character, empty);
* an **authored page summary that may be stale**: it must carry ``summary_of: <digest>``, the
  :func:`~homelabnext.context.levels.outline_digest` of the page's heading outline when the
  summary was last reread.  A missing ``summary_of``, or a digest that no longer matches, fails
  with the page named; reread the summary, then ``summaries --restamp PATH``.  Edits to body text
  that change no heading do not trigger it.

Exempt from ``summary_of``: a **generated** summary (its generator's ``--check`` keeps it current)
and **register records** (lessons, runbooks: a record is structured fields, not a heading outline,
its summary is inside the record's review digest, and any change to the record already
invalidates its reviews, so a second staleness stamp would add nothing).

``--restamp PATH...`` rewrites only the ``summary_of`` line of each named authored page (a
targeted line edit, validated by re-parsing; idempotent); there is deliberately no restamp
without paths, since restamping should follow a reread.  ``--restamp-all`` is for a migration only.

A path is a register directory (one holding ``lessons/`` or ``runbooks/``: their ``*.md``
records are checked) or any other directory (every ``*.md`` page under it, ``_``-prefixed
templates left out) or a single ``.md`` file.  Output is deterministic: sorted paths, one line
per problem, then the counts.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["RECORD_DIRS", "RestampError", "SummaryReport", "lint_summaries", "restamp"]

#: the register subdirectories whose records the lint reads
RECORD_DIRS = ("lessons", "runbooks")


@dataclass
class SummaryReport:
    """What the lint found; ``problems`` (a missing summary is one) fail it."""

    records: int = 0
    pages: int = 0
    missing_records: list[str] = field(default_factory=list)
    missing_pages: list[str] = field(default_factory=list)
    #: pages whose summary a generator derived (``summary_generated: true``): they have one, but
    #: no person wrote or reviewed it, so they are counted apart from the authored ones
    generated_pages: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    #: things worth fixing that do not fail the lint (a ``summary_generated`` that is not a bool)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def lines(self, missing: bool = False) -> list[str]:
        """One line per problem, then the counts.  ``missing`` is kept for old callers: a missing
        summary is a problem (a ``FAIL`` line) now."""
        out = [f"FAIL {p}" for p in self.problems] + [f"WARN {w}" for w in self.warnings]
        out.append(
            f"summaries: {self.records} record(s), {len(self.missing_records)} without a summary; "
            f"{self.pages} page(s), {len(self.missing_pages)} without a summary, "
            f"{len(self.generated_pages)} with a generated one"
        )
        return out


def _files(path: Path) -> list[tuple[Path, bool]]:
    """``(file, is_record)`` for every Markdown file ``path`` names, sorted."""
    if path.is_file():
        return [(path, path.parent.name in RECORD_DIRS)]
    subs = [path / d for d in RECORD_DIRS if (path / d).is_dir()]
    if subs:
        return [(f, True) for d in subs for f in sorted(d.glob("*.md"))]
    return [(f, False) for f in sorted(path.rglob("*.md")) if not f.name.startswith("_")]


def lint_summaries(paths: Iterable[str | Path], root: str | Path | None = None) -> SummaryReport:
    """Check the summary of every record and page under ``paths`` (shown relative to ``root``,
    default the current directory)."""
    from homelabnext.context.levels import (
        GENERATED_KEY,
        OUTLINE_KEY,
        check_summary,
        front_matter,
        outline_digest,
    )

    base = Path(root or ".").resolve()
    rep = SummaryReport()
    seen: set[Path] = set()
    for raw in paths:
        for f, is_record in _files(Path(raw)):
            full = f.resolve()
            if full in seen:
                continue
            seen.add(full)
            shown = full.relative_to(base).as_posix() if full.is_relative_to(base) else str(f)
            text = f.read_text(encoding="utf-8", errors="replace")
            front, _ = front_matter(text)
            if is_record:
                rep.records += 1
            else:
                rep.pages += 1
            if not front or "summary" not in front:
                (rep.missing_records if is_record else rep.missing_pages).append(shown)
                rep.problems.append(
                    f"{shown}: no front-matter summary (add a one-line `summary:`, at most 160 "
                    "characters)"
                )
                continue
            why = check_summary(front["summary"])
            if why:
                rep.problems.append(f"{shown}: {why}")
            elif front.get(GENERATED_KEY) is True:
                rep.generated_pages.append(shown)
            elif not is_record:
                have, want = front.get(OUTLINE_KEY), outline_digest(text)
                if have != want:
                    state = (
                        f"has no {OUTLINE_KEY}"
                        if OUTLINE_KEY not in front
                        else f"is stale: {OUTLINE_KEY} {have!r} is not the outline {want}"
                    )
                    rep.problems.append(
                        f"{shown}: the summary {state}; reread the summary, then run "
                        f"`python3 -m homelabnext.registers summaries --restamp {shown}`"
                    )
            if GENERATED_KEY in front and not isinstance(front[GENERATED_KEY], bool):
                rep.warnings.append(
                    f"{shown}: {GENERATED_KEY} must be the boolean true or false, not "
                    f"{front[GENERATED_KEY]!r}: the summary is read as authored"
                )
    return rep


class RestampError(ValueError):
    """A page cannot be restamped (named in the message); nothing was written."""


_KEY_LINE = re.compile(r"[^\s#-][^:]*:(?:\s|$)|\"[^\"]*\":|'[^']*':")


def _is_key_line(line: str) -> bool:
    """True for a top-level front-matter key line (not indented, not a comment or list item)."""
    return bool(_KEY_LINE.match(line))


def _stamped(text: str, digest: str) -> str:
    """``text`` with the front matter's ``summary_of`` set to ``digest`` by a line edit: an
    existing key's line(s) are replaced, else a new line follows the ``summary`` entry.  Every
    other byte, line ending included, is kept."""
    from homelabnext.context.levels import _FRONT, OUTLINE_KEY

    m = _FRONT.match(text, 1 if text.startswith("\ufeff") else 0)
    if not m or m["fm"] is None:
        raise RestampError("no front matter")
    start, end = m.span("fm")
    block = text[start:end]
    eol = "\r\n" if "\r\n" in block else "\n"
    lines = block.split(eol)
    new = f"{OUTLINE_KEY}: {digest}"

    def span(key: str) -> tuple[int, int] | None:
        """``[first, after)`` line indexes of the top-level ``key`` entry, continuation lines
        (indented or blank) included."""
        for i, ln in enumerate(lines):
            if ln.startswith(key + ":"):
                j = i + 1
                while (
                    j < len(lines) and not _is_key_line(lines[j]) and not lines[j].startswith("---")
                ):
                    j += 1
                return i, j
        return None

    have = span(OUTLINE_KEY)
    if have:
        lines[have[0] : have[1]] = [new]
    else:
        at = span("summary")
        if not at:
            raise RestampError("no top-level `summary:` line to stamp after")
        # insert after the summary's own lines, not after trailing comments/blank lines
        lines.insert(at[1], new)
    return text[:start] + eol.join(lines) + text[end:]


def restamp(path: str | Path) -> bool:
    """Set ``summary_of`` of the page at ``path`` to the digest of its current heading outline.
    Returns True when the file changed, False when it already held that digest.  Refuses (raises
    :class:`RestampError`, writes nothing) a path that is not a ``.md`` page, a register record, a
    page without an authored summary (none, generated, or malformed), or an edit that does not
    re-parse to the same front matter plus ``summary_of``."""
    from homelabnext.context.levels import (
        GENERATED_KEY,
        OUTLINE_KEY,
        check_summary,
        front_matter,
        outline_digest,
    )

    p = Path(path)
    if p.suffix != ".md" or not p.is_file():
        raise RestampError(f"{path}: not a Markdown page")
    if p.parent.name in RECORD_DIRS:
        raise RestampError(f"{path}: a register record has no summary_of (it is exempt)")
    with open(p, encoding="utf-8", newline="") as fh:
        text = fh.read()
    front, _ = front_matter(text)
    if not front or "summary" not in front:
        raise RestampError(f"{path}: no summary to stamp")
    if front.get(GENERATED_KEY) is True:
        raise RestampError(f"{path}: the summary is generated (summary_generated: true), exempt")
    why = check_summary(front["summary"])
    if why:
        raise RestampError(f"{path}: {why}; fix the summary first")
    digest = outline_digest(text)
    try:
        out = _stamped(text, digest)
    except RestampError as ex:
        raise RestampError(f"{path}: {ex}") from None
    after, _ = front_matter(out)
    expect = {**front, OUTLINE_KEY: digest}
    if after != expect or list(after) != _order(front, OUTLINE_KEY):
        raise RestampError(f"{path}: the line edit would change other front matter; edit by hand")
    if out == text:
        return False
    with open(p, "w", encoding="utf-8", newline="") as fh:
        fh.write(out)
    return True


def _order(front: dict, key: str) -> list[str]:
    """The key order a restamp leaves: the existing order, with a new ``key`` after ``summary``."""
    keys = list(front)
    if key not in keys:
        keys.insert(keys.index("summary") + 1, key)
    return keys
