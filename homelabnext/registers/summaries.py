# SPDX-License-Identifier: Apache-2.0
"""``hnx registers summaries``: the level-0 lint of authored Markdown (ADR-0032).

A lesson, a runbook or a docs page may carry a front-matter ``summary:`` -- one reviewed line of
at most 160 characters that ``context_for`` serves instead of the content.  This lint holds
every summary present to that rule (:func:`homelabnext.context.levels.check_summary`: too long,
multi-line, a control or invisible formatting character, empty) and **fails** on a broken one; a
record or page without a summary is only **counted, as a warning**, while the practice is new
(``--missing`` lists them).  The record validation
(:mod:`.schema`) refuses a malformed summary too, so a broken one cannot reach a render either.

A path is a register directory (one holding ``lessons/`` or ``runbooks/``: their ``*.md``
records are checked) or any other directory (every ``*.md`` page under it, ``_``-prefixed
templates left out) or a single ``.md`` file.  Output is deterministic: sorted paths, one line
per problem, then the counts.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["RECORD_DIRS", "SummaryReport", "lint_summaries"]

#: the register subdirectories whose records the lint reads
RECORD_DIRS = ("lessons", "runbooks")


@dataclass
class SummaryReport:
    """What the lint found; ``problems`` fail it, ``missing_*`` only warn."""

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
        """One line per problem, ``missing:`` lines when asked, then the counts."""
        out = [f"FAIL {p}" for p in self.problems] + [f"WARN {w}" for w in self.warnings]
        if missing:
            out += [f"missing {p}" for p in self.missing_records + self.missing_pages]
        out.append(
            f"summaries: {self.records} record(s), {len(self.missing_records)} without a summary; "
            f"{self.pages} page(s), {len(self.missing_pages)} without a summary, "
            f"{len(self.generated_pages)} with a generated one"
            + (" (WARNING: a missing summary is not a failure yet)" if self._missing else "")
        )
        return out

    @property
    def _missing(self) -> int:
        return len(self.missing_records) + len(self.missing_pages)


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
    from homelabnext.context.levels import GENERATED_KEY, check_summary, front_matter

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
            front, _ = front_matter(f.read_text(encoding="utf-8", errors="replace"))
            if is_record:
                rep.records += 1
            else:
                rep.pages += 1
            if not front or "summary" not in front:
                (rep.missing_records if is_record else rep.missing_pages).append(shown)
                continue
            why = check_summary(front["summary"])
            if why:
                rep.problems.append(f"{shown}: {why}")
            elif front.get(GENERATED_KEY) is True:
                rep.generated_pages.append(shown)
            if GENERATED_KEY in front and not isinstance(front[GENERATED_KEY], bool):
                rep.warnings.append(
                    f"{shown}: {GENERATED_KEY} must be the boolean true or false, not "
                    f"{front[GENERATED_KEY]!r}: the summary is read as authored"
                )
    return rep
