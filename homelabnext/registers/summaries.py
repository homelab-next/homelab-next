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

import contextlib
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "RECORD_DIRS",
    "RestampError",
    "SummaryReport",
    "atomic_write_text",
    "lint_summaries",
    "plan_restamp",
    "restamp",
    "restamp_many",
]

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

    def lines(self) -> list[str]:
        """One line per problem (a missing summary is one), then the counts."""
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
            bad = None if front is not None else _front_error(text)
            if bad:
                (rep.missing_records if is_record else rep.missing_pages).append(shown)
                rep.problems.append(f"{shown}: {bad}")
                continue
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


def atomic_write_text(path: Path, text: str) -> None:
    """Replace ``path`` with ``text`` (no newline translation) through a temp file in the same
    directory and :func:`os.replace`; the temp file is created exclusively and never follows a
    link, and the old mode is kept."""
    mode = os.stat(path).st_mode & 0o7777
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def read_text_exact(path: Path) -> str:
    """The text of the regular file ``path`` with no newline translation, never following a final
    symbolic link."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, encoding="utf-8", newline="") as fh:
        return fh.read()


def _checked_page(path: str | Path) -> Path:
    """The page at ``path`` if it may be restamped, else :class:`RestampError`: a regular
    ``.md`` file, reached through no symbolic link (below the working directory) and no ``..``
    component, and not a register record (a file in a ``lessons``/``runbooks`` directory)."""
    raw = Path(path)
    if ".." in raw.parts:
        raise RestampError(f"{path}: a path with `..` is refused; name the page directly")
    absolute = Path(os.path.abspath(raw))
    cwd = Path(os.path.abspath(os.getcwd()))
    node = absolute
    while node != node.parent:
        if node.is_symlink() and not cwd.is_relative_to(node):
            raise RestampError(f"{path}: {node} is a symbolic link; restamp the page itself")
        node = node.parent
    if absolute.suffix != ".md" or not absolute.is_file():
        raise RestampError(f"{path}: not a regular Markdown page")
    real = absolute.resolve()
    if real.parent.name in RECORD_DIRS or absolute.parent.name in RECORD_DIRS:
        raise RestampError(f"{path}: a register record has no summary_of (it is exempt)")
    return absolute


def _key_pattern(key: str) -> re.Pattern[str]:
    return re.compile(rf"""(["']?){re.escape(key)}\1[ \t]*:(?:[ \t]|$)""")


def _stamped(text: str, digest: str) -> str:
    """``text`` with the front matter's ``summary_of`` set to ``digest`` by a line edit: an
    existing key's line(s) are replaced, else a new line follows the ``summary`` entry.  Every
    other byte, line ending included, is kept.  An entry is its key line plus the indented lines
    after it; a blank line, a comment or the next key ends it, so a comment after ``summary_of``
    survives."""
    from homelabnext.context.levels import _FRONT, OUTLINE_KEY

    m = _FRONT.match(text, 1 if text.startswith("\ufeff") else 0)
    if not m or m["fm"] is None:
        raise RestampError("no front matter")
    start, end = m.span("fm")
    eol = "\r\n" if "\r\n" in m[0] else "\n"
    lines = text[start:end].split(eol)
    new = f"{OUTLINE_KEY}: {digest}"

    def span(key: str) -> tuple[int, int] | None:
        """``[first, after)`` line indexes of the top-level ``key`` entry."""
        pat = _key_pattern(key)
        for i, ln in enumerate(lines):
            if pat.match(ln):
                j = i + 1
                while j < len(lines) and lines[j][:1] in (" ", "\t") and lines[j].strip():
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
        lines.insert(at[1], new)
    return text[:start] + eol.join(lines) + text[end:]


def plan_restamp(path: str | Path) -> tuple[Path, str, str]:
    """``(page, old text, new text)`` for restamping ``path``, nothing written.  Refuses (raises
    :class:`RestampError`) a path that is a symbolic link or not a regular ``.md`` file, a
    register record, a page without an authored summary (none, generated, or malformed), a page
    whose front matter does not parse, or an edit that does not re-parse to the same front matter
    plus ``summary_of``."""
    from homelabnext.context.levels import (
        GENERATED_KEY,
        OUTLINE_KEY,
        check_summary,
        front_matter,
        outline_digest,
    )

    p = _checked_page(path)
    text = read_text_exact(p)
    front, _ = front_matter(text)
    if front is None:
        bad = _front_error(text)
        raise RestampError(f"{path}: {bad or 'no front matter, so no summary to stamp'}")
    if "summary" not in front:
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
        raise RestampError(f"{path}: {ex}; edit the front matter by hand") from None
    after, _ = front_matter(out)
    expect = {**front, OUTLINE_KEY: digest}
    if after != expect or list(after) != _order(front, OUTLINE_KEY):
        raise RestampError(f"{path}: the line edit would change other front matter; edit by hand")
    return p, text, out


def restamp_many(paths: Iterable[str | Path]) -> list[tuple[Path, bool]]:
    """Restamp every page of ``paths`` or none: each target is planned (and so validated) before
    the first is written.  ``(page, changed)`` per path, in order."""
    plans = [plan_restamp(p) for p in paths]
    done = []
    for p, old, new in plans:
        if new != old:
            atomic_write_text(p, new)
        done.append((p, new != old))
    return done


def restamp(path: str | Path) -> bool:
    """Set ``summary_of`` of the page at ``path`` to the digest of its current heading outline.
    True when the file changed, False when it already held that digest (:func:`plan_restamp`
    lists the refusals)."""
    return restamp_many([path])[0][1]


def _front_error(text: str) -> str | None:
    """Why the front-matter block of ``text`` is not a YAML mapping (a duplicate key, a syntax
    error), or None when there is no block or it parses."""
    import yaml

    from homelabnext._yaml import UniqueKeyStrDateLoader
    from homelabnext.context.levels import _FRONT, MAX_FRONT_CHARS

    m = _FRONT.match(text, 1 if text.startswith("\ufeff") else 0)
    if not m:
        return None
    if len(m["fm"] or "") > MAX_FRONT_CHARS:
        return "the front matter is too long to read"
    try:
        data = yaml.load(m["fm"] or "", Loader=UniqueKeyStrDateLoader)
    except Exception as ex:
        reason = " ".join(str(ex).split())[:160]
        return f"the front matter is not valid YAML ({type(ex).__name__}: {reason})"
    return None if isinstance(data, dict) else "the front matter is not a YAML mapping"


def _order(front: dict, key: str) -> list[str]:
    """The key order a restamp leaves: the existing order, with a new ``key`` after ``summary``."""
    keys = list(front)
    if key not in keys:
        keys.insert(keys.index("summary") + 1, key)
    return keys
