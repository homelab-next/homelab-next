# SPDX-License-Identifier: Apache-2.0
"""``hnx docs facts generate|check [FILE...]``: facts the docs state that have a source of truth
elsewhere -- how many capabilities there are and their names, the extended suites, the tool
classes and the reader and broker rules over them, every schema's ``$id`` version -- are generated
spans, so a page cannot drift from the code, the class table or the schemas.

A fact is the same ``hnx:gen`` comment family the system pages and the docs index use, named
``fact:NAME``.  Inline, on one line::

    Capability names (<!-- hnx:gen:fact:capability-count -->18<!-- /hnx:gen -->, ...)

A table is a block: the open marker ends its line and the close marker starts one::

    <!-- hnx:gen:fact:schema-versions -->
    | schema | version | ... |
    <!-- /hnx:gen -->

``generate`` rewrites only the text between each marker pair; everything outside a span is left
byte for byte (line endings too).  ``check`` exits 1 when a span is stale, names a fact this module
does not know, is written in the wrong form (an inline fact as a block or the reverse), or when a
``hnx:gen:fact:`` marker has no close.  With no FILE, both walk every ``*.md`` page under
``docs/`` of the checkout that holds a fact marker (the ADRs are left out: an ADR is append-only
and states the facts of its day).

The sources: :data:`homelabnext.conform.registry.CAPABILITIES` and ``EXTENDED`` (the core and
extended suites; ``capabilities.yml`` is held equal to the core list by ``tools/conform_coverage``),
the packaged ``homelabnext/agent/tool_classes.yml`` (read through
:class:`homelabnext.agent.readers.ToolClasses`), and every live schema under ``schemas/*/`` (its
``$id`` names it and carries its version; ``x-draft`` marks a draft).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from homelabnext.registers.summaries import atomic_write_text, read_text_exact

__all__ = ["FACTS", "SPAN", "check", "facts", "files_with_facts", "generate", "refresh"]

SPAN = re.compile(
    r"(?P<open><!-- hnx:gen:fact:(?P<name>[a-z0-9-]+) -->)(?P<body>.*?)(?P<close><!-- /hnx:gen -->)",
    re.S,
)
_OPEN = re.compile(r"<!-- hnx:gen:fact:(?P<name>[^\s>]*) ?-->|hnx:gen:fact:")
ID_PREFIX = "https://schemas.example.internal/homelabnext/"

_WORDS = [
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
    "thirteen",
    "fourteen",
    "fifteen",
    "sixteen",
    "seventeen",
    "eighteen",
    "nineteen",
]
_TENS = ["_", "_", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"]


def number_word(n: int) -> str:
    """``18`` -> ``eighteen`` (0..99; larger numbers stay digits)."""
    if n < 20:
        return _WORDS[n]
    if n < 100:
        return _TENS[n // 10] + ("" if n % 10 == 0 else "-" + _WORDS[n % 10])
    return str(n)


def _ticks(names) -> str:
    return ", ".join(f"`{n}`" for n in names)


@dataclass(frozen=True)
class Fact:
    """One generated fact: ``block`` facts are tables (their body starts and ends a line)."""

    render: Callable[[Path], str]
    block: bool = False


def _core(_root: Path) -> tuple[str, ...]:
    from homelabnext.conform.registry import CAPABILITIES

    return CAPABILITIES


def _extended(_root: Path) -> tuple[str, ...]:
    from homelabnext.conform.registry import EXTENDED

    return EXTENDED


def _classes(_root: Path):
    import yaml

    from homelabnext.agent.readers import DEFAULT_CLASSES, ToolClasses

    doc = yaml.safe_load(DEFAULT_CLASSES.read_text(encoding="utf-8")) or {}
    return ToolClasses(doc, source=str(DEFAULT_CLASSES))


def _in_order(t, chosen) -> list[str]:
    return [c for c in t.classes if c in chosen]


def _class_table(root: Path) -> str:
    t = _classes(root)
    rows = [
        "| class | what it is | a reader may hold it | only through the broker |",
        "|---|---|---|---|",
    ]
    for name, what in t.classes.items():
        what = " ".join(str(what).split()).replace("|", "\\|")
        reader = "no" if name in t.reader_forbidden else "yes"
        broker = "yes" if name in t.broker_only else "no"
        rows.append(f"| `{name}` | {what} | {reader} | {broker} |")
    return "\n".join(rows)


def schemas(root: Path) -> list[tuple[str, str, str, bool]]:
    """``(name, version, path, draft)`` of every live schema under ``root/schemas/*/``, sorted by
    name (``name`` is ``<dir>/<name>`` from the ``$id``)."""
    out = []
    base = root / "schemas"
    for p in sorted(base.glob("*/*.json")):
        if p.parent.name.startswith("_"):
            continue
        doc = json.loads(p.read_text(encoding="utf-8"))
        sid = str(doc.get("$id") or "")
        if not sid.startswith(ID_PREFIX) or sid.count("/") < 2:
            raise ValueError(f"{p.relative_to(root)}: $id {sid!r} is not under {ID_PREFIX}")
        name, _, version = sid[len(ID_PREFIX) :].rpartition("/")
        out.append((name, version, p.relative_to(root).as_posix(), bool(doc.get("x-draft"))))
    return sorted(out)


def _schema_table(root: Path) -> str:
    rows = ["| schema (`$id` name) | version | file | status |", "|---|---|---|---|"]
    for name, version, path, draft in schemas(root):
        rows.append(f"| `{name}` | {version} | `{path}` | {'draft' if draft else 'stable'} |")
    return "\n".join(rows)


def _schema_dirs(root: Path) -> str:
    return _ticks(sorted({n.split("/", 1)[0] for n, *_ in schemas(root)}))


#: every fact a page may hold, by name
FACTS: dict[str, Fact] = {
    "capability-count": Fact(lambda r: str(len(_core(r)))),
    "capability-count-word": Fact(lambda r: number_word(len(_core(r)))),
    "capabilities": Fact(lambda r: _ticks(_core(r))),
    "extended-count-word": Fact(lambda r: number_word(len(_extended(r)))),
    "extended-suites": Fact(lambda r: _ticks(_extended(r))),
    "tool-classes": Fact(lambda r: _ticks(_classes(r).classes)),
    "reader-forbidden": Fact(
        lambda r: _ticks(_in_order(_classes(r), _classes(r).reader_forbidden))
    ),
    "broker-only": Fact(lambda r: _ticks(_in_order(_classes(r), _classes(r).broker_only))),
    "tool-class-table": Fact(_class_table, block=True),
    "schema-dirs": Fact(_schema_dirs),
    "schema-versions": Fact(_schema_table, block=True),
}


def facts(root: Path) -> dict[str, str]:
    """Every fact's rendered body (a block's without its surrounding newlines)."""
    return {name: f.render(root) for name, f in FACTS.items()}


def _shown(page: Path, base: Path | None) -> str:
    if base is not None:
        try:
            return page.resolve().relative_to(base.resolve()).as_posix()
        except ValueError:
            pass
    return page.as_posix()


def refresh(text: str, root: Path, where: str = "page") -> tuple[str, list[str], list[str]]:
    """``(new text, stale facts, problems)``: ``text`` with every fact span set to its value."""
    values: dict[str, str] = {}
    stale: list[str] = []
    problems: list[str] = []
    nl = "\r\n" if "\r\n" in text else "\n"

    def line_of(pos: int) -> int:
        return text.count("\n", 0, pos) + 1

    def one(m: re.Match[str]) -> str:
        name = m["name"]
        fact = FACTS.get(name)
        at = f"{where}:{line_of(m.start())}"
        if fact is None:
            problems.append(f"{at}: unknown fact {name!r} (known: {', '.join(FACTS)})")
            return m[0]
        body = m["body"]
        is_block = body.startswith(("\n", "\r\n"))
        if fact.block != is_block:
            form = "a block (open marker alone ending its line)" if fact.block else "inline"
            problems.append(f"{at}: fact {name!r} must be written {form}")
            return m[0]
        if name not in values:
            values[name] = fact.render(root)
        want = values[name]
        if fact.block:
            want = nl + want.replace("\n", nl) + nl
        if body != want:
            stale.append(f"{at}: {name}")
        return f"{m['open']}{want}{m['close']}"

    new = SPAN.sub(one, text)
    rest = SPAN.sub("", text)
    for m in _OPEN.finditer(rest):
        problems.append(
            f"{where}: malformed or unclosed fact marker {m[0]!r} (expected "
            "`<!-- hnx:gen:fact:NAME -->value<!-- /hnx:gen -->`)"
        )
    return new, stale, problems


def files_with_facts(root: Path) -> list[Path]:
    """Every page under ``root/docs`` that holds a fact marker, the ADRs left out."""
    adr = root / "docs" / "adr"
    out = []
    for p in sorted((root / "docs").rglob("*.md")):
        if adr in p.parents:
            continue
        if "hnx:gen:fact:" in p.read_text(encoding="utf-8", errors="replace"):
            out.append(p)
    return out


def generate(page: Path, root: Path, base: Path | None = None) -> tuple[bool, list[str]]:
    """Rewrite the fact spans of ``page``.  ``(changed, problems)``; with a problem nothing is
    written."""
    text = read_text_exact(page)
    new, _, problems = refresh(text, root, _shown(page, base))
    if problems or new == text:
        return False, problems
    atomic_write_text(page, new)
    return True, problems


def check(page: Path, root: Path, base: Path | None = None) -> list[str]:
    """One line per stale span or problem of ``page``; empty when it is current."""
    text = read_text_exact(page)
    _, stale, problems = refresh(text, root, _shown(page, base))
    return [f"stale: {s}" for s in stale] + problems
