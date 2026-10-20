# SPDX-License-Identifier: Apache-2.0
"""Build the graph from a checkout and check its integrity.

:func:`build` runs every reader of :mod:`.sources` and returns the :class:`~.model.Graph` with a
:class:`Integrity` report.  :func:`check` checks that integrity and, given an output directory,
also compares the generated files there with a fresh build (``docs/graph/`` is a local,
uncommitted build).

Failures (``hnx graph check`` exits 1): a dangling edge (either end names an id no reader
defined), a duplicate id (two places define the same node), and with an output directory a
stale, missing or orphan generated file.  Reported, never failed: orphan nodes (no edge at all) and lesson/runbook system
tags that resolve to no service, capability or product.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .model import Edge, Graph, dumps
from .sources import GRAPH_DIR, READERS, Builder

__all__ = ["GRAPH_JSON", "Integrity", "Report", "build", "check", "generate", "render_all"]

GRAPH_JSON = f"{GRAPH_DIR}/graph.json"


@dataclass
class Integrity:
    dangling: list[Edge] = field(default_factory=list)
    duplicates: list[tuple[str, str, str]] = field(default_factory=list)
    orphans: list[str] = field(default_factory=list)
    unresolved_tags: list[str] = field(default_factory=list)

    def ok(self) -> bool:
        return not self.dangling and not self.duplicates


def build(root: str | Path) -> tuple[Graph, Integrity]:
    """The graph of the checkout at ``root`` and its integrity report (deterministic)."""
    b = Builder(Path(root).resolve())
    for _, reader in READERS:
        reader(b)
    b.finish()
    graph = Graph(dict(b.nodes), list(b.edges))
    rep = Integrity(duplicates=sorted(set(b.duplicates)))
    rep.dangling = [e for e in graph.edges if e.src not in graph.nodes or e.dst not in graph.nodes]
    touched = {e.src for e in graph.edges} | {e.dst for e in graph.edges}
    rep.orphans = [n for n in graph.nodes if n not in touched]
    rep.unresolved_tags = [
        n.id
        for n in graph.of_kind("system")
        if not any(e.type == "resolves_to" for e in graph.out_edges(n.id))
    ]
    return graph, rep


def render_all(graph: Graph) -> dict[str, str]:
    """Every generated file under ``docs/graph/`` (relative name -> content)."""
    from .views import render_views

    out = {"graph.json": dumps(graph)}
    out.update(render_views(graph))
    return out


def generate(root: str | Path, out_dir: str | Path | None = None) -> tuple[list[str], list[str]]:
    """Write the generated files; return (written, removed orphans).

    Orphans are removed only from a directory the graph generator owns
    (:func:`homelabnext._generated.claim`: ``docs/graph/``, or one it created or marked); any
    other ``--out`` is written to and nothing in it is deleted."""
    from homelabnext._generated import claim

    root = Path(root)
    graph, _ = build(root)
    out = Path(out_dir) if out_dir else root / GRAPH_DIR
    prune = claim(out, "hnx graph build", root / GRAPH_DIR)
    files = render_all(graph)
    written = []
    for name, text in sorted(files.items()):
        p = out / name
        if not p.is_file() or p.read_text(encoding="utf-8") != text:
            p.write_text(text, encoding="utf-8")
        written.append(name)
    removed = []
    for p in sorted(out.iterdir()) if prune else ():
        if p.is_file() and p.name not in files and p.suffix in (".md", ".json"):
            p.unlink()
            removed.append(p.name)
    return written, removed


@dataclass
class Report:
    integrity: Integrity
    stale: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    orphan_files: list[str] = field(default_factory=list)
    counts: tuple[int, int] = (0, 0)

    def ok(self) -> bool:
        return self.integrity.ok() and not (self.stale or self.missing or self.orphan_files)

    def lines(self) -> list[str]:
        i = self.integrity
        out: list[str] = []
        out += [f"dangling edge: {e.src} -{e.type}-> {e.dst}  ({e.source})" for e in i.dangling]
        out += [f"duplicate id: {d} (defined at {a} and {b})" for d, a, b in i.duplicates]
        out += [f"stale: {GRAPH_DIR}/{n} (run `hnx graph build`)" for n in self.stale]
        out += [f"missing: {GRAPH_DIR}/{n} (run `hnx graph build`)" for n in self.missing]
        out += [
            f"orphan file: {GRAPH_DIR}/{n} (not generated; remove it)" for n in self.orphan_files
        ]
        out.append(f"orphan nodes (reported, not failed): {len(i.orphans)}")
        out += [f"  {n}" for n in i.orphans]
        out.append(f"unresolved system tags (reported, not failed): {len(i.unresolved_tags)}")
        out += [f"  {n}" for n in i.unresolved_tags]
        return out


def check(root: str | Path, out_dir: str | Path | None = None) -> Report:
    """Integrity of a fresh build; with ``out_dir``, also that the generated files there match.

    ``docs/graph/`` is not committed (almost every change in the repository would make a
    committed copy stale), so by default only the integrity of the graph itself is checked.
    """
    root = Path(root)
    graph, integrity = build(root)
    rep = Report(integrity, counts=(len(graph.nodes), len(graph.edges)))
    if out_dir is None:
        return rep
    out = Path(out_dir)
    files = render_all(graph)
    for name, text in sorted(files.items()):
        p = out / name
        if not p.is_file():
            rep.missing.append(name)
        elif p.read_text(encoding="utf-8") != text:
            rep.stale.append(name)
    if out.is_dir():
        rep.orphan_files = sorted(
            p.name
            for p in out.iterdir()
            if p.is_file() and p.name not in files and p.suffix in (".md", ".json")
        )
    return rep
