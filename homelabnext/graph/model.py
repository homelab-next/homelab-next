# SPDX-License-Identifier: Apache-2.0
"""The graph's data model: :class:`Node`, :class:`Edge` and the loaded :class:`Graph`.

A node is identified by a namespaced id (``svc:secrets``, ``lesson:LL-001``); an edge is typed and
names the file and field that asserted it (``source``), so every fact can be traced back to the
line that states it.  The serialised form (:func:`dumps`) is deterministic: nodes sorted by id,
edges by ``(src, type, dst, source)``, one record per line, no timestamps.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = ["FORMAT", "Edge", "Graph", "Node", "dumps", "load", "loads"]

FORMAT = "homelabnext.graph/1"


@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    title: str = ""
    path: str = ""  # repo-relative file or directory that defines it ("" when none)
    attrs: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "path": self.path,
            "attrs": dict(self.attrs),
        }


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    type: str
    source: str  # "<file>" or "<file>#<field>": what asserted this edge
    attrs: Mapping[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str, str, str]:
        return (self.src, self.type, self.dst, self.source)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "src": self.src,
            "type": self.type,
            "dst": self.dst,
            "source": self.source,
        }
        if self.attrs:
            out["attrs"] = dict(self.attrs)
        return out


@dataclass
class Graph:
    """A built graph.  ``nodes`` by id; ``edges`` sorted, one per (src, type, dst, source);
    indexes built on construction."""

    nodes: dict[str, Node]
    edges: list[Edge]
    _out: dict[str, list[Edge]] = field(default_factory=dict, repr=False)
    _in: dict[str, list[Edge]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.nodes = dict(sorted(self.nodes.items()))
        self.edges = _sorted_unique(self.edges)
        self._out, self._in = {}, {}
        for e in self.edges:
            self._out.setdefault(e.src, []).append(e)
            self._in.setdefault(e.dst, []).append(e)

    def out_edges(self, node_id: str) -> list[Edge]:
        return self._out.get(node_id, [])

    def in_edges(self, node_id: str) -> list[Edge]:
        return self._in.get(node_id, [])

    def kinds(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for n in self.nodes.values():
            out[n.kind] = out.get(n.kind, 0) + 1
        return dict(sorted(out.items()))

    def edge_types(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.edges:
            out[e.type] = out.get(e.type, 0) + 1
        return dict(sorted(out.items()))

    def of_kind(self, kind: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind == kind]


def _sorted_unique(edges: Iterable[Edge]) -> list[Edge]:
    seen: dict[tuple[str, str, str, str], Edge] = {}
    for e in edges:
        seen.setdefault(e.key(), e)
    return [seen[k] for k in sorted(seen)]


def dumps(graph: Graph, extra: Mapping[str, Any] | None = None) -> str:
    """Deterministic JSON: one node or edge per line, keys sorted, trailing newline."""

    def line(obj: Mapping[str, Any]) -> str:
        return json.dumps(obj, sort_keys=True, ensure_ascii=False)

    head = {"format": FORMAT, **dict(extra or {})}
    parts = ["{"]
    for k in sorted(head):
        parts.append(f"  {json.dumps(k)}: {json.dumps(head[k], sort_keys=True)},")
    parts.append('  "nodes": [')
    nodes = [n.as_dict() for n in graph.nodes.values()]
    parts += [f"    {line(n)}{',' if i < len(nodes) - 1 else ''}" for i, n in enumerate(nodes)]
    parts.append("  ],")
    parts.append('  "edges": [')
    edges = [e.as_dict() for e in graph.edges]
    parts += [f"    {line(e)}{',' if i < len(edges) - 1 else ''}" for i, e in enumerate(edges)]
    parts.append("  ]")
    parts.append("}")
    return "\n".join(parts) + "\n"


def loads(text: str) -> Graph:
    doc = json.loads(text)
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise ValueError(f"not a {FORMAT} document")
    nodes = {
        n["id"]: Node(n["id"], n["kind"], n.get("title", ""), n.get("path", ""), n.get("attrs", {}))
        for n in doc["nodes"]
    }
    edges = [
        Edge(e["src"], e["dst"], e["type"], e["source"], e.get("attrs", {})) for e in doc["edges"]
    ]
    return Graph(nodes, edges)


def load(path: str | Path) -> Graph:
    return loads(Path(path).read_text(encoding="utf-8"))
