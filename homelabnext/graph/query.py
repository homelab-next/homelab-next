# SPDX-License-Identifier: Apache-2.0
"""Pure query functions over a loaded :class:`~.model.Graph` (what the context pack, the
``context`` capability and the MCP server call).

* :func:`neighbours` -- every node within ``depth`` hops, optionally by edge type and direction;
* :func:`related` -- a ranked, budgeted neighbourhood: nearer first, then by the product of the
  edge-type weights along the best path, ties broken by id (deterministic);
* :func:`seeds_for` -- the nodes a task starts from: the files being edited (a node's ``path``,
  else the owning package or directory node) and names mentioned in text (exact id, title or
  bare-name match, never fuzzy).

Inactive records -- a lesson or runbook whose ``status`` is ``retired``, ``superseded`` or
``incorporated`` (absorbed into a runbook or system page, which now carries the knowledge) -- are
left out of :func:`neighbours`, :func:`related` and :func:`seeds_for` unless
``include_inactive=True``: a retired lesson is history, and must stop costing context tokens.
An inactive node is neither returned nor expanded (nothing is reached *through* it).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath

from .model import Graph, Node

__all__ = [
    "BARE_NAME_KINDS",
    "DEFAULT_WEIGHTS",
    "INACTIVE_STATUSES",
    "Related",
    "is_active",
    "neighbours",
    "related",
    "seeds_for",
]

INACTIVE_STATUSES = frozenset({"retired", "superseded", "incorporated"})

#: edge type -> weight in (0, 1]; a type absent here weighs DEFAULT_WEIGHT, 0 is not traversed.
#: Structural edges (what implements, provides, checks or documents a thing) outrank incidental
#: ones (a page linking another, a script read by a job).
DEFAULT_WEIGHTS: dict[str, float] = {
    "implements": 1.0,
    "provides": 1.0,
    "documents": 1.0,
    "faked_by": 0.9,
    "checked_by": 0.5,
    "controlled_by": 0.9,
    "retired_by": 0.9,
    "superseded_by": 0.9,
    "incorporated_into": 0.9,
    "from_lesson": 0.6,
    "operates": 0.9,
    "runs": 0.8,
    "for": 0.8,
    "depends_on": 0.8,
    "loads_schema": 0.8,
    "grants": 0.7,
    "uses": 0.7,
    "uses_model": 0.6,
    "exposes": 0.7,
    "about": 0.7,
    "resolves_to": 0.9,
    "verified_by": 0.7,
    "checks": 0.6,
    "enforces": 0.6,
    "applies_to": 0.7,
    "governed_by": 0.6,
    "links": 0.4,
    "mentions": 0.4,
    "refs": 0.4,
    "triggered_by": 0.4,
    "reads": 0.3,
    "runs_on": 0.5,
    "in_zone": 0.3,
    "serves": 0.2,
}
DEFAULT_WEIGHT = 0.5


def is_active(node: Node | None) -> bool:
    """False for a retired or superseded record (and for an id the graph does not have)."""
    return node is not None and node.attrs.get("status") not in INACTIVE_STATUSES


def _steps(graph: Graph, nid: str, direction: str):
    if direction in ("out", "both"):
        for e in graph.out_edges(nid):
            yield e, e.dst
    if direction in ("in", "both"):
        for e in graph.in_edges(nid):
            yield e, e.src


def neighbours(
    graph: Graph,
    ids: Iterable[str],
    depth: int = 1,
    edge_types: Iterable[str] | None = None,
    direction: str = "both",
    include_inactive: bool = False,
) -> list[str]:
    """Every node within ``depth`` hops of ``ids`` (the seeds themselves excluded), nearest
    first then by id.  ``direction``: ``out`` (edges leaving), ``in`` (edges arriving), ``both``."""
    if direction not in ("out", "in", "both"):
        raise ValueError(f"direction must be out|in|both, not {direction!r}")
    types = set(edge_types) if edge_types is not None else None
    seeds = [i for i in dict.fromkeys(ids) if i in graph.nodes]
    dist = dict.fromkeys(seeds, 0)
    frontier = [s for s in seeds if include_inactive or is_active(graph.nodes[s])]
    for d in range(1, depth + 1):
        nxt: list[str] = []
        for nid in frontier:
            for e, other in _steps(graph, nid, direction):
                if types is not None and e.type not in types:
                    continue
                node = graph.nodes.get(other)
                if node is None or other in dist:
                    continue
                if not include_inactive and not is_active(node):
                    continue
                dist[other] = d
                nxt.append(other)
        frontier = sorted(nxt)
    return sorted((n for n in dist if dist[n] > 0), key=lambda n: (dist[n], n))


@dataclass(frozen=True)
class Related:
    id: str
    kind: str
    title: str
    distance: int
    score: float
    via: str  # the edge type of the best path's last hop
    parent: str  # the node that hop came from

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "distance": self.distance,
            "score": round(self.score, 6),
            "via": self.via,
            "from": self.parent,
        }


def related(
    graph: Graph,
    seeds: Iterable[str],
    budget: int = 25,
    weights: Mapping[str, float] | None = None,
    max_depth: int = 3,
    include_inactive: bool = False,
) -> list[Related]:
    """At most ``budget`` nodes related to ``seeds`` (seeds excluded), ranked by distance, then
    by the best path's weight product (each hop multiplies by its edge type's weight), then by
    id.  So every direct neighbour ranks above every two-hop node; within a ring the strongest
    relationships come first.  Edges are followed in both directions; a type weighing 0 is not
    followed; an inactive record is neither returned nor expanded."""
    w = dict(DEFAULT_WEIGHTS if weights is None else weights)
    seed_ids = [s for s in dict.fromkeys(seeds) if s in graph.nodes]
    best: dict[str, tuple[int, float, str, str]] = dict.fromkeys(seed_ids, (0, 1.0, "", ""))
    ring = sorted(s for s in seed_ids if include_inactive or is_active(graph.nodes[s]))
    for d in range(1, max_depth + 1):
        found: dict[str, tuple[int, float, str, str]] = {}
        for nid in ring:
            base = best[nid][1]
            for e, other in _steps(graph, nid, "both"):
                weight = w.get(e.type, DEFAULT_WEIGHT)
                node = graph.nodes.get(other)
                if weight <= 0 or node is None or other in best:
                    continue
                if not include_inactive and not is_active(node):
                    continue
                cand = (d, base * weight, e.type, nid)
                cur = found.get(other)
                if cur is None or (-cand[1], cand[2], cand[3]) < (-cur[1], cur[2], cur[3]):
                    found[other] = cand
        best.update(found)
        ring = sorted(found)
        if not ring:
            break
    out = [
        Related(n, graph.nodes[n].kind, graph.nodes[n].title, d, s, via, parent)
        for n, (d, s, via, parent) in best.items()
        if d > 0
    ]
    out.sort(key=lambda r: (r.distance, -r.score, r.id))
    return out[: max(budget, 0)]


#: kinds whose bare name (the id after ``kind:``) is matched in task text
BARE_NAME_KINDS = frozenset(
    {"cap", "svc", "product", "script", "role", "custom", "profile", "mdl", "skill", "persona"}
)

#: an edited node also seeds what it is the identity of: an adapter file is about its capability
_ANCHOR_EDGES = frozenset({"implements", "documents"})


def seeds_for(
    graph: Graph,
    paths: Iterable[str] = (),
    text: str = "",
    include_inactive: bool = False,
) -> list[str]:
    """Seed node ids for a task, sorted.

    ``paths`` (repo-relative files being edited): every node whose ``path`` is the file, else
    the node owning the nearest enclosing directory (a package); plus what such a node
    ``implements`` or ``documents`` (an adapter seeds its capability, a system page its service).
    ``text``: every node whose full id appears, whose bare name does (``secrets`` for
    ``cap:secrets``; only for the kinds in :data:`BARE_NAME_KINDS`, where a bare name is a real
    name rather than a word like ``test``), or whose title of three or more words does -- whole
    words, exact strings only."""
    by_path: dict[str, list[str]] = {}
    for n in graph.nodes.values():
        if n.path:
            by_path.setdefault(n.path.rstrip("/"), []).append(n.id)
    out: set[str] = set()
    for raw in paths:
        p = PurePosixPath(str(raw).replace("\\", "/").removeprefix("./") or ".")
        hits = by_path.get(str(p), [])
        cur = p.parent
        while not hits and str(cur) not in (".", ""):
            hits = by_path.get(str(cur), [])
            cur = cur.parent
        for h in hits:
            out.add(h)
            out |= {e.dst for e in graph.out_edges(h) if e.type in _ANCHOR_EDGES}
    if text:
        for n in graph.nodes.values():
            names = {n.id}
            if n.kind in BARE_NAME_KINDS:
                names.add(n.id.split(":", 1)[-1])
            if len(n.title.split()) >= 3 and len(n.title) <= 120:
                names.add(n.title)
            for name in names:
                if len(name) >= 3 and re.search(rf"(?<![\w:/.-]){re.escape(name)}(?![\w/-])", text):
                    out.add(n.id)
                    break
    return sorted(
        s for s in out if s in graph.nodes and (include_inactive or is_active(graph.nodes[s]))
    )
