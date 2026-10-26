# SPDX-License-Identifier: Apache-2.0
"""The repository's own knowledge graph as context documents.

Every graph node becomes one :class:`~.model.Document` with the node's id, kind, title, path
and lifecycle ``status``; its links are the node's outgoing edges (the store follows them both
ways).  Its content is the file that defines it when that file defines nothing else (a page,
an ADR, a capability page, a one-file-per-record lesson or runbook); otherwise -- a register
row, a check, a capability, a service -- a short text built from the node's title and attrs.
"""

from __future__ import annotations

import json
from pathlib import Path

from homelabnext.graph import Graph, build

from .model import MAX_CONTENT_CHARS, Document
from .store import ContextStore

__all__ = ["documents_from_graph", "read_served", "repo_store"]


def _summary(node) -> str:
    lines = [node.title or node.id, f"id: {node.id}", f"kind: {node.kind}"]
    if node.path:
        lines.append(f"path: {node.path}")
    for k in sorted(node.attrs):
        lines.append(f"{k}: {json.dumps(node.attrs[k], sort_keys=True, ensure_ascii=False)}")
    return "\n".join(lines) + "\n"


def read_served(base: Path, rel: str) -> str | None:
    """The text the context store indexes for the file ``rel`` under ``base`` (resolved): decoded
    as UTF-8 with undecodable bytes replaced, or ``None`` when it is not a file inside ``base``,
    cannot be read, or is longer than :data:`MAX_CONTENT_CHARS` (the store then indexes the node's
    attributes instead).  Shared with the context pack's levels, so a slug or a digest there is
    the one the MCP server serves."""
    f = (base / rel).resolve()
    if not (f.is_file() and f.is_relative_to(base)):
        return None
    try:
        text = f.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return text if len(text) <= MAX_CONTENT_CHARS else None


def documents_from_graph(graph: Graph, root: str | Path) -> list[Document]:
    """One document per node, sorted by id (deterministic for a given checkout)."""
    base = Path(root).resolve()
    owners: dict[str, int] = {}
    for n in graph.nodes.values():
        if n.path:
            owners[n.path] = owners.get(n.path, 0) + 1
    out: list[Document] = []
    for n in graph.nodes.values():
        content = ""
        if n.path and owners[n.path] == 1:
            content = read_served(base, n.path) or ""
        links = tuple(sorted({e.dst for e in graph.out_edges(n.id) if e.dst in graph.nodes}))
        out.append(
            Document(
                id=n.id,
                kind=n.kind,
                content=content or _summary(n),
                title=n.title,
                path=n.path,
                status=str(n.attrs.get("status", "")),
                links=links,
            )
        )
    return out


def repo_store(root: str | Path) -> ContextStore:
    """A :class:`ContextStore` holding every node of the checkout's graph at ``root``."""
    graph, _ = build(root)
    store = ContextStore()
    store.index(documents_from_graph(graph, root))
    return store
