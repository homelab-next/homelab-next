# SPDX-License-Identifier: Apache-2.0
"""The reference ``context`` store: documents as graph nodes, ranked by relation, then keywords.

Ranking, the same for every query and with no corpus-wide statistics:

1. Relation.  The documents the caller may see (and, unless ``include_inactive``, the active
   ones) form a graph whose edges are the documents' ``links``, followed in both directions.  A
   seed is at distance 0, its neighbours at 1, theirs at 2 (:data:`MAX_DEPTH`); the walk is
   :func:`homelabnext.graph.neighbours` over that scoped graph, so it never passes through a
   document the caller cannot see or an inactive record.  Every related document outranks every
   document that is only a keyword match, and nearer outranks farther.
2. Keywords.  The fraction of distinct query terms that occur as whole words in the document's
   id, title or content, plus a small bonus for how often they occur.  A document that is neither
   related nor matching is not a hit.
3. Ties are ordered by id.

Scores depend only on the query and the documents in scope: a document the caller cannot see
changes neither which hits come back nor their scores.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence

from homelabnext.graph.model import Edge, Graph, Node
from homelabnext.graph.query import neighbours

from .model import (
    Document,
    Hit,
    IndexReport,
    NotFound,
    Query,
    check_documents,
    check_query,
    digest,
    in_scope,
    is_active,
    snippet,
    terms,
)

__all__ = ["MAX_DEPTH", "ContextStore", "keyword_score"]

_WORD = re.compile(r"\w+")

#: how many hops from a seed still count as related
MAX_DEPTH = 2


def keyword_score(words: Sequence[str], counts: Counter[str]) -> float:
    """In [0, 1): mostly the fraction of query terms present, a little for their frequency."""
    if not words:
        return 0.0
    present = [w for w in words if counts.get(w)]
    if not present:
        return 0.0
    tf = min(sum(counts[w] for w in present), 100)
    return 0.9 * len(present) / len(words) + 0.09 * tf / 100


class ContextStore:
    """In-process context store over :class:`~.model.Document` (the reference implementation).

    ``index`` and ``delete`` are the indexer's operations; ``query`` and ``get`` are the
    reader's and always take the caller's scope.  :func:`homelabnext.context.repo_store` fills
    one from the repository's knowledge graph.
    """

    features: frozenset[str] = frozenset()

    def __init__(self) -> None:
        self._docs: dict[str, Document] = {}
        self._words: dict[str, Counter[str]] = {}

    # -- indexer -------------------------------------------------------------------------------
    def index(self, docs: Sequence[Document]) -> IndexReport:
        batch = check_documents(docs)
        added, replaced, unchanged = [], [], []
        for d in batch:
            old = self._docs.get(d.id)
            if old is None:
                added.append(d.id)
            elif old == d:
                unchanged.append(d.id)
                continue
            else:
                replaced.append(d.id)
            self._docs[d.id] = d
            self._words[d.id] = Counter(
                t.lower() for t in _WORD.findall(f"{d.id}\n{d.title}\n{d.content}")
            )
        return IndexReport(tuple(sorted(added)), tuple(sorted(replaced)), tuple(sorted(unchanged)))

    def delete(self, doc_id: str) -> None:
        if not isinstance(doc_id, str) or doc_id not in self._docs:
            raise NotFound("no such document")
        del self._docs[doc_id]
        del self._words[doc_id]

    # -- reader --------------------------------------------------------------------------------
    def get(self, doc_id: str, allowed: frozenset[str]) -> Hit:
        q = check_query(Query(allowed=allowed))
        d = self._docs.get(doc_id) if isinstance(doc_id, str) else None
        if d is None or not in_scope(doc_id, q.allowed):
            raise NotFound(f"no document {doc_id!r} in scope")
        return _hit(d, 0.0, [])

    def query(self, q: Query) -> list[Hit]:
        q = check_query(q)
        words = terms(q.text)
        if q.budget == 0 or (not words and not q.seeds):
            return []
        visible = [
            d
            for d in self._docs.values()
            if in_scope(d.id, q.allowed) and (q.include_inactive or is_active(d.status))
        ]
        dist = self._distances(visible, q.seeds)
        hits: list[Hit] = []
        for d in visible:
            if q.kinds is not None and d.kind not in q.kinds:
                continue
            kw = keyword_score(words, self._words[d.id])
            if d.id in dist:
                score = (MAX_DEPTH + 1 - dist[d.id]) + kw
            elif kw > 0:
                score = kw
            else:
                continue
            hits.append(_hit(d, round(score, 9), words))
        hits.sort(key=lambda h: (-h.score, h.id))
        return hits[: q.budget]

    def _distances(self, visible: list[Document], seeds: Sequence[str]) -> dict[str, int]:
        ids = {d.id for d in visible}
        start = [s for s in dict.fromkeys(seeds) if s in ids]
        if not start:
            return {}
        nodes = {d.id: Node(d.id, d.kind, d.title, d.path, {"status": d.status}) for d in visible}
        edges = [
            Edge(d.id, other, "links", "context")
            for d in visible
            for other in d.links
            if other in ids and other != d.id
        ]
        g = Graph(nodes, edges)
        dist: dict[str, int] = {}
        for depth in range(MAX_DEPTH, 0, -1):  # nearer rings overwrite farther ones
            for n in neighbours(g, start, depth=depth, include_inactive=True):
                dist[n] = depth
        dist.update(dict.fromkeys(start, 0))
        return dist


def _hit(d: Document, score: float, words: Sequence[str]) -> Hit:
    return Hit(
        id=d.id,
        kind=d.kind,
        title=d.title,
        path=d.path,
        score=score,
        snippet=snippet(d.content, words),
        content=d.content,
        digest=digest(d.content),
    )
