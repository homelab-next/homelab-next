# SPDX-License-Identifier: Apache-2.0
"""``context`` fake: link neighbours plus exact keyword scoring over a dict, and its broken twins.

Standard library only.  A related document scores ``10 - distance`` plus its keyword score; a
keyword-only match scores the fraction of query terms it contains (below 1).  It declares the
product feature ``semantic`` through a fixed table of synonyms (:data:`CONCEPTS`), so the
``semantic-recall`` SHOULD runs against it; real recall by meaning is a product's property.  The defects each
override one hook, so every twin differs from the fake in exactly one rule.
"""

from __future__ import annotations

import random
import re
from collections.abc import Iterable, Sequence

from homelabnext.context import (
    Document,
    Hit,
    IndexReport,
    NotFound,
    Query,
    check_documents,
    check_query,
    digest,
    in_scope,
)
from homelabnext.context.model import is_active, snippet, terms

_WORD = re.compile(r"\w+")
_DEPTH = 2
#: word -> concept: the fake's whole "understanding" of meaning
CONCEPTS = {
    "automobile": "car",
    "vehicle": "car",
    "maintenance": "repair",
    "servicing": "repair",
    "fix": "repair",
}


def _concepts(words: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(CONCEPTS.get(w, w) for w in words))


class FakeContextStore:
    """In-memory ``context`` store: breadth-first link walk, then whole-word keyword matches."""

    features = frozenset({"semantic"})

    def __init__(self) -> None:
        self._docs: dict[str, Document] = {}

    # hooks the defective twins override ------------------------------------------------------
    def _visible(self, doc_id: str, allowed: frozenset[str]) -> bool:
        return in_scope(doc_id, allowed)

    def _active(self, d: Document, q: Query) -> bool:
        return q.include_inactive or is_active(d.status)

    def _walkable(self, visible: list[Document], q: Query) -> list[Document]:
        return visible

    def _store(self, d: Document) -> None:
        self._docs[d.id] = d

    def _order(self, hits: list[Hit]) -> list[Hit]:
        return sorted(hits, key=lambda h: (-h.score, h.id))

    def _rows(self) -> list[Document]:
        return list(self._docs.values())

    # the contract ----------------------------------------------------------------------------
    def index(self, docs: Sequence[Document]) -> IndexReport:
        added, replaced, unchanged = [], [], []
        for d in check_documents(docs):
            old = self._docs.get(d.id)
            if old == d:
                unchanged.append(d.id)
                continue
            (added if old is None else replaced).append(d.id)
            self._store(d)
        return IndexReport(tuple(sorted(added)), tuple(sorted(replaced)), tuple(sorted(unchanged)))

    def delete(self, doc_id: str) -> None:
        if doc_id not in self._docs:
            raise NotFound("no such document")
        del self._docs[doc_id]

    def get(self, doc_id: str, allowed: frozenset[str]) -> Hit:
        q = check_query(Query(allowed=allowed))
        d = self._docs.get(doc_id)
        if d is None or not self._visible(doc_id, q.allowed):
            raise NotFound(f"no document {doc_id!r} in scope")
        return _hit(d, 0.0, [])

    def query(self, q: Query) -> list[Hit]:
        q = check_query(q)
        words = terms(q.text)
        if q.budget == 0 or (not words and not q.seeds):
            return []
        meant = _concepts(words)
        visible = [d for d in self._rows() if self._visible(d.id, q.allowed) and self._active(d, q)]
        dist = _walk(self._walkable(visible, q), q.seeds)
        hits = []
        for d in visible:
            if q.kinds is not None and d.kind not in q.kinds:
                continue
            text = f"{d.id}\n{d.title}\n{d.content}"
            found = set(_concepts(t.lower() for t in _WORD.findall(text)))
            kw = sum(1 for w in meant if w in found) / (len(meant) + 1)
            if d.id in dist:
                hits.append(_hit(d, 10 - dist[d.id] + kw, words))
            elif kw > 0:
                hits.append(_hit(d, kw, words))
        return self._order(hits)[: q.budget]


def _walk(docs: list[Document], seeds: Sequence[str]) -> dict[str, int]:
    """Distance from the seeds over links in both directions, at most ``_DEPTH`` hops."""
    ids = {d.id for d in docs}
    adj: dict[str, set[str]] = {i: set() for i in ids}
    for d in docs:
        for other in d.links:
            if other in ids:
                adj[d.id].add(other)
                adj[other].add(d.id)
    dist = {s: 0 for s in seeds if s in ids}
    ring = sorted(dist)
    for depth in range(1, _DEPTH + 1):
        nxt = sorted({o for n in ring for o in adj[n] if o not in dist})
        dist.update(dict.fromkeys(nxt, depth))
        ring = nxt
    return dist


def _hit(d: Document, score: float, words: Sequence[str]) -> Hit:
    return Hit(
        d.id, d.kind, d.title, d.path, round(score, 9), snippet(d.content, words), d.content,
        digest(d.content),
    )  # fmt: skip


class ScopeBlindContextStore(FakeContextStore):
    """Defect: ignores ``allowed`` -- every document is visible to every caller."""

    def _visible(self, doc_id: str, allowed: frozenset[str]) -> bool:
        return True


class LoosePrefixContextStore(FakeContextStore):
    """Defect: treats every scope entry as a prefix (``pub`` also admits ``pub:x``, ``pubx:y``)."""

    def _visible(self, doc_id: str, allowed: frozenset[str]) -> bool:
        return any(doc_id.startswith(e) for e in allowed)


class InactiveLeakContextStore(FakeContextStore):
    """Defect: returns retired, superseded and incorporated records by default."""

    def _active(self, d: Document, q: Query) -> bool:
        return True


class HiddenBridgeContextStore(FakeContextStore):
    """Defect: follows links through documents outside the caller's scope."""

    def _walkable(self, visible: list[Document], q: Query) -> list[Document]:
        return [d for d in self._docs.values() if self._active(d, q)]


class StaleCopyContextStore(FakeContextStore):
    """Defect: re-indexing keeps the old version, which queries can still return."""

    def __init__(self) -> None:
        super().__init__()
        self._old: list[Document] = []

    def _store(self, d: Document) -> None:
        if d.id in self._docs:
            self._old.append(self._docs[d.id])
        super()._store(d)

    def _rows(self) -> list[Document]:
        return [*self._old, *super()._rows()]


class ShuffledTiesContextStore(FakeContextStore):
    """Defect: hits with equal scores come back in a random order."""

    def _order(self, hits: list[Hit]) -> list[Hit]:
        rng = random.Random()
        return sorted(hits, key=lambda h: (-h.score, rng.random()))
