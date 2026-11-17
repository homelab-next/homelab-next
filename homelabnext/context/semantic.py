# SPDX-License-Identifier: Apache-2.0
"""A hybrid (sparse + dense) ``context`` adapter that declares the ``semantic`` feature.

It is a :class:`~homelabnext.context.ContextStore` whose *text* score is replaced: scope, the
inactive rule, relation-first ranking, determinism and fidelity are the reference store's own
code, so the contract's guarantees hold unchanged, and only the question "how well does this
document match these words" is answered by meaning as well as by words:

* **sparse**: BM25 over the documents the caller may see (txtai's scoring index), so a
  document the caller cannot see changes neither a hit nor its score;
* **dense**: cosine similarity of sentence embeddings (txtai ``Embeddings``) of the query and
  the document, the vectors computed once at ``index`` time from a model pinned by revision and
  sha256 (:mod:`.semantic_model`), fully local, on the CPU.  The model directory is verified
  before it is loaded and no code here fetches anything: provisioning is
  :func:`~homelabnext.context.semantic_model.fetch`, run by an operator.

The two scores are fused (``w * bm25/max + (1 - w) * cosine``); a document is a hit only when
it shares a query word or its cosine reaches ``min_similarity``, and (when ``min_score`` is set)
its fused score reaches that, so a question the corpus does not answer can return nothing
instead of the nearest wrong thing.  ``min_score`` is a corpus-dependent knob: calibrate it on
one corpus and check it on another before trusting it.

**TLP** (ADR-0033).  Every indexed document is given a label at ``index`` time
(``tlp_of(document)``; the default reads a ``tlp:`` line in the first lines of the content and
treats anything else as ``red``, so an unlabelled item hides rather than leaks).  A query is
answered for a reader ``ceiling`` (the constructor's, or ``query(q, ceiling=...)``): a document
above it is exactly as absent as one outside ``allowed``, from hits, from ``get`` and from the
BM25 statistics.

Needs the optional extra ``context-semantic`` (txtai, which brings torch); importing this module
without it works, constructing the store raises :class:`SemanticUnavailable`.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from collections.abc import Callable, Sequence
from pathlib import Path

from homelabnext import tlp as _tlp

from . import model as _m
from .model import Document, Hit, IndexReport, NotFound, Query
from .semantic_model import check_dir
from .store import MAX_DEPTH, ContextStore, _hit

__all__ = ["SemanticContextStore", "SemanticUnavailable", "default_tlp_of", "make"]

_WORD = re.compile(r"\w+")
_MIN_DOCS_FOR_STOP = 20
_STOP_SHARE = 0.5
_TLP_LINE = re.compile(r"^\s*(?:#\s*)?tlp\s*:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_HEAD_CHARS = 2000
#: the longest text embedded per document (the model reads ~256 word pieces anyway)
EMBED_CHARS = 2000


class SemanticUnavailable(RuntimeError):
    """The optional ``context-semantic`` extra is not installed."""


def default_tlp_of(doc: Document) -> _tlp.Label:
    """The label a document carries: a ``tlp: <label>`` line near its top, else ``red``."""
    m = _TLP_LINE.search(doc.content[:_HEAD_CHARS])
    return _tlp.read(m.group(1)) if m else _tlp.Label.RED


class SemanticContextStore(ContextStore):
    features: frozenset[str] = frozenset({"semantic"})

    def __init__(
        self,
        model_dir: str | Path,
        *,
        ceiling: str | _tlp.Label = "red",
        tlp_of: Callable[[Document], _tlp.Label] = default_tlp_of,
        dense_weight: float = 0.5,
        min_similarity: float = 0.36,
        min_score: float = 0.0,
    ) -> None:
        super().__init__()
        try:
            from txtai import Embeddings
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise SemanticUnavailable(
                "install the 'context-semantic' extra (txtai) to use the semantic adapter"
            ) from exc
        if not 0.0 <= dense_weight <= 1.0:
            raise ValueError("dense_weight must be in [0, 1]")
        self._model_dir = check_dir(model_dir)  # verified by sha256 before anything loads
        self._emb = Embeddings(path=str(self._model_dir))
        self._ceiling = ceiling if isinstance(ceiling, _tlp.Label) else _tlp.parse(ceiling)
        self._tlp_of = tlp_of
        self._w = dense_weight
        self._min_sim = min_similarity
        self._min_score = min_score
        self._vec: dict[str, object] = {}
        self._tlp: dict[str, _tlp.Label] = {}
        self._sparse_cache: dict[tuple[str, ...], tuple[object, Counter[str], int]] = {}

    # -- indexer -------------------------------------------------------------------------------
    def index(self, docs: Sequence[Document]) -> IndexReport:
        batch = _m.check_documents(docs)
        report = super().index(batch)
        changed = [d for d in batch if d.id in set(report.added) | set(report.replaced)]
        if changed:
            vecs = self._emb.batchtransform([_embed_text(d) for d in changed])
            for d, v in zip(changed, vecs, strict=True):
                self._vec[d.id] = v
                self._tlp[d.id] = _tlp.read(self._tlp_of(d))
            self._sparse_cache.clear()
        return report

    def delete(self, doc_id: str) -> None:
        super().delete(doc_id)
        self._vec.pop(doc_id, None)
        self._tlp.pop(doc_id, None)
        self._sparse_cache.clear()

    def tlp(self, doc_id: str) -> _tlp.Label:
        """The label an indexed document carries (``NotFound`` for an unknown id)."""
        if doc_id not in self._tlp:
            raise NotFound("no such document")
        return self._tlp[doc_id]

    # -- reader --------------------------------------------------------------------------------
    def get(self, doc_id: str, allowed: frozenset[str], *, ceiling: str | _tlp.Label | None = None):
        c = self._reader(ceiling)
        hit = super().get(doc_id, allowed)
        if not _tlp.allows(c, self._tlp[doc_id]):
            raise NotFound(f"no document {doc_id!r} in scope")
        return hit

    def query(self, q: Query, *, ceiling: str | _tlp.Label | None = None) -> list[Hit]:
        c = self._reader(ceiling)
        q = _m.check_query(q)
        words = _m.terms(q.text)
        if q.budget == 0 or (not words and not q.seeds):
            return []
        visible = [
            d
            for d in self._docs.values()
            if _m.in_scope(d.id, q.allowed)
            and _tlp.allows(c, self._tlp[d.id])
            and (q.include_inactive or _m.is_active(d.status))
        ]
        visible.sort(key=lambda d: d.id)  # index order must not reach a float sum
        scores = self._text_scores(q.text, words, visible)
        dist = self._distances(visible, q.seeds)
        hits: list[Hit] = []
        for d in visible:
            if q.kinds is not None and d.kind not in q.kinds:
                continue
            kw = scores.get(d.id, 0.0)
            if d.id in dist:
                score = (MAX_DEPTH + 1 - dist[d.id]) + kw
            elif kw > 0:
                score = kw
            else:
                continue
            hits.append(_hit(d, round(score, 9), words))
        hits.sort(key=lambda h: (-h.score, h.id))
        return hits[: q.budget]

    # -- scoring -------------------------------------------------------------------------------
    def _reader(self, ceiling: str | _tlp.Label | None) -> _tlp.Label:
        if ceiling is None:
            return self._ceiling
        return ceiling if isinstance(ceiling, _tlp.Label) else _tlp.parse(ceiling)

    def _sparse(self, visible: list[Document]) -> tuple[object, Counter[str], int]:
        from txtai.scoring import ScoringFactory

        key = tuple(sorted(d.id for d in visible))
        got = self._sparse_cache.get(key)
        if got is None:
            idx = ScoringFactory.create({"method": "bm25", "terms": True})
            texts = [f"{d.id} {d.title} {d.content}" for d in visible]
            idx.index([(d.id, t, None) for d, t in zip(visible, texts, strict=True)])
            df: Counter[str] = Counter()
            for t in texts:
                df.update({w.lower() for w in _WORD.findall(t)})
            if len(self._sparse_cache) >= 8:
                self._sparse_cache.clear()
            got = self._sparse_cache[key] = (idx, df, len(visible))
        return got

    def _text_scores(
        self, text: str, words: list[str], visible: list[Document]
    ) -> dict[str, float]:
        """In [0, 1): fused BM25 and cosine for the visible documents that clear the cut-off."""
        if not words or not visible:
            return {}
        sparse: dict[str, float] = {}
        idx, df, n = self._sparse(visible)
        # words in over half of a sizeable corpus carry no signal (the corpus's own stop words)
        rare = [w for w in words if n < _MIN_DOCS_FOR_STOP or df.get(w, 0) <= n * _STOP_SHARE]
        found = idx.search(" ".join(rare), len(visible)) if rare else []
        top = max((s for _, s in found), default=0.0)
        if top > 0:
            sparse = {str(i): round(s / top, 6) for i, s in found if s > 0}
        qv = self._emb.batchtransform([text[:EMBED_CHARS]])[0]
        out: dict[str, float] = {}
        for d in visible:
            # batch padding moves the last float bits of a vector; five places hide that
            cos = round(max(0.0, float(qv @ self._vec[d.id])), 5)
            sp = sparse.get(d.id, 0.0)
            if sp <= 0 and cos < self._min_sim:
                continue
            fused = min(0.999, (1 - self._w) * sp + self._w * cos)
            if fused >= self._min_score:  # the abstention cut-off: 0 keeps everything
                out[d.id] = fused
        return out


def _embed_text(d: Document) -> str:
    return f"{d.title}\n{d.content}"[:EMBED_CHARS]


def make(
    model_dir: str | None = None,
    ceiling: str = "red",
    dense_weight: float = 0.5,
    min_similarity: float = 0.36,
    min_score: float = 0.0,
) -> SemanticContextStore:
    """The factory a conformance target names: ``adapter: homelabnext.context.semantic:make``.

    ``model_dir`` defaults to the environment variable ``HNX_CONTEXT_MODEL_DIR``."""
    model_dir = model_dir or os.environ.get("HNX_CONTEXT_MODEL_DIR", "")
    if not model_dir:
        raise SemanticUnavailable("set model_dir or HNX_CONTEXT_MODEL_DIR to the pinned model")
    return SemanticContextStore(
        model_dir,
        ceiling=ceiling,
        dense_weight=dense_weight,
        min_similarity=min_similarity,
        min_score=min_score,
    )
