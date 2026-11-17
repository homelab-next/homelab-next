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
(``tlp_of(document)``; the default is :func:`default_tlp_of`: the strictest of every TLP marker in
the title and content, ``red`` when there is none, so an unlabelled item hides rather than
leaks).  A query is answered for the reader ``ceiling`` given at construction (required: there is
no default): a document above it is exactly as absent as one outside ``allowed``, from hits, from
``get`` and from the BM25 statistics.  A call may *lower* the ceiling (``query(q,
ceiling=...)``) but never raise it; a higher ceiling is a different store, built by a trusted
caller.  ``index`` is all-or-nothing: vectors and labels are computed first and the batch is
committed only if both succeed, so a document never exists without its label.

Needs the optional extra ``context-semantic`` (txtai, which brings torch); importing this module
without it works, constructing the store raises :class:`SemanticUnavailable`.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from collections.abc import Callable, Sequence
from contextvars import ContextVar
from pathlib import Path
from typing import Protocol

from homelabnext import tlp as _tlp
from homelabnext.context import ContextStore
from homelabnext.context import model as _m
from homelabnext.context.model import Document, Hit, IndexReport, NotFound, Query
from homelabnext.context.semantic_model import check_dir

__all__ = ["SemanticContextStore", "SemanticUnavailable", "default_tlp_of", "make"]

_READING: ContextVar[_tlp.Label | None] = ContextVar("context_reader_ceiling", default=None)
_WORD = re.compile(r"\w+")
_MIN_DOCS_FOR_STOP = 20
_STOP_SHARE = 0.5
#: the longest text embedded per document (the model reads ~256 word pieces anyway)
EMBED_CHARS = 2000


class Embedder(Protocol):
    def batchtransform(self, texts: Sequence[str]) -> Sequence[Sequence[float]]: ...


class SemanticUnavailable(RuntimeError):
    """The optional ``context-semantic`` extra is not installed."""


def default_tlp_of(doc: Document) -> _tlp.Label:
    """The label a document carries: the strictest TLP marker anywhere in its title or content.

    The marker grammar is the platform's (:func:`homelabnext.tlp.markers`: ``TLP:RED``,
    ``[TLP=AMBER]``, ``tlp: clear``, ...), read over the whole text, so ``tlp: clear`` followed
    later by ``tlp: red`` is ``red``.  No marker is ``red`` (unlabelled).  A document that only
    *quotes* a marker (for example a page about TLP showing ``tlp: clear``) cannot be told from
    one that carries it, so it takes that label: authors who need otherwise pass their own
    ``tlp_of`` (a source's declared label); the conservative default is for the strictest marker,
    never the first.
    """
    found = _tlp.markers([doc.title, doc.content])
    return _tlp.strictest(found) if found else _tlp.Label.RED


class SemanticContextStore(ContextStore):
    features: frozenset[str] = frozenset({"semantic"})

    def __init__(
        self,
        model_dir: str | Path | None = None,
        *,
        ceiling: str | _tlp.Label,
        tlp_of: Callable[[Document], _tlp.Label] = default_tlp_of,
        dense_weight: float = 0.5,
        min_similarity: float = 0.36,
        min_score: float = 0.0,
        embedder: Embedder | None = None,
        sparse_factory: Callable[[], object] | None = None,
    ) -> None:
        """``ceiling`` is the reader's TLP ceiling and has no default.  ``embedder`` and
        ``sparse_factory`` are test seams (an object with ``batchtransform(texts)`` and a factory
        of objects with ``index(rows)`` / ``search(query, limit)``); production leaves both out
        and gets txtai's embeddings, from the verified ``model_dir``, and its BM25."""
        super().__init__()
        if not 0.0 <= dense_weight <= 1.0:
            raise ValueError("dense_weight must be in [0, 1]")
        if embedder is None:
            if model_dir is None:
                raise ValueError("model_dir is required without an embedder")
            self._model_dir = check_dir(model_dir)  # verified by sha256 before anything loads
            # the model is never fetched here: provisioning is semantic_model.fetch
            os.environ["HF_HUB_OFFLINE"] = "1"
            os.environ["TRANSFORMERS_OFFLINE"] = "1"
            try:
                from txtai import Embeddings
            except ImportError as exc:  # pragma: no cover - exercised only without the extra
                raise SemanticUnavailable(
                    "install the 'context-semantic' extra (txtai) to use the semantic adapter"
                ) from exc
            embedder = Embeddings(path=str(self._model_dir))
        self._emb = embedder
        self._sparse_factory = sparse_factory
        self._ceiling = _label(ceiling)
        self._tlp_of = tlp_of
        self._w = dense_weight
        self._min_sim = min_similarity
        self._min_score = min_score
        self._vec: dict[str, Sequence[float]] = {}
        self._tlp: dict[str, _tlp.Label] = {}
        self._sparse_cache: dict[tuple[str, ...], tuple[object, Counter[str], int]] = {}

    # -- indexer -------------------------------------------------------------------------------
    def index(self, docs: Sequence[Document]) -> IndexReport:
        batch = _m.check_documents(docs)
        changed = [d for d in batch if self._docs.get(d.id) != d]
        # everything that can fail runs before anything is stored: a failure leaves the index
        # exactly as it was, never a document without its vector or label, never a stale label
        vecs = self._emb.batchtransform([_embed_text(d) for d in changed]) if changed else []
        labels = [_tlp.read(self._tlp_of(d)) for d in changed]
        if len(vecs) != len(changed):
            raise _m.InvalidDocument("the embedder returned the wrong number of vectors")
        report = super().index(batch)
        for d, v, label in zip(changed, vecs, labels, strict=True):
            self._vec[d.id] = v
            self._tlp[d.id] = label
        if changed:
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
    def get(
        self, doc_id: str, allowed: frozenset[str], *, ceiling: str | _tlp.Label | None = None
    ) -> Hit:
        c = self._reader(ceiling)
        hit = super().get(doc_id, allowed)
        if not _tlp.allows(c, self._tlp[doc_id]):
            raise NotFound(f"no document {doc_id!r} in scope")
        return hit

    def query(self, q: Query, *, ceiling: str | _tlp.Label | None = None) -> list[Hit]:
        token = _READING.set(self._reader(ceiling))  # per call and per thread, never shared
        try:
            return super().query(q)
        finally:
            _READING.reset(token)

    def _visible(self, q: Query) -> list[Document]:
        c = _READING.get() or self._ceiling
        seen = [d for d in super()._visible(q) if _tlp.allows(c, self._tlp[d.id])]
        seen.sort(key=lambda d: d.id)  # index order must not reach a float sum
        return seen

    # -- scoring -------------------------------------------------------------------------------
    def _reader(self, ceiling: str | _tlp.Label | None) -> _tlp.Label:
        """The constructor's ceiling, or a lower one asked for; never a higher one."""
        if ceiling is None:
            return self._ceiling
        return min(self._ceiling, _label(ceiling))

    def _sparse(self, visible: list[Document]) -> tuple[object, Counter[str], int]:
        key = tuple(sorted(d.id for d in visible))
        got = self._sparse_cache.get(key)
        if got is None:
            if self._sparse_factory is not None:
                idx = self._sparse_factory()
            else:
                from txtai.scoring import ScoringFactory

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
        self, q: Query, words: Sequence[str], visible: list[Document]
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
        qv = self._emb.batchtransform([q.text[:EMBED_CHARS]])[0]
        out: dict[str, float] = {}
        for d in visible:
            # batch padding moves the last float bits of a vector; five places hide that
            cos = round(max(0.0, _dot(qv, self._vec[d.id])), 5)
            sp = sparse.get(d.id, 0.0)
            if sp <= 0 and cos < self._min_sim:
                continue
            fused = min(0.999, (1 - self._w) * sp + self._w * cos)
            if fused >= self._min_score:  # the abstention cut-off: 0 keeps everything
                out[d.id] = fused
        return out


def _label(value: str | _tlp.Label) -> _tlp.Label:
    return value if isinstance(value, _tlp.Label) else _tlp.parse(value)


def _dot(a: Sequence[float], b: Sequence[float]) -> float:
    try:
        return float(a @ b)  # type: ignore[operator]  # numpy vectors
    except TypeError:
        return float(sum(x * y for x, y in zip(a, b, strict=True)))


def _embed_text(d: Document) -> str:
    return f"{d.title}\n{d.content}"[:EMBED_CHARS]


def make(
    model_dir: str | None = None,
    ceiling: str = "clear",
    dense_weight: float = 0.5,
    min_similarity: float = 0.36,
    min_score: float = 0.0,
) -> SemanticContextStore:
    """The factory a conformance target names: ``adapter: homelabnext.context_semantic:make``.

    ``model_dir`` defaults to the environment variable ``HNX_CONTEXT_MODEL_DIR``.  The target
    file gives the ceiling its suite documents carry (they are unlabelled, so ``red``) explicitly."""
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
