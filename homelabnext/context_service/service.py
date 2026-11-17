# SPDX-License-Identifier: Apache-2.0
"""The retrieval service behind the HTTP routes: one semantic ``context`` store, kept current from
the configured sources, read at each caller's TLP ceiling, optionally gated by a judge.

* **One store, every label.**  The store holds every indexed item at its label and is built with
  the ceiling ``red``; each read passes the *caller's* ceiling, which the store can only lower
  (:class:`~homelabnext.context_semantic.SemanticContextStore`), so an item above a reader's
  ceiling is as absent as one that does not exist: not a hit, not a ``get``, not in BM25 statistics.
* **Reindex** fetches every source, collects its documents, and then, under the store's lock,
  indexes them (only changed documents are embedded again), removes what no source holds any more,
  and first drops any document whose *label* changed with its content unchanged (the store would
  keep the old label otherwise).  Fetching and reading happen before the lock, so a failed fetch or
  a malformed source leaves the index exactly as it was.  A failure of the indexing itself (the
  embedder) also leaves it as it was **except** that the documents whose label changed in that run
  stay dropped until the next successful run: the failure is closed (such a document is absent,
  never readable at its old label), and the run's report counts them (``relabel_dropped``).  The
  run's record is written to ``<data>/state/last-reindex.json``.
* **Every hit is checked again under the store's lock** before it is answered: its label is read
  in the same critical section and a hit that a concurrent reindex removed or raised above the
  reader's ceiling is dropped (never a 500, never content above the ceiling).
* **The judge** (optional; on when the configuration names one) is the abstention gate of
  :class:`~homelabnext.context.judge.JudgedStore` around the locked store: the store's order is kept,
  and a query abstains when no top passage clears the threshold.  The gateway request carries the
  caller's question as well as the passage, and the question is unlabelled data at the caller's
  tier, so the label sent (``X-HNX-TLP``) is the request's **effective ceiling** (the strictest of
  the passage's label and the ceiling, which is the ceiling: every passage is at or below it).  A
  request whose effective ceiling is above the judge's ceiling is never sent: the judge's
  ``on_error`` policy decides (``fallback``: the store's own ranking, unjudged; ``abstain``:
  nothing); a caller that wants the gate lowers ``ceiling`` on its request, declaring its question
  to be at that tier.  The gate runs outside the lock (a judged query takes seconds).
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from homelabnext import tlp as _tlp
from homelabnext.context import Hit, NotFound, Query
from homelabnext.context.judge import GatewayJudge, Judge, JudgedStore, JudgeError
from homelabnext.context.model import Document
from homelabnext.state import atomic_write_text

from .config import Caller, Config
from .sources import Collected, SourceError, collect, sync

__all__ = ["ContextService", "ReindexBusy", "make_judge", "make_store"]

StoreFactory = Callable[[Callable[[Document], _tlp.Label]], Any]


class ReindexBusy(RuntimeError):
    """A reindex is already running."""


def make_store(cfg: Config) -> StoreFactory:
    """The production store factory: the semantic adapter over the pinned model directory."""

    def build(tlp_of: Callable[[Document], _tlp.Label]):
        from homelabnext.context_semantic import SemanticContextStore

        return SemanticContextStore(
            cfg.model_dir,
            ceiling=_tlp.Label.RED,
            tlp_of=tlp_of,
            dense_weight=cfg.dense_weight,
            min_similarity=cfg.min_similarity,
            min_score=cfg.min_score,
        )

    return build


def make_judge(cfg: Config, env: Mapping[str, str]) -> Judge | None:
    """The gateway judge the configuration names, or ``None`` (the gate is off)."""
    j = cfg.judge
    if j is None:
        return None
    from homelabnext.conform.adapters.openai_compat import OpenAICompat

    key = env.get(j.key_env, "")
    if not key or any(c.isspace() for c in key):
        raise ValueError("the judge's gateway key is not set")
    client = OpenAICompat(
        j.url,
        auth=lambda: f"Bearer {key}",
        timeout=j.timeout,
        features=(),
        allow_plaintext=j.allow_plaintext,
    )
    return GatewayJudge(client, model=j.role, tag=j.tag, threshold=j.threshold)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class _Locked:
    """The store, one call at a time (reindex mutates it while readers query)."""

    def __init__(self, store: Any, lock: threading.RLock) -> None:
        self._store, self._lock = store, lock
        self.features = frozenset(getattr(store, "features", ()))

    def query(self, q: Query, **kw: Any) -> list[Hit]:
        with self._lock:
            return self._store.query(q, **kw)

    def tlp(self, doc_id: str) -> _tlp.Label:
        with self._lock:
            return self._store.tlp(doc_id)


@dataclass
class _Run:
    ok: bool
    report: dict[str, Any]


class ContextService:
    def __init__(
        self,
        cfg: Config,
        *,
        env: Mapping[str, str] | None = None,
        store_factory: StoreFactory | None = None,
        judge: Judge | None = None,
        runner: Callable[..., Any] | None = None,
        clock: Callable[[], str] = _now,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.cfg = cfg
        self._env = dict(os.environ if env is None else env)
        self._labels: dict[str, _tlp.Label] = {}
        self._lock = threading.RLock()
        self._reindexing = threading.Lock()
        self._store = (store_factory or make_store(cfg))(lambda d: self._labels[d.id])
        self._locked = _Locked(self._store, self._lock)
        self._judge = judge if judge is not None else make_judge(cfg, self._env)
        self._runner = runner
        self._clock = clock
        self.monotonic = monotonic
        self._ids: set[str] = set()
        self.last: dict[str, Any] | None = None
        self.indexed_once = False
        #: time.monotonic() when the last reindex finished (the routes' rate limit reads it)
        self.last_finished: float | None = None
        self._relabel_dropped = 0

    # -- state --------------------------------------------------------------------------------
    @property
    def judge_on(self) -> bool:
        return self._judge is not None

    @property
    def documents(self) -> int:
        with self._lock:
            return len(self._ids)

    def _sources_dir(self) -> Path:
        return self.cfg.data_dir / "sources"

    def _record(self, report: dict[str, Any]) -> None:
        state = self.cfg.data_dir / "state"
        state.mkdir(parents=True, exist_ok=True)
        text = json.dumps(report, sort_keys=True, indent=1) + "\n"
        atomic_write_text(state / "last-reindex.json", text, mode=0o640)

    # -- reindex ------------------------------------------------------------------------------
    def reindex(self, *, fetch: bool = True) -> dict[str, Any]:
        """Fetch (unless ``fetch`` is false: the checkouts already on disk), collect and index.
        Returns the run's report (``ok`` false on a failure, the index then unchanged)."""
        if not self._reindexing.acquire(blocking=False):
            raise ReindexBusy("a reindex is already running")
        try:
            run = self._reindex(fetch)
        finally:
            self.last_finished = self.monotonic()
            self._reindexing.release()
        self.last = run.report
        try:
            self._record(run.report)
        except OSError:
            run.report["record_error"] = True
        return run.report

    def _reindex(self, fetch: bool) -> _Run:
        started = self._clock()
        report: dict[str, Any] = {"started_at": started, "fetched": fetch, "sources": {}}
        collected: list[tuple[Document, _tlp.Label]] = []
        self._relabel_dropped = 0
        try:
            for s in self.cfg.sources:
                if fetch:
                    kw: dict[str, Any] = {
                        "env": self._env,
                        "git": self.cfg.git,
                        "timeout": self.cfg.git_timeout,
                    }
                    if self._runner is not None:
                        kw["runner"] = self._runner
                    checkout, commit = sync(s, self._sources_dir(), **kw)
                else:
                    checkout, commit = self._sources_dir() / s.name, ""
                    if not checkout.is_dir() or checkout.is_symlink():
                        raise SourceError(f"source {s.name}: no checkout on disk yet")
                got: Collected = collect(checkout, s)
                collected.extend(got.documents)
                report["sources"][s.name] = {
                    "commit": commit,
                    "documents": len(got.documents),
                    "skipped": got.skipped,
                }
            ids = [d.id for d, _ in collected]
            if len(set(ids)) != len(ids):
                raise SourceError("two sources produce the same document id")
            changes = self._apply(collected)
        except (SourceError, ValueError) as exc:
            report.update(ok=False, error=str(exc), finished_at=self._clock())
            return _Run(False, report)
        except Exception as exc:  # the store's own failure (the embedder): the index is unchanged
            report.update(ok=False, error=f"indexing failed ({type(exc).__name__})")
            report["relabel_dropped"] = self._relabel_dropped
            report["finished_at"] = self._clock()
            return _Run(False, report)
        report.update(ok=True, documents=len(collected), finished_at=self._clock(), **changes)
        self.indexed_once = True
        return _Run(True, report)

    def _apply(self, collected: list[tuple[Document, _tlp.Label]]) -> dict[str, int]:
        docs = [d for d, _ in collected]
        new_labels = {d.id: label for d, label in collected}
        with self._lock:
            relabel = [
                i for i in self._ids if i in new_labels and self._store.tlp(i) != new_labels[i]
            ]
            # a document whose label changed is dropped first, so it never keeps a stale label
            for i in sorted(relabel):
                self._store.delete(i)
                self._ids.discard(i)
            self._relabel_dropped = len(relabel)
            self._labels = dict(new_labels)
            rep = self._store.index(docs)
            gone = sorted(self._ids - set(new_labels))
            for i in gone:
                self._store.delete(i)
            self._ids = set(new_labels)
        return {
            "added": len(rep.added),
            "replaced": len(rep.replaced),
            "unchanged": len(rep.unchanged),
            "removed": len(gone),
            "relabelled": len(relabel),
        }

    # -- reads --------------------------------------------------------------------------------
    @staticmethod
    def ceiling(caller: Caller, asked: str | None) -> _tlp.Label:
        """The caller's ceiling, or a lower one it asks for; never a higher one."""
        if asked is None:
            return caller.ceiling
        return min(caller.ceiling, _tlp.parse(asked))

    def judged_at(self, ceiling: _tlp.Label) -> bool:
        """Whether a query read at ``ceiling`` is put to the judge: the judge is on and the
        request's label (its effective ceiling) is within the judge's ceiling."""
        return self._judge is not None and _tlp.allows(self.cfg.judge.ceiling, ceiling)

    def query(self, q: Query, ceiling: _tlp.Label) -> tuple[list[Hit], list[_tlp.Label]]:
        """Hits at ``ceiling`` with their labels, each re-checked under the lock."""
        if self._judge is not None:
            j = self.cfg.judge
            gate = JudgedStore(
                self._locked,
                self._judge,
                top_k=j.top_k,
                threshold=j.threshold,
                # the label of what the gateway receives: the passage AND the caller's question
                tlp_of=lambda _doc_id: ceiling,
                judge_ceiling=j.ceiling,
                on_error=j.on_error,
                workers=j.workers,
            )
            hits = gate.query(q, ceiling=ceiling)
        else:
            hits = self._locked.query(q, ceiling=ceiling)
        out: list[Hit] = []
        labels: list[_tlp.Label] = []
        with self._lock:
            for h in hits:
                try:
                    label = self._store.tlp(h.id)
                except NotFound:
                    continue  # removed by a reindex since the store answered
                if not _tlp.allows(ceiling, label):
                    continue  # raised above the reader's ceiling since the store answered
                out.append(h)
                labels.append(label)
        return out, labels

    def get(
        self, doc_id: str, allowed: frozenset[str], ceiling: _tlp.Label
    ) -> tuple[Hit, _tlp.Label]:
        with self._lock:
            hit = self._store.get(doc_id, allowed, ceiling=ceiling)
            return hit, self._store.tlp(doc_id)

    def check(self) -> dict[str, Any]:
        """The canned query finds its known item; with the judge on, the judge answers that the
        item answers it.  ``ok`` is false otherwise, with the reason.  Also the index's size and
        the last reindex's outcome (``/ready`` shows them to an authenticated caller only)."""
        h = self.cfg.health
        out: dict[str, Any] = {
            "ok": False,
            "judge": {"on": self.judge_on},
            "documents": self.documents,
            "last_reindex_ok": bool((self.last or {}).get("ok")),
        }
        if not self.indexed_once:
            out["reason"] = "not indexed yet"
            return out
        namespace = h.expect.split(":", 1)[0] + ":"
        q = Query(allowed=frozenset({namespace}), text=h.text, budget=h.top)
        hits = self._locked.query(q, ceiling=h.ceiling)
        ids = [x.id for x in hits]
        if h.expect not in ids:
            out["reason"] = "the canned query did not find its item"
            out["found"] = len(ids)
            return out
        out["rank"] = ids.index(h.expect) + 1
        if self._judge is not None:
            hit = hits[ids.index(h.expect)]
            # what is sent: the canned question (at the health query's ceiling) and the passage
            label = _tlp.strictest([self._locked.tlp(hit.id), h.ceiling])
            if not _tlp.allows(self.cfg.judge.ceiling, label):
                out["reason"] = "the canned query's ceiling is above the judge's ceiling"
                return out
            try:
                v = self._judge.judge(h.text, hit, label)
            except JudgeError as exc:
                out["reason"] = f"the judge did not answer ({exc})"
                return out
            out["judge"].update(answers=v.answers, confidence=round(v.confidence, 4))
            if not v.answers:
                out["reason"] = "the judge did not clear the canned item"
                return out
        out["ok"] = True
        return out

    def ready(self) -> dict[str, Any]:
        last = self.last or {}
        return {
            "ready": self.indexed_once and self.documents > 0,
            "documents": self.documents,
            "judge": self.judge_on,
            "last_reindex": {
                k: last.get(k) for k in ("ok", "started_at", "finished_at", "documents", "fetched")
            },
        }
