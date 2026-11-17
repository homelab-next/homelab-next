# SPDX-License-Identifier: Apache-2.0
"""An optional abstention gate (and opt-in reranker): ask a small model whether a passage answers the question.

:class:`JudgedStore` wraps any ``context`` store.  Its default mode is ``gate``: the store's own
ranking is kept, the best ``top_k`` hits are put to a :class:`Judge` ("does this passage answer
the question?", a probability), and the query abstains (returns ``[]``) when none of them reaches
``threshold``.  The gate needs only one passage to clear, so the calls run concurrently (``workers``)
and stop at the first that does.  Mode ``rerank`` instead keeps the hits judged yes and orders them
by the judge's confidence.  The judge only drops or reorders what the store, already scoped and
TLP-filtered, returned; it can never add a document.

Why the gate is the default (live eval 2026-11-16, the fast-classifier decision model on
``/v1/systemone``, T = 0.10, state "Question: ...\nPassage: ..."): as a gate it took abstain recall
from 0% to 100% with 100% precision and no lost hit on a private set of 32 answerable and 6
no-answer questions (hit@1 94%, hit@5 100%, unchanged), and on the public fixture (23 and 6) from 17% to 100% at
no hit@5 cost, one wrong abstain on a question the store already missed.  As a reranker it was
worse than the store's own order (hit@1 94% to 91% private, 74% to 65% public).  Cost: about 3 s
a call, so 15 to 20 s a query when five passages are judged one after another; hence the
concurrency and the early stop.  Only six no-answer questions per set: re-check on a larger set.

Judges:

* :class:`GatewayJudge` asks a decision role (``fast-classifier`` by default, ``kind: decision``)
  through the LLM gateway's ``POST /v1/systemone``: the state is "Question: <q>\nPassage: <p>", the
  noul question "Does this passage answer the question?", the returned probability the confidence.
  The passage is cut to ``max_chars`` (1400; or ``max_tokens`` when a ``count_tokens`` estimate is
  given) to stay under the decision server's batch limit (LL-492), and shrunk once and retried on
  an HTTP 500 or 502 (the gateway's view of a backend 5xx).  ``X-HNX-TLP`` is set to the strictest label of what it sends and an ``X-HNX-Tag`` so the turn is attributable (ADR-0033, ADR-0038).  A backend that
  misbehaves raises :class:`JudgeError`; the judge never guesses a verdict.
* :class:`RecordedJudge` replays verdicts recorded earlier (a JSON file keyed by the sha256 of
  question and passage), so CI exercises the whole path with no model.  A pair that was never
  recorded raises :class:`JudgeError` rather than inventing an answer.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from homelabnext import tlp as _tlp
from homelabnext.conform.adapters.openai_compat import InferenceError, OpenAICompat

from .model import Hit, Query

__all__ = [
    "GatewayJudge",
    "Judge",
    "JudgeError",
    "JudgedStore",
    "RecordedJudge",
    "Verdict",
    "pair_key",
]

PASSAGE_CHARS = 1500


class JudgeError(Exception):
    """The judge could not give a verdict (backend error, bad reply, an unrecorded pair)."""


@dataclass(frozen=True)
class Verdict:
    answers: bool
    confidence: float


class Judge(Protocol):
    def judge(self, question: str, hit: Hit, tlp: _tlp.Label) -> Verdict: ...


def pair_key(question: str, passage: str) -> str:
    h = hashlib.sha256()
    h.update(question.encode("utf-8", "surrogatepass"))
    h.update(b"\0")
    h.update(passage.encode("utf-8", "surrogatepass"))
    return h.hexdigest()


QUESTION = "Does this passage answer the question?"
#: the passage cut that keeps a call under the decision server's batch limit (about 500 tokens, LL-492)
MAX_CHARS = 1400
MAX_TOKENS = 450
_SHRINK = 0.6


def _state(question: str, passage: str) -> str:
    return f"Question: {question}\nPassage: {passage}"


class GatewayJudge:
    """Asks a decision role (``kind: decision``, ``POST /v1/systemone``) one noul question per
    passage: the returned probability is the confidence, and the passage answers when it is at
    least ``threshold`` (default 0.10: the live eval's no-answer maximum was 0.083, the weakest
    answerable one 0.638)."""

    def __init__(
        self,
        client: OpenAICompat,
        *,
        model: str = "fast-classifier",
        tag: str,
        threshold: float = 0.10,
        max_chars: int = MAX_CHARS,
        max_tokens: int = MAX_TOKENS,
        count_tokens: Callable[[str], int] | None = None,
    ):
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold is a probability")
        self._client, self._model, self._tag, self._threshold = client, model, tag, threshold
        self._max_chars, self._max_tokens, self._count = max_chars, max_tokens, count_tokens

    def _cut(self, text: str) -> str:
        """``text`` cut to ``max_tokens`` when a token estimate is known, else to ``max_chars``."""
        text = text[: self._max_chars]
        if self._count is not None:
            while len(text) > 1 and self._count(text) > self._max_tokens:
                text = text[: int(len(text) * _SHRINK)]
        return text

    def _ask(self, question: str, passage: str, fields) -> float:
        got = self._client.decide_fields(
            self._model, {"q": QUESTION}, fields, state=_state(question, passage)
        )
        return got["q"]

    def judge(self, question: str, hit: Hit, tlp: _tlp.Label) -> Verdict:
        fields = [("X-HNX-TLP", str(tlp)), ("X-HNX-Tag", self._tag)]
        passage = self._cut(hit.content)
        try:
            try:
                p = self._ask(question, passage, fields)
            except InferenceError as exc:
                if exc.status not in (500, 502):
                    raise
                # the decision server's batch limit (LL-492; the gateway shows a backend 5xx as
                # 502): shrink the passage and retry once
                p = self._ask(question, passage[: max(1, int(len(passage) * _SHRINK))], fields)
        except Exception as exc:  # the client's own error types vary by transport
            raise JudgeError(f"gateway call failed ({type(exc).__name__})") from exc
        return Verdict(p >= self._threshold, p)


class RecordedJudge:
    def __init__(self, recordings: Mapping[str, tuple[bool, float]]):
        self._rec = dict(recordings)

    @classmethod
    def load(cls, path: str | Path) -> RecordedJudge:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls({k: (bool(v[0]), float(v[1])) for k, v in raw.items()})

    def judge(self, question: str, hit: Hit, tlp: _tlp.Label) -> Verdict:
        got = self._rec.get(pair_key(question, hit.content[:PASSAGE_CHARS]))
        if got is None:
            raise JudgeError("no recorded verdict for this question and passage")
        return Verdict(*got)


class JudgedStore:
    """``store`` plus a judge: by default abstain when no top hit answers (``gate``, the store's
    ranking kept); with ``mode="rerank"`` keep the hits judged yes ordered by confidence."""

    features: frozenset[str] = frozenset()

    def __init__(
        self,
        store,
        judge: Judge,
        *,
        top_k: int = 5,
        threshold: float = 0.10,
        tlp_of=None,
        judge_ceiling: _tlp.Label | None = None,
        on_error: str = "fallback",
        mode: str = "gate",
        workers: int = 2,
    ) -> None:
        """``judge_ceiling`` is the most restrictive label the judge's endpoint may receive: a
        passage above it is never sent.  ``on_error`` says what a judge failure (backend error,
        bad reply, an unrecorded pair, a passage above the ceiling) does to the query:
        ``fallback`` returns the store's own ranking, ``abstain`` returns nothing.  ``workers``
        bounds the concurrent judge calls (the decision server's parallel slots)."""
        if on_error not in ("fallback", "abstain"):
            raise ValueError("on_error is 'fallback' or 'abstain'")
        if mode not in ("gate", "rerank"):
            raise ValueError("mode is 'gate' or 'rerank'")
        if workers < 1:
            raise ValueError("workers is at least 1")
        self._judge_ceiling, self._on_error = judge_ceiling, on_error
        self._mode, self._workers = mode, workers
        self._store, self._judge = store, judge
        self._top_k, self._threshold = top_k, threshold
        # the label sent with a passage: the store's own when it keeps one, else red
        self._tlp_of = tlp_of or getattr(store, "tlp", lambda _id: _tlp.Label.RED)
        self.features = frozenset(getattr(store, "features", ()))

    def __getattr__(self, name: str):
        return getattr(self._store, name)

    def _labels(self, head: list[Hit]) -> list:
        out = []
        for h in head:
            label = _tlp.read(self._tlp_of(h.id))
            if self._judge_ceiling is not None and not _tlp.allows(self._judge_ceiling, label):
                raise JudgeError("passage is above the judge's TLP ceiling")
            out.append(label)
        return out

    def _verdicts(self, q: Query, head: list[Hit], labels: list, *, stop_on_clear: bool):
        """``{rank: Verdict}`` for ``head``, the calls at most ``workers`` at a time.  With
        ``stop_on_clear`` the first verdict that clears the threshold ends the run: calls not yet
        started are skipped, and a failure of a call still running after one cleared is ignored.
        Any other judge error raises."""
        got: dict[int, Verdict] = {}
        stop = threading.Event()

        def ask(h: Hit, label) -> Verdict | None:
            if stop.is_set():
                return None  # a passage already cleared: this one is never sent
            v = self._judge.judge(q.text, h, label)
            if stop_on_clear and v.answers and v.confidence >= self._threshold:
                stop.set()
            return v

        ex = ThreadPoolExecutor(max_workers=self._workers)
        try:
            futs = {
                ex.submit(ask, h, lb): i for i, (h, lb) in enumerate(zip(head, labels, strict=True))
            }
            for f in as_completed(futs):
                try:
                    v = f.result()
                except JudgeError:
                    if stop.is_set():
                        continue  # a passage already cleared: a sibling's failure cannot undo it
                    raise
                if v is not None:
                    got[futs[f]] = v
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
        return got

    def query(self, q: Query, **kw) -> list[Hit]:
        hits = self._store.query(q, **kw)
        head = hits[: self._top_k]
        gate = self._mode == "gate"
        try:
            got = self._verdicts(q, head, self._labels(head), stop_on_clear=gate)
        except JudgeError:
            return [] if self._on_error == "abstain" else hits[: q.budget]
        kept = [
            (v.confidence, rank, head[rank])
            for rank, v in got.items()
            if v.answers and v.confidence >= self._threshold
        ]
        if not kept:
            return []
        if gate:
            return hits[: q.budget]
        kept.sort(key=lambda t: (-t[0], t[1]))
        ordered = [h for _, _, h in kept]
        # scores must stay descending for the contract's ordering rule
        n = len(ordered)
        out = [
            Hit(h.id, h.kind, h.title, h.path, float(n - i), h.snippet, h.content, h.digest)
            for i, h in enumerate(ordered)
        ]
        return out[: q.budget]
