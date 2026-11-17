# SPDX-License-Identifier: Apache-2.0
"""An optional rerank-and-abstain step: ask a small model whether a passage answers the question.

:class:`JudgedStore` wraps any ``context`` store.  For a query it takes the store's best
``top_k`` hits, asks a :class:`Judge` of each ("does this passage answer the question?", yes or
no with a confidence), keeps the ones judged yes at or above ``threshold``, orders them by
confidence (the store's own order breaks ties) and returns ``[]`` when none qualifies: that is
the abstention.  The judge only reorders and drops what the store, already scoped and
TLP-filtered, returned; it can never add a document.

Judges:

* :class:`GatewayJudge` asks a decision role (``fast-classifier`` by default, ``kind: decision``)
  through the LLM gateway's ``POST /v1/systemone`` ("Does this passage answer the question: ...?"
  as a noul question; the returned probability is the confidence), with ``X-HNX-TLP`` set to the strictest label of what it
  sends and an ``X-HNX-Tag`` so the turn is attributable (ADR-0033, ADR-0038).  A backend that
  misbehaves raises :class:`JudgeError`; the judge never guesses a verdict.
* :class:`RecordedJudge` replays verdicts recorded earlier (a JSON file keyed by the sha256 of
  question and passage), so CI exercises the whole path with no model.  A pair that was never
  recorded raises :class:`JudgeError` rather than inventing an answer.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from homelabnext import tlp as _tlp
from homelabnext.conform.adapters.openai_compat import OpenAICompat

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


def _question(question: str, passage: str) -> str:
    return f"Does this passage answer the question: {question}?\n\nPASSAGE:\n{passage}"


class GatewayJudge:
    """Asks a decision role (``kind: decision``, ``POST /v1/systemone``) one noul question per
    passage: the returned probability is the confidence, and the passage answers when it is at
    least ``threshold``."""

    def __init__(
        self,
        client: OpenAICompat,
        *,
        model: str = "fast-classifier",
        tag: str,
        threshold: float = 0.5,
    ):
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold is a probability")
        self._client, self._model, self._tag, self._threshold = client, model, tag, threshold

    def judge(self, question: str, hit: Hit, tlp: _tlp.Label) -> Verdict:
        try:
            got = self._client.decide_fields(
                self._model,
                {"q": _question(question, hit.content[:PASSAGE_CHARS])},
                [("X-HNX-TLP", str(tlp)), ("X-HNX-Tag", self._tag)],
            )
            p = got["q"]
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
    """``store`` plus a judge: rerank the top hits by verdict, abstain when none answers."""

    features: frozenset[str] = frozenset()

    def __init__(
        self,
        store,
        judge: Judge,
        *,
        top_k: int = 5,
        threshold: float = 0.5,
        tlp_of=None,
        judge_ceiling: _tlp.Label | None = None,
        on_error: str = "fallback",
    ) -> None:
        """``judge_ceiling`` is the most restrictive label the judge's endpoint may receive: a
        passage above it is never sent.  ``on_error`` says what a judge failure (backend error,
        bad reply, an unrecorded pair, a passage above the ceiling) does to the query:
        ``fallback`` returns the store's own ranking, ``abstain`` returns nothing."""
        if on_error not in ("fallback", "abstain"):
            raise ValueError("on_error is 'fallback' or 'abstain'")
        self._judge_ceiling, self._on_error = judge_ceiling, on_error
        self._store, self._judge = store, judge
        self._top_k, self._threshold = top_k, threshold
        # the label sent with a passage: the store's own when it keeps one, else red
        self._tlp_of = tlp_of or getattr(store, "tlp", lambda _id: _tlp.Label.RED)
        self.features = frozenset(getattr(store, "features", ()))

    def __getattr__(self, name: str):
        return getattr(self._store, name)

    def query(self, q: Query, **kw) -> list[Hit]:
        hits = self._store.query(q, **kw)
        head = hits[: self._top_k]
        kept: list[tuple[float, int, Hit]] = []
        try:
            for rank, h in enumerate(head):
                label = _tlp.read(self._tlp_of(h.id))
                if self._judge_ceiling is not None and not _tlp.allows(self._judge_ceiling, label):
                    raise JudgeError("passage is above the judge's TLP ceiling")
                v = self._judge.judge(q.text, h, label)
                if v.answers and v.confidence >= self._threshold:
                    kept.append((v.confidence, rank, h))
        except JudgeError:
            return [] if self._on_error == "abstain" else hits[: q.budget]
        kept.sort(key=lambda t: (-t[0], t[1]))
        ordered = [h for _, _, h in kept]
        if not ordered:
            return []
        # scores must stay descending for the contract's ordering rule
        n = len(ordered)
        out = [
            Hit(h.id, h.kind, h.title, h.path, float(n - i), h.snippet, h.content, h.digest)
            for i, h in enumerate(ordered)
        ]
        return out[: q.budget]
