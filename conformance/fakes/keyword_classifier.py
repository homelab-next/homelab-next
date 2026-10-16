# SPDX-License-Identifier: Apache-2.0
"""``fast-classifier`` fake: deterministic keyword scoring over the labels offered."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from homelabnext.conform.adapters.openai_classifier import Classification

DEFAULT_KEYWORDS: Mapping[str, Sequence[str]] = {
    "positive": ("wonderful", "excellent", "great", "thank", "love", "success"),
    "negative": ("terrible", "awful", "broken", "failure", "hate", "crash"),
    "accept": ("approve", "rollback", "safe", "revert"),
    "reject": ("risky", "irreversible", "destroy", "delete everything"),
}


class KeywordClassifier:
    features = frozenset()

    def __init__(self, keywords: Mapping[str, Sequence[str]] | None = None):
        self._kw = {k: tuple(v) for k, v in (keywords or DEFAULT_KEYWORDS).items()}

    def classify(self, text: str, labels: Sequence[str]) -> Classification:
        if not labels:
            raise ValueError("at least one label is required")
        low = text.lower()
        uniq = sorted(set(labels))  # order of the offered labels never changes the answer
        scores = {lab: sum(low.count(w) for w in self._kw.get(lab, ())) for lab in uniq}
        best = max(scores.values())
        if best == 0:
            return Classification(uniq[0], round(1.0 / (len(uniq) + 1), 3))
        winners = [lab for lab in uniq if scores[lab] == best]
        total = sum(scores.values())
        conf = best / total if len(winners) == 1 else best / (total + len(winners))
        return Classification(winners[0], round(min(0.99, max(0.0, conf)), 3))


class InventingClassifier(KeywordClassifier):
    """Defect: when nothing matches it answers a label that was never offered."""

    def classify(self, text: str, labels: Sequence[str]) -> Classification:
        res = super().classify(text, labels)
        if not any(w in text.lower() for ws in self._kw.values() for w in ws):
            return Classification("unknown", res.confidence)
        return res
