# SPDX-License-Identifier: Apache-2.0
"""Contract for ``fast-classifier``: a small, quick text classifier behind a role alias.

``classify(text, labels)`` returns one of the labels the *caller* gave and a confidence in
[0, 1].  It never invents a label, never returns a label that was not offered, and gives the
same answer for the same input.  The decision cascade escalates on low confidence, so
``confidence`` is part of the contract, not decoration.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from homelabnext.conform.adapters.openai_classifier import Classification, ClassifierError

__all__ = ["Classification", "Classifier", "ClassifierError"]


@runtime_checkable
class Classifier(Protocol):
    def classify(self, text: str, labels: Sequence[str]) -> Classification:
        """Raises ValueError for fewer than one label; ClassifierError if the backend misbehaves
        (it must never guess a label in that case)."""
