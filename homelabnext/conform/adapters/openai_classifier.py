# SPDX-License-Identifier: Apache-2.0
"""A ``fast-classifier`` backed by any OpenAI-compatible chat endpoint.

The model is asked for ``{"label": ..., "confidence": ...}``.  Anything else - not JSON, a label
that was not offered, a confidence outside [0, 1] - raises :class:`ClassifierError`: the adapter
never guesses a label on the model's behalf.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass

from .openai_compat import OpenAICompat

__all__ = ["Classification", "ClassifierError", "OpenAIClassifier"]


class ClassifierError(Exception):
    pass


@dataclass(frozen=True)
class Classification:
    label: str
    confidence: float


class OpenAIClassifier:
    features: tuple[str, ...] = ()

    def __init__(self, client: OpenAICompat, model: str):
        self._client, self._model = client, model

    def close(self) -> None:
        self._client.close()

    def classify(self, text: str, labels: Sequence[str]) -> Classification:
        offered = list(dict.fromkeys(labels))
        if not offered:
            raise ValueError("at least one label is required")
        system = (
            "Classify the user's text. Reply with only a JSON object "
            '{"label": <one of ' + json.dumps(offered) + '>, "confidence": <number 0..1>}.'
        )
        res = self._client.chat(
            self._model,
            [{"role": "system", "content": system}, {"role": "user", "content": text}],
            max_tokens=64,
            temperature=0.0,
        )
        try:
            doc = json.loads(res.content)
            label, conf = doc["label"], float(doc["confidence"])
        except (ValueError, KeyError, TypeError) as exc:
            raise ClassifierError("model reply is not the expected JSON object") from exc
        if label not in offered:
            raise ClassifierError(f"model answered {label!r}, which was not offered")
        if not 0.0 <= conf <= 1.0:
            raise ClassifierError("confidence outside [0, 1]")
        return Classification(label, conf)
