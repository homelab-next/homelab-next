# SPDX-License-Identifier: Apache-2.0
"""``inference`` / ``fast-classifier`` fakes built on the wave-2 fake OpenAI server."""

from __future__ import annotations

import json
from dataclasses import replace

from conformance.fakes.openai_server import FakeOpenAIServer, Rule, label_rule
from homelabnext.conform.adapters.openai_classifier import OpenAIClassifier
from homelabnext.conform.adapters.openai_compat import ChatResult, OpenAICompat

MODEL = "example-chat-4b"


def start_server(**kw) -> FakeOpenAIServer:
    return FakeOpenAIServer(models=[MODEL], default_reply="This is a canned reply.", **kw).start()


class FakeInferenceClient(OpenAICompat):
    """An :class:`OpenAICompat` wired to a private fake server (stopped by ``close``)."""

    def __init__(self) -> None:
        self.server = start_server()
        super().__init__(self.server.url)
        self.model = MODEL
        self.closers.append(self.server.stop)


class WrongModelClient(FakeInferenceClient):
    """Defect: the reply names a different model than the one asked for (a silent alias swap)."""

    def chat(self, model, messages, **kw) -> ChatResult:
        return replace(super().chat(model, messages, **kw), model="substituted-model")


def classifier_rules() -> list[Rule]:
    return [
        label_rule(r"wonderful|excellent|great|thank", "positive", 0.95),
        label_rule(r"terrible|awful|broken|failure", "negative", 0.93),
        Rule(r"^$", json.dumps({"label": "negative", "confidence": 0.4})),
    ]


class FakeServerClassifier(OpenAIClassifier):
    """The OpenAI-backed classifier over a fake server with rule-based answers."""

    def __init__(self) -> None:
        self.server = FakeOpenAIServer(
            models=[MODEL],
            rules=classifier_rules(),
            default_reply=json.dumps({"label": "positive", "confidence": 0.3}),
        ).start()
        client = OpenAICompat(self.server.url)
        client.closers.append(self.server.stop)
        super().__init__(client, MODEL)
