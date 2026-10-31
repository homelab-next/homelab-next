# SPDX-License-Identifier: Apache-2.0
"""``inference`` / ``fast-classifier`` fakes built on the wave-2 fake OpenAI server."""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from dataclasses import replace
from typing import ClassVar

from conformance.fakes.openai_server import FakeOpenAIServer, Rule, label_rule
from conformance.protocols.inference import TURN_FIELDS
from homelabnext.conform.adapters.openai_classifier import OpenAIClassifier
from homelabnext.conform.adapters.openai_compat import ChatResult, OpenAICompat
from homelabnext.status.model import iso, parse_iso

MODEL = "example-chat-4b"
#: a role whose prompts leave the lab, at the TLP ceiling clear (ADR-0033 decision 10)
CLOUD_ROLE = "example-remote-chat"
GATEWAY_KEY = "sk-fake-gateway-key-0000"
THROTTLE_KEY = "sk-fake-throttle-key-0000"
THROTTLE_N = 2
#: a key whose sending TLP ceiling (amber) is above CLOUD_ROLE's: scoped to MODEL only
OVER_KEY = "sk-fake-over-ceiling-key-0000"
#: the fake gateway's per-call log: two jobs' tags, three calls, in one hour
TURN_TAGS = ["run-f001", "run-f002"]
TURN_WINDOW = (parse_iso("2026-01-01T00:00:00Z"), parse_iso("2026-01-01T01:00:00Z"))


def start_server(models: Collection[str] = (MODEL,), **kw) -> FakeOpenAIServer:
    return FakeOpenAIServer(
        models=list(models), default_reply="This is a canned reply.", **kw
    ).start()


class FakeInferenceClient(OpenAICompat):
    """An :class:`OpenAICompat` wired to a private fake server in gateway mode (keys, a
    throttled key and a key scoped away from a role above its TLP ceiling), so the ``gateway`` and
    ``tlp-ceiling`` checks run against it too; stopped by ``close``."""

    #: the scope the gateway gives each key (the generator scopes no key to a role whose TLP
    #: ceiling is below the key's sending ceiling)
    KEY_MODELS: ClassVar[Mapping[str, list[str]]] = {OVER_KEY: [MODEL]}

    def __init__(self) -> None:
        self.server = start_server(
            models=[MODEL, CLOUD_ROLE],
            api_keys=[GATEWAY_KEY, THROTTLE_KEY, OVER_KEY],
            key_limits={THROTTLE_KEY: THROTTLE_N},
            key_models=dict(self.KEY_MODELS),
        )
        super().__init__(
            self.server.url,
            auth=lambda: f"Bearer {GATEWAY_KEY}",
            features=("embeddings", "streaming", "gateway", "tlp-ceiling", "turn-records"),
        )
        self.model = MODEL
        self.closers.append(self.server.stop)

    def declared_models(self) -> list[str]:
        return [MODEL, CLOUD_ROLE]

    def with_key(self, token: str | None) -> OpenAICompat:
        return OpenAICompat(self.server.url, auth=lambda: f"Bearer {token}" if token else None)

    def throttled(self) -> tuple[OpenAICompat, str, int]:
        return self.with_key(THROTTLE_KEY), MODEL, THROTTLE_N

    def over_ceiling(self) -> tuple[OpenAICompat, str, str]:
        return self.with_key(OVER_KEY), CLOUD_ROLE, MODEL

    def turn_records(self) -> tuple[FakeTurnSource, float, float, list[str]]:
        return FakeTurnSource(fake_turns()), *TURN_WINDOW, list(TURN_TAGS)


def fake_turns() -> list[dict]:
    """The fake gateway's log as neutral turn records (fictional)."""
    lo = TURN_WINDOW[0]
    rows = [
        ("call-f1", TURN_TAGS[0], 60),
        ("call-f2", TURN_TAGS[0], 120),
        ("call-f3", TURN_TAGS[1], 900),
    ]
    return [
        dict.fromkeys(TURN_FIELDS)
        | {"turn_id": tid, "gateway_tag": tag, "started_at": iso(lo + s), "model_role": MODEL,
           "status": "success", "input_tokens": 100, "output_tokens": 20, "cost_usd": 0.0}
        for tid, tag, s in rows
    ]  # fmt: skip


class FakeTurnSource:
    """A :class:`~conformance.protocols.inference.TurnSource` over a list of turn records."""

    def __init__(self, turns: list[dict]) -> None:
        self.log = turns

    def turns(self, start: float, end: float, tags: Collection[str]) -> list[dict]:
        wanted = set(tags)
        return [
            dict(t)
            for t in self.log
            if t["gateway_tag"] in wanted and start <= parse_iso(t["started_at"]) <= end
        ]


class CeilingIgnoredClient(FakeInferenceClient):
    """Defect: the gateway scopes the over-ceiling key to every role, so an amber-ceiling sender
    reaches a role whose prompts leave the lab at clear."""

    KEY_MODELS: ClassVar[Mapping[str, list[str]]] = {}


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
