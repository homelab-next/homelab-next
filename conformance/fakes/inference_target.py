# SPDX-License-Identifier: Apache-2.0
"""``inference`` / ``fast-classifier`` fakes built on the wave-2 fake OpenAI server."""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from dataclasses import replace
from typing import ClassVar

from conformance.fakes.openai_server import FakeOpenAIServer, Rule, label_rule
from conformance.protocols.inference import TURN_FIELDS
from homelabnext import tlp
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
#: a key whose sending TLP ceiling is clear: it may call CLOUD_ROLE with a label within it
SENDER_KEY = "sk-fake-clear-sender-key-0000"
#: an embedding role (the embeddings checks call it, ``embed_model``)
EMBED_MODEL = "example-embed"
#: a role whose deployments fail and whose first fallback is refused: a later fallback serves it
FAILOVER_ROLE = "example-failover"
#: each key's sending TLP ceiling (the admin key's is always red)
KEY_CEILINGS = {
    GATEWAY_KEY: tlp.Label.RED,
    THROTTLE_KEY: tlp.Label.RED,
    OVER_KEY: tlp.Label.AMBER,
    SENDER_KEY: tlp.Label.CLEAR,
}
#: the roles that leave the lab and their ceilings (every other role stays in it, ceiling red)
LEAVING = {CLOUD_ROLE: tlp.Label.CLEAR}
TLP_HEADER = "X-HNX-TLP"


class TlpGatewayServer(FakeOpenAIServer):
    """The fake in gateway mode with the per-request TLP admission of ADR-0038 decision 5: no
    ``X-HNX-TLP`` field is red (``unlabelled``), one field is ``tlp.read``, more than one is red; a
    role that leaves the lab judges at the higher of the label and the key's sending ceiling.
    ``leaving`` (role -> ceiling) and ``key_ceilings`` (key -> sending ceiling) default to this
    module's :data:`LEAVING` and :data:`KEY_CEILINGS`."""

    def __init__(
        self,
        *args,
        leaving: Mapping[str, tlp.Label] | None = None,
        key_ceilings: Mapping[str, tlp.Label] | None = None,
        **kw,
    ) -> None:
        super().__init__(*args, **kw)
        self.leaving = dict(LEAVING if leaving is None else leaving)
        self.key_ceilings = dict(KEY_CEILINGS if key_ceilings is None else key_ceilings)

    def judge(self, fields: list[str], leaves: bool, sender: tlp.Label) -> tlp.Label:
        label = tlp.read(fields[0]) if len(fields) == 1 else tlp.Label.RED
        return max(label, sender) if leaves else label

    def unlabelled(self, fields: list[str]) -> bool:
        return not fields

    def gate(self, headers, path, model):
        fields = list(headers.get_all(TLP_HEADER) or [])
        token = (headers.get("Authorization") or "").removeprefix("Bearer ").strip()
        ceiling = self.leaving.get(model, tlp.Label.RED)
        sender = self.key_ceilings.get(token, tlp.Label.RED)
        label = self.judge(fields, model in self.leaving, sender)
        if label <= ceiling:
            return None
        reason = "unlabelled" if self.unlabelled(fields) else "above-ceiling"
        return 403, f"tlp refused ({reason}): judged at {label}, above the ceiling {ceiling}"


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
    KEY_MODELS: ClassVar[Mapping[str, list[str]]] = {
        OVER_KEY: [MODEL],
        SENDER_KEY: [MODEL, CLOUD_ROLE],
    }
    SERVER: ClassVar[type[FakeOpenAIServer]] = TlpGatewayServer

    def __init__(self) -> None:
        self.server = self.SERVER(
            models=self.declared_models(),
            default_reply="This is a canned reply.",
            api_keys=[GATEWAY_KEY, THROTTLE_KEY, OVER_KEY, SENDER_KEY],
            key_limits={THROTTLE_KEY: THROTTLE_N},
            key_models=dict(self.KEY_MODELS),
        ).start()
        super().__init__(
            self.server.url,
            auth=lambda: f"Bearer {GATEWAY_KEY}",
            features=(
                "embeddings", "streaming", "gateway", "tlp-ceiling", "tlp-admit", "turn-records",
            ),
        )  # fmt: skip
        self.model = MODEL
        self.embed_model = EMBED_MODEL
        self.closers.append(self.server.stop)

    def declared_models(self) -> list[str]:
        return [MODEL, CLOUD_ROLE, EMBED_MODEL, FAILOVER_ROLE]

    def with_key(self, token: str | None) -> OpenAICompat:
        return OpenAICompat(self.server.url, auth=lambda: f"Bearer {token}" if token else None)

    def throttled(self) -> tuple[OpenAICompat, str, int]:
        return self.with_key(THROTTLE_KEY), MODEL, THROTTLE_N

    def over_ceiling(self) -> tuple[OpenAICompat, str, str]:
        return self.with_key(OVER_KEY), CLOUD_ROLE, MODEL

    def tlp_admit(self) -> tuple[OpenAICompat, OpenAICompat, str, str]:
        return self.with_key(SENDER_KEY), self.with_key(GATEWAY_KEY), CLOUD_ROLE, MODEL

    def refused_fallback(self) -> tuple[OpenAICompat, str]:
        # the fake has no deployments to fail: it serves the role as its later fallback would
        return self, FAILOVER_ROLE

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
    reaches a role whose prompts leave the lab at clear (a gateway with no admission of its own,
    which LiteLLM is, has only key scope to stop it)."""

    KEY_MODELS: ClassVar[Mapping[str, list[str]]] = {}
    SERVER = FakeOpenAIServer


class _LabelOnlyServer(TlpGatewayServer):
    def judge(self, fields, leaves, sender):
        return super().judge(fields, False, sender)


class LabelOnlyClient(FakeInferenceClient):
    """Defect: a role that leaves the lab judges a request at its label alone, so a key whose
    sending ceiling is above the role's reaches it by claiming a lower label."""

    SERVER = _LabelOnlyServer


class _LenientLabelServer(TlpGatewayServer):
    def judge(self, fields, leaves, sender):
        value = fields[0].strip() if len(fields) == 1 else ""
        unknown = value.lower().removeprefix("tlp:") != "red"
        if value and unknown and tlp.read(value) is tlp.Label.RED:
            fields = ["clear"]  # the defect: a value that is no label reads as clear
        return super().judge(fields, leaves, sender)


class LenientLabelClient(FakeInferenceClient):
    """Defect: an ``X-HNX-TLP`` value that is not a label (``bogus``, a look-alike) reads as
    ``clear`` instead of ``red``."""

    SERVER = _LenientLabelServer


class _EmptyFieldServer(TlpGatewayServer):
    def unlabelled(self, fields):
        return not [f for f in fields if f.strip()]


class EmptyFieldUnlabelledClient(FakeInferenceClient):
    """Defect: an empty ``X-HNX-TLP`` field is read as no field, so it is refused as
    ``unlabelled`` rather than as a label that reads red."""

    SERVER = _EmptyFieldServer


class TlpSubstituteClient(FakeInferenceClient):
    """Defect: a TLP refusal of the requested role falls back to another role, which answers
    under the requested alias: to the caller that is a served request (the server admits all)."""

    SERVER = FakeOpenAIServer


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
