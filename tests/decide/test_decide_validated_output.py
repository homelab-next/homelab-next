# SPDX-License-Identifier: Apache-2.0
"""A-04: every model-tier reply is schema-validated; an invalid one is retried once, then escalated."""

import json
import random

import jsonschema
import pytest
from decide_support import abstain, spec

from homelabnext.decide import Cascade, Item, ModelTier
from homelabnext.decide.tiers import TierInvalidOutput, output_schema, validate_output
from homelabnext.registry.models import ChatResult

LABELS = ("accept", "reject", "escalate")
ITEM = Item("i-1", "a plain change")


class Scripted:
    """A chat function that replies from a script and records every call."""

    def __init__(self, *replies: str):
        self.replies = list(replies)
        self.calls: list[list[dict]] = []

    def __call__(self, messages: list[dict]) -> ChatResult:
        self.calls.append(messages)
        return ChatResult(self.replies.pop(0), "fake-model", "stop")


def ok(label="accept", conf=0.95, **extra) -> str:
    return json.dumps({"label": label, "confidence": conf, **extra})


def tier(chat) -> ModelTier:
    return ModelTier("small", chat, ("Is it fine?",), LABELS)


def test_valid_reply_is_used_without_a_retry():
    chat = Scripted(ok())
    ans = tier(chat).decide(ITEM)
    assert (ans.label, ans.confidence, len(chat.calls)) == ("accept", 0.95, 1)


def test_invalid_reply_is_retried_once_with_the_problems_fed_back():
    chat = Scripted("not json at all", ok("reject", 0.91))
    ans = tier(chat).decide(ITEM)
    assert (ans.label, len(chat.calls)) == ("reject", 2)
    assert "valid after one retry" in ans.rationale
    feedback = chat.calls[1][-1]
    assert feedback["role"] == "user" and "not JSON" in feedback["content"]


def test_two_invalid_replies_raise_and_never_a_third_call():
    chat = Scripted("nope", ok("maybe"), ok())
    with pytest.raises(TierInvalidOutput, match="after 2 attempts"):
        tier(chat).decide(ITEM)
    assert len(chat.calls) == 2


def test_cascade_escalates_an_invalid_tier_and_records_it():
    chat = Scripted("{}", '{"label": "accept"}')
    s = spec(tiers=[{"name": "floor"}, {"name": "small", "model_role": "mdl:a"}])
    d = Cascade(s, {"floor": abstain("floor"), "small": tier(chat)}).decide(ITEM)
    assert d.verdict == "human" and d.escalated and not d.acted
    step = d.trace[1]
    assert step.outcome == "invalid" and "confidence: required" in step.detail


@pytest.mark.parametrize(
    "reply",
    [
        "[]",
        '"accept"',
        ok("maybe"),
        ok(conf=1.5),
        ok(conf=-0.1),
        ok(conf=True),
        ok(conf="0.9"),
        ok(impact="severe"),
        ok(rationale=7),
        ok(extra_key=1),
        '{"confidence": 0.9}',
        '{"label": "accept"}',
    ],
)
def test_schema_violations_are_invalid(reply):
    assert validate_output(json.loads(reply), LABELS)
    assert not jsonschema.Draft202012Validator(output_schema(LABELS)).is_valid(json.loads(reply))


def _random_reply(rng: random.Random) -> str:
    """A reply drawn from valid answers, near misses and garbage (seeded, so reproducible)."""
    pool = [
        lambda: ok(rng.choice([*LABELS, "maybe", "ACCEPT"]), rng.choice([0, 0.5, 1, 1.01, -1])),
        lambda: ok(rng.choice(LABELS), round(rng.random(), 3), impact=rng.choice(["low", "huge"])),
        lambda: json.dumps({"label": rng.choice(LABELS)}),
        lambda: json.dumps({rng.choice(["label", "x"]): 1, "confidence": rng.random()}),
        lambda: rng.choice(["", "null", "[1]", "{", "accept", "```json\n{}\n```"]),
        lambda: ok(rng.choice(LABELS), 0.9, rationale=rng.choice(["why", 3, None])),
    ]
    return rng.choice(pool)()


def test_validator_agrees_with_the_declared_json_schema_and_answers_are_always_valid():
    rng = random.Random(4)
    v = jsonschema.Draft202012Validator(output_schema(LABELS))
    used = 0
    for _ in range(600):
        a, b = _random_reply(rng), _random_reply(rng)
        for text in (a, b):
            try:
                doc = json.loads(text)
            except ValueError:
                continue
            assert (not validate_output(doc, LABELS)) == v.is_valid(doc), text
        chat = Scripted(a, b)
        try:
            ans = tier(chat).decide(ITEM)
        except TierInvalidOutput:
            assert len(chat.calls) == 2
            continue
        used += 1
        # 100% of what the tier hands the cascade came from a schema-valid reply
        last = json.loads(a if len(chat.calls) == 1 else b)
        assert v.is_valid(last)
        assert ans.label == last["label"] and 0 <= ans.confidence <= 1
    assert 50 < used < 600
