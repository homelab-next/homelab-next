# SPDX-License-Identifier: Apache-2.0
"""G-10: exceeding a rate, token or cost budget throttles the model call and alerts."""

import json

import pytest
from models_support import role_doc

from homelabnext.decide import Cascade, Item, ModelTier, parse_spec
from homelabnext.notify import FakeSender, Notifier
from homelabnext.registry.limits import (
    KEY_PREFIX,
    PROBLEM,
    RECOVERY,
    Budget,
    Limiter,
    Throttled,
)
from homelabnext.registry.models import ChatResult, RoleTable, RoleTableError
from homelabnext.state import StateStore


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def chat_with(tokens: int, reply: str = "ok"):
    calls = []

    def chat(messages):
        calls.append(messages)
        return ChatResult(reply, "fake-model", "stop", usage={"total_tokens": tokens})

    chat.calls = calls
    return chat


@pytest.fixture
def env(tmp_path):
    clock, sender = Clock(), FakeSender()
    notifier = Notifier(sender, StateStore(tmp_path / "n.json"), clock=clock)
    return clock, sender, notifier


MSG = [{"role": "user", "content": "x"}]


def test_request_limit_throttles_alerts_once_and_recovers(env):
    clock, sender, notifier = env
    lim = Limiter({"mdl:fast": Budget(60, max_requests=3)}, clock=clock, notifier=notifier)
    chat = chat_with(5)
    call = lim.wrap(chat, "mdl:fast")
    for _ in range(3):
        call(MSG)
    with pytest.raises(Throttled, match="3 requests") as ei:
        call(MSG)
    assert ei.value.kind == "throttled"
    with pytest.raises(Throttled):
        call(MSG)
    assert len(chat.calls) == 3  # throttled calls never reach the backend
    assert sender.titles == [PROBLEM] and lim.throttled == 2
    assert sender.sent[0].key == KEY_PREFIX + "mdl:fast"
    clock.t += 60
    call(MSG)
    assert sender.titles == [PROBLEM, RECOVERY]


def test_token_limit_counts_backend_usage(env):
    clock, _, notifier = env
    lim = Limiter({"mdl:big": Budget(3600, max_tokens=100)}, clock=clock, notifier=notifier)
    call = lim.wrap(chat_with(40), "mdl:big")
    for _ in range(3):  # 0, 40, 80 used before each call: all admitted, 120 after
        call(MSG)
    assert lim.usage("mdl:big") == {"requests": 3, "tokens": 120, "cost": 0.0}
    with pytest.raises(Throttled, match="120 tokens"):
        call(MSG)


def test_cost_limit(env):
    clock, sender, notifier = env
    budget = Budget(3600, max_cost=0.1, cost_per_1k_tokens=1.0)
    lim = Limiter({"mdl:paid": budget}, clock=clock, notifier=notifier)
    call = lim.wrap(chat_with(60), "mdl:paid")
    call(MSG)
    call(MSG)
    with pytest.raises(Throttled, match=r"cost 0\.12"):
        call(MSG)
    assert sender.titles == [PROBLEM]


def test_profile_budget_applies_beside_the_role_budget(env):
    clock, _, notifier = env
    profile = Budget.from_profile(
        {"max_input_tokens": 50, "max_output_tokens": 50, "max_runtime_s": 900, "max_tool_calls": 3}
    )
    lim = Limiter(
        {"mdl:fast": Budget(60, max_requests=100), "profile:triage": profile},
        clock=clock,
        notifier=notifier,
    )
    call = lim.wrap(chat_with(60), "mdl:fast", "profile:triage", "unlimited-key")
    call(MSG)
    call(MSG)
    with pytest.raises(Throttled) as ei:
        call(MSG)
    assert ei.value.key == "profile:triage"
    assert lim.usage("mdl:fast")["requests"] == 2  # a refused call is admitted under no budget


def test_usage_without_total_tokens_sums_prompt_and_completion(env):
    clock, _, _ = env
    lim = Limiter({"k": Budget(60, max_tokens=10)}, clock=clock)

    def chat(messages):
        return ChatResult("ok", "m", "stop", usage={"prompt_tokens": 4, "completion_tokens": 7})

    lim.wrap(chat, "k")(MSG)
    assert lim.usage("k")["tokens"] == 11 and lim.over("k")


def test_limits_come_from_the_role_table(env):
    clock, _, _ = env
    doc = role_doc()
    doc["roles"]["fast-classifier"]["limits"] = {"window_s": 60, "max_requests": 1}
    lim = Limiter.for_roles(RoleTable.from_dict(doc), clock=clock)
    assert set(lim.budgets) == {"mdl:fast-classifier"}
    call = lim.wrap(chat_with(1), "mdl:fast-classifier")
    call(MSG)
    with pytest.raises(Throttled):
        call(MSG)
    doc["roles"]["fast-classifier"]["limits"] = {"max_requests": 1}
    with pytest.raises(RoleTableError, match="window_s"):
        RoleTable.from_dict(doc)
    with pytest.raises(ValueError, match="window_s"):
        Budget(0)


def test_a_throttled_classifier_tier_escalates_never_answers(env):
    clock, sender, notifier = env
    spec = parse_spec(
        {
            "id": "budgeted",
            "version": 1,
            "question_set": ["Is it fine?"],
            "decision_table": [{"when": "fine", "then": "accept"}],
            "tiers": [{"name": "small", "model_role": "mdl:fast", "min_confidence": 0.5}],
            "error_direction": "fail-closed",
            "on_error": "escalate",
            "latency_budget_ms": 1000,
            "sample_audit_pct": 1,
        }
    )
    lim = Limiter({"mdl:fast": Budget(60, max_requests=1)}, clock=clock, notifier=notifier)
    reply = json.dumps({"label": "accept", "confidence": 0.99})
    tier = ModelTier("small", lim.wrap(chat_with(3, reply), "mdl:fast"), spec.question_set,
                     ("accept", "reject", "escalate"))  # fmt: skip
    c = Cascade(spec, {"small": tier})
    assert c.decide(Item("a", "x")).verdict == "accept"
    d = c.decide(Item("b", "x"))
    assert d.verdict == "human" and "throttled" in d.trace[0].detail
    assert sender.titles == [PROBLEM]
