# SPDX-License-Identifier: Apache-2.0
"""A decision role: the role table accepts it, and ModelClient.decide asks it (POST /v1/systemone)."""

import copy

import pytest
from models_support import role_doc

from conformance.fakes.openai_server import FakeOpenAIServer
from homelabnext.golden.canary import CanaryError, chat_refusal
from homelabnext.registry.models import ModelClient, ModelError, ResolvedModel, RoleTable
from homelabnext.registry.resolver import Endpoint


def _doc():
    d = copy.deepcopy(role_doc())
    d["roles"]["clef"] = {
        "kind": "decision",
        "tier": "fast",
        "bindings": [{"backend": "svc:inference-small", "model_id": "example-decider"}],
    }
    return d


def test_the_role_table_accepts_a_decision_role():
    assert RoleTable.from_dict(_doc()).get("clef").kind == "decision"


def _resolved(srv, model):
    host, port = srv.address
    ep = Endpoint("inference", "http", host, port, "env")
    return ResolvedModel(
        role="r", asked="r", kind="decision", model_id=model, backend="b", endpoint=ep, params={}
    )


def _client(srv, model):
    return ModelClient(_resolved(srv, model))


@pytest.fixture
def decider():
    srv = FakeOpenAIServer(
        models=["chat-m"],
        decision_models=["decider-m"],
        decision_rules={"capital": 0.93, "moon": 0.04},
    ).start()
    yield srv
    srv.stop()


def test_decide_returns_a_probability_per_question(decider):
    out = _client(decider, "decider-m").decide(
        {"a": "Does this answer: capital of France?", "b": "Does this answer: height of the moon?"}
    )
    assert out.probabilities == {"a": 0.93, "b": 0.04}
    assert out.usage["input_tokens"] > 0
    sent = decider.requests[-1]
    assert sent["path"] == "/v1/systemone"
    assert sent["body"]["questions"]["a"]["type"] == "noul"


def test_a_decision_model_refuses_chat_and_a_chat_model_refuses_systemone(decider):
    # the client refuses text calls on a decision role before sending anything
    n = len(decider.requests)
    for call in (
        lambda c: c.chat([{"role": "user", "content": "hi"}]),
        lambda c: c.complete("hi"),
        lambda c: c.embed(["hi"]),
    ):
        with pytest.raises(ModelError, match="is a decision role") as e1:
            call(_client(decider, "decider-m"))
        assert e1.value.kind == "misconfigured"
    assert len(decider.requests) == n
    # and the server refuses it too: the canary's probe reads that refusal
    assert chat_refusal(*_client(decider, "decider-m").chat_probe()) == (True, "")
    assert decider.requests[-1]["path"] == "/v1/chat/completions"
    with pytest.raises(ModelError) as e2:
        _client(decider, "chat-m").decide({"a": "x"})
    assert e2.value.status == 404


def test_a_malformed_decision_answer_is_an_error(decider):
    class Bad(ModelClient):
        def _call(self, path, body):
            return {"answers": {"a": {"type": "noul", "noul": 1.7}}}

    with pytest.raises(ModelError, match="malformed"):
        Bad(_resolved(decider, "decider-m")).decide({"a": "x"})


def test_the_chat_probe_reports_a_backend_that_answers_chat(decider):
    """A chat-capable backend declared a decision role: the probe says so."""
    refused, why = chat_refusal(*_client(decider, "chat-m").chat_probe())
    assert not refused and "answered a chat completion" in why


def _err(code):
    return {"error": {"message": "m", "type": "t", "code": code}}


@pytest.mark.parametrize(
    ("status", "body"),
    [(501, _err("not_implemented")), (501, None), (400, _err("wrong_model_kind"))],
)
def test_only_a_decision_models_501_or_the_gateways_wrong_kind_is_a_refusal(status, body):
    assert chat_refusal(status, body) == (True, "")


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (400, _err("invalid_request_error")),  # another 400
        (400, None),
        (401, _err("invalid_api_key")),
        (403, _err("forbidden")),
        (404, _err("not_found")),
        (405, None),
        (413, _err("request_too_large")),
        (429, _err("rate_limited")),
        (500, None),
        (502, None),
    ],
)
def test_any_other_answer_is_no_proof_and_raises(status, body):
    """A rate limit, an auth or scope error, an oversized body, a missing route: none says the
    backend has no chat, so the canary sample is an error, never a pass (#476 re-review)."""
    with pytest.raises(CanaryError, match=f"HTTP {status}"):
        chat_refusal(status, body)


def test_a_200_chat_answer_is_a_finding_not_a_refusal():
    refused, why = chat_refusal(200, {"choices": [{"message": {"content": "hi"}}]})
    assert not refused and why


@pytest.mark.parametrize("status", [401, 403, 413, 429])
def test_a_decision_canary_sample_on_a_non_refusal_is_an_error(status):
    from homelabnext.golden import canary as cn
    from homelabnext.golden.runner import ClientDecider

    class Client:
        def decide(self, qs, state=None):
            from homelabnext.registry.models import DecisionResult

            return DecisionResult(dict.fromkeys(qs, 0.1))

        def chat_probe(self):
            return status, _err("x")

    rep = cn.run_decision_canary(cn.load_suite(), ClientDecider(Client()), samples=1)
    assert not rep["summary"]["ok"]
    assert all(t["findings"] == {"error": 1} for t in rep["tasks"].values())
