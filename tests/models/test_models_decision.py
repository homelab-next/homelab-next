# SPDX-License-Identifier: Apache-2.0
"""A decision role: the role table accepts it, and ModelClient.decide asks it (POST /v1/systemone)."""

import copy

import pytest
from models_support import role_doc

from conformance.fakes.openai_server import FakeOpenAIServer
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
    assert _client(decider, "decider-m").chat_refused() == (True, "")
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
    refused, why = _client(decider, "chat-m").chat_refused()
    assert not refused and "answered a chat completion" in why
