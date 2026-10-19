# SPDX-License-Identifier: Apache-2.0
"""/v1/systemone adapter over a cascade whose classifier tier talks to the fake backend."""

import json
import urllib.error
import urllib.request

import pytest
from models_support import make_registry, role_doc

from conformance.fakes.openai_server import FakeOpenAIServer, Fault, label_rule
from homelabnext.decide import Cascade, ModelTier, SystemOneServer, handle_decide, regex_floor
from homelabnext.decide.evalset import EXAMPLES
from homelabnext.decide.spec import load_spec
from homelabnext.registry import FakeDNS, Resolver
from homelabnext.registry.models import ModelClient, ModelResolver, RoleTable


@pytest.fixture
def stack():
    backend = FakeOpenAIServer(
        models=["example-4b"],
        rules=[
            label_rule("previous build", "accept", 0.97, impact="low"),
            label_rule("hand-edited", "reject", 0.5, impact="critical"),
        ],
        default_reply="not json",
        logprob=-0.01,
    ).start()
    reg = make_registry()
    env = {"HNX_ENDPOINT_INFERENCE_SMALL": backend.url}
    resolver = ModelResolver(
        reg, RoleTable.from_dict(role_doc()), Resolver(reg, dns=FakeDNS(), hosts={}, environ=env)
    )
    client = ModelClient(resolver.resolve("fast-classifier"), timeout=2)
    spec = load_spec(EXAMPLES / "decision_spec.yml")
    small = ModelTier(
        "small", lambda m: client.chat(m), spec.question_set, ("accept", "reject", "escalate")
    )
    never = ModelTier(
        "large",
        lambda m: (_ for _ in ()).throw(RuntimeError("down")),
        spec.question_set,
        ("accept",),
    )
    cascade = Cascade(
        spec,
        {"floor": regex_floor([(r"no-rollback", "reject")]), "small": small, "large": never},
    )
    server = SystemOneServer({"change-review": cascade}).start()
    yield server, backend
    server.stop()
    backend.stop()


def call(server, path, doc=None):
    data = None if doc is None else json.dumps(doc).encode()
    req = urllib.request.Request(
        server.url + path, data=data, method="GET" if doc is None else "POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def decide(server, **kw):
    return call(server, "/v1/systemone/decide", {"spec": "change-review", "id": "r1", **kw})


def test_floor_answers_without_touching_the_model(stack):
    server, backend = stack
    code, body = decide(server, text="NO-ROLLBACK here")
    assert code == 200 and body["protocol"] == "systemone/1"
    assert body["decision"]["verdict"] == "reject" and body["decision"]["tier"] == "floor"
    assert backend.requests == []


def test_classifier_tier_answers_through_the_fake_backend(stack):
    server, backend = stack
    code, body = decide(server, text="the change can be reverted using the previous build")
    d = body["decision"]
    assert (code, d["verdict"], d["tier"], d["acted"]) == (200, "accept", "small", True)
    assert 0.96 < d["confidence"] <= 0.97  # min(stated 0.97, mean token prob ~0.99)
    sent = backend.requests[0]["body"]
    assert sent["model"] == "example-4b" and sent["logprobs"] is True


def test_low_confidence_and_a_failing_next_tier_escalate_to_human(stack):
    server, _ = stack
    code, body = decide(server, text="hand-edited config on the production database")
    d = body["decision"]
    assert code == 200 and d["verdict"] == "human" and d["escalated"] and not d["acted"]
    assert d["interim"] == "hold" and d["impact"] == "critical"
    assert [s["outcome"] for s in body["trace"]][-2:] == ["below-threshold", "error"]


def test_unparseable_model_reply_and_backend_outage_escalate(stack):
    server, backend = stack
    code, body = decide(server, text="something the backend cannot parse")
    assert body["decision"]["verdict"] == "human"
    # A-04: an unparseable reply is retried once, then the tier is invalid and the item escalates
    assert any(s["outcome"] == "invalid" and s["tier"] == "small" for s in body["trace"])
    chats = [r for r in backend.requests if r["path"] == "/v1/chat/completions"]
    assert len(chats) == 2
    backend.faults.append(Fault("http_error", status=503))
    code, body = decide(server, text="the previous build comes back")
    assert code == 200 and body["decision"]["verdict"] == "human"


def test_protocol_errors(stack):
    server, _ = stack
    assert call(server, "/v1/systemone/health") == (
        200,
        {"status": "ok", "protocol": "systemone/1"},
    )
    assert call(server, "/v1/systemone/specs")[1]["specs"] == ["change-review"]
    code, body = call(server, "/v1/systemone/decide", {"spec": "ghost", "id": "x", "text": "t"})
    assert (code, body["error"]["code"]) == (404, "unknown_spec")
    code, body = decide(server, text="")
    assert (code, body["error"]["code"]) == (400, "bad_request")
    code, body = decide(server, text="t", impact="extreme", extra=1)
    assert (
        code == 400
        and "impact" in body["error"]["message"]
        and "unknown keys" in body["error"]["message"]
    )
    assert call(server, "/v1/nope")[0] == 404


def test_handle_decide_without_a_socket():
    assert handle_decide({}, [1])[0] == 400
    assert handle_decide({}, {"spec": "s", "id": "i", "text": "t"})[0] == 404
