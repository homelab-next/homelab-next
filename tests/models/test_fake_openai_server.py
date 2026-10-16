# SPDX-License-Identifier: Apache-2.0
"""The fake OpenAI-compatible server: routes, rules, latency, faults, determinism."""

import json
import time
import urllib.error
import urllib.request

import pytest

from conformance.fakes.openai_server import FakeOpenAIServer, Fault, Rule, embed_vector, label_rule


def post(url, path, body, timeout=3):
    req = urllib.request.Request(url + path, data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read())


def test_models_and_rule_based_chat():
    rules = [label_rule("rollback", "accept", 0.97), Rule("hello", lambda r: "hi " + r["model"])]
    with FakeOpenAIServer(models=["m1", "m2"], rules=rules, default_reply="dunno") as s:
        listing = json.loads(urllib.request.urlopen(s.url + "/v1/models").read())
        assert [m["id"] for m in listing["data"]] == ["m1", "m2"]

        def chat(text, **kw):
            body = {"model": "m1", "messages": [{"role": "user", "content": text}], **kw}
            return post(s.url, "/v1/chat/completions", body)["choices"][0]["message"]["content"]

        assert json.loads(chat("has a Rollback plan")) == {"label": "accept", "confidence": 0.97}
        assert chat("hello there") == "hi m1"
        assert chat("something else") == "dunno"
        assert len(s.requests) == 4


def test_unknown_model_is_404_in_openai_shape():
    with FakeOpenAIServer(models=["m1"]) as s:
        body = {"model": "ghost", "messages": [{"role": "user", "content": "x"}]}
        with pytest.raises(urllib.error.HTTPError) as ei:
            post(s.url, "/v1/chat/completions", body)
        err = json.loads(ei.value.read())["error"]
        assert ei.value.code == 404 and err["type"] == "model_not_found"


def test_completions_embeddings_and_determinism():
    with FakeOpenAIServer(models=["m1"], rules=[Rule("ping", "pong")], embed_dim=5) as s:
        out = post(s.url, "/v1/completions", {"model": "m1", "prompt": "ping"})
        assert out["choices"][0]["text"] == "pong"
        a = post(s.url, "/v1/embeddings", {"model": "m1", "input": ["x", "y"]})
        b = post(s.url, "/v1/embeddings", {"model": "m1", "input": "x"})
        assert a["data"][0]["embedding"] == b["data"][0]["embedding"]
        assert len(a["data"][1]["embedding"]) == 5
    assert embed_vector("x", 5) == embed_vector("x", 5)


def test_logprobs_only_when_requested_and_configured():
    with FakeOpenAIServer(models=["m1"], default_reply="a b c", logprob=-0.1) as s:
        base = {"model": "m1", "messages": [{"role": "user", "content": "q"}]}
        plain = post(s.url, "/v1/chat/completions", base)["choices"][0]
        withlp = post(s.url, "/v1/chat/completions", {**base, "logprobs": True})["choices"][0]
        assert "logprobs" not in plain
        assert [t["logprob"] for t in withlp["logprobs"]["content"]] == [-0.1] * 3


def test_stream_ends_with_done():
    with FakeOpenAIServer(models=["m1"], default_reply="one two") as s:
        req = urllib.request.Request(
            s.url + "/v1/chat/completions",
            data=json.dumps(
                {"model": "m1", "stream": True, "messages": [{"role": "user", "content": "q"}]}
            ).encode(),
            method="POST",
        )
        body = urllib.request.urlopen(req, timeout=3).read().decode()
        assert body.rstrip().endswith("data: [DONE]") and "one" in body and "two" in body


def test_latency_is_applied_and_fault_windows_are_respected():
    faults = [Fault("http_error", status=502, path="chat", after=1, count=1)]
    with FakeOpenAIServer(models=["m1"], latency_ms=60, faults=faults) as s:
        body = {"model": "m1", "messages": [{"role": "user", "content": "q"}]}
        t0 = time.monotonic()
        post(s.url, "/v1/chat/completions", body)  # call 1 passes
        assert time.monotonic() - t0 >= 0.06
        with pytest.raises(urllib.error.HTTPError) as ei:
            post(s.url, "/v1/chat/completions", body)  # call 2 faulted
        assert ei.value.code == 502
        post(s.url, "/v1/chat/completions", body)  # call 3 passes again


def test_faults_can_change_while_running():
    with FakeOpenAIServer(models=["m1"]) as s:
        assert urllib.request.urlopen(s.url + "/health").status == 200
        s.faults.append(Fault("malformed"))
        assert urllib.request.urlopen(s.url + "/health").read() == b"<<not json>>"
