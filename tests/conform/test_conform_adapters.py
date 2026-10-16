# SPDX-License-Identifier: Apache-2.0
"""The OpenAI-compatible client and classifier adapters, against the wave-2 fake server."""

import json

import pytest

from conformance.fakes.openai_server import FakeOpenAIServer, Fault, label_rule
from homelabnext.conform.adapters.openai_classifier import ClassifierError, OpenAIClassifier
from homelabnext.conform.adapters.openai_compat import InferenceError, OpenAICompat


@pytest.fixture
def server():
    with FakeOpenAIServer(
        models=["m1"],
        rules=[label_rule("wonderful", "positive", 0.9), label_rule("awful", "negative", 0.8)],
        default_reply="plain words here",
    ) as s:
        yield s


def test_client_roundtrip(server):
    c = OpenAICompat(server.url)
    assert c.models() == ["m1"]
    r = c.chat("m1", [{"role": "user", "content": "hi"}])
    assert r.content == "plain words here" and r.model == "m1" and r.finish_reason == "stop"
    assert "".join(c.chat_stream("m1", [{"role": "user", "content": "hi"}])).split() == [
        "plain",
        "words",
        "here",
    ]
    assert len(c.embed("m1", ["a", "b"])) == 2


def test_client_errors_are_inference_errors(server):
    c = OpenAICompat(server.url)
    with pytest.raises(InferenceError) as e:
        c.chat("ghost", [{"role": "user", "content": "x"}])
    assert e.value.status == 404
    url = server.url
    server.stop()
    with pytest.raises(InferenceError, match="transport"):
        OpenAICompat(url, timeout=1).models()


def test_client_refuses_a_non_http_base_url_and_hides_it_in_repr():
    with pytest.raises(ValueError):
        OpenAICompat("ftp://nowhere")
    url = "http://192.0.2.1:9"  # no-raw-endpoint: allow RFC 5737 documentation address
    assert "http" not in repr(OpenAICompat(url))


def test_client_surfaces_malformed_replies():
    msgs = [{"role": "user", "content": "x"}]
    faults = [Fault("malformed", path="/v1/chat")]
    with (
        FakeOpenAIServer(models=["m1"], faults=faults) as s,
        pytest.raises(InferenceError, match="not JSON"),
    ):
        OpenAICompat(s.url).chat("m1", msgs)
    faults = [Fault("bad_shape", path="/v1/chat")]
    with (
        FakeOpenAIServer(models=["m1"], faults=faults) as s,
        pytest.raises(InferenceError, match="unexpected shape"),
    ):
        OpenAICompat(s.url).chat("m1", msgs)


def test_auth_header_is_read_at_request_time(server):
    c = OpenAICompat(server.url, auth=lambda: "Bearer t0k")
    c.models()
    # the fake does not check auth; the point is that the callable ran and nothing is stored
    assert "t0k" not in repr(c) and "t0k" not in json.dumps(vars(c), default=str)


def test_classifier_over_the_server(server):
    clf = OpenAIClassifier(OpenAICompat(server.url), "m1")
    got = clf.classify("What a wonderful day", ["positive", "negative"])
    assert (got.label, got.confidence) == ("positive", 0.9)
    with pytest.raises(ValueError):
        clf.classify("x", [])


def test_classifier_never_guesses_on_a_bad_model_reply(server):
    clf = OpenAIClassifier(OpenAICompat(server.url), "m1")
    with pytest.raises(ClassifierError, match="expected JSON"):
        clf.classify("neutral text", ["positive", "negative"])  # default reply is not JSON
    with (
        FakeOpenAIServer(
            models=["m1"], default_reply=json.dumps({"label": "other", "confidence": 0.9})
        ) as s,
        pytest.raises(ClassifierError, match="not offered"),
    ):
        OpenAIClassifier(OpenAICompat(s.url), "m1").classify("x", ["positive"])
    with (
        FakeOpenAIServer(
            models=["m1"], default_reply=json.dumps({"label": "positive", "confidence": 7})
        ) as s,
        pytest.raises(ClassifierError, match="confidence"),
    ):
        OpenAIClassifier(OpenAICompat(s.url), "m1").classify("x", ["positive"])
