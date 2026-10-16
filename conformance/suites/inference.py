# SPDX-License-Identifier: Apache-2.0
"""``inference``: an OpenAI-compatible endpoint - models, chat, streaming, embeddings, errors."""

from __future__ import annotations

from conformance.fakes.inference_target import FakeInferenceClient, WrongModelClient
from conformance.protocols.inference import InferenceError
from homelabnext.conform.core import Mutant, Suite

from ._util import raises

SUITE = Suite(
    "inference",
    "OpenAI-compatible /v1 chat, streaming and embeddings behind a role alias",
    "conformance.protocols.inference:InferenceClient",
)

PROMPT = [{"role": "user", "content": "Say hello in one short sentence."}]


def _model(c):
    return getattr(c, "model", None) or c.models()[0]


@SUITE.check("models-lists-the-served-model", "/v1/models lists the model the target serves")
def _(c):
    ids = c.models()
    assert ids, "no models listed"
    assert _model(c) in ids, f"{_model(c)!r} not in {ids}"


@SUITE.check("chat-returns-text", "a chat completion has non-empty text and a finish reason")
def _(c):
    r = c.chat(_model(c), PROMPT)
    assert isinstance(r.content, str) and r.content.strip(), f"empty content {r.content!r}"
    assert r.finish_reason in ("stop", "length"), f"finish_reason {r.finish_reason!r}"


@SUITE.check("chat-echoes-requested-model", "the reply names the model that was asked for")
def _(c):
    m = _model(c)
    r = c.chat(m, PROMPT)
    assert r.model == m, f"asked for {m!r}, answered by {r.model!r}"


@SUITE.check("unknown-model-rejected", "an unserved model id is a client error (4xx), not a guess")
def _(c):
    exc = raises(lambda: c.chat("no-such-model-zz", PROMPT), "unknown model", InferenceError)
    assert exc.status in (400, 404), f"status {exc.status}"


@SUITE.check("usage-adds-up", "usage totals equal prompt plus completion tokens", severity="should")
def _(c):
    r = c.chat(_model(c), PROMPT)
    if r.total_tokens is None:
        return "no usage reported"
    assert r.total_tokens == (r.prompt_tokens or 0) + (r.completion_tokens or 0), f"usage {r}"


@SUITE.check("deterministic-at-temperature-zero", "the same request twice gives the same text")
def _(c):
    a = c.chat(_model(c), PROMPT, temperature=0.0).content
    b = c.chat(_model(c), PROMPT, temperature=0.0).content
    assert a == b, f"{a!r} != {b!r}"


@SUITE.check(
    "stream-matches-completion",
    "streamed pieces add up to the non-streamed text",
    severity="should",
    requires=["streaming"],
)
def _(c):
    whole = c.chat(_model(c), PROMPT).content
    streamed = "".join(c.chat_stream(_model(c), PROMPT))
    assert streamed.split() == whole.split(), f"{streamed!r} != {whole!r}"


@SUITE.check(
    "embeddings-fixed-dimension", "every embedding has the same length", requires=["embeddings"]
)
def _(c):
    vecs = c.embed(_model(c), ["alpha", "beta", "a much longer third input text"])
    assert len(vecs) == 3, f"{len(vecs)} vectors for 3 inputs"
    assert len({len(v) for v in vecs}) == 1 and len(vecs[0]) > 0, "dimensions differ"


@SUITE.check(
    "embeddings-deterministic-and-distinct",
    "same text same vector; different text different vector",
    requires=["embeddings"],
)
def _(c):
    a1, a2, b = c.embed(_model(c), ["alpha", "alpha", "beta"])
    assert a1 == a2, "same input gave different vectors"
    assert a1 != b, "different inputs gave the same vector"


def make_fake():
    return FakeInferenceClient()


MUTANTS = {
    "alias-swap": Mutant(
        WrongModelClient, "chat-echoes-requested-model", "replies come from a different model"
    ),
}
