# SPDX-License-Identifier: Apache-2.0
"""``inference``: an OpenAI-compatible endpoint - models, chat, streaming, embeddings, errors."""

from __future__ import annotations

import re

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


# --- feature ``gateway``: what a model gateway in front of the backends is for -----------------
BAD_KEY = "sk-bf-fake-not-a-key-0000"  # sk-bf- so a gateway that wants that prefix still parses it
#: an auth failure must read as one: these are the words of a gateway whose key store is missing
#: (LiteLLM without Postgres answers "No connected db." with HTTP 400 to a wrong key)
NOT_AUTH = re.compile(r"no connected db|database|prisma|\bdb\b|internal server error", re.I)


def _auth_rejection(client, label):
    exc = raises(lambda: client.chat(_model(client), PROMPT), label, InferenceError)
    assert exc.status == 401, f"{label}: HTTP {exc.status} ({exc.detail[:120]!r}), expected 401"
    assert not NOT_AUTH.search(exc.detail), f"{label}: 401 but the reason is {exc.detail[:120]!r}"


@SUITE.check(
    "gateway-rejects-bad-key",
    "a wrong key and a missing key are each a 401 that says so, never a 5xx or a store error",
    requires=["gateway"],
)
def _(c):
    _auth_rejection(c.with_key(BAD_KEY), "wrong key")
    _auth_rejection(c.with_key(None), "no key")


@SUITE.check(
    "gateway-limit-throttles",
    "a configured request limit answers 429 once it is used up, and nothing else fails",
    requires=["gateway"],
)
def _(c):
    client, model, n = c.throttled()
    statuses, other = [], []
    for _ in range(n + 1):
        try:
            client.chat(model, PROMPT)
            statuses.append(200)
        except InferenceError as exc:
            statuses.append(exc.status)
            if exc.status != 429:
                other.append(f"HTTP {exc.status} ({exc.detail[:120]!r})")
    assert not other, f"{other[0]} while throttling"
    assert 429 in statuses, f"{n + 1} calls against a limit of {n} were all served: {statuses}"
    assert statuses.count(200) <= n, f"more than {n} calls served: {statuses}"


@SUITE.check(
    "gateway-models-match-roles",
    "/v1/models lists exactly the declared role aliases (no backend ids, no extras)",
    requires=["gateway"],
)
def _(c):
    served, declared = sorted(c.models()), sorted(c.declared_models())
    assert declared, "the target declares no models"
    assert served == declared, f"/v1/models {served} != declared {declared}"


def make_fake():
    return FakeInferenceClient()


MUTANTS = {
    "alias-swap": Mutant(
        WrongModelClient, "chat-echoes-requested-model", "replies come from a different model"
    ),
}
