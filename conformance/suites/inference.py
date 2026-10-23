# SPDX-License-Identifier: Apache-2.0
"""``inference``: an OpenAI-compatible endpoint - models, chat, streaming, embeddings, errors."""

from __future__ import annotations

import re

from conformance.fakes.inference_target import FakeInferenceClient, WrongModelClient
from conformance.protocols.inference import TURN_FIELDS, InferenceError, turn_problems
from homelabnext.conform.core import Mutant, Suite
from homelabnext.status.model import parse_iso

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


CHAT = "/v1/chat/completions"


def _auth_rejection(client, model, label):
    """``client`` (another key, or none) asks for ``model`` - taken from the admin client, so the
    refused call is the chat itself, not a ``/v1/models`` lookup that a gateway may guard while
    serving chat to anyone."""
    exc = raises(lambda: client.chat(model, PROMPT), label, InferenceError)
    assert exc.status == 401, f"{label}: HTTP {exc.status} ({exc.detail[:120]!r}), expected 401"
    assert exc.path == CHAT, f"{label}: the 401 came from {exc.path or '?'}, not {CHAT}"
    assert not NOT_AUTH.search(exc.detail), f"{label}: 401 but the reason is {exc.detail[:120]!r}"


@SUITE.check(
    "gateway-rejects-bad-key",
    "a chat call with a wrong key and with no key is each a 401 that says so, never a 5xx or a "
    "store error",
    requires=["gateway"],
)
def _(c):
    model = _model(c)
    _auth_rejection(c.with_key(BAD_KEY), model, "wrong key")
    _auth_rejection(c.with_key(None), model, "no key")


@SUITE.check(
    "gateway-limit-throttles",
    "on a key limited to n requests, the first n chat calls are served and call n+1 is a 429",
    requires=["gateway"],
)
def _(c):
    # The limit is per window (60 s on the lab's key): a rerun inside the window starts on a key
    # that is already used up and fails on its first call.  Wait out the window before a rerun.
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
    assert not other, f"{other[0]} while throttling: {statuses}"
    assert statuses[:n] == [200] * n, (
        f"calls 1..{n} on a key limited to {n} were not all served: {statuses} "
        "(a rerun within the limit's window starts on a used-up key)"
    )
    assert statuses[n] == 429, f"call {n + 1} against a limit of {n} was served: {statuses}"


@SUITE.check(
    "gateway-models-match-roles",
    "/v1/models lists exactly the declared role aliases (no backend ids, no extras)",
    requires=["gateway"],
)
def _(c):
    served, declared = sorted(c.models()), sorted(c.declared_models())
    assert declared, "the target declares no models"
    assert served == declared, f"/v1/models {served} != declared {declared}"


# --- feature ``turn-records``: the gateway's per-call log as neutral turn records --------------
#: a tag no request carries
NO_SUCH_TAG = "conformance-no-such-tag-zz"


def _turns(c):
    source, start, end, tags = c.turn_records()
    assert tags, "turn_records() names no tags"
    return source, start, end, list(tags), list(source.turns(start, end, tags))


@SUITE.check(
    "turn-records-are-neutral",
    "every turn of a window known to hold some is exactly the neutral turn record "
    f"({len(TURN_FIELDS)} fields, each of its kind): nothing else of the gateway's log",
    requires=["turn-records"],
)
def _(c):
    *_, got = _turns(c)
    assert got, "no turns in the window turn_records() names"
    for t in got:
        probs = turn_problems(t)
        assert not probs, f"turn {t.get('turn_id') if isinstance(t, dict) else t!r}: {probs}"


@SUITE.check(
    "turn-records-only-the-asked-tags",
    "every turn carries one of the tags asked for; a tag no request used gives no turns, and each "
    "tag alone gives exactly that tag's turns",
    requires=["turn-records"],
)
def _(c):
    source, start, end, tags, got = _turns(c)
    other = sorted({t["gateway_tag"] for t in got} - set(tags))
    assert not other, f"turns of tags not asked for: {other}"
    assert list(source.turns(start, end, [NO_SUCH_TAG])) == [], "turns for a tag nobody used"
    for tag in tags:
        alone = {t["turn_id"] for t in source.turns(start, end, [tag])}
        want = {t["turn_id"] for t in got if t["gateway_tag"] == tag}
        assert alone == want, f"{tag}: alone {sorted(alone)} != {sorted(want)}"


@SUITE.check(
    "turn-records-in-the-window",
    "every turn started inside the window asked for (whole seconds), and a window before any "
    "gives none",
    requires=["turn-records"],
)
def _(c):
    source, start, end, tags, got = _turns(c)
    late = [t["turn_id"] for t in got if not start - 1 < parse_iso(t["started_at"]) < end + 1]
    assert not late, f"turns outside [{start}, {end}]: {late}"
    first = min(parse_iso(t["started_at"]) for t in got)
    assert list(source.turns(first - 7200, first - 3600, tags)) == [], "turns before the window"


@SUITE.check(
    "turn-records-stable-ids",
    "reading the same window twice gives the same turn ids, once each (a re-read rewrites, never "
    "adds)",
    requires=["turn-records"],
)
def _(c):
    source, start, end, tags, got = _turns(c)
    ids = [t["turn_id"] for t in got]
    assert len(ids) == len(set(ids)), f"a turn id twice in one read: {ids}"
    again = sorted(t["turn_id"] for t in source.turns(start, end, tags))
    assert again == sorted(ids), f"a second read gave {again}, the first {sorted(ids)}"


def make_fake():
    return FakeInferenceClient()


MUTANTS = {
    "alias-swap": Mutant(
        WrongModelClient, "chat-echoes-requested-model", "replies come from a different model"
    ),
}
