# SPDX-License-Identifier: Apache-2.0
"""The semantic context adapter, its pinned model, the judge and the eval harness.

Everything that needs the optional ``context-semantic`` extra and the provisioned model directory
(``HNX_CONTEXT_MODEL_DIR``) skips without them; the rest runs on the standard library.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from homelabnext import tlp
from homelabnext.conform.adapters.openai_compat import ChatResult
from homelabnext.context import (
    ContextStore,
    Document,
    Hit,
    NotFound,
    Query,
    evalrun,
    semantic_model,
)
from homelabnext.context.judge import (
    GatewayJudge,
    JudgedStore,
    JudgeError,
    RecordedJudge,
    Verdict,
    pair_key,
)

ROOT = Path(__file__).resolve().parents[2]
QUESTIONS = ROOT / "evals" / "context" / "questions.json"


def _q(allowed, **kw):
    return Query(allowed=frozenset(allowed), **kw)


# -- the pinned model --------------------------------------------------------------------------


def test_manifest_is_pinned_and_shaped():
    assert len(semantic_model.REVISION) == 40 and set(semantic_model.REVISION) <= set(
        "0123456789abcdef"
    )
    for rel, (sha, size) in semantic_model.FILES.items():
        assert len(sha) == 64 and size > 0 and not rel.startswith("/") and ".." not in rel


def test_check_dir_refuses_missing_and_tampered(tmp_path):
    with pytest.raises(semantic_model.ModelError):
        semantic_model.check_dir(tmp_path / "absent")
    with pytest.raises(semantic_model.ModelError, match="missing"):
        semantic_model.check_dir(tmp_path)
    (tmp_path / "config.json").write_text("{}")
    with pytest.raises(semantic_model.ModelError, match="wrong size"):
        semantic_model.check_dir(tmp_path)


def test_fetch_refuses_a_shallow_destination():
    with pytest.raises(semantic_model.ModelError, match="shallow"):
        semantic_model.fetch("/")
    with pytest.raises(semantic_model.ModelError, match="shallow"):
        semantic_model.fetch("/tmp")


# -- the judge ---------------------------------------------------------------------------------


def _store():
    s = ContextStore()
    s.index(
        [
            Document("d:a", "doc", "restart the proxy to clear the stuck session"),
            Document("d:b", "doc", "proxy certificates are renewed every month"),
            Document("d:c", "doc", "proxy logs rotate weekly"),
        ]
    )
    return s


class _Client:
    def __init__(self, reply):
        self.reply, self.calls = reply, []

    def chat_fields(self, model, messages, fields, *, max_tokens=64):
        self.calls.append((model, messages, list(fields)))
        return ChatResult(self.reply, "stop", model)


def test_judge_reranks_and_abstains():
    s = _store()
    q = _q({"d:"}, text="proxy", budget=5)
    base = [h.id for h in s.query(q)]
    assert set(base) == {"d:a", "d:b", "d:c"}
    rec = {pair_key("proxy", h.content): (h.id == "d:c", 0.9) for h in s.query(q)}
    got = JudgedStore(s, RecordedJudge(rec)).query(q)
    assert [h.id for h in got] == ["d:c"]
    assert [h.score for h in got] == sorted((h.score for h in got), reverse=True)
    none = dict.fromkeys(rec, (False, 0.9))
    assert JudgedStore(s, RecordedJudge(none)).query(q) == []
    low = dict.fromkeys(rec, (True, 0.2))
    assert JudgedStore(s, RecordedJudge(low), threshold=0.5).query(q) == []


def test_judge_never_invents_a_verdict():
    h = _store().get("d:a", frozenset({"d:"}))
    with pytest.raises(JudgeError):
        RecordedJudge({}).judge("anything", h, tlp.Label.RED)


def test_gateway_judge_sends_tlp_and_tag_and_parses():
    h = _store().get("d:a", frozenset({"d:"}))
    client = _Client('{"answers": "yes", "confidence": 0.8}')
    v = GatewayJudge(client, tag="hnx-eval-test").judge("proxy?", h, tlp.Label.AMBER)
    assert v == Verdict(True, 0.8)
    model, messages, fields = client.calls[0]
    assert model == "fast-classifier" and ("X-HNX-TLP", "amber") in fields
    assert ("X-HNX-Tag", "hnx-eval-test") in fields
    assert "restart the proxy" in messages[1]["content"]
    for bad in (
        "nope",
        '{"answers": "maybe", "confidence": 0.5}',
        '{"answers": "yes", "confidence": 3}',
    ):
        with pytest.raises(JudgeError):
            GatewayJudge(_Client(bad), tag="t").judge("q", h, tlp.Label.CLEAR)


# -- the eval harness --------------------------------------------------------------------------


def test_questions_are_validated(tmp_path):
    p = tmp_path / "q.json"
    p.write_text(json.dumps([{"id": "a", "kind": "none", "q": "x", "answers": ["d:a"]}]))
    with pytest.raises(ValueError, match="none"):
        evalrun.load_questions(p)
    p.write_text(json.dumps([{"id": "a", "kind": "weird", "q": "x"}]))
    with pytest.raises(ValueError):
        evalrun.load_questions(p)


def test_corpus_refuses_vacuous_input(tmp_path):
    with pytest.raises(ValueError, match="exactly one"):
        evalrun.load_corpus()
    (tmp_path / "empty").mkdir()
    with pytest.raises(ValueError, match="empty"):
        evalrun.load_corpus(docs=str(tmp_path / "empty"))
    c = tmp_path / "c.jsonl"
    c.write_text("")
    with pytest.raises(ValueError, match="empty"):
        evalrun.load_corpus(corpus=str(c))


def test_jsonl_corpus_labels_default_to_red(tmp_path):
    c = tmp_path / "c.jsonl"
    rows = [
        {"id": "d:a", "kind": "doc", "title": "A", "content": "alpha"},
        {"id": "d:b", "kind": "doc", "title": "B", "content": "beta", "tlp": "green"},
    ]
    c.write_text("\n".join(json.dumps(r) for r in rows))
    docs, labels = evalrun.load_corpus(corpus=str(c))
    assert len(docs) == 2 and labels == {"d:a": tlp.Label.RED, "d:b": tlp.Label.GREEN}


def test_evaluate_metrics_on_a_tiny_corpus():
    docs = [
        Document("d:a", "doc", "the proxy certificate expired on friday"),
        Document("d:b", "doc", "the printer is out of toner"),
    ]
    qs = [
        evalrun.Question("1", "symptom", "proxy certificate expired", ("d:a",)),
        evalrun.Question("2", "howto", "printer toner", ("d:b",)),
        evalrun.Question("3", "none", "zebra migration", ()),
    ]
    (r,) = evalrun.evaluate({"keyword": evalrun._keyword}, docs, qs)
    assert (r.hit1, r.hit5, r.mrr) == (1.0, 1.0, 1.0)
    assert r.abstain_recall == 1.0 and r.abstain_precision == 1.0 and r.false_abstains == 0
    assert "| keyword |" in evalrun.render([r], 2, 1)
    with pytest.raises(ValueError, match="not in the corpus"):
        evalrun.evaluate(
            {"keyword": evalrun._keyword}, docs, [evalrun.Question("9", "howto", "x", ("d:zz",))]
        )


def test_public_fixture_questions_point_at_real_docs():
    docs, _ = evalrun.load_corpus(docs=str(ROOT / "docs"))
    qs = evalrun.load_questions(QUESTIONS)
    ids = {d.id for d in docs}
    assert sum(q.kind == "none" for q in qs) >= 5 and len(qs) >= 25
    assert {a for q in qs for a in q.answers} <= ids
    assert {q.kind for q in qs} == set(evalrun.KINDS)


# -- the adapter (needs the extra and the provisioned model) ------------------------------------


def _semantic(**kw):
    pytest.importorskip("txtai")
    model = os.environ.get("HNX_CONTEXT_MODEL_DIR")
    if not model:
        pytest.skip("HNX_CONTEXT_MODEL_DIR is not set")
    from homelabnext.context.semantic import SemanticContextStore

    return SemanticContextStore(model, **kw)


def test_semantic_passes_the_conformance_suite():
    _semantic()
    from homelabnext.conform.runner import run_capability

    run = run_capability("context", "context-semantic", ROOT)
    assert run.error is None and run.too_few is None
    assert not run.failed_must and not run.failed_should, [r.evidence for r in run.results]


def test_semantic_tlp_ceiling_hides_what_is_above_it():
    labels = {"d:open": "clear", "d:shared": "green", "d:secret": "red"}
    s = _semantic(ceiling="green", tlp_of=lambda d: tlp.read(labels[d.id]))
    s.index([Document(i, "doc", "the disk filled up overnight") for i in labels])
    allowed = frozenset({"d:"})
    got = {h.id for h in s.query(_q(allowed, text="disk filled", budget=10))}
    assert got == {"d:open", "d:shared"}
    with pytest.raises(NotFound):
        s.get("d:secret", allowed)
    assert {h.id for h in s.query(_q(allowed, text="disk filled"), ceiling="red")} >= {"d:secret"}
    assert {h.id for h in s.query(_q(allowed, text="disk filled"), ceiling="clear")} == {"d:open"}
    assert s.tlp("d:shared") is tlp.Label.GREEN
    assert isinstance(s.get("d:open", allowed), Hit)


def test_semantic_unlabelled_is_red_and_finds_by_meaning():
    s = _semantic(ceiling="amber")
    s.index([Document("d:x", "doc", "how to repair the brakes of a car")])
    assert s.query(_q({"d:"}, text="automobile maintenance")) == []  # unlabelled: red
    s = _semantic(ceiling="red")
    s.index(
        [
            Document("d:x", "doc", "how to repair the brakes of a car"),
            Document("d:y", "doc", "bread"),
        ]
    )
    assert [h.id for h in s.query(_q({"d:"}, text="automobile maintenance"))][:1] == ["d:x"]


def test_semantic_min_score_lets_a_query_abstain():
    docs = [Document("d:x", "doc", "how to repair the brakes of a car")]
    loose = _semantic()
    loose.index(docs)
    assert loose.query(_q({"d:"}, text="brakes"))  # a shared word is a hit
    strict = _semantic(min_score=0.999)
    strict.index(docs)
    assert strict.query(_q({"d:"}, text="brakes")) == []
