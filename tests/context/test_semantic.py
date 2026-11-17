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
from homelabnext.conform.adapters.openai_compat import InferenceError
from homelabnext.context import (
    ContextStore,
    Document,
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
from homelabnext.context.model import Hit
from homelabnext.context_semantic import SemanticContextStore, default_tlp_of

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

    def decide_fields(self, model, questions, fields=(), *, state=None):
        self.calls.append((model, dict(questions), list(fields), state))
        if isinstance(self.reply, Exception):
            raise self.reply
        if isinstance(self.reply, list):  # one scripted reply per call
            r = self.reply.pop(0)
            if isinstance(r, Exception):
                raise r
            return r
        return self.reply


def test_judge_reranks_and_abstains():
    s = _store()
    q = _q({"d:"}, text="proxy", budget=5)
    base = [h.id for h in s.query(q)]
    assert set(base) == {"d:a", "d:b", "d:c"}
    rec = {pair_key("proxy", h.content): (h.id == "d:c", 0.9) for h in s.query(q)}
    got = JudgedStore(s, RecordedJudge(rec), mode="rerank").query(q)
    assert [h.id for h in got] == ["d:c"]
    assert [h.score for h in got] == sorted((h.score for h in got), reverse=True)
    none = dict.fromkeys(rec, (False, 0.9))
    assert JudgedStore(s, RecordedJudge(none), mode="rerank").query(q) == []
    low = dict.fromkeys(rec, (True, 0.2))
    assert JudgedStore(s, RecordedJudge(low), threshold=0.5, mode="rerank").query(q) == []


def test_judge_never_invents_a_verdict():
    h = _store().get("d:a", frozenset({"d:"}))
    with pytest.raises(JudgeError):
        RecordedJudge({}).judge("anything", h, tlp.Label.RED)


def test_gateway_judge_asks_a_noul_question_with_tlp_and_tag():
    h = _store().get("d:a", frozenset({"d:"}))
    client = _Client({"q": 0.8})
    v = GatewayJudge(client, tag="hnx-eval-test").judge("proxy?", h, tlp.Label.AMBER)
    assert v == Verdict(True, 0.8)
    model, questions, fields, state = client.calls[0]
    assert model == "fast-classifier" and ("X-HNX-TLP", "amber") in fields
    assert ("X-HNX-Tag", "hnx-eval-test") in fields
    assert questions == {"q": "Does this passage answer the question?"}
    assert state.startswith("Question: proxy?\nPassage: ") and "restart the proxy" in state


def test_gateway_judge_threshold_decides_yes():
    h = _store().get("d:a", frozenset({"d:"}))
    assert GatewayJudge(_Client({"q": 0.05}), tag="t").judge("q", h, tlp.Label.CLEAR) == Verdict(
        False, 0.05
    )
    assert GatewayJudge(_Client({"q": 0.12}), tag="t").judge("q", h, tlp.Label.CLEAR).answers
    assert (
        GatewayJudge(_Client({"q": 0.4}), tag="t", threshold=0.3)
        .judge("q", h, tlp.Label.CLEAR)
        .answers
    )
    with pytest.raises(ValueError):
        GatewayJudge(_Client({}), tag="t", threshold=1.5)


def test_gateway_judge_failures_are_judge_errors_and_the_store_falls_back():
    h = _store().get("d:a", frozenset({"d:"}))
    for bad in ({}, RuntimeError("down")):
        with pytest.raises(JudgeError):
            GatewayJudge(_Client(bad), tag="t").judge("q", h, tlp.Label.CLEAR)
    s = _store()
    q = _q({"d:"}, text="proxy", budget=5)
    base = [h.id for h in s.query(q)]
    broken = JudgedStore(s, GatewayJudge(_Client(RuntimeError("down")), tag="t"))
    assert [h.id for h in broken.query(q)] == base
    assert (
        JudgedStore(
            s, GatewayJudge(_Client(RuntimeError("down")), tag="t"), on_error="abstain"
        ).query(q)
        == []
    )


def _long_hit(n=5000):
    h = _store().get("d:a", frozenset({"d:"}))
    return Hit(h.id, h.kind, h.title, h.path, h.score, h.snippet, "x" * n, h.digest)


def test_gateway_judge_truncates_the_passage_by_chars_or_by_a_token_estimate():
    c = _Client({"q": 0.5})
    GatewayJudge(c, tag="t").judge("q", _long_hit(), tlp.Label.CLEAR)
    assert len(c.calls[0][3]) == len("Question: q\nPassage: ") + 1400
    c = _Client({"q": 0.5})
    GatewayJudge(c, tag="t", count_tokens=lambda t: len(t) // 4, max_tokens=100).judge(
        "q", _long_hit(), tlp.Label.CLEAR
    )
    assert len(c.calls[0][3]) - len("Question: q\nPassage: ") <= 400


def test_gateway_judge_shrinks_and_retries_once_on_http_500():
    err = InferenceError("HTTP 500", 500, "batch", "/v1/systemone")
    c = _Client([err, {"q": 0.5}])
    assert GatewayJudge(c, tag="t").judge("q", _long_hit(), tlp.Label.CLEAR).answers
    first, second = (len(call[3]) for call in c.calls)
    assert second < first and second - len("Question: q\nPassage: ") == int(1400 * 0.6)
    twice = _Client([err, err, {"q": 0.5}])
    with pytest.raises(JudgeError):
        GatewayJudge(twice, tag="t").judge("q", _long_hit(), tlp.Label.CLEAR)
    assert len(twice.calls) == 2
    other = _Client([InferenceError("HTTP 403", 403, "no", "/v1/systemone")])
    with pytest.raises(JudgeError):
        GatewayJudge(other, tag="t").judge("q", _long_hit(), tlp.Label.CLEAR)
    assert len(other.calls) == 1


class _Scripted:
    """A judge with a probability per document id; records the calls and the peak concurrency."""

    def __init__(self, probs, delay=0.0):
        import threading

        self.probs, self.delay, self.calls = probs, delay, []
        self._lock, self._live, self.peak = threading.Lock(), 0, 0

    def judge(self, question, hit, label):
        import time

        with self._lock:
            self.calls.append(hit.id)
            self._live += 1
            self.peak = max(self.peak, self._live)
        time.sleep(self.delay)
        with self._lock:
            self._live -= 1
        p = self.probs[hit.id]
        return Verdict(p >= 0.1, p)


def test_the_gate_keeps_the_stores_ranking_and_abstains_below_the_threshold():
    s = _store()
    q = _q({"d:"}, text="proxy", budget=5)
    base = s.query(q)
    ids = [h.id for h in base]
    # the judge likes the last hit best: the gate does not reorder
    probs = dict(zip(ids, [0.2, 0.3, 0.9], strict=False))
    got = JudgedStore(s, _Scripted(probs)).query(q)
    assert got == base
    low = dict.fromkeys(ids, 0.05)
    assert JudgedStore(s, _Scripted(low)).query(q) == []
    assert JudgedStore(s, _Scripted(probs), threshold=0.95).query(q) == []


def test_rerank_is_opt_in_and_orders_by_confidence():
    s = _store()
    q = _q({"d:"}, text="proxy", budget=5)
    ids = [h.id for h in s.query(q)]
    probs = dict(zip(ids, [0.2, 0.3, 0.9], strict=False))
    got = JudgedStore(s, _Scripted(probs), mode="rerank").query(q)
    assert [h.id for h in got] == [ids[2], ids[1], ids[0]]
    with pytest.raises(ValueError):
        JudgedStore(s, _Scripted(probs), mode="best")


def test_the_gate_stops_at_the_first_passage_that_clears_and_bounds_concurrency():
    s = _store()
    q = _q({"d:"}, text="proxy", budget=5)
    ids = [h.id for h in s.query(q)]
    first = _Scripted(dict.fromkeys(ids, 0.9))
    JudgedStore(s, first, workers=1, top_k=3).query(q)
    assert len(first.calls) == 1  # one worker: the first clears, the rest never start
    slow = _Scripted(dict.fromkeys(ids, 0.01), delay=0.05)
    assert JudgedStore(s, slow, workers=2, top_k=3).query(q) == []
    assert sorted(slow.calls) == sorted(ids) and slow.peak == 2
    one = _Scripted(dict.fromkeys(ids, 0.01), delay=0.02)
    JudgedStore(s, one, workers=1, top_k=3).query(q)
    assert one.peak == 1


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


# -- the adapter, on fakes (runs everywhere) -----------------------------------------------------

import math
import re
import sys
import types
from argparse import Namespace

DIM = 32


def _words(text):
    return re.findall(r"\w+", text.lower())


class _FakeEmbedder:
    """Bag-of-words hashing vectors, normalised: shared words mean similarity, no model."""

    def __init__(self, fail=False):
        self.fail, self.calls = fail, 0

    def batchtransform(self, texts):
        self.calls += 1
        if self.fail:
            raise RuntimeError("embedder down")
        out = []
        for t in texts:
            v = [0.0] * DIM
            for w in _words(t):
                v[sum(map(ord, w)) % DIM] += 1.0
            n = math.sqrt(sum(x * x for x in v)) or 1.0
            out.append([x / n for x in v])
        return out


class _FakeBm25:
    def __init__(self):
        self.docs = {}

    def index(self, rows):
        self.docs = {i: _words(t) for i, t, _ in rows}

    def search(self, query, limit):
        n = len(self.docs)
        scores = {}
        for i, toks in self.docs.items():
            s = 0.0
            for w in set(_words(query)):
                tf = toks.count(w)
                df = sum(w in t for t in self.docs.values())
                if tf:
                    s += tf * math.log(1 + n / df)
            if s > 0:
                scores[i] = s
        return sorted(scores.items(), key=lambda kv: -kv[1])[:limit]


def _sem(labels=None, ceiling="red", embedder=None, **kw):
    if labels is not None:
        kw["tlp_of"] = lambda d: tlp.read(labels.get(d.id))
    return SemanticContextStore(
        ceiling=ceiling, embedder=embedder or _FakeEmbedder(), sparse_factory=_FakeBm25, **kw
    )


ALL = frozenset({"d:"})


def test_ceiling_is_required_and_a_call_may_only_lower_it():
    with pytest.raises(TypeError):
        SemanticContextStore(embedder=_FakeEmbedder(), sparse_factory=_FakeBm25)
    labels = {"d:a": "clear", "d:b": "green", "d:c": "amber"}
    s = _sem(labels, ceiling="green")
    s.index([Document(i, "doc", "disk full overnight") for i in labels])
    q = _q(ALL, text="disk full", budget=10)
    assert {h.id for h in s.query(q)} == {"d:a", "d:b"}
    assert {h.id for h in s.query(q, ceiling="clear")} == {"d:a"}
    assert {h.id for h in s.query(q, ceiling="red")} == {"d:a", "d:b"}  # never raised
    with pytest.raises(NotFound):
        s.get("d:c", ALL, ceiling="red")
    with pytest.raises(NotFound):
        s.get("d:c", ALL)
    assert s.get("d:b", ALL).id == "d:b"
    assert s.tlp("d:b") is tlp.Label.GREEN
    with pytest.raises(NotFound):
        s.tlp("d:zz")


def test_a_replaced_document_takes_its_new_stricter_label():
    labels = {"d:x": "clear"}
    s = _sem(labels, ceiling="clear")
    s.index([Document("d:x", "doc", "disk full overnight")])
    assert [h.id for h in s.query(_q(ALL, text="disk full"))] == ["d:x"]
    labels["d:x"] = "red"
    s.index([Document("d:x", "doc", "disk full overnight again")])
    assert s.query(_q(ALL, text="disk full")) == []
    with pytest.raises(NotFound):
        s.get("d:x", ALL)


def test_a_failed_index_changes_nothing():
    emb = _FakeEmbedder()
    labels = {"d:x": "clear"}
    s = _sem(labels, ceiling="clear", embedder=emb)
    s.index([Document("d:x", "doc", "disk full overnight")])
    emb.fail = True
    labels["d:x"] = "red"
    with pytest.raises(RuntimeError):  # a replace that fails keeps the old version, label included
        s.index([Document("d:x", "doc", "changed text"), Document("d:y", "doc", "new one")])
    assert s.get("d:x", ALL).content == "disk full overnight"
    assert s.tlp("d:x") is tlp.Label.CLEAR
    with pytest.raises(NotFound):  # a failed add leaves no unlabelled document behind
        s.get("d:y", ALL)
    emb.fail = False
    assert [h.id for h in s.query(_q(ALL, text="disk full"))] == ["d:x"]  # and queries still work

    def boom(d):
        raise ValueError("no label")

    s2 = SemanticContextStore(
        ceiling="red", embedder=_FakeEmbedder(), sparse_factory=_FakeBm25, tlp_of=boom
    )
    with pytest.raises(ValueError):
        s2.index([Document("d:z", "doc", "anything")])
    assert s2.query(_q(ALL, text="anything")) == []


def test_a_malformed_batch_indexes_nothing():
    s = _sem()
    with pytest.raises(Exception):  # noqa: B017 - InvalidDocument, whichever subclass
        s.index([Document("d:ok", "doc", "fine"), Document("d:ok", "doc", "repeated id")])
    assert s.query(_q(ALL, text="fine")) == []


def test_default_label_is_the_strictest_marker_over_the_whole_document():
    def lab(text, title=""):
        return default_tlp_of(Document("d:x", "doc", text, title=title))

    assert lab("intro\ntlp: clear\n" + "x" * 5000 + "\ntlp: red\n") is tlp.Label.RED
    assert lab("TLP:GREEN body [TLP=AMBER] more") is tlp.Label.AMBER
    assert lab("no marker at all") is tlp.Label.RED  # unlabelled is red
    assert lab("body", title="TLP:RED") is tlp.Label.RED
    # a page that only quotes a marker is indistinguishable from one that carries it
    assert lab("this page explains that a record may say tlp: clear") is tlp.Label.CLEAR


def test_hidden_documents_change_neither_hits_nor_scores():
    base = [Document(f"d:p{i}", "doc", f"disk full on host {i} overnight") for i in range(4)]
    labels = {d.id: "clear" for d in base}
    plain = _sem(labels, ceiling="clear")
    plain.index(base)
    q = _q(ALL, text="disk full overnight", budget=20)
    before = [(h.id, h.score) for h in plain.query(q)]
    assert before
    hidden = [Document(f"d:h{i}", "doc", "disk full overnight disk disk") for i in range(30)]
    labels.update({d.id: "red" for d in hidden})
    mixed = _sem(labels, ceiling="clear")
    mixed.index(hidden + base)
    assert [(h.id, h.score) for h in mixed.query(q)] == before


def test_semantic_scoring_cutoffs_and_relations():
    s = _sem(min_similarity=0.9, min_score=0.0)
    s.index(
        [
            Document("d:a", "doc", "restart the proxy to clear the stuck session"),
            Document("d:b", "doc", "printer toner", links=("d:a",)),
        ]
    )
    got = [h.id for h in s.query(_q(ALL, text="proxy session", seeds=("d:b",)))]
    assert got[0] == "d:b" and "d:a" in got  # the seed, then what it links to
    strict = _sem(min_score=0.999)
    strict.index([Document("d:a", "doc", "restart the proxy")])
    assert strict.query(_q(ALL, text="proxy")) == []
    assert s.query(_q(ALL, text="zebra")) == []
    s.delete("d:a")
    assert [h.id for h in s.query(_q(ALL, text="printer"))] == ["d:b"]


def test_the_model_directory_must_be_exactly_the_pinned_files(tmp_path, monkeypatch):
    (tmp_path / "evil.py").write_text("print('x')")
    with pytest.raises(semantic_model.ModelError) as e:
        semantic_model.check_dir(tmp_path)
    assert "evil.py: unexpected file" in str(e.value)
    # the load path forces offline mode and reads only the verified directory
    seen = {}

    class _Emb:
        def __init__(self, path):
            seen["path"] = path

        def batchtransform(self, texts):
            return [[1.0]] * len(texts)

    fake = types.ModuleType("txtai")
    fake.Embeddings = _Emb
    monkeypatch.setitem(sys.modules, "txtai", fake)
    import homelabnext.context_semantic as cs

    monkeypatch.setattr(cs, "check_dir", lambda p: Path(p))
    for k in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE"):
        monkeypatch.delenv(k, raising=False)
    SemanticContextStore(tmp_path, ceiling="clear", sparse_factory=_FakeBm25)
    assert seen["path"] == str(tmp_path)
    assert os.environ["HF_HUB_OFFLINE"] == "1" and os.environ["TRANSFORMERS_OFFLINE"] == "1"


# -- judge failure and the eval's transport ------------------------------------------------------


class _Boom:
    def judge(self, question, hit, tlp_label):
        raise JudgeError("backend down")


def test_a_failing_judge_never_crashes_the_query():
    s = _sem()
    s.index([Document(f"d:{i}", "doc", f"proxy note {i}") for i in range(3)])
    q = _q(ALL, text="proxy", budget=5)
    own = [h.id for h in s.query(q)]
    assert [h.id for h in JudgedStore(s, _Boom()).query(q)] == own  # fallback: the store's order
    assert JudgedStore(s, _Boom(), on_error="abstain").query(q) == []
    with pytest.raises(ValueError):
        JudgedStore(s, _Boom(), on_error="guess")


def test_a_passage_above_the_judge_ceiling_is_never_sent():
    labels = {"d:0": "clear", "d:1": "red"}
    s = _sem(labels)
    s.index([Document(i, "doc", "proxy note") for i in labels])
    sent = []

    class _Spy:
        def judge(self, question, hit, label):
            sent.append((hit.id, label))
            return Verdict(True, 0.9)

    q = _q(ALL, text="proxy", budget=5)
    got = JudgedStore(s, _Spy(), judge_ceiling=tlp.Label.GREEN).query(q)
    assert all(label <= tlp.Label.GREEN for _, label in sent)
    assert [h.id for h in got] == [h.id for h in s.query(q)]  # fell back, nothing red was sent


def test_the_eval_judge_refuses_plaintext_with_a_token_unless_opted_in(monkeypatch):
    monkeypatch.setenv("HNX_EVAL_GATEWAY_TOKEN", "t")
    base = {
        "judge_record": None,
        "judge_url": "http://" + "gateway.example.internal" + ":" + "8000",
        "judge_token_env": "HNX_EVAL_GATEWAY_TOKEN",
        "judge_model": "fast-classifier",
        "judge_save": None,
        "judge_allow_plaintext": False,
    }
    with pytest.raises(ValueError, match="plaintext"):
        evalrun._make_judge(Namespace(**base))
    assert evalrun._make_judge(Namespace(**{**base, "judge_allow_plaintext": True})) is not None


# -- the real adapter (needs the extra and the provisioned model) -------------------------------


def _semantic(**kw):
    pytest.importorskip("txtai")
    model = os.environ.get("HNX_CONTEXT_MODEL_DIR")
    if not model:
        pytest.skip("the pinned model is not available (set HNX_CONTEXT_MODEL_DIR)")
    kw.setdefault("ceiling", "red")
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
    got = {h.id for h in s.query(_q(ALL, text="disk filled", budget=10))}
    assert got == {"d:open", "d:shared"}
    with pytest.raises(NotFound):
        s.get("d:secret", ALL)
    assert {h.id for h in s.query(_q(ALL, text="disk filled"), ceiling="clear")} == {"d:open"}


def test_semantic_unlabelled_is_red_and_finds_by_meaning():
    s = _semantic(ceiling="amber")
    s.index([Document("d:x", "doc", "how to repair the brakes of a car")])
    assert s.query(_q(ALL, text="automobile maintenance")) == []  # unlabelled: red
    s = _semantic(ceiling="red")
    s.index(
        [
            Document("d:x", "doc", "how to repair the brakes of a car"),
            Document("d:y", "doc", "bread"),
        ]
    )
    assert [h.id for h in s.query(_q(ALL, text="automobile maintenance"))][:1] == ["d:x"]


def test_semantic_min_score_lets_a_query_abstain():
    docs = [Document("d:x", "doc", "how to repair the brakes of a car")]
    loose = _semantic()
    loose.index(docs)
    assert loose.query(_q(ALL, text="brakes"))  # a shared word is a hit
    strict = _semantic(min_score=0.999)
    strict.index(docs)
    assert strict.query(_q(ALL, text="brakes")) == []
