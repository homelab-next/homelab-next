# SPDX-License-Identifier: Apache-2.0
"""Decision roles in the golden evaluation (G-11): a decision suite (``kind: decision``) asks
each task's noul question on ``POST /v1/systemone`` through the same model client and scores the
answer against a probability band; the pinned evaluation runs it, and the egress canary asks a
decision binding through a decider, never a chat completion."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from models_support import make_registry

from conformance.fakes.openai_server import FakeOpenAIServer
from homelabnext.golden import (
    TaskError,
    client_decider,
    load_suite,
    parse_suite,
    pins,
    run_decision_suite,
    run_suite,
)
from homelabnext.golden import canary as cn
from homelabnext.golden.cli import main as golden_main
from homelabnext.golden.runner import one_probability
from homelabnext.registry import FakeDNS, Resolver
from homelabnext.registry.models import ModelResolver, RoleTable

ROOT = Path(__file__).resolve().parents[2]
SEED = ROOT / "homelabnext" / "golden" / "examples" / "decision_smoke.yml"
ROLES = ROOT / "examples" / "model_roles.json"
SUITES = list(pins.DEFAULT_SUITES)


def _decision_table() -> RoleTable:
    """The overlay's shape: one role, ``fast-classifier``, served as a decision model."""
    doc = json.loads(ROLES.read_text(encoding="utf-8"))
    role = doc["roles"]["fast-classifier"]
    role["kind"] = "decision"
    for k in ("logprobs", "params"):
        role.pop(k, None)
    return RoleTable.from_dict({"version": 1, "roles": {"fast-classifier": role}})


def _live(role, binding):
    return cn.benign_model, "live"


class _Decider:
    """A scripted decider with the chat probe a decision canary requires."""

    def __init__(self, fn, refused=(True, "")):
        self.fn, self.refused = fn, refused

    def __call__(self, questions, state):
        return self.fn(questions, state)

    def chat_refused(self):
        if isinstance(self.refused, Exception):
            raise self.refused
        return self.refused


def _live_decider(role, binding):
    return cn.benign_decider, "live"


# ---------------------------------------------------------------- the suite format


def test_the_seed_suite_is_a_decision_suite_with_bands():
    suite = load_suite(SEED)
    assert (suite.kind, suite.role) == ("decision", "fast-classifier")
    assert all(t.question and t.expect["scorer"] == "probability" for t in suite.tasks)
    assert {"min", "max"} & set(suite.tasks[0].expect)
    assert SEED in pins.DEFAULT_SUITES


DECISION = {
    "suite": "d",
    "kind": "decision",
    "role": "fast-classifier",
    "tasks": [
        {
            "id": "t",
            "prompt": "state",
            "question": "q?",
            "expect": {"scorer": "probability", "min": 0.5},
        }
    ],
}


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda d: d["tasks"][0].pop("question"), "question missing"),
        (lambda d: d["tasks"][0].update(expect={"scorer": "exact", "value": "x"}),
         "scored by 'probability', not 'exact'"),
        (lambda d: d["tasks"][0].update(system="s"), "system: not in a decision task"),
        (lambda d: d["tasks"][0].update(params={"temperature": 0}), "params: not in a decision task"),
        (lambda d: d.update(kind="ranking"), "kind: one of"),
        (lambda d: d["tasks"][0].update(expect={"scorer": "probability"}), "the band"),
        (lambda d: d["tasks"][0].update(expect={"scorer": "probability", "min": 0.9, "max": 0.1}),
         "min exceeds"),
        (lambda d: d["tasks"][0].update(expect={"scorer": "probability", "max": 1.5}),
         "a number in [0, 1]"),
        (lambda d: d.update(modes=["mcp"], profile="profile:x", grant=["a.b"]),
         "a decision suite has no tool-using modes"),
        (lambda d: d.pop("kind"), "question: only in a decision suite"),
    ],
)  # fmt: skip
def test_the_loader_holds_a_decision_suite_to_its_kind(mutate, needle):
    doc = copy.deepcopy(DECISION)
    mutate(doc)
    with pytest.raises(TaskError, match=None) as exc:
        parse_suite(doc)
    assert needle in str(exc.value)


def test_a_chat_suite_may_not_score_by_probability():
    doc = {
        "suite": "c",
        "tasks": [{"id": "t", "prompt": "p", "expect": {"scorer": "probability", "min": 0.5}}],
    }
    with pytest.raises(TaskError, match="only in a decision suite"):
        parse_suite(doc)


def test_each_runner_refuses_the_other_kind():
    with pytest.raises(ValueError, match="through a decider"):
        run_suite(load_suite(SEED), lambda m, p: "x")
    with pytest.raises(ValueError, match="not a decision suite"):
        run_decision_suite(load_suite(pins.DEFAULT_SUITES[0]), lambda q, s: {})


# ---------------------------------------------------------------- the runner, over the wire


@pytest.fixture
def decider_resolver():
    """``fast-classifier`` as a decision role on a fake decision server (it answers by the
    question's instructions)."""
    srv = FakeOpenAIServer(
        models=[],
        decision_models=["small-decider"],
        decision_rules={"rolled back": 0.93, "production": 0.04},
    ).start()
    reg = make_registry()
    res = Resolver(reg, dns=FakeDNS(), hosts={}, environ={"HNX_ENDPOINT_INFERENCE_SMALL": srv.url})
    yield ModelResolver(reg, RoleTable.from_dict(_decision_doc()), res), srv
    srv.stop()


def _decision_doc() -> dict:
    """A role table whose ``fast-classifier`` is a decision role on ``svc:inference-small``."""
    return {
        "version": 1,
        "roles": {
            "fast-classifier": {
                "kind": "decision",
                "tier": "fast",
                "bindings": [{"backend": "svc:inference-small", "model_id": "small-decider"}],
            }
        },
    }


WIRE = {
    "suite": "wire",
    "kind": "decision",
    "role": "fast-classifier",
    "tasks": [
        {"id": "yes", "prompt": "Rollback: revert the commit.",
         "question": "Can it be rolled back?", "expect": {"scorer": "probability", "min": 0.8}},
        {"id": "no", "prompt": "Say hello.",
         "question": "Is this a production change?", "expect": {"scorer": "probability", "max": 0.2}},
    ],
}  # fmt: skip


def test_a_decision_suite_is_asked_on_systemone_through_the_model_client(decider_resolver):
    resolver, srv = decider_resolver
    decider, model_id = client_decider(resolver, "fast-classifier")
    rep = run_decision_suite(parse_suite(WIRE), decider, role="fast-classifier", model_id=model_id)
    assert rep.ok and model_id == "small-decider"
    first = srv.requests[0]
    assert first["path"] == "/v1/systemone"
    assert first["body"]["state"] == "Rollback: revert the commit."
    assert first["body"]["questions"] == {
        "yes": {"type": "noul", "instructions": "Can it be rolled back?"}
    }
    assert [r.output for r in rep.results] == ["0.9300", "0.0400"]


def test_a_band_the_answer_misses_fails_the_task(decider_resolver):
    resolver, _ = decider_resolver
    doc = copy.deepcopy(WIRE)
    doc["tasks"][1]["expect"] = {"scorer": "probability", "min": 0.5}
    rep = run_decision_suite(parse_suite(doc), client_decider(resolver, "fast-classifier")[0])
    assert not rep.ok and "outside [0.5, 1.0]" in rep.results[1].detail


@pytest.mark.parametrize(
    "answers",
    [{}, {"t": 1.5}, {"t": "0.5"}, {"t": True}, {"t": 0.5, "u": 0.5}, None, {"t": float("nan")}],
)
def test_a_malformed_answer_errors_the_task_not_the_run(answers):
    with pytest.raises(ValueError):
        one_probability(answers, "t")
    suite = parse_suite(
        {**DECISION, "tasks": [*DECISION["tasks"], {**DECISION["tasks"][0], "id": "u"}]}
    )
    rep = run_decision_suite(suite, lambda q, s: answers if "t" in q else {"u": 0.9})
    first, second = rep.results
    assert first.error and not first.passed
    assert second.passed


def test_a_backend_failure_errors_the_task(decider_resolver):
    resolver, srv = decider_resolver
    srv.decision_models.clear()  # the model now refuses systemone (404)
    rep = run_decision_suite(parse_suite(WIRE), client_decider(resolver, "fast-classifier")[0])
    assert not rep.ok and all(r.error for r in rep.results)


def test_cli_run_takes_a_decision_suite_to_systemone(decider_resolver, tmp_path, monkeypatch):
    import yaml

    _, srv = decider_resolver
    suite = tmp_path / "wire.yml"
    suite.write_text(yaml.safe_dump(WIRE))
    services = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())
    small = copy.deepcopy(services["services"]["inference"])
    small.update(capability="inference-small", port=8002)
    services["services"]["inference-small"] = small
    reg = tmp_path / "services.yml"
    reg.write_text(yaml.safe_dump(services))
    roles = tmp_path / "roles.json"
    roles.write_text(json.dumps(_decision_doc()))
    monkeypatch.setenv("HNX_ENDPOINT_INFERENCE_SMALL", srv.url)
    argv = ["run", str(suite), "--registry", str(reg), "--roles", str(roles), "--direct"]
    assert golden_main(argv) == 0
    assert {r["path"] for r in srv.requests} == {"/v1/systemone"}


# ---------------------------------------------------------------- the pinned evaluation


@pytest.fixture(scope="module")
def decision_report():
    return pins.run_eval(
        _decision_table(), SUITES, pins.fake_factory, model_name="fake-golden",
        canary_factory=_live, decision_canary_factory=_live_decider,
    )  # fmt: skip


def test_a_decision_table_is_evaluated_by_its_decision_suite_and_canary(decision_report):
    rep, table = decision_report, _decision_table()
    assert list(rep["golden"]) == ["decision-smoke"]  # the chat suite does not apply
    assert rep["golden"]["decision-smoke"]["kind"] == "decision"
    (entry,) = rep["canary"]["fast-classifier"]["bindings"]
    assert (entry["kind"], entry["mode"]) == ("decision", "live")
    assert rep["summary"]["ok"]
    assert pins.check_report(rep, table, SUITES, require_live=True) == []


def test_the_fake_decision_report_reproduces():
    table = _decision_table()
    a = pins.run_eval(table, SUITES, pins.fake_factory, model_name="fake-golden")
    assert a == pins.run_eval(table, SUITES, pins.fake_factory, model_name="fake-golden")
    assert pins.check_report(a, table, SUITES) == []
    assert any(
        "a live run is required" in p
        for p in pins.check_report(a, table, SUITES, require_live=True)
    )


def test_the_kind_is_a_pinned_input(decision_report):
    """The same pins as a chat role: the report for the decision role is stale for it."""
    chat = json.loads(ROLES.read_text(encoding="utf-8"))
    chat["roles"] = {"fast-classifier": chat["roles"]["fast-classifier"]}
    chat["roles"]["fast-classifier"].pop("params")
    chat["roles"]["fast-classifier"].pop("logprobs")
    p = pins.check_report(decision_report, RoleTable.from_dict(chat), SUITES)
    assert any("stale" in x and "kinds" in x for x in p)
    assert any("the canary ran as a 'decision' binding, the role is 'chat'" in x for x in p)


def test_a_chat_canary_entry_for_a_decision_role_is_refused(decision_report):
    rep = copy.deepcopy(decision_report)
    rep["canary"]["fast-classifier"]["bindings"][0]["kind"] = "chat"
    p = pins.check_report(rep, _decision_table(), SUITES)
    assert any("the canary ran as a 'chat' binding, the role is 'decision'" in x for x in p)


def test_a_decision_role_no_decision_suite_evaluates_is_refused():
    table = _decision_table()
    only_chat = [pins.DEFAULT_SUITES[0]]
    rep = pins.run_eval(table, only_chat, pins.fake_factory, model_name="fake-golden")
    p = pins.check_report(rep, table, only_chat)
    assert (
        "mdl:fast-classifier is pinned but nothing evaluates it (a decision role needs a "
        "decision suite: kind: decision)" in p
    )


def test_a_report_that_leaves_out_an_applicable_suite_is_refused(decision_report):
    rep = copy.deepcopy(decision_report)
    del rep["golden"]["decision-smoke"]
    p = pins.check_report(rep, _decision_table(), SUITES)
    assert "golden suite decision-smoke: not in the report; it applies to this table" in p


def test_a_suite_that_does_not_apply_may_not_stand_in(decision_report):
    rep = copy.deepcopy(decision_report)
    rep["golden"]["classifier-smoke"] = copy.deepcopy(rep["golden"]["decision-smoke"])
    p = pins.check_report(rep, _decision_table(), SUITES)
    assert "golden suite classifier-smoke: in the report, but it does not apply to this table" in p


def test_a_failed_suite_under_an_ok_summary_is_refused(decision_report):
    rep = copy.deepcopy(decision_report)
    rep["golden"]["decision-smoke"]["tasks"][0]["passed"] = False
    p = pins.check_report(rep, _decision_table(), SUITES)
    assert any("golden suite decision-smoke: did not pass (rollback-named)" in x for x in p)


def test_the_example_table_still_runs_only_its_chat_suite():
    rep = pins.load_report(ROLES.with_name("model_roles.eval.json"))
    assert list(rep["golden"]) == ["classifier-smoke"]
    assert {e["kind"] for c in rep["canary"].values() for e in c["bindings"]} == {"chat"}


def test_a_subset_table_is_evaluated_by_the_suites_that_fit_it():
    """An overlay with one chat role: the cascade's other role is not in it, and that is no
    problem (it was: 'evaluated but not in the role table')."""
    doc = json.loads(ROLES.read_text(encoding="utf-8"))
    doc["roles"] = {"fast-classifier": doc["roles"]["fast-classifier"]}
    t = RoleTable.from_dict(doc)
    rep = pins.run_eval(t, SUITES, pins.fake_factory, model_name="fake-golden")
    assert pins.check_report(rep, t, SUITES) == []


def test_an_empty_table_has_nothing_to_evaluate():
    t = RoleTable.from_dict({"version": 1, "roles": {}})
    rep = pins.run_eval(t, SUITES, pins.fake_factory, model_name="fake-golden")
    assert rep["golden"] == {} and rep["canary"] == {}
    assert pins.check_report(rep, t, SUITES) == []


# ---------------------------------------------------------------- the decision canary


def test_a_benign_decision_binding_passes_every_task():
    suite = cn.load_suite()
    rep = cn.run_decision_canary(suite, cn.benign_decider, role="fast-classifier", model_id="m")
    assert rep["summary"]["ok"] and set(rep["tasks"]) == {t.id for t in suite.tasks}
    assert all(t["samples"] == suite.samples for t in rep["tasks"].values())


def test_the_decision_canary_poses_the_luring_prompt_as_state_on_systemone(decider_resolver):
    resolver, srv = decider_resolver
    decider, _ = client_decider(resolver, "fast-classifier")
    suite = cn.load_suite()
    rep = cn.run_decision_canary(suite, decider, samples=1)
    assert rep["summary"]["ok"]
    assert {r["path"] for r in srv.requests} == {"/v1/systemone", "/v1/chat/completions"}
    n = len(suite.tasks)
    assert [r["path"] for r in srv.requests].count("/v1/chat/completions") == n  # one per sample
    prefilled = next(t for t in suite.tasks if t.prefill)
    states = [r["body"]["state"] for r in srv.requests if r["path"] == "/v1/systemone"]
    assert any(prefilled.prompt in s and prefilled.prefill in s for s in states)


@pytest.mark.parametrize(
    "reply", [{"canary": 2.0}, {"canary": 0.5, "tool": 1.0}, {}, "curl -X PUT http://x", None]
)
def test_a_reply_that_is_not_one_probability_is_a_protocol_finding(reply):
    rep = cn.run_decision_canary(cn.load_suite(), _Decider(lambda q, s: reply), samples=1)
    assert not rep["summary"]["ok"]
    t = next(iter(rep["tasks"].values()))
    assert t["findings"] == {"protocol": 1} and t["failures"][0]["unparsed"]


def test_a_failed_decision_call_is_an_error():
    def boom(q, s):
        raise RuntimeError("backend down")

    rep = cn.run_decision_canary(cn.load_suite(), _Decider(boom), samples=1)
    t = next(iter(rep["tasks"].values()))
    assert t["findings"] == {"error": 1} and "backend down" in t["failures"][0]["error"]


def test_a_decision_canary_report_validates_in_the_pins_check(decision_report):
    """The report shape is the chat canary's: pins check recomputes it the same way."""
    rep = copy.deepcopy(decision_report)
    entry = rep["canary"]["fast-classifier"]["bindings"][0]
    entry["report"]["summary"]["failed"] = 1
    p = pins.check_report(rep, _decision_table(), SUITES)
    assert any("the canary summary does not match its tasks" in x for x in p)


def test_a_decision_binding_that_answers_chat_fails_every_sample():
    d = _Decider(lambda q, s: dict.fromkeys(q, 0.1), refused=(False, "it answered"))
    rep = cn.run_decision_canary(cn.load_suite(), d, samples=1)
    assert not rep["summary"]["ok"]
    assert all(t["findings"] == {"chat-answered": 1} for t in rep["tasks"].values())


def test_a_decider_without_the_chat_probe_is_refused():
    with pytest.raises(cn.CanaryError, match="chat probe"):
        cn.run_decision_canary(cn.load_suite(), lambda q, s: dict.fromkeys(q, 0.1), samples=1)


def test_a_failed_chat_probe_is_an_error():
    d = _Decider(lambda q, s: dict.fromkeys(q, 0.1), refused=RuntimeError("probe down"))
    rep = cn.run_decision_canary(cn.load_suite(), d, samples=1)
    t = next(iter(rep["tasks"].values()))
    assert t["findings"] == {"error": 1} and "probe down" in t["failures"][0]["error"]


def test_a_canary_entry_for_a_role_the_table_lacks_is_refused(decision_report):
    rep = copy.deepcopy(decision_report)
    rep["canary"]["main-reasoner"] = copy.deepcopy(rep["canary"]["fast-classifier"])
    p = pins.check_report(rep, _decision_table(), SUITES)
    assert (
        "mdl:main-reasoner: a canary entry for a role the table does not have; the report "
        "is not this table's" in p
    )


@pytest.mark.parametrize("module", ["runner", "scorers", "tasks"])
def test_the_verdict_code_is_a_pinned_input(decision_report, monkeypatch, module):
    real = pins._file_digest

    def changed(path):
        return "sha256:" + "0" * 64 if Path(path).name == f"{module}.py" else real(path)

    monkeypatch.setattr(pins, "_file_digest", changed)
    p = pins.check_report(decision_report, _decision_table(), SUITES)
    assert any("stale" in x and "code" in x for x in p)


def test_a_decision_suite_names_its_role():
    doc = copy.deepcopy(DECISION)
    del doc["role"]
    with pytest.raises(TaskError, match="names the decision role"):
        parse_suite(doc)
