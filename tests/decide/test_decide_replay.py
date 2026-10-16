# SPDX-License-Identifier: Apache-2.0
"""Replay gate and the synthetic-gold-set evaluation harness."""

import json
from pathlib import Path

from decide_support import fixed

from homelabnext.decide import (
    Record,
    baseline_from_records,
    compare,
    gate,
    load_records,
    replay,
)
from homelabnext.decide.evalset import PhraseTier, demo_cascade, generate_gold_set
from homelabnext.decide.replay import dump_records

DATA = Path(__file__).parent / "data"
SEED, N = 7, 200
FIXED_COVERAGE = 0.885  # 177 of 200 decided without a human


def test_gold_set_is_deterministic():
    a, b = generate_gold_set(N, SEED), generate_gold_set(N, SEED)
    assert [r.to_dict() for r in a] == [r.to_dict() for r in b]
    assert generate_gold_set(N, SEED + 1)[0].to_dict() != a[0].to_dict()
    assert a[0].to_dict() == json.loads((DATA / "gold_first.json").read_text())


def test_synthetic_eval_reproduces_a_fixed_coverage_number():
    rep = replay(generate_gold_set(N, SEED), demo_cascade())
    assert (rep.automatic, rep.n) == (177, 200)
    assert rep.coverage == FIXED_COVERAGE
    assert rep.wrong == 0 and rep.error_rate == 0.0 and rep.impact_under == 0
    assert {k: v.answered for k, v in rep.per_tier.items()} == {
        "floor": 83,
        "small": 65,
        "large": 29,
    }
    assert gate(rep).passed


def test_replay_report_matches_golden_file():
    recs = generate_gold_set(N, SEED)
    cand = replay(recs, demo_cascade())
    base = replay(recs, _floor_only())
    out = {"report": cand.to_dict(), "baseline": base.to_dict(), "compare": compare(cand, base)}
    assert out == json.loads((DATA / "replay_report.json").read_text())


def _floor_only():
    from homelabnext.decide import parse_spec
    from homelabnext.decide.evalset import EXAMPLES, load_spec

    doc = load_spec(EXAMPLES / "decision_spec.yml")
    only = parse_spec(
        {
            "id": "floor-only",
            "version": 1,
            "question_set": list(doc.question_set),
            "decision_table": [{"when": a, "then": b} for a, b in doc.decision_table],
            "tiers": [{"name": "floor", "acts": True}],
            "error_direction": "fail-closed",
            "on_error": "escalate",
            "latency_budget_ms": 1000,
            "sample_audit_pct": 0,
        }
    )
    full = demo_cascade()
    from homelabnext.decide import Cascade

    return Cascade(only, {"floor": full.tiers["floor"]}, full.scanner)


def test_candidate_vs_baseline_coverage_gain():
    recs = generate_gold_set(N, SEED)
    cmp = compare(replay(recs, demo_cascade()), replay(recs, _floor_only()))
    assert cmp["coverage_baseline"] == 0.415 and cmp["coverage_delta"] == 0.47
    assert cmp["error_rate_delta"] == 0.0 and cmp["newly_wrong"] == []


def wrong_small():
    """A small tier that is confidently wrong about one known phrase."""
    return PhraseTier(
        "small", {"there is no way back once this is applied": "accept"}, conf_hit=0.97
    )


def test_hard_rule_acting_tier_with_a_confident_error_fails_the_gate():
    rep = replay(generate_gold_set(N, SEED), demo_cascade(small=wrong_small()))
    assert rep.wrong > 0 and rep.per_tier["small"].wrong == rep.wrong
    assert rep.acting_wrong == rep.wrong
    res = gate(rep)
    assert not res.passed and "zero confident errors" in res.failures[0]
    # no option waives it
    assert not gate(rep, max_error_rate_increase=1.0, min_coverage=0.0).passed


def test_advisory_tier_errors_are_reported_but_do_not_trip_the_hard_rule():
    from decide_support import spec_doc

    from homelabnext.decide import Cascade, parse_spec

    doc = spec_doc(
        tiers=[{"name": "floor", "acts": True}, {"name": "small", "model_role": "mdl:a"}]
    )
    s = parse_spec(doc)
    c = Cascade(s, {"floor": fixed("floor", "reject", 1.0), "small": fixed("small", "reject")})
    recs = [Record("a", _item("a"), gold="accept")]
    rep = replay(recs, c)
    assert rep.wrong == 1 and rep.acting_wrong == 1  # the floor acts and was wrong
    s2 = parse_spec(spec_doc(tiers=[{"name": "floor"}, {"name": "small", "model_role": "mdl:a"}]))
    c2 = Cascade(s2, {"floor": fixed("floor", "reject", 1.0), "small": fixed("small", "reject")})
    rep2 = replay(recs, c2)
    assert rep2.wrong == 1 and rep2.acting_wrong == 0 and gate(rep2).passed


def _item(i):
    from homelabnext.decide import Item

    return Item(i, "text")


def test_gate_needs_gold_labels():
    from homelabnext.decide import Cascade

    c = Cascade(_spec_floor(), {"floor": fixed("floor", "accept", 1.0)})
    rep = replay([Record("a", _item("a"))], c)
    assert not gate(rep).passed and "no gold-labelled" in gate(rep).failures[0]


def _spec_floor():
    from decide_support import spec

    return spec(tiers=[{"name": "floor", "acts": True}])


def test_gate_baseline_rules():
    recs = generate_gold_set(N, SEED)
    cand = replay(recs, demo_cascade())
    worse = replay(recs, demo_cascade(small=wrong_small()))
    res = gate(cand, worse)
    assert res.passed and res.comparison["newly_right"]  # fixing errors is fine
    assert gate(worse, cand).comparison["newly_wrong"]
    floor_only = replay(recs, _floor_only())
    assert gate(floor_only, cand).passed  # coverage loss is allowed by default
    strict = gate(floor_only, cand, allow_coverage_regression=False)
    assert not strict.passed and "coverage fell" in strict.failures[0]
    assert not gate(replay(recs[:50], demo_cascade()), min_coverage=0.99).passed


def test_baseline_from_recorded_answers_and_roundtrip(tmp_path):
    recs = [
        Record("a", _item("a"), "accept", baseline_verdict="accept", baseline_tier="small"),
        Record("b", _item("b"), "reject", baseline_verdict="accept", baseline_tier="small"),
        Record("c", _item("c"), "accept"),
    ]
    base = baseline_from_records(recs)
    assert (base.automatic, base.wrong, base.coverage) == (2, 1, 2 / 3)
    path = tmp_path / "recs.jsonl"
    dump_records(recs, path)
    assert [r.to_dict() for r in load_records(path)] == [r.to_dict() for r in recs]


def test_cli_eval_passes_and_reports_coverage(capsys):
    from homelabnext.cli import main

    assert main(["decide", "eval"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["report"]["coverage"] == FIXED_COVERAGE and out["gate"]["passed"]
    assert main(["decide", "scan", "please wipe all data"]) == 0
    assert json.loads(capsys.readouterr().out)["tier"] == "critical"
