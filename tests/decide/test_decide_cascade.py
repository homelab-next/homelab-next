# SPDX-License-Identifier: Apache-2.0
"""Cascade rules: thresholds, escalation, K-06 fault injection, K-07 impact monotonicity."""

import json
from pathlib import Path

import pytest
from decide_support import abstain, fixed, spec, spec_doc

from homelabnext.decide import (
    CallableTier,
    Cascade,
    CascadeConfigError,
    FaultyTier,
    ImpactScanner,
    Item,
    SpecError,
    TierAnswer,
    parse_spec,
)
from homelabnext.decide.cascade import audit_selected

ITEM = Item("i-1", "a plain change")
ROOT = Path(__file__).resolve().parents[2]


def cascade(tiers, **over):
    return Cascade(spec(**over), tiers)


def test_first_confident_tier_answers_and_later_tiers_do_not_run():
    ran = []
    large = CallableTier("large", lambda i: ran.append(1) or TierAnswer("reject", 1.0))
    d = cascade(
        {"floor": abstain("floor"), "small": fixed("small", "accept", 0.8), "large": large}
    ).decide(ITEM)
    assert (d.verdict, d.tier, d.escalated) == ("accept", "small", False)  # 0.8 >= 0.8
    assert ran == []


def test_below_threshold_escalates_to_next_tier_then_human():
    c = cascade(
        {
            "floor": abstain("floor"),
            "small": fixed("small", "accept", 0.79),
            "large": fixed("large", "reject", 0.89),
        }
    )
    d = c.decide(ITEM)
    assert d.verdict == "human" and d.escalated and not d.acted
    assert [s.outcome for s in d.trace] == ["abstained", "below-threshold", "below-threshold"]


def test_escalate_label_is_not_an_answer():
    c = cascade(
        {
            "floor": abstain("floor"),
            "small": fixed("small", "escalate", 1.0),
            "large": fixed("large", "reject", 0.95),
        }
    )
    d = c.decide(ITEM)
    assert (d.verdict, d.tier) == ("reject", "large")


def test_per_spec_thresholds_are_honoured():
    tiers = {
        "floor": abstain("floor"),
        "small": fixed("small", "accept", 0.85),
        "large": abstain("large"),
    }
    assert cascade(tiers).decide(ITEM).tier == "small"
    strict = spec_doc(
        tiers=[
            {"name": "floor"},
            {"name": "small", "model_role": "mdl:a", "min_confidence": 0.9},
            {"name": "large", "model_role": "mdl:b"},
        ],
        default_min_confidence=0.99,
    )
    assert Cascade(parse_spec(strict), tiers).decide(ITEM).verdict == "human"


def test_interim_posture_is_never_an_answer():
    tiers = {"floor": abstain("floor"), "small": abstain("small"), "large": abstain("large")}
    closed = cascade(tiers).decide(ITEM)
    opened = cascade(tiers, error_direction="fail-open").decide(ITEM)
    assert (closed.interim, opened.interim) == ("hold", "allow")
    assert closed.verdict == opened.verdict == "human" and not opened.acted


def test_acting_tier_is_marked_acted():
    s = spec(tiers=[{"name": "floor", "acts": True}, {"name": "small", "model_role": "mdl:a"}])
    d = Cascade(s, {"floor": fixed("floor", "accept", 1.0), "small": abstain("small")}).decide(ITEM)
    assert d.acted
    d2 = Cascade(s, {"floor": abstain("floor"), "small": fixed("small", "accept", 0.99)}).decide(
        ITEM
    )
    assert not d2.acted  # small is advisory in this spec


# ------------------------------------------------------------ K-06: faults escalate
@pytest.mark.parametrize("mode", ["error", "timeout", "garbage", "bad_confidence"])
def test_k06_faulty_tier_escalates_never_answers(mode):
    bad = FaultyTier(fixed("small", "accept", 0.99), mode)
    c = cascade({"floor": abstain("floor"), "small": bad, "large": abstain("large")})
    d = c.decide(ITEM)
    assert d.verdict == "human" and d.escalated and not d.acted
    assert d.trace[1].outcome in ("error", "timeout", "invalid")


def test_k06_fault_falls_through_to_a_healthy_later_tier():
    c = cascade(
        {
            "floor": abstain("floor"),
            "small": FaultyTier(fixed("small", "accept"), "error"),
            "large": fixed("large", "reject", 0.95),
        }
    )
    d = c.decide(ITEM)
    assert (d.verdict, d.tier) == ("reject", "large")
    assert d.trace[1].outcome == "error"


def test_k06_generic_exception_in_a_tier_escalates():
    boom = CallableTier("small", lambda i: 1 / 0)
    d = cascade({"floor": abstain("floor"), "small": boom, "large": abstain("large")}).decide(ITEM)
    assert d.verdict == "human" and "ZeroDivisionError" in d.trace[1].detail


def test_k06_real_deadline_turns_a_hang_into_a_timeout():
    s = spec(tiers=[{"name": "floor"}, {"name": "small", "model_role": "mdl:a", "timeout_ms": 50}])
    slow = FaultyTier(fixed("small", "accept", 0.99), "hang", hang_s=0.4)
    d = Cascade(s, {"floor": abstain("floor"), "small": slow}).decide(ITEM)
    assert d.verdict == "human" and d.trace[1].outcome == "timeout"


def test_k06_fault_window_recovers():
    flaky = FaultyTier(fixed("small", "accept", 0.99), "error", after=1, count=1)
    c = cascade({"floor": abstain("floor"), "small": flaky, "large": abstain("large")})
    assert [c.decide(ITEM).verdict for _ in range(3)] == ["accept", "human", "accept"]


def test_latency_budget_spent_goes_to_human():
    now = [0.0]

    def slow(item):
        now[0] += 0.6
        return TierAnswer(None)

    c = Cascade(
        spec(latency_budget_ms=1000),
        {
            "floor": CallableTier("floor", slow),
            "small": CallableTier("small", slow),
            "large": fixed("large", "accept"),
        },
        clock=lambda: now[0],
    )
    d = c.decide(ITEM)
    assert d.verdict == "human" and d.trace[-1].outcome == "budget"


# ------------------------------------------------------------ K-07: impact never lowered
def test_k07_model_cannot_lower_impact():
    scanner = ImpactScanner({"high": ["production database"]})
    c = Cascade(
        spec(),
        {
            "floor": abstain("floor"),
            "small": fixed("small", "accept", 0.95, impact="low"),
            "large": abstain("large"),
        },
        scanner,
    )
    d = c.decide(Item("i", "edit the production database", impact="medium"))
    assert d.base_impact == "high" and d.impact == "high"
    assert "ignored proposed lower impact" in d.trace[-1].detail


def test_k07_model_may_raise_impact_even_below_threshold():
    c = cascade(
        {
            "floor": abstain("floor"),
            "small": fixed("small", "accept", 0.1, impact="critical"),
            "large": abstain("large"),
        }
    )
    d = c.decide(Item("i", "x", impact="low"))
    assert d.verdict == "human" and d.impact == "critical" and d.base_impact == "low"


def test_k07_declared_floor_and_scan_set_the_base():
    scanner = ImpactScanner({"medium": ["firewall rule"]})
    c = Cascade(
        spec(impact={"floor": "high"}),
        {"floor": abstain("floor"), "small": abstain("small"), "large": abstain("large")},
        scanner,
    )
    assert c.decide(Item("i", "add a firewall rule", impact="low")).impact == "high"


def test_k07_invalid_impact_is_an_invalid_answer():
    c = cascade(
        {
            "floor": abstain("floor"),
            "small": fixed("small", "accept", 0.99, impact="extreme"),
            "large": abstain("large"),
        }
    )
    assert c.decide(ITEM).trace[1].outcome == "invalid"


def safety_cascade(small):
    s = spec(
        safety=True,
        tiers=[{"name": "floor"}, {"name": "small", "model_role": "mdl:a", "min_confidence": 0.9}],
    )
    return Cascade(s, {"floor": abstain("floor"), "small": small})


def test_k07_safety_spec_tiers_cannot_approve():
    d = safety_cascade(fixed("small", "accept", 1.0)).decide(ITEM)
    assert d.verdict == "human" and d.trace[1].outcome == "invalid" and not d.acted


def test_k07_safety_raise_is_applied_and_hold_does_not_lower():
    d = safety_cascade(fixed("small", "raise", 0.95, impact="high")).decide(Item("i", "x"))
    assert (d.verdict, d.impact, d.base_impact, d.acted) == ("raise", "high", "low", False)
    d = safety_cascade(fixed("small", "hold", 0.95, impact="low")).decide(
        Item("i", "x", impact="medium")
    )
    assert (d.verdict, d.impact) == ("hold", "medium")


def test_k07_safety_low_confidence_raise_still_applies_but_hold_needs_confidence():
    d = safety_cascade(fixed("small", "raise", 0.2, impact="critical")).decide(ITEM)
    assert d.verdict == "human" and d.impact == "critical"
    d = safety_cascade(fixed("small", "hold", 0.2)).decide(ITEM)
    assert d.verdict == "human"


def test_k07_safety_raise_without_impact_is_invalid():
    d = safety_cascade(fixed("small", "raise", 0.99)).decide(ITEM)
    assert d.trace[1].outcome == "invalid"


def test_k07_safety_spec_refuses_acting_model_tiers():
    with pytest.raises(SpecError, match="only raise"):
        spec(safety=True, tiers=[{"name": "small", "model_role": "mdl:a", "acts": True}])


# ------------------------------------------------------------ config and misc
def test_missing_tier_implementation_is_a_config_error():
    with pytest.raises(CascadeConfigError, match="large"):
        cascade({"floor": abstain("floor"), "small": abstain("small")})


def test_audit_sampling_is_deterministic_and_proportional():
    ids = [f"i-{n}" for n in range(2000)]
    hits = [audit_selected("s", i, 10) for i in ids]
    assert hits == [audit_selected("s", i, 10) for i in ids]
    assert 150 < sum(hits) < 250
    assert not any(audit_selected("s", i, 0) for i in ids)
    assert all(audit_selected("s", i, 100) for i in ids)


@pytest.mark.parametrize(
    ("over", "needle"),
    [
        ({"on_error": "accept"}, "on_error"),
        ({"error_direction": "sideways"}, "error_direction"),
        ({"tiers": []}, "tiers: empty"),
        ({"tiers": [{"name": "small"}]}, "model_role"),
        ({"tiers": [{"name": "large", "model_role": "mdl:a"}, {"name": "small", "model_role": "mdl:a"}]}, "out of order"),
        ({"tiers": [{"name": "floor", "min_confidence": 2}]}, "min_confidence"),
        ({"decision_table": [{"when": "x", "then": "maybe"}]}, "decision_table"),
    ],
)  # fmt: skip
def test_malformed_specs_are_refused(over, needle):
    with pytest.raises(SpecError, match=needle):
        parse_spec(spec_doc(**over))


def test_schema_examples_parse_and_match_the_json_schema():
    import jsonschema

    schema = json.loads((ROOT / "schemas/registers/decision_spec.json").read_text())
    from schema_check import build_registry

    v = jsonschema.Draft202012Validator(schema, registry=build_registry(ROOT))
    for name in ("decision_spec.valid.json", "decision_spec.safety.json"):
        doc = json.loads((ROOT / "schemas/registers/examples" / name).read_text())
        assert not list(v.iter_errors(doc))
        parse_spec(doc)
    example = (ROOT / "homelabnext/decide/examples/decision_spec.yml").read_text()
    import yaml

    doc = yaml.safe_load(example)
    assert not list(v.iter_errors(doc))
    # the framework refuses what the schema refuses
    bad = json.loads(
        (ROOT / "schemas/registers/negative/decision_spec.on-error-accept.json").read_text()
    )
    with pytest.raises(SpecError):
        parse_spec(bad)
