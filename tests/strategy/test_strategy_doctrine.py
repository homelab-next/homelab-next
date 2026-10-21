# SPDX-License-Identifier: Apache-2.0
"""Each mechanical doctrine rule fails on a bad tree, passes on the example, and is tuned or
switched off by doctrine.yml."""

import pytest
import yaml
from strategy_helpers import EXAMPLE, NOW, U, edit, rel

from homelabnext.registers.schema import RegisterError
from homelabnext.strategy import (
    DEFAULT_HIERARCHY,
    DEFAULT_LINKS,
    DEFAULT_RULES,
    grade,
    load_doctrine,
    load_tree,
    validate,
)
from homelabnext.strategy.records import write_events


def report(root):
    return validate(load_tree(root), policy=False)


def tune(root, rule, **spec):
    p = root / "doctrine.yml"
    doc = yaml.safe_load(p.read_text())
    doc["rules"][rule] = {**doc["rules"][rule], **spec}
    p.write_text(yaml.safe_dump(doc))


def test_the_example_doctrine_is_the_default():
    d = load_doctrine(EXAMPLE)
    assert d.rules == DEFAULT_RULES | {
        "measures_per_owner": {**DEFAULT_RULES["measures_per_owner"], "why": d.rules["measures_per_owner"]["why"]}
    }  # fmt: skip
    assert d.rfi_default_ltiov_days == 30 and len(d.judgment) == 4
    assert d.hierarchy == DEFAULT_HIERARCHY and d.links == DEFAULT_LINKS  # the file says it all


def test_without_a_doctrine_file_the_defaults_apply(lab):
    (lab / "doctrine.yml").unlink()
    assert load_doctrine(lab).rules == DEFAULT_RULES


@pytest.mark.parametrize(
    "bad",
    ["rules:\n  be_careful: {enforce: error}\n", "rules:\n  activity_never_moe: {enforce: off}\n"],
)
def test_a_doctrine_outside_its_schema_is_fatal(lab, bad):
    (lab / "doctrine.yml").write_text(f"doctrine_version: 1\nname: tuned doctrine\n{bad}")
    with pytest.raises(RegisterError):
        load_doctrine(lab)


def test_activity_counts_are_never_moes(lab):
    edit(lab, "measures/MOE-003.md", "kind: output", "kind: activity")
    assert any("an activity count is never a MOE" in e for e in report(lab).errors)
    edit(lab, "measures/MOP-001.md", "kind: activity", "kind: activity")  # a MOP may be one
    tune(lab, "activity_never_moe", enforce="off")
    assert report(lab).errors == []


def test_every_objective_has_a_moe(lab):
    edit(lab, "MOE-003", "parent: TO-001", "parent: OO-001")  # one edit: the measure's parent
    want = f"TO 1.1.1 {U['TO-001']}: 0 active MOE(s)"
    assert any(e.startswith(want) for e in report(lab).errors)
    tune(lab, "moe_per_objective", levels=["SO", "OO"])  # MOEs only roll up at OO/SO here
    assert report(lab).errors == []


def test_not_measurable_is_a_finding_never_a_blank(lab):
    text = (lab / rel("MOE-005")).read_text()
    (lab / rel("MOE-005")).write_text(text.split("## Not measurable")[0] + "\n")
    assert any("needs a `## Not measurable` section" in e for e in report(lab).errors)


def test_never_fabricate_a_value_for_what_is_not_measurable(lab):
    tree = load_tree(lab)
    from homelabnext.strategy.records import definition_digest

    ev = {
        "event": "value", "by": "human:example-operator", "date": NOW.date(), "value": 0.5,
        "observed_at": "2026-10-20T13:00:00Z", "sample": 1, "evidence": "a guess",
        "definition_digest": definition_digest(tree.of("measures")[U["MOE-005"]]), "definition_version": 1,
    }  # fmt: skip
    with pytest.raises(RegisterError, match="not measurable has no values"):
        write_events(lab, {tree.paths[U["MOE-005"]]: [(ev, NOW)]})
    assert not list(
        (lab / rel("MOE-005").replace(".md", ".events")).glob("*-value-*")
    )  # nothing written


def test_a_redefinition_is_never_silent(lab):
    edit(lab, "measures/MOE-002.md", "passed in its latest run", "passed in either of its last two runs")  # fmt: skip
    errs = report(lab).errors
    assert any("bump definition_version" in e for e in errs)
    edit(lab, "measures/MOE-002.md", "definition_version: 1", "definition_version: 2")
    assert report(lab).errors == []
    g = grade(load_tree(lab).of("measures")[U["MOE-002"]], load_tree(lab), load_doctrine(lab), NOW)
    assert g.state == "baseline"  # read under the old definition: the new one has no grade yet


def test_baseline_so_one_per_requirement_and_never_shared(lab):
    edit(lab, "requirements/PIR-001.md", "supports: [SO-002]", "supports: [SO-002, SO-001]")
    errs = report(lab).errors
    assert any(f"PIR 1 {U['PIR-001']}: supports 2 baseline SO(s)" in e for e in errs)
    assert any("SO 1 is already the baseline SO of FFIR 1" in e for e in errs)
    edit(lab, "objectives/SO-001.md", "parent: null", "parent: null\nsupplemental: true")
    errs = report(lab).errors  # FFIR-001 now has no baseline SO: still one rule broken
    assert any(f"FFIR 1 {U['FFIR-001']}: supports 0 baseline SO(s)" in e for e in errs)
    tune(lab, "baseline_so", types=["PIR"])
    assert report(lab).errors == []


def test_an_unsupported_so_is_a_warning(lab):
    edit(lab, "requirements/PIR-001.md", "supports: [SO-002]", "supports: [SO-001]")
    tune(lab, "baseline_so", enforce="off")
    rep = report(lab)
    want = [f"SO 2 {U['SO-002']}: no active requirement supports this SO"]
    assert rep.errors == [] and rep.warnings == want


def test_the_retired_measure_ceiling_can_be_turned_back_on(lab):
    assert report(lab).errors == []
    tune(lab, "measures_per_owner", enforce="error", max=3)
    assert report(lab).errors == ["human:example-operator: 8 measures > 3"]


def _reading(v, digest, at, version=1):
    return {
        "value": v, "observed_at": at, "sample": 1, "evidence": "test",
        "definition_digest": digest, "definition_version": version,
    }  # fmt: skip


def _graded(lab, mid, values, rule=None, **spec):
    if rule:
        tune(lab, rule, **spec)
    tree = load_tree(lab)
    m = {**tree.of("measures")[mid], "values": values}
    return grade(m, tree, load_doctrine(lab), NOW)


def test_cold_start_is_a_baseline_not_a_grade(lab):
    from homelabnext.strategy.records import definition_digest

    d = definition_digest(load_tree(lab).of("measures")[U["MOE-003"]])
    one = [_reading(0, d, "2026-10-20T13:00:00Z")]
    assert _graded(lab, U["MOE-003"], one).state == "baseline"
    two = [*one, _reading(5, d, "2026-10-20T13:05:00Z")]
    assert _graded(lab, U["MOE-003"], two).state == "red"
    assert _graded(lab, U["MOE-003"], one, "cold_start_baseline", enforce="off").state == "green"


def test_trend_only_on_an_unchanged_definition(lab):
    from homelabnext.strategy.records import definition_digest

    d = definition_digest(load_tree(lab).of("measures")[U["MOE-003"]])
    old = "sha256:000000000000"
    vals = [_reading(1, d, "2026-10-20T12:00:00Z"), _reading(3, d, "2026-10-20T13:00:00Z")]
    g = _graded(lab, U["MOE-003"], vals)
    assert (g.trend, g.state) == ("up", "amber")
    rebased = [_reading(1, old, "2026-10-20T11:00:00Z"), *vals[1:]]
    assert _graded(lab, U["MOE-003"], rebased).trend == "re-baseline"  # never across definitions
    assert _graded(lab, U["MOE-003"], vals, "trend_same_definition", enforce="off").trend is None


def test_a_self_measured_moe_is_amber_at_best(lab):
    tree = load_tree(lab)
    g = grade(tree.of("measures")[U["MOE-004"]], tree, load_doctrine(lab), NOW)
    assert (g.value, g.state, g.capped) == (1.0, "amber", True)  # manual: the owner's own word
    tune(lab, "self_measured_moe_cap", enforce="off")
    tree = load_tree(lab)
    assert grade(tree.of("measures")[U["MOE-004"]], tree, load_doctrine(lab), NOW).state == "green"


def test_measured_by_the_objectives_own_owner_is_self_measured(lab):
    from homelabnext.strategy.rules import self_measured

    tree = load_tree(lab)
    assert not self_measured(tree.of("measures")[U["MOE-002"]], tree)
    edit(lab, "measures/MOE-002.md", "measured_by: profile:example-checker", "measured_by: human:example-operator")  # fmt: skip
    tree = load_tree(lab)
    assert self_measured(tree.of("measures")[U["MOE-002"]], tree)
    g = grade(tree.of("measures")[U["MOE-002"]], tree, load_doctrine(lab), NOW)
    assert (g.state, g.capped) == ("amber", True)


def test_a_thin_reading_reports_low_confidence(lab):
    from homelabnext.strategy.records import definition_digest

    d = definition_digest(load_tree(lab).of("measures")[U["MOE-002"]])
    vals = [_reading(1, d, "2026-10-01T00:00:00Z"), _reading(1, d, "2026-10-02T00:00:00Z")]
    g = _graded(lab, U["MOE-002"], vals)
    assert g.state == "green" and g.confidence == "low" and "h old > 168" in g.thin


def test_the_doctrine_defaults_are_a_copy(lab):
    d = load_doctrine(lab)
    d.rules["activity_never_moe"]["enforce"] = "off"
    assert DEFAULT_RULES["activity_never_moe"]["enforce"] == "error"
