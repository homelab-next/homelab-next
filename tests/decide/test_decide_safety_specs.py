# SPDX-License-Identifier: Apache-2.0
"""K-15: the four required safety specs exist, are safety-only, and pass their cases."""

import shutil

import pytest
import yaml

from homelabnext.decide import FaultyTier, Item
from homelabnext.decide.cli import main as decide_main
from homelabnext.decide.lint import lint_paths
from homelabnext.decide.safety import (
    REQUIRED,
    SPECS_DIR,
    build_cascade,
    check,
    load_spec,
)


def test_the_required_list_names_the_four_safety_specs():
    assert set(REQUIRED) == {
        "sensitive-content",
        "hostile-content",
        "purpose-consistency",
        "disclosure-risk",
    }


def test_every_required_spec_is_present_and_passes_its_cases():
    results = check()
    assert [r.spec for r in results] == list(REQUIRED)
    for r in results:
        assert r.ok, (r.spec, r.failures)
        assert r.cases >= 5


def test_required_specs_are_safety_specs_and_pass_the_spec_lint():
    for name in REQUIRED:
        assert load_spec(SPECS_DIR / f"{name}.yml").safety
    n, problems = lint_paths([SPECS_DIR])
    assert n == len(REQUIRED) and problems == []


def test_cli_gate(capsys):
    assert decide_main(["safety"]) == 0
    assert "4 required spec(s), 0 failing" in capsys.readouterr().out


@pytest.fixture
def specs(tmp_path):
    d = tmp_path / "specs"
    shutil.copytree(SPECS_DIR, d)
    return d


def _edit(path, fn):
    doc = yaml.safe_load(path.read_text())
    fn(doc)
    path.write_text(yaml.safe_dump(doc, sort_keys=False))


def _failures(d):
    return {r.spec: r.failures for r in check(d) if not r.ok}


def test_a_missing_required_spec_fails(specs, capsys):
    (specs / "disclosure-risk.yml").unlink()
    assert _failures(specs) == {"disclosure-risk": ["missing disclosure-risk.yml"]}
    assert decide_main(["safety", "--dir", str(specs)]) == 1


def test_a_spec_that_is_not_safety_only_fails(specs):
    _edit(specs / "hostile-content.yml", lambda d: d.update(safety=False))
    assert "safety: true is required" in _failures(specs)["hostile-content"][0]


def test_a_wrong_expectation_fails(specs):
    def flip(doc):
        doc["cases"][0]["expect"]["impact"] = "low"

    _edit(specs / "sensitive-content.cases.yml", flip)
    (msg,) = _failures(specs)["sensitive-content"]
    assert "keyword-api-token" in msg and "impact expected 'low'" in msg


def test_a_removed_keyword_is_caught_by_its_case(specs):
    def drop(doc):
        doc["tiers"]["critical"].remove("ignore previous instructions")

    _edit(specs / "hostile-content.keywords.yml", drop)
    assert any("keyword-override" in f for f in _failures(specs)["hostile-content"])


@pytest.mark.parametrize(
    ("fn", "needle"),
    [
        (lambda d: d.update(cases=[]), "non-empty 'cases'"),
        (lambda d: d.update(spec="other"), "case file is for 'other'"),
        (lambda d: d["cases"][0].update(expect={"verdict": "accept", "impact": "low"}), "verdict"),
    ],
)
def test_malformed_case_files_fail(specs, fn, needle):
    _edit(specs / "purpose-consistency.cases.yml", fn)
    assert any(needle in f for f in _failures(specs)["purpose-consistency"])


def test_spec_id_must_match_the_file(specs):
    _edit(specs / "disclosure-risk.yml", lambda d: d.update(id="leak-risk"))
    assert any("does not match" in f for f in _failures(specs)["disclosure-risk"])


def test_a_faulty_model_tier_never_lowers_or_approves():
    """With every model tier failing, each case still escalates at no less than the scan's impact."""
    for name in REQUIRED:
        spec = load_spec(SPECS_DIR / f"{name}.yml")
        cases = yaml.safe_load((SPECS_DIR / f"{name}.cases.yml").read_text())
        c = build_cascade(spec, SPECS_DIR, cases["fake_tiers"])
        for t in ("small", "large"):
            c.tiers[t] = FaultyTier(c.tiers[t], "error")
        for case in cases["cases"]:
            d = c.decide(Item(case["id"], case["text"], case.get("impact", "low")))
            assert not d.acted and d.verdict in ("raise", "human")
            if d.verdict == "raise":
                assert d.tier == "floor"
