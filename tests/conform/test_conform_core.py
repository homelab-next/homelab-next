# SPDX-License-Identifier: Apache-2.0
"""The suite format: severities, skips, waivers, fresh subjects, never-raising checks."""

import pytest

from homelabnext.conform import CheckResult, Skip, Suite, run_checks


class Subject:
    features = frozenset({"extra"})
    made = 0
    closed = 0

    def __init__(self):
        type(self).made += 1

    def close(self):
        type(self).closed += 1


def _suite():
    s = Suite("demo", "demo suite")

    @s.check("passes", "always fine")
    def _(x):
        return "evidence text"

    @s.check("asserts", "fails by assertion")
    def _(x):
        raise AssertionError("expected 1, got 2")

    @s.check("explodes", "fails by exception")
    def _(x):
        raise KeyError("boom")

    @s.check("skips", "raises Skip")
    def _(x):
        raise Skip("not here")

    @s.check("needs-feature", "needs a missing feature", requires=["nope"])
    def _(x):
        raise AssertionError("must not run")

    @s.check("wants-extra", "needs a declared feature", requires=["extra"])
    def _(x):
        return None

    @s.check("soft", "a should check", severity="should")
    def _(x):
        raise AssertionError("soft failure")

    return s


def by_id(results):
    return {r.check: r for r in results}


def test_every_outcome_is_a_result_and_nothing_escapes():
    res = by_id(run_checks(_suite(), Subject))
    assert res["passes"].ok and res["passes"].evidence == "evidence text"
    assert not res["asserts"].ok and res["asserts"].evidence == "expected 1, got 2"
    assert not res["explodes"].ok and "KeyError" in res["explodes"].evidence
    assert res["skips"].status == "skip" and res["skips"].ok
    assert res["needs-feature"].status == "skip" and "nope" in res["needs-feature"].evidence
    assert res["wants-extra"].status == "pass"
    assert res["soft"].severity == "should" and not res["soft"].ok


def test_skip_and_waived_are_not_passes():
    res = by_id(run_checks(_suite(), Subject, waive={"soft": "known gap"}))
    assert res["skips"].counts_as_pass is False
    assert res["soft"].status == "waived" and res["soft"].ok and not res["soft"].counts_as_pass
    assert "known gap" in res["soft"].evidence


def test_each_check_gets_a_fresh_subject_which_is_closed():
    Subject.made = Subject.closed = 0
    run_checks(_suite(), Subject)
    assert Subject.made == Subject.closed == 7  # waived/none: all seven are run


def test_declared_features_are_merged_with_the_subjects():
    s = Suite("d", "d")

    @s.check("needs-declared", "x", requires=["from-target"])
    def _(x):
        return "ran"

    plain = by_id(run_checks(s, object))
    assert plain["needs-declared"].status == "skip"
    declared = by_id(run_checks(s, object, features=["from-target"]))
    assert declared["needs-declared"].status == "pass"


def test_a_must_check_cannot_be_waived_and_a_waiver_needs_a_reason():
    s = _suite()
    with pytest.raises(ValueError, match="MUST"):
        run_checks(s, Subject, waive={"asserts": "because"})
    with pytest.raises(ValueError, match="reason"):
        run_checks(s, Subject, waive={"soft": "  "})
    with pytest.raises(ValueError, match="no check"):
        run_checks(s, Subject, waive={"ghost": "x"})


def test_check_ids_are_validated_and_unique():
    s = Suite("d", "d")
    for bad in ("Upper", "with space", "-lead", "trail-", ""):
        with pytest.raises(ValueError):
            s.check(bad, "x")
    with pytest.raises(ValueError, match="severity"):
        s.check("ok-id", "x", severity="could")

    @s.check("dup", "x")
    def _(x):
        return None

    with pytest.raises(ValueError, match="duplicate"):
        s.check("dup", "again")(lambda x: None)


def test_a_factory_that_raises_propagates_it_is_not_a_check_failure():
    s = Suite("d", "d")
    s.check("one", "x")(lambda x: None)

    def broken():
        raise ConnectionError("service down")

    with pytest.raises(ConnectionError):
        run_checks(s, broken)


def test_capability_protocol_shape():
    s = _suite()
    fns = s.checks()
    assert [f.check_id for f in fns] == s.ids()
    out = fns[0](Subject())
    assert isinstance(out, CheckResult) and out.check == "passes"


def test_check_result_validates_its_fields():
    with pytest.raises(ValueError):
        CheckResult("x", True, "e", severity="maybe")
    with pytest.raises(ValueError):
        CheckResult("x", True, "e", status="great")
    r = CheckResult("x", False, "bad")
    assert r.status == "fail" and r.to_dict()["ok"] is False


def test_only_selects_checks():
    res = run_checks(_suite(), Subject, only=["passes"])
    assert [r.check for r in res] == ["passes"]
