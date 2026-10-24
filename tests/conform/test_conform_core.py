# SPDX-License-Identifier: Apache-2.0
"""The suite format: severities, skips, waivers, fresh subjects, never-raising checks."""

import sys

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

    @s.check("skips", "raises Skip", skippable=True)
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


# defined under another file name, as an adapter module would be
_ns: dict = {"Skip": Skip}
exec(
    compile(
        "class SkippingSubject:\n"
        "    features = frozenset()\n"
        "    def do(self):\n"
        "        raise Skip('backend busy')\n",
        "<adapter>",
        "exec",
    ),
    _ns,
)
SkippingSubject = _ns["SkippingSubject"]


def test_only_the_suite_may_skip_a_check():
    s = Suite("d", "d")

    @s.check("skippable-but-subject-skips", "x", skippable=True)
    def _(x):
        x.do()

    @s.check("not-skippable", "x")
    def _(x):
        raise Skip("the suite itself, but undeclared")

    @s.check("subject-skips-plain", "x")
    def _(x):
        x.do()

    res = by_id(run_checks(s, SkippingSubject))
    for cid in ("skippable-but-subject-skips", "not-skippable", "subject-skips-plain"):
        assert res[cid].status == "fail" and not res[cid].ok, (cid, res[cid])
    assert "subject raised Skip" in res["skippable-but-subject-skips"].evidence
    assert "not skippable" in res["not-skippable"].evidence


def test_a_must_needing_an_undeclared_test_hook_is_untested_not_skipped():
    s = Suite("d", "d")
    s.check("needs-clock", "x", requires=["clock-control"])(lambda x: None)
    s.check("needs-faults-soft", "x", requires=["fault-injection"], severity="should")(
        lambda x: None
    )
    s.check("needs-product-feature", "x", requires=["streaming"])(lambda x: None)
    res = by_id(run_checks(s, object))
    assert res["needs-clock"].status == "untested" and not res["needs-clock"].ok
    assert res["needs-faults-soft"].status == "skip"  # a SHOULD may still skip
    assert res["needs-product-feature"].status == "skip"  # product features may be absent
    declared = by_id(run_checks(s, object, features=["clock-control"]))
    assert declared["needs-clock"].status == "pass"


def test_a_missing_product_feature_skips_even_when_the_hook_is_missing_too():
    """The product decides first: with no ``admission`` there is no capacity for a fault to
    leak, so a MUST needing ``admission`` and ``fault-injection`` skips on a target with
    neither; only a target that has the product but not the hook is ``untested``."""
    s = Suite("d", "d")
    s.check("needs-both", "x", requires=["admission", "fault-injection"])(lambda x: None)
    assert by_id(run_checks(s, object))["needs-both"].status == "skip"
    assert "admission" in by_id(run_checks(s, object))["needs-both"].evidence
    product_only = by_id(run_checks(s, object, features=["admission"]))["needs-both"]
    assert product_only.status == "untested" and not product_only.ok
    both = by_id(run_checks(s, object, features=["admission", "fault-injection"]))
    assert both["needs-both"].status == "pass"


def test_can_skip_with_counts_the_features_a_subject_declares():
    s = Suite("d", "d")
    s.check("needs-both", "x", requires=["admission", "fault-injection"])(lambda x: None)
    s.check("soft", "x", skippable=True)(lambda x: None)
    specs = {sp.id: sp for sp in s.specs}
    assert specs["needs-both"].can_skip
    assert specs["needs-both"].can_skip_with(["admission"])
    assert not specs["needs-both"].can_skip_with(["admission", "fault-injection", "deadline"])
    assert specs["soft"].can_skip_with(["anything"])  # skippable always can


def test_unknown_only_ids_are_a_misconfiguration():
    with pytest.raises(ValueError, match="no check"):
        run_checks(_suite(), Subject, only=["passes", "no-such-id"])


def test_specs_say_whether_a_check_can_skip():
    specs = {sp.id: sp for sp in _suite().specs}
    assert specs["skips"].can_skip and specs["needs-feature"].can_skip
    assert not specs["passes"].can_skip


def test_subject_raised_skip_counts_against_minimum(monkeypatch, tmp_path):
    """A subject that skips everything is a failing run, not 'PASS, 0 executed'."""
    from homelabnext.conform import run_capability

    mod = tmp_path / "skipping_idp.py"
    mod.write_text(
        "from homelabnext.conform.core import Skip\n"
        "class S:\n"
        "    features = frozenset()\n"
        "    def issue(self, *a, **k):\n"
        "        raise Skip('busy')\n"
        "    verify = revoke = issue\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    t = tmp_path / "t.yml"
    t.write_text("capabilities:\n  idp: {adapter: 'skipping_idp:S'}\n")
    run = run_capability("idp", str(t))
    assert not run.ok and run.executed and all(r.status == "fail" for r in run.results)
    sys.modules.pop("skipping_idp", None)
