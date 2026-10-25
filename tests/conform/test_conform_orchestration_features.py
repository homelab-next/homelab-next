# SPDX-License-Identifier: Apache-2.0
"""The optional orchestration features (clauses f-j, the ``orchestration-features`` suite): what
the suite and its mutants do not pin by themselves.

``lower-priority-number-starts-first`` is a SHOULD, so the defect it catches cannot be a registered
mutant (only a MUST failure fails a capability, ``docs/conformance.md``); it is pinned here, as
the records deciders are."""

import pytest

from conformance.fakes import llm_orchestrator_api as api
from conformance.fakes.orchestrator import (
    BACKENDS,
    FakeOrchestrator,
    FirstComeFirstServedOrchestrator,
)
from conformance.protocols.orchestration import (
    Capacity,
    ConstraintsUnsatisfiable,
    ShadowRunPending,
    SubmitOptions,
)
from conformance.suites import orchestration_features as suite
from homelabnext.conform.adapters import llm_orchestrator as lo
from homelabnext.conform.core import run_checks
from homelabnext.conform.registry import load_suite

PRIORITY = "lower-priority-number-starts-first"
OPTIONAL = {"priority", "shadow", "constraints", "local-only", "list-runs"}


def test_first_come_first_served_fails_the_priority_check_and_nothing_else():
    res = run_checks(suite.SUITE, FirstComeFirstServedOrchestrator)
    failed = [(r.check, r.severity) for r in res if not r.ok]
    assert failed == [(PRIORITY, "should")], failed
    (bad,) = [r for r in res if r.check == PRIORITY]
    assert "['low', 'high']" in bad.evidence


def test_the_priority_check_skips_without_a_reported_limit():
    class NoLimit(FakeOrchestrator):
        def capacity(self):
            return Capacity(None, *super().capacity()[1:])

    (res,) = run_checks(suite.SUITE, NoLimit, only=[PRIORITY])
    assert res.status == "skip" and "no limit" in res.evidence


def test_the_suite_is_extended_and_every_check_needs_an_optional_feature():
    s = load_suite("orchestration-features")
    assert s.tier == "extended"
    for spec in s.specs:
        assert set(spec.requires) & OPTIONAL, spec.id


def test_a_target_without_the_features_skips_every_check():
    class Plain(FakeOrchestrator):
        features = frozenset({"admission", "deadline", "fault-injection"})

    assert {r.status for r in run_checks(suite.SUITE, Plain)} == {"skip"}


def test_the_fake_refuses_bad_feature_arguments():
    o = FakeOrchestrator()
    o.define("j", lambda p: 1)
    for bad in (0, -1, True, 1.5):
        with pytest.raises(ValueError, match="priority"):
            o.submit("j", {}, idempotency_key=f"k{bad}", priority=bad)
    for bad in ({"tags": ["x"]}, {"require_tags": "gpu"}, {"min_context": 0}):
        with pytest.raises(ValueError):
            o.define("c", lambda p: 1, constraints=bad)
    o.define("c", lambda p: 1, constraints={"require_tags": ["large"]})  # local-a, cloud-a
    with pytest.raises(ConstraintsUnsatisfiable):  # only cloud-a has that much context
        o.define("c", lambda p: 1, constraints={"min_context": 150000}, local_only=True)
    o.define("s", lambda p: 1)
    first = o.submit("s", {}, idempotency_key="a", shadow=True)
    with pytest.raises(ShadowRunPending):
        o.submit("s", {}, idempotency_key="b", shadow=True)
    o.cancel(first)
    assert {b.locality for b in BACKENDS} == {"local", "cloud"}


def test_the_controller_adapter_declares_priority_and_sends_it(tmp_path):
    fake = api.FakeController(tmp_path).start()
    o = lo.LLMOrchestrator(fake.url, profiles_dir=tmp_path, poll=0.01, wait_floor=5)
    try:
        assert "priority" in o.features and isinstance(o, SubmitOptions)
        o.define("j", lambda p: "ok")
        rid = o.submit("j", {}, idempotency_key="k", priority=7)
        assert fake.status(rid)[1]["priority"] == 7
        assert fake.status(o.submit("j", {}, idempotency_key="d"))[1]["priority"] == 50
        for bad in (0, 101, True):
            with pytest.raises(ValueError, match="1 to 100"):
                o.submit("j", {}, idempotency_key=f"b{bad}", priority=bad)
        # the only optional feature it declares: the job API shows no backend, lane or run list
        assert not (o.features & (OPTIONAL - {"priority"}))
    finally:
        o.close()
        fake.stop()
