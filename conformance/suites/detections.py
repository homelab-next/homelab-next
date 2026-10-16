# SPDX-License-Identifier: Apache-2.0
"""``detections``: a rule engine that fires on must-fire events and stays quiet otherwise."""

from __future__ import annotations

import copy

from conformance.fakes.detection_target import AlwaysFireDetectionTarget, FakeDetectionTarget
from homelabnext.conform.core import Mutant, Suite
from homelabnext.detections.fixtures import load_fixtures
from homelabnext.detections.sigma import load_rules

SUITE = Suite(
    "detections",
    "detection engine: shipped must-fire fixtures fire, must-not-fire fixtures stay silent",
    "conformance.protocols.detections:DetectionTarget",
)


def _cases(t, kind):
    rules = load_rules(t.root)
    out = []
    for rule in rules:
        out += [(rule, fx) for fx in load_fixtures(t.root, rule.slug) if fx.kind == kind]
    return out


@SUITE.check(
    "rules-have-both-fixture-kinds",
    "every rule ships at least one must-fire and one must-not-fire event",
)
def _(t):
    rules = load_rules(t.root)
    assert rules, f"no rules under {t.root}"
    for r in rules:
        kinds = {fx.kind for fx in load_fixtures(t.root, r.slug)}
        assert {"must_fire", "must_not_fire"} <= kinds, f"{r.det_id}: fixtures {sorted(kinds)}"


@SUITE.check("must-fire-fixtures-fire", "the engine fires on every must-fire fixture")
def _(t):
    cases = _cases(t, "must_fire")
    assert cases, "no must-fire fixtures"
    missed = [f"{r.det_id}/{fx.path.name}" for r, fx in cases if not t.engine.matches(r, fx.event)]
    assert not missed, f"missed: {missed}"


@SUITE.check(
    "must-not-fire-fixtures-silent", "the engine stays silent on every must-not-fire fixture"
)
def _(t):
    cases = _cases(t, "must_not_fire")
    assert cases, "no must-not-fire fixtures"
    noisy = [f"{r.det_id}/{fx.path.name}" for r, fx in cases if t.engine.matches(r, fx.event)]
    assert not noisy, f"false positives: {noisy}"


@SUITE.check("verdict-is-a-bool", "matches() returns a real boolean")
def _(t):
    (r, fx) = _cases(t, "must_fire")[0]
    assert type(t.engine.matches(r, fx.event)) is bool, "matches() did not return bool"


@SUITE.check("deterministic", "the same rule and event give the same verdict every time")
def _(t):
    for r, fx in _cases(t, "must_fire") + _cases(t, "must_not_fire"):
        verdicts = {t.engine.matches(r, fx.event) for _ in range(3)}
        assert len(verdicts) == 1, f"{r.det_id}/{fx.path.name} flip-flops"


@SUITE.check("event-not-mutated", "evaluating a rule leaves the event untouched")
def _(t):
    for r, fx in _cases(t, "must_fire"):
        before = copy.deepcopy(fx.event)
        t.engine.matches(r, fx.event)
        assert fx.event == before, f"{r.det_id}/{fx.path.name} was modified by the engine"


@SUITE.check("empty-event-is-no-match", "an empty event matches no rule and does not crash")
def _(t):
    for r in load_rules(t.root):
        assert t.engine.matches(r, {}) is False, f"{r.det_id} fired on an empty event"


@SUITE.check("unrelated-event-is-no-match", "an event with no relevant fields matches no rule")
def _(t):
    event = {"unrelated_field": "value", "n": 1, "nested": {"x": ["y"]}}
    for r in load_rules(t.root):
        assert t.engine.matches(r, event) is False, f"{r.det_id} fired on an unrelated event"


@SUITE.check(
    "extra-fields-do-not-break-a-match",
    "adding an unrelated field to a must-fire event still fires",
)
def _(t):
    for r, fx in _cases(t, "must_fire"):
        ev = {**copy.deepcopy(fx.event), "zz_extra_field": "noise"}
        assert t.engine.matches(r, ev), (
            f"{r.det_id}/{fx.path.name} stopped firing with an extra field"
        )


def make_fake():
    return FakeDetectionTarget()


MUTANTS = {
    "fires-on-everything": Mutant(
        AlwaysFireDetectionTarget,
        "must-not-fire-fixtures-silent",
        "the engine matches every event",
    ),
}
