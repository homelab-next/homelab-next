# SPDX-License-Identifier: Apache-2.0
"""swap_record schema: examples are valid and semantically sound, negatives fail at the schema."""

from __future__ import annotations

import json

import pytest
from support import ROOT

from homelabnext.swap import record

EX = sorted((ROOT / "schemas" / "platform" / "examples").glob("swap_record.*.json"))
NEG = sorted((ROOT / "schemas" / "platform" / "negative").glob("swap_record.*.json"))

WHERE = {  # negative label -> the part of the document the schema must blame
    "capability-wrong-kind": "capability",
    "unknown-step-name": "steps/0/name",
    "eight-steps": "steps",
    "status-unknown": "status",
    "rolled-back-without-rollback": "rollback",
    "rollback-reason-too-short": "rollback",
    "closed-without-closure": "closure",
    "active-with-null-current-step": "current_step",
    "passed-step-without-evidence": "steps/1/evidence",
    "evidence-ref-traversal": "steps/0/evidence/0/ref",
    "hash-malformed": "transitions/0/hash",
    "negative-soak-hours": "plan/soak_hours",
    "extra-field": "$",
    "adapter-is-url": "to_adapter",
    "transition-unknown-event": "transitions/1/event",
    "adr-ref-not-an-adr": "closure",
    "port-out-of-range": "route/after/port",
    "swap-id-uppercase": "swap_id",
    "no-transitions": "transitions",
    "actor-with-space": "transitions/0/actor",
    "missing-rollback-key": "$",
    "passed-step-without-finish-time": "steps/2",
}


def test_three_kinds_of_example_exist():
    assert {p.name.split(".")[1] for p in EX} == {"active", "closed", "rolled-back"}


@pytest.mark.parametrize("path", EX, ids=lambda p: p.name)
def test_examples_validate_and_are_semantically_sound(path):
    doc = json.loads(path.read_text())
    assert record.schema_problems(doc) == []
    assert record.record_problems(doc) == []


@pytest.mark.parametrize("path", NEG, ids=lambda p: p.name)
def test_negatives_are_rejected_for_the_intended_reason(path):
    label = path.name.split("swap_record.")[1][: -len(".json")]
    problems = record.schema_problems(json.loads(path.read_text()))
    assert problems, f"{path.name} was accepted"
    assert any(f"schema: {WHERE[label]}:" in p for p in problems), problems


def test_every_negative_has_an_expectation():
    assert {p.name.split("swap_record.")[1][:-5] for p in NEG} == set(WHERE)


def test_examples_contain_only_documentation_data():
    """No address, MAC or identity shape outside the documentation ranges (tools/leak_scan.py)."""
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("leak_scan", ROOT / "tools" / "leak_scan.py")
    leak_scan = importlib.util.module_from_spec(spec)
    # registered before it runs: its @dataclass looks its module up in sys.modules (Python 3.13)
    sys.modules.setdefault("leak_scan", leak_scan)
    spec.loader.exec_module(leak_scan)

    groups = {"network", "identity"}
    patterns = [pat for pat in leak_scan.PATTERNS if pat.group in groups]
    for p in EX + NEG:
        assert leak_scan.scan_text(p.read_text(), p.name, patterns) == [], p.name
