# SPDX-License-Identifier: Apache-2.0
"""Helpers shared by the decide tests."""

from homelabnext.decide import CallableTier, TierAnswer, parse_spec


def spec_doc(**over):
    doc = {
        "id": "unit-spec",
        "version": 1,
        "question_set": ["Is it fine?"],
        "decision_table": [{"when": "fine", "then": "accept"}, {"when": "otherwise", "then": "escalate"}],
        "tiers": [
            {"name": "floor"},
            {"name": "small", "model_role": "mdl:fast-classifier", "min_confidence": 0.8},
            {"name": "large", "model_role": "mdl:main-reasoner", "min_confidence": 0.9},
        ],
        "error_direction": "fail-closed",
        "on_error": "escalate",
        "latency_budget_ms": 1000,
        "sample_audit_pct": 0,
    }  # fmt: skip
    doc.update(over)
    return doc


def spec(**over):
    return parse_spec(spec_doc(**over))


def fixed(name, label, conf=0.95, impact=None):
    return CallableTier(name, lambda item: TierAnswer(label, conf, impact))


def abstain(name):
    return CallableTier(name, lambda item: TierAnswer(None))
