# SPDX-License-Identifier: Apache-2.0
"""The Code Mode drafts (schemas/codemode, ADR-0031): every example validates and every negative is
refused for the reason its name states, not merely refused."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import schema_check as sc

ROOT = Path(__file__).resolve().parents[2]
DIR = ROOT / "schemas" / "codemode"
REGISTRY = sc.build_registry(ROOT)
SCHEMAS = sorted(DIR.glob("*.schema.json"))

#: negative file stem -> (JSON path of the error, a fragment of its message)
WHY = {
    "execution_request.wall-too-long": ("budget/wall_s", "maximum"),
    "execution_request.language-unknown": ("language", "is not one of"),
    "execution_request.actor-in-params": ("$", "'actor' was unexpected"),
    "execution_request.resume-of-another-execution": ("$", "'resume_of' was unexpected"),
    "execution_result.paused-without-pending": ("$", "'pending' is a required property"),
    "execution_result.paused-without-a-pending-call": ("calls", "does not contain items"),
    "execution_result.ok-with-a-pending-call": ("calls", "'const': 'pending'"),
    "execution_result.denied-without-a-denied-call": ("calls", "does not contain items"),
    "execution_result.limit-unnamed": ("$", "'limit' is a required property"),
    "execution_result.ok-with-limit": ("$", "under {'required': ['limit']}"),
    "execution_result.denied-without-reason": ("calls/0", "'reason' is a required property"),
    "execution_result.denied-with-a-success-reason": ("calls/0/reason", "should not be valid"),
    "execution_result.replayed-pending-call": ("calls/1", "{'replayed': {'const': True}}"),
    "execution_result.log-line-with-line-separator": ("logs/0", "does not match"),
    "execution_result.duplicate-pending": ("pending", "non-unique"),
    "execution_result.broker-call-without-request-id": ("calls/0", "'request_id' is a required"),
    "execution_result.ok-with-error": ("$", "under {'required': ['error']}"),
    "execution_result.ok-without-value": ("$", "'value' is a required property"),
    "execution_result.log-line-with-newline": ("logs/0", "does not match"),
    "execution_result.pending-with-free-text": ("pending/0", "'summary' was unexpected"),
    "execution_result.pending-without-digest": ("pending/0", "'request_digest' is a required"),
    "execution_result.truncated-without-value": ("$", "'value' is a dependency of 'truncated'"),
    "token.issuer-not-broker": ("issuer", "'svc:broker' was expected"),
    "token.no-actions": ("actions", "should be non-empty"),
    "token.no-expiry": ("$", "'expires_at' is a required property"),
    "token.duplicate-action": ("actions", "non-unique"),
    "token.carries-a-secret": ("$", "'secret' was unexpected"),
    "token.nested-execution": ("actions/1", "^codemode"),
    "token.wildcard-action": ("actions/0", "does not match"),
    "token.not-bound-to-a-sandbox": ("$", "'sandbox_id' is a required property"),
    "journal_step.no-request-digest": ("$", "'request_digest' is a required property"),
    "journal_step.no-actor": ("$", "'actor' is a required property"),
    "journal_step.no-code-digest": ("$", "'code_digest' is a required property"),
    "journal_step.ok-without-result": ("$", "'result' is a required property"),
    "journal_step.pending-with-result": ("$", "{'required': ['result']}"),
    "journal_step.negative-step": ("step", "minimum"),
    "journal_step.client-refusal-journalled": ("reason", "should not be valid"),
    "journal_step.denied-with-result": ("$", "{'required': ['result']}"),
}


def _schema(name: str) -> dict:
    return json.loads((DIR / f"{name}.schema.json").read_text())


def test_the_four_drafts_are_present_and_drafts():
    names = {p.name.removesuffix(".schema.json") for p in SCHEMAS}
    assert names == {"execution_request", "execution_result", "token", "journal_step"}
    for p in SCHEMAS:
        assert "ADR-0031" in json.loads(p.read_text())["x-draft"], p.name


def test_every_negative_has_a_stated_reason():
    negs = {p.name.rsplit(".", 1)[0] for p in (DIR / "negative").iterdir()}
    assert negs == set(WHY)


@pytest.mark.parametrize("stem", sorted(WHY))
def test_negative_is_refused_for_its_reason(stem):
    where, fragment = WHY[stem]
    errors = sc.errors_for(
        _schema(stem.split(".")[0]),
        json.loads((DIR / "negative" / f"{stem}.json").read_text()),
        REGISTRY,
    )
    assert any(e.startswith(f"{where}: ") and fragment in e for e in errors), errors


@pytest.mark.parametrize("path", SCHEMAS, ids=lambda p: p.name)
def test_examples_validate(path):
    assert sc.check_schema(ROOT, path, REGISTRY, strict=True) == []


def test_a_paused_result_needs_at_least_one_pending_request():
    doc = json.loads((DIR / "examples" / "execution_result.paused.json").read_text())
    doc["pending"] = []
    assert sc.errors_for(_schema("execution_result"), doc, REGISTRY)


def test_only_a_paused_result_lists_pending_requests():
    doc = json.loads((DIR / "examples" / "execution_result.ok.json").read_text())
    call = doc["calls"][0]
    doc["pending"] = [{k: call[k] for k in ("step", "request_id", "request_digest", "action")}]
    errors = sc.errors_for(_schema("execution_result"), doc, REGISTRY)
    assert any("should not be valid under {'required': ['pending']}" in e for e in errors), errors


def test_a_call_refused_before_the_broker_has_no_request_id():
    doc = json.loads((DIR / "examples" / "execution_result.denied-handled.json").read_text())
    doc["calls"][1] |= {"request_id": "req-0099", "request_digest": "sha256:" + "e" * 64}
    assert sc.errors_for(_schema("execution_result"), doc, REGISTRY)


def test_a_replayed_denial_keeps_its_reason():
    doc = json.loads((DIR / "examples" / "execution_result.denied-handled.json").read_text())
    doc["calls"][0]["replayed"] = True
    assert sc.errors_for(_schema("execution_result"), doc, REGISTRY) == []


def test_an_ok_call_carries_no_reason():
    doc = json.loads((DIR / "examples" / "execution_result.ok.json").read_text())
    doc["calls"][0]["reason"] = "not-granted"
    assert sc.errors_for(_schema("execution_result"), doc, REGISTRY)


#: what the broker answers with (homelabnext/broker, docs/broker.md) for calls it did not run
BROKER_REFUSALS = [
    "default-deny", "not-granted", "invalid-params", "invalid-target", "too-many-pending",
    "lane-quota-exceeded", "lane-rate-exceeded", "handler-failed", "handler-timeout",
    "handler-spawn-failed", "secret-unavailable", "internal-error", "busy", "audit-unavailable",
]  # fmt: skip


@pytest.mark.parametrize("reason", BROKER_REFUSALS)
def test_a_broker_refusal_reason_is_recorded_as_given(reason):
    doc = json.loads((DIR / "examples" / "execution_result.lane-quota.json").read_text())
    doc["calls"][0]["reason"] = reason
    assert sc.errors_for(_schema("execution_result"), doc, REGISTRY) == []


def test_the_success_reasons_excluded_are_the_brokers_own():
    decision = json.loads((ROOT / "schemas/broker/decision.schema.json").read_text())
    vocab = set(decision["properties"]["reason"]["enum"])
    reason = _schema("execution_result")["properties"]["calls"]["items"]["properties"]["reason"]
    assert set(reason["not"]["enum"]) == {"allowed", "approved", "approval-required"} <= vocab


def test_a_rate_limited_call_has_no_request_id():
    doc = json.loads((DIR / "examples" / "execution_result.lane-quota.json").read_text())
    doc["calls"][0]["reason"] = "rate-limited"
    assert sc.errors_for(_schema("execution_result"), doc, REGISTRY)
    for k in ("request_id", "request_digest"):
        del doc["calls"][0][k]
    assert sc.errors_for(_schema("execution_result"), doc, REGISTRY) == []
