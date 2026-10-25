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
    "execution_request.extra-field": ("$", "credentials"),
    "execution_request.actor-not-a-profile": ("actor", "does not match"),
    "execution_result.paused-without-pending": ("$", "'pending' is a required property"),
    "execution_result.limit-unnamed": ("$", "'limit' is a required property"),
    "execution_result.denied-without-reason": ("calls/0", "'reason' is a required property"),
    "execution_result.ok-with-error": ("$", "should not be valid"),
    "execution_result.ok-without-value": ("$", "'value' is a required property"),
    "token.issuer-not-broker": ("issuer", "'svc:broker' was expected"),
    "token.no-actions": ("actions", "should be non-empty"),
    "token.no-expiry": ("$", "'expires' is a required property"),
    "token.duplicate-action": ("actions", "non-unique"),
    "token.carries-a-secret": ("$", "secret"),
    "journal_step.no-request-digest": ("$", "'request_digest' is a required property"),
    "journal_step.pending-is-not-a-step": ("outcome", "is not one of"),
    "journal_step.negative-step": ("step", "minimum"),
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
    doc["pending"] = [{"request_id": "req-0001", "action": "dhcp.lease"}]
    assert sc.errors_for(_schema("execution_result"), doc, REGISTRY)


def test_a_replayed_call_carries_no_reason():
    doc = json.loads((DIR / "examples" / "execution_result.ok.json").read_text())
    doc["calls"][0] |= {"outcome": "replayed", "reason": "from-journal"}
    assert sc.errors_for(_schema("execution_result"), doc, REGISTRY)
