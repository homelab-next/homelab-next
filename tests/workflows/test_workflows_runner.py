# SPDX-License-Identifier: Apache-2.0
"""The offline runner's deterministic parts: references, conditions, the enrich operations."""

import pytest
from wf_support import manifest, pack

from homelabnext.workflows import extract_iocs, request_id, run_fixture, triggered
from homelabnext.workflows.runner import holds, render, resolve

# documentation addresses (RFC 5737): IOC-extraction input, not endpoints
IP_A = "203.0.113.7"  # no-raw-endpoint: allow IOC-extraction test data
IP_B = "203.0.113.9"  # no-raw-endpoint: allow IOC-extraction test data

SCOPE = {
    "event": {"data": {"entities": [{"kind": "host", "value": "app-01"}], "n": 3}},
    "steps": {"owner": {"row": {"team": "payments"}}, "skipped": None},
}


@pytest.mark.parametrize(
    ("ref", "want"),
    [
        ("$event.data.n", 3),
        ("$event.data.entities.0.value", "app-01"),
        ("$event.data.entities.5.value", None),
        ("$event.data.missing.deeper", None),
        ("$steps.owner.row.team", "payments"),
        ("$steps.skipped.row", None),
        ("$steps.nope", None),
        ("$elsewhere.x", None),
    ],
)
def test_resolve(ref, want):
    assert resolve(ref, SCOPE) == want


def test_render_literals_refs_and_escape():
    value = {"a": "$event.data.n", "b": ["x", "$steps.owner.row.team"], "c": "$$5", "d": 7}
    assert render(value, SCOPE) == {"a": 3, "b": ["x", "payments"], "c": "$5", "d": 7}


def test_conditions():
    assert holds(None, SCOPE)
    assert holds([{"ref": "$event.data.n", "equals": 3}], SCOPE)
    assert not holds([{"ref": "$event.data.n", "in": [1, 2]}], SCOPE)
    assert holds([{"ref": "$steps.skipped", "exists": False}], SCOPE)
    assert not holds(
        [{"ref": "$event.data.n", "equals": 3}, {"ref": "$steps.owner", "exists": False}], SCOPE
    )


def test_extract_iocs_refangs_and_invents_nothing():
    text = (
        "Visit hxxps://pay-verify[.]example[.]net/x, or https://login.example.org/verify.\n"
        f"Callback {IP_A} and 999.1.2.3 (not an address); version 1.2.3.4.5 is no IP.\n"
        "Attachment hash " + "AB" * 32 + " and a short one deadbeef."
    )
    got = extract_iocs([text])
    assert got["urls"] == ["https://login.example.org/verify", "https://pay-verify.example.net/x"]
    assert got["domains"] == ["login.example.org", "pay-verify.example.net"]
    assert got["ipv4"] == [IP_A]
    assert got["sha256"] == ["ab" * 32]
    assert got["count"] == 6
    assert extract_iocs(["nothing to see"])["count"] == 0


def test_url_with_ip_host_is_not_a_domain():
    got = extract_iocs([f"http://{IP_B}:8080/a"])
    assert got["domains"] == [] and got["ipv4"] == [IP_B]


def test_request_id_is_deterministic_and_a_slug():
    a = request_id("phishing-report", "evt-1", "block")
    assert a == request_id("phishing-report", "evt-1", "block")
    assert a != request_id("phishing-report", "evt-2", "block")
    assert a.startswith("block-") and len(a) == len("block-") + 12


def test_trigger_matches_type_and_where():
    doc = pack("new-critical-alert")
    ev = doc["fixtures"][0]["event"]
    assert triggered(doc, ev)
    assert not triggered(doc, {**ev, "type": "homelabnext.case.opened"})
    assert not triggered(doc, {**ev, "data": {**ev["data"], "severity": "high"}})


def test_skipped_steps_and_outputs_are_reported():
    doc = pack("new-critical-alert")
    res = run_fixture(doc, doc["fixtures"][2], manifest=manifest())
    assert res.skipped == ["classify", "page"]
    assert res.outputs["owner"] == {"key": "stray-07", "found": False, "row": None}
    assert res.outputs["hosts"] == {"values": ["stray-07"], "first": "stray-07", "count": 1}
    assert [c.action for c in res.calls] == ["case.open"]


def test_not_triggered_runs_nothing():
    doc = pack("new-critical-alert")
    res = run_fixture(doc, doc["fixtures"][3], manifest=manifest())
    assert not res.triggered and res.calls == [] and res.outputs == {}
