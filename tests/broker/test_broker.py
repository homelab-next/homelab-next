# SPDX-License-Identifier: Apache-2.0
"""Broker contracts: schemas, the decision table, digest binding, manifest/handler consistency."""

import copy
import json
from pathlib import Path

import pytest
import yaml

from homelabnext.agent.schemas import schema_errors
from homelabnext.broker import check_manifest_handlers, decide, request_digest

ROOT = Path(__file__).resolve().parents[2]
TABLE = yaml.safe_load((Path(__file__).parent / "fixtures" / "decision_table.yml").read_text())
NOW = "2026-01-15T10:02:00Z"


def _request(case, **over):
    req = {
        "request_id": "req-0001",
        "action": case["action"],
        "actor": case["actor"],
        "target": "svc:queue",
        "params": {"grace_s": 30},
        "created": "2026-01-15T10:00:00Z",
    }
    req.update(over)
    req["digest"] = request_digest(req)
    return req


def _approval(kind, req):
    appr = {
        "approval_id": "appr-0001",
        "request_id": req["request_id"],
        "request_digest": req["digest"],
        "decision": "approved",
        "approver": {"subject": "approver-one", "issuer": "sso"},
        "approved_at": "2026-01-15T10:01:00Z",
    }
    if kind == "wrong-digest":
        appr["request_digest"] = "sha256:" + "0" * 64
    elif kind == "denied":
        appr["decision"] = "denied"
    elif kind == "self":
        appr["approver"]["subject"] = req["actor"].split(":", 1)[1]
    elif kind == "expired":
        appr["approved_at"] = "2026-01-15T08:00:00Z"
    return appr


@pytest.mark.parametrize("case", TABLE["cases"], ids=lambda c: c["name"])
def test_decision_table(case):
    manifest = TABLE["manifests"][case["manifest"]]
    req = _request(case)
    kind = case["approval"]
    approval = None
    if kind == "altered":
        approval = _approval("valid", req)
        req = _request(case, params={"grace_s": 0})  # changed after approval
    elif kind != "none":
        approval = _approval(kind, req)
    dec = decide(manifest, req, approval, now=NOW)
    assert (dec["verdict"], dec["reason"]) == (case["verdict"], case["reason"])
    assert dec["enforced"] is case.get("enforced", True)
    assert dec["request_digest"] == request_digest(req)
    assert schema_errors("broker", "decision", dec) == []
    if approval:
        assert schema_errors("broker", "approval", approval) == []


def test_only_explicit_allows_allow():
    """Property: across the whole table, every allow is one of the two allow reasons."""
    for case in TABLE["cases"]:
        assert (case["verdict"] == "allow") == (case["reason"] in ("allowed", "approved"))


def test_every_action_in_table_is_decided_even_if_garbage():
    manifest = TABLE["manifests"]["enforce"]
    for action in ("a.b", "x.y-z", "service.status.extra", "SERVICE.STATUS"):
        case = {"action": action, "actor": "profile:reader"}
        assert decide(manifest, _request(case), None, now=NOW)["verdict"] == "deny"


def test_digest_is_over_bound_fields_only_and_stable():
    case = {"action": "service.restart", "actor": "profile:operator"}
    a = _request(case)
    b = _request(case, request_id="req-9999", created="2030-01-01T00:00:00Z")
    assert request_digest(a) == request_digest(b)  # ids and timestamps are not bound
    assert request_digest(a) != request_digest(_request(case, params={"grace_s": 31}))
    assert request_digest(a) != request_digest(_request(case, target="svc:other"))
    reordered = dict(reversed(list(a.items())))
    assert request_digest(reordered) == request_digest(a)


def test_manifest_must_be_default_deny():
    manifest = copy.deepcopy(TABLE["manifests"]["enforce"])
    manifest["default"] = "allow"
    case = {"action": "service.status", "actor": "profile:reader"}
    assert decide(manifest, _request(case), None, now=NOW)["verdict"] == "deny"


def _handler(action, path, tier, approval):
    return {
        "action": action,
        "handler": path,
        "handler_digest": "sha256:" + "b" * 64,
        "tier": tier,
        "description": "Synthetic handler for the table test.",
        "params_schema": {"type": "object"},
        "timeout_s": 30,
        "idempotent": True,
        "requires_approval": approval,
        "audit": True,
    }


def _handlers(manifest):
    return [
        _handler(a["action"], a["handler"], a["tier"], a["requires_approval"])
        for a in manifest["actions"]
    ]


def test_manifest_and_handlers_consistent():
    m = TABLE["manifests"]["enforce"]
    hs = _handlers(m)
    assert check_manifest_handlers(m, hs) == []
    for h in hs:
        assert schema_errors("broker", "handler", h) == []


def test_manifest_handler_mismatches_reported():
    m = TABLE["manifests"]["enforce"]
    hs = _handlers(m)
    assert any("exactly one" in p for p in check_manifest_handlers(m, hs[1:]))
    bad = copy.deepcopy(hs)
    bad[0]["tier"] = "write"
    assert any("tier" in p for p in check_manifest_handlers(m, bad))
    bad = copy.deepcopy(hs)
    bad[3]["handler"] = "handlers/other.sh"
    assert any("path" in p for p in check_manifest_handlers(m, bad))
    extra = [*hs, _handler("host.format", "handlers/format.sh", "privileged", True)]
    assert any("not in the manifest" in p for p in check_manifest_handlers(m, extra))


def test_table_manifests_validate_except_the_deliberate_no_handler_one():
    assert schema_errors("broker", "manifest", TABLE["manifests"]["enforce"]) == []
    assert schema_errors("broker", "manifest", TABLE["manifests"]["shadow"]) == []
    assert schema_errors("broker", "manifest", TABLE["manifests"]["no-handler"]) != []


def test_shipped_examples_are_mutually_consistent():
    ex = ROOT / "schemas" / "broker" / "examples"
    req = json.loads((ex / "request.restart.json").read_text())
    assert request_digest(req) == req["digest"]
    appr = json.loads((ex / "approval.approved.json").read_text())
    assert appr["request_digest"] == req["digest"]
    manifest = json.loads((ex / "manifest.example.json").read_text())
    dec = json.loads((ex / "decision.allow-approved.json").read_text())
    assert decide(manifest, req, appr, now=dec["decided_at"]) == dec
