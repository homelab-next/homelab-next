# SPDX-License-Identifier: Apache-2.0
"""Broker contracts: schemas, the decision table, digest binding, manifest/handler consistency."""

import copy
import json
from pathlib import Path

import pytest
import yaml

from homelabnext.agent.schemas import schema_errors
from homelabnext.broker import (
    DEFAULT_APPROVAL_TTL_S,
    MemoryApprovalStore,
    check_manifest_handlers,
    decide,
    decide_access,
    normalize_identity,
    request_digest,
)

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
    elif kind == "self-spelling":
        appr["approver"] = {
            "subject": "operator.",
            "issuer": "elsewhere",
        }  # normalizes to the actor
    elif kind == "expired":
        appr["approved_at"] = "2026-01-15T08:00:00Z"
    elif kind == "expires-at-past":
        appr["expires_at"] = "2026-01-15T10:01:30Z"
    elif kind == "future":
        appr["approved_at"] = "2099-01-01T00:00:00Z"
    elif kind == "before-request":
        appr["approved_at"] = "2026-01-15T09:59:00Z"
    elif kind == "unlisted":
        appr["approver"]["subject"] = "someone-else"
    elif kind == "other-issuer":
        appr["approver"]["issuer"] = "self-hosted"
    elif kind == "agent":
        appr["approver"] = {"subject": "writer", "issuer": "agents"}
    return appr


@pytest.mark.parametrize("case", TABLE["cases"], ids=lambda c: c["name"])
def test_decision_table(case):
    manifest = TABLE["manifests"][case["manifest"]]
    # `created` is not digest-bound; an expired approval must still post-date its request
    req = (
        _request(case, created="2026-01-15T07:59:00Z")
        if case["approval"] == "expired"
        else _request(case)
    )
    kind = case["approval"]
    approval = None
    if kind == "altered":
        approval = _approval("valid", req)
        req = _request(case, params={"grace_s": 0})  # changed after approval
    elif kind != "none":
        approval = _approval(kind, req)
    dec = decide(manifest, req, approval, now=NOW, store=MemoryApprovalStore())
    assert (dec["verdict"], dec["reason"]) == (case["verdict"], case["reason"])
    assert dec["enforced"] is case.get("enforced", True)
    assert dec["request_digest"] == request_digest(req)
    assert schema_errors("broker", "decision", dec) == []
    if approval:
        assert schema_errors("broker", "approval", approval) == []


@pytest.mark.parametrize("case", TABLE["access_cases"], ids=lambda c: c["name"])
def test_access_table(case):
    """P-07: a request is bound to its actor; nobody else may read or cancel it."""
    manifest = TABLE["manifests"][case["manifest"]]
    req = _request({"action": "service.status", "actor": case["owner"]})
    dec = decide_access(manifest, req, case["caller"], case["operation"], now=NOW)
    assert (dec["verdict"], dec["reason"]) == (case["verdict"], case["reason"])
    assert dec["enforced"] is case.get("enforced", True)
    # the decision is the audit record of the attempt: who asked, to do what, to which request
    assert (dec["caller"], dec["operation"]) == (case["caller"], case["operation"])
    assert (dec["request_id"], dec["request_digest"]) == (req["request_id"], req["digest"])
    assert schema_errors("broker", "decision", dec) == []


def test_access_table_covers_both_operations_both_ways():
    seen = {(c["operation"], c["verdict"]) for c in TABLE["access_cases"]}
    assert seen >= {("read", "allow"), ("read", "deny"), ("cancel", "allow"), ("cancel", "deny")}


def test_access_rejects_unknown_operations():
    req = _request({"action": "service.status", "actor": "profile:reader"})
    with pytest.raises(ValueError, match="operation"):
        decide_access(TABLE["manifests"]["enforce"], req, "profile:reader", "execute", now=NOW)


def test_access_decision_without_owner_reason_is_rejected_by_schema():
    req = _request({"action": "service.status", "actor": "profile:reader"})
    dec = decide_access(TABLE["manifests"]["enforce"], req, "profile:writer", "read", now=NOW)
    assert schema_errors("broker", "decision", dict(dec, verdict="allow")) != []


def test_only_explicit_allows_allow():
    """Property: across the whole table, every allow is one of the two allow reasons."""
    for case in TABLE["cases"] + TABLE["access_cases"]:
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


# ---- approval hardening (security review: expiry, self-approval, allowlist, single use)
OPS = {
    "manifest_id": "m",
    "default": "deny",
    "mode": "enforce",
    "approval_ttl_s": 60,
    "actions": [
        {
            "action": "host.reboot",
            "tier": "execute",
            "handler": "h/reboot.sh",
            "requires_approval": True,
        }
    ],
    "grants": [
        {"profile": "profile:ops-bot", "actions": ["host.reboot"], "max_tier": "execute"},
        {"profile": "profile:other-bot", "actions": ["host.reboot"], "max_tier": "execute"},
    ],
    "approvers": [
        {"issuer": "sso", "subject": "alice", "kind": "human"},
        {"issuer": "x", "subject": "ops_bot", "kind": "human"},
        {"issuer": "agents", "subject": "other-bot"},
    ],
}


def _ops_req():
    req = {
        "request_id": "r1",
        "action": "host.reboot",
        "actor": "profile:ops-bot",
        "target": "svc:db",
        "params": {},
        "created": "2026-01-01T00:00:00Z",
    }
    req["digest"] = request_digest(req)
    return req


def _ops_appr(req, **over):
    appr = {
        "approval_id": "a1",
        "request_id": "r1",
        "request_digest": req["digest"],
        "decision": "approved",
        "approver": {"subject": "alice", "issuer": "sso"},
        "approved_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-01T00:00:01Z",
    }
    appr.update(over)
    return appr


def _reason(manifest, approval, now, store=None):
    return decide(manifest, _ops_req(), approval, now=now, store=store or MemoryApprovalStore())[
        "reason"
    ]


def test_expires_at_is_enforced():
    req = _ops_req()
    assert _reason(OPS, _ops_appr(req), "2027-01-01T00:00:00Z") == "approval-expired"
    assert _reason(OPS, _ops_appr(req), "2026-01-01T00:00:01Z") == "approved"


def test_missing_ttl_gets_the_default():
    m = {k: v for k, v in OPS.items() if k != "approval_ttl_s"}
    appr = _ops_appr(_ops_req())
    del appr["expires_at"]
    assert _reason(m, appr, "2027-01-01T00:00:00Z") == "approval-expired"
    edge = f"2026-01-01T00:{DEFAULT_APPROVAL_TTL_S // 60:02d}:00Z"
    assert _reason(m, appr, edge) == "approved"


def test_now_defaults_to_the_clock():
    appr = _ops_appr(_ops_req())
    dec = decide(OPS, _ops_req(), appr, store=MemoryApprovalStore())
    assert dec["reason"] == "approval-expired"  # 2026-01-01 is in the past
    assert dec["decided_at"] != _ops_req()["created"]


def test_approval_from_the_future_is_refused():
    appr = _ops_appr(
        _ops_req(), approved_at="2099-01-01T00:00:00Z", expires_at="2099-01-01T00:01:00Z"
    )
    assert _reason(OPS, appr, "2027-01-01T00:00:00Z") == "approval-time-invalid"


def test_self_approval_is_compared_normalized():
    appr = _ops_appr(_ops_req(), approver={"subject": "ops_bot", "issuer": "x"})
    assert _reason(OPS, appr, "2026-01-01T00:00:00Z") == "approval-self-approved"
    assert normalize_identity("Ops.Bot") == normalize_identity("ops_bot") == "ops-bot"


def test_unlisted_and_agent_approvers_are_refused():
    req = _ops_req()
    stranger = _ops_appr(req, approver={"subject": "mallory", "issuer": "sso"})
    assert _reason(OPS, stranger, "2026-01-01T00:00:00Z") == "approval-approver-not-allowed"
    wrong_issuer = _ops_appr(req, approver={"subject": "alice", "issuer": "agents"})
    assert _reason(OPS, wrong_issuer, "2026-01-01T00:00:00Z") == "approval-approver-not-allowed"
    agent = _ops_appr(req, approver={"subject": "other-bot", "issuer": "agents"})
    assert _reason(OPS, agent, "2026-01-01T00:00:00Z") == "approval-agent-approver"
    assert (
        _reason(dict(OPS, allow_agent_approvers=True), agent, "2026-01-01T00:00:00Z") == "approved"
    )
    no_list = {k: v for k, v in OPS.items() if k != "approvers"}
    assert (
        _reason(no_list, _ops_appr(req), "2026-01-01T00:00:00Z") == "approval-approver-not-allowed"
    )


def test_approval_is_single_use():
    store = MemoryApprovalStore()
    appr = _ops_appr(_ops_req())
    assert _reason(OPS, appr, "2026-01-01T00:00:00Z", store) == "approved"
    assert _reason(OPS, appr, "2026-01-01T00:00:00Z", store) == "approval-replayed"
    assert store.consumed("a1")


def test_shadow_does_not_consume_but_reports_replay():
    store = MemoryApprovalStore()
    appr = _ops_appr(_ops_req())
    shadow = dict(OPS, mode="shadow")
    assert _reason(shadow, appr, "2026-01-01T00:00:00Z", store) == "approved"
    assert not store.consumed("a1")
    assert _reason(OPS, appr, "2026-01-01T00:00:00Z", store) == "approved"
    assert _reason(shadow, appr, "2026-01-01T00:00:00Z", store) == "approval-replayed"


def test_hardening_decisions_validate():
    for appr in (
        _ops_appr(_ops_req()),
        _ops_appr(_ops_req(), approver={"subject": "x", "issuer": "y"}),
    ):
        dec = decide(OPS, _ops_req(), appr, now="2026-01-01T00:00:00Z", store=MemoryApprovalStore())
        assert schema_errors("broker", "decision", dec) == []
    assert schema_errors("broker", "manifest", OPS) == []
