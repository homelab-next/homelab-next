# SPDX-License-Identifier: Apache-2.0
"""Regressions from the broker service review: each test fails on the code as reviewed and passes
on the fix (the approval's real state, consuming an approval only when the run proceeds, audit
records that cannot be made unwritable, the keyed request digest, bounded listings, manifest
problems instead of a traceback, cached params validators).  The transport, exec and importer
regressions live beside their modules' tests."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from conformance.protocols.broker import ArgSpec, BrokerError, Denied
from homelabnext.agent.digest import digest_of
from homelabnext.agent.schemas import schema_errors
from homelabnext.broker import request_digest, validation
from homelabnext.broker.service import BrokerService, validate_manifest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "broker"
EXAMPLE = EXAMPLES / "manifest.yml"
T0 = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
AGENT = "profile:triage"
APPROVER = "sso:operator-one"
TOKEN = "fake-demo-token-9e3a"


class Clock:
    def __init__(self, t: datetime = T0) -> None:
        self.t = t

    def __call__(self) -> datetime:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += timedelta(seconds=seconds)


def _svc(tmp_path, clock=None, **kw):
    kw.setdefault("resolve_secret", {"DEMO_API_TOKEN": TOKEN}.__getitem__)
    return BrokerService.from_manifest(
        EXAMPLE, tmp_path / "state", data_root=tmp_path / "data", clock=clock or Clock(), **kw
    )


def _restart(svc):
    return svc.submit(AGENT, "service.restart", {"grace_s": 30}, target="svc:queue")


def _row(rows, rid):
    return next(r for r in rows if r["request_id"] == rid)


# -- 1: the approval's real state -----------------------------------------------------------------


def test_pending_reports_the_approval_state_not_just_that_one_exists(tmp_path):
    clock = Clock()
    svc = _svc(tmp_path, clock)
    rid = _restart(svc)
    row = _row(svc.pending(), rid)
    assert (row["approval_state"], row["approved"]) == ("none", False)
    svc.approve(rid, APPROVER)
    row, mine = _row(svc.pending(), rid), _row(svc.pending_for(AGENT), rid)
    assert (row["approval_state"], row["approved"]) == ("valid", True)
    assert (mine["approval_state"], mine["awaiting_approval"]) == ("valid", False)
    clock.advance(901)  # past approval_ttl_s: the approval no longer lets the request run
    row, mine = _row(svc.pending(), rid), _row(svc.pending_for(AGENT), rid)
    assert (row["approval_state"], row["approved"]) == ("expired", False)
    assert (mine["approval_state"], mine["awaiting_approval"]) == ("expired", True)
    svc.approve(rid, APPROVER)  # a fresh approval after expiry
    assert _row(svc.pending(), rid)["approval_state"] == "valid"
    assert svc.run(AGENT, rid)["exit_code"] == 0


def test_a_consumed_approval_is_reported_consumed(tmp_path):
    svc = _svc(tmp_path)
    rid = _restart(svc)
    appr = svc.approve(rid, APPROVER)
    svc.approvals.consume(appr["approval_id"])  # e.g. a run that crashed after consuming it
    row = _row(svc.pending(), rid)
    assert (row["approval_state"], row["approved"]) == ("consumed", False)


# -- 2: an approval is consumed only when the run proceeds ----------------------------------------


def test_a_refused_run_does_not_burn_the_approval(tmp_path):
    svc = _svc(tmp_path)
    rid = _restart(svc)
    appr = svc.approve(rid, APPROVER)
    # the handler document changed under the request: its params no longer validate
    manifest, docs = dict(svc.manifest), [dict(d) for d in svc._docs.values()]
    for d in docs:
        if d["action"] == "service.restart":
            d["params_schema"] = {**d["params_schema"], "properties": {"grace_s": {"maximum": 5}}}
    strict = BrokerService(
        tmp_path / "state",
        manifest,
        handler_docs=docs,
        base_dir=EXAMPLES,
        data_root=tmp_path / "data",
        clock=Clock(),
        resolve_secret={"DEMO_API_TOKEN": TOKEN}.__getitem__,
    )
    with pytest.raises(BrokerError) as info:
        strict.run(AGENT, rid)
    assert info.value.reason == "invalid-params"
    assert not svc.approvals.consumed(appr["approval_id"])
    assert svc.state.state_of(rid) == "pending"
    assert svc.run(AGENT, rid)["exit_code"] == 0  # the same approval still runs it, once


def test_a_lost_claim_does_not_burn_the_approval(tmp_path, monkeypatch):
    svc = _svc(tmp_path)
    rid = _restart(svc)
    appr = svc.approve(rid, APPROVER)
    monkeypatch.setattr(svc.state, "claim", lambda *a, **k: False)
    with pytest.raises(BrokerError) as info:
        svc.run(AGENT, rid)
    assert info.value.reason == "not-pending"
    assert not svc.approvals.consumed(appr["approval_id"])


# -- 3: the audit record of a denial is always written --------------------------------------------


def test_a_long_action_name_is_denied_and_audited(tmp_path):
    svc = _svc(tmp_path)
    with pytest.raises(Denied) as info:
        svc.call(AGENT, "x" * 300, {})
    assert info.value.reason == "default-deny"
    (rec,) = svc.audit_documents(outcome="denied")
    assert rec["action"] == "x" * 128 and schema_errors("broker", "audit", rec) == []


def test_an_invalid_audit_record_still_leaves_a_record(tmp_path):
    svc = _svc(tmp_path)
    with pytest.raises(BrokerError, match="audit record invalid"):
        svc._audit(AGENT, "a.b", "call", "denied", reason="Not A Reason")
    (rec,) = list(svc.state.audit_records())
    assert (rec["outcome"], rec["reason"]) == ("denied", "audit-record-invalid")
    assert schema_errors("broker", "audit", rec) == []


# -- 9: the digest never carries a secret argument in the clear ---------------------------------


def test_the_request_digest_is_keyed_over_secret_arguments(tmp_path):
    svc = BrokerService(tmp_path / "state", clock=Clock())
    spec = {"user": ArgSpec("str"), "pw": ArgSpec("str", secret=True)}
    svc.register("ops.login", lambda **kw: "ok", spec)
    svc.allow("ops", ["ops.login"])
    rid = svc.submit("ops", "ops.login", {"user": "svc", "pw": "1234"})
    req = svc.state.get_request(rid)["request"]
    clear = digest_of(
        {"action": "ops.login", "actor": "ops", "params": {"user": "svc", "pw": "1234"}}
    )
    assert req["digest"] != clear, "a low-entropy secret could be brute-forced from the digest"
    assert req["digest"] == request_digest(req), "the stored request still binds its digest"
    assert "1234" not in json.dumps(req)
    again = svc.submit("ops", "ops.login", {"user": "svc", "pw": "1234"})
    assert svc.state.get_request(again)["request"]["params"]["pw"] == req["params"]["pw"]
    other = BrokerService(tmp_path / "state", clock=Clock())  # same state: the same key
    assert other._keyed("1234") == req["params"]["pw"]
    assert svc.run("ops", rid) == "ok"


# -- 11: bounded listings, manifest problems, cached validators ----------------------------------


def test_pending_reads_only_open_requests(tmp_path, monkeypatch):
    svc = _svc(tmp_path)
    for i in range(20):
        svc.cancel(AGENT, svc.submit(AGENT, "memory.write", {"name": f"a{i}.md", "content": "x"}))
    rid = _restart(svc)
    reads = []
    real = svc.state.get_request
    monkeypatch.setattr(svc.state, "get_request", lambda r: reads.append(r) or real(r))
    assert [r["request_id"] for r in svc.pending()] == [rid]
    assert [r["request_id"] for r in svc.pending_for(AGENT)] == [rid]
    assert len(reads) <= 2, reads


def test_open_requests_index_is_rebuilt_for_existing_state(tmp_path):
    svc = _svc(tmp_path)
    rid = _restart(svc)
    shutil.rmtree(tmp_path / "state" / "open")
    assert [r["request_id"] for r in _svc(tmp_path).pending()] == [rid]


def test_audit_documents_tail_reads_newest_first(tmp_path, monkeypatch):
    svc = _svc(tmp_path)
    for i in range(30):
        svc.call(AGENT, "memory.write", {"name": f"m{i}.md", "content": "x"})
    from homelabnext.broker import state as state_mod

    loads = []
    real = state_mod._load
    monkeypatch.setattr(state_mod, "_load", lambda p: loads.append(p) or real(p))
    rows = svc.audit_documents(limit=3, outcome="ok")
    assert [r["args"]["name"] for r in rows] == ["m27.md", "m28.md", "m29.md"]
    assert len(loads) == 5, "each call is a started and an ok record: the tail is five files"


def test_a_malformed_handler_document_is_a_problem_not_a_crash(tmp_path):
    dst = tmp_path / "ex"
    shutil.copytree(EXAMPLES, dst)
    (dst / "handlers" / "service-status.handler.json").write_text("{not json")
    doc = yaml.safe_load((dst / "manifest.yml").read_text())
    _, problems = validate_manifest(doc, dst)
    assert any("service-status.handler.json: cannot be read" in p for p in problems), problems


def test_params_validators_are_cached_per_schema():
    schema = {"type": "object", "properties": {"n": {"type": "integer"}}}
    validation.inline_errors(schema, {"n": 1})
    before = validation._inline_validator.cache_info()
    assert validation.inline_errors(dict(schema), {"n": "x"})
    assert validation._inline_validator.cache_info().hits == before.hits + 1


def test_request_ids_are_oldest_first(tmp_path):
    svc = _svc(tmp_path)
    rids = [
        svc.submit(AGENT, "memory.write", {"name": f"o{i}.md", "content": "x"}) for i in range(8)
    ]
    assert svc.state.request_ids() == rids
