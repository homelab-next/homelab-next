# SPDX-License-Identifier: Apache-2.0
"""The reference broker service: the conformance suite on it, the example manifest end to end, the
approvals flow, durable single-use approvals across processes, and the audit trail."""

from __future__ import annotations

import json
import multiprocessing
import re
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from conformance.protocols.broker import ArgSpec, BrokerError, Denied, InvalidArguments
from homelabnext.agent.schemas import schema_errors
from homelabnext.broker import decide, request_digest
from homelabnext.broker.service import (
    BrokerService,
    ManifestError,
    load_manifest,
    make,
    validate_manifest,
)
from homelabnext.broker.state import FileApprovalStore, StateDir, is_id, write_exclusive
from homelabnext.conform.runner import mutation_runs, run_capability
from homelabnext.events.envelope import event_problems

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "broker" / "manifest.yml"
T0 = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
AGENT = "profile:triage"
APPROVER = "sso:operator-one"
TOKEN = "fake-demo-token-4b1d"


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


def _audit_ok(svc):
    docs = list(svc.state.audit_records())
    for doc in docs:
        assert schema_errors("broker", "audit", doc) == [], doc
    return docs


# -- the conformance suite ------------------------------------------------------------------------


def test_reference_service_passes_the_suite():
    run = run_capability("broker", "broker-reference", ROOT)
    assert run.error is None and run.too_few is None
    assert not run.failed_must and not run.failed_should, [r.evidence for r in run.results]


def test_the_suite_still_catches_every_broker_mutant():
    runs = mutation_runs("broker", ROOT)
    assert runs and all(m.detected for m in runs), [m.name for m in runs if not m.detected]


def test_factory_gives_each_check_a_private_state_dir():
    a, b = make(), make()
    assert a.state.root != b.state.root and a.state.root.is_dir()
    assert make(manifest=str(EXAMPLE)).manifest["manifest_id"] == "example-lab-broker"


# -- the manifest ---------------------------------------------------------------------------------


def test_example_manifest_validates():
    manifest, docs = load_manifest(EXAMPLE)
    assert {d["action"] for d in docs} == {"service.status", "service.restart"}
    assert schema_errors("broker", "manifest", manifest) == []


def _copy_example(tmp_path):
    dst = tmp_path / "ex"
    shutil.copytree(EXAMPLE.parent, dst)
    return dst / "manifest.yml"


def test_tampered_handler_fails_validation_and_never_runs(tmp_path):
    path = _copy_example(tmp_path)
    load_manifest(path)  # passes as shipped
    h = path.parent / "handlers" / "service-status.sh"
    h.write_text(h.read_text() + "touch /tmp/never\n")
    with pytest.raises(ManifestError) as info:
        load_manifest(path)
    assert any("handler_digest does not match" in p for p in info.value.problems)


def _problems(mutate, tmp_path):
    import yaml

    path = _copy_example(tmp_path)
    doc = yaml.safe_load(path.read_text())
    mutate(doc)
    return validate_manifest(doc, path.parent)[1]


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda d: d["actions"][0].update(lane="nowhere"), "is not declared"),
        (lambda d: d["actions"][0].update(handler="handlers/service-status.sh"), "builtin/lane"),
        (lambda d: d["actions"][0].update(tier="read"), "tier write"),
        (lambda d: d["lanes"].append(dict(d["lanes"][0])), "declared twice"),
        (lambda d: d["lanes"][0].update(filename_pattern="("), "does not compile"),
        (lambda d: d["actions"][3].update(handler="builtin/shell"), "not a built-in handler"),
        (lambda d: d["handler_docs"].append("handlers/absent.json"), "missing or outside"),
        (lambda d: d["handler_docs"].pop(), "expected exactly one handler document"),
        (lambda d: d.update(default="allow"), "manifest:"),
    ],
)
def test_manifest_problems_are_reported(tmp_path, mutate, needle):
    assert _problems(lambda d: None, tmp_path) == []
    problems = _problems(mutate, tmp_path / "bad")
    assert any(needle in p for p in problems), problems


def test_handler_document_problems(tmp_path):
    path = _copy_example(tmp_path)
    doc_path = path.parent / "handlers" / "service-restart.handler.json"
    doc = json.loads(doc_path.read_text())
    doc["secrets"] = ["PATH"]
    doc["params_schema"] = {"type": "nonsense"}
    doc_path.write_text(json.dumps(doc))
    problems = validate_manifest(load_yaml(path), path.parent)[1]
    assert any("reserved" in p for p in problems) and any("params_schema" in p for p in problems)
    doc_path.write_text(json.dumps({"action": "service.restart"}))
    assert validate_manifest(load_yaml(path), path.parent)[1]
    (path.parent / "handlers" / "service-restart.sh").unlink()
    doc_path.write_text(
        json.dumps(json.loads((EXAMPLE.parent / doc_path.relative_to(path.parent)).read_text()))
    )
    assert any("missing" in p for p in validate_manifest(load_yaml(path), path.parent)[1])


def load_yaml(path):
    import yaml

    return yaml.safe_load(path.read_text())


def test_a_manifest_that_is_not_a_mapping(tmp_path):
    p = tmp_path / "m.json"
    p.write_text("[]")
    with pytest.raises(ManifestError):
        load_manifest(p)


# -- the example end to end -----------------------------------------------------------------------


def test_lane_writes_through_the_broker(tmp_path):
    svc = _svc(tmp_path)
    out = svc.call(AGENT, "memory.write", {"name": "queue-notes.md", "content": "slow drain\n"})
    assert out["path"] == "memory/triage/queue-notes.md"
    assert (tmp_path / "data" / out["path"]).read_text() == "slow drain\n"
    with pytest.raises(Denied) as info:
        svc.call(AGENT, "memory.write", {"name": "../../etc/x.md", "content": "x"})
    assert info.value.reason == "lane-name-invalid"
    with pytest.raises(Denied) as info:
        svc.call(AGENT, "memory.write", {"name": "queue-notes.md", "content": "again"})
    assert info.value.reason == "lane-exists"
    with pytest.raises(InvalidArguments) as info:
        svc.call(AGENT, "memory.write", {"name": "big.md", "content": "x" * 70000})
    assert info.value.reason == "lane-too-large"
    with pytest.raises(Denied) as info:
        svc.call("profile:reader", "memory.write", {"name": "r.md", "content": "x"})
    assert info.value.reason == "not-granted"
    outcomes = [(d["outcome"], d["reason"]) for d in _audit_ok(svc)]
    assert outcomes == [
        ("started", ""),  # admitted: the intent is recorded before the write
        ("ok", ""),
        ("denied", "lane-name-invalid"),  # refused at admission: nothing started
        ("started", ""),
        ("denied", "lane-exists"),  # refused by the write itself
        ("invalid", "lane-too-large"),
        ("denied", "not-granted"),
    ]
    assert _audit_ok(svc)[5]["args"]["content"]["bytes"] > 70000, "large values are summarized"


def test_findings_and_proposals_lanes(tmp_path):
    svc = _svc(tmp_path)
    f = svc.call(AGENT, "finding.write", {"name": "2026-01-15-queue.md", "content": "# Finding\n"})
    assert f["path"] == "findings/triage/2026-01-15-queue.md"
    note = {"title": "Raise the drain timeout", "risk": "low", "rollback": "set it back"}
    p = svc.call(AGENT, "proposal.file", {"note": note, "body": "Seen twice."})
    assert re.fullmatch(
        r"records/inbox/2026-01-15-triage-raise-the-drain-timeout-[0-9a-f]{8}\.md", p["path"]
    )
    events = svc.state.outbox()
    assert [e["type"] for e in events] == ["homelabnext.proposal.created"]
    assert event_problems(events[0]) == [] and events[0]["data"]["risk"] == "low"
    with pytest.raises(Denied) as info:
        svc.call(AGENT, "proposal.file", {"note": dict(note, requesting_agent="profile:reader")})
    assert info.value.reason == "lane-identity-mismatch"
    # a future-dated note (to pre-claim a later day's name) is refused: the broker dates it
    with pytest.raises(InvalidArguments) as info:
        svc.call(AGENT, "proposal.file", {"note": dict(note, created="2026-12-01T00:00:00Z")})
    assert info.value.reason == "lane-created-set"


def test_read_only_exec_action(tmp_path):
    svc = _svc(tmp_path)
    out = svc.call("profile:reader", "service.status", {"verbose": True}, target="svc:queue")
    assert out["output"] == {
        "service": "svc:queue",
        "state": "running",
        "params": {"verbose": True},
    }
    with pytest.raises(InvalidArguments) as info:
        svc.call("profile:reader", "service.status", {"verbose": "yes"})
    assert info.value.reason == "invalid-params"
    with pytest.raises(InvalidArguments) as info:
        svc.call("profile:reader", "service.status", {}, target="https://x")
    assert info.value.reason == "invalid-target"
    with pytest.raises(InvalidArguments):
        svc.call("profile:reader", "service.status", ["not", "a", "mapping"])


def test_handler_tampered_after_load_is_refused_at_run_time(tmp_path):
    path = _copy_example(tmp_path)
    svc = BrokerService.from_manifest(path, tmp_path / "state", clock=Clock())
    h = path.parent / "handlers" / "service-status.sh"
    h.write_text(h.read_text() + "echo tampered\n")
    with pytest.raises(Denied) as info:
        svc.call("profile:reader", "service.status", {})
    assert info.value.reason == "handler-digest-mismatch"
    assert _audit_ok(svc)[-1]["reason"] == "handler-digest-mismatch"


def test_failing_and_slow_handlers_are_contained(tmp_path):
    path = _copy_example(tmp_path)
    h = path.parent / "handlers" / "service-status.sh"
    h.write_text("#!/bin/sh\necho internal-detail-9f >&2\nexit 3\n")
    doc_path = path.parent / "handlers" / "service-status.handler.json"
    doc = json.loads(doc_path.read_text())
    from homelabnext.broker.execute import file_digest

    doc["handler_digest"] = file_digest(h)
    doc_path.write_text(json.dumps(doc))
    svc = BrokerService.from_manifest(path, tmp_path / "state", clock=Clock())
    with pytest.raises(BrokerError) as info:
        svc.call("profile:reader", "service.status", {})
    assert info.value.reason == "handler-failed" and "internal-detail" not in str(info.value)
    h.write_text("#!/bin/sh\nsleep 30\n")
    doc["handler_digest"], doc["timeout_s"] = file_digest(h), 1
    doc_path.write_text(json.dumps(doc))
    svc = BrokerService.from_manifest(path, tmp_path / "state", clock=Clock())
    with pytest.raises(BrokerError) as info:
        svc.call("profile:reader", "service.status", {})
    assert info.value.reason == "handler-timeout"


# -- approvals ------------------------------------------------------------------------------------


def _restart(svc):
    return svc.submit(AGENT, "service.restart", {"grace_s": 30}, target="svc:queue")


def test_approval_flow_end_to_end(tmp_path):
    clock = Clock()
    svc = _svc(tmp_path, clock)
    with pytest.raises(Denied) as info:  # needs approval: call refuses, submit is the way
        svc.call(AGENT, "service.restart", {"grace_s": 30})
    assert info.value.reason == "approval-required"
    rid = _restart(svc)
    assert svc.status(AGENT, rid).state == "pending"
    [requested] = svc.state.outbox()
    assert requested["type"] == "homelabnext.decision.requested" and event_problems(requested) == []
    assert requested["data"]["decision_id"] == rid
    assert [p["request_id"] for p in svc.pending()] == [rid]
    with pytest.raises(Denied) as info:
        svc.run(AGENT, rid)
    assert info.value.reason == "approval-required"
    for who, reason in (
        ("sso:triage", "approval-self-approved"),
        ("sso:someone-else", "approval-approver-not-allowed"),
        ("elsewhere:operator-one", "approval-approver-not-allowed"),
    ):
        with pytest.raises(Denied) as info:
            svc.approve(rid, who)
        assert info.value.reason == reason
    with pytest.raises(InvalidArguments):
        svc.approve(rid, "no-issuer")
    clock.advance(60)
    appr = svc.approve(rid, APPROVER, note="ok for the window")
    assert schema_errors("broker", "approval", appr) == []
    assert appr["request_digest"] == svc.state.get_request(rid)["request"]["digest"]
    assert svc.pending()[0]["approved"] is True
    clock.advance(60)
    out = svc.run(AGENT, rid)
    assert out["output"]["would_restart"] == "svc:queue" and out["output"]["token_present"] is True
    assert svc.status(AGENT, rid).state == "done" and svc.pending() == []
    with pytest.raises(BrokerError) as info:
        svc.run(AGENT, rid)
    assert info.value.reason == "not-pending"
    returned = [e for e in svc.state.outbox() if e["type"] == "homelabnext.decision.returned"]
    assert len(returned) == 1 and returned[0]["data"]["verdict"] == "accept"
    assert event_problems(returned[0]) == []
    assert svc.detail(AGENT, rid)["result"]["state"] == "done"
    docs = _audit_ok(svc)
    assert all(TOKEN not in json.dumps(d) for d in docs)
    assert not any(TOKEN in p.read_text() for p in (tmp_path / "state").rglob("*.json"))


def test_expired_approval_leaves_the_request_pending_for_a_new_one(tmp_path):
    clock = Clock()
    svc = _svc(tmp_path, clock)
    rid = _restart(svc)
    svc.approve(rid, APPROVER)
    clock.advance(901)
    with pytest.raises(Denied) as info:
        svc.run(AGENT, rid)
    assert info.value.reason == "approval-expired"
    assert svc.status(AGENT, rid).state == "pending"
    svc.approve(rid, APPROVER)
    assert svc.run(AGENT, rid)["exit_code"] == 0


def test_denial_ends_the_request(tmp_path):
    svc = _svc(tmp_path)
    rid = _restart(svc)
    with pytest.raises(Denied) as info:
        svc.deny(rid, "sso:stranger")  # a stranger cannot deny either
    assert info.value.reason == "approval-approver-not-allowed"
    svc.deny(rid, APPROVER, note="not during business hours")
    assert svc.status(AGENT, rid).state == "denied"
    with pytest.raises(BrokerError):
        svc.run(AGENT, rid)
    with pytest.raises(BrokerError) as info:
        svc.approve(rid, APPROVER)
    assert info.value.reason == "not-awaiting-approval"
    with pytest.raises(Denied) as info:
        svc.approve("req-0000000000000000", APPROVER)
    assert info.value.reason == "unknown-request"
    verdicts = [e["data"]["verdict"] for e in svc.state.outbox() if "returned" in e["type"]]
    assert verdicts == ["reject"]


def test_an_allowed_request_is_not_awaiting_approval(tmp_path):
    svc = _svc(tmp_path)
    rid = svc.submit(AGENT, "memory.write", {"name": "a.md", "content": "x"})
    with pytest.raises(BrokerError):
        svc.approve(rid, APPROVER)
    assert svc.pending() == []
    svc.cancel(AGENT, rid)
    assert svc.status(AGENT, rid).state == "cancelled"
    with pytest.raises(BrokerError):
        svc.cancel(AGENT, rid)


def test_a_request_changed_after_approval_no_longer_matches(tmp_path):
    svc = _svc(tmp_path)
    rid = _restart(svc)
    svc.approve(rid, APPROVER)
    path = tmp_path / "state" / "requests" / f"{rid}.json"
    rec = json.loads(path.read_text())
    rec["request"]["params"]["grace_s"] = 0  # someone edits the stored request
    path.write_text(json.dumps(rec))
    with pytest.raises(Denied) as info:
        svc.run(AGENT, rid)
    assert info.value.reason == "approval-digest-mismatch"


def test_approval_is_single_use_across_service_instances(tmp_path):
    a = _svc(tmp_path)
    b = _svc(tmp_path)  # a second process over the same state directory
    rid = _restart(a)
    appr = a.approve(rid, APPROVER)
    req = a.state.get_request(rid)["request"]
    now = "2026-01-15T10:00:00Z"
    first = decide(a._view(), req, appr, now=now, store=a.approvals)
    second = decide(b._view(), req, appr, now=now, store=b.approvals)
    assert (first["reason"], second["reason"]) == ("approved", "approval-replayed")


def test_a_cancel_by_its_owner_closes_the_page_quietly(tmp_path):
    """A settled message per cancel let a submit/cancel loop send two messages a cycle."""
    sent = []
    svc = _svc(tmp_path, notifier=_notifier(sent))
    rid = _restart(svc)
    svc.cancel(AGENT, rid)
    assert [m.title for m in sent] == ["Broker approval needed"]
    assert svc.notifier.state_of(f"broker-approval-{rid}") == "ok", "the page is closed"


def _notifier(sent):
    from homelabnext.notify.core import Notifier

    class Sender:
        def send(self, message):
            sent.append(message)

    class Store(dict):
        def put(self, k, v):
            self[k] = v

        def delete(self, k):
            return self.pop(k, None) is not None

    return Notifier(sender=Sender(), store=Store(), clock=lambda: 0.0)


def test_notify_and_bus(tmp_path):
    sent, published = [], []

    class Bus:
        def publish(self, subject, data, *, msg_id=None):
            published.append((subject, json.loads(data), msg_id))
            return len(published)

    svc = _svc(tmp_path, notifier=_notifier(sent), bus=Bus())
    rid = _restart(svc)
    svc.approve(rid, APPROVER)
    assert [m.title for m in sent] == ["Broker approval needed", "Broker approval settled"]
    assert sent[0].level == "warn" and rid in sent[0].body
    assert [p[0] for p in published] == [
        "homelabnext.decision.requested",
        "homelabnext.decision.returned",
    ]
    assert all(p[1]["id"] == p[2] for p in published)
    assert svc.state.outbox() == [], "with a bus, nothing goes to the outbox"


def _quota_svc(tmp_path, clock=None, **quotas):
    manifest, docs = load_manifest(EXAMPLE)
    if quotas:
        manifest["quotas"] = quotas
    kw = {"notifier": quotas.pop("notifier")} if "notifier" in quotas else {}
    return BrokerService(
        tmp_path / "state",
        manifest,
        handler_docs=docs,
        base_dir=EXAMPLE.parent,
        data_root=tmp_path / "data",
        clock=clock or Clock(),
        **kw,
    )


def test_an_actor_may_have_only_so_many_requests_pending(tmp_path):
    """A looping agent with an approval-gated grant filed hundreds of requests a minute, each one
    a page and a row on the Approvals page, where one malicious request could hide."""
    svc = _quota_svc(tmp_path, pending_per_actor=3)
    rids = [_restart(svc) for _ in range(3)]
    with pytest.raises(Denied) as info:
        _restart(svc)
    assert info.value.reason == "too-many-pending"
    [rec] = svc.audit_documents(reason="too-many-pending")
    assert (rec["operation"], rec["outcome"], rec["caller"]) == ("submit", "denied", AGENT)
    assert len(svc.pending()) == 3 and len(svc.state.request_ids()) == 3
    svc.cancel(AGENT, rids[0])  # a settled request frees its place
    _restart(svc)
    assert len(svc.pending()) == 3


def test_a_lane_quota_from_the_manifest_refuses_the_write_and_audits_it(tmp_path):
    manifest, docs = load_manifest(EXAMPLE)
    manifest["lanes"][0]["max_files"] = 2
    assert validate_manifest(manifest, EXAMPLE.parent)[1] == []
    svc = BrokerService(
        tmp_path / "state", manifest, handler_docs=docs, base_dir=EXAMPLE.parent,
        data_root=tmp_path / "data", clock=Clock(),
    )  # fmt: skip
    for name in ("a.md", "b.md"):
        svc.call(AGENT, "memory.write", {"name": name, "content": "x"})
    with pytest.raises(Denied) as info:
        svc.call(AGENT, "memory.write", {"name": "c.md", "content": "x"})
    assert info.value.reason == "lane-quota-exceeded"
    assert svc.audit_documents(reason="lane-quota-exceeded")


def test_one_agent_cannot_lock_every_other_out_of_the_proposals_inbox(tmp_path):
    """The proposals inbox is one shared directory: one looping agent filled its quota in under
    a minute, with no refusal on the way, and every other agent's proposal was then refused."""
    manifest, docs = load_manifest(EXAMPLE)
    manifest["grants"][1]["actions"].append("proposal.file")
    manifest["grants"][1]["max_tier"] = "write"
    svc = BrokerService(
        tmp_path / "state", manifest, handler_docs=docs, base_dir=EXAMPLE.parent,
        data_root=tmp_path / "data", clock=Clock(),
    )  # fmt: skip
    note = {"title": "t", "risk": "low", "rollback": "r", "type": "proposal"}
    filed, why = 0, None
    while why is None and filed < 5000:
        try:
            svc.call(AGENT, "proposal.file", {"note": note, "body": "A", "slug": f"s{filed}"})
            filed += 1
        except Denied as exc:
            why = exc.reason
    assert why in ("lane-rate-exceeded", "lane-quota-exceeded") and filed <= 512
    svc.call("profile:reader", "proposal.file", {"note": dict(note, title="help"), "body": "x"})


def test_the_operator_hears_once_that_a_lane_refuses_an_agent_for_its_quota(tmp_path):
    """lane-quota-exceeded reached the agent alone: under the Hermes rules a finding that is never
    written reads like a run that never happened, and nothing told the operator."""
    sent = []
    manifest, docs = load_manifest(EXAMPLE)
    manifest["lanes"][0]["max_files"] = 5
    svc = BrokerService(
        tmp_path / "state", manifest, handler_docs=docs, base_dir=EXAMPLE.parent,
        data_root=tmp_path / "data", clock=Clock(), notifier=_notifier(sent),
    )  # fmt: skip
    for name in ("a.md", "a1.md", "a2.md", "a3.md", "a4.md"):
        svc.call(AGENT, "memory.write", {"name": name, "content": "x"})
    for name in ("b.md", "c.md", "d.md"):
        with pytest.raises(Denied):
            svc.call(AGENT, "memory.write", {"name": name, "content": "x"})
    [notice] = sent
    assert notice.title == "Broker lane quota reached" and notice.level == "warn"
    assert AGENT in notice.body and "memory" in notice.body
    clock = svc.clock
    clock.advance(1000)
    for name in ("a.md", "a1.md", "a2.md"):  # back under 80% of the quota that was hit
        (tmp_path / "data" / "memory" / "triage" / name).unlink()
    svc.call(AGENT, "memory.write", {"name": "b.md", "content": "x"})
    assert [m.title for m in sent] == ["Broker lane quota reached", "Broker lane quota cleared"]
    svc.call(AGENT, "finding.write", {"name": "2026-01-15-x.md", "content": "x"})
    assert len(sent) == 2, "a write that lands with nothing to clear sends nothing"


def test_a_lane_quota_notice_does_not_flap_between_reached_and_cleared(tmp_path):
    """ "Cleared" went out on the next write that landed: alternating a write that does not fit
    with a one-byte one that does sent 600 operator messages in 20 seconds."""
    sent = []
    clock = Clock()
    manifest, docs = load_manifest(EXAMPLE)
    manifest["lanes"][0].update(max_files=None, max_total_bytes=1000, max_bytes=200)
    svc = BrokerService(
        tmp_path / "state", manifest, handler_docs=docs, base_dir=EXAMPLE.parent,
        data_root=tmp_path / "data", clock=clock, notifier=_notifier(sent),
    )  # fmt: skip
    for i in range(4):
        svc.call(AGENT, "memory.write", {"name": f"f{i}.md", "content": "x" * 200})
    svc.call(AGENT, "memory.write", {"name": "g.md", "content": "x" * 50})
    for i in range(50):  # 850 held: a 200-byte write is refused, a 1-byte one fits
        with pytest.raises(Denied):
            svc.call(AGENT, "memory.write", {"name": f"big{i}.md", "content": "x" * 200})
        svc.call(AGENT, "memory.write", {"name": f"s{i}.md", "content": "x"})
        clock.advance(60)
    assert [m.title for m in sent] == ["Broker lane quota reached"], "still 90% full: no clear"
    for i in range(4):
        (tmp_path / "data" / "memory" / "triage" / f"f{i}.md").unlink()
    svc.call(AGENT, "memory.write", {"name": "after.md", "content": "x"})
    assert [m.title for m in sent][-1] == "Broker lane quota cleared"
    for i in range(4):  # 101 held, + 4 x 190 = 861: they fit, and 200 more do not
        svc.call(AGENT, "memory.write", {"name": f"again{i}.md", "content": "x" * 190})
    with pytest.raises(Denied):  # full again at once: inside the interval, no new notice
        svc.call(AGENT, "memory.write", {"name": "again-last.md", "content": "x" * 200})
    assert len(sent) == 2


def test_a_held_cleared_notice_is_sent_without_another_write(tmp_path):
    """A "cleared" held back by the interval was retried only on the actor's next landed write:
    a drained lane the actor never wrote to again stayed red."""
    sent = []
    clock = Clock()
    manifest, docs = load_manifest(EXAMPLE)
    manifest["lanes"][0]["max_files"] = 5
    svc = BrokerService(
        tmp_path / "state", manifest, handler_docs=docs, base_dir=EXAMPLE.parent,
        data_root=tmp_path / "data", clock=clock, notifier=_notifier(sent),
    )  # fmt: skip
    for i in range(5):
        svc.call(AGENT, "memory.write", {"name": f"a{i}.md", "content": "x"})
    with pytest.raises(Denied):
        svc.call(AGENT, "memory.write", {"name": "b.md", "content": "x"})
    for i in range(5):
        (tmp_path / "data" / "memory" / "triage" / f"a{i}.md").unlink()  # the decider drains it
    clock.advance(1000)
    svc.poll_pages()
    assert [m.title for m in sent] == ["Broker lane quota reached", "Broker lane quota cleared"]


@pytest.mark.parametrize("root", ["memory", "memory/deeper", "findings/../x"])
def test_lanes_over_one_directory_are_refused(root):
    """Two lanes over one directory each kept their own ledger: an actor writing through both had
    two shares and two write rates over the same files."""
    manifest, _ = load_manifest(EXAMPLE)
    manifest["lanes"].append(dict(manifest["lanes"][0], name="memory-two", root=root))
    problems = validate_manifest(manifest, EXAMPLE.parent)[1]
    assert any("overlap" in p or ".." in p for p in problems), problems
    manifest["lanes"][-1]["root"] = "memory-two"  # a sibling, not an overlap
    assert validate_manifest(manifest, EXAMPLE.parent)[1] == []


def test_the_pending_quota_has_a_default(tmp_path):
    from homelabnext.broker.service import DEFAULT_PENDING_PER_ACTOR

    svc = _quota_svc(tmp_path)
    for _ in range(DEFAULT_PENDING_PER_ACTOR):
        _restart(svc)
    with pytest.raises(Denied):
        _restart(svc)


def test_approval_pages_are_coalesced_while_the_actor_has_an_open_page(tmp_path):
    sent = []
    clock = Clock()
    svc = _quota_svc(tmp_path, clock, notifier=_notifier(sent))
    first = _restart(svc)
    rest = []
    for _ in range(4):
        clock.advance(10)
        rest.append(_restart(svc))
    assert [m.title for m in sent] == ["Broker approval needed"], "one open page per actor"
    assert first in sent[0].body
    assert len(svc.state.outbox()) == 5, "every request still emits its event"
    clock.advance(3600)
    _restart(svc)
    assert len(sent) == 1, "the page is still open: no time window reopens it"
    svc.approve(first, APPROVER)  # the paged one settles: the page moves to the oldest waiting
    settled, moved = sent[1:]
    assert settled.title == "Broker approval settled" and "5 more" in settled.body
    assert moved.title == "Broker approval needed" and moved.level == "warn"
    assert rest[0] in moved.body and all(r in moved.body for r in rest), "names every waiting id"
    assert "5 requests await approval" in moved.body


def test_a_request_filed_after_a_cancelled_decoy_still_pages(tmp_path):
    """The page window was spent by a decoy the actor then cancelled: the real request, filed
    inside the window, never paged, now or later."""
    sent = []
    clock = Clock()
    svc = _quota_svc(tmp_path, clock, notifier=_notifier(sent))
    decoy = _restart(svc)
    clock.advance(5)
    svc.cancel(AGENT, decoy)
    clock.advance(5)
    real = _restart(svc)
    assert len(sent) == 1, "the floor between an actor's pages holds"
    clock.advance(300)
    svc.pending()  # what the hub lists every few seconds: the due page goes out
    assert [m.title for m in sent][-1] == "Broker approval needed" and real in sent[-1].body


def test_a_retry_after_a_denial_pages(tmp_path):
    sent = []
    clock = Clock()
    svc = _quota_svc(tmp_path, clock, notifier=_notifier(sent))
    svc.deny(_restart(svc), APPROVER)
    clock.advance(30)
    retry = _restart(svc)
    assert sent[-1].title == "Broker approval settled"
    clock.advance(300)
    assert svc.poll_pages() == 1
    assert sent[-1].title == "Broker approval needed" and retry in sent[-1].body


def test_a_submit_cancel_loop_pages_at_most_once_per_floor(tmp_path):
    """With only the open-page gate, 200 submit/cancel cycles sent 400 messages in five seconds,
    every operation answered ok, so neither the refusal limit nor the pending quota tripped."""
    sent = []
    clock = Clock()
    svc = _quota_svc(tmp_path, clock, notifier=_notifier(sent))
    for _ in range(200):
        svc.cancel(AGENT, _restart(svc))
    assert len(sent) == 1
    clock.advance(300)
    svc.poll_pages()
    assert len(sent) == 1, "nothing waits: nothing is due"


def test_one_actor_cannot_spend_another_actors_notifier_budget(tmp_path):
    from homelabnext.notify.core import RateLimit

    sent = []
    manifest, docs = load_manifest(EXAMPLE)
    manifest["grants"][1]["actions"].append("service.restart")
    manifest["grants"][1]["max_tier"] = "execute"
    manifest["quotas"] = {"notify_window_s": 0}  # no floor: only the budget stands in the way
    notifier = _notifier(sent)
    notifier.rate_limit = RateLimit(max_sends=20, window_s=3600)
    svc = BrokerService(
        tmp_path / "state", manifest, handler_docs=docs, base_dir=EXAMPLE.parent,
        data_root=tmp_path / "data", clock=Clock(), notifier=notifier,
    )  # fmt: skip
    for _ in range(30):
        svc.cancel(AGENT, _restart(svc))
    assert len(sent) == 20, "the looping agent spent its own budget"
    other = svc.submit("profile:reader", "service.restart", {"grace_s": 1}, target="svc:queue")
    assert other in sent[-1].body, "another agent is still paged"


def test_an_approval_that_expires_unused_pages_again(tmp_path):
    sent = []
    clock = Clock()
    svc = _quota_svc(tmp_path, clock, notifier=_notifier(sent))
    rid = _restart(svc)
    clock.advance(400)
    svc.approve(rid, APPROVER)
    assert [m.title for m in sent] == ["Broker approval needed", "Broker approval settled"]
    clock.advance(902)  # past approval_ttl_s: the request waits for an approver again
    svc.poll_pages()
    assert sent[-1].title == "Broker approval needed" and rid in sent[-1].body


def test_a_deferred_page_is_sent_by_its_timer(tmp_path):
    import time

    sent = []
    clock = Clock()
    svc = _quota_svc(tmp_path, clock, notifier=_notifier(sent), notify_window_s=1)
    svc.cancel(AGENT, _restart(svc))
    waiting = _restart(svc)
    clock.advance(2)  # the broker's clock passes the floor; the timer fires in real time
    for _ in range(100):
        if len(sent) == 2:
            break
        time.sleep(0.05)
    assert len(sent) == 2 and waiting in sent[1].body


def test_a_page_due_before_a_restart_is_sent_after_it(tmp_path):
    """What was due lived in memory: after a restart, a request whose page the floor had
    deferred was never paged, whatever else happened."""
    sent = []
    clock = Clock()
    notifier = _notifier(sent)
    svc = _quota_svc(tmp_path, clock, notifier=notifier)
    svc.cancel(AGENT, _restart(svc))
    clock.advance(10)
    waiting = _restart(svc)
    assert len(sent) == 1
    clock.advance(600)
    _quota_svc(tmp_path, clock, notifier=notifier)  # the broker restarts on the same state
    assert waiting in sent[-1].body and sent[-1].title == "Broker approval needed"


def test_a_page_whose_send_failed_is_retried(tmp_path):
    sent = []
    clock = Clock()
    svc = _quota_svc(tmp_path, clock, notifier=_notifier(sent))
    real, calls = svc.notifier.sender.send, []

    def flaky(message):
        calls.append(message)
        if len(calls) == 1:
            raise RuntimeError("ntfy down")
        real(message)

    svc.notifier.sender.send = flaky
    rid = _restart(svc)
    svc.pending()
    assert sent == [] and len(calls) == 1, "not retried on every listing"
    clock.advance(61)
    svc.pending()
    assert [m.title for m in sent] == ["Broker approval needed"] and rid in sent[0].body


def test_an_expiry_is_not_lost_behind_an_earlier_due(tmp_path):
    """One due slot per actor: approving r1 deferred r2's page, and r1's expiry, later, was
    dropped; r1's approval expired unused and it was never paged again."""
    sent = []
    clock = Clock()
    svc = _quota_svc(tmp_path, clock, notifier=_notifier(sent))
    r1 = _restart(svc)
    clock.advance(1)
    r2 = _restart(svc)
    clock.advance(60)
    svc.approve(r1, APPROVER)
    clock.advance(300)
    svc.poll_pages()
    assert r2 in sent[-1].body
    svc.deny(r2, APPROVER)
    n = len(sent)
    clock.advance(4000)
    svc.poll_pages()
    assert any(r1 in m.body and m.title == "Broker approval needed" for m in sent[n:])


def test_the_timer_is_armed_for_the_next_due_check(tmp_path):
    sent = []
    clock = Clock()
    svc = _quota_svc(tmp_path, clock, notifier=_notifier(sent))
    svc.cancel(AGENT, _restart(svc))
    _restart(svc)  # deferred by the floor: a check is due when it passes
    try:
        at, timer = svc._timer
        assert timer.is_alive() and at == svc._last_page[AGENT] + svc.notify_window_s
    finally:
        svc._timer[1].cancel()


def test_a_settled_requests_page_is_dropped_from_the_notifier_store(tmp_path):
    sent = []
    svc = _quota_svc(tmp_path, Clock(), notifier=_notifier(sent))
    rid = _restart(svc)
    assert svc.notifier.store.get(f"notify/broker-approval-{rid}") is not None
    svc.deny(rid, APPROVER)
    assert svc.notifier.store.get(f"notify/broker-approval-{rid}") is None


def test_a_failed_page_does_not_silence_the_actors_next_requests(tmp_path):
    """The window was taken before the send: one failed send (an ntfy blip) silenced every page
    of that actor for the whole window."""
    sent = []
    clock = Clock()
    svc = _quota_svc(tmp_path, clock, notifier=_notifier(sent))
    real, calls = svc.notifier.sender.send, []

    def flaky(message):
        calls.append(message)
        if len(calls) == 1:
            raise RuntimeError("ntfy down")
        real(message)

    svc.notifier.sender.send = flaky
    a = _restart(svc)
    clock.advance(10)
    b = _restart(svc)
    assert sent == [], "a failed send is retried after PAGE_RETRY_S, not on every request"
    clock.advance(60)
    svc.pending()
    [page] = sent
    assert b in page.body and a in page.body, "the page names every request still waiting"


def test_a_failing_notifier_never_fails_the_operation(tmp_path):
    class Broken:
        def register_pair(self, *a):
            pass

        def report(self, *a):
            raise RuntimeError("send failed")

    svc = _svc(tmp_path, notifier=Broken())
    rid = _restart(svc)
    assert svc.status(AGENT, rid).state == "pending"
    assert _audit_ok(svc)[1]["reason"] == "notify-failed"


def test_shadow_mode_decides_and_runs_nothing(tmp_path):
    manifest, docs = load_manifest(EXAMPLE)
    manifest["mode"] = "shadow"
    svc = BrokerService(
        tmp_path / "state",
        manifest,
        handler_docs=docs,
        base_dir=EXAMPLE.parent,
        data_root=tmp_path / "data",
        clock=Clock(),
    )
    out = svc.call(AGENT, "memory.write", {"name": "a.md", "content": "x"})
    assert out["shadow"] is True and out["decision"]["enforced"] is False
    assert not (tmp_path / "data").exists()
    rid = svc.submit(AGENT, "memory.write", {"name": "a.md", "content": "x"})
    assert svc.run(AGENT, rid)["shadow"] is True
    assert {d["outcome"] for d in _audit_ok(svc) if d["operation"] in ("call", "run")} == {"shadow"}


# -- in-process commands and secrets --------------------------------------------------------------


def test_secret_arguments_never_reach_disk(tmp_path):
    svc = BrokerService(tmp_path / "state", clock=Clock())
    secret = "fake-opaque-value-1a2b"
    svc.register(
        "ops.login", lambda **kw: "ok", {"user": ArgSpec("str"), "pw": ArgSpec("str", secret=True)}
    )
    svc.allow("ops", ["ops.login"])
    rid = svc.submit("ops", "ops.login", {"user": "svc", "pw": secret})
    assert svc.run("ops", rid) == "ok"
    for p in (tmp_path / "state").rglob("*"):
        if p.is_file():
            assert secret not in p.read_text(), p
    # another process over the same state does not hold the value: it refuses rather than run
    # the command with a placeholder
    rid2 = svc.submit("ops", "ops.login", {"user": "svc", "pw": secret})
    other = BrokerService(tmp_path / "state", clock=Clock())
    other.register(
        "ops.login", lambda **kw: "ok", {"user": ArgSpec("str"), "pw": ArgSpec("str", secret=True)}
    )
    other.allow("ops", ["ops.login"])
    with pytest.raises(BrokerError) as info:
        other.run("ops", rid2)
    assert info.value.reason == "secret-args-lost"


def test_submit_keeps_the_arguments_it_checked(tmp_path):
    """The mapping a caller passed to submit is copied before it is checked: changing it
    afterwards changes nothing that runs."""
    svc = BrokerService(tmp_path / "state", clock=Clock())
    got = []
    svc.register("ops.echo", lambda **kw: got.append(kw) or "ok", {"name": ArgSpec("str")})
    svc.allow("ops", ["ops.echo"])
    given = {"name": "x"}
    rid = svc.submit("ops", "ops.echo", given)
    given["name"] = 5
    given["extra"] = "--force"
    assert svc.run("ops", rid) == "ok"
    assert got == [{"name": "x"}], got


def test_registering_over_a_manifest_action_is_refused(tmp_path):
    svc = _svc(tmp_path)
    with pytest.raises(ValueError):
        svc.register("memory.write", lambda **kw: None, {})


def test_foreign_and_malformed_request_ids_look_unknown(tmp_path):
    svc = _svc(tmp_path)
    rid = svc.submit(AGENT, "memory.write", {"name": "a.md", "content": "x"})
    for bad in ("../requests/x", "REQ", rid):
        with pytest.raises(Denied) as info:
            svc.status("profile:reader", bad)
        assert info.value.reason == "not-request-owner"
    assert svc.status("Profile:Triage", rid).state == "pending", "owner compared normalized"


def test_audit_filters(tmp_path):
    svc = _svc(tmp_path)
    svc.call(AGENT, "memory.write", {"name": "a.md", "content": "x"})
    with pytest.raises(Denied):
        svc.call("profile:reader", "memory.write", {"name": "a.md", "content": "x"})
    assert len(svc.audit_documents(outcome="denied")) == 1
    assert len(svc.audit_documents(caller=AGENT, outcome=None)) == 2  # started, ok
    assert [r.outcome for r in svc.audit()] == ["ok", "denied"]


# -- durable state --------------------------------------------------------------------------------


def test_write_exclusive_never_overwrites(tmp_path):
    p = tmp_path / "a.json"
    assert write_exclusive(p, b"one") is True
    assert write_exclusive(p, b"two") is False
    assert p.read_bytes() == b"one" and [x.name for x in tmp_path.iterdir()] == ["a.json"]


def test_state_dir_refuses_symlinked_subdirs_and_bad_ids(tmp_path):
    from homelabnext.broker.state import StateError

    (tmp_path / "s").mkdir()
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "s" / "audit").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(StateError):
        StateDir(tmp_path / "s")
    st = StateDir(tmp_path / "ok")
    assert st.get_request("../x") is None and st.approvals("../x") == []
    with pytest.raises(StateError):
        st.put_request("../x", {})
    with pytest.raises(StateError):
        FileApprovalStore(tmp_path / "c").consume("../x")
    with pytest.raises(StateError):
        st.put_outbox({"id": "../x"})
    assert not is_id("a" * 65) and is_id("req-1")


def _consume_worker(directory, approval_id, barrier, results):
    barrier.wait()
    results.put(FileApprovalStore(directory).consume(approval_id))


def test_racing_processes_consume_one_approval_exactly_once(tmp_path):
    ctx = multiprocessing.get_context("fork")
    n = 6
    barrier, results = ctx.Barrier(n), ctx.Queue()
    procs = [
        ctx.Process(target=_consume_worker, args=(tmp_path, "appr-race", barrier, results))
        for _ in range(n)
    ]
    for p in procs:
        p.start()
    got = [results.get(timeout=30) for _ in range(n)]
    for p in procs:
        p.join(timeout=30)
    assert sorted(got) == [False] * (n - 1) + [True]
    assert FileApprovalStore(tmp_path).consumed("appr-race")


def _run_worker(tmp, rid, barrier, results):
    svc = BrokerService.from_manifest(
        EXAMPLE,
        Path(tmp) / "state",
        data_root=Path(tmp) / "data",
        clock=Clock(T0 + timedelta(seconds=30)),
        resolve_secret={"DEMO_API_TOKEN": TOKEN}.__getitem__,
    )
    barrier.wait()
    try:
        svc.run(AGENT, rid)
        results.put("ok")
    except BrokerError as exc:
        results.put(getattr(exc, "reason", "error"))


@pytest.mark.parametrize("action", ["memory.write", "service.restart"])
def test_racing_processes_run_one_request_exactly_once(tmp_path, action):
    svc = _svc(tmp_path)
    if action == "memory.write":
        rid = svc.submit(AGENT, action, {"name": "race.md", "content": "x"})
    else:
        rid = _restart(svc)
        svc.approve(rid, APPROVER)
    ctx = multiprocessing.get_context("fork")
    n = 4
    barrier, results = ctx.Barrier(n), ctx.Queue()
    procs = [
        ctx.Process(target=_run_worker, args=(tmp_path, rid, barrier, results)) for _ in range(n)
    ]
    for p in procs:
        p.start()
    got = [results.get(timeout=60) for _ in range(n)]
    for p in procs:
        p.join(timeout=60)
    assert got.count("ok") == 1, got
    assert set(got) - {"ok"} <= {"not-pending", "approval-replayed"}, got
    runs = [
        d for d in svc.state.audit_records() if d["operation"] == "run" and d["outcome"] == "ok"
    ]
    assert len(runs) == 1


def test_request_documents_validate(tmp_path):
    svc = _svc(tmp_path)
    rid = _restart(svc)
    req = svc.state.get_request(rid)["request"]
    assert schema_errors("broker", "request", req) == []
    assert req["digest"] == request_digest(req)


def test_recent_decisions_read_the_decisions_index_not_the_trail(tmp_path, monkeypatch):
    """The hub's recent approve/deny query walked the whole audit trail newest first until it
    found its rows, so a trail an agent filled with refusals made the Approvals page time out."""
    svc = _svc(tmp_path)
    rids = [svc.submit(AGENT, "service.restart", {"grace_s": 5}) for _ in range(3)]
    svc.approve(rids[0], "sso:operator-one")
    svc.deny(rids[1], "sso:operator-one")
    for i in range(30):  # the noise: refusals far outnumber decisions
        with pytest.raises(Denied):
            svc.call(AGENT, f"nope.{i}", {})

    def no_trail(**kw):
        raise AssertionError("the decisions query read the whole audit trail")

    monkeypatch.setattr(svc.state, "audit_records", no_trail)
    [appr] = svc.audit_documents(operation="approve", outcome="ok", limit=20)
    [deny] = svc.audit_documents(operation="deny", outcome="ok", limit=20)
    assert (appr["request_id"], deny["request_id"]) == (rids[0], rids[1])
    assert svc.audit_documents(request_id=rids[0], operation="approve", outcome="ok", limit=50)
    monkeypatch.undo()
    # a state directory from before the index gets it built once, from the trail
    shutil.rmtree(tmp_path / "state" / "decisions")
    again = BrokerService.from_manifest(EXAMPLE, tmp_path / "state")
    assert [r["request_id"] for r in again.state.decision_records()] == rids[:2]
    refused = again.audit_documents(operation="approve", outcome="denied")
    assert refused == [], "only filed decisions are indexed; other queries read the trail"


def _decision(i: int) -> dict:
    return {"operation": "approve", "outcome": "ok", "request_id": f"r{i}"}


def test_a_decision_whose_index_write_was_lost_is_reindexed_on_start(tmp_path, monkeypatch):
    """The index file is written after the audit record; a crash between the two left the
    decision out of decisions/ for good, because only a missing directory triggered a rebuild."""
    from homelabnext.broker import state as state_mod

    st = state_mod.StateDir(tmp_path / "s")
    for i in range(5):
        st.append_audit(_decision(i), f"2026-01-01T00:00:0{i}Z")
    newest = sorted((tmp_path / "s" / "decisions").glob("*.json"))[-1]
    newest.unlink()  # the crash
    monkeypatch.setattr(state_mod, "RECONCILE_AUDIT", 2)
    again = state_mod.StateDir(tmp_path / "s")
    assert [r["request_id"] for r in again.decision_records()] == [f"r{i}" for i in range(5)]


def test_an_interrupted_rebuild_of_the_decisions_index_runs_again(tmp_path, monkeypatch):
    from homelabnext.broker import state as state_mod

    st = state_mod.StateDir(tmp_path / "s")
    for i in range(6):
        st.append_audit(_decision(i), f"2026-01-01T00:00:0{i}Z")
    shutil.rmtree(tmp_path / "s" / "decisions")
    (tmp_path / "s" / state_mod.DECISIONS_COMPLETE).unlink()  # a state dir from before the index
    monkeypatch.setattr(state_mod, "write_exclusive", _fail_after(state_mod.write_exclusive, 2))
    with pytest.raises(OSError):  # the rebuild dies part-way
        state_mod.StateDir(tmp_path / "s")
    monkeypatch.undo()
    monkeypatch.setattr(state_mod, "RECONCILE_AUDIT", 1)  # only a full rebuild can fill the gap
    again = state_mod.StateDir(tmp_path / "s")
    assert [r["request_id"] for r in again.decision_records()] == [f"r{i}" for i in range(6)]
    assert (tmp_path / "s" / state_mod.DECISIONS_COMPLETE).is_file()


def _fail_after(real, n):
    calls = {"n": 0}

    def wrapped(path, data, **kw):
        if path.parent.name == "decisions":
            calls["n"] += 1
            if calls["n"] > n:
                raise OSError("disk full")
        return real(path, data, **kw)

    return wrapped


@pytest.mark.parametrize(
    "who,approver,tier",
    [
        (APPROVER, None, "human"),
        (
            "svc:auto-approver",
            {"issuer": "svc", "subject": "auto-approver", "kind": "agent"},
            "agent",
        ),
    ],
)
def test_decision_returned_names_who_approved(tmp_path, who, approver, tier):
    """decision.returned said tier_used human for every approval, an agent's under
    allow_agent_approvers included, so StackStorm's A03 (which acts on human only) ran what an
    agent approved.  An agent approver now emits tier_used agent."""
    import yaml

    path = _copy_example(tmp_path)
    doc = yaml.safe_load(path.read_text())
    if approver is not None:
        doc["approvers"].append(approver)
        doc["allow_agent_approvers"] = True
    path.write_text(yaml.safe_dump(doc, sort_keys=False))
    clock = Clock()
    svc = BrokerService.from_manifest(
        path, tmp_path / "state", data_root=tmp_path / "data", clock=clock,
        resolve_secret={"DEMO_API_TOKEN": TOKEN}.__getitem__,
    )  # fmt: skip
    rid = _restart(svc)
    clock.advance(30)
    svc.approve(rid, who)
    [returned] = [e for e in svc.state.outbox() if e["type"] == "homelabnext.decision.returned"]
    assert returned["data"]["tier_used"] == tier and returned["data"]["verdict"] == "accept"
    assert event_problems(returned) == []
    assert svc.run(AGENT, rid)["output"]["would_restart"] == "svc:queue"  # it still counts


# -- audit before execute: an action never runs without a record of it ---------------------------


def _full_disk(svc, monkeypatch, *outcomes, results=False):
    """Make the audit trail (and, with ``results``, the result files) unwritable for records of
    ``outcomes``, as a full disk would."""
    import errno

    real = svc.state.append_audit

    def append(record, stamp):
        if record["outcome"] in outcomes:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(record, stamp)

    monkeypatch.setattr(svc.state, "append_audit", append)
    if results:

        def put_result(rid, doc):
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(svc.state, "put_result", put_result)


def _memory(tmp_path):
    return sorted(p.name for p in (tmp_path / "data").rglob("*.md"))


def test_a_call_whose_started_record_cannot_be_written_never_runs(tmp_path, monkeypatch):
    """With the trail unwritable (a full disk), the lane write ran first and its "ok" record then
    failed: the side effect happened and the trail had no record of it."""
    svc = _svc(tmp_path)
    _full_disk(svc, monkeypatch, "started")
    with pytest.raises(BrokerError) as info:
        svc.call(AGENT, "memory.write", {"name": "a.md", "content": "x"})
    assert info.value.reason == "audit-unavailable"
    assert _memory(tmp_path) == [], "the action ran without a record"


def test_every_executed_call_has_a_started_record(tmp_path, monkeypatch):
    svc = _svc(tmp_path)
    svc.call(AGENT, "memory.write", {"name": "a.md", "content": "x"})
    started, ok = (svc.audit_documents(action="memory.write", outcome=o) for o in ("started", "ok"))
    assert len(started) == len(ok) == 1 and started[0]["at"] <= ok[0]["at"]
    assert started[0]["request_id"] == ok[0]["request_id"]
    assert _audit_ok(svc)
    assert [r.outcome for r in svc.audit()] == ["ok"], "the contract view: one record per call"
    # the outcome record fails after the write: the started record is the evidence it ran
    _full_disk(svc, monkeypatch, "ok")
    with pytest.raises(BrokerError) as info:
        svc.call(AGENT, "memory.write", {"name": "b.md", "content": "x"})
    assert info.value.reason == "audit-incomplete"
    assert _memory(tmp_path) == ["a.md", "b.md"]
    assert len(svc.audit_documents(action="memory.write", outcome="started")) == 2


def test_a_run_that_cannot_audit_its_start_changes_nothing(tmp_path, monkeypatch):
    svc = _svc(tmp_path)
    rid = _restart(svc)
    appr = svc.approve(rid, APPROVER)
    with monkeypatch.context() as m:
        _full_disk(svc, m, "started")
        with pytest.raises(BrokerError) as info:
            svc.run(AGENT, rid)
    assert info.value.reason == "audit-unavailable"
    assert svc.status(AGENT, rid).state == "pending"
    assert not svc.approvals.consumed(appr["approval_id"]), "the approval was burnt"
    svc.run(AGENT, rid)  # once the disk is back, the same approval runs it
    assert svc.status(AGENT, rid).state == "done"


def test_a_run_whose_outcome_cannot_be_audited_ends_in_error_not_running(tmp_path, monkeypatch):
    svc = _svc(tmp_path)
    rid = _restart(svc)
    svc.approve(rid, APPROVER)
    _full_disk(svc, monkeypatch, "ok")
    with pytest.raises(BrokerError) as info:
        svc.run(AGENT, rid)
    assert info.value.reason == "audit-incomplete"
    assert svc.state.state_of(rid) == "error"
    assert svc.state.get_result(rid)["reason"] == "audit-incomplete"


def test_a_run_that_can_record_nothing_reads_interrupted(tmp_path, monkeypatch):
    svc = _svc(tmp_path)
    rid = _restart(svc)
    svc.approve(rid, APPROVER)
    _full_disk(svc, monkeypatch, "ok", "error", results=True)
    with pytest.raises(BrokerError) as info:
        svc.run(AGENT, rid)
    assert info.value.reason == "audit-incomplete"
    assert svc.state.state_of(rid) == "interrupted", "not 'running' forever"


def test_a_run_whose_process_died_reads_interrupted(tmp_path):
    import subprocess
    import sys

    svc = _svc(tmp_path)
    rid = _restart(svc)
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()  # a pid that no longer runs
    assert svc.state.claim(rid, {"op": "run", "by": AGENT, "at": "2026-01-15T10:00:00Z",
                                 "pid": child.pid})  # fmt: skip
    assert StateDir(tmp_path / "state").state_of(rid) == "interrupted"
    alive = _restart(svc)
    svc.state.claim(alive, {"op": "run", "by": AGENT, "at": "2026-01-15T10:00:00Z", "pid": 1})
    assert svc.state.state_of(alive) == "running"


def test_an_io_error_inside_an_approved_run_ends_it_in_error(tmp_path, monkeypatch):
    """An OSError on the way to the handler (ENOSPC writing its copy, EMFILE) left the claimed
    run reading running until the broker restarted, with no outcome record."""
    import errno

    from homelabnext.broker import service as service_mod

    def enospc(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")

    svc = _svc(tmp_path)
    rid = _restart(svc)
    svc.approve(rid, APPROVER)
    with monkeypatch.context() as m:
        m.setattr(service_mod._exec, "run_handler", enospc)
        with pytest.raises(BrokerError) as info:
            svc.run(AGENT, rid)
    assert info.value.reason == "handler-io-error"
    assert svc.state.state_of(rid) == "error"
    assert svc.state.get_result(rid)["reason"] == "handler-io-error"
    outcomes = [(r["operation"], r["outcome"]) for r in svc.audit_documents(request_id=rid)]
    assert outcomes[-2:] == [("run", "started"), ("run", "error")]
    _audit_ok(svc)


def test_any_exception_inside_a_run_still_records_how_it_ended(tmp_path, monkeypatch):
    svc = _svc(tmp_path)
    rid = _restart(svc)
    svc.approve(rid, APPROVER)

    def boom(*a, **k):
        raise RuntimeError("a bug")

    monkeypatch.setattr(svc, "_execute", boom)
    with pytest.raises(RuntimeError):
        svc.run(AGENT, rid)
    assert svc.state.get_result(rid) == {
        "state": "error",
        "at": "2026-01-15T10:00:00Z",
        "reason": "internal-error",
    }


def test_a_filed_proposal_whose_event_cannot_be_queued_is_still_filed(tmp_path, monkeypatch):
    import errno

    svc = _svc(tmp_path)

    def enospc(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(svc.state, "put_outbox", enospc)
    note = {"title": "t", "risk": "low", "rollback": "r", "type": "proposal"}
    out = svc.call(AGENT, "proposal.file", {"note": note, "body": "x"})
    assert (tmp_path / "data" / out["path"]).is_file()
    assert [r["outcome"] for r in svc.audit_documents(action="proposal.file")] == [
        "started",
        "error",
        "ok",
    ]
    assert svc.audit_documents(reason="outbox-failed")


def test_a_run_claim_names_its_process_beyond_the_pid(tmp_path):
    """A claim held only the pid: a dead earlier broker whose pid came back (pid 1 again in a
    container) read running forever, and a reader in another PID namespace saw a live run as
    interrupted."""
    from homelabnext.broker.state import process_identity

    svc = _svc(tmp_path)
    me = process_identity()
    assert {"pid", "pid_start", "boot_id", "pid_ns", "host"} <= set(me)

    def claimed(**over):
        rid = _restart(svc)
        doc = {"op": "run", "by": AGENT, "at": "2026-01-15T10:00:00Z", **me, **over}
        assert svc.state.claim(rid, doc)
        return svc.state.state_of(rid)

    assert claimed() == "running", "this very process"
    assert claimed(pid_start="1") == "interrupted", "this pid, an earlier process"
    assert claimed(boot_id="00000000-0000-4000-8000-000000000000") == "interrupted"
    assert claimed(host="elsewhere.example", pid_start="1") == "running", "cannot be judged"
    assert claimed(pid_ns="1", pid_start="1") == "running", "another PID namespace"
    rid = _restart(svc)
    svc.approve(rid, APPROVER)
    svc.run(AGENT, rid)
    claim = svc.state.get_claim(rid)
    assert (claim["pid_start"], claim["boot_id"]) == (me["pid_start"], me["boot_id"])


def test_a_claim_is_judged_by_its_brokers_instance_lock(tmp_path):
    """A claim judged by pid, host and PID namespace read running forever after a container
    restart (a new namespace, a new hostname) and the answer hung on which namespace inode the
    kernel handed out.  The claimant's instance lock answers it on any namespace."""
    import os
    import subprocess
    import sys

    svc = _svc(tmp_path)
    state = tmp_path / "state"
    code = (
        "import sys, time; from homelabnext.broker.state import StateDir;"
        "print(StateDir(sys.argv[1]).instance_id(), flush=True); time.sleep(float(sys.argv[2]))"
    )

    def broker(seconds):
        env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(ROOT), *sys.path])}
        return subprocess.Popen([sys.executable, "-c", code, str(state), str(seconds)],
                                stdout=subprocess.PIPE, text=True, env=env)  # fmt: skip

    def claimed(instance):
        rid = _restart(svc)
        doc = {"op": "run", "by": AGENT, "at": "2026-01-15T10:00:00Z", "instance": instance,
               "pid": 1, "pid_start": "1", "host": "another-container", "pid_ns": "7"}  # fmt: skip
        assert svc.state.claim(rid, doc)
        return rid

    live = broker(60)
    try:
        held = claimed(live.stdout.readline().strip())
        assert svc.state.state_of(held) == "running", "its broker still holds the lock"
        gone_proc = broker(0)
        gone = claimed(gone_proc.stdout.readline().strip())
        gone_proc.wait()
        assert svc.state.state_of(gone) == "interrupted", "its broker is gone, whatever its pid"
    finally:
        live.kill()
        live.wait()
    assert StateDir(state).state_of(held) == "interrupted"
    rid = _restart(svc)
    svc.approve(rid, APPROVER)
    svc.run(AGENT, rid)
    assert svc.state.get_claim(rid)["instance"] == svc.state.instance_id()


def test_a_sweep_by_another_broker_cannot_unlink_a_starting_instance(tmp_path, monkeypatch):
    """A second broker's sweep landing between the create of live/<id> and its flock judged the
    file gone and unlinked it: the live broker then held a lock nobody could find, and its
    claims read interrupted."""
    import fcntl

    from homelabnext.broker import state as state_mod

    d = tmp_path / "state"
    starting, other = StateDir(d), StateDir(d)
    real, fired = fcntl.flock, []

    def racing(fd, op):
        if op == fcntl.LOCK_EX and not fired:
            fired.append(1)
            other._sweep_live(d / "live")  # the other broker's first claim, at the worst moment
        return real(fd, op)

    monkeypatch.setattr(state_mod.fcntl, "flock", racing)
    iid = starting.instance_id()
    monkeypatch.setattr(state_mod.fcntl, "flock", real)
    assert fired and (d / "live" / iid).is_file()
    assert StateDir(d)._claimant_alive({"instance": iid}) is True
    assert not list((d / "live").glob(".new-*")), "no temporary name is left behind"


def test_an_abandoned_instance_temp_file_is_swept_once_stale(tmp_path):
    import os

    d = tmp_path / "state"
    live = d / "live"
    live.mkdir(parents=True)
    old, fresh = live / ".new-brk-0000000000000001", live / ".new-brk-0000000000000002"
    for p in (old, fresh):
        p.write_text("")
    now = fresh.stat().st_mtime + 5
    os.utime(old, (now - 3600, now - 3600))
    StateDir(d)._sweep_live(live, now=now)
    assert not old.exists() and fresh.exists(), "a recent one may be mid-create"


def test_the_page_heap_holds_one_entry_per_time_and_a_stale_timer_keeps_the_new_one(tmp_path):
    sent = []
    clock = Clock()
    svc = _quota_svc(tmp_path, clock, notifier=_notifier(sent))
    svc.page_timers = False
    for _ in range(5):
        svc._wake_at(1000.0)
    assert svc._wakeups.count(1000.0) == 1
    import threading

    old, new = threading.Timer(60, lambda: None), threading.Timer(60, lambda: None)
    svc._timer = (2000.0, new)
    svc._timer_fired(old)  # a timer replaced since it was armed fires late
    assert svc._timer == (2000.0, new), "the armed timer is not forgotten"
    svc._timer_fired(new)
    assert svc._timer is None


# -- single use: run consumes its approval exactly once ------------------------------------------


def test_a_run_consumes_its_approval_in_the_durable_store(tmp_path):
    svc = _svc(tmp_path)
    rid = _restart(svc)
    appr = svc.approve(rid, APPROVER)
    assert not svc.approvals.consumed(appr["approval_id"])
    svc.run(AGENT, rid)
    assert svc.approvals.consumed(appr["approval_id"])
    durable = FileApprovalStore(tmp_path / "state" / "consumed")  # what another process sees
    assert durable.consumed(appr["approval_id"])
    assert svc.approval_state(rid, svc.state.get_request(rid)["request"]) == "consumed"


def test_a_run_whose_approval_was_consumed_elsewhere_is_refused(tmp_path, monkeypatch):
    """The approval-replayed refusal (an approval used outside this request's run, between the
    decision and the claim) was never executed by any test, so a run that ignored consume()'s
    answer, or never called it, passed the whole suite."""
    svc = _svc(tmp_path)
    rid = _restart(svc)
    appr = svc.approve(rid, APPROVER)
    consumed = []
    real = svc.approvals.consume

    def consume_elsewhere(aid):
        consumed.append(aid)
        real(aid)  # another process took it first
        return real(aid)  # so this one gets False

    monkeypatch.setattr(svc.approvals, "consume", consume_elsewhere)
    with pytest.raises(Denied) as info:
        svc.run(AGENT, rid)
    assert info.value.reason == "approval-replayed"
    assert consumed == [appr["approval_id"]], "consumed exactly once, after the claim"
    assert svc.state.get_result(rid)["reason"] == "approval-replayed"
    assert svc.state.state_of(rid) == "error"
    [rec] = svc.audit_documents(reason="approval-replayed")
    assert (rec["operation"], rec["outcome"], rec["approval_id"]) == (
        "run", "denied", appr["approval_id"],
    )  # fmt: skip
    assert not svc.audit_documents(action="service.restart", outcome="ok", operation="run")
    with pytest.raises(BrokerError) as again:
        svc.run(AGENT, rid)
    assert again.value.reason == "not-pending"


# -- handler containment: a handler that resolves outside the base never runs --------------------


def test_a_handler_symlinked_outside_the_base_fails_validation(tmp_path):
    path = _copy_example(tmp_path)
    handler = path.parent / "handlers" / "service-status.sh"
    outside = tmp_path / "outside.sh"
    shutil.copy2(handler, outside)  # identical bytes: the digest still matches
    handler.unlink()
    handler.symlink_to(outside)
    problems = validate_manifest(load_yaml(path), path.parent)[1]
    assert any("service-status.sh is missing or outside" in p for p in problems), problems


def test_a_handler_swapped_for_a_symlink_after_load_is_refused_at_run(tmp_path):
    path = _copy_example(tmp_path)
    svc = BrokerService.from_manifest(
        path, tmp_path / "state", data_root=tmp_path / "data", clock=Clock(),
        resolve_secret={"DEMO_API_TOKEN": TOKEN}.__getitem__,
    )  # fmt: skip
    handler = path.parent / "handlers" / "service-restart.sh"
    outside = tmp_path / "outside.sh"
    shutil.copy2(handler, outside)
    handler.unlink()
    handler.symlink_to(outside)
    rid = _restart(svc)
    svc.approve(rid, APPROVER)
    with pytest.raises(Denied) as info:
        svc.run(AGENT, rid)
    assert info.value.reason == "handler-path-escape"
    assert svc.audit_documents(reason="handler-path-escape")
