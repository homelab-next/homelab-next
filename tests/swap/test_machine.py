# SPDX-License-Identifier: Apache-2.0
"""The state machine against a scripted backend: gates, dry-run, revert, rollback from any step."""

from __future__ import annotations

import json

import pytest
from support import FakeClock

from homelabnext.swap import (
    STEPS,
    Backend,
    GateFailed,
    Outcome,
    RollbackRefused,
    SwapError,
    SwapRunner,
    plan_text,
    record,
)

BEFORE = {"host": "host-a", "port": 8443, "impl": "old"}
AFTER = {"host": "host-b", "port": 8443, "impl": "new"}
ADR = "docs/adr/0005-swap-procedure-and-conformance.md"


class Stub(Backend):
    """Everything passes unless listed in ``fail``; records every call."""

    def __init__(self, fail=(), scan_findings=0):
        self.fail = set(fail)
        self.calls: list[tuple] = []
        self.route = dict(BEFORE)
        self.old = "running"
        self.scan_findings = scan_findings

    def _o(self, name, **data):
        self.calls.append((name,))
        return Outcome(
            name not in self.fail, f"{name} {'ok' if name not in self.fail else 'bad'}", data
        )

    def conformance(self, role):
        return self._o(f"conformance_{role}")

    def shadow_start(self):
        return self._o("shadow_start")

    def start_mirror(self):
        return self._o("start_mirror")

    def mirror_status(self):
        o = self._o("mirror_status", unresolved=3 if "divergent" in self.fail else 0)
        o.ok = "mirror_status" not in self.fail
        return o

    def stop_mirror(self):
        return self._o("stop_mirror")

    def parity(self):
        return self._o("parity", rows_compared=0 if "no_rows" in self.fail else 100)

    def preview_route(self, target):
        return Outcome(True, f"{self.route['host']} -> {target['host']}")

    def apply_route(self, target):
        self.calls.append(("apply_route", target["host"]))
        if "apply" in self.fail:
            return Outcome(False, "registry write failed")
        if "revert" in self.fail and target["host"] == BEFORE["host"]:
            return Outcome(False, "cannot restore")
        self.route = dict(target)
        return Outcome(True, "applied")

    def verify_route(self, target):
        self.calls.append(("verify_route", target["host"]))
        ok = self.route["host"] == target["host"] and "canary" not in self.fail
        return Outcome(ok, "canary " + ("green" if ok else "red"))

    def stop_old(self):
        self.old = "stopped"
        return self._o("stop_old")

    def start_old(self):
        self.old = "running"
        return self._o("start_old")

    def old_state(self):
        return Outcome(True, "", {"state": self.old})

    def decommission_scan(self):
        o = self._o("decommission_scan", findings=[{"x": 1}] * self.scan_findings)
        o.ok = self.scan_findings == 0
        return o


def make(tmp_path, backend=None, clock=None, **plan):
    clock = clock or FakeClock()
    backend = backend or Stub()
    p = {"soak_hours": 24, "rollback_window_hours": 24, "max_divergences": 0, "min_parity_rows": 10}
    p.update(plan)
    r = SwapRunner.create(
        tmp_path / "s.swap.json",
        backend,
        swap_id="swap-test-0001",
        capability="cap:lake-query",
        from_adapter="old-impl",
        to_adapter="new-impl",
        service="lake-query",
        before=BEFORE,
        after=AFTER,
        plan=p,
        clock=clock,
        actor="tester",
    )
    return r, backend, clock


def advance_to(r, clock, step):
    while r.status()["current_step"] != step:
        cur = r.status()["current_step"]
        if cur in ("soak", "rollback-window"):
            clock.advance(hours=25)
        r.advance(closure={"adr_ref": ADR})


def test_created_record_is_valid_and_declared(tmp_path):
    r, *_ = make(tmp_path)
    d = r.record()
    assert d["status"] == "active" and d["current_step"] == "declare"
    assert [t["event"] for t in d["transitions"]] == ["declared"]
    assert record.problems(d) == []
    with pytest.raises(SwapError, match="already exists"):
        make(tmp_path)


def test_happy_path_in_order_with_evidence_per_step(tmp_path):
    r, b, clock = make(tmp_path)
    seen = []
    while r.status()["status"] == "active":
        cur = r.status()["current_step"]
        if cur in ("soak", "rollback-window"):
            clock.advance(hours=25)
        res = r.advance(closure={"adr_ref": ADR, "lesson_ref": "none needed"})
        seen.append(res.step)
    assert seen == list(STEPS)
    d = r.record()
    assert d["status"] == "closed" and all(s["evidence"] for s in d["steps"])
    assert d["closure"]["lesson_ref"] == "none needed"
    assert record.verify_evidence(d, r.evidence_dir) == []
    assert b.old == "stopped"


def test_failed_gate_refuses_and_retry_runs_the_same_step(tmp_path):
    b = Stub(fail={"conformance_old"})
    r, _, _ = make(tmp_path, b)
    with pytest.raises(GateFailed) as exc:
        r.advance()
    assert exc.value.result.step == "declare"
    d = r.record()
    assert d["current_step"] == "declare" and d["steps"][0]["status"] == "failed"
    assert d["transitions"][-1]["event"] == "gate-failed"
    assert (r.evidence_dir / "declare.01.json").is_file()
    b.fail.clear()
    r.advance()
    d = r.record()
    assert d["current_step"] == "shadow-start" and d["steps"][0]["attempts"] == 2


@pytest.mark.parametrize(
    "fail,step,gate",
    [
        ({"conformance_new"}, "shadow-start", "candidate-conformance"),
        ({"shadow_start"}, "shadow-start", "shadow-started"),
        ({"start_mirror"}, "dual-write", "mirror-running"),
        ({"divergent"}, "dual-write", "divergences-within-budget"),
        ({"parity"}, "parity-compare", "parity-holds"),
        ({"no_rows"}, "parity-compare", "enough-rows"),
    ],
)
def test_each_postcondition_blocks(tmp_path, fail, step, gate):
    b = Stub()
    r, _, clock = make(tmp_path, b)
    advance_to(r, clock, step)
    b.fail |= fail
    with pytest.raises(GateFailed) as exc:
        r.advance()
    assert any(g.id == gate and not g.passed for g in exc.value.result.gates)
    assert r.status()["current_step"] == step


def test_unimplemented_backend_methods_fail_the_gate_not_pass_it(tmp_path):
    r, _, _ = make(tmp_path, Backend())
    with pytest.raises(GateFailed) as exc:
        r.advance()
    assert "does not implement" in str(exc.value)


def test_dry_run_writes_nothing_and_reports_pre_conditions(tmp_path):
    r, b, clock = make(tmp_path)
    before = r.path.read_bytes()
    res = r.advance(dry_run=True)
    assert res.dry_run and res.passed and res.plan
    assert r.path.read_bytes() == before and not r.evidence_dir.exists()
    assert b.calls == []  # a dry run never touches the backend
    advance_to(r, clock, "soak")
    res = r.advance(dry_run=True)
    assert not res.passed and "still to wait" in res.gates[0].detail
    advance_to(r, clock, "soak")
    clock.advance(hours=25)
    r.advance()
    cut = r.advance(dry_run=True)
    assert cut.step == "cutover" and any("host-a -> host-b" in line for line in cut.plan)
    assert r.record()["route"]["flipped"] is False


def test_soak_and_window_use_the_injected_clock(tmp_path):
    r, _, clock = make(tmp_path)
    advance_to(r, clock, "soak")
    clock.advance(hours=23)
    with pytest.raises(GateFailed):
        r.advance()
    clock.advance(hours=1)
    r.advance()
    r.advance()  # cutover
    with pytest.raises(GateFailed):
        r.advance()
    clock.advance(hours=24)
    r.advance()


def test_cutover_canary_failure_reverts_immediately(tmp_path):
    b = Stub()
    r, _, clock = make(tmp_path, b)
    advance_to(r, clock, "cutover")
    b.fail.add("canary")
    with pytest.raises(GateFailed) as exc:
        r.advance()
    assert exc.value.result.reverted
    d = r.record()
    assert d["route"]["flipped"] is False and b.route["host"] == "host-a" and b.old == "running"
    events = [t["event"] for t in d["transitions"]]
    assert events[-2:] == ["cutover-reverted", "gate-failed"]
    b.fail.clear()
    r.advance()  # the retry succeeds
    assert r.record()["route"]["flipped"] is True


def test_cutover_apply_failure_never_flips(tmp_path):
    b = Stub(fail={"apply"})
    r, _, clock = make(tmp_path, b)
    advance_to(r, clock, "cutover")
    with pytest.raises(GateFailed):
        r.advance()
    assert r.record()["route"]["flipped"] is False


def test_failed_revert_is_recorded_as_flipped_and_rollback_fixes_it(tmp_path):
    b = Stub()
    r, _, clock = make(tmp_path, b)
    advance_to(r, clock, "cutover")
    b.fail |= {"canary", "revert"}
    with pytest.raises(GateFailed) as exc:
        r.advance()
    assert any(g.id == "revert" for g in exc.value.result.gates)
    d = r.record()
    assert d["route"]["flipped"] is True and d["steps"][5]["status"] == "failed"
    assert record.problems(d) == []
    b.fail.clear()
    r.rollback("cutover failed and the automatic revert also failed")
    assert b.route["host"] == "host-a" and r.record()["status"] == "rolled_back"


@pytest.mark.parametrize("stop_at", STEPS[:8])
def test_rollback_from_every_step_before_decommission(tmp_path, stop_at):
    b = Stub()
    r, _, clock = make(tmp_path, b)
    advance_to(r, clock, stop_at)
    flipped = r.record()["route"]["flipped"]
    d = r.rollback("rolling back to test the procedure from " + stop_at)
    assert d["status"] == "rolled_back" and d["rollback"]["from_step"] == stop_at
    assert d["rollback"]["restored_route"] is flipped
    assert b.route["host"] == "host-a" and b.old == "running"
    assert d["route"]["flipped"] is False
    assert record.problems(d) == []
    assert d["transitions"][-1]["event"] == "rolled-back"
    with pytest.raises(SwapError):
        r.advance()
    with pytest.raises(RollbackRefused):
        r.rollback("a second rollback of a finished swap")


def test_rollback_refused_after_decommission_and_without_reason(tmp_path):
    r, _, clock = make(tmp_path)
    with pytest.raises(RollbackRefused, match="reason"):
        r.rollback("short")
    advance_to(r, clock, "decommission-check")
    r.advance()
    with pytest.raises(RollbackRefused, match="decommission"):
        r.rollback("this is far too late to undo")
    assert r.record()["status"] == "active"


def test_incomplete_rollback_is_recorded_and_retryable(tmp_path):
    b = Stub()
    r, _, clock = make(tmp_path, b)
    advance_to(r, clock, "rollback-window")
    b.fail.add("revert")
    with pytest.raises(SwapError, match="rollback incomplete"):
        r.rollback("route will not restore on the first try")
    d = r.record()
    assert d["status"] == "active" and d["transitions"][-1]["event"] == "note"
    b.fail.clear()
    assert r.rollback("route restores on the second try")["status"] == "rolled_back"


def test_decommission_findings_block_close(tmp_path):
    b = Stub(scan_findings=2)
    r, _, clock = make(tmp_path, b)
    advance_to(r, clock, "decommission-check")
    with pytest.raises(GateFailed):
        r.advance()
    b.scan_findings = 0
    r.advance()
    with pytest.raises(GateFailed, match="adr-reference"):
        r.advance(closure={"adr_ref": "not-an-adr"})
    r.advance(closure={"adr_ref": ADR})
    assert r.record()["status"] == "closed"


def test_notes_and_status_and_plan_text(tmp_path):
    r, *_ = make(tmp_path)
    r.note("operator paused the swap for a freeze window")
    d = r.record()
    assert d["transitions"][-1]["event"] == "note" and record.problems(d) == []
    assert r.status()["steps"]["declare"] == "pending"
    text = plan_text(d)
    for s in STEPS:
        assert s in text
    assert "[pending]" in text


def test_tampering_with_the_record_is_detected(tmp_path):
    r, _, clock = make(tmp_path)
    advance_to(r, clock, "soak")
    d = r.record()
    t = json.loads(json.dumps(d))
    t["transitions"][1]["note"] = "edited after the fact"
    assert any("hash does not match" in p for p in record.problems(t))
    t = json.loads(json.dumps(d))
    del t["transitions"][2]
    assert any("seq" in p or "link" in p for p in record.problems(t))
    t = json.loads(json.dumps(d))
    t["steps"][2]["status"] = "pending"
    assert any("prefix" in p for p in record.problems(t))
    t = json.loads(json.dumps(d))
    t["route"]["flipped"] = True
    assert any("flipped" in p for p in record.problems(t))
    ev = r.evidence_dir / "declare.01.json"
    ev.write_text(ev.read_text() + " ")
    assert any("recorded hash" in p for p in record.verify_evidence(d, r.evidence_dir))
    with pytest.raises(record.RecordError):
        record.save(tmp_path / "bad.json", t)
    assert not (tmp_path / "bad.json").exists()
