# SPDX-License-Identifier: Apache-2.0
"""End to end: swap between two fake lakes. Run 1 rolls back; run 2 goes through to decommission."""

from __future__ import annotations

import json

import lakes
import pytest
from scenario import AFTER, Scenario
from support import check_example

from homelabnext.swap import GateFailed, RollbackRefused, SwapError, record, retired_from_record
from homelabnext.swap.flip import load_doc


def doc_of(sc: Scenario) -> dict:
    return json.loads(sc.runner.path.read_text(encoding="utf-8"))


def test_shadow_parity_flip_rollback(tmp_path):
    sc = Scenario(tmp_path)
    sc.run_to_cutover()
    d = doc_of(sc)
    assert d["current_step"] == "rollback-window" and d["route"]["flipped"] is True
    flipped = load_doc(sc.registry.read_text(encoding="utf-8"))["services"]["lake-query"]
    assert (flipped["host"], flipped["impl"]) == (AFTER["host"], AFTER["impl"])
    assert sc.backend.old_state().data["state"] == "stopped"

    # the cutover holds: new writes land on the candidate; the stopped incumbent is parked
    sc.backend.writer.write_batch(
        "dns_activity",
        [dict(lakes.rows_for("dns_activity")[0], uid="after-flip")],
        idempotency_key="after-flip",
    )
    assert sc.backend.writer.status()["pending"] == 1

    sc.clock.advance(hours=5)
    sc.runner.rollback("canary latency regression observed on the candidate")
    d = doc_of(sc)
    assert d["status"] == "rolled_back" and d["current_step"] is None
    assert d["route"]["flipped"] is False and d["rollback"]["restored_route"] is True
    assert d["rollback"]["from_step"] == "rollback-window"
    assert sc.registry.read_text(encoding="utf-8") == sc.original_registry  # byte-identical
    assert sc.backend.old_state().data["state"] == "running"
    # nothing written after the flip was lost: the parked batch was replayed into the incumbent
    assert sc.backend.writer.status()["pending"] == 0
    assert record.problems(d) == []
    assert record.verify_evidence(d, sc.runner.evidence_dir) == []
    with pytest.raises(SwapError):
        sc.runner.advance()
    check_example("rolled-back", record.dumps(d))


def test_full_swap_to_decommission_and_close(tmp_path):
    sc = Scenario(tmp_path)
    sc.run_to_cutover()
    sc.clock.advance(hours=73)
    sc.runner.advance()  # rollback-window
    assert sc.backend.mirroring is False

    sc.leave_stale_references()
    with pytest.raises(GateFailed):
        sc.runner.advance()  # decommission-check refuses: references remain
    ev = json.loads((sc.runner.evidence_dir / "decommission-check.01.json").read_text())
    kinds = {f["kind"] for f in ev["details"]["scan"]["data"]["findings"]}
    assert {"unit-file", "env-var", "doc"} <= kinds
    d = doc_of(sc)
    assert d["current_step"] == "decommission-check"
    assert d["steps"][7]["status"] == "failed"
    assert d["transitions"][-1]["event"] == "gate-failed"
    with pytest.raises(GateFailed):  # cannot skip ahead: still the same step, still refused
        sc.runner.advance()

    sc.clean_references()
    sc.runner.advance()  # decommission-check passes
    with pytest.raises(RollbackRefused):
        sc.runner.rollback("trying to undo after the old component is gone")

    with pytest.raises(GateFailed):
        sc.runner.advance()  # close needs an ADR reference
    sc.runner.advance(closure={"adr_ref": "docs/adr/0005-swap-procedure-and-conformance.md"})
    d = doc_of(sc)
    assert d["status"] == "closed" and d["current_step"] is None and d["route"]["flipped"] is True
    assert [s["status"] for s in d["steps"]] == ["passed"] * 9
    assert record.problems(d) == []
    assert record.verify_evidence(d, sc.runner.evidence_dir) == []
    events = [t["event"] for t in d["transitions"]]
    assert events[0] == "declared" and events[-2:] == ["step-passed", "closed"]
    assert "gate-failed" in events
    # the record alone says which names were retired
    assert retired_from_record(d).impls == ("trino",)
    check_example("closed", record.dumps(d))


def test_synthetic_drift_blocks_the_swap_until_fixed(tmp_path):
    sc = Scenario(tmp_path)
    r = sc.runner
    r.advance()
    r.advance()
    r.advance()
    # a write that bypasses the mirror: the classic dual-write gap
    sc.old.write_batch(
        "dns_activity",
        [dict(lakes.rows_for("dns_activity")[0], uid="gap-1")],
        idempotency_key="gap",
    )
    with pytest.raises(GateFailed) as exc:
        r.advance()
    assert any(g.id == "parity-holds" and not g.passed for g in exc.value.result.gates)
    assert doc_of(sc)["current_step"] == "parity-compare"
    assert sc.registry.read_text(encoding="utf-8") == sc.original_registry  # nothing flipped

    sc.new.write_batch(  # reconcile the gap, retry the same step
        "dns_activity",
        [dict(lakes.rows_for("dns_activity")[0], uid="gap-1")],
        idempotency_key="gap",
    )
    r.advance()
    assert doc_of(sc)["current_step"] == "soak"


def test_soak_and_window_are_enforced(tmp_path):
    sc = Scenario(tmp_path)
    r = sc.runner
    for _ in range(4):
        r.advance()
    with pytest.raises(GateFailed) as exc:
        r.advance()
    assert "still to wait" in exc.value.result.gates[0].detail
    sc.clock.advance(hours=48)
    r.advance()
    r.advance()  # cutover
    with pytest.raises(GateFailed):
        r.advance()  # window not elapsed
    assert doc_of(sc)["route"]["flipped"] is True


def test_active_example_mid_swap(tmp_path):
    sc = Scenario(tmp_path)
    for _ in range(4):
        sc.runner.advance()
    check_example("active", record.dumps(doc_of(sc)))
