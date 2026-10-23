# SPDX-License-Identifier: Apache-2.0
"""End to end: swap between two fake lakes. Run 1 rolls back; run 2 goes through to decommission."""

from __future__ import annotations

import json

import lakes
import pytest
from scenario import AFTER, BEFORE, Scenario
from support import check_example

from homelabnext.lake import LakeError
from homelabnext.swap import (
    GateFailed,
    LakeBackend,
    RollbackRefused,
    SwapError,
    record,
    retired_from_record,
)
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


def _count(lake, uid: str) -> int:
    return lake.query("SELECT count(*) AS n FROM dns_activity WHERE uid = :u", {"u": uid})[0]["n"]


def test_rollback_replays_writes_parked_while_the_old_component_was_stopped(tmp_path):
    # the route flip and the rollback each re-point the writer; the batch parked for the stopped
    # incumbent must survive both and land in the incumbent when it starts again
    sc = Scenario(tmp_path)
    sc.run_to_cutover()
    row = dict(lakes.rows_for("dns_activity")[0], uid="written-while-old-stopped")
    sc.backend.writer.write_batch("dns_activity", [row], idempotency_key="k-during-cutover")
    assert sc.backend.writer.status()["pending"] == 1
    sc.clock.advance(hours=5)
    sc.runner.rollback("canary latency regression observed on the candidate")
    assert _count(sc.old, row["uid"]) == 1  # the incumbent, primary again, holds the write
    assert _count(sc.new, row["uid"]) == 1
    assert sc.backend.writer.status()["pending"] == 0
    assert sc.backend.writer.status()["replayed_ok"] == 1
    actions = doc_of(sc)["rollback"]["actions"]
    assert any("replayed 1 parked batches" in a for a in actions), actions


def test_the_route_is_not_restored_to_a_stopped_old_component_that_is_owed_writes(tmp_path):
    sc = Scenario(tmp_path)
    b = sc.backend
    assert b.shadow_start().ok and b.start_mirror().ok
    assert b.apply_route(AFTER).ok and b.stop_old().ok
    row = dict(lakes.rows_for("dns_activity")[0], uid="parked-for-old")
    b.writer.write_batch("dns_activity", [row], idempotency_key="k-parked")
    refused = b.apply_route(BEFORE)  # old is stopped: the batch owed to it cannot be replayed
    assert not refused.ok and "1 parked batches" in refused.detail
    assert sc.registry.read_text(encoding="utf-8") != sc.original_registry  # still flipped
    assert "replayed 1 parked batches" in b.start_old().detail
    assert b.apply_route(BEFORE).ok
    assert _count(sc.old, row["uid"]) == 1


class _Flaky:
    """A component whose writes can be made to fail (it stays "running")."""

    def __init__(self, inner):
        self.inner, self.down = inner, False

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def write_batch(self, *a, **kw):
        if self.down:
            raise RuntimeError("component unavailable")
        return self.inner.write_batch(*a, **kw)


def test_a_batch_parked_for_the_candidate_is_replayed_before_it_becomes_primary(tmp_path):
    # parked during the mirror, it must land before the candidate takes newer batches as primary,
    # or a later replay moves the lake's source mark backwards
    sc = Scenario(tmp_path)
    b = sc.backend
    assert b.shadow_start().ok and b.start_mirror().ok
    flaky = _Flaky(sc.new)
    b.new = flaky
    b.writer = b.writer.rerouted(b.old, flaky)
    base = lakes.rows_for("dns_activity")[0]
    flaky.down = True
    b.writer.write_batch("dns_activity", [dict(base, uid="r1")], idempotency_key="b1", source="src", high_water="100")  # fmt: skip
    flaky.down = False
    assert b.apply_route(AFTER).ok
    assert b.writer.status()["pending"] == 0 and _count(sc.new, "r1") == 1
    b.writer.write_batch("dns_activity", [dict(base, uid="r2")], idempotency_key="b2", source="src", high_water="200")  # fmt: skip
    assert b.start_old().ok and b.apply_route(BEFORE).ok
    mark = sc.new.describe("dns_activity").committed["src"]
    assert (mark.batch_id, mark.high_water) == ("b2", "200")  # never rewound to b1


def test_the_flip_is_refused_while_a_batch_owed_to_the_candidate_cannot_be_replayed(tmp_path):
    sc = Scenario(tmp_path)
    b = sc.backend
    assert b.shadow_start().ok and b.start_mirror().ok
    flaky = _Flaky(sc.new)
    b.new = flaky
    b.writer = b.writer.rerouted(b.old, flaky)
    flaky.down = True
    b.writer.write_batch("dns_activity", [dict(lakes.rows_for("dns_activity")[0], uid="r1")], idempotency_key="b1")  # fmt: skip
    out = b.apply_route(AFTER)
    assert not out.ok and out.data["pending"] == 1
    assert sc.registry.read_text(encoding="utf-8") == sc.original_registry


def test_start_old_fails_and_says_so_while_a_batch_stays_parked(tmp_path):
    sc = Scenario(tmp_path)
    b = sc.backend
    assert b.shadow_start().ok and b.start_mirror().ok
    assert b.apply_route(AFTER).ok and b.stop_old().ok
    b.writer.write_batch("dns_activity", [dict(lakes.rows_for("dns_activity")[0], uid="p1")], idempotency_key="p1")  # fmt: skip
    b.old._inner = _Flaky(b.old._inner)
    b.old._inner.down = True  # running again, but its writes still fail
    out = b.start_old()
    assert not out.ok and "1 still parked" in out.detail and out.data["pending"] == 1


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


def _with_flaky_candidate(sc):
    b = sc.backend
    assert b.shadow_start().ok and b.start_mirror().ok
    flaky = _Flaky(sc.new)
    b.new = flaky
    b.writer = b.writer.rerouted(b.old, flaky)
    return b, flaky


def test_a_batch_written_between_the_park_and_the_flip_waits_its_turn(tmp_path):
    # b1 parked, the candidate recovers, b2 is mirrored: b2 must not land before b1
    sc = Scenario(tmp_path)
    b, flaky = _with_flaky_candidate(sc)
    base = lakes.rows_for("dns_activity")[0]
    flaky.down = True
    b.writer.write_batch("dns_activity", [dict(base, uid="r1")], idempotency_key="b1", source="src", high_water="100")  # fmt: skip
    flaky.down = False
    b.writer.write_batch("dns_activity", [dict(base, uid="r2")], idempotency_key="b2", source="src", high_water="200")  # fmt: skip
    assert b.writer.status()["pending"] == 0
    assert b.apply_route(AFTER).ok
    mark = sc.new.describe("dns_activity").committed["src"]
    assert (mark.batch_id, mark.high_water) == ("b2", "200")


def test_a_batch_is_parked_behind_older_ones_still_refused(tmp_path):
    sc = Scenario(tmp_path)
    b, flaky = _with_flaky_candidate(sc)
    base = lakes.rows_for("dns_activity")[0]
    flaky.down = True
    for k in ("b1", "b2"):
        b.writer.write_batch("dns_activity", [dict(base, uid=k)], idempotency_key=k, source="src", high_water=k)  # fmt: skip
    assert [p.idempotency_key for p in b.writer.pending] == ["b1", "b2"]
    assert [d.kind for d in b.writer.divergences][-1] == "queued"  # b2 never went past b1
    flaky.down = False
    assert b.mirror_status().data["pending"] == 0  # the status check replays, in order
    assert sc.new.describe("dns_activity").committed["src"].batch_id == "b2"


def test_mirror_status_replays_so_the_divergence_gates_can_clear(tmp_path):
    sc = Scenario(tmp_path)
    b, flaky = _with_flaky_candidate(sc)
    flaky.down = True
    b.writer.write_batch("dns_activity", [dict(lakes.rows_for("dns_activity")[0], uid="m1")], idempotency_key="m1")  # fmt: skip
    assert b.mirror_status().data["unresolved"] == 1
    flaky.down = False
    assert b.mirror_status().data["unresolved"] == 0 and _count(sc.new, "m1") == 1


def _poisoned_rollback_scenario(tmp_path):
    sc = Scenario(tmp_path)
    sc.run_to_cutover()
    b = sc.backend
    row = dict(lakes.rows_for("dns_activity")[0], uid="poison")
    b.writer.write_batch("dns_activity", [row], idempotency_key="k-poison")
    inner = b.old._inner

    class Refuses:
        def __getattr__(self, name):
            return getattr(inner, name)

        def write_batch(self, table, rows, **kw):
            if any(r.get("uid") == "poison" for r in rows):
                raise ValueError("old component refuses this row")
            return inner.write_batch(table, rows, **kw)

    b.old._inner = Refuses()
    sc.clock.advance(hours=5)
    return sc


def test_a_rollback_blocked_by_a_refused_write_leaves_the_old_component_stopped(tmp_path):
    sc = _poisoned_rollback_scenario(tmp_path)
    with pytest.raises(SwapError, match="1 still parked"):
        sc.runner.rollback("canary latency regression observed on the candidate")
    assert sc.backend.old_state().data["state"] == "stopped"
    assert doc_of(sc)["route"]["flipped"] is True
    assert sc.backend.writer.status()["pending"] == 1  # nothing dropped on its own


def _abandon_evidence(sc, d):
    [ev] = [e for s in d["steps"] for e in s["evidence"] if e["kind"] == "abandoned-parked"]
    path = sc.runner.evidence_dir / ev["ref"]
    return json.loads(path.read_text()), path


def test_rollback_abandon_parked_drops_the_refused_writes_into_the_evidence(tmp_path):
    sc = _poisoned_rollback_scenario(tmp_path)
    d = sc.runner.rollback("canary regression; the old lake refuses k-poison", abandon_parked=True)
    assert d["status"] == "rolled_back" and d["route"]["flipped"] is False
    acts = d["rollback"]["actions"]
    assert acts[0].startswith("start old component: FAILED")  # the first, failed attempt
    assert any(a.startswith("abandon parked writes: ok (discarded 1") for a in acts)
    body, path = _abandon_evidence(sc, d)
    [gone] = body["abandoned_parked"]
    assert gone["idempotency_key"] == "k-poison" and gone["rows"][0]["uid"] == "poison"
    assert path.stat().st_mode & 0o777 == 0o600  # it holds rows
    [rb] = [e for s in d["steps"] for e in s["evidence"] if e["kind"] == "rollback"]
    assert (sc.runner.evidence_dir / rb["ref"]).stat().st_mode & 0o777 == 0o600
    assert record.problems(d) == [] and record.verify_evidence(d, sc.runner.evidence_dir) == []
    assert [x.kind for x in sc.backend.writer.divergences][-1] == "discarded"


def test_abandoned_writes_are_evidence_even_when_a_later_step_fails(tmp_path):
    sc = _poisoned_rollback_scenario(tmp_path)
    real = sc.backend.apply_route
    sc.backend.apply_route = lambda target: (_ for _ in ()).throw(OSError("registry write failed"))
    with pytest.raises(SwapError, match="rollback incomplete"):
        sc.runner.rollback("canary regression; the old lake refuses k-poison", abandon_parked=True)
    d = doc_of(sc)
    body, _ = _abandon_evidence(sc, d)
    assert [g["idempotency_key"] for g in body["abandoned_parked"]] == ["k-poison"]
    assert record.problems(d) == [] and record.verify_evidence(d, sc.runner.evidence_dir) == []
    note = d["transitions"][-1]["note"]
    assert note.startswith("rollback incomplete; actions:") and "abandon parked writes: ok" in note
    sc.backend.apply_route = real
    again = sc.runner.rollback("retry after the registry write failed")
    assert again["status"] == "rolled_back"


def test_abandon_drops_only_the_refused_write_and_replays_the_rest(tmp_path):
    sc = _poisoned_rollback_scenario(tmp_path)
    good = dict(lakes.rows_for("dns_activity")[0], uid="good")
    sc.backend.writer.write_batch("dns_activity", [good], idempotency_key="k-good")  # queued
    assert [p.idempotency_key for p in sc.backend.writer.pending] == ["k-poison", "k-good"]
    d = sc.runner.rollback("canary regression; the old lake refuses k-poison", abandon_parked=True)
    body, _ = _abandon_evidence(sc, d)
    assert [g["idempotency_key"] for g in body["abandoned_parked"]] == ["k-poison"]
    assert _count(sc.old, "good") == 1  # the old component, primary again, has the good write


def _backend_like(sc, pending_path):
    return LakeBackend(
        sc.old,
        sc.new,
        tables=list(lakes.TABLES),
        registry_path=sc.registry,
        service="lake-query",
        new_host="lake-core-2",
        pending_path=pending_path,
    )


def _journal_records(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_parked_writes_survive_a_restart_with_direction_and_state(tmp_path):
    sc = Scenario(tmp_path)
    path = tmp_path / "parked.jsonl"
    b = _backend_like(sc, path)
    assert b.shadow_start().ok and b.start_mirror().ok
    assert b.apply_route(AFTER).ok and b.stop_old().ok
    row = dict(lakes.rows_for("dns_activity")[0], uid="kept-across-restart")
    b.writer.write_batch("dns_activity", [row], idempotency_key="k-restart", source="s", high_water="7")  # fmt: skip
    assert path.stat().st_mode & 0o777 == 0o600
    b.close()  # the process ends
    again = _backend_like(sc, path)  # no re-routing by hand: the registry says flipped
    assert again.writer.primary is again.new and again.writer.secondary is again.old
    assert again.old_state().data["state"] == "stopped"
    assert again.writer.owed_to(again.old) == 1
    more = dict(row, uid="after-restart")
    again.writer.write_batch("dns_activity", [more], idempotency_key="k-more", source="s", high_water="8")  # fmt: skip
    assert [p.idempotency_key for p in again.writer.pending] == ["k-restart", "k-more"]
    assert "replayed 2 parked batches" in again.start_old().detail
    assert _count(sc.old, row["uid"]) == 1 and _count(sc.old, more["uid"]) == 1
    mark = sc.old.describe("dns_activity").committed["s"]
    assert (mark.batch_id, mark.high_water) == ("k-more", "8")
    again.close()
    third = _backend_like(sc, path)  # compacted at open: nothing parked, old running
    assert third.writer.pending == [] and third.old_state().data["state"] == "running"
    assert {r["op"] for r in _journal_records(path)} <= {"mark", "old"}  # no park, no settled
    third.close()


def test_the_guard_marks_survive_a_restart(tmp_path):
    sc = Scenario(tmp_path)
    path = tmp_path / "parked.jsonl"
    b = _backend_like(sc, path)
    flaky = _Flaky(sc.new)
    b.new = flaky
    b.writer = b.writer.rerouted(b.old, flaky)
    b.writer.journal.b = b
    flaky.down = True
    b.writer.write_batch("dns_activity", [dict(lakes.rows_for("dns_activity")[0], uid="g1")], idempotency_key="g1", source="s", high_water="1")  # fmt: skip
    b.writer._mark(flaky, "dns_activity", "s", 99)  # a newer batch the candidate took
    b.close()
    marks = [r for r in _journal_records(path) if r["op"] == "mark"]
    assert marks == [
        {"op": "mark", "on": "new", "order": 99, "source": "s", "table": "dns_activity"}
    ]
    again = _backend_like(sc, path)
    assert again.writer._order["marked"][(id(again.new), "dns_activity", "s")] == 99
    assert again.writer._order["n"] >= 99
    again.close()


def test_a_journal_held_by_another_backend_is_refused(tmp_path):
    sc = Scenario(tmp_path)
    path = tmp_path / "parked.jsonl"
    first = _backend_like(sc, path)
    with pytest.raises(LakeError, match="in use by another swap backend"):
        _backend_like(sc, path)
    first.close()
    _backend_like(sc, path).close()  # released


def test_an_unreadable_journal_refuses_to_start_and_a_torn_tail_is_dropped(tmp_path):
    sc = Scenario(tmp_path)
    path = tmp_path / "parked.jsonl"
    path.write_text('{not json\n{"op": "old", "down": false}\n')
    with pytest.raises(LakeError, match="unreadable"):
        _backend_like(sc, path)
    path.write_text('{"op": "old", "down": true}\n{"op": "park", "ord')  # crash mid-append
    b = _backend_like(sc, path)
    assert b.old_state().data["state"] == "stopped" and b.writer.pending == []
    b.close()


def test_stale_temp_files_of_a_crashed_compaction_are_swept(tmp_path):
    sc = Scenario(tmp_path)
    path = tmp_path / "parked.jsonl"
    stale = tmp_path / ".parked.jsonl.999999999.deadbeef.tmp"
    stale.write_text("x")
    _backend_like(sc, path).close()
    assert not stale.exists()


def test_parking_costs_one_record_not_a_rewrite_of_the_queue(tmp_path):
    import time

    sc = Scenario(tmp_path)
    path = tmp_path / "parked.jsonl"
    b = _backend_like(sc, path)
    assert b.apply_route(AFTER).ok and b.stop_old().ok
    batch = [dict(r, uid=f"p-{i}") for i, r in enumerate(lakes.rows_for("dns_activity") * 10)][:50]  # fmt: skip
    t0 = time.perf_counter()
    sizes = []
    for n in range(400):
        b.writer.write_batch("dns_activity", batch, idempotency_key=f"k{n}")
        if n in (199, 399):
            sizes.append(path.stat().st_size)
    elapsed = time.perf_counter() - t0
    assert 1.9 < sizes[1] / sizes[0] < 2.1  # linear in the parks, not quadratic
    assert elapsed < 60, elapsed  # generous: the whole-queue rewrite took minutes at this size
    b.close()


def test_an_abandon_drops_nothing_while_the_old_component_is_unreachable(tmp_path):
    sc = Scenario(tmp_path)
    sc.run_to_cutover()
    b = sc.backend
    for i in range(3):
        b.writer.write_batch("dns_activity", [dict(lakes.rows_for("dns_activity")[0], uid=f"u{i}")], idempotency_key=f"k{i}")  # fmt: skip
    inner = b.old._inner

    class Unreachable:
        def __getattr__(self, name):
            return getattr(inner, name)

        def write_batch(self, *a, **kw):
            raise ConnectionError("old unreachable (transient)")

    b.old._inner = Unreachable()
    sc.clock.advance(hours=5)
    with pytest.raises(SwapError, match="old unreachable"):
        sc.runner.rollback("canary regression; old briefly unreachable", abandon_parked=True)
    assert [p.idempotency_key for p in b.writer.pending] == ["k0", "k1", "k2"]  # nothing dropped
    assert not any(e["kind"] == "abandoned-parked" for s in doc_of(sc)["steps"] for e in s["evidence"])  # fmt: skip
    assert b.old_state().data["state"] == "stopped" and doc_of(sc)["route"]["flipped"] is True


def test_abandoned_writes_are_parked_again_when_their_evidence_cannot_be_written(tmp_path):
    sc = _poisoned_rollback_scenario(tmp_path)
    good = dict(lakes.rows_for("dns_activity")[0], uid="good")
    sc.backend.writer.write_batch("dns_activity", [good], idempotency_key="k-good")  # queued
    real = sc.runner._evidence

    def no_space(doc, step, kind, *a, **kw):
        if kind == "abandoned-parked":
            raise OSError(28, "No space left on device")
        return real(doc, step, kind, *a, **kw)

    sc.runner._evidence = no_space
    with pytest.raises(SwapError, match="rollback incomplete"):
        sc.runner.rollback("canary regression; the old lake refuses k-poison", abandon_parked=True)
    assert [p.idempotency_key for p in sc.backend.writer.pending] == ["k-poison"]  # kept
    assert _count(sc.old, "good") == 1  # the good write behind it was replayed
    d = doc_of(sc)
    assert "abandon evidence: FAILED" in d["transitions"][-1]["note"]
    assert sc.backend.old_state().data["state"] == "stopped" and d["route"]["flipped"] is True
    sc.runner._evidence = real
    done = sc.runner.rollback("retry once the evidence disk has room", abandon_parked=True)
    assert done["status"] == "rolled_back"
    body, _ = _abandon_evidence(sc, done)
    assert [g["idempotency_key"] for g in body["abandoned_parked"]] == ["k-poison"]


def test_an_unclosed_backend_releases_its_journal_when_collected(tmp_path):
    import gc

    sc = Scenario(tmp_path)
    path = tmp_path / "parked.jsonl"
    b = _backend_like(sc, path)
    del b
    gc.collect()
    _backend_like(sc, path).close()  # not refused for the rest of the process


def test_the_backend_is_a_context_manager_and_a_park_after_close_raises(tmp_path):
    sc = Scenario(tmp_path)
    path = tmp_path / "parked.jsonl"
    with _backend_like(sc, path) as b:
        assert b.apply_route(AFTER).ok and b.stop_old().ok
    with pytest.raises(LakeError, match="closed"):  # never parked in memory only
        b.writer.write_batch("dns_activity", [dict(lakes.rows_for("dns_activity")[0], uid="late")], idempotency_key="late")  # fmt: skip
    _backend_like(sc, path).close()  # the context released the lock


def test_a_symlink_at_the_lock_path_is_not_followed(tmp_path):
    sc = Scenario(tmp_path)
    path = tmp_path / "parked.jsonl"
    victim = tmp_path / "victim"
    (tmp_path / "parked.jsonl.lock").symlink_to(victim)
    with pytest.raises(LakeError, match="cannot open the lock"):
        _backend_like(sc, path)
    assert not victim.exists()
