# SPDX-License-Identifier: Apache-2.0
"""``orchestration-features``: the optional features of the orchestration contract (clauses f-j
of ``conformance/protocols/orchestration.py``; docs/orchestration-controller.md, "Additive
``orchestration`` contract features").

Every check requires the product feature it proves, so a target that declares none of them (the
in-memory fake of another product, a StackStorm-backed adapter) skips the suite, and one that
declares some runs only those.  The checks are a suite of their own because the orchestration
suite would reach the 24-check ceiling with them (``docs/conformance.md``).

``priority`` is a SHOULD: ordering is observable only while a single slot is free, so its check
needs ``admission`` and a reported limit, and skips without one.  Its defect is pinned by a test
(``tests/conform/test_conform_orchestration_features.py``), not registered as a mutant, because
only a MUST failure fails a capability.  Every other check is a MUST with a mutant that it, and
only it, catches.
"""

from __future__ import annotations

import threading
from typing import Any

from conformance.fakes.orchestrator import (
    BestEffortPlacementOrchestrator,
    ExclusiveNotEnforcedOrchestrator,
    FakeOrchestrator,
    LocalOnlyEscalatesOrchestrator,
    RetryIgnoresConstraintsOrchestrator,
    RowPerAttemptOrchestrator,
    ShadowLimitCountsRunningOrchestrator,
    ShadowRetryOnRealLaneOrchestrator,
)
from conformance.protocols.orchestration import (
    LANES,
    TERMINAL,
    OrchestrationError,
    ShadowRunPending,
)
from homelabnext.conform.core import Mutant, Skip, Suite

from ._util import raises, uniq
from .orchestration import START_S, _drive, _Gate, _grace, _until

SUITE = Suite(
    "orchestration-features",
    "optional orchestration features: priority, shadow runs, placement constraints, local-only "
    "jobs and the run list",
    "conformance.protocols.orchestration:OrchestrationFeatures",
    tier="extended",
)


def _bound(o: Any) -> float:
    """How long a check watches for something that must NOT happen (a run starting where it may
    not): two graces, at least 20 ms."""
    return max(0.02, 2 * _grace(o))


def _flaky(calls: list[Any]) -> Any:
    """A job body whose first attempt of each run fails (params carry the run's own tag)."""
    lock, seen = threading.Lock(), set()

    def body(p: Any) -> str:
        with lock:
            calls.append(p.get("tag"))
            first = p.get("tag") not in seen
            seen.add(p.get("tag"))
        if first:
            raise RuntimeError("transient")
        return "ok"

    return body


# ---------------------------------------------------------------- f. priority
@SUITE.check(
    "lower-priority-number-starts-first",
    "with one slot free, the queued run with the lower priority number starts first",
    severity="should",
    requires=["priority", "admission"],
    skippable=True,
)
def _(o):
    limit = o.capacity().limit
    if limit is None:
        raise Skip("capacity() reports no limit, so the slots cannot be filled to order a queue")
    gates = [_Gate() for _ in range(int(limit))]
    blockers = []
    for gate in gates:
        name = uniq("job")
        o.define(name, gate)
        rid = o.submit(name, {}, idempotency_key=uniq("k"))
        blockers.append(rid)
        _drive(o, rid, START_S + _grace(o))
    order: list[str] = []
    rec = uniq("job")
    o.define(rec, lambda p: order.append(p["tag"]))
    try:
        assert all(g.started.wait(START_S) for g in gates), "the blocking runs never all started"
        low = o.submit(rec, {"tag": "low"}, idempotency_key=uniq("k"), priority=9)
        high = o.submit(rec, {"tag": "high"}, idempotency_key=uniq("k"), priority=1)
        for rid in (low, high):  # both are waited on, so both are candidates for the slot
            assert o.wait(rid, timeout=0).state == "queued", "a run started with no free slot"
            _drive(o, rid, START_S)
        gates[0].release.set()  # one slot frees
        assert _until(lambda: len(order) == 2, START_S), f"the queued runs did not run: {order}"
        assert order[0] == "high", f"runs started in the order {order}; priority 1 starts first"
    finally:
        for g in gates:
            g.release.set()


# ---------------------------------------------------------------- g. shadow
@SUITE.check(
    "shadow-run-executes-only-on-the-shadow-lane",
    "every attempt of a shadow run, its retry included, executes on the shadow lane, and every "
    "attempt of an ordinary run on the real one",
    requires=["shadow"],
)
def _(o):
    name, calls = uniq("job"), []
    o.define(name, _flaky(calls), retries=1)
    shadow = o.submit(name, {"tag": "s"}, idempotency_key=uniq("k"), shadow=True)
    real = o.submit(name, {"tag": "r"}, idempotency_key=uniq("k"))
    for rid, lane in ((shadow, "shadow"), (real, "real")):
        st = o.wait(rid, timeout=START_S)
        assert (st.state, st.attempts) == ("succeeded", 2), f"{lane} run: {st}"
        lanes = [p.lane for p in o.placements(rid)]
        assert len(lanes) == 2 and set(lanes) <= set(LANES), f"{lane} run placed {lanes}"
        assert lanes == [lane, lane], f"a {lane} run executed on the lanes {lanes}"


@SUITE.check(
    "one-unfinished-shadow-run-per-job",
    "while a job has a queued or running shadow run another shadow submit raises "
    "ShadowRunPending; its own key, ordinary runs and other jobs are not limited",
    requires=["shadow"],
)
def _(o):
    job, other, gate = uniq("job"), uniq("job"), _Gate()
    # the first shadow run blocks until released, so it is still unfinished (queued, or running
    # on a target that starts runs on its own) for every submit that must be refused
    o.define(job, lambda p: gate(p) if p.get("hold") else "ok")
    o.define(other, lambda p: "ok")
    key = uniq("k")
    try:
        first = o.submit(job, {"hold": True}, idempotency_key=key, shadow=True)
        same = o.submit(job, {"hold": True}, idempotency_key=key, shadow=True)
        assert same == first, "a repeated key moved"
        raises(
            lambda: o.submit(job, {}, idempotency_key=uniq("k"), shadow=True),
            "a second shadow run while the first is unfinished",
            ShadowRunPending,
        )
        _drive(o, first, START_S)
        assert gate.started.wait(START_S), "the first shadow run never started"
        raises(
            lambda: o.submit(job, {}, idempotency_key=uniq("k"), shadow=True),
            "a second shadow run while the first is running",
            ShadowRunPending,
        )
        real = o.submit(job, {}, idempotency_key=uniq("k"))
        elsewhere = o.submit(other, {}, idempotency_key=uniq("k"), shadow=True)
        for rid in (real, elsewhere):
            assert o.wait(rid, timeout=START_S).state == "succeeded", f"{rid} did not run"
    finally:
        gate.release.set()
    assert o.wait(first, timeout=START_S).state == "succeeded", "the first shadow run never ended"
    # once the first has finished, a new shadow run is accepted (this submit must not raise)
    after = o.submit(job, {}, idempotency_key=uniq("k"), shadow=True)
    assert o.wait(after, timeout=START_S).state == "succeeded"


# ---------------------------------------------------------------- h. constraints
def _tightest(o: Any) -> tuple[dict[str, Any], set[str]]:
    """Constraints that the fewest backends meet (one backend's own tags and context), and the
    names of the backends that meet them."""
    best: tuple[dict[str, Any], set[str]] | None = None
    backends = o.backends()
    for x in backends:
        c: dict[str, Any] = {"require_tags": sorted(x.tags)}
        if x.max_context is not None:
            c["min_context"] = x.max_context
        ok = {
            b.name
            for b in backends
            if x.tags <= b.tags and (x.max_context is None or (b.max_context or 0) >= x.max_context)
        }
        if best is None or len(ok) < len(best[1]):
            best = (c, ok)
    assert best is not None, "backends() lists no backend"
    return best


@SUITE.check(
    "unsatisfiable-constraints-never-run",
    "a job whose required tags or minimum context no backend has is rejected, or its run stays "
    "queued (or fails) without executing anywhere",
    requires=["constraints"],
)
def _(o):
    known = [b.max_context for b in o.backends() if b.max_context is not None]
    impossible = [{"require_tags": [uniq("no-such-tag")]}]
    if known:
        impossible.append({"min_context": max(known) + 1})
    for c in impossible:
        name, calls = uniq("job"), []
        try:
            o.define(name, lambda p, calls=calls: calls.append(1), constraints=c)
            rid = o.submit(name, {}, idempotency_key=uniq("k"))
        except OrchestrationError:
            continue  # rejected
        st = o.wait(rid, timeout=_bound(o))
        try:
            assert st.state in ("queued", "failed"), f"constraints {c}: the run is {st.state}"
            assert calls == [] and o.placements(rid) == (), (
                f"constraints {c} no backend satisfies, yet the run executed on "
                f"{[p.backend for p in o.placements(rid)]}"
            )
        finally:
            o.cancel(rid)


@SUITE.check(
    "every-attempt-meets-the-constraints",
    "each attempt of a constrained run, its retry included, executes on a backend with every "
    "required tag and at least the minimum context",
    requires=["constraints"],
)
def _(o):
    c, ok = _tightest(o)
    name, calls = uniq("job"), []
    o.define(name, _flaky(calls), retries=1, constraints=c)
    rid = o.submit(name, {"tag": "c"}, idempotency_key=uniq("k"))
    st = o.wait(rid, timeout=START_S)
    assert (st.state, st.attempts) == ("succeeded", 2), f"status {st}"
    placed = [p.backend for p in o.placements(rid)]
    assert len(placed) == 2, f"two attempts, placements {placed}"
    assert set(placed) <= ok, f"constraints {c} hold on {sorted(ok)}; attempts ran on {placed}"


@SUITE.check(
    "exclusive-run-has-its-backend-alone",
    "an exclusive run does not start on a backend another run is executing on, and while it "
    "executes no other run starts on its backend",
    requires=["constraints"],
)
def _(o):
    c, ok = _tightest(o)
    shared, alone = uniq("job"), uniq("job")
    g1, g2, ge = _Gate(), _Gate(), _Gate()
    gates = {"first": g1, "second": g2}
    o.define(shared, lambda p: gates[p["tag"]](p), constraints=c)
    o.define(alone, ge, constraints={**c, "exclusive": True})
    try:
        first = o.submit(shared, {"tag": "first"}, idempotency_key=uniq("k"))
        _drive(o, first, START_S)
        assert g1.started.wait(START_S), "the first run never started"
        (busy,) = {p.backend for p in o.placements(first)}
        excl = o.submit(alone, {}, idempotency_key=uniq("k"))
        _drive(o, excl, START_S)
        onto = lambda: any(p.backend == busy for p in o.placements(excl))  # noqa: E731
        assert not _until(onto, _bound(o)), (
            f"an exclusive run started on {busy} while another run executes there"
        )
        g1.release.set()
        assert ge.started.wait(START_S), "the exclusive run never started"
        (mine,) = {p.backend for p in o.placements(excl)}
        second = o.submit(shared, {"tag": "second"}, idempotency_key=uniq("k"))
        _drive(o, second, START_S)
        beside = lambda: any(p.backend == mine for p in o.placements(second))  # noqa: E731
        assert not _until(beside, _bound(o)), (
            f"a run started on {mine} while an exclusive run executes there"
        )
        ge.release.set()
        g2.release.set()
        for rid in (first, excl, second):
            assert o.wait(rid, timeout=START_S).state == "succeeded", f"{rid} did not finish"
        assert {p.backend for r in (first, excl, second) for p in o.placements(r)} <= ok
    finally:
        for g in (g1, g2, ge):
            g.release.set()


# ---------------------------------------------------------------- i. local-only
@SUITE.check(
    "local-only-run-never-reruns-on-cloud",
    "a local-only run whose attempts fail is retried on local backends only and is never re-run "
    "on cloud, under its run id or another",
    requires=["local-only"],
)
def _(o):
    cloud = {b.name for b in o.backends() if b.locality == "cloud"}
    name, calls = uniq("job"), []

    def always(p):
        calls.append(1)
        raise RuntimeError("backend down")

    o.define(name, always, retries=1, local_only=True)
    rid = o.submit(name, {}, idempotency_key=uniq("k"))
    st = o.wait(rid, timeout=START_S)
    assert (st.state, st.attempts) == ("failed", 2), f"status {st}"
    placed = [p.backend for p in o.placements(rid)]
    assert len(placed) == 2 and not set(placed) & cloud, f"a local-only run executed on {placed}"
    assert not _until(lambda: len(calls) > 2, _bound(o)), (
        f"the job body ran {len(calls)} times for a local-only run with retries=1: it was re-run"
    )
    return "ok" if cloud else "ok (no cloud backend to escalate to)"


# ---------------------------------------------------------------- j. list-runs
@SUITE.check(
    "runs-lists-every-run-once-in-its-state",
    "runs() lists every submitted run exactly once (a repeated key or a retry adds no row) in its "
    "current state, and runs(state) only runs in that state",
    requires=["list-runs"],
)
def _(o):
    ok, bad, block = uniq("job"), uniq("job"), uniq("job")
    gate = _Gate()

    def boom(p):
        raise RuntimeError("no")

    o.define(ok, lambda p: "ok")
    o.define(bad, boom, retries=1)
    o.define(block, gate)
    key = uniq("k")
    done = o.submit(ok, {}, idempotency_key=key)
    o.wait(done, timeout=START_S)
    assert o.submit(ok, {}, idempotency_key=key) == done
    failed = o.submit(bad, {}, idempotency_key=uniq("k"))
    assert o.wait(failed, timeout=START_S).attempts == 2
    cancelled = o.submit(ok, {}, idempotency_key=uniq("k"))
    o.cancel(cancelled)
    queued = o.submit(ok, {}, idempotency_key=uniq("k"))
    running = o.submit(block, {}, idempotency_key=uniq("k"))
    _drive(o, running, START_S)
    try:
        assert gate.started.wait(START_S), "the blocking run never started"
        # these cannot move while the check looks; `queued` was never waited on, so it is queued
        # unless the subject admits on its own, and only ever moves forward
        stable = {done: "succeeded", failed: "failed", cancelled: "cancelled", running: "running"}
        ours = (*stable, queued)
        rows = [s for s in o.runs() if s.run_id in ours]
        ids = [s.run_id for s in rows]
        assert sorted(ids) == sorted(ours), f"runs() lists {ids} for the runs {list(ours)}"
        for s in rows:
            if s.run_id in stable:
                assert s.state == stable[s.run_id], (
                    f"runs() reports {s.run_id} {s.state}; it is {stable[s.run_id]}"
                )
        for state in (*TERMINAL, "queued", "running"):
            sub = o.runs(state=state)
            wrong = [(s.run_id, s.state) for s in sub if s.state != state]
            assert not wrong, f"runs(state={state!r}) returned {wrong}"
            mine = [s.run_id for s in sub if s.run_id in ours]
            assert len(mine) == len(set(mine)), f"runs(state={state!r}) repeats {mine}"
            want = {r for r, st in stable.items() if st == state}
            assert want <= set(mine), f"runs(state={state!r}) misses {sorted(want - set(mine))}"
        (q,) = [s.state for s in rows if s.run_id == queued]
        later = o.wait(queued, timeout=0).state
        assert q in ("queued", "running", later), f"runs() reports a queued run {q}, then {later}"
    finally:
        gate.release.set()
    o.cancel(queued)


def make_fake():
    return FakeOrchestrator()


MUTANTS = {
    "shadow-retry-on-real-lane": Mutant(
        ShadowRetryOnRealLaneOrchestrator,
        "shadow-run-executes-only-on-the-shadow-lane",
        "a shadow run's retry executes on the real lane",
        features=frozenset({"shadow"}),
    ),
    "shadow-limit-counts-running-only": Mutant(
        ShadowLimitCountsRunningOrchestrator,
        "one-unfinished-shadow-run-per-job",
        "a second shadow run is accepted while the first is still queued",
        features=frozenset({"shadow"}),
    ),
    "best-effort-placement": Mutant(
        BestEffortPlacementOrchestrator,
        "unsatisfiable-constraints-never-run",
        "a job no backend satisfies is accepted and runs on the first backend",
        features=frozenset({"constraints"}),
    ),
    "retry-ignores-constraints": Mutant(
        RetryIgnoresConstraintsOrchestrator,
        "every-attempt-meets-the-constraints",
        "a retry escalates to cloud without the job's constraints",
        features=frozenset({"constraints"}),
    ),
    "exclusive-not-enforced": Mutant(
        ExclusiveNotEnforcedOrchestrator,
        "exclusive-run-has-its-backend-alone",
        "an exclusive run shares its backend",
        features=frozenset({"constraints"}),
    ),
    "local-only-escalates": Mutant(
        LocalOnlyEscalatesOrchestrator,
        "local-only-run-never-reruns-on-cloud",
        "a failed attempt of a local-only job is re-run on cloud",
        features=frozenset({"local-only"}),
    ),
    "row-per-attempt": Mutant(
        RowPerAttemptOrchestrator,
        "runs-lists-every-run-once-in-its-state",
        "runs() lists a retried run once per attempt",
        features=frozenset({"list-runs"}),
    ),
}
