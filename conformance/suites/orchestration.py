# SPDX-License-Identifier: Apache-2.0
"""``orchestration``: idempotent submission, bounded retries, cancellation, isolation, and
capacity held only by live work (clauses a-e of ``conformance/protocols/orchestration.py``)."""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable
from typing import Any

from conformance.fakes.orchestrator import (
    FakeOrchestrator,
    LeakOnCancelOrchestrator,
    LeakOnKillOrchestrator,
    NoDedupeOrchestrator,
    NoRestartReconcileOrchestrator,
)
from conformance.protocols.orchestration import CANCEL_GRACE_S, TERMINAL, UnknownJob
from homelabnext.conform.core import Mutant, Suite

from ._util import raises, uniq

SUITE = Suite(
    "orchestration",
    "named jobs: run once per idempotency key, retry a bounded number of times, cancel, isolate, "
    "and hold capacity only for live work",
    "conformance.protocols.orchestration:Orchestrator",
)


@SUITE.check("runs-job-and-returns-result", "a submitted job runs and its result is reported")
def _(o):
    name = uniq("job")
    o.define(name, lambda p: {"echo": p["x"] * 2})
    st = o.wait(o.submit(name, {"x": 21}, idempotency_key=uniq("k")))
    assert st.state == "succeeded" and st.result == {"echo": 42}, f"status {st}"
    assert st.attempts == 1


@SUITE.check("idempotency-key-runs-once", "the same key twice gives one run and one execution")
def _(o):
    name, key, calls = uniq("job"), uniq("k"), []
    o.define(name, lambda p: calls.append(1) or "done")
    r1 = o.submit(name, {}, idempotency_key=key)
    r2 = o.submit(name, {}, idempotency_key=key)
    o.wait(r1)
    o.wait(r2)
    assert r1 == r2, f"run ids differ: {r1} vs {r2}"
    assert len(calls) == 1, f"job body ran {len(calls)} times"


@SUITE.check("distinct-keys-distinct-runs", "different keys are different runs")
def _(o):
    name, calls = uniq("job"), []
    o.define(name, lambda p: calls.append(1))
    a = o.submit(name, {}, idempotency_key=uniq("k"))
    b = o.submit(name, {}, idempotency_key=uniq("k"))
    o.wait(a)
    o.wait(b)
    assert a != b and len(calls) == 2


@SUITE.check("failure-is-recorded", "a raising job ends failed with its error text and one attempt")
def _(o):
    name = uniq("job")

    def boom(p):
        raise RuntimeError("kaboom")

    o.define(name, boom)
    st = o.wait(o.submit(name, {}, idempotency_key=uniq("k")))
    assert st.state == "failed" and st.attempts == 1, f"status {st}"
    assert "kaboom" in (st.error or ""), f"error text {st.error!r}"


@SUITE.check(
    "retries-until-success", "a job that fails twice succeeds on the third attempt with retries=2"
)
def _(o):
    name, n = uniq("job"), []

    def flaky(p):
        n.append(1)
        if len(n) < 3:
            raise RuntimeError("transient")
        return "ok"

    o.define(name, flaky, retries=2)
    st = o.wait(o.submit(name, {}, idempotency_key=uniq("k")))
    assert (st.state, st.attempts, st.result) == ("succeeded", 3, "ok"), f"status {st}"


@SUITE.check("retries-are-bounded", "a job that always fails stops after retries + 1 attempts")
def _(o):
    name, n = uniq("job"), []

    def always(p):
        n.append(1)
        raise RuntimeError("no")

    o.define(name, always, retries=1)
    st = o.wait(o.submit(name, {}, idempotency_key=uniq("k")))
    assert st.state == "failed" and st.attempts == 2 and len(n) == 2, f"status {st}, calls {len(n)}"


@SUITE.check("unknown-job-raises", "submitting an undefined job raises UnknownJob")
def _(o):
    raises(
        lambda: o.submit(uniq("nojob"), {}, idempotency_key=uniq("k")), "unknown job", UnknownJob
    )


@SUITE.check("cancel-before-start-never-runs", "a cancelled queued run does not execute")
def _(o):
    name, calls = uniq("job"), []
    o.define(name, lambda p: calls.append(1))
    rid = o.submit(name, {}, idempotency_key=uniq("k"))
    assert o.cancel(rid).state == "cancelled"
    assert o.wait(rid).state == "cancelled"
    assert calls == [], "a cancelled run executed"


@SUITE.check("cancel-finished-run-is-noop", "cancelling a finished run leaves it as it was")
def _(o):
    name = uniq("job")
    o.define(name, lambda p: 1)
    rid = o.submit(name, {}, idempotency_key=uniq("k"))
    o.wait(rid)
    assert o.cancel(rid).state == "succeeded"


@SUITE.check("params-arrive-unchanged", "nested parameters reach the handler as submitted")
def _(o):
    name, seen = uniq("job"), []
    o.define(name, lambda p: seen.append(p))
    params = {"a": [1, 2, {"b": None}], "c": "café", "d": 1.5}
    o.wait(o.submit(name, params, idempotency_key=uniq("k")))
    assert seen == [params], f"handler saw {seen}"


@SUITE.check("failing-run-does-not-affect-others", "one failed run leaves another run unharmed")
def _(o):
    bad, good = uniq("job"), uniq("job")

    def boom(p):
        raise RuntimeError("x")

    o.define(bad, boom)
    o.define(good, lambda p: "fine")
    rb = o.submit(bad, {}, idempotency_key=uniq("k"))
    rg = o.submit(good, {}, idempotency_key=uniq("k"))
    assert o.wait(rb).state == "failed"
    assert o.wait(rg).state == "succeeded"


# ---------------------------------------------------------------- holds (clauses a-e)
#: how long a check gives a submitted run to start executing its body
START_S = 15.0
#: how long a blocked job body waits for its release before giving up by itself: far beyond any
#: grace, so a hold that is released only because the body returned is still caught
BODY_BACKSTOP_S = 60.0


class _Gate:
    """A job body that says it started and then blocks until the check releases it."""

    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def __call__(self, params: Any) -> str:
        self.calls += 1
        self.started.set()
        self.release.wait(BODY_BACKSTOP_S)
        return "late"


def _grace(o: Any) -> float:
    return float(getattr(o, "cancel_grace_s", CANCEL_GRACE_S))


def _capacity(o: Any) -> tuple[int, frozenset[str]]:
    _limit, in_flight, holders = o.capacity()
    return int(in_flight), frozenset(holders)


def _until(pred: Callable[[], bool], seconds: float) -> bool:
    end = time.monotonic() + seconds
    while True:
        if pred():
            return True
        if time.monotonic() >= end:
            return False
        time.sleep(0.01)


def _drive(o: Any, run_id: str, seconds: float) -> threading.Thread:
    """Wait on ``run_id`` from another thread, so it is admitted and executes meanwhile.  What
    that wait returns or raises is not the check's evidence: the check reads the run itself."""

    def drive() -> None:
        with contextlib.suppress(Exception):  # e.g. a subject closed under a stuck wait
            o.wait(run_id, timeout=seconds)

    t = threading.Thread(target=drive, daemon=True)
    t.start()
    return t


def _running_gate(o: Any) -> tuple[_Gate, str, threading.Thread, int]:
    """A run whose body is executing and blocked, the thread driving it, and the in-flight count
    before it was submitted.  The run must hold capacity while it runs: a check that never sees
    the hold proves nothing about releasing it."""
    base, _ = _capacity(o)
    gate, name = _Gate(), uniq("job")
    o.define(name, gate)
    rid = o.submit(name, {}, idempotency_key=uniq("k"))
    t = _drive(o, rid, START_S + _grace(o))
    if not gate.started.wait(START_S):
        gate.release.set()
        raise AssertionError(f"the run never started within {START_S}s")
    held = _until(lambda: rid in _capacity(o)[1], _grace(o))
    if not held:
        gate.release.set()
        raise AssertionError(f"a running run holds no capacity: capacity() = {o.capacity()}")
    return gate, rid, t, base


def _released(o: Any, rid: str, base: int) -> bool:
    in_flight, holders = _capacity(o)
    return rid not in holders and in_flight <= base


def _finish(o: Any, gate: _Gate, t: threading.Thread) -> None:
    """Release the body; give the driving wait a grace to return (it never returns while a
    defective subject keeps a dead run ``running``, and it is a daemon)."""
    gate.release.set()
    t.join(_grace(o))


@SUITE.check(
    "cancel-running-run-frees-capacity",
    "cancelling a running run stops it: it ends cancelled and its capacity is released at once",
    requires=["admission"],
)
def _(o):
    gate, rid, t, base = _running_gate(o)
    try:
        o.cancel(rid)
        freed = _until(lambda: _released(o, rid, base), _grace(o))
        st = o.wait(rid, timeout=_grace(o))
        assert st.state == "cancelled", f"a cancelled running run is {st.state}"
        assert freed, (
            f"capacity still held {_grace(o)}s after cancel while the body runs: {o.capacity()}"
        )
    finally:
        _finish(o, gate, t)
    st = o.wait(rid, timeout=_grace(o))
    assert st.state == "cancelled", f"the stopped worker's late result landed: {st}"


@SUITE.check(
    "killed-worker-fails-run-and-frees-capacity",
    "a run whose worker dies ends failed and its capacity is released",
    requires=["admission", "fault-injection"],
)
def _(o):
    gate, rid, t, base = _running_gate(o)
    try:
        o.kill(rid)
        freed = _until(lambda: _released(o, rid, base), _grace(o))
        st = o.wait(rid, timeout=_grace(o))
        assert st.state == "failed", f"a run whose worker died is {st.state}"
        assert freed, f"capacity still held {_grace(o)}s after the worker died: {o.capacity()}"
    finally:
        _finish(o, gate, t)
    st = o.wait(rid, timeout=_grace(o))
    assert st.state == "failed", f"a dead worker's result landed: {st}"


@SUITE.check(
    "deadline-expiry-frees-capacity",
    "a run past its deadline ends failed and releases its capacity without waiting for its body",
    requires=["admission", "deadline"],
)
def _(o):
    base, _ = _capacity(o)
    gate, name, deadline = _Gate(), uniq("job"), 0.1
    o.define(name, gate)
    rid = o.submit(name, {}, idempotency_key=uniq("k"), deadline_s=deadline)
    t = _drive(o, rid, START_S + _grace(o))
    try:
        # the body may or may not have been admitted before the deadline: either way the run
        # ends failed and holds nothing (a fake admits at once, so its body is mid-run here)
        st = o.wait(rid, timeout=deadline + START_S + _grace(o))
        assert st.state == "failed", f"a run past its deadline is {st.state}"
        assert "deadline" in (st.error or "").lower(), f"the error does not name it: {st.error!r}"
        freed = _until(lambda: _released(o, rid, base), _grace(o))
        assert freed, f"capacity still held after the deadline: {o.capacity()}"
    finally:
        _finish(o, gate, t)


@SUITE.check(
    "restart-reconciles-runs-and-capacity",
    "after a restart no run is running without a worker, no dead worker holds capacity, and "
    "queued runs and idempotency keys survive",
    requires=["admission", "fault-injection"],
)
def _(o):
    gate, rid, t, base = _running_gate(o)
    quick, key = uniq("job"), uniq("k")
    try:
        o.define(quick, lambda p: "after")
        queued = o.submit(quick, {}, idempotency_key=key)
        o.restart()
        st = o.wait(rid, timeout=_grace(o))
        rerun = st.state == "running" and gate.calls > 1  # requeued and given a new worker
        assert st.state in ("queued", "failed", "cancelled") or rerun, (
            f"run is {st.state} after a restart with no live worker"
        )
        allowed = {rid} if rerun else set()
        in_flight, holders = _capacity(o)
        assert holders <= allowed and in_flight <= base + len(allowed), (
            f"capacity held by dead workers after a restart: {o.capacity()}"
        )
        again = o.submit(quick, {}, idempotency_key=key)
        assert again == queued, f"idempotency key lost on restart: {again} vs {queued}"
        st2 = o.wait(queued, timeout=START_S)
        assert st2.state == "succeeded", f"a run queued across the restart is {st2.state}"
    finally:
        _finish(o, gate, t)
    if gate.calls == 1:
        late = o.wait(rid, timeout=_grace(o))
        assert late.state == st.state, f"a pre-restart worker's result landed: {late}"


@SUITE.check(
    "capacity-returns-to-zero-after-churn",
    "after runs that succeed, fail, retry and are cancelled queued or running, no hold remains",
    requires=["admission"],
)
def _(o):
    base, _ = _capacity(o)
    ok, bad, gate = uniq("job"), uniq("job"), _Gate()

    def boom(p):
        raise RuntimeError("churn")

    o.define(ok, lambda p: "ok")
    o.define(bad, boom, retries=1)
    runs = [o.submit(ok, {"i": i}, idempotency_key=uniq("k")) for i in range(3)]
    runs += [o.submit(bad, {"i": i}, idempotency_key=uniq("k")) for i in range(2)]
    never = o.submit(ok, {"i": "never"}, idempotency_key=uniq("k"))
    assert o.cancel(never).state == "cancelled"
    try:
        for rid in runs:
            assert o.wait(rid, timeout=START_S).state in TERMINAL, f"{rid} did not finish"
        gate_name = uniq("job")
        o.define(gate_name, gate)
        running = o.submit(gate_name, {}, idempotency_key=uniq("k"))
        _drive(o, running, START_S + _grace(o))
        assert gate.started.wait(START_S), "the run never started"
        o.cancel(running)
        assert o.wait(running, timeout=_grace(o)).state == "cancelled"
        churned = {*runs, never, running}
        assert _until(
            lambda: not (_capacity(o)[1] & churned) and _capacity(o)[0] <= base, _grace(o)
        ), f"holds left after churn: {o.capacity()} (in flight before: {base})"
    finally:
        gate.release.set()


def make_fake():
    return FakeOrchestrator()


MUTANTS = {
    "idempotency-ignored": Mutant(
        NoDedupeOrchestrator,
        "idempotency-key-runs-once",
        "a repeated key starts a second run",
    ),
    "leak-on-cancel": Mutant(
        LeakOnCancelOrchestrator,
        "cancel-running-run-frees-capacity",
        "cancelling a running run never returns its slot",
        features=frozenset({"admission"}),
    ),
    "leak-on-kill": Mutant(
        LeakOnKillOrchestrator,
        "killed-worker-fails-run-and-frees-capacity",
        "a dead worker's run fails but its slot is never returned",
        features=frozenset({"admission", "fault-injection"}),
    ),
    "no-restart-reconcile": Mutant(
        NoRestartReconcileOrchestrator,
        "restart-reconciles-runs-and-capacity",
        "a restart leaves runs running and slots held by workers that no longer exist",
        features=frozenset({"admission", "fault-injection"}),
    ),
}
