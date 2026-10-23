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
    LateResultLandsOrchestrator,
    LeakOnCancelOrchestrator,
    LeakOnFailureOrchestrator,
    LeakOnKillOrchestrator,
    LyingCapacityOrchestrator,
    NoDedupeOrchestrator,
    NoRestartReconcileOrchestrator,
    RestartRerunsLiveRunOrchestrator,
    TTLReleaseOrchestrator,
)
from conformance.protocols.orchestration import (
    CANCEL_GRACE_S,
    MAX_CANCEL_GRACE_S,
    TERMINAL,
    UnknownJob,
)
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
#: how long a blocked job body waits for its release before giving up by itself: several times
#: MAX_CANCEL_GRACE_S, so a hold that is released only because the body returned is still caught
BODY_BACKSTOP_S = 60.0
#: a live run must still hold its capacity this many graces after it was seen holding it, so a
#: TTL (or any timer) standing in for the release is caught (clause a, ADR-0029 rule 3)
HOLD_GRACES = 2
#: the shortest wait for freed capacity to admit new runs (the bound is 4 graces, at least this)
EFFECT_FLOOR_S = 0.3
#: the shortest time a stopped run is watched for a late result after its body returned
SETTLE_FLOOR_S = 0.1


class _Gate:
    """A job body that says it started and then blocks until the check releases it; ``returned``
    is set once a body has come back (so a late result can be waited for, not raced)."""

    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.returned = threading.Event()
        self._lock = threading.Lock()
        self.calls = 0

    def __call__(self, params: Any) -> str:
        with self._lock:
            self.calls += 1
        self.started.set()
        try:
            self.release.wait(BODY_BACKSTOP_S)
        finally:
            self.returned.set()
        return "late"


def _grace(o: Any) -> float:
    g = float(getattr(o, "cancel_grace_s", CANCEL_GRACE_S))
    assert 0 < g <= MAX_CANCEL_GRACE_S, (
        f"cancel_grace_s {g} is outside (0, {MAX_CANCEL_GRACE_S}]: a longer grace would let a "
        "hold released only when its body returns pass"
    )
    return g


def _capacity(o: Any) -> tuple[int | None, int, frozenset[str]]:
    limit, in_flight, holders = o.capacity()
    return (None if limit is None else int(limit)), int(in_flight), frozenset(holders)


def _until(pred: Callable[[], bool], seconds: float, step: float = 0.01) -> bool:
    """Poll ``pred`` every ``step`` seconds for up to ``seconds``."""
    end = time.monotonic() + seconds
    while True:
        if pred():
            return True
        if time.monotonic() >= end:
            return False
        time.sleep(step)


def _drive(o: Any, run_id: str, seconds: float) -> threading.Thread:
    """Wait on ``run_id`` from another thread, so it is admitted and executes meanwhile.  What
    that wait returns or raises is not the check's evidence: the check reads the run itself."""

    def drive() -> None:
        with contextlib.suppress(Exception):  # e.g. a subject closed under a stuck wait
            o.wait(run_id, timeout=seconds)

    t = threading.Thread(target=drive, daemon=True)
    t.start()
    return t


def _step(o: Any) -> float:
    """How often a check polls the subject: a twentieth of its grace, at least 10 ms (each poll of
    a real adapter is a request)."""
    return max(0.01, _grace(o) / 20)


def _released(o: Any, rid: str, base: int) -> bool:
    """``rid`` holds nothing.  With a limit the in-flight count is back to ``base`` too; without
    one (a shared controller's counter moves with other traffic) only membership is judged."""
    limit, in_flight, holders = _capacity(o)
    return rid not in holders and (limit is None or in_flight <= base)


def _running_gate(o: Any, *, watch: bool = False) -> tuple[_Gate, str, threading.Thread, int]:
    """A run whose body is executing and blocked, the thread driving it, and the in-flight count
    before it was submitted.  The run must hold capacity while it runs: a check that never sees
    the hold proves nothing about releasing it.  With ``watch`` it must also keep holding it for
    :data:`HOLD_GRACES` graces: a hold that goes away on its own while the body still runs is a
    timer, not a release (one check watches; a timer is not specific to one release path)."""
    _, base, _ = _capacity(o)
    gate, name, g = _Gate(), uniq("job"), _grace(o)
    o.define(name, gate)
    rid = o.submit(name, {}, idempotency_key=uniq("k"))
    t = _drive(o, rid, START_S + g)
    try:
        assert gate.started.wait(START_S), f"the run never started within {START_S}s"
        assert _until(lambda: rid in _capacity(o)[2], g, _step(o)), (
            f"a running run holds no capacity: capacity() = {o.capacity()}"
        )
        dropped = watch and _until(lambda: rid not in _capacity(o)[2], HOLD_GRACES * g, g / 10)
        assert not dropped, (
            f"a live, still-blocked run lost its hold within {HOLD_GRACES} x {g}s: a timer is "
            f"not a release ({o.capacity()})"
        )
    except BaseException:
        gate.release.set()
        raise
    return gate, rid, t, base


def _late_result_discarded(o: Any, rid: str, gate: _Gate, t: threading.Thread) -> None:
    """Let the stopped body return, wait until it has, and require that the run it belonged to
    does not change afterwards: a late result is discarded (clause b)."""
    g = _grace(o)
    before = o.wait(rid, timeout=g)
    gate.release.set()
    if gate.started.is_set():
        assert gate.returned.wait(START_S), "the job body never returned after its release"

        def changed() -> bool:
            now = o.wait(rid, timeout=0)
            return (now.state, now.result, now.error) != (before.state, before.result, before.error)

        assert not _until(changed, max(g, SETTLE_FLOOR_S), _step(o)), (
            f"a stopped worker's late result landed: {o.wait(rid, 0)}"
        )
    t.join(g)


def _admits(o: Any) -> None:
    """Capacity by effect, not by report: with a limit, ``limit`` new runs all start promptly.  A
    ``capacity()`` that says the slots are free while admission still counts them fails here.
    Without a limit (the controller reports none) only the report can be judged."""
    limit, _, _ = _capacity(o)
    if limit is None:
        return
    g = _grace(o)
    bound = max(EFFECT_FLOOR_S, 4 * g)
    gate, name = _Gate(), uniq("job")
    o.define(name, gate)
    rids = [o.submit(name, {}, idempotency_key=uniq("k")) for _ in range(limit)]
    for rid in rids:
        _drive(o, rid, bound + g)
    try:
        assert _until(lambda: gate.calls >= limit, bound), (
            f"only {gate.calls} of {limit} new runs started within {bound}s although "
            f"capacity() reports {o.capacity()}: freed capacity does not admit"
        )
    finally:
        gate.release.set()
    for rid in rids:
        assert o.wait(rid, timeout=START_S).state == "succeeded"


@SUITE.check(
    "cancel-running-run-frees-capacity",
    "cancelling a running run stops it: it ends cancelled, its capacity is released at once and "
    "admits new work, and its late result is discarded",
    requires=["admission"],
)
def _(o):
    gate, rid, t, base = _running_gate(o, watch=True)
    try:
        o.cancel(rid)
        freed = _until(lambda: _released(o, rid, base), _grace(o), _step(o))
        st = o.wait(rid, timeout=_grace(o))
        assert st.state == "cancelled", f"a cancelled running run is {st.state}"
        assert freed, (
            f"capacity still held {_grace(o)}s after cancel while the body runs: {o.capacity()}"
        )
        _late_result_discarded(o, rid, gate, t)
    finally:
        gate.release.set()
    _admits(o)


@SUITE.check(
    "killed-worker-fails-run-and-frees-capacity",
    "a run whose worker dies ends failed, its capacity is released and admits new work, and "
    "nothing the dead worker produces lands",
    requires=["admission", "fault-injection"],
)
def _(o):
    gate, rid, t, base = _running_gate(o)
    try:
        o.kill(rid)
        freed = _until(lambda: _released(o, rid, base), _grace(o), _step(o))
        st = o.wait(rid, timeout=_grace(o))
        assert st.state == "failed", f"a run whose worker died is {st.state}"
        assert freed, f"capacity still held {_grace(o)}s after the worker died: {o.capacity()}"
        _late_result_discarded(o, rid, gate, t)
    finally:
        gate.release.set()
    _admits(o)


@SUITE.check(
    "deadline-expiry-frees-capacity",
    "a run past its deadline ends failed with an error naming the deadline, releases its capacity "
    "without waiting for its body, and its late result is discarded",
    requires=["admission", "deadline"],
)
def _(o):
    _, base, _ = _capacity(o)
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
        freed = _until(lambda: _released(o, rid, base), _grace(o), _step(o))
        assert freed, f"capacity still held after the deadline: {o.capacity()}"
        _late_result_discarded(o, rid, gate, t)
    finally:
        gate.release.set()
    _admits(o)


@SUITE.check(
    "restart-reconciles-runs-and-capacity",
    "after a restart a run that was executing is ended (never run a second time), no dead worker "
    "holds capacity or reports a result, and queued runs and idempotency keys survive",
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
        assert st.state in ("failed", "cancelled"), (
            f"a run that was executing is {st.state} after a restart: its old worker may still "
            "be running, so it must be ended, not left running or run again"
        )
        assert gate.calls == 1, f"the run's body executed {gate.calls} times across a restart"
        assert _released(o, rid, base), f"a dead worker holds capacity: {o.capacity()}"
        again = o.submit(quick, {}, idempotency_key=key)
        assert again == queued, f"idempotency key lost on restart: {again} vs {queued}"
        st2 = o.wait(queued, timeout=START_S)
        assert st2.state == "succeeded", f"a run queued across the restart is {st2.state}"
        _late_result_discarded(o, rid, gate, t)
    finally:
        gate.release.set()
    _admits(o)


@SUITE.check(
    "capacity-returns-to-zero-after-churn",
    "after runs that succeed, fail, retry and are cancelled queued or running, no hold remains "
    "and the capacity admits new work",
    requires=["admission"],
)
def _(o):
    _, base, _ = _capacity(o)
    ok, bad, gate = uniq("job"), uniq("job"), _Gate()

    def boom(p):
        raise RuntimeError("churn")

    o.define(ok, lambda p: "ok")
    o.define(bad, boom, retries=1)
    runs = [o.submit(ok, {"i": i}, idempotency_key=uniq("k")) for i in range(2)]
    runs += [o.submit(bad, {"i": 0}, idempotency_key=uniq("k"))]
    never = o.submit(ok, {"i": "never"}, idempotency_key=uniq("k"))
    assert o.cancel(never).state == "cancelled"
    try:
        for rid in runs:  # each finished run, failed or retried ones included, holds nothing
            assert o.wait(rid, timeout=START_S).state in TERMINAL, f"{rid} did not finish"
            assert _until(lambda r=rid: _released(o, r, base), _grace(o), _step(o)), (
                f"{rid} finished but its capacity is still held: {o.capacity()}"
            )
        gate_name = uniq("job")
        o.define(gate_name, gate)
        running = o.submit(gate_name, {}, idempotency_key=uniq("k"))
        _drive(o, running, START_S + _grace(o))
        assert gate.started.wait(START_S), "the run never started"
        o.cancel(running)
        assert o.wait(running, timeout=_grace(o)).state == "cancelled"
        churned = {*runs, never, running}
        assert _until(lambda: all(_released(o, r, base) for r in churned), _grace(o), _step(o)), (
            f"holds left after churn: {o.capacity()} (in flight before: {base})"
        )
    finally:
        gate.release.set()
    _admits(o)


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
    "ttl-release": Mutant(
        TTLReleaseOrchestrator,
        "cancel-running-run-frees-capacity",
        "holds end by a timer shorter than the grace, not by cancel, kill, deadline or restart",
        features=frozenset({"admission"}),
    ),
    "lying-capacity": Mutant(
        LyingCapacityOrchestrator,
        "cancel-running-run-frees-capacity",
        "a stopped run's slot leaks while capacity() reports only running holders",
        features=frozenset({"admission"}),
    ),
    "restart-reruns-live-run": Mutant(
        RestartRerunsLiveRunOrchestrator,
        "restart-reconciles-runs-and-capacity",
        "a restart requeues an executing run without stopping its old worker",
        features=frozenset({"admission", "fault-injection"}),
    ),
    "leak-on-failure": Mutant(
        LeakOnFailureOrchestrator,
        "capacity-returns-to-zero-after-churn",
        "a run that ends failed never returns its slot (only the success path releases)",
        features=frozenset({"admission"}),
    ),
    "late-result-lands": Mutant(
        LateResultLandsOrchestrator,
        "cancel-running-run-frees-capacity",
        "a stopped worker's result overwrites the cancelled run when its body returns",
        features=frozenset({"admission"}),
    ),
}
