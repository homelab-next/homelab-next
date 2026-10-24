# SPDX-License-Identifier: Apache-2.0
"""The in-memory orchestrator's holds: what the suite's capacity checks lean on, beyond them."""

import itertools
import threading

import pytest

from conformance.fakes.orchestrator import (
    AttemptScopedHoldOrchestrator,
    FakeOrchestrator,
    LateResultLandsOrchestrator,
    LeakOnFailureOrchestrator,
)
from conformance.protocols.orchestration import Admission, Capacity, Deadlines, FaultInjection
from conformance.suites import orchestration as suite
from homelabnext.conform.core import run_checks


def test_the_fake_offers_every_optional_part_of_the_contract():
    o = FakeOrchestrator()
    assert isinstance(o, Admission) and isinstance(o, Deadlines) and isinstance(o, FaultInjection)
    assert o.features == {"admission", "deadline", "fault-injection"}
    assert o.capacity() == Capacity(2, 0, frozenset())


def test_slots_bound_the_runs_in_flight_and_a_freed_slot_is_reused():
    o, release = FakeOrchestrator(slots=1), threading.Event()
    o.define("block", lambda p: release.wait(10) and "done")
    o.define("quick", lambda p: "quick")
    a = o.submit("block", {}, idempotency_key="a")
    assert o.wait(a, timeout=0.05).state == "running"
    b = o.submit("quick", {}, idempotency_key="b")
    assert o.wait(b, timeout=0.05).state == "queued", "a second run started with no free slot"
    assert o.capacity() == Capacity(1, 1, frozenset({a}))
    release.set()
    assert o.wait(a).state == "succeeded"
    assert o.wait(b).state == "succeeded"
    assert o.capacity().in_flight == 0


def test_a_deadline_that_passes_in_the_queue_fails_the_run_without_running_it():
    o, calls = FakeOrchestrator(), []
    o.define("j", lambda p: calls.append(1))
    rid = o.submit("j", {}, idempotency_key="k", deadline_s=0.01)
    threading.Event().wait(0.1)
    st = o.wait(rid)
    assert (st.state, st.error, calls) == ("failed", "deadline exceeded before the run started", [])
    o.close()


def test_kill_and_restart_leave_finished_and_queued_runs_alone():
    o = FakeOrchestrator()
    o.define("j", lambda p: "ok")
    done = o.submit("j", {}, idempotency_key="done")
    o.wait(done)
    queued = o.submit("j", {}, idempotency_key="queued")
    o.kill(done)
    o.restart()
    assert o.wait(done, timeout=0).state == "succeeded"
    assert o.submit("j", {}, idempotency_key="queued") == queued
    assert o.wait(queued).state == "succeeded"


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [({"deadline_s": 0}, "deadline_s"), ({"idempotency_key": ""}, "idempotency_key")],
)
def test_bad_submits_are_refused(kwargs, match):
    o = FakeOrchestrator()
    o.define("j", lambda p: 1)
    with pytest.raises(ValueError, match=match):
        o.submit("j", {}, **{"idempotency_key": "k", **kwargs})
    with pytest.raises(ValueError, match="slots"):
        FakeOrchestrator(slots=0)


HOLDS = [s.id for s in suite.SUITE.specs if "admission" in s.requires]


class _SharedCounter(FakeOrchestrator):
    """A controller-like target: no limit, and an in-flight counter that other traffic keeps
    raising (one more foreign job each time it is read)."""

    def __init__(self):
        super().__init__()
        self._others = itertools.count()

    def capacity(self):
        _, n, holders = super().capacity()
        return Capacity(None, n + next(self._others), holders)


class _NoisyLimited(_SharedCounter):
    def capacity(self):
        _, n, holders = super().capacity()
        return Capacity(self.slots, n, holders)


def test_without_a_limit_a_release_is_judged_by_membership_not_the_shared_counter():
    """With no limit, ``in_flight`` is a counter other traffic moves (the live controller's), so
    only the run's own membership in ``holders`` is judged; with a limit the count must return."""
    res = run_checks(suite.SUITE, _SharedCounter, only=HOLDS)
    assert {r.check: r.status for r in res} == dict.fromkeys(HOLDS, "pass")
    (res,) = run_checks(suite.SUITE, _NoisyLimited, only=["cancel-running-run-frees-capacity"])
    assert res.status == "fail" and "capacity still held" in res.evidence


def test_a_grace_above_the_protocol_cap_fails_the_capacity_checks():
    """A self-declared grace longer than MAX_CANCEL_GRACE_S would let a hold released only when
    its body returns pass for one released on cancel."""

    class Slow(FakeOrchestrator):
        cancel_grace_s = 11.0

    (res,) = run_checks(suite.SUITE, Slow, only=["cancel-running-run-frees-capacity"])
    assert res.status == "fail" and "outside (0, 10.0]" in res.evidence


@pytest.mark.parametrize(
    ("defect", "check"),
    [
        (LateResultLandsOrchestrator, "cancel-running-run-frees-capacity"),
        (LateResultLandsOrchestrator, "deadline-expiry-frees-capacity"),
        (LeakOnFailureOrchestrator, "capacity-returns-to-zero-after-churn"),
    ],
    ids=["late-result-cancel", "late-result-deadline", "leak-on-failure"],
)
def test_more_defects_the_holds_checks_catch(defect, check, monkeypatch):
    """Defects the checks catch that are not registered as mutants (each registered one costs a
    full suite run in every mutation pass): a stopped worker's late result landing, and a slot
    released only on success."""
    # a longer grace than the fake's 10 ms, so the late write is always inside the watch
    monkeypatch.setattr(defect, "cancel_grace_s", 0.2)
    (res,) = run_checks(suite.SUITE, defect, only=[check])
    assert res.status == "fail", res


class _RunTableCapacity(FakeOrchestrator):
    """``capacity()`` read from the run table (the runs that are ``running``), not from the slots
    admission counts: it looks clean whatever leaked."""

    leak_on: tuple[str, ...] = ()

    def capacity(self):
        with self._cv:
            live = frozenset(r for r in self._holds if self._runs[r]["state"] == "running")
            return Capacity(self.slots, len(live), live)

    def _release(self, run_id, why):
        failed = why == "done" and self._runs[run_id]["state"] == "failed"
        if why in self.leak_on or (failed and "failure" in self.leak_on):
            self._holds[run_id] = -1  # the slot is never returned
        else:
            super()._release(run_id, why)

    def _reconcile(self):
        if "restart" not in self.leak_on:
            return super()._reconcile()
        for run_id in self._holds:
            self._holds[run_id] = -1
        for r in self._runs.values():
            if r["state"] == "running":
                r["state"], r["error"] = "failed", "orchestrator restarted: worker lost"
        self._cv.notify_all()


@pytest.mark.parametrize(
    ("leak", "check"),
    [
        ("kill", "killed-worker-fails-run-and-frees-capacity"),
        ("deadline", "deadline-expiry-frees-capacity"),
        ("restart", "restart-reconciles-runs-and-capacity"),
        ("failure", "capacity-returns-to-zero-after-churn"),
    ],
)
def test_a_leak_on_one_path_behind_a_run_table_capacity_fails_that_paths_check(leak, check):
    """A slot leaked on one path only (a crash, a timeout, a restart, a failed attempt) while
    ``capacity()`` reports from the run table passes every report-based assertion; the check of
    that path must still fail it, by effect: freed capacity does not admit new runs."""
    defect = type(f"LeakOn{leak.title()}", (_RunTableCapacity,), {"leak_on": (leak,)})
    (res,) = run_checks(suite.SUITE, defect, only=[check])
    assert res.status == "fail" and "freed capacity does not admit" in res.evidence, res
    # and the same capacity() with no leak passes every holds check
    res = run_checks(suite.SUITE, _RunTableCapacity, only=HOLDS)
    assert {r.check: r.status for r in res} == dict.fromkeys(HOLDS, "pass")


def test_a_run_between_attempts_is_live():
    """A retry is the same run: a hold scoped to an attempt (released when it fails, as when
    liveness is judged by whether an attempt's process exists) fails the retry check, and the fake
    passes it."""
    (res,) = run_checks(
        suite.SUITE, AttemptScopedHoldOrchestrator, only=["retrying-run-keeps-its-hold"]
    )
    assert res.status == "fail" and "liveness is the run's" in res.evidence, res
    (res,) = run_checks(suite.SUITE, FakeOrchestrator, only=["retrying-run-keeps-its-hold"])
    assert res.status == "pass", res
