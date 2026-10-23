# SPDX-License-Identifier: Apache-2.0
"""The in-memory orchestrator's holds: what the suite's capacity checks lean on, beyond them."""

import itertools
import threading

import pytest

from conformance.fakes.orchestrator import FakeOrchestrator
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
