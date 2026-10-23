# SPDX-License-Identifier: Apache-2.0
"""The in-memory orchestrator's holds: what the suite's capacity checks lean on, beyond them."""

import threading

import pytest

from conformance.fakes.orchestrator import FakeOrchestrator
from conformance.protocols.orchestration import Admission, Capacity, Deadlines, FaultInjection


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
