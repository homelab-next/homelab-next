# SPDX-License-Identifier: Apache-2.0
"""Draining agent.job.finished from the bus (the in-memory fake): stored or duplicate is acked,
poison is dead-lettered and never retried, a store failure is redelivered."""

from __future__ import annotations

import copy
import sqlite3

from orch_helpers import T0, body, examples

from conformance.fakes.event_bus import FakeEventBus
from homelabnext.orchestration import FINISHED_EVENT
from homelabnext.orchestration.bus import DURABLE, drain
from homelabnext.orchestration.store import TelemetryStore


def _bus_with(*bodies: bytes) -> FakeEventBus:
    bus = FakeEventBus()
    bus.consumer(DURABLE, FINISHED_EVENT)  # the durable exists before anything is published
    for i, b in enumerate(bodies):
        bus.publish(FINISHED_EVENT, b, msg_id=f"m{i}")
    return bus


def test_valid_records_are_stored_and_poison_is_dead_lettered(store):
    evs = examples()
    foreign = copy.deepcopy(evs[0]) | {"id": "evt-foreign", "source": "svc:status-hub"}
    bus = _bus_with(
        *(body(e) for e in evs), body(evs[0]), b"not json", body(foreign), b"x" * 70_000
    )
    bus.publish("homelabnext.agent.job.failed", body(evs[0]))  # not this durable's subject
    counts = drain(bus, store, batch=3)
    assert counts == {"processed": 4, "duplicate": 1, "quarantined": 3}
    assert len(store.jobs()) == 4
    dead = bus.consumer(DURABLE, FINISHED_EVENT).dead_letters()
    assert [d.data[:8] for d in dead] == [b"not json", body(foreign)[:8], b"x" * 8]
    assert drain(bus, store) == {}  # all settled: nothing comes back


def test_a_store_failure_is_redelivered_not_lost(store, monkeypatch):
    bus = _bus_with(*(body(e) for e in examples()))
    real, calls = store.consume, []

    def flaky(data):
        calls.append(1)
        if len(calls) == 2:
            raise sqlite3.OperationalError("database is locked")
        return real(data)

    monkeypatch.setattr(store, "consume", flaky)
    assert drain(bus, store, batch=4) == {"processed": 1, "retried": 3}
    assert drain(bus, store, batch=4) == {"processed": 3}
    assert len(store.jobs()) == 4


def test_an_impossible_timestamp_is_poison_and_the_batch_behind_it_is_stored(store):
    """A date the schema's pattern accepts but the calendar does not (2026-02-30) is dead-lettered;
    it is not a store outage, so the valid records in the same batch are still stored."""
    evs = examples()
    bad = copy.deepcopy(evs[0]) | {"id": "evt-bad-date"}
    bad["data"].update(run_id="run-bad-date", finished_at="2026-02-30T00:00:00Z")
    bus = _bus_with(body(bad), *(body(e) for e in evs))
    assert drain(bus, store, batch=5) == {"quarantined": 1, "processed": 4}
    assert len(store.jobs()) == 4
    assert [d.data for d in bus.consumer(DURABLE, FINISHED_EVENT).dead_letters()] == [body(bad)]


def test_a_content_error_the_store_did_not_name_is_poison_not_a_retry(store, monkeypatch):
    bus = _bus_with(*(body(e) for e in examples()))
    real, calls = store.consume, []

    def picky(data):
        calls.append(1)
        if len(calls) == 1:
            raise KeyError("usage")  # a defect of this record, not of the store
        return real(data)

    monkeypatch.setattr(store, "consume", picky)
    assert drain(bus, store, batch=4) == {"quarantined": 1, "processed": 3}


def test_a_record_past_retention_is_acked_as_expired(tmp_path):
    store = TelemetryStore(tmp_path / "t.db", clock=lambda: T0 + 200 * 86400)
    bus = _bus_with(*(body(e) for e in examples()))
    assert drain(bus, store) == {"expired": 4}
    assert bus.consumer(DURABLE, FINISHED_EVENT).dead_letters() == []
    assert drain(bus, store) == {} and store.jobs() == []
