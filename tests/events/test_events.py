# SPDX-License-Identifier: Apache-2.0
"""Envelope validation, the fake and HTTP forwarders, and the idempotent publisher."""

from __future__ import annotations

import copy
import urllib.error

import pytest

from homelabnext.events import (
    EventError,
    FakeForwarder,
    FakeForwarderServer,
    HttpForwarder,
    PermanentError,
    Publisher,
    RetryPolicy,
    TransientError,
    build_event,
    derive_event_id,
    event_problems,
    schema_for_type,
    validate_event,
)
from homelabnext.state import StateStore

TASK = {
    "task_id": "TASK-0001",
    "profile": "profile:reader",
    "priority": 50,
    "idempotency_key": "reader-2026-01-01",
}


def task_event(key="a", **kw):
    return build_event(
        "homelabnext.task.queued",
        "svc:siem",
        TASK,
        dedupe_key=key,
        time="2026-01-01T00:00:00Z",
        **kw,
    )


class Crash(BaseException):
    """Stands in for the process dying (kill -9) at an exact point."""


class CrashingStore:
    """Wraps a store; raises Crash when a record is about to become `sent`."""

    def __init__(self, inner):
        self.inner = inner
        self.armed = False

    def get(self, key, default=None):
        return self.inner.get(key, default)

    def keys(self):
        return self.inner.keys()

    def put(self, key, value):
        if self.armed and value.get("status") == "sent":
            raise Crash
        self.inner.put(key, value)


@pytest.fixture
def store(tmp_path):
    return StateStore(tmp_path / "events.json")


def pub(fwd, store, **kw):
    sleeps = []
    p = Publisher(fwd, store, sleep=sleeps.append, **kw)
    p.sleeps = sleeps
    return p


# ---------------------------------------------------------------- envelope
def test_build_validates_against_envelope_and_type_schema():
    ev = task_event()
    assert ev["specversion"] == "1.0" and ev["id"].startswith("evt-")
    assert schema_for_type(ev["type"]).name == "task.queued.schema.json"
    assert event_problems(ev) == []


def test_type_schema_is_enforced():
    ev = task_event()
    ev["data"]["priority"] = 500
    assert any("priority" in p for p in event_problems(ev))
    with pytest.raises(EventError):
        build_event("homelabnext.task.queued", "svc:siem", {"task_id": "x"}, dedupe_key="a")


@pytest.mark.parametrize(
    "edit",
    [
        lambda e: e.update(specversion="0.3"),
        lambda e: e.update(source="https://example.invalid/x"),
        lambda e: e.update(time="yesterday"),
        lambda e: e.update(Bad="x"),
        lambda e: e.pop("data"),
        lambda e: e.update(id="has space"),
    ],
)
def test_envelope_negatives(edit):
    ev = {
        "specversion": "1.0",
        "id": "evt-1",
        "source": "svc:siem",
        "type": "homelabnext.custom.thing",
        "time": "2026-01-01T00:00:00Z",
        "data": {},
    }
    assert event_problems(ev) == []
    edit(ev)
    assert event_problems(ev)
    with pytest.raises(EventError):
        validate_event(ev)


def test_unknown_type_checked_against_envelope_only():
    ev = build_event("homelabnext.custom.thing", "svc:siem", {"x": 1}, dedupe_key="k")
    assert schema_for_type(ev["type"]) is None


def test_non_object_is_a_problem():
    assert event_problems(["not", "an", "object"]) == ["event must be a JSON object"]


def test_derived_id_is_stable_and_identity_sensitive():
    a = derive_event_id("homelabnext.x.y", "svc:a", "k1")
    assert a == derive_event_id("homelabnext.x.y", "svc:a", "k1")
    assert a != derive_event_id("homelabnext.x.y", "svc:a", "k2")
    assert a != derive_event_id("homelabnext.x.y", "svc:b", "k1")
    assert a != derive_event_id("homelabnext.x.y", "svc:a", "k1", subject="s")
    with pytest.raises(ValueError):
        derive_event_id("homelabnext.x.y", "svc:a", "")


def test_build_needs_exactly_one_of_id_or_dedupe_key():
    with pytest.raises(ValueError):
        build_event("homelabnext.custom.thing", "svc:siem", {})
    with pytest.raises(ValueError):
        build_event("homelabnext.custom.thing", "svc:siem", {}, id="a", dedupe_key="b")


# ---------------------------------------------------------------- publisher + fake
def test_publish_sends_once_and_records_sent(store):
    f = FakeForwarder()
    p = pub(f, store)
    ev = task_event()
    r = p.publish(ev)
    assert (r.status, r.attempts, r.ok) == ("sent", 1, True)
    assert f.ids == [ev["id"]] and p.status_of(ev["id"]) == "sent"


def test_republishing_a_sent_id_makes_no_call(store):
    f = FakeForwarder()
    p = pub(f, store)
    ev = task_event()
    p.publish(ev)
    r = p.publish(copy.deepcopy(ev))
    assert (r.status, r.attempts) == ("duplicate", 0)
    assert f.calls == [ev["id"]]


def test_same_id_different_body_is_refused(store):
    p = pub(FakeForwarder(), store)
    ev = task_event()
    p.publish(ev)
    other = copy.deepcopy(ev)
    other["data"]["priority"] = 51
    with pytest.raises(EventError, match="different body"):
        p.publish(other)


def test_invalid_event_is_refused_before_any_io(store):
    f = FakeForwarder()
    p = pub(f, store)
    ev = task_event()
    ev["data"]["priority"] = -1
    with pytest.raises(EventError):
        p.publish(ev)
    assert f.calls == [] and store.keys() == []


def test_transient_failures_back_off_then_succeed(store):
    f = FakeForwarder()
    f.fail_next = 2
    p = pub(f, store, policy=RetryPolicy(max_attempts=5, base_s=1, factor=2, max_s=30))
    r = p.publish(task_event())
    assert (r.status, r.attempts) == ("sent", 3)
    assert p.sleeps == [1, 2]
    assert len(f.accepted) == 1


def test_backoff_is_capped():
    pol = RetryPolicy(max_attempts=10, base_s=1, factor=2, max_s=5)
    assert [pol.delay(n) for n in (1, 2, 3, 4, 5)] == [1, 2, 4, 5, 5]


@pytest.mark.parametrize(
    "kw", [{"max_attempts": 0}, {"base_s": -1}, {"factor": 0.5}, {"max_s": -1}]
)
def test_retry_policy_validates(kw):
    with pytest.raises(ValueError):
        RetryPolicy(**kw)


def test_exhausted_retries_leave_event_pending_and_flush_delivers_it(store):
    f = FakeForwarder()
    f.fail_next = 3
    p = pub(f, store, policy=RetryPolicy(max_attempts=3, base_s=0))
    ev = task_event()
    r = p.publish(ev)
    assert (r.status, r.attempts, r.ok) == ("pending", 3, False)
    assert p.pending_ids() == [ev["id"]] and f.accepted == {}
    done = p.flush()
    assert [d.status for d in done] == ["sent"] and p.pending_ids() == []
    assert p.flush() == []  # nothing left; no extra calls
    assert f.ids == [ev["id"]]


def test_permanent_rejection_is_not_retried(store):
    f = FakeForwarder()
    f.reject_next = 1
    p = pub(f, store)
    ev = task_event()
    r = p.publish(ev)
    assert (r.status, r.attempts) == ("rejected", 1)
    assert p.sleeps == []
    assert p.publish(ev).status == "rejected" and f.calls == [ev["id"]]
    assert p.pending_ids() == []


def test_lost_ack_is_retried_and_accepted_once(store):
    f = FakeForwarder()
    f.lose_ack_next = 1
    p = pub(f, store, policy=RetryPolicy(max_attempts=3, base_s=0))
    ev = task_event()
    r = p.publish(ev)
    assert r.status == "duplicate" and r.attempts == 2  # second send found it already stored
    assert f.ids == [ev["id"]] and f.calls == [ev["id"], ev["id"]]


def test_crash_between_send_and_ack_then_restart(tmp_path):
    inner = StateStore(tmp_path / "events.json")
    store = CrashingStore(inner)
    f = FakeForwarder()
    ev = task_event()
    store.armed = True
    with pytest.raises(Crash):
        pub(f, store).publish(ev)
    # The forwarder has the event, the publisher never recorded the ack.
    assert f.ids == [ev["id"]]
    assert inner.get(f"events/{ev['id']}")["status"] == "pending"
    # A fresh process on the same state file resends the same id: accepted once in total.
    restarted = pub(f, StateStore(tmp_path / "events.json"))
    results = restarted.flush()
    assert [r.status for r in results] == ["duplicate"]
    assert f.calls == [ev["id"], ev["id"]] and f.ids == [ev["id"]]
    assert restarted.status_of(ev["id"]) == "sent"
    assert restarted.publish(ev).attempts == 0


def test_republish_after_crash_is_also_safe(tmp_path):
    inner = StateStore(tmp_path / "events.json")
    store = CrashingStore(inner)
    f = FakeForwarder()
    ev = task_event()
    store.armed = True
    with pytest.raises(Crash):
        pub(f, store).publish(ev)
    r = pub(f, StateStore(tmp_path / "events.json")).publish(ev)  # caller just publishes again
    assert r.status == "duplicate" and len(f.accepted) == 1


def test_fake_forwarder_rejects_id_collision_with_other_body():
    f = FakeForwarder()
    a = task_event()
    f.forward(a)
    b = copy.deepcopy(a)
    b["data"]["priority"] = 1
    with pytest.raises(PermanentError):
        f.forward(b)


def test_many_events_each_accepted_once(store):
    f = FakeForwarder()
    p = pub(f, store)
    evs = [task_event(key=str(i)) for i in range(20)]
    for _ in range(3):
        for e in evs:
            p.publish(e)
    assert sorted(f.ids) == sorted(e["id"] for e in evs)
    assert len(f.calls) == 20


# ---------------------------------------------------------------- http forwarder
def test_http_forwarder_round_trip_against_loopback_server(store):
    with FakeForwarderServer() as srv:
        p = pub(HttpForwarder(srv.url), store)
        ev = task_event()
        assert p.publish(ev).status == "sent"
        hdr = srv.headers_seen[0]
        assert hdr["idempotency-key"] == ev["id"]
        assert hdr["content-type"] == "application/cloudevents+json"
        # a second, independent publisher (fresh state) re-sends the same id: duplicate ack
        other = pub(HttpForwarder(srv.url), StateStore(store.path.with_name("other.json")))
        assert other.publish(ev).status == "duplicate"
        assert srv.fake.ids == [ev["id"]]


def test_http_lost_ack_and_retry_over_the_wire(store):
    with FakeForwarderServer() as srv:
        srv.fake.lose_ack_next = 1  # 503 after storing
        p = pub(HttpForwarder(srv.url), store, policy=RetryPolicy(max_attempts=3, base_s=0))
        r = p.publish(task_event())
        assert (r.status, r.attempts) == ("duplicate", 2)
        assert len(srv.fake.accepted) == 1


def test_http_status_mapping():
    class Resp:
        def __init__(self, status, body=b"{}"):
            self.status, self._b = status, body

        def read(self, n=-1):
            return self._b if n < 0 else self._b[:n]

        def close(self):
            pass

    def hf(outcome):
        def opener(req, timeout):
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        return HttpForwarder("http://forwarder.example.invalid/e", opener=opener)

    ev = task_event()
    assert hf(Resp(202)).forward(ev).duplicate is False
    assert hf(Resp(200, b'{"duplicate": true}')).forward(ev).duplicate is True
    assert hf(Resp(204, b"")).forward(ev).duplicate is False

    def http_err(code):
        return urllib.error.HTTPError("http://x.invalid", code, "m", {}, None)

    for code in (429, 500, 503):
        with pytest.raises(TransientError):
            hf(http_err(code)).forward(ev)
    for code in (400, 401, 404, 409):
        with pytest.raises(PermanentError):
            hf(http_err(code)).forward(ev)
    with pytest.raises(TransientError):
        hf(urllib.error.URLError("down")).forward(ev)
    with pytest.raises(TransientError):
        hf(TimeoutError()).forward(ev)
    with pytest.raises(PermanentError, match="larger than"):
        hf(Resp(200, b" " * (64 * 1024 + 1))).forward(ev)


def test_http_forwarder_refuses_credentials_over_plaintext():
    with pytest.raises(ValueError, match="plaintext"):
        HttpForwarder("http://forwarder.example.invalid/e", auth=lambda: "Bearer t")
    HttpForwarder("http://localhost:9/e", auth=lambda: "t")  # no-raw-endpoint: allow loopback
    HttpForwarder("http://forwarder.example.invalid/e", auth=lambda: "t", allow_plaintext=True)
    f = HttpForwarder("https://forwarder.example.invalid/e", auth=lambda: "Bearer t")
    assert f.build_request(task_event()).get_header("Authorization") == "Bearer t"


def test_http_forwarder_requires_http_url():
    with pytest.raises(ValueError):
        HttpForwarder("file:///etc/passwd")


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_a_non_finite_number_is_refused_by_the_producer_and_on_every_decode_path(bad):
    """Regression: the producer validated and serialized ``NaN`` (``json.dumps`` allows it by
    default), so an in-repo publisher could emit a body every consumer quarantines; and a body
    handed to ``decode_event`` as a mapping skipped the parse hooks that refuse it on the wire."""
    import json
    from pathlib import Path

    from homelabnext.events.consumer import decode_event
    from homelabnext.events.envelope import canonical_body

    root = Path(__file__).resolve().parents[2]
    ev = json.loads((root / "schemas/events/examples/decision.returned.valid.json").read_text())
    ev["data"]["confidence"] = bad
    with pytest.raises(EventError, match="data/confidence: not a finite number"):
        validate_event(ev)
    with pytest.raises(ValueError):
        canonical_body(ev)
    with pytest.raises(EventError, match="not a finite number"):
        decode_event(ev)  # the mapping path
    with pytest.raises(EventError, match="not a finite number"):
        decode_event({**ev, "data": {**ev["data"], "nested": [{"x": bad}]}})
