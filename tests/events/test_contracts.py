# SPDX-License-Identifier: Apache-2.0
"""Generated contract tests: a publisher and a consumer test for EVERY event type (T-07, Q-05).

The parameters come from ``schemas/events/`` (``homelabnext.events.contract``), so a new type is
covered the moment its schema lands; ``tools/contract_coverage.py`` fails the build when a type
has no passing ``test_publisher_contract[<type>]`` and ``test_consumer_contract[<type>]``.

Publisher: the type's example is rebuilt through ``build_event`` and published over HTTP to the
loopback forwarder.  Consumer: the bytes the forwarder received are decoded and validated by
``decode_event``, dispatched once, acknowledged as a duplicate on redelivery, and an unknown
extension attribute is tolerated; every negative of the type and every required ``data`` field's
absence is refused.
"""

from __future__ import annotations

import copy

import pytest

from homelabnext.events import (
    EventError,
    FakeForwarderServer,
    HttpForwarder,
    Publisher,
    build_event,
    schema_for_type,
)
from homelabnext.events.consumer import Consumer, decode_event
from homelabnext.events.contract import (
    data_required,
    event_type,
    event_type_stems,
    negatives,
    samples,
)
from homelabnext.events.envelope import canonical_body
from homelabnext.state import StateStore

STEMS = event_type_stems()
_BUILD_ARGS = ("subject", "severity", "correlationid", "dataschema")


def _id(sample: dict) -> str:
    # the examples share ids across types; one forwarder holds every type's events
    return f"{sample['id']}.{sample['type']}"


def _rebuild(sample: dict) -> dict:
    """The sample as a publisher produces it: through ``build_event``, which validates."""
    ev = build_event(
        sample["type"],
        sample["source"],
        sample["data"],
        id=_id(sample),
        time=sample["time"],
        **{k: sample[k] for k in _BUILD_ARGS if k in sample},
    )
    ev.update({k: v for k, v in sample.items() if k not in ev})  # extension attributes
    assert {**ev, "id": sample["id"]} == sample  # nothing lost or added on the way
    return ev


@pytest.fixture(scope="module")
def forwarder():
    with FakeForwarderServer() as srv:  # one loopback server for the module
        yield srv


def _published(stem: str, srv, tmp_path) -> list[tuple[dict, bytes]]:
    """Publish every sample over HTTP; return (event, the wire body the forwarder received)."""
    out = []
    pub = Publisher(HttpForwarder(srv.url), StateStore(tmp_path / "pub.json"), sleep=lambda s: None)
    for sample in samples(stem):
        ev = _rebuild(sample)
        assert pub.publish(ev).ok  # sent, or a duplicate of the other contract test's send
        out.append((ev, canonical_body(srv.fake.accepted[ev["id"]])))
    return out


def test_every_type_is_discovered():
    assert len(STEMS) >= 10
    assert "envelope" not in STEMS


@pytest.mark.parametrize("stem", STEMS)
def test_publisher_contract(stem, forwarder, tmp_path):
    assert schema_for_type(event_type(stem)) is not None, "the type has no schema of its own"
    published = _published(stem, forwarder, tmp_path)
    assert published, f"{stem}: no example to publish (schemas/events/examples/{stem}.*.json)"
    for ev, wire in published:
        assert ev["type"] == event_type(stem)
        assert decode_event(wire) == ev  # what the forwarder holds is exactly what was sent


@pytest.mark.parametrize("stem", STEMS)
def test_consumer_contract(stem, forwarder, tmp_path):
    etype = event_type(stem)
    handled: list[str] = []
    consumer = Consumer({etype: lambda e: handled.append(e["id"])})
    for ev, wire in _published(stem, forwarder, tmp_path):
        assert consumer.handle(wire).status == "processed"
        assert consumer.handle(wire).status == "duplicate"  # redelivery is harmless
        future = dict(ev, zzfuture="added-later")  # an extension this consumer does not know
        assert decode_event(canonical_body(future), types=[etype])["zzfuture"] == "added-later"
        for field in data_required(stem):
            broken = copy.deepcopy(ev)
            del broken["data"][field]
            with pytest.raises(EventError):
                decode_event(canonical_body(broken), types=[etype])
    assert handled == [_id(s) for s in samples(stem)]
    negs = negatives(stem)
    assert negs, f"{stem}: no negative (schemas/events/negative/{stem}.*.json)"
    accepted = []
    for name, neg in negs:
        try:
            decode_event(canonical_body(neg), types=[etype])
            accepted.append(name)
        except EventError:
            pass
    assert accepted == [], "negatives the consumer accepted"


def test_consumer_refuses_envelope_negatives_and_garbage():
    for _name, neg in negatives("envelope"):
        body = canonical_body(neg) if isinstance(neg, dict) else str(neg)
        with pytest.raises(EventError):
            decode_event(body)
    for body in (b"not json", b"[1]", b"\xff"):
        with pytest.raises(EventError):
            decode_event(body)


def test_consumer_refuses_a_body_nested_past_the_parsers_stack():
    """A parser bomb is a refused body (EventError), never a RecursionError that kills the
    consumer and comes back on every redelivery."""
    for body in (b"[" * 100_000, b'{"a":' * 20_000 + b"1" + b"}" * 20_000):
        with pytest.raises(EventError, match="not JSON"):
            decode_event(body)


def test_consumer_refuses_an_id_collision_and_retries_after_a_handler_failure():
    (sample,) = samples("task.queued")
    calls = []

    def flaky(e):
        calls.append(e["id"])
        if len(calls) == 1:
            raise RuntimeError("handler crashed")

    c = Consumer({sample["type"]: flaky})
    with pytest.raises(RuntimeError):
        c.handle(canonical_body(sample))
    assert c.handle(canonical_body(sample)).status == "processed"  # redelivered, not lost
    other = copy.deepcopy(sample)
    other["data"]["priority"] = 1
    with pytest.raises(EventError):
        c.handle(canonical_body(other))
    with pytest.raises(ValueError):
        Consumer({})
