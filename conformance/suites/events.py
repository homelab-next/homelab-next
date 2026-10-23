# SPDX-License-Identifier: Apache-2.0
"""``events``: durable pub/sub with at-least-once delivery, redelivery and a DLQ."""

from __future__ import annotations

from conformance.fakes.event_bus import (
    BrokenDlqEventBus,
    DoubleSettleEventBus,
    FakeEventBus,
    LosesUnsettledEventBus,
    ReplayingEventBus,
    RestartsAtTailEventBus,
    StaleSettleEventBus,
)
from homelabnext.conform.core import Mutant, Suite

from ._util import uniq

SUITE = Suite(
    "events",
    "publish/consume with acknowledgement, bounded redelivery and dead letters",
    "conformance.protocols.events:EventBus",
)


def _subject(bus, leaf="a"):
    return f"conf.{uniq('t').replace('-', '')}.{leaf}"


@SUITE.check("delivers-in-publish-order", "one consumer sees messages in the order published")
def _(bus):
    s = _subject(bus)
    c = bus.consumer(uniq("c"), s)
    for i in range(5):
        bus.publish(s, f"m{i}".encode())
    got = [d.data for d in c.fetch(10)]
    assert got == [f"m{i}".encode() for i in range(5)], f"got {got}"


@SUITE.check("fetch-never-blocks-when-empty", "fetch on an empty consumer returns nothing")
def _(bus):
    c = bus.consumer(uniq("c"), _subject(bus))
    assert list(c.fetch(5)) == []


@SUITE.check("ack-settles-once", "an acknowledged message is not delivered again")
def _(bus):
    s = _subject(bus)
    c = bus.consumer(uniq("c"), s)
    bus.publish(s, b"x")
    (d,) = c.fetch(1)
    d.ack()
    assert list(c.fetch(5)) == [], "acked message was redelivered"


@SUITE.check("nack-redelivers-with-attempt-count", "a nacked message returns with attempt + 1")
def _(bus):
    s = _subject(bus)
    c = bus.consumer(uniq("c"), s, max_deliver=3)
    bus.publish(s, b"x")
    (d1,) = c.fetch(1)
    assert d1.attempt == 1, f"first attempt is {d1.attempt}"
    d1.nack()
    (d2,) = c.fetch(1)
    assert d2.data == b"x" and d2.attempt == 2, f"redelivery attempt {d2.attempt}"


@SUITE.check(
    "dlq-after-max-deliver", "after max_deliver failed attempts the message is dead-lettered"
)
def _(bus):
    s = _subject(bus)
    c = bus.consumer(uniq("c"), s, max_deliver=2)
    bus.publish(s, b"poison")
    for _ in range(2):
        (d,) = c.fetch(1)
        d.nack()
    assert list(c.fetch(5)) == [], "message delivered beyond max_deliver"
    dead = c.dead_letters()
    assert [d.data for d in dead] == [b"poison"], f"dead letters: {[d.data for d in dead]}"


@SUITE.check("term-dead-letters-immediately", "term sends the message to the DLQ without retries")
def _(bus):
    s = _subject(bus)
    c = bus.consumer(uniq("c"), s, max_deliver=5)
    bus.publish(s, b"bad")
    (d,) = c.fetch(1)
    d.term()
    assert list(c.fetch(5)) == []
    assert [x.data for x in c.dead_letters()] == [b"bad"]


@SUITE.check("publish-dedups-on-msg-id", "a repeated msg_id is published once")
def _(bus):
    s = _subject(bus)
    c = bus.consumer(uniq("c"), s)
    mid = uniq("id")
    first = bus.publish(s, b"x", msg_id=mid)
    second = bus.publish(s, b"x", msg_id=mid)
    assert first == second, f"sequence differs for a repeat: {first} vs {second}"
    assert len(list(c.fetch(10))) == 1, "duplicate msg_id delivered twice"


@SUITE.check("durables-are-independent", "two consumers each receive every message")
def _(bus):
    s = _subject(bus)
    c1, c2 = bus.consumer(uniq("c"), s), bus.consumer(uniq("c"), s)
    bus.publish(s, b"x")
    assert len(list(c1.fetch(5))) == 1 and len(list(c2.fetch(5))) == 1


@SUITE.check("only-matching-subjects-delivered", "a consumer sees its subject and nothing else")
def _(bus):
    base = _subject(bus, "x").rsplit(".", 1)[0]
    c = bus.consumer(uniq("c"), base + ".a")
    bus.publish(base + ".b", b"other")
    bus.publish(base + ".a", b"mine")
    assert [d.data for d in c.fetch(10)] == [b"mine"]


@SUITE.check(
    "unsettled-redelivered-on-reopen",
    "a message fetched but never settled is delivered again after the consumer restarts",
)
def _(bus):
    s, name = _subject(bus), uniq("c")
    c = bus.consumer(name, s)
    bus.publish(s, b"x")
    (d1,) = c.fetch(1)  # the process "crashes" here: no ack, nack or term
    c = bus.consumer(name, s)
    got = list(c.fetch(5))
    assert [d.data for d in got] == [b"x"], f"after restart got {[d.data for d in got]}"
    assert got[0].attempt == d1.attempt + 1, f"redelivery attempt {got[0].attempt}"
    got[0].ack()
    assert list(c.fetch(5)) == [], "acked redelivery was delivered again"


@SUITE.check(
    "durable-resumes-after-reopen",
    "a reopened durable consumer continues after its last ack, including messages sent meanwhile",
)
def _(bus):
    s, name = _subject(bus), uniq("c")
    c = bus.consumer(name, s)
    for i in range(4):
        bus.publish(s, f"m{i}".encode())
    for d in c.fetch(2):
        d.ack()
    bus.publish(s, b"m4")
    c = bus.consumer(name, s)
    got = [d.data for d in c.fetch(10)]
    assert got == [b"m2", b"m3", b"m4"], f"after reopen got {got}"


@SUITE.check(
    "settle-twice-is-noop",
    "only the first ack/nack/term of a delivery counts",
)
def _(bus):
    s = _subject(bus)
    c = bus.consumer(uniq("c"), s, max_deliver=5)
    bus.publish(s, b"acked")
    (d,) = c.fetch(1)
    d.ack()
    d.nack()
    assert list(c.fetch(5)) == [], "a nack after an ack redelivered the message"
    bus.publish(s, b"nacked")
    (e,) = c.fetch(1)
    e.nack()
    e.nack()
    first = list(c.fetch(5))
    assert [x.data for x in first] == [b"nacked"], f"got {[x.data for x in first]}"
    first[0].ack()
    assert list(c.fetch(5)) == [], "a second nack queued the message twice"


@SUITE.check(
    "stale-delivery-settles-nothing",
    "settling an earlier delivery, or one handed out before a reopen, leaves the live one alone",
)
def _(bus):
    # a consumer restarts; the old process's late ack lands after the new process's delivery
    s, name = _subject(bus), uniq("c")
    c = bus.consumer(name, s, max_deliver=5)
    bus.publish(s, b"reopened")
    (old,) = c.fetch(1)
    c = bus.consumer(name, s, max_deliver=5)
    (live,) = c.fetch(1)
    old.ack()  # stale: must be a no-op
    live.nack()  # the live delivery failed: the message must come back
    got = [d.data for d in c.fetch(5)]
    assert got == [b"reopened"], f"a stale ack settled the live delivery: redelivered {got}"
    # without a reopen: a second settlement of a delivery after its redelivery was fetched
    s = _subject(bus)
    c = bus.consumer(uniq("c"), s, max_deliver=5)
    bus.publish(s, b"again")
    (first,) = c.fetch(1)
    first.nack()
    (second,) = c.fetch(1)
    first.ack()  # settled already: must not count, and must not touch ``second``
    second.nack()
    got = [d.data for d in c.fetch(5)]
    assert got == [b"again"], f"a second settlement settled the redelivery: redelivered {got}"


@SUITE.check(
    "new-consumer-starts-at-creation",
    "a new durable consumer sees what is published after it was created, not the history",
)
def _(bus):
    s = _subject(bus)
    bus.publish(s, b"before")
    c = bus.consumer(uniq("c"), s)
    bus.publish(s, b"after")
    got = [d.data for d in c.fetch(10)]
    assert got == [b"after"], f"a new consumer was handed {got}"


@SUITE.check(
    "star-wildcard-matches-one-token",
    "'*' matches exactly one token",
    severity="should",
    requires=["wildcards"],
)
def _(bus):
    base = _subject(bus, "x").rsplit(".", 1)[0]
    c = bus.consumer(uniq("c"), base + ".*")
    bus.publish(base + ".a", b"1")
    bus.publish(base + ".a.deep", b"2")
    assert [d.data for d in c.fetch(10)] == [b"1"]


def make_fake():
    return FakeEventBus()


MUTANTS = {
    "dlq-drops-messages": Mutant(
        BrokenDlqEventBus,
        "dlq-after-max-deliver",
        "exhausted messages vanish instead of being dead-lettered",
    ),
    "loses-unsettled-on-restart": Mutant(
        LosesUnsettledEventBus,
        "unsettled-redelivered-on-reopen",
        "a message fetched but not settled is lost when the consumer restarts",
    ),
    "restart-at-tail": Mutant(
        RestartsAtTailEventBus,
        "durable-resumes-after-reopen",
        "reopening a durable consumer skips everything not yet delivered",
    ),
    "stale-delivery-settles": Mutant(
        StaleSettleEventBus,
        "stale-delivery-settles-nothing",
        "a stale delivery settles the live redelivery of the same message",
    ),
    "new-consumer-replays-history": Mutant(
        ReplayingEventBus,
        "new-consumer-starts-at-creation",
        "a new durable consumer is handed every message published before it existed",
    ),
    "double-settle": Mutant(
        DoubleSettleEventBus,
        "settle-twice-is-noop",
        "a delivery can be settled more than once",
    ),
}
