# SPDX-License-Identifier: Apache-2.0
"""``events``: durable pub/sub with at-least-once delivery, redelivery and a DLQ."""

from __future__ import annotations

from conformance.fakes.event_bus import BrokenDlqEventBus, FakeEventBus
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
}
