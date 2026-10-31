# SPDX-License-Identifier: Apache-2.0
"""A notification channel's TLP ceiling (ADR-0033 decision 13)."""

from __future__ import annotations

import argparse

import pytest

from homelabnext import tlp
from homelabnext.notify import CeilingSender, FakeSender, Message, Notifier
from homelabnext.notify.ceiling import WITHHELD_TITLE, ceiling_arg, ceiling_from_flag
from homelabnext.state import StateStore


def _gate(ceiling: str) -> tuple[CeilingSender, FakeSender]:
    inner = FakeSender()
    return CeilingSender(inner, tlp.parse(ceiling)), inner


def test_a_message_at_or_below_the_ceiling_is_sent_unchanged():
    gate, inner = _gate("amber")
    for label in ("clear", "green", "amber"):
        msg = Message(key="k", title="disk filling", body="78% used", tlp=label)
        gate.send(msg)
        assert inner.sent[-1] is msg
    assert gate.withheld == 0


def _fields(m: Message) -> str:
    return " ".join(str(v) for v in (m.title, m.body, m.tags, m.click, m.topic, m.email, m.key))


@pytest.mark.parametrize(
    "msg",
    [
        Message(key="k", title="t1", body="b1"),  # no claim: red
        Message(key="k", title="t1", body="b1", tlp="red"),
        Message(key="k", title="t1", body="b1", tlp="bogus"),  # unreadable claim: red
        Message(key="k", title="t1", body="detail-7 TLP:RED inside", tlp="clear"),
        Message(key="k", title="TLP:AMBER+STRICT summary-9", body="b1", tlp="green"),
        Message(key="k", title="t1", body="b1", tags=("tlp:red", "host-4"), tlp="clear"),
        Message(key="k", title="t1", body="b1", click="https://x.example/TLP:RED", tlp="clear"),
        Message(key="k", title="t1", body="b1", topic="TLP:RED", tlp="clear"),
        Message(key="k", title="t1", body="b1", email="tlp:red@x.example", tlp="clear"),
        Message(
            key="k", title="t1", body="b1", topic="ops-6", email="a@x.example", tags=("tag-zz",)
        ),
    ],
)
def test_a_message_above_the_ceiling_is_replaced_by_a_content_free_notice(msg):
    """Negative: a claim never loosens a marker in any field the sender transmits, a missing or
    unreadable claim is red, and the notice carries nothing the producer wrote: not its title,
    body, tags, link, topic or email target."""
    gate, inner = _gate("green")
    gate.send(msg)
    assert gate.withheld == 1
    (sent,) = inner.sent
    assert sent.title == WITHHELD_TITLE
    for value in (msg.title, msg.body, *msg.tags, msg.click, msg.topic, msg.email):
        if value:
            assert value not in sent.title + sent.body, value
    assert sent.tags == () and sent.click is None and sent.topic is None and sent.email is None
    assert sent.level == msg.level and sent.effective_priority == msg.effective_priority
    assert sent.tlp == "green" and "above this channel's green ceiling" in sent.body


def test_the_notice_names_the_label_and_keeps_the_page(caplog):
    gate, inner = _gate("clear")
    msg = Message(key="k", title="secret host down", body="b", level="crit", tlp="amber")
    gate.send(msg)
    (sent,) = inner.sent
    assert sent.level == "crit" and sent.effective_priority == 5
    assert "labelled amber" in sent.body and "secret host" not in _fields(sent).replace("k", "")
    assert "withheld" in caplog.text and "secret host" not in caplog.text


def test_a_recovery_is_labelled_at_least_as_strictly_as_its_problem(tmp_path):
    """The recovery repeats the problem's tags (and title, given no body), so it takes the
    problem's label; a problem that claimed nothing recovers red."""
    gate, inner = _gate("green")
    n = Notifier(gate, StateStore(tmp_path / "s.json"))
    n.register_pair("Lake ingest stalled", "Lake ingest recovered")
    stalled = Message(key="x", title="Lake ingest stalled", body="b", tags=("lake",), tlp="green")
    assert n.report("ingest", "crit", stalled)
    assert n.report("ingest", "ok", Message(key="x", title="x", body="", tlp="clear"))
    assert inner.titles == ["Lake ingest stalled", "Lake ingest recovered"]
    assert inner.sent[-1].tlp == "green" and "recovered" in inner.sent[-1].tags
    # the caller's own recovery body brings its claim: stricter than the channel, withheld
    assert n.report("ingest", "crit", stalled)
    assert n.report("ingest", "ok", Message(key="x", title="x", body="detail", tlp="amber"))
    assert inner.titles[-1] == WITHHELD_TITLE and inner.sent[-1].tags == ("recovered",)
    # a problem with no claim: both the page and its recovery arrive as the notice
    n.register_pair("Disk filling", "Disk recovered")
    assert n.report("disk", "warn", Message(key="d", title="Disk filling", body="b"))
    assert n.report("disk", "ok", Message(key="d", title="x", body="", tlp="clear"))
    assert inner.titles[-2:] == [WITHHELD_TITLE, WITHHELD_TITLE]


def test_a_red_ceiling_admits_everything():
    gate, inner = _gate("red")
    gate.send(Message(key="k", title="TLP:RED", body="b"))
    assert inner.titles == ["TLP:RED"] and gate.withheld == 0


def test_the_ceiling_is_a_parsed_label_and_the_flag_refuses_a_misspelling():
    with pytest.raises(TypeError):
        CeilingSender(FakeSender(), "green")  # type: ignore[arg-type]
    assert ceiling_from_flag(None) is tlp.Label.RED
    assert ceiling_from_flag("tlp:green") is tlp.Label.GREEN
    assert ceiling_from_flag(tlp.Label.AMBER) is tlp.Label.AMBER
    for bad in ("", "gren", "black"):
        with pytest.raises(ValueError, match="--notify-ceiling"):
            ceiling_from_flag(bad)
        with pytest.raises(argparse.ArgumentTypeError):
            ceiling_arg(bad)
