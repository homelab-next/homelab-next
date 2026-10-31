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


@pytest.mark.parametrize(
    "msg",
    [
        Message(key="k", title="t", body="b"),  # no claim: red
        Message(key="k", title="t", body="b", tlp="red"),
        Message(key="k", title="t", body="b", tlp="bogus"),  # unreadable claim: red
        Message(key="k", title="t", body="host detail TLP:RED inside", tlp="clear"),
        Message(key="k", title="TLP:AMBER+STRICT summary", body="b", tlp="green"),
        Message(key="k", title="t", body="b", tags=("tlp:red",), tlp="clear"),
        Message(key="k", title="t", body="b", click="https://x.example/TLP:RED", tlp="clear"),
    ],
)
def test_a_message_above_the_ceiling_is_replaced_by_a_content_free_notice(msg):
    """Negative: a claim never loosens a marker, a missing or unreadable claim is red, and what
    replaces the message carries none of its title, body, tags or link."""
    gate, inner = _gate("green")
    gate.send(msg)
    assert gate.withheld == 1
    (sent,) = inner.sent
    assert sent.title == WITHHELD_TITLE
    assert msg.body not in sent.body or msg.body == "b"
    assert sent.tags == () and sent.click is None
    assert sent.level == msg.level and sent.topic == msg.topic and sent.email == msg.email
    assert sent.tlp == "green" and "above this channel's green ceiling" in sent.body


def test_the_notice_names_the_label_and_keeps_the_page():
    gate, inner = _gate("clear")
    gate.send(Message(key="k", title="secret host down", body="b", level="crit", tlp="amber"))
    (sent,) = inner.sent
    assert sent.level == "crit" and sent.effective_priority == 5
    assert "labelled amber" in sent.body and "secret host" not in sent.body + sent.title


def test_the_notifier_pages_and_recovers_through_the_gate(tmp_path):
    """The notifier's state is unchanged by a swap: the problem is held, and the recovery goes
    through the same check."""
    gate, inner = _gate("green")
    n = Notifier(gate, StateStore(tmp_path / "s.json"))
    n.register_pair("Lake ingest stalled", "Lake ingest recovered")
    assert n.report("ingest", "crit", Message(key="ingest", title="Lake ingest stalled", body="b"))
    assert inner.titles == [WITHHELD_TITLE]
    ok = Message(key="ingest", title="x", body="b", tlp="clear")
    assert n.report("ingest", "ok", ok)
    assert inner.titles[-1] == WITHHELD_TITLE, "the recovery claims nothing of its own: red"


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
