# SPDX-License-Identifier: Apache-2.0
"""Envelope 1.2: an event carries its TLP label (``tlp``) and its inputs (``derivedfrom``);
absent reads red (ADR-0033 decisions 2 and 4)."""

import pytest

from homelabnext.events import FakeForwarder, Publisher, build_event, event_problems
from homelabnext.events.envelope import event_label
from homelabnext.state import StateStore
from homelabnext.tlp import Label


def _event(**kw):
    return build_event(
        "homelabnext.task.queued",
        "svc:siem",
        {
            "task_id": "TASK-0001",
            "profile": "profile:reader",
            "priority": 50,
            "idempotency_key": "reader-2026-01-01",
        },
        dedupe_key="k",
        time="2026-01-01T00:00:00Z",
        **kw,
    )


def test_an_event_without_a_label_reads_red():
    ev = _event()
    assert "tlp" not in ev and "derivedfrom" not in ev
    assert event_label(ev) is Label.RED


@pytest.mark.parametrize("value", ["amber-strict", "", None, 3, "tlp: red"])
def test_an_unreadable_label_reads_red(value):
    assert event_label({"tlp": value}) is Label.RED


def test_a_label_is_written_canonically_with_its_inputs_and_validates():
    ev = _event(label="TLP:Amber+Strict", derived_from=["evt-0001", "evt-0002"])
    assert ev["tlp"] == "amber+strict"
    assert ev["derivedfrom"] == ["evt-0001", "evt-0002"]
    assert event_label(ev) is Label.AMBER_STRICT
    assert event_label(_event(label=Label.GREEN)) is Label.GREEN


def test_a_misspelt_label_is_refused_when_building():
    with pytest.raises(ValueError, match="not a TLP label"):
        _event(label="amber-strict")


@pytest.mark.parametrize(
    ("extra", "where"),
    [
        ({"tlp": "amber-strict"}, "tlp"),
        ({"tlp": "TLP:RED"}, "tlp"),  # on the wire only the canonical spelling
        ({"derivedfrom": []}, "derivedfrom"),
        ({"derivedfrom": ["evt 1"]}, "derivedfrom/0"),
        ({"derivedfrom": ["evt-1", "evt-1"]}, "derivedfrom"),
    ],
)
def test_a_typed_event_refuses_a_bad_label_through_the_envelope(extra, where):
    # a type schema reaches envelope 1.2 by its $ref, so the label is checked on every type
    ev = {**_event(), **extra}
    problems = event_problems(ev)
    assert any(p.startswith(f"{where}:") for p in problems), problems


def test_the_publisher_delivers_the_label_unchanged(tmp_path):
    fwd = FakeForwarder()
    pub = Publisher(fwd, StateStore(tmp_path / "pub.json"), sleep=lambda s: None)
    ev = _event(label="green", derived_from=["evt-0001"])
    assert pub.publish(ev).ok
    sent = fwd.accepted[ev["id"]]
    assert (sent["tlp"], sent["derivedfrom"]) == ("green", ["evt-0001"])
    assert event_label(sent) is Label.GREEN
