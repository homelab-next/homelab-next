# SPDX-License-Identifier: Apache-2.0
"""``homelabnext.lake.rows.row_from_event``: the row's ``tlp`` is ``labels.hnx_tlp``, never the
event's own ``tlp`` field (ADR-0033 decisions 3 and 5, docs/log-pipeline.md)."""

import pytest
import synthetic

from homelabnext.lake import FakeLake, RowRejected, load_schemas
from homelabnext.lake.rows import row_from_event
from homelabnext.lake.tables import row_label
from homelabnext.logpipeline import SourceTable, enrich_tlp
from homelabnext.tlp import Label

SCHEMAS = load_schemas()
S = SCHEMAS["authentication"]


def _event(**over):
    event = synthetic.authentication(1)[0]
    event.update(over)
    return event


def test_the_row_takes_the_pipeline_label_not_the_event_s_own():
    row = row_from_event(_event(tlp="clear", labels={"hnx_tlp": "red"}), S)
    assert row["tlp"] == "red"
    assert "labels" not in row  # not a column of the table
    lake = FakeLake(SCHEMAS)
    lake.write_batch("authentication", [row], idempotency_key="b1", source="t")
    assert row_label(lake.query('SELECT * FROM "authentication"')[0]) is Label.RED


def test_through_the_pipeline_a_self_claimed_clear_is_stored_at_the_declaration():
    table = SourceTable(sources={"feeds/partner": (Label.AMBER, False)})
    event = enrich_tlp(_event(tlp="clear"), "feeds/partner", table)
    assert row_from_event(event, S)["tlp"] == "amber"


@pytest.mark.parametrize(
    "labels",
    [None, {}, {"hnx_tlp": None}, {"hnx_tlp": "white"}, {"hnx_tlp": "Green"}, "red", ["red"]],
)
def test_an_event_without_a_canonical_pipeline_label_is_refused(labels):
    event = _event(tlp="clear")
    if labels is not None:
        event["labels"] = labels
    with pytest.raises(RowRejected, match="hnx_tlp"):
        row_from_event(event, S)


def test_the_event_is_not_changed_and_a_non_object_is_refused():
    event = _event(tlp="clear", labels={"hnx_tlp": "amber"})
    row_from_event(event, S)["metadata"]["product"] = "changed"
    assert event["tlp"] == "clear" and event["metadata"] != {"product": "changed"}
    with pytest.raises(RowRejected):
        row_from_event(["not", "an", "object"], S)  # type: ignore[arg-type]
