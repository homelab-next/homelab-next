# SPDX-License-Identifier: Apache-2.0
"""``homelabnext.logpipeline.tlp_labels``: the TLP label from the route's declaration (ADR-0033)."""

import copy
import json
from pathlib import Path

import pytest

from homelabnext.logpipeline import SourceTable, SourceTableError, enrich_tlp
from homelabnext.logpipeline import tlp_labels as tl
from homelabnext.tlp import Label

ROOT = Path(__file__).resolve().parents[2]
ROWS = [
    ("feeds/open", Label.CLEAR, False),
    ("feeds/partner", Label.AMBER, False),
    ("feeds/community", Label.GREEN, True),
    ("sensor/sightings", Label.RED, False),
]
TABLE = SourceTable.from_doc(tl.table_doc(ROWS))


def _label(event):
    return event["labels"][tl.LABEL]


@pytest.mark.parametrize(
    "event, route, want",
    [
        ({}, "feeds/open", "clear"),
        ({}, "feeds/partner", "amber"),
        ({}, "feeds/community", "green"),
        ({}, "sensor/sightings", "red"),
        # stricter item labels are kept, unreadable ones are red
        ({"tlp": "amber"}, "feeds/open", "amber"),
        ({"TLP ": "tlp:red"}, "feeds/open", "red"),
        ({"tlp": None}, "feeds/open", "red"),
        ({"tlp": ""}, "feeds/open", "red"),
        ({"tlp": "amber-strict"}, "feeds/open", "red"),
        # looser ones are raised unless honoured
        ({"tlp": "clear"}, "feeds/partner", "amber"),
        ({"tlp": "clear"}, "sensor/sightings", "red"),
        ({"tlp": "clear"}, "feeds/community", "clear"),
        # two spellings of the claim: the strictest of them
        ({"tlp": "clear", "Tlp": "amber"}, "feeds/community", "amber"),
        # an unknown, missing or malformed route is red
        ({"tlp": "clear"}, "feeds/unlisted", "red"),
        ({}, None, "red"),
        ({}, "FEEDS/OPEN", "red"),
        ({}, " feeds/open", "red"),
        ({}, ["feeds/open"], "red"),
        ({"route": "feeds/open", "event": {"dataset": "feeds/open"}}, None, "red"),
    ],
)
def test_the_label(event, route, want):
    assert _label(enrich_tlp(event, route, TABLE)) == want


def test_a_str_subclass_route_is_not_a_route():
    class Route(str):
        def __eq__(self, other):
            return True

        def __hash__(self):
            return hash("feeds/open")

    assert _label(enrich_tlp({}, Route("feeds/unlisted"), TABLE)) == "red"


def test_every_self_set_spelling_is_replaced_and_nothing_else_changes():
    event = {
        "labels": {tl.LABEL: "clear", "HNX_TLP ": "clear", "site": "lab-a"},
        tl.FLAT_KEY: "clear",
        " Labels.hnx_tlp": "clear",
        "tlp": "clear",
        "message": "m",
    }
    before = copy.deepcopy(event)
    got = enrich_tlp(event, "sensor/sightings", TABLE)
    assert event == before  # the caller's event is not modified
    assert got == {"labels": {tl.LABEL: "red", "site": "lab-a"}, "tlp": "clear", "message": "m"}


@pytest.mark.parametrize("labels", [None, "x", ["a"], 3])
def test_labels_that_cannot_carry_the_label_is_replaced(labels):
    assert enrich_tlp({"labels": labels}, "feeds/open", TABLE)["labels"] == {tl.LABEL: "clear"}


@pytest.mark.parametrize("odd", [None, "a string", ["a", "list"], 3])
def test_a_record_that_is_not_an_object_passes_through(odd):
    assert enrich_tlp(odd, "feeds/open", TABLE) == odd


def test_an_empty_table_labels_everything_red():
    assert _label(enrich_tlp({"tlp": "clear"}, "feeds/open", SourceTable())) == "red"


# ---------------------------------------------------------------- the table
def test_the_document_round_trips_and_is_ordered():
    doc = tl.table_doc(ROWS)
    assert list(doc["sources"]) == sorted(r[0] for r in ROWS)
    assert doc["sources"]["feeds/community"] == {
        "tlp": "green",
        "honour_item_labels": True,
        "module": "feeds",
        "dataset": "community",
    }
    assert SourceTable.from_doc(json.loads(json.dumps(doc))) == TABLE


@pytest.mark.parametrize(
    "rows, needle",
    [
        ([("feeds", Label.CLEAR, False)], "not <module>/<dataset>"),
        ([("Feeds/open", Label.CLEAR, False)], "not <module>/<dataset>"),
        ([("feeds/open", "clear", False)], "not a TLP label"),
        ([("feeds/open", Label.CLEAR, 1)], "not a bool"),
        ([("feeds/open", Label.CLEAR, False)] * 2, "given twice"),
    ],
)
def test_table_doc_refuses(rows, needle):
    with pytest.raises(SourceTableError, match=needle):
        tl.table_doc(rows)


def _doc(**entry):
    base = {"tlp": "clear", "honour_item_labels": False, "module": "feeds", "dataset": "open"}
    return {"schema": tl.SCHEMA, "label": tl.LABEL, "sources": {"feeds/open": {**base, **entry}}}


@pytest.mark.parametrize(
    "doc, needle",
    [
        ([], "JSON object"),
        ({**_doc(), "extra": 1}, "unknown keys"),
        ({**_doc(), "schema": "other/v1"}, "schema is"),
        ({**_doc(), "label": "hnx_runtime"}, "label is"),
        ({**_doc(), "sources": []}, "sources is not an object"),
        (_doc(tlp="TLP:CLEAR"), "not a canonical TLP label"),
        (_doc(tlp="white"), "not a canonical TLP label"),
        (_doc(tlp=None), "not a canonical TLP label"),
        (_doc(honour_item_labels="true"), "not a bool"),
        (_doc(module="other"), "do not spell the route"),
        (_doc(note="x"), "only"),
        ({**_doc(), "sources": {"feeds": _doc()["sources"]["feeds/open"]}}, "not <module>"),
    ],
)
def test_from_doc_refuses(doc, needle):
    with pytest.raises(SourceTableError, match=needle):
        SourceTable.from_doc(doc)


def test_load_reports_an_unreadable_file(tmp_path):
    with pytest.raises(SourceTableError, match=r"missing\.json"):
        SourceTable.load(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(SourceTableError, match=r"bad\.json"):
        SourceTable.load(bad)
