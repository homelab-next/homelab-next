# SPDX-License-Identifier: Apache-2.0
"""``homelabnext.lake.backfill``: the one-off TLP backfill plan (ADR-0033 decision 5)."""

import dataclasses

import pytest
import synthetic

from homelabnext.lake import FakeLake, load_schemas
from homelabnext.lake.backfill import BackfillError, Source, plan
from homelabnext.tlp import Label

SCHEMAS = load_schemas()
S = SCHEMAS["authentication"]
SOURCES = {
    "feeds/open": Source(Label.CLEAR, items_carried_no_labels=True),
    "feeds/community": Source(Label.GREEN, honour_item_labels=True),
    "sensor/sightings": Source(Label.AMBER, items_carried_no_labels=True),
}
MAP = {"sensor-a": "feeds/open", "sensor-b": "feeds/community", "o'brien": "sensor/sightings"}


def test_the_plan():
    steps = plan(
        S,
        table='"authentication"',
        sources=SOURCES,
        source_map=MAP,
        source_column="metadata.log_source",
    )
    assert steps[0] == 'ALTER TABLE "authentication" ADD COLUMN IF NOT EXISTS "tlp" VARCHAR'
    by_value = {s.rsplit(" = ", 1)[1]: s for s in steps[1:-3]}
    assert "SET \"tlp\" = 'clear'" in by_value["'sensor-a'"]
    # a source with no human record that its items carried no labels is backfilled red
    assert "SET \"tlp\" = 'red'" in by_value["'sensor-b'"]
    assert "'o''brien'" in by_value  # a literal is quoted
    assert all('WHERE "tlp" IS NULL' in s for s in steps[1:-2])
    # everything else takes the strictest source's backfill label
    assert steps[-3] == 'UPDATE "authentication" SET "tlp" = \'red\' WHERE "tlp" IS NULL'
    # then the operator's checks: nothing unlabelled, and the non-canonical rows listed
    assert steps[-2].startswith('SELECT count(*) AS unlabelled FROM "authentication"')
    assert "NOT IN ('clear', 'green', 'amber', 'amber+strict', 'red')" in steps[-1]


def test_without_a_source_column_every_row_takes_the_strictest():
    open_ = Source(Label.CLEAR, items_carried_no_labels=True)
    steps = plan(S, table="t", sources={"feeds/open": open_}, source_map={})
    assert steps[1:-2] == ['UPDATE t SET "tlp" = \'clear\' WHERE "tlp" IS NULL']


@pytest.mark.parametrize("honour", [False, True])
def test_without_a_human_record_old_rows_are_red_whatever_the_source_honours(honour):
    # The rows predate the column, so an item's own (possibly stricter) label was never stored:
    # a green source that does not honour item labels may still have carried an amber item.
    assert Source(Label.GREEN, honour_item_labels=honour).backfill is Label.RED
    steps = plan(S, table="t", sources={"feeds/x": Source(Label.GREEN, honour)}, source_map={})
    assert steps[1:-2] == ['UPDATE t SET "tlp" = \'red\' WHERE "tlp" IS NULL']
    recorded = Source(Label.GREEN, honour, items_carried_no_labels=True)
    assert recorded.backfill is Label.GREEN


def test_the_plan_runs_and_keeps_labelled_rows():
    lake = FakeLake(SCHEMAS)
    rows = synthetic.authentication(6)
    lake.write_batch("authentication", rows, idempotency_key="k")
    db = lake._db
    db.execute('UPDATE "authentication" SET tlp = NULL WHERE uid != ?', ("auth-000000",))
    kept = db.execute('SELECT tlp FROM "authentication" WHERE uid = ?', ("auth-000000",)).fetchone()
    steps = plan(
        S,
        table='"authentication"',
        sources={"feeds/open": Source(Label.GREEN, items_carried_no_labels=True)},
        source_map={"sensor-a": "feeds/open"},
        source_column="metadata.log_source",
        add_column=False,
    )
    for step in steps:
        db.execute(
            step.replace('"metadata"."log_source"', "json_extract(metadata, '$.log_source')")
        )
    got = dict(db.execute('SELECT uid, tlp FROM "authentication"').fetchall())
    assert got.pop("auth-000000") == kept[0]
    assert set(got.values()) == {"green"}
    again = dict(db.execute('SELECT uid, tlp FROM "authentication"').fetchall())
    for step in steps[:-2]:  # a second run changes nothing
        db.execute(
            step.replace('"metadata"."log_source"', "json_extract(metadata, '$.log_source')")
        )
    assert dict(db.execute('SELECT uid, tlp FROM "authentication"').fetchall()) == again


@pytest.mark.parametrize(
    "kwargs, needle",
    [
        ({"sources": {}}, "no source feeds it"),
        ({"source_map": {"x": "nowhere/route"}}, "which is no source"),
        ({"source_column": "nope"}, "no column"),
        ({"source_column": "metadata.nope"}, "no field"),
        ({"source_column": "a.b.c"}, "one struct field"),
        ({"source_column": "class_uid"}, "not a string"),
        ({"table": "t; DROP TABLE x"}, "not a table name"),
        ({"table": "a.b.c.d"}, "not a table name"),
        ({"table": 'lake."o\nx"'}, "not a table name"),
        ({"source_map": {"a\nb": "feeds/open"}}, "control character"),
    ],
)
def test_plan_refuses(kwargs, needle):
    args = {"table": "t", "sources": SOURCES, "source_map": {}, **kwargs}
    with pytest.raises(BackfillError, match=needle):
        plan(S, **args)


def test_an_unlabelled_schema_has_nothing_to_fill():
    bare = dataclasses.replace(S, columns=tuple(c for c in S.columns if c.name != "tlp"))
    with pytest.raises(BackfillError, match="no tlp column"):
        plan(bare, table="t", sources=SOURCES, source_map={})
