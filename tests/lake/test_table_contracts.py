# SPDX-License-Identifier: Apache-2.0
"""Generated contract tests: a publisher (writer) and a consumer (reader) test for EVERY shared
lake table with a schema (Q-05).  Parameters come from ``schemas/ocsf/``; a new table is covered
the moment its schema lands, and ``tools/contract_coverage.py`` fails the build when a table has no
passing ``test_publisher_contract[<table>]`` and ``test_consumer_contract[<table>]``.

Publisher: every example row satisfies the table's JSON Schema and is written through the lake
writer interface; every negative is refused by the schema.  Consumer: rows read back through the
query interface carry exactly the schema's columns and normalise to the rows written.
"""

from __future__ import annotations

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from homelabnext.events.contract import (
    table_names,
    table_negatives,
    table_samples,
    table_schema_doc,
)
from homelabnext.lake import FakeLake, load_schemas
from homelabnext.lake.validate import normalize_rows

TABLES = table_names()
SCHEMAS = load_schemas()


def _validator(table):
    return Draft202012Validator(table_schema_doc(table), format_checker=FormatChecker())


def _write(lake, table):
    rows = table_samples(table)
    assert rows, f"{table}: no example row (schemas/ocsf/examples/{table}.v*.json)"
    res = lake.write_batch(table, rows, idempotency_key=f"contract-{table}")
    assert res.rows_written == len(rows)
    return rows


def test_every_table_is_discovered_and_loaded():
    assert sorted(SCHEMAS) == TABLES


@pytest.mark.parametrize("table", TABLES)
def test_publisher_contract(table):
    v = _validator(table)
    for row in table_samples(table):
        v.validate(row)
    _write(FakeLake(SCHEMAS), table)
    negs = table_negatives(table)
    assert negs, f"{table}: no negative (schemas/ocsf/negative/{table}.v*.json)"
    for name, neg in negs:
        assert not v.is_valid(neg), f"{name} was accepted by the table schema"


@pytest.mark.parametrize("table", TABLES)
def test_consumer_contract(table):
    lake = FakeLake(SCHEMAS)
    written = _write(lake, table)
    got = lake.query(f"SELECT * FROM {table}")
    schema = SCHEMAS[table]
    assert len(got) == len(written)
    for row in got:
        assert set(row) == set(schema.column_names)
    key = schema.key
    norm_got = sorted(normalize_rows(schema, got), key=lambda r: [str(r[k]) for k in key])
    norm_written = sorted(normalize_rows(schema, written), key=lambda r: [str(r[k]) for k in key])
    assert norm_got == norm_written
    # a replay of the same batch is a no-op for the reader
    assert lake.write_batch(table, written, idempotency_key=f"contract-{table}").rows_written == 0
    assert len(lake.query(f"SELECT * FROM {table}")) == len(written)
