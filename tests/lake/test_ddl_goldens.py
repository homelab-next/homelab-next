# SPDX-License-Identifier: Apache-2.0
"""Arrow schema, Iceberg schema and per-engine DDL are generated from the OCSF schema files and
pinned by goldens. A column added to a schema file changes the golden, so the diff is reviewed."""

from __future__ import annotations

import pytest
from golden_util import check_golden

from homelabnext.lake import ddl, load_schemas

SCHEMAS = load_schemas()
NAMES = sorted(SCHEMAS)


def test_five_classes_are_pinned():
    assert NAMES == [
        "authentication",
        "detection_finding",
        "dns_activity",
        "network_activity",
        "vulnerability_finding",
    ]
    assert {s.ocsf_version for s in SCHEMAS.values()} == {"1.3.0"}


@pytest.mark.parametrize("name", NAMES)
def test_trino_ddl_golden(name):
    check_golden(
        f"{name}.trino.sql", ddl.trino_ddl(SCHEMAS[name], catalog="lake", schema_name="ocsf")
    )


@pytest.mark.parametrize("name", NAMES)
def test_duckdb_ddl_golden(name):
    check_golden(f"{name}.duckdb.sql", ddl.duckdb_ddl(SCHEMAS[name]))


@pytest.mark.parametrize("name", NAMES)
def test_sqlite_ddl_golden(name):
    check_golden(f"{name}.sqlite.sql", ddl.sqlite_ddl(SCHEMAS[name]))


@pytest.mark.parametrize("name", NAMES)
def test_pyarrow_schema_golden(name):
    pytest.importorskip("pyarrow")
    check_golden(f"{name}.arrow.txt", ddl.arrow_schema_text(ddl.to_pyarrow(SCHEMAS[name])))


@pytest.mark.parametrize("name", NAMES)
def test_iceberg_schema_golden(name):
    pytest.importorskip("pyiceberg")
    from homelabnext.lake.iceberg import _ice_field

    ice = ddl.to_iceberg(SCHEMAS[name])
    text = "\n".join(f"{f.field_id}: {_ice_field(f)}" for f in ice.fields) + "\n"
    check_golden(f"{name}.iceberg.txt", text)


def test_trino_ddl_partitions_and_quotes_reserved_names():
    text = ddl.trino_ddl(SCHEMAS["authentication"], catalog="lake", schema_name="ocsf")
    assert "partitioning = ARRAY['day(time)']" in text
    assert '"time" TIMESTAMP(6) WITH TIME ZONE NOT NULL' in text
    assert "ROW(" in text


def test_missing_pyarrow_is_a_clear_error(monkeypatch):
    import sys

    from homelabnext.lake import MissingExtra

    monkeypatch.setitem(sys.modules, "pyarrow", None)
    with pytest.raises(MissingExtra, match=r"pip install 'homelabnext\[lake\]'"):
        ddl.to_pyarrow(SCHEMAS["authentication"])
