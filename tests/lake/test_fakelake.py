# SPDX-License-Identifier: Apache-2.0
"""FakeLake is a full LakeClient on the standard library alone."""

from __future__ import annotations

import pytest
import synthetic

from homelabnext.lake import (
    FakeLake,
    LakeClient,
    LakeError,
    LakeQuery,
    LakeWriter,
    RowRejected,
    UnknownTable,
)


def test_implements_the_protocols():
    f = FakeLake()
    assert isinstance(f, LakeClient) and isinstance(f, LakeQuery) and isinstance(f, LakeWriter)
    assert f.list_tables()[0] == "authentication"


def test_write_describe_query_roundtrip():
    f = FakeLake()
    res = f.write_batch(
        "authentication",
        synthetic.authentication(10),
        idempotency_key="b1",
        source="s",
        high_water="10",
    )
    assert (res.rows_in, res.rows_written, res.rows_skipped, res.replayed) == (10, 10, 0, False)
    info = f.describe("table:authentication")
    assert info.row_count == 10 and info.key == ("uid",)
    assert info.committed["s"].batch_id == "b1" and info.committed["s"].high_water == "10"
    assert f.query("SELECT count(*) AS n FROM authentication") == [{"n": 10}]


def test_same_idempotency_key_twice_writes_once():
    f = FakeLake()
    rows = synthetic.authentication(5)
    f.write_batch("authentication", rows, idempotency_key="k")
    again = f.write_batch("authentication", rows, idempotency_key="k")
    assert again.replayed and again.rows_written == 0
    assert f.describe("authentication").row_count == 5


def test_different_key_same_rows_is_deduped_by_content_key():
    f = FakeLake()
    rows = synthetic.authentication(5)
    f.write_batch("authentication", rows, idempotency_key="k1")
    res = f.write_batch(
        "authentication", rows + synthetic.authentication(8)[5:], idempotency_key="k2"
    )
    assert (res.rows_written, res.rows_skipped) == (3, 5)
    assert f.query("SELECT count(DISTINCT uid) AS n, count(*) AS m FROM authentication") == [
        {"n": 8, "m": 8}
    ]


def test_duplicate_inside_one_batch_is_collapsed():
    f = FakeLake()
    r = synthetic.authentication(1)
    res = f.write_batch("authentication", r + r, idempotency_key="k")
    assert res.rows_written == 1 and res.rows_skipped == 1


def test_bad_row_rejects_whole_batch_and_writes_nothing():
    f = FakeLake()
    rows = synthetic.authentication(3)
    rows[2]["activity_id"] = "x"
    with pytest.raises(RowRejected):
        f.write_batch("authentication", rows, idempotency_key="k")
    assert f.describe("authentication").row_count == 0
    # the key was not consumed by the failed attempt
    assert (
        f.write_batch(
            "authentication", synthetic.authentication(3), idempotency_key="k"
        ).rows_written
        == 3
    )


def test_unknown_table_and_bad_names_and_empty_key():
    f = FakeLake()
    with pytest.raises(UnknownTable):
        f.describe("nope")
    with pytest.raises(LakeError):
        f.write_batch("Bad-Name", [], idempotency_key="k")
    with pytest.raises(LakeError, match="idempotency_key"):
        f.write_batch("authentication", [], idempotency_key="")


def test_write_alias_returns_rows_written():
    f = FakeLake()
    assert f.write("authentication", synthetic.authentication(4), batch_id="x") == 4
    assert f.write("authentication", synthetic.authentication(4), batch_id="x") == 0


def test_named_queries_and_params():
    f = FakeLake(
        named_queries={"by_user": "SELECT count(*) AS n FROM authentication WHERE user_name = :u"}
    )
    f.write_batch("authentication", synthetic.authentication(10), idempotency_key="k")
    assert f.named("by_user", {"u": "alice"}) == [{"n": 2}]
    with pytest.raises(LakeError, match="no named query"):
        f.named("missing")
    with pytest.raises(LakeError, match="query failed"):
        f.query("SELECT * FROM nonexistent")


def test_nested_and_list_values_roundtrip():
    f = FakeLake()
    f.write_batch("authentication", synthetic.authentication(2), idempotency_key="k")
    f.write_batch("dns_activity", synthetic.dns_activity(2), idempotency_key="k")
    r = f.query("SELECT src_endpoint, is_mfa FROM authentication ORDER BY uid LIMIT 1")[0]
    assert r["src_endpoint"]["ip"].startswith("198.51.100.") and r["is_mfa"] is True
    assert f.query("SELECT answers FROM dns_activity ORDER BY uid LIMIT 1") == [{"answers": []}]
