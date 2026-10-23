# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
import synthetic

from homelabnext.lake import RowRejected, get_schema
from homelabnext.lake.validate import normalize_rows, parse_timestamp

S = get_schema("authentication")


def row(**kw):
    r = synthetic.authentication(1)[0]
    r.update(kw)
    return r


def test_valid_row_is_normalised_to_utc_and_complete():
    r = normalize_rows(S, [row(time="2026-03-01T09:00:00+01:00")])[0]
    assert r["time"] == datetime(2026, 3, 1, 8, 0, tzinfo=UTC)
    assert set(r) == set(S.column_names)


def test_naive_timestamp_refused():
    with pytest.raises(RowRejected, match="no UTC offset"):
        normalize_rows(S, [row(time=datetime(2026, 3, 1, 9, 0))])
    with pytest.raises(ValueError, match="no UTC offset"):
        parse_timestamp("2026-03-01T09:00:00")


def test_aware_non_utc_datetime_accepted():
    t = datetime(2026, 3, 1, 9, tzinfo=timezone(timedelta(hours=-5)))
    assert normalize_rows(S, [row(time=t)])[0]["time"].hour == 14


@pytest.mark.parametrize(
    ("patch", "needle"),
    [
        ({"uid": None}, "uid: required"),
        ({"surprise": 1}, "surprise: unknown column"),
        ({"activity_id": "1"}, "activity_id: expected integer"),
        ({"activity_id": True}, "expected integer"),
        ({"is_mfa": 1}, "is_mfa: expected boolean"),
        ({"src_endpoint": {"ip": "x", "nope": 1}}, "src_endpoint.nope: unknown field"),
        ({"src_endpoint": {"port": "80"}}, "src_endpoint.port: expected integer"),
        ({"metadata": {"product": "p"}}, "metadata.version: required"),
        ({"user_name": 5}, "user_name: expected string"),
        ({"activity_id": 2**63}, "activity_id: integer 9223372036854775808 is outside"),
        ({"activity_id": -(2**63) - 1}, "activity_id: integer -9223372036854775809 is outside"),
        ({"src_endpoint": {"port": 10**30}}, "src_endpoint.port: integer"),
    ],
)
def test_bad_rows_are_rejected_with_the_field_named(patch, needle):
    with pytest.raises(RowRejected, match=needle):
        normalize_rows(S, [row(**patch)])


def test_nan_and_lists():
    v = get_schema("vulnerability_finding")
    r = synthetic.vulnerability_finding(1)[0]
    r["cvss_score"] = float("nan")
    with pytest.raises(RowRejected, match="finite"):
        normalize_rows(v, [r])
    d = get_schema("dns_activity")
    r = synthetic.dns_activity(1)[0]
    r["answers"] = "ns1.example.com"
    with pytest.raises(RowRejected, match="expected list"):
        normalize_rows(d, [r])


def test_whole_batch_rejected_and_all_problems_reported():
    with pytest.raises(RowRejected) as ei:
        normalize_rows(S, [row(), row(uid=None), row(surprise=1)])
    assert len(ei.value.problems) == 2


def test_the_64_bit_bounds_of_a_long_are_accepted():
    for v in (2**63 - 1, -(2**63)):
        assert normalize_rows(S, [row(activity_id=v)])[0]["activity_id"] == v


def test_an_out_of_range_long_is_rejected_before_the_fake_lake_writes():
    from homelabnext.lake import FakeLake

    lake = FakeLake()
    with pytest.raises(RowRejected):  # not an OverflowError from SQLite mid-transaction
        lake.write_batch("authentication", [row(activity_id=2**64)], idempotency_key="b")
    assert lake.query("SELECT count(*) AS n FROM authentication") == [{"n": 0}]
