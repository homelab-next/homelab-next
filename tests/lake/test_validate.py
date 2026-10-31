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
        ({"activity_id": 2**63}, "activity_id: a 64-bit integer is outside the 64-bit range"),
        ({"activity_id": -(2**63) - 1}, "activity_id: a negative 64-bit integer is outside"),
        ({"src_endpoint": {"port": 10**30}}, "src_endpoint.port: a 100-bit integer"),
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


def test_a_double_given_an_int_beyond_float_range_is_rejected():
    v = get_schema("vulnerability_finding")
    col = next(c.name for c in v.columns if c.type == "double")
    doc = synthetic.vulnerability_finding(1)[0]
    doc[col] = 10**400
    with pytest.raises(
        RowRejected, match=f"{col}: a 1329-bit integer is outside"
    ):  # not an OverflowError
        normalize_rows(v, [doc])
    doc[col] = 7  # an int in range is still taken as a double
    assert normalize_rows(v, [doc])[0][col] == 7.0


@pytest.mark.parametrize("sign", [1, -1])
def test_an_int_too_long_to_print_is_still_a_row_problem(sign):
    # str() of an int over 4300 digits raises ValueError; the message never prints the value
    huge = sign * 10**5000
    v = get_schema("vulnerability_finding")
    col = next(c.name for c in v.columns if c.type == "double")
    doc = synthetic.vulnerability_finding(1)[0]
    doc[col] = huge
    with pytest.raises(RowRejected, match=rf"{col}: a .*16610-bit integer"):
        normalize_rows(v, [doc])
    with pytest.raises(RowRejected, match=r"activity_id: a .*16610-bit integer is outside"):
        normalize_rows(S, [row(activity_id=huge)])


# ---------------------------------------------------------------- the row's TLP label (ADR-0033)
def test_every_table_is_labelled_with_the_five_labels():
    from homelabnext import tlp
    from homelabnext.lake import load_schemas

    for s in load_schemas().values():
        assert s.labelled and s.column("tlp").enum == tlp.LABELS


@pytest.mark.parametrize("label", ["clear", "green", "amber", "amber+strict", "red"])
def test_a_row_with_a_label_is_written(label):
    assert normalize_rows(S, [row(tlp=label)])[0]["tlp"] == label


@pytest.mark.parametrize("missing", [{"tlp": None}, "drop"])
def test_a_row_without_a_label_is_refused(missing):
    r = row()
    if missing == "drop":
        r.pop("tlp")
    else:
        r.update(missing)
    with pytest.raises(RowRejected, match="written with its TLP label"):
        normalize_rows(S, [r])


@pytest.mark.parametrize("bad", ["TLP:AMBER", "Amber", "white", "amber-strict", "black", "", 3])
def test_only_a_canonical_label_is_written(bad):
    # the writer normalises (homelabnext.tlp) before it writes; the lake stores one spelling
    with pytest.raises(RowRejected, match="tlp"):
        normalize_rows(S, [row(tlp=bad)])


def test_one_unlabelled_row_refuses_the_whole_batch():
    rows = [row(uid="a-1", tlp="clear"), row(uid="a-2", tlp=None)]
    with pytest.raises(RowRejected, match="row 1 tlp"):
        normalize_rows(S, rows)


@pytest.mark.parametrize(
    "stored, want",
    [
        ({"tlp": "green"}, "green"),
        ({"tlp": "amber+strict"}, "amber+strict"),
        ({}, "red"),  # a row stored before the column existed
        ({"tlp": None}, "red"),
        # the lake stores only the canonical spelling: anything else was stored around it
        ({"tlp": "Green"}, "red"),
        ({"tlp": " green"}, "red"),
        ({"tlp": "TLP:GREEN"}, "red"),
        ({"tlp": "white"}, "red"),
        ({"tlp": "gren"}, "red"),
        ({"tlp": 1}, "red"),
        ("not a row", "red"),
    ],
)
def test_a_stored_row_reads_its_label_or_red(stored, want):
    from homelabnext.lake.tables import row_label

    assert str(row_label(stored)) == want


class _AlwaysEqual(str):
    def __eq__(self, other):
        return True

    def __hash__(self):
        return hash("red")


def test_a_str_subclass_cannot_pass_the_label_check():
    with pytest.raises(RowRejected, match="'bogus' is not one of"):
        normalize_rows(S, [row(tlp=_AlwaysEqual("bogus"))])
    stored = normalize_rows(S, [row(tlp=_AlwaysEqual("amber"))])[0]["tlp"]
    assert type(stored) is str and stored == "amber"
    from homelabnext.lake.tables import row_label

    assert str(row_label({"tlp": _AlwaysEqual("clear")})) == "red"


def test_a_label_object_is_refused_with_a_hint():
    from homelabnext.tlp import Label

    with pytest.raises(RowRejected, match="pass the canonical spelling"):
        normalize_rows(S, [row(tlp=Label.CLEAR)])


@pytest.mark.parametrize(
    "spec, needle",
    [
        ({"type": "string", "enum": []}, "non-empty list"),
        ({"type": "string", "enum": "red"}, "non-empty list"),
        ({"type": "string", "enum": ["red", 1]}, "non-empty list"),
        ({"type": "array", "items": {"type": "string", "enum": ["red"]}}, "list items"),
    ],
)
def test_an_enum_the_lake_cannot_enforce_is_refused(spec, needle):
    from homelabnext.lake import LakeError
    from homelabnext.lake.tables import _column

    with pytest.raises(LakeError, match=needle):
        _column("c", spec, False)


def test_an_enum_on_a_struct_field_is_enforced():
    from homelabnext.lake.tables import _column
    from homelabnext.lake.validate import _check

    col = _column(
        "s", {"type": "object", "properties": {"k": {"type": "string", "enum": ["a"]}}}, False
    )
    problems: list[str] = []
    _check(col, {"k": "b"}, "s", problems)
    assert problems and "'b' is not one of a" in problems[0]
