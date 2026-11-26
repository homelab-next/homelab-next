# SPDX-License-Identifier: Apache-2.0
"""The data-freshness built-ins: the age of a table's newest snapshot and of each backup group's
newest snapshot, judged against warn_after_s and fail_after_s.  An unreadable payload is the
source's error, an empty datastore is a fail, never an ok."""

from __future__ import annotations

import pytest

from homelabnext.status import apply_mapping
from homelabnext.status.mapping import MappingError

NOW = 1_800_000_000.0
H = 3600


def _table(*ages_s):
    return {
        "metadata": {
            "snapshots": [
                {"snapshot-id": i, "timestamp-ms": int((NOW - a) * 1000)}
                for i, a in enumerate(ages_s)
            ]
        }
    }


def _run(payload, **mapping):
    return apply_mapping(payload, mapping, now=NOW, fallback_item="x")


def test_table_age_ok_warn_fail_by_the_newest_snapshot():
    lim = {
        "builtin": "table-snapshot-age",
        "item": "cti.events",
        "warn_after_s": 2 * H,
        "fail_after_s": 6 * H,
    }
    (ok,) = _run(_table(30 * H, 1 * H), **lim)
    assert (ok.item, ok.state, ok.value) == ("cti.events", "ok", H)
    assert "2 snapshots" in ok.summary
    (warn,) = _run(_table(3 * H), **lim)
    assert warn.state == "warn" and "over the 2h" in warn.summary
    (fail,) = _run(_table(7 * H), **lim)
    assert fail.state == "fail"


def test_table_without_snapshots_or_with_a_future_one_is_never_ok():
    (none,) = _run({"metadata": {"snapshots": []}}, builtin="table-snapshot-age")
    assert none.state == "warn" and "no snapshot" in none.summary
    (future,) = _run(_table(-3 * H), builtin="table-snapshot-age")
    assert future.state == "unknown"


@pytest.mark.parametrize("payload", [None, [], {}, {"metadata": "x"}])
def test_table_payload_that_is_not_a_load_table_result_is_an_error(payload):
    with pytest.raises(MappingError):
        _run(payload, builtin="table-snapshot-age")


def _snap(kind, ident, age, verification=None):
    row = {"backup-type": kind, "backup-id": ident, "backup-time": int(NOW - age)}
    if verification:
        row["verification"] = {"state": verification}
    return row


def test_backup_age_is_judged_per_group_on_the_newest_snapshot():
    payload = {
        "data": [
            _snap("vm", "133", 40 * H),
            _snap("vm", "133", 2 * H, "ok"),
            _snap("vm", "134", 30 * H),
            _snap("ct", "100", 80 * H),
        ]
    }
    got = {
        d.item: d
        for d in _run(
            payload, builtin="backup-snapshot-age", warn_after_s=26 * H, fail_after_s=50 * H
        )
    }
    assert set(got) == {"vm/133", "vm/134", "ct/100"}
    assert got["vm/133"].state == "ok" and "verified ok" in got["vm/133"].summary
    assert got["vm/134"].state == "warn"
    assert got["ct/100"].state == "fail"


def test_a_failed_verification_fails_a_fresh_snapshot():
    payload = {"data": [_snap("vm", "133", H, "failed")]}
    (d,) = _run(payload, builtin="backup-snapshot-age", warn_after_s=26 * H)
    assert d.state == "fail" and "FAILED" in d.summary


def test_an_empty_datastore_is_a_fail_and_a_wrong_payload_an_error():
    (d,) = _run({"data": []}, builtin="backup-snapshot-age")
    assert d.state == "fail"
    with pytest.raises(MappingError):
        _run({"errors": "no"}, builtin="backup-snapshot-age")
    assert (
        _run({"data": [{"backup-id": "1"}, "junk"]}, builtin="backup-snapshot-age")[0].state
        == "fail"
    )


# -------------------------------------------------- drill records (ADR-0042 decision 3)
D = 86400


def _drill_iso(age_s: float) -> str:
    import datetime

    tz = datetime.timezone.utc  # noqa: UP017
    t = datetime.datetime.fromtimestamp(NOW - age_s, tz)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_drill_records_judge_each_guest_by_the_last_verified_against_the_limits():
    payload = {
        "guests": {
            "guest:a": {
                "name": "a",
                "last_verified": _drill_iso(5 * D),
                "snapshot": "vm/130/x",
            },
            "guest:b": {"name": "b", "last_verified": _drill_iso(40 * D), "snapshot": "vm/131/y"},
            "guest:c": {"name": "c", "last_verified": _drill_iso(120 * D), "snapshot": "vm/132/z"},
            "guest:d": {"name": "d"},
        },
        "services": {"idp-main": {"last_verified": _drill_iso(5 * D), "verified": True}},
    }
    got = {
        d.item: d
        for d in _run(payload, builtin="drill-records", warn_after_s=30 * D, fail_after_s=90 * D)
    }
    assert set(got) == {"guest:a", "guest:b", "guest:c", "guest:d", "export:idp-main"}
    assert got["guest:a"].state == "ok" and "5d" in got["guest:a"].summary
    assert got["guest:a"].value == 5 * D
    assert "vm/130/x" in got["guest:a"].summary
    assert got["guest:b"].state == "warn" and "over the 30d" in got["guest:b"].summary
    assert got["guest:c"].state == "fail"
    assert got["guest:d"].state == "unknown" and "not drilled yet" in got["guest:d"].summary
    assert got["export:idp-main"].state == "ok"


def test_drill_records_a_last_failure_newer_than_the_last_verified_fails():
    payload = {
        "guests": {
            "guest:cases": {
                "name": "cases",
                "last_verified": _drill_iso(14 * D),
                "last_failure": _drill_iso(2 * D),
                "failure": "no partition of the restored image is a root filesystem",
                "snapshot": "vm/139/old",
            }
        }
    }
    (d,) = _run(payload, builtin="drill-records")
    assert d.state == "fail" and "FAILED" in d.summary
    assert "no partition" in d.summary and "14d" in d.summary


def test_drill_records_a_never_verified_record_with_a_failure_is_fail_not_unknown():
    payload = {
        "guests": {
            "guest:never": {
                "name": "never",
                "last_failure": _drill_iso(4 * D),
                "failure": "the guest should carry an application export and has none",
            }
        }
    }
    (d,) = _run(payload, builtin="drill-records")
    assert d.state == "fail" and "never verified" in d.summary


def test_drill_records_default_limits_are_30_and_90_days():
    payload = {
        "guests": {
            "guest:a": {"name": "a", "last_verified": _drill_iso(29 * D)},
            "guest:b": {"name": "b", "last_verified": _drill_iso(31 * D)},
            "guest:c": {"name": "c", "last_verified": _drill_iso(91 * D)},
        }
    }
    got = {d.item: d.state for d in _run(payload, builtin="drill-records")}
    assert got == {"guest:a": "ok", "guest:b": "warn", "guest:c": "fail"}


@pytest.mark.parametrize(
    "payload",
    [None, [], "x", {"guests": "x", "services": "x"}, {"other": 1}],
)
def test_drill_records_payload_that_is_not_a_drills_file_is_an_error(payload):
    with pytest.raises(MappingError):
        _run(payload, builtin="drill-records")


def test_drill_records_payload_with_only_services_still_reads():
    payload = {"services": {"idp-realm": {"last_verified": _drill_iso(3 * D)}}}
    (d,) = _run(payload, builtin="drill-records")
    assert d.item == "export:idp-realm" and d.state == "ok"


def test_drill_records_an_unreadable_last_verified_is_a_source_error():
    payload = {"guests": {"guest:a": {"last_verified": "not-a-date"}}}
    with pytest.raises(MappingError):
        _run(payload, builtin="drill-records")
