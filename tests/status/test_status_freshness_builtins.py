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
