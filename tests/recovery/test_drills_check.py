# SPDX-License-Identifier: Apache-2.0
"""``hnx recovery drills check``: stale, failing, never-drilled and overdue records."""

from __future__ import annotations

import datetime
import json

import pytest

from homelabnext.recovery import drills

NOW = "2026-11-22T12:00:00Z"
D30, D90 = datetime.timedelta(days=30), datetime.timedelta(days=90)


def now():
    return drills._ts(NOW)


def ago(days):
    return (now() - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def states(doc, **kw):
    return {i: s for i, s, _ in drills.check(doc, now(), D30, D90, **kw)}


def test_recent_overdue_stale_and_never_verified_are_ok_warn_fail_fail():
    doc = {
        "guests": {
            "a": {"last_verified": ago(3)},
            "b": {"last_verified": ago(45)},
            "c": {"last_verified": ago(120)},
            "d": {"last_failure": ago(1)},
        }
    }
    assert states(doc) == {"a": "ok", "b": "warn", "c": "fail", "d": "fail"}


def test_a_failure_after_the_last_verified_drill_fails_and_a_verified_one_after_a_failure_recovers():
    assert states(
        {"guests": {"a": {"last_verified": ago(5), "last_failure": ago(1), "failure": "x"}}}
    ) == {"a": "fail"}
    assert states({"guests": {"a": {"last_verified": ago(1), "last_failure": ago(5)}}}) == {
        "a": "ok"
    }


def test_a_required_guest_with_no_record_fails():
    assert states({"guests": {}}, require=["guest:x"]) == {"guest:x": "fail"}


def test_export_restores_are_required_and_a_stale_one_is_a_warning_not_a_fail():
    doc = {
        "guests": {"a": {"last_verified": ago(1)}},
        "services": {"db": {"last_verified": ago(2)}, "old": {"last_verified": ago(200)}},
    }
    got = states(doc, require_export=1)
    assert got["export:db"] == "ok" and got["export:old"] == "warn" and "export-restores" not in got
    assert (
        states({"guests": {"a": {"last_verified": ago(1)}}}, require_export=1)["export-restores"]
        == "fail"
    )


@pytest.mark.parametrize("doc", [[], {}, {"guests": []}, "x"])
def test_records_with_no_guests_mapping_are_an_error_not_a_pass(doc):
    with pytest.raises(ValueError):
        drills.check(doc, now(), D30, D90)


def run(tmp_path, doc, *extra):
    p = tmp_path / "drills.json"
    p.write_text(json.dumps(doc))
    return drills.main(["check", "--records", str(p), "--now", NOW, *extra])


def test_the_command_exits_by_the_worst_row_and_strict_counts_warnings(tmp_path, capsys):
    ok = {"guests": {"a": {"last_verified": ago(2)}}}
    assert run(tmp_path, ok) == 0
    warn = {"guests": {"a": {"last_verified": ago(40)}}}
    assert run(tmp_path, warn) == 0 and run(tmp_path, warn, "--strict") == 1
    assert run(tmp_path, {"guests": {"a": {"last_verified": ago(95)}}}) == 1
    assert "FAIL" in capsys.readouterr().out


def test_a_missing_file_a_bad_duration_or_a_bad_time_is_a_usage_error(tmp_path):
    assert drills.main(["check", "--records", str(tmp_path / "no.json")]) == 2
    assert run(tmp_path, {"guests": {}}, "--max-age", "90") == 2
    assert drills.main(["check", "--records", str(tmp_path / "x"), "--now", "yesterday"]) == 2
