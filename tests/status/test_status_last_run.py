# SPDX-License-Identifier: Apache-2.0
"""The ``job-last-run`` mapping: the last-run records role timers leave on each host become one
item per job and host -- a failed run is fail, an overdue one warn (judged from the schedule the
record carries) -- and through the hub they date the Schedule page's last run."""

from __future__ import annotations

import json

from status_helpers import spec

from homelabnext.state import StateStore
from homelabnext.status import CollectContext, Scheduler, StatusHub, apply_mapping, due
from homelabnext.status.collectors import COLLECTORS
from homelabnext.status.maps import schedule
from homelabnext.status.model import parse_iso, schema_problems

NOW = parse_iso("2026-10-21T00:00:00Z")
MAPPING = {"builtin": "job-last-run", "module": "jobs"}


def rec(**kw):
    base = {
        "schema": "homelabnext.status.last-run/1",
        "job": "timer:lynis/scan",
        "unit": "hnx-lynis.service",
        "host": "web-1",
        "on_calendar": "*-*-* 04:10:00 UTC",
        "randomized_delay_s": 900,
        "started_at": "2026-10-20T04:17:03Z",
        "finished_at": "2026-10-20T04:19:41Z",
        "running": False,
        "result": "success",
        "exit_code": "exited",
        "exit_status": "0",
    }
    base.update(kw)
    return base


def one(record, mapping=MAPPING):
    (d,) = apply_mapping(record, mapping, now=NOW, fallback_item="job-runs")
    return d


def test_a_finished_run_is_ok_and_says_when_the_next_one_is_due():
    d = one(rec())
    assert (d.item, d.state) == ("timer:lynis/scan@web-1", "ok")
    assert d.value == NOW - parse_iso("2026-10-20T04:17:03Z")  # the run's age dates it
    # next calendar time after the start + the randomized delay + this run's duration
    assert "success; started 2026-10-20T04:17:03Z" in d.summary and "took 2m" in d.summary
    assert d.summary.endswith("next due by 2026-10-21T04:27:38Z")


def test_a_failed_run_is_fail_whatever_its_age():
    d = one(rec(result="exit-code", exit_status="2"))
    assert d.state == "fail" and d.summary.startswith("failed: exit-code (exit status 2);")
    assert one(rec(result="signal", exit_code="killed", exit_status="TERM")).state == "fail"


def test_a_run_whose_next_one_is_overdue_is_warn():
    late = one(rec(started_at="2026-10-18T04:12:00Z", finished_at="2026-10-18T04:13:00Z"))
    assert late.state == "warn"
    assert late.summary.startswith("overdue since 2026-10-19T04:26:00Z: success;")
    # one minute before that deadline it is still ok
    early = apply_mapping(
        rec(started_at="2026-10-18T04:12:00Z", finished_at="2026-10-18T04:13:00Z"),
        MAPPING,
        now=parse_iso("2026-10-19T04:25:59Z"),
        fallback_item="x",
    )[0]
    assert early.state == "ok"


def test_a_running_job_is_ok_until_its_next_run_is_due():
    d = one(rec(started_at="2026-10-20T23:50:00Z", finished_at=None, running=True, result=None))
    assert d.state == "ok" and d.summary.startswith("running since 2026-10-20T23:50:00Z (10m ago)")
    hung = one(rec(started_at="2026-10-19T04:12:00Z", finished_at=None, running=True, result=None))
    assert hung.state == "warn" and hung.summary.startswith("overdue since 2026-10-20T04:25:00Z")


def test_a_calendar_not_read_exactly_falls_back_to_warn_after_s():
    local = rec(on_calendar="daily", started_at="2026-10-20T22:00:00Z")
    d = one(local)
    assert d.state == "ok" and "lateness not judged (calendar 'daily'" in d.summary
    assert one(local, {**MAPPING, "warn_after_s": 3600}).state == "warn"
    assert one(local, {**MAPPING, "warn_after_s": 3 * 3600}).state == "ok"


def test_what_is_not_a_record_is_unknown_never_ok():
    (d,) = apply_mapping(rec(job="lynis scan"), MAPPING, now=NOW, fallback_item="x")
    assert d.state == "unknown" and d.item.startswith("invalid/") and "not a last-run" in d.summary
    assert schema_problems("last_run.schema.json", rec()) == []
    assert schema_problems("last_run.schema.json", rec(host="web-1\n")) != []


def write(path, doc):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")


def test_a_record_directory_one_subdirectory_per_host(tmp_path):
    d = tmp_path / "last-run"
    write(d / "web-1" / "timer-lynis-scan.json", rec())
    write(d / "web-1" / "copy" / "deeper.json", rec())  # two levels down: not read
    write(d / "web-2" / "timer-lynis-scan.json", rec(host="web-2", result="exit-code"))
    write(d / "web-2" / "old-copy.json", rec(host="web-2", started_at="2026-10-01T04:12:00Z"))
    write(d / "web-2" / "broken.json", "{not json")
    write(d / "timer-aide-scan.json", rec(job="timer:aide/scan", unit="hnx-aide.service"))
    s = spec("job-runs", kind="poll-file", file="last-run", path=None, mapping=MAPPING)
    got = {
        x.item: x
        for x in COLLECTORS["poll-file"].collect(
            s, CollectContext(clock=lambda: NOW, root=tmp_path)
        )
    }
    assert sorted(got) == [
        "timer:aide/scan@web-1",
        "timer:lynis/scan@web-1",
        "timer:lynis/scan@web-2",
        "unreadable/web-2/broken.json",
    ]
    assert got["timer:lynis/scan@web-2"].state == "fail"  # the newest record of a host wins
    assert got["unreadable/web-2/broken.json"].state == "unknown"


def test_through_the_hub_the_schedule_dates_the_run_and_names_the_late_host(tmp_path):
    d = tmp_path / "last-run"
    write(d / "web-1" / "a.json", rec())
    write(d / "web-2" / "a.json", rec(host="web-2", started_at="2026-10-18T04:12:00Z",
                                      finished_at="2026-10-18T04:13:00Z"))  # fmt: skip
    s = spec("job-runs", kind="poll-file", file="last-run", path=None, mapping=MAPPING)
    hub = StatusHub([s], StateStore(tmp_path / "state.json", clock=lambda: NOW), clock=lambda: NOW)
    ctx = CollectContext(clock=lambda: NOW, root=tmp_path)
    for result in Scheduler().run(due([s], hub.last_attempts(), NOW), ctx):
        hub.record(result)
    inputs = {"timers": [{"id": "timer:lynis/scan", "owner": "lynis", "what": "Lynis",
                          "path": "x.timer", "calendars": ["*-*-* 04:10:00 UTC"], "delay_s": 900,
                          "problems": []}]}  # fmt: skip
    vm = schedule.build(inputs, now="2026-10-21T00:00:00Z", observations=hub.observations())
    (row,) = vm["groups"][0]["rows"]
    assert (row["last_run"], row["state"], row["hosts"]) == ("2026-10-20T04:17:03Z", "warn", 2)
    (late,) = row["attention"]
    assert late["host"] == "web-2" and late["last_run"] == "2026-10-18T04:12:00Z"
    assert "overdue since 2026-10-19T04:26:00Z" in schedule.render(vm)


def test_a_host_directory_speaks_only_for_its_own_host(tmp_path):
    """web-1 shipping a newer passing record that names web-2 used to hide web-2's failure."""
    d = tmp_path / "last-run"
    write(d / "web-2" / "a.json", rec(host="web-2", result="exit-code"))
    write(d / "web-1" / "mask.json", rec(host="web-2", started_at="2026-10-20T23:59:00Z"))
    s = spec("job-runs", kind="poll-file", file="last-run", path=None, mapping=MAPPING)
    got = {
        x.item: x
        for x in COLLECTORS["poll-file"].collect(
            s, CollectContext(clock=lambda: NOW, root=tmp_path)
        )
    }
    assert got["timer:lynis/scan@web-2"].state == "fail"
    (bad,) = [x for k, x in got.items() if k.startswith("invalid/")]
    assert bad.state == "unknown" and "directory it was shipped to" in bad.summary


def test_a_record_from_the_future_is_unknown_and_masks_nothing():
    future = rec(started_at="2026-10-22T00:00:00Z", finished_at="2026-10-22T00:01:00Z")
    (d,) = apply_mapping(future, MAPPING, now=NOW, fallback_item="x")
    assert d.state == "unknown" and "future" in d.summary
    failed = rec(result="exit-code")
    (d,) = apply_mapping([future, failed], MAPPING, now=NOW, fallback_item="x")
    assert d.state == "fail"  # the real record wins over one dated ahead
    skewed = rec(started_at="2026-10-21T00:04:00Z", finished_at="2026-10-21T00:04:30Z")
    assert apply_mapping(skewed, MAPPING, now=NOW, fallback_item="x")[0].state == "ok"
