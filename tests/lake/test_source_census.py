# SPDX-License-Identifier: Apache-2.0
"""The source census (``homelabnext.lake.census``; ADR-0049 decision 9) over the in-memory lake.

Every case writes a raw-archive-shaped table (time, source, decoder), fixes the clock and reads
the verdict.  The census never learns a source's cadence from a blanket rule: a daily source is
not stale after 30 hours and an hourly one is stale after ten.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest

from homelabnext.lake import FakeLake
from homelabnext.lake.census import (
    Ack,
    CensusConfig,
    CensusError,
    Expected,
    census,
    config_from,
    dark,
)
from homelabnext.lake.cli import fixture_schema
from homelabnext.lake.dialect import hour_expr

NOW = datetime(2026, 7, 31, 22, 30, tzinfo=UTC)
HOUR = timedelta(hours=1)


def lake_with(*sources) -> FakeLake:
    """``sources``: (source, decoder, [hours ago an event arrived])."""
    lake = FakeLake([fixture_schema("raw_archive", ("location", "decoder_name"), "time")])
    rows, n = [], 0
    for src, dec, ago in sources:
        for h in ago:
            n += 1
            rows.append(
                {
                    "uid": f"u{n}",
                    "time": NOW - timedelta(hours=h) + timedelta(minutes=1),
                    "location": src,
                    "decoder_name": dec,
                }
            )
    if rows:
        lake.write_batch("raw_archive", rows, idempotency_key="seed")
    return lake


def run_census(lake, cfg=None, now=NOW):
    return census(lake.query, lake, cfg or CensusConfig(), now=now)


def by_name(report, name):
    (r,) = [r for r in report.results if r.name == name]
    return r


EVERY_HOUR_8D = range(1, 8 * 24)  # an event every hour for the whole window


def test_a_continuous_source_within_its_cadence_is_ok():
    rep = run_census(lake_with(("auth.log", "sshd", EVERY_HOUR_8D)))
    r = by_name(rep, "auth.log / sshd")
    assert r.status == "OK" and r.cadence_hours == 1.0
    assert rep.status == "pass"


def test_a_continuous_source_silent_for_ten_hours_is_stale_and_fails():
    rep = run_census(lake_with(("auth.log", "sshd", range(10, 8 * 24))))
    r = by_name(rep, "auth.log / sshd")
    assert r.status == "STALE" and r.silence_hours > 8
    assert rep.status == "fail" and "[STALE] auth.log / sshd" in rep.evidence()


def test_each_source_is_judged_by_its_own_cadence():
    daily = list(range(30, 8 * 24, 24))  # one event a day, last one 30 h ago
    rep = run_census(
        lake_with(("scan.jsonl", "scanner", daily), ("auth.log", "sshd", EVERY_HOUR_8D))
    )
    r = by_name(rep, "scan.jsonl / scanner")
    assert r.cadence_hours == 24.0
    # 30 hours of silence is routine for a daily source (a blanket 24 h rule would flag it)
    assert r.status == "OK"
    assert rep.status == "pass"


def test_a_daily_source_silent_for_four_days_is_stale():
    daily = list(range(96, 8 * 24, 24))
    rep = run_census(lake_with(("scan.jsonl", "scanner", daily)))
    assert by_name(rep, "scan.jsonl / scanner").status == "STALE"


def test_a_young_source_is_learning_passes_and_the_report_warns():
    rep = run_census(lake_with(("new.log", "app", range(1, 48))))
    r = by_name(rep, "new.log / app")
    assert r.status == "LEARNING" and not r.failing
    assert rep.status == "warn"
    assert "still learning" in rep.evidence() and "new.log / app" in rep.evidence()


def test_a_learning_source_that_arrived_three_times_and_is_silent_past_the_floor_fails():
    rep = run_census(lake_with(("new.log", "app", [60, 61, 62])))
    r = by_name(rep, "new.log / app")
    assert r.status == "LEARNING-STALE" and r.failing
    assert rep.status == "fail"


def test_a_learning_source_with_fewer_arrivals_is_not_failed():
    rep = run_census(lake_with(("new.log", "app", [60, 61])))
    assert by_name(rep, "new.log / app").status == "LEARNING"


def test_the_floor_is_overlay_settable():
    cfg = CensusConfig(floor_hours=100)
    rep = run_census(lake_with(("new.log", "app", [60, 61, 62])), cfg)
    assert by_name(rep, "new.log / app").status == "LEARNING"


def test_an_acknowledged_quiet_source_passes_until_its_expiry():
    lake = lake_with(("auth.log", "sshd", range(30, 8 * 24)))
    ack = Ack(
        "platform-team",
        "the host is off for repair",
        NOW.date() + timedelta(days=3),
        match={"location": "auth.log"},
    )
    rep = run_census(lake, CensusConfig(acknowledged=(ack,)))
    r = by_name(rep, "auth.log / sshd")
    assert r.status == "ACKNOWLEDGED" and "platform-team" in r.detail
    assert rep.status == "pass"
    expired = Ack(
        "platform-team",
        "the host is off for repair",
        NOW.date() - timedelta(days=1),
        match={"location": "auth.log"},
    )
    rep = run_census(lake, CensusConfig(acknowledged=(expired,)))
    r = by_name(rep, "auth.log / sshd")
    assert r.status == "STALE" and "expired" in r.detail and rep.status == "fail"


def test_the_ack_covers_the_day_it_expires():
    ack = Ack("o", "r", NOW.date(), match={"location": "auth.log"})
    rep = run_census(
        lake_with(("auth.log", "sshd", range(30, 8 * 24))), CensusConfig(acknowledged=(ack,))
    )
    assert rep.status == "pass"


def test_a_declared_source_that_never_arrived_is_missing():
    cfg = CensusConfig(
        expected=(Expected("Scanner export", {"location": "/var/log/scan.json"}, 168, 2),)
    )
    rep = run_census(lake_with(("auth.log", "sshd", EVERY_HOUR_8D)), cfg)
    r = by_name(rep, "Scanner export")
    assert r.status == "MISSING" and rep.status == "fail"


def test_a_declared_source_matches_by_file_name_and_fragment_not_one_exact_path():
    cfg = CensusConfig(
        expected=(
            Expected(
                "Edge access log",
                {"location": {"suffix": "/access.log", "contains": "/edge/"}},
                1,
                3,
            ),
        )
    )
    # the producer moved its directory layout; the name and the fragment survived
    rows = [
        ("/var/log/edge/site-a/access.log", None, range(1, 8 * 24)),
        ("/var/log/other/access.log", None, [1]),
    ]
    rep = run_census(lake_with(*rows), cfg)
    assert by_name(rep, "Edge access log").status == "OK"
    # the unmatched file is a learned source of its own, not claimed by the declaration
    assert by_name(rep, "/var/log/other/access.log / (none)").status == "LEARNING"


def test_a_declared_source_is_never_learning_and_uses_its_declared_grace():
    cfg = CensusConfig(expected=(Expected("Weekly scan", {"location": "scan"}, 168, 2),))
    rep = run_census(
        lake_with(("scan", None, [150, 151])), cfg
    )  # a learned source this young would be LEARNING
    r = by_name(rep, "Weekly scan")
    assert r.status == "OK"  # 149 h of silence is inside 2 x 168 h
    rep = run_census(
        lake_with(("scan", None, [100, 101])),
        CensusConfig(expected=(Expected("Weekly scan", {"location": "scan"}, 24, 2),)),
    )
    assert by_name(rep, "Weekly scan").status == "STALE"  # 99 h of silence against 2 x 24 h


def test_an_ack_can_cover_a_declared_source_by_name():
    cfg = CensusConfig(
        expected=(Expected("Weekly scan", {"location": "scan"}, 24, 1),),
        acknowledged=(
            Ack(
                "o", "scanner retired next week", NOW.date() + timedelta(days=2), name="Weekly scan"
            ),
        ),
    )
    rep = run_census(lake_with(("scan", None, [100])), cfg)
    assert by_name(rep, "Weekly scan").status == "ACKNOWLEDGED"


def test_nothing_arrived_is_a_failure_not_a_vacuous_pass():
    rep = run_census(lake_with())
    assert rep.status == "fail" and "no source arrived" in rep.evidence()


def test_a_missing_table_is_could_not_measure():
    lake = FakeLake([fixture_schema("other", ("location", "decoder_name"), "time")])
    with pytest.raises(CensusError, match="cannot read raw_archive"):
        run_census(lake)


def test_a_source_column_that_is_not_a_source_is_refused_not_truncated():
    lake = lake_with(("a", "x", range(1, 60)), ("b", "y", range(1, 60)))
    with pytest.raises(CensusError, match="more than 3"):
        run_census(lake, CensusConfig(max_groups=3))


def test_two_hours_in_a_group_count_once_and_arrivals_are_summed():
    rep = run_census(lake_with(("a", "x", [1, 1, 2])))
    assert by_name(rep, "a / x").arrivals == 3


@pytest.mark.parametrize(
    "kw",
    [
        {"table": 'raw"; DROP TABLE x; --'},
        {"source_columns": ("location", "dec oder")},
        {"time_column": "time;"},
        {"source_columns": ()},
        {"window_days": 1},
        {"multiple": 0.5},
        {"learning_min_arrivals": 0},
        {"expected": (Expected("x", {"nope": "v"}, 1, 1),)},
        {"expected": (Expected("x", {"location": {"regex": ".*"}}, 1, 1),)},
        {"expected": (Expected("x", {"location": "v"}, 0, 1),)},
        {"acknowledged": (Ack("", "why", date(2030, 1, 1), match={"location": "v"}),)},
        {"acknowledged": (Ack("o", "why", date(2030, 1, 1), name="undeclared"),)},
        {"acknowledged": (Ack("o", "why", date(2030, 1, 1)),)},
    ],
)
def test_bad_settings_are_refused(kw):
    with pytest.raises(CensusError):
        CensusConfig(**kw)


def test_config_from_a_parsed_document():
    cfg = config_from(
        {
            "table": "raw_archive",
            "source_columns": ["location", "decoder_name"],
            "window_days": 8,
            "expected": [
                {
                    "name": "Edge",
                    "match": {"location": {"suffix": "/access.log"}},
                    "cadence_hours": 1,
                    "grace": 3,
                }
            ],
            "acknowledged": [
                {"name": "Edge", "owner": "o", "reason": "r", "expires": "2030-01-02"}
            ],
        }
    )
    assert cfg.expected[0].name == "Edge" and cfg.acknowledged[0].expires == date(2030, 1, 2)
    with pytest.raises(CensusError, match="unknown census setting"):
        config_from({"tabel": "x"})
    with pytest.raises(CensusError, match="KeyError"):
        config_from({"expected": [{"name": "x"}]})


def test_the_hour_bucket_is_the_same_text_in_both_dialects():
    assert hour_expr("json-text", '"time"') == hour_expr("struct", '"time"')
    with pytest.raises(Exception, match="unknown SQL dialect"):
        hour_expr("nope", '"time"')


# ------------------------------------------------------------------ all classes dark
def test_all_classes_dark_fails_on_an_empty_lake_during_learning():
    d = dark(lake_with().query, ["raw_archive"], now=NOW)
    assert d.dark and "no event in any of raw_archive" in d.evidence()


def test_all_classes_dark_passes_when_any_table_has_an_event():
    lake = FakeLake(
        [
            fixture_schema("raw_archive", ("location", "decoder_name"), "time"),
            fixture_schema("detections", ("location", "decoder_name"), "time"),
        ]
    )
    lake.write_batch(
        "detections",
        [{"uid": "a", "time": NOW - timedelta(hours=3), "location": "x", "decoder_name": "y"}],
        idempotency_key="k",
    )
    d = dark(lake.query, ["raw_archive", "detections"], now=NOW)
    assert not d.dark and d.tables == (("raw_archive", False), ("detections", True))


def test_all_classes_dark_window_is_its_own():
    lake = lake_with(("a", "b", [30]))
    assert dark(lake.query, ["raw_archive"], now=NOW, hours=24).dark
    assert not dark(lake.query, ["raw_archive"], now=NOW, hours=48).dark


def test_all_classes_dark_refuses_bad_input():
    with pytest.raises(CensusError):
        dark(lake_with().query, [], now=NOW)
    with pytest.raises(CensusError):
        dark(lake_with().query, ["x y"], now=NOW)
    with pytest.raises(CensusError, match="cannot read nope"):
        dark(lake_with().query, ["nope"], now=NOW)


@pytest.mark.static
def test_the_census_reads_only_columns_the_raw_archive_schema_has():
    """The fixture is the lake-writer module's raw_archive schema as of its PR; the census's
    defaults (table, time and source columns) must all exist in it."""
    import json
    from pathlib import Path

    doc = json.loads(
        (Path(__file__).parent / "fixtures" / "lake_writer_raw_archive.v1.json").read_text()
    )
    cfg = CensusConfig()
    assert doc["x-lake"]["table"] == cfg.table
    assert doc["x-lake"]["time_column"] == cfg.time_column
    cols = set(doc["properties"])
    assert {cfg.time_column, *cfg.source_columns} <= cols
    assert set(cfg.source_columns) <= set(doc["required"]) | {"decoder_name"}
