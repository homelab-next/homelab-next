# SPDX-License-Identifier: Apache-2.0
"""The cti-schedules packs (one per old timer) and the cti-watch checks and packs."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from wf_support import ROOT, manifest

from homelabnext.workflows import cti_schedules as cs
from homelabnext.workflows import cti_watch as cw
from homelabnext.workflows import load_doc, pack_digest, run_fixture

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

# the 23 timers on the old host (`systemctl list-timers 'cti-*'`, 2026-11-19)
OLD_TIMERS = {
    "cti-fresh.timer",
    "cti-extract.timer",
    "cti-publish.timer",
    "cti-cve.timer",
    "cti-enrich-honeypot.timer",
    "cti-graph-sync.timer",
    "cti-graph-report.timer",
    "cti-podcast-weekly.timer",
    "cti-podcast-monthly.timer",
    "cti-podcast-quarterly.timer",
    "cti-podcast-semiannual.timer",
    "cti-podcast-yearly.timer",
    "cti-country-landscape.timer",
    *{f"cti-actor-rotation-slot-{n}.timer" for n in range(1, 11)},
}


def test_every_old_timer_maps_to_exactly_one_rule():
    assert len(OLD_TIMERS) == 23
    assert {t[5] for t in cs.TIMERS} == OLD_TIMERS and len(cs.TIMERS) == 23


@pytest.mark.parametrize("lane", cs.LANES)
def test_the_committed_files_are_what_the_table_renders(lane):
    if lane != cs.LANE:  # the tree is committed for the default lane; the other renders cleanly
        for t in cs.TIMERS:
            assert "shadow: true" in cs.render_pack(t, lane)
        return
    for path, text in cs.expected(lane).items():
        assert path.read_text() == text, (
            f"{path.name} drifted: python -m homelabnext.workflows.cti_schedules --write"
        )


def test_the_shadow_lane_sends_shadow_and_the_real_lane_does_not():
    t = cs.TIMERS[0]
    assert "shadow: true" in cs.render_pack(t, "shadow")
    assert "shadow" not in cs.render_pack(t, "real").split("steps:")[1].split("fixtures:")[0]
    with pytest.raises(ValueError):
        cs.render_pack(t, "both")


@pytest.mark.static
def test_each_schedule_pack_validates_pins_and_fires_one_keyed_job():
    deploy = {p["pack"]: p["digest"] for p in load_doc(ROOT / "workflows/deploy.yml")["pins"]}
    for t in cs.TIMERS:
        doc = load_doc(ROOT / "workflows/packs" / f"{cs.pack_name(t[0])}.yml")
        assert deploy[doc["pack"]] == pack_digest(doc)
        step = doc["steps"][0]
        assert (
            step["action"] == "agent.job.submit"
            and step["params"]["idempotency_key"] == "$event.id"
        )
        # the real lane (cs.LANE): the job goes to the live pipeline's units, no shadow flag
        assert step["params"]["agent_key"] == t[2] and "shadow" not in step["params"]
        for fx in doc["fixtures"]:
            res = run_fixture(doc, fx, manifest=manifest())
            assert not res.problems, (doc["pack"], res.problems)


def test_the_site_binding_adds_23_utc_shadow_rules_and_leaves_the_committed_one_alone(tmp_path):
    binding = tmp_path / "binding.yml"
    binding.write_text(cs.binding_text())
    doc = load_doc(binding)
    rules = {r["pack"]: r for r in doc["rules"]}
    ids = []
    for t in cs.TIMERS:
        r = rules[cs.pack_name(t[0])]
        ids.append(r["id"])
        assert r["mode"] == "shadow" and "promotion" not in r
        assert r["schedule"] == {"id": cs.schedule_id(t[0]), "cron": t[1]}
        assert r["coalesce"] == {"key": "$event.data.schedule", "window_s": t[4]}
    assert len(set(ids)) == 23
    # every pre-existing rule is still there, and the committed binding names none of ours: a rendered
    # rule adds files the product-name baseline refuses (docs: "The CTI packs")
    committed = {r["pack"] for r in load_doc(cs.BINDING)["rules"]}
    assert committed <= set(rules) and not any(p.startswith(cs.PREFIX) for p in committed)


def test_every_cron_is_five_utc_fields_digits_only_and_never_restricts_both_day_fields():
    by = {t[0]: t[1] for t in cs.TIMERS}
    assert (
        by["graph-report"].split()[4] == "0" and by["podcast-weekly"].split()[4] == "1"
    )  # Sunday, Monday
    assert by["country-landscape"] == "0 5 1 1,7 *"
    for tid, cron, *_ in cs.TIMERS:
        fields = cron.split()
        assert len(fields) == 5, tid
        _m, _h, dom, _mo, dow = fields
        assert dow.isdigit() or dow == "*", tid  # the engine takes digits, not day names
        # a timer fires on day-of-month AND day-of-week, cron on either: bind only one of them
        assert dom == "*" or dow == "*", tid


def test_the_rotation_slots_are_the_old_ones_in_utc():
    slots = [t[1] for t in cs.TIMERS if t[0].startswith("rotation-")]
    assert slots[0] == "40 11 * * *" and slots[-1] == "22 14 * * *" and len(slots) == 10
    assert slots == sorted(slots, key=lambda c: (int(c.split()[1]), int(c.split()[0])))


# ------------------------------------------------------------------ cti-watch checks
def test_site_stale_fresh_unreadable_and_future():
    fresh = '<script>const DATA={"generated_at":"2026-01-01T11:30:00Z","x":1}</script>'
    old = '{"generated_at": "2026-01-01T08:00:00+00:00"}'
    assert cw.site_check(fresh, NOW)["stale"] is False
    r = cw.site_check(old, NOW)
    assert r["stale"] is True and r["value"] == 4.0
    for bad in (None, "", "<html>no timestamp</html>", '{"generated_at": "soon"}'):
        assert cw.site_check(bad, NOW)["stale"] is True  # could not measure: stale, never fresh
    assert cw.site_check('{"generated_at":"2026-01-02T12:00:00Z"}', NOW)["stale"] is True


def _hourly(per_hour: int, hours: int, skip_last: int = 0):
    top = NOW.replace(minute=0)
    return [(top - timedelta(hours=i), per_hour) for i in range(skip_last, hours)]


def test_lake_healthy_dead_air_drop_and_failed_streak():
    assert cw.lake_check(_hourly(10, 24 * 8), [0, 0, 0], NOW)["stale"] is False
    dead = cw.lake_check(_hourly(10, 24 * 8, skip_last=3), [0, 0, 0], NOW)
    assert dead["stale"] is True and "no new rows" in dead["summary"]
    # rows keep arriving, but a fifth of the normal volume: LL-542's thin rollup
    thin = [(h, 1 if i < 3 else 10) for i, (h, _n) in enumerate(_hourly(10, 24 * 8))]
    r = cw.lake_check(thin, [0], NOW)
    assert r["stale"] is True and "trailing median" in r["summary"]
    # "extracted 0, failed 5" three runs running with the timers green
    r = cw.lake_check(_hourly(10, 24 * 8), [5, 5, 5, 0], NOW)
    assert r["stale"] is True and "failed" in r["summary"]
    assert cw.lake_check(_hourly(10, 24 * 8), [5, 0, 5], NOW)["stale"] is False


def test_lake_with_no_counts_is_an_error_not_a_pass():
    for empty in (None, []):
        assert cw.lake_check(empty, None, NOW)["stale"] is True


def _lines(n, ago_h=0.5, jsonl=True):
    ts = (NOW - timedelta(hours=ago_h)).isoformat()
    if jsonl:
        return "\n".join(
            json.dumps({"ts": ts, "event": "llm-route-fallback", "to": "cli"}) for _ in range(n)
        )
    return "\n".join(f"{ts} WARNING cti.llm llm-route-fallback: local to cli" for _ in range(n))


@pytest.mark.parametrize("jsonl", [True, False])
def test_fallback_counts_above_the_threshold_in_the_window(jsonl):
    assert cw.fallback_check(_lines(5, jsonl=jsonl), NOW)["stale"] is False  # at the threshold
    r = cw.fallback_check(_lines(6, jsonl=jsonl), NOW)
    assert r["stale"] is True and r["value"] == 6
    assert (
        cw.fallback_check(_lines(9, ago_h=5, jsonl=jsonl), NOW)["value"] == 0
    )  # outside the window
    assert cw.fallback_check(_lines(2, jsonl=jsonl), NOW, threshold=1)["stale"] is True


def test_fallback_ignores_other_lines_and_an_unreadable_log_is_stale():
    noise = "info all fine\n" + json.dumps(
        {"ts": NOW.isoformat(), "event": "route", "fallback": False}
    )
    assert cw.fallback_check(noise, NOW)["value"] == 0
    assert cw.fallback_check("", NOW)["stale"] is False
    assert cw.fallback_check(None, NOW)["stale"] is True


def test_the_table_is_keyed_by_each_packs_schedule_id_and_the_cli_exits_on_stale(tmp_path, capsys):
    site = tmp_path / "site.html"
    site.write_text('{"generated_at":"2026-01-01T11:00:00Z"}')
    lake = tmp_path / "lake.json"
    lake.write_text(
        json.dumps(
            {"hourly": [[h.isoformat(), n] for h, n in _hourly(10, 24 * 8)], "extract_failed": [0]}
        )
    )
    log = tmp_path / "route.log"
    log.write_text(_lines(1))
    argv = [
        "--now",
        NOW.isoformat(),
        "--site-file",
        str(site),
        "--lake-json",
        str(lake),
        "--route-log",
        str(log),
    ]
    assert cw.main(argv) == 0
    table = json.loads(capsys.readouterr().out)
    assert set(table) == {"cti-watch-site", "cti-watch-lake", "cti-watch-fallback"}
    assert all(r["stale"] is False for r in table.values())
    log.write_text(_lines(20))
    assert cw.main(argv) == 1
    assert json.loads(capsys.readouterr().out)["cti-watch-fallback"]["stale"] is True


# ------------------------------------------------------------------ cti-watch packs
@pytest.mark.parametrize(
    "name,action", [("site", "notify.page"), ("lake", "notify.page"), ("fallback", "notify.post")]
)
def test_watch_packs_validate_and_notify_only_on_a_stale_row(name, action):
    doc = load_doc(ROOT / "workflows/packs" / f"cti-watch-{name}.yml")
    assert doc["steps"][1]["action"] == action
    assert doc["trigger"]["where"][0]["equals"] == f"cti-watch-{name}"
    quiet = next(f for f in doc["fixtures"] if f["name"] == "fresh-is-quiet")
    assert run_fixture(doc, quiet, manifest=manifest()).calls == []
    for fx in doc["fixtures"]:
        assert not run_fixture(doc, fx, manifest=manifest()).problems
    # the pack is a reference pack, as new-critical-alert is: not pinned or bound until something
    # writes its table (table:cti.watch) as a file a binding can declare (docs/stackstorm.md, Tables)
    assert doc["pack"] not in {p["pack"] for p in load_doc(ROOT / "workflows/deploy.yml")["pins"]}


# ------------------------------------------------------------------ follow-up: literal expectations
# (rule id, UTC cron, agent key), written out by hand and independent of cti_schedules.TIMERS, so a
# wrong regeneration (a table edit and `--write`) fails here instead of quietly shipping.
EXPECTED_RULES = [
    ("C01", "0 * * * *", "cti-fresh"),
    ("C02", "20 * * * *", "cti-publish"),
    ("C03", "10 */4 * * *", "cti-extract"),
    ("C04", "0 14 * * *", "cti-cve"),
    ("C05", "30 21 * * *", "cti-enrich-honeypot"),
    ("C06", "0 13 * * *", "cti-graph-sync"),
    ("C07", "30 13 * * 0", "cti-graph-report"),
    ("C08", "40 11 * * *", "cti-rotation"),
    ("C09", "58 11 * * *", "cti-rotation"),
    ("C10", "16 12 * * *", "cti-rotation"),
    ("C11", "34 12 * * *", "cti-rotation"),
    ("C12", "52 12 * * *", "cti-rotation"),
    ("C13", "10 13 * * *", "cti-rotation"),
    ("C14", "28 13 * * *", "cti-rotation"),
    ("C15", "46 13 * * *", "cti-rotation"),
    ("C16", "4 14 * * *", "cti-rotation"),
    ("C17", "22 14 * * *", "cti-rotation"),
    ("C18", "0 0 * * 1", "cti-podcast-weekly"),
    ("C19", "0 0 1 * *", "cti-podcast-monthly"),
    ("C20", "0 2 1 * *", "cti-podcast-quarterly"),
    ("C21", "0 4 1 * *", "cti-podcast-semiannual"),
    ("C22", "0 6 1 * *", "cti-podcast-yearly"),
    ("C23", "0 5 1 1,7 *", "cti-country-landscape"),
]


def test_the_23_rules_match_the_literal_expectations(tmp_path):
    binding = tmp_path / "b.yml"
    binding.write_text(cs.binding_text())
    ours = [r for r in load_doc(binding)["rules"] if r["pack"].startswith(cs.PREFIX)]
    assert [(r["id"], r["schedule"]["cron"]) for r in ours] == [
        (i, c) for i, c, _ in EXPECTED_RULES
    ]
    for r, (_i, cron, agent) in zip(ours, EXPECTED_RULES, strict=True):
        doc = load_doc(ROOT / "workflows/packs" / f"{r['pack']}.yml")
        assert doc["steps"][0]["params"]["agent_key"] == agent
        assert doc["trigger"]["where"][0]["equals"] == r["schedule"]["id"]
        assert f"`{cron}`" in (ROOT / "workflows/packs" / f"{r['pack']}.yml").read_text()


# ------------------------------------------------------------------ follow-up: cti-watch hardening
def test_site_reads_the_top_level_generated_at_of_the_embedded_data():
    stale_top = (
        '<script>const DATA = {"runs": [{"generated_at": "2026-01-01T11:59:00Z"}], '
        '"generated_at": "2026-01-01T06:00:00Z"};</script>'
    )
    assert cw.site_check(stale_top, NOW)["stale"] is True  # the nested fresh one must not stand in
    assert cw.site_check(stale_top, NOW)["value"] == 6.0
    nested_only = (
        '<script>const DATA = {"runs": [{"generated_at": "2026-01-01T11:59:00Z"}]};</script>'
    )
    assert cw.site_check(nested_only, NOW)["stale"] is True  # no top-level one at all
    assert (
        cw.site_check('const DATA = {"generated_at": "2026-01-01T11:30:00Z"}', NOW)["stale"]
        is False
    )
    assert cw.site_check('{"x": {"generated_at": "2026-01-01T11:30:00Z"}}', NOW)["stale"] is True


def test_lake_without_extract_failed_fails_closed(tmp_path, capsys):
    assert cw.lake_check(_hourly(10, 24 * 8), None, NOW)["stale"] is True
    lake = tmp_path / "lake.json"
    lake.write_text(json.dumps({"hourly": [[h.isoformat(), n] for h, n in _hourly(10, 24 * 8)]}))
    cw.main(["--now", NOW.isoformat(), "--lake-json", str(lake)])
    assert json.loads(capsys.readouterr().out)["cti-watch-lake"]["stale"] is True


def test_the_lake_query_is_utc_and_the_schema_is_an_identifier():
    sql = cw.lake_rows_sql("cti")
    assert "at_timezone(ingested_at, 'UTC')" in sql and "{" not in sql
    for bad in ("cti; DROP TABLE x", "cti.reporting", "Cti", "", "a b", "cti\n", "1cti", None):
        with pytest.raises(ValueError):
            cw.lake_rows_sql(bad)
