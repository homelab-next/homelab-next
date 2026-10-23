# SPDX-License-Identifier: Apache-2.0
"""The directory pages of the hub (Links, Schedule, Agent roster): the calendar reader, each
page's view-model and HTML (goldens over small synthetic inputs), escaping, the repository's own
data, and the hub wiring (menu group, serve routes, static render)."""

from __future__ import annotations

import json
import threading
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_maps import as_json, assert_safe, golden

from homelabnext.mcp import servers
from homelabnext.registry.model import load
from homelabnext.status.cli import main
from homelabnext.status.maps import MapSite, cadence, links, mcp, roster, schedule
from homelabnext.status.model import sources_from_registry
from homelabnext.status.views import build_status, load_views

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "examples" / "services.yml"
VIEWS = ROOT / "examples" / "status" / "views.yml"
FIX = Path(__file__).parent / "fixtures" / "maps" / "directory"
NOW = "2026-10-21T00:00:00Z"


def _at(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


# ------------------------------------------------------------------------------ cadence
@pytest.mark.parametrize(
    ("expr", "dialect", "words", "after", "nxt"),
    [
        ("17 3 * * *", "cron", "daily at 03:17 UTC", NOW, "2026-10-21T03:17:00Z"),
        ("41 4 * * 1", "cron", "weekly on Monday at 04:41 UTC", NOW, "2026-10-26T04:41:00Z"),
        ("0 9 * * 7", "cron", "weekly on Sunday at 09:00 UTC", NOW, "2026-10-25T09:00:00Z"),
        ("30 6 * * 1-5", "cron", "weekdays at 06:30 UTC", NOW, "2026-10-21T06:30:00Z"),
        ("*/15 * * * *", "cron", "every 15 minutes", "2026-10-21T00:07:00Z", "2026-10-21T00:15:00Z"),
        ("5 * * * *", "cron", "every hour at minute 05", "2026-10-21T00:05:00Z", "2026-10-21T01:05:00Z"),
        ("0 0 1 * *", "cron", "monthly on day 1 at 00:00 UTC", NOW, "2026-11-01T00:00:00Z"),
        # cron: a restricted day-of-month OR a restricted weekday (2026-10-23 is a Friday)
        ("0 12 25 * 5", "cron", "on a calendar (at 12:00 UTC)", NOW, "2026-10-23T12:00:00Z"),
        ("*-*-* 05:20:00 UTC", "systemd", "daily at 05:20 UTC", NOW, "2026-10-21T05:20:00Z"),
        ("Sun *-*-* 02:50:00 UTC", "systemd", "weekly on Sunday at 02:50 UTC", NOW,
         "2026-10-25T02:50:00Z"),
        ("Mon..Fri *-*-* 06:00 UTC", "systemd", "weekdays at 06:00 UTC", "2026-10-24T07:00:00Z",
         "2026-10-26T06:00:00Z"),
        ("*-*-* *:0/30:00 UTC", "systemd", "every 30 minutes", "2026-10-21T00:30:00Z",
         "2026-10-21T01:00:00Z"),
        ("Sat,Sun *-*-01 00:00:30 UTC", "systemd", "on a calendar (at 00:00:30 UTC)", NOW,
         "2026-11-01T00:00:30Z"),
    ],
)  # fmt: skip
def test_calendars_in_plain_words_and_their_next_run(expr, dialect, words, after, nxt):
    said, cal = cadence.describe(expr, dialect)
    assert said == words and cal is not None
    assert cadence.next_run(cal, _at(after)).strftime("%Y-%m-%dT%H:%M:%SZ") == nxt


@pytest.mark.parametrize(
    ("expr", "dialect", "words"),
    [
        ("daily", "systemd", "daily, in the host's local time zone"),
        ("*-*-* 02:00", "systemd", "*-*-* 02:00 (no UTC token: the host's local time zone)"),
        ("*-*-* 02:00 Europe/Berlin", "systemd",
         "*-*-* 02:00 Europe/Berlin (no UTC token: the host's local time zone)"),
        ("2026-*-* 02:00 UTC", "systemd", "2026-*-* 02:00 UTC (outside the subset this page reads)"),
        ("@daily", "cron", "cron @daily (UTC), outside the subset this page reads"),
        ("61 * * * *", "cron", "cron 61 * * * * (UTC), outside the subset this page reads"),
        ("0 0 31 2 *", "cron", "on a calendar (at 00:00 UTC)"),
    ],
)  # fmt: skip
def test_what_cannot_be_read_exactly_has_no_next_run(expr, dialect, words):
    said, cal = cadence.describe(expr, dialect)
    assert said == words
    assert cal is None or cadence.next_run(cal, _at(NOW)) is None  # Feb 31 never comes


def test_interval_words():
    assert [cadence.interval_words(s) for s in (30, 60, 120, 300, 3600, 5400, 86400)] == [
        "every 30 seconds", "every minute", "every 2 minutes", "every 5 minutes", "every hour",
        "every 90 minutes", "every day"]  # fmt: skip


# -------------------------------------------------------------------------------- links
def test_links_view_model_and_page_match_their_goldens():
    reg = load(FIX / "services.yml")
    vm = links.build(reg)
    assert [z["zone"] for z in vm["zones"]] == ["mgmt", "data"]  # registry order, empty skipped
    rows = {r["name"]: r for z in vm["zones"] for r in z["services"]}
    assert rows["board"]["private_tier"] and not rows["login"]["private_tier"]
    assert (
        rows["board"]["href"] == "https://board.lab.example/"
        and rows["board"]["access"] == "public"
    )
    assert rows["query"]["access"] == "lab only" and rows["query"]["href"].startswith(
        "https://lake-query.svc."
    )
    assert rows["query"]["mcp"]["href"].endswith("/mcp") and rows["query"]["health"] is None
    assert rows["db"]["href"] is None and rows["db"]["endpoint"].startswith(
        "postgres://records-db.svc."
    )
    assert vm["counts"] == {"services": 4, "web": 3, "public": 2, "private_tier": 1}
    golden("links.json", as_json(vm))
    html = links.render(vm)
    assert_safe(html)
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; the board" in html
    assert '<span class="s stale">private tier</span>' in html
    # no address is ever written: every link is a registry name (public hostname or alias)
    assert not any(h.address in html for h in reg.hosts.values())
    golden("links.html", html)


def test_links_of_the_example_registry_name_every_service_and_no_address():
    reg = load(REGISTRY)
    vm = links.build(reg)
    assert sorted(r["name"] for z in vm["zones"] for r in z["services"]) == sorted(reg.services)
    html = links.render(vm)
    assert not any(h.address in html for h in reg.hosts.values())
    tiers = {r["name"] for z in vm["zones"] for r in z["services"] if r["private_tier"]}
    assert tiers == {n for n, s in reg.services.items() if s.front_door}


# ----------------------------------------------------------------------------- schedule
SCHEDULE_INPUTS = {
    "timers": [
        {"id": "timer:scan/run", "owner": "scan", "what": "Nightly scan", "path": "r/run.timer",
         "calendars": ["*-*-* 04:10:00 UTC"], "delay_s": 900, "problems": []},
        {"id": "timer:local/tick", "owner": "local", "what": "Local tick", "path": "r/tick.timer",
         "calendars": ["*-*-* 02:00"], "delay_s": None, "problems": ["r/tick.timer: OnBootSec= is not a calendar; the next run is not computed"]},
    ],
    "fleet_units": [
        {"id": "fleet-unit:compact", "what": "Compact", "calendars": ["Sun *-*-* 01:00:00 UTC"],
         "delay_s": None, "retired": None, "path": "fleet_units.yml"},
        {"id": "fleet-unit:old", "what": "Old", "calendars": ["*-*-* 01:00:00 UTC"],
         "delay_s": None, "retired": "st2:pack.sweep", "path": "fleet_units.yml"},
    ],
    "ci": [{"id": "ci:nightly", "what": "nightly", "crons": ["17 3 * * *"], "jobs": ["smoke"],
            "path": ".github/workflows/nightly.yml"}],
    "packs": [{"id": "pack:page", "what": "Pages on <b>alerts</b>", "event": "homelabnext.alert.created",
               "actor": "profile:fixer", "path": "workflows/packs/page.yml"}],
    "scripts": {"timer:scan/run": ["scan-run"], "ci:nightly/smoke": ["lab-smoke"]},
    "collectors": [
        {"id": "alerts", "kind": "poll-prometheus", "service": "metrics", "interval_s": 60,
         "stale_after_s": 180, "what": "Firing alerts"},
        {"id": "runs", "kind": "push-event", "service": "runtime", "interval_s": 300,
         "stale_after_s": 900, "what": "Pushed run outcomes"},
        {"id": "never", "kind": "poll-file", "service": "records", "interval_s": 3600,
         "stale_after_s": 10800, "what": "Not read yet"},
    ],
}  # fmt: skip
SOURCES = [
    {"id": "alerts", "state": "ok", "last_attempt": "2026-10-20T23:59:30Z", "last_ok": "2026-10-20T23:59:30Z"},
    {"id": "runs", "state": "stale", "last_attempt": None, "last_ok": "2026-10-20T20:00:00Z"},
]  # fmt: skip
OBSERVATIONS = [
    {"source": "jobs", "module": "jobs", "item": "timer:scan/run", "state": "ok",
     "observed_at": "2026-10-20T04:21:00Z"},
    {"source": "jobs", "module": "jobs", "item": "timer:scan/run", "state": "fail",
     "observed_at": "2026-10-19T04:20:00Z"},
    # what the job-last-run mapping reports: one item per host, value = the run's age
    {"source": "job-runs", "module": "jobs", "item": "fleet-unit:compact@web-1", "state": "ok",
     "summary": "success; started 2026-10-18T01:00:00Z", "observed_at": "2026-10-20T23:55:00Z",
     "value": 255300},
    {"source": "job-runs", "module": "jobs", "item": "fleet-unit:compact@web-2", "state": "warn",
     "summary": "overdue since 2026-10-11T01:00:00Z: success; started 2026-10-04T01:00:00Z",
     "observed_at": "2026-10-20T23:55:00Z", "value": 1465500},
]  # fmt: skip


def test_schedule_view_model_and_page_match_their_goldens():
    vm = schedule.build(SCHEDULE_INPUTS, now=NOW, sources=SOURCES, observations=OBSERVATIONS)
    rows = {r["id"]: r for g in vm["groups"] for r in g["rows"]}
    scan = rows["timer:scan/run"]
    assert scan["cadence"] == "daily at 04:10 UTC, up to 15 minutes later (randomized)"
    assert (scan["next_run"], scan["last_run"], scan["state"]) == (
        "2026-10-21T04:10:00Z",
        "2026-10-20T04:21:00Z",
        "ok",
    )  # the newest observation wins
    assert scan["runs"] == ["scan-run"] and rows["ci:nightly"]["runs"] == ["lab-smoke"]
    assert rows["timer:local/tick"]["next_run"] is None  # a local-time calendar: not computed
    assert rows["fleet-unit:compact"]["next_run"] == "2026-10-25T01:00:00Z"
    # per-host reports: the newest run (observed_at less its age), the worst state, who is late
    compact = rows["fleet-unit:compact"]
    assert (compact["last_run"], compact["state"], compact["hosts"]) == (
        "2026-10-18T01:00:00Z", "warn", 2)  # fmt: skip
    assert [a["host"] for a in compact["attention"]] == ["web-2"]
    assert (rows["fleet-unit:old"]["last_run"], rows["fleet-unit:old"]["hosts"]) == (None, 0)
    assert rows["fleet-unit:old"]["cadence"] == "retired: replaced by st2:pack.sweep"
    assert rows["fleet-unit:old"]["next_run"] is None
    assert rows["pack:page"]["cadence"] == "on each homelabnext.alert.created event"
    # collectors: the last poll and the next one due; a pushed source has no next run
    assert (rows["status:alerts"]["last_run"], rows["status:alerts"]["next_run"]) == (
        "2026-10-20T23:59:30Z", "2026-10-21T00:00:30Z")  # fmt: skip
    assert (
        rows["status:runs"]["cadence"] == "pushed by the service; stale after 15 minutes of silence"
    )
    assert (rows["status:runs"]["last_run"], rows["status:runs"]["next_run"]) == (
        "2026-10-20T20:00:00Z",
        None,
    )
    assert rows["status:never"]["last_run"] is None and rows["status:never"]["next_run"] is None
    assert vm["problems"] == SCHEDULE_INPUTS["timers"][1]["problems"]
    golden("schedule.json", as_json(vm))
    html = schedule.render(vm)
    assert_safe(html)
    assert "Pages on &lt;b&gt;alerts&lt;/b&gt;" in html and "not reported" in html
    assert "2 hosts" in html and "web-2: overdue since 2026-10-11T01:00:00Z" in html
    golden("schedule.html", html)


def test_schedule_without_a_time_computes_no_next_run():
    vm = schedule.build(SCHEDULE_INPUTS)
    assert {r["next_run"] for g in vm["groups"] for r in g["rows"]} == {None}
    assert "next runs are not computed" in schedule.render(vm)


def _checkout(tmp: Path) -> Path:
    def put(rel: str, text: str) -> None:
        (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp / rel).write_text(text, encoding="utf-8")

    put("ansible/roles/scan/defaults/main.yml", 'scan_schedule: "*-*-* 04:10:00 UTC"\n')
    put("ansible/roles/scan/vars/main.yml", "scan_other: 1\n")
    put("ansible/roles/scan/templates/run.timer.j2",
        "[Unit]\nDescription=Nightly scan\n[Timer]\nOnCalendar={{ scan_schedule }}\n"
        "RandomizedDelaySec=15min\n")  # fmt: skip
    put("ansible/roles/scan/templates/run.service.j2", "[Service]\nExecStart=/bin/true\n")
    put("ansible/roles/good/templates/tick.timer.j2",
        "[Timer]\nOnCalendar={{ good_schedule }}\nRandomizedDelaySec=10min\n")  # fmt: skip
    put("ansible/roles/good/defaults/main.yml", 'good_schedule: "*-*-* 03:00:00 UTC"\n')
    args = ('--dir /var/lib/homelabnext/last-run --group root --job timer:good/tick --unit %n '
            '--calendar "{{ good_schedule }}" --delay 600')  # fmt: skip
    put("ansible/roles/good/templates/tick.service.j2",
        f"[Service]\nExecStartPre=-{schedule.WRITER} start {args}\nExecStart=/bin/true\n"
        f"ExecStopPost=-{schedule.WRITER} finish {args}\n")  # fmt: skip
    put("ansible/roles/good/tasks/config.yml",
        "- ansible.builtin.include_role:\n    name: last_run\n")  # fmt: skip
    put(
        "ansible/roles/boot/files/tick.timer", "[Timer]\nOnBootSec=5min\nOnCalendar={{ missing }}\n"
    )
    put("profiles/extra/files/sweep.timer", "[Timer]\nOnCalendar=Mon *-*-* 01:00:00 UTC\n")
    put(".github/workflows/nightly.yml",
        "name: nightly\non:\n  schedule:\n    - cron: '17 3 * * *'\njobs:\n  smoke: {}\n")  # fmt: skip
    put(".github/workflows/ci.yml", "name: ci\non: [push]\njobs:\n  test: {}\n")
    put("workflows/packs/page.yml",
        "pack: page\ndescription: >-\n  Pages on\n  alerts.\ntrigger: {event: homelabnext.alert.created}\nactor: profile:fixer\n")  # fmt: skip
    put("lab/fleet_units.yml",
        "- {name: compact, description: Compact, exec: /usr/local/bin/c, on_calendar: ['*-*-* 02:30:00 UTC']}\n"
        "- {name: old, exec: /bin/x, on_calendar: '*-*-* 01:00:00 UTC', replaced_by: 'st2:a.b'}\n")  # fmt: skip
    put("tests/fleet_units/specs/basic.yml", "- {name: fixture, exec: /bin/x, on_calendar: x}\n")
    put("docs/scripts/catalog.json",
        json.dumps({"scripts": [{"id": "scan-run", "trigger": ["timer:scan/run", "role:scan"]}]}))  # fmt: skip
    return tmp


def test_schedule_gathers_a_checkout(tmp_path):
    reg = load(FIX / "services.yml")
    inputs = schedule.gather(_checkout(tmp_path), reg)
    timers = {t["id"]: t for t in inputs["timers"]}
    assert sorted(timers) == [
        "timer:boot/tick", "timer:extra/sweep", "timer:good/tick", "timer:scan/run"]  # fmt: skip
    assert timers["timer:scan/run"]["calendars"] == ["*-*-* 04:10:00 UTC"]
    assert (timers["timer:scan/run"]["delay_s"], timers["timer:scan/run"]["what"]) == (
        900,
        "Nightly scan",
    )
    assert timers["timer:boot/tick"]["calendars"] == []
    assert [p.split(": ", 1)[1][:24] for p in timers["timer:boot/tick"]["problems"]] == [
        "OnCalendar {{ missing }}", "OnBootSec= is not a cale", "no tick.service beside i"]  # fmt: skip
    # every timer must report its runs: a service without the writer fails, a compliant one passes
    assert timers["timer:good/tick"]["problems"] == []
    scan = "\n".join(timers["timer:scan/run"]["problems"])
    assert "no ExecStartPre=-/usr/local/libexec/homelabnext/hnx-last-run start" in scan
    assert "no ExecStopPost=-/usr/local/libexec/homelabnext/hnx-last-run finish" in scan
    assert "ansible/roles/scan: no task includes role last_run" in scan
    assert [u["id"] for u in inputs["fleet_units"]] == [
        "fleet-unit:compact",
        "fleet-unit:old",
    ]  # tests/ skipped
    assert [c["id"] for c in inputs["ci"]] == [
        "ci:nightly"
    ]  # a push-only workflow is not scheduled
    assert inputs["packs"][0]["what"] == "Pages on alerts." and inputs["scripts"][
        "timer:scan/run"
    ] == ["scan-run"]
    assert inputs["collectors"] == []  # this registry declares no status source
    vm = schedule.build(inputs, now=NOW)
    rows = {r["id"]: r for g in vm["groups"] for r in g["rows"]}
    assert (
        rows["timer:boot/tick"]["cadence"] == "no calendar"
        and rows["timer:extra/sweep"]["next_run"] == "2026-10-26T01:00:00Z"
    )


def test_the_schedule_lists_every_scheduled_thing_the_repository_has():
    """Every catalogued ``timer:`` trigger, every scheduled workflow and every status source of
    the example registry is a row (the check fails on a checkout whose timer it cannot find)."""
    reg = load(REGISTRY)
    inputs = schedule.gather(ROOT, reg)
    vm = schedule.build(inputs, now=NOW)
    ids = {r["id"] for g in vm["groups"] for r in g["rows"]}
    catalog = json.loads((ROOT / "docs" / "scripts" / "catalog.json").read_text(encoding="utf-8"))
    timers = {t for s in catalog["scripts"] for t in s["trigger"] if t.startswith("timer:")}
    assert timers and timers <= ids
    assert {f"status:{s.id}" for s in sources_from_registry(reg)} <= ids
    assert {"ci:nightly", "ci:codeql", "ci:scorecard"} <= ids
    assert vm["problems"] == []
    unread = [
        r["id"]
        for g in vm["groups"]
        if g["kind"] in ("timer", "ci")
        for r in g["rows"]
        if not r["next_run"]
    ]
    assert unread == []  # every timer and CI schedule in the repository is a calendar we read


# ------------------------------------------------------------------------------- roster
SESSIONS = [
    {"agent": "fixer-cli", "runtime": "claude-code", "state": "waiting", "last_seen": "2026-10-20T10:00:00Z"},
    {"agent": "profile:fixer", "runtime": "claude-code", "state": "done", "last_seen": "2026-10-19T10:00:00Z"},
    {"agent": "watcher", "runtime": "orchestrator", "state": "errored", "last_seen": "2026-10-20T11:00:00Z"},
    {"agent": "somebody-else", "runtime": "codex", "state": "working", "last_seen": "2026-10-20T12:00:00Z"},
]  # fmt: skip


def test_roster_view_model_and_page_match_their_goldens():
    vm = roster.build(roster.gather(FIX / "roster" / "roster.yml"), SESSIONS)
    by = {a["id"]: a for a in vm["agents"]}
    assert sorted(by) == ["profile:fixer", "profile:ghost", "profile:orphan", "profile:watcher"]
    fixer = by["profile:fixer"]
    assert (fixer["owner"], fixer["runtime"], fixer["tier"], fixer["mcp"]) == (
        "ops-team", "claude-code", "execute", ["records"])  # fmt: skip
    assert fixer["model_backends"] == ["svc:infer-large", "svc:infer-small"]
    assert [ln["lane"] for ln in fixer["lanes"]] == ["inbox", "notes"] and fixer["packs"] == [
        '<img src=x onerror="y">'
    ]
    assert [a["action"] for a in fixer["actions"] if a["approval"]] == ["service.restart"]
    assert fixer["activity"] == {"sessions": 2, "last_seen": "2026-10-20T10:00:00Z", "state": "waiting",
                                 "runtimes": ["claude-code"]}  # fmt: skip
    assert (
        by["profile:watcher"]["activity"]["state"] == "errored"
        and by["profile:watcher"]["lanes"] == []
    )
    assert by["profile:ghost"]["activity"]["sessions"] == 0
    assert vm["problems"] == [
        "profile:ghost: no compiled profile (grants and MCP servers unknown)",
        "profile:orphan: no roster entry (owner and runtime unknown)",
        "profile:orphan: no compiled profile (grants and MCP servers unknown)",
    ]
    golden("roster.json", as_json(vm))
    html = roster.render(vm)
    assert_safe(html)
    assert "acts via the broker &amp; nothing else" in html and "not declared" in html
    assert "&lt;img src=x onerror=&quot;y&quot;&gt;" in html
    golden("roster.html", html)


def test_roster_without_the_activity_tier_says_so():
    vm = roster.build(roster.gather(FIX / "roster" / "roster.yml"))
    assert {a["activity"] for a in vm["agents"]} == {None}
    assert "activity tier not configured" in roster.render(vm)


def test_an_invalid_roster_is_refused(tmp_path):
    bad = tmp_path / "roster.yml"
    bad.write_text(
        "roster_version: 1\nprofiles: []\nagents:\n  - {profile: profile:x, owner: X Y, runtime: r, mcp: [a]}\n"
    )
    with pytest.raises(roster.RosterError) as exc:
        roster.gather(bad)
    assert len(exc.value.problems) == 2  # owner not a slug, and grants are never restated
    missing = tmp_path / "r2.yml"
    missing.write_text("roster_version: 1\nprofiles: []\nmodel_roles: none.json\nagents: []\n")
    with pytest.raises(roster.RosterError, match=r"none\.json"):
        roster.gather(missing)
    missing.write_text("roster_version: 1\nprofiles: []\nbrokers: [gone.yml]\nagents: []\n")
    with pytest.raises(roster.RosterError, match=r"gone\.yml"):
        roster.gather(missing)


@pytest.mark.parametrize(
    "field",
    [
        "profiles: [../outside.json]",
        "profiles: ['../*.json']",
        "brokers: [sub/../../outside.json]",
        "model_roles: ../outside.json",
    ],
)
def test_a_roster_path_out_of_its_root_is_refused(tmp_path, field):
    """A roster's paths may climb (the example reads ../../schemas/...) but never out of the root
    the hub reads (``--maps ROOT``; without one, the roster's own directory)."""
    d = tmp_path / "checkout" / "roster"
    (d / "sub").mkdir(parents=True)
    (d.parent / "outside.json").write_text('{"roles": {"fake": 1}}')
    r = d / "roster.yml"
    head = "" if field.startswith("profiles") else "profiles: []\n"
    r.write_text(f"roster_version: 1\n{head}{field}\nagents: []\n")
    for root in (None, d):
        with pytest.raises(roster.RosterError, match="resolves outside"):
            roster.gather(r, root)
    roster.gather(r, d.parent)  # inside a root that holds it: read


def test_a_roster_file_that_resolves_out_of_its_root_is_refused(tmp_path):
    (tmp_path / "outside.json").write_text('{"roles": {"fake": 1}}')
    d = tmp_path / "roster"
    d.mkdir()
    (d / "roles.json").symlink_to(tmp_path / "outside.json")
    (d / "p.json").symlink_to(tmp_path / "outside.json")
    r = d / "roster.yml"
    r.write_text("roster_version: 1\nprofiles: []\nmodel_roles: roles.json\nagents: []\n")
    with pytest.raises(roster.RosterError, match="resolves outside"):
        roster.gather(r)
    r.write_text("roster_version: 1\nprofiles: ['*.json']\nagents: []\n")
    with pytest.raises(roster.RosterError, match="resolves outside"):
        roster.gather(r, d)


def test_the_hub_reads_the_roster_inside_its_maps_root(tmp_path):
    (tmp_path / "outside.json").write_text('{"roles": {"fake": 1}}')
    d = tmp_path / "checkout"
    d.mkdir()
    r = d / "roster.yml"
    r.write_text("roster_version: 1\nprofiles: []\nmodel_roles: ../outside.json\nagents: []\n")
    assert "resolves outside" in MapSite(root=d, roster=r).body("roster")


def test_the_example_roster_declares_every_profile_the_repository_names():
    """Every profile a compiled profile, a broker grant or a workflow pack names has an owner and
    a runtime in examples/status/roster.yml (the fixture above shows the check failing)."""
    vm = roster.build(roster.gather(ROOT / "examples" / "status" / "roster.yml", ROOT))
    assert not [p for p in vm["problems"] if "no roster entry" in p]
    by = {a["id"]: a for a in vm["agents"]}
    assert by["profile:workflow-soc"]["packs"] and by["profile:triage"]["lanes"]


# ------------------------------------------------------------------- the hub: menu, pages
def _doc(maps=(), agents=None):
    reg = load(REGISTRY)
    views = load_views(VIEWS, reg, sources_from_registry(reg))
    snap = {"now": NOW, "observations": [], "sources": []}
    return build_status(snap, views, reg, [], maps=maps, agents=agents)


def test_the_directory_pages_are_a_menu_group_available_only_when_configured():
    menu = {m["id"]: m for m in _doc({"links"})["menu"]}
    for panel in ("links", "schedule", "roster", "mcp-servers"):
        assert menu[panel]["group"] == "directory" and menu[panel]["href"] == f"/{panel}"
        assert menu[panel]["available"] is (panel == "links")
    site = MapSite(root=ROOT, registry=load(REGISTRY))
    assert {"links", "schedule", "roster"} <= site.available()
    assert (
        MapSite(root=ROOT).available() >= {"schedule", "roster"}
        and "links" not in MapSite(root=ROOT).available()
    )
    assert not {"links", "schedule", "roster"} & MapSite(guests="g", guests_site="s").available()


def test_a_missing_roster_is_unavailable_and_a_bad_one_an_error_line(tmp_path):
    assert "roster" not in MapSite(root=tmp_path).available()
    bad = tmp_path / "roster.yml"
    bad.write_text("roster_version: 2\n")
    site = MapSite(root=tmp_path, roster=bad)
    assert "roster" in site.available() and "cannot build the map" in site.body("roster")


def test_serve_routes_the_directory_pages():
    from homelabnext.status.serve import make_server

    site = MapSite(root=ROOT, registry=load(REGISTRY))
    agents = {"counts": {}, "sessions": [{"agent": "triage-agent", "runtime": "claude-code",
              "state": "working", "last_seen": "2026-10-20T23:00:00Z"}]}  # fmt: skip
    srv = make_server(lambda: _doc(site.available(), agents), maps=site)
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    host, port = srv.server_address[:2]
    try:
        for route, needle in (("/links", "svc:dashboards"), ("/schedule", "timer:aide/scan"),
                              ("/roster", "profile:triage"), ("/mcp-servers", "mcp:hnx-broker")):  # fmt: skip
            url = f"http://{host}:{port}{route}"  # loopback
            with urllib.request.urlopen(url, timeout=10) as r:
                csp, html = r.headers["Content-Security-Policy"], r.read().decode()
            assert csp.startswith("default-src 'none'") and "script-src" not in csp
            assert needle in html and "cannot build" not in html
            assert_safe(html)
        url = f"http://{host}:{port}/roster"  # loopback
        with urllib.request.urlopen(url, timeout=10) as r:
            assert "1 session(s)" in r.read().decode()  # the activity tier's last session
    finally:
        srv.shutdown()
        srv.server_close()


def test_render_writes_the_directory_pages(tmp_path):
    out = tmp_path / "site"
    args = ["render", "--out", str(out), "--registry", str(REGISTRY), "--views", str(VIEWS),
            "--state", str(tmp_path / "s.json"), "--now", NOW, "--maps", str(ROOT),
            "--roster", str(FIX / "roster" / "roster.yml")]  # fmt: skip
    assert main(args) == 0
    for name in ("links.html", "schedule.html", "roster.html", "mcp-servers.html"):
        page = (out / name).read_text()
        assert_safe(page)
        assert 'href="index.html#view-overview"' in page and "cannot build" not in page
    assert "profile:watcher" in (out / "roster.html").read_text()
    assert f"next runs computed after {NOW}" in (out / "schedule.html").read_text()
    assert '<a href="links.html">Links</a>' in (out / "index.html").read_text()


def test_roster_option_is_checked(tmp_path, capsys):
    base = ["render", "--out", str(tmp_path / "o"), "--registry", str(REGISTRY),
            "--state", str(tmp_path / "s.json")]  # fmt: skip
    assert main([*base, "--roster", str(FIX / "roster" / "roster.yml")]) == 2
    assert main([*base, "--maps", str(ROOT), "--roster", str(tmp_path / "none.yml")]) == 2
    err = capsys.readouterr().err
    assert "--roster needs --maps" in err and "not a file" in err


def test_no_page_writes_an_endpoint_literal():
    """The pages hold registry names only; their code holds no address or port literal."""
    from tools.no_raw_endpoints import scan_text

    for mod in (links, schedule, roster, cadence):
        path = Path(mod.__file__)
        assert scan_text(path.name, path.read_text(encoding="utf-8")) == []


# --------------------------------------------------------------------------- mcp servers
def test_mcp_servers_view_model_and_page_match_their_goldens():
    profiles = [p["doc"] for p in roster.gather(FIX / "roster" / "roster.yml")["profiles"]]
    vm = mcp.build(servers.load(FIX / "mcp"), profiles)
    rows = {r["id"]: r for r in vm["servers"]}
    assert rows["records"]["granted_to"] == ["profile:fixer"]
    assert rows["records"]["approval"] == ["propose"] and rows["records"]["parameters"] == ["scope"]
    assert rows["records"]["classes"] == ["read", "record-write"] and rows["records"]["pinned"]
    assert rows["records"]["reviews"] == []  # its review is of another content
    assert (rows["lake"]["pinned"], rows["lake"]["pin"], rows["lake"]["where"]) == (
        False, "no digest", "svc:query/mcp")  # fmt: skip
    assert rows["lake"]["granted_to"] == ["profile:watcher"]
    assert rows["probe"]["origin"] == "unknown" and rows["probe"]["classes"] == []
    assert vm["counts"] == {"servers": 3, "active": 1, "unpinned": 2, "granted": 2}
    golden("mcp-servers.json", as_json(vm))
    html = mcp.render(vm)
    assert_safe(html)
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in html
    assert '<span class="s fail">no digest</span>' in html and "moving to a newer" in html
    golden("mcp-servers.html", html)


def test_a_grant_the_catalog_does_not_hold_is_listed():
    vm = mcp.build(servers.load(FIX / "mcp"), [{"id": "profile:x", "mcp": ["ghost"]}])
    assert vm["unknown_grants"] == [{"server": "ghost", "profiles": ["profile:x"]}]
    assert "granted but not in the catalog" in mcp.render(vm)


def test_the_example_catalog_page_lists_every_server_and_no_address(tmp_path):
    site = MapSite(root=ROOT, registry=load(REGISTRY))
    html = site.body("mcp-servers")
    for f in (ROOT / "examples" / "mcp").glob("*.yml"):
        assert f"mcp:{f.stem}" in html
    assert "cannot build" not in html and "svc:lake-query/mcp" in html
    assert not any(h.address in html for h in load(REGISTRY).hosts.values())
    assert "mcp-servers" not in MapSite(root=tmp_path).available()  # no catalog: unavailable
    assert "mcp-servers" in MapSite(root=tmp_path, mcp_catalog=FIX / "mcp").available()
