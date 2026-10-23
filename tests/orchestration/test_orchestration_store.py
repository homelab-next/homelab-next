# SPDX-License-Identifier: Apache-2.0
"""The telemetry store: agent.job.finished consumed idempotently (by event id and by run id), only
from the controller, purged by age; the rollup's numbers per profile, backend and lane."""

from __future__ import annotations

import copy
import json
import shlex
import sqlite3

import pytest
from orch_helpers import BLANK, CONTROLLER_EXAMPLE, DOTTED_EXAMPLE, EXAMPLES, T0, body, examples

from homelabnext.events.envelope import EventError
from homelabnext.orchestration import ROLLUP_SCHEMA, cli, percentile, rollup
from homelabnext.orchestration.export import export_lines
from homelabnext.orchestration.pages import OrchestrationSite
from homelabnext.orchestration.store import DEFAULT_RETENTION_DAYS, TelemetryStore, dedupe_sql
from homelabnext.status.model import iso, parse_iso


def test_each_example_is_stored_once_and_a_redelivery_is_a_duplicate(store):
    evs = examples()
    assert [store.consume(body(e)).status for e in evs] == ["processed"] * 4
    assert [store.consume(body(e)).status for e in evs] == ["duplicate"] * 4
    assert [j["run_id"] for j in store.jobs()] == ["run-0004", "run-0003", "run-0002", "run-0001"]
    assert store.job("run-0002") == evs[1]["data"]  # the record is the event's data, as sent


@pytest.mark.parametrize(
    "mutate, why",
    [
        (lambda e: e["data"].update(output_bytes=7), "already consumed with another body"),
        (lambda e: e.update(id="evt-other"), "already recorded under event 'evt-0001'"),
        (
            lambda e: e.update(id="evt-other") or e["data"].update(run_id="run-other"),
            "gateway tag 'run-0001' already joins run 'run-0001'",
        ),
        (lambda e: e.update(id="evt-other", source="svc:status-hub"), "only svc:llm-orchestrator"),
        (lambda e: e["data"].update(prompt="fake task text"), "invalid"),
        (lambda e: e.update(type="homelabnext.agent.job.failed"), ""),
    ],
)
def test_a_conflicting_foreign_or_invalid_record_is_refused(filled, mutate, why):
    ev = copy.deepcopy(examples()[0])
    mutate(ev)
    with pytest.raises(EventError) as err:
        filled.consume(body(ev))
    assert why in str(err.value)
    assert filled.job("run-0001") == examples()[0]["data"]  # the stored record is untouched


@pytest.mark.parametrize(
    "key, value",
    [
        ("finished_at", "2026-02-30T00:00:00Z"),  # no such day
        ("queued_at", "2026-01-01T24:00:00Z"),  # no such hour
        ("started_at", "2026-01-01T00:00:00+99:00"),  # no such offset
        ("finished_at", "0000-01-01T00:00:00Z"),  # no year 0
    ],
)
def test_a_pattern_valid_but_impossible_timestamp_is_refused_as_poison(store, key, value):
    ev = copy.deepcopy(examples()[0])
    ev["data"][key] = value
    with pytest.raises(EventError) as err:
        store.consume(body(ev))
    assert f"data.{key}" in str(err.value) and "not a real date and time" in str(err.value)
    assert store.jobs() == []


@pytest.mark.parametrize(
    ("changes", "early", "late"),
    [
        ({"queued_at": "2026-01-01T05:00:00Z", "started_at": None}, "queued_at", "finished_at"),
        ({"started_at": "2026-01-01T05:00:00Z"}, "started_at", "finished_at"),
        ({"queued_at": "2026-01-01T05:00:00Z"}, "queued_at", "started_at"),
    ],
)
def test_timestamps_out_of_order_are_refused_as_poison(store, changes, early, late):
    """A queue time after the finish (or a start outside queue..finish) is no real job, and its
    span would overlap no read window, so its turns would never settle."""
    ev = copy.deepcopy(examples()[0])
    ev["data"].update(changes)
    with pytest.raises(EventError) as err:
        store.consume(body(ev))
    assert f"data.{early}" in str(err.value) and f"is after data.{late}" in str(err.value)
    assert store.jobs() == []


def test_timestamps_a_second_out_of_order_are_accepted(store):
    """The controller stamps all three from one clock, so a wall-clock step (an NTP correction)
    between two stamps is what inverts them; a second of it is not poison."""
    ev = copy.deepcopy(examples()[0])
    finished = parse_iso(ev["data"]["finished_at"])
    ev["data"].update(started_at=iso(finished + 1), queued_at=iso(finished + 1))
    assert store.consume(body(ev)).status == "processed"


@pytest.mark.parametrize(
    "queued_at, started_at",
    [
        ("2025-12-23T02:00:00Z", None),  # held in the queue eight days, then cancelled
        ("2025-12-23T01:00:00Z", "2025-12-23T02:00:00Z"),  # an eight-day run: no ceiling
        ("2025-10-03T03:00:01Z", "2025-12-30T03:00:00Z"),  # queued just inside retention
    ],
)
def test_a_job_queued_or_running_for_days_is_stored(store, queued_at, started_at):
    """The controller bounds neither queue wait nor run time (no wall-clock ceiling; queued jobs
    survive restarts and holds, and one cancelled in the queue still reports): a week-long job is
    a real record, not poison."""
    ev = copy.deepcopy(examples()[0])
    ev["data"].update(
        queued_at=queued_at, started_at=started_at, finished_at="2025-12-31T03:00:00Z"
    )
    assert store.consume(body(ev)).status == "processed"


@pytest.mark.parametrize(
    "queued_at, needle",
    [
        ("0001-01-01T00:00:00Z", "before 2000"),  # Go's zero time behind a parse error
        ("1999-12-31T23:59:59Z", "before 2000"),
        ("2025-10-02T02:59:59Z", "more than 90 days before data.finished_at"),  # past retention
    ],
)
def test_a_job_with_an_impossible_queue_time_is_poison(store, queued_at, needle):
    """Only an instant no job has is refused: a zero time, or a queue time older than anything
    the store keeps; its span would otherwise be read as one window per hour back to it."""
    ev = copy.deepcopy(examples()[0])
    ev["data"].update(queued_at=queued_at, started_at=None, finished_at="2025-12-31T03:00:00Z")
    with pytest.raises(EventError, match=needle):
        store.consume(body(ev))
    assert store.jobs() == []


def test_a_record_older_than_retention_is_expired_not_processed(tmp_path):
    """It would be deleted in the very write that stores it: reported ``expired``, not stored."""
    store = TelemetryStore(tmp_path / "t.db", clock=lambda: T0 + 200 * 86400)
    ev = body(examples()[1])
    assert [store.consume(ev).status for _ in range(2)] == ["expired", "expired"]
    assert store.jobs() == []


def test_the_database_refuses_a_second_job_with_the_same_tag(filled):
    """The tag joins the gateway's turns to one job: two jobs sharing one would merge their
    turns, so the store's schema refuses it even past consume()'s own check."""
    with pytest.raises(sqlite3.IntegrityError), sqlite3.connect(filled.path) as db:
        db.execute(
            "INSERT INTO jobs SELECT 'run-x', 'evt-x', digest, profile, backend, lane, outcome,"
            " finished, gateway_tag, received, turns_settled, doc, event FROM jobs WHERE run_id = ?",
            ("run-0001",),
        )


def test_jobs_and_turns_past_retention_are_purged(tmp_path):
    now = [T0]
    store = TelemetryStore(tmp_path / "t.db", clock=lambda: now[0], retention_days=1)
    store.consume(body(examples()[0]))
    store.add_turns(
        [
            BLANK
            | {"turn_id": "req-a1", "gateway_tag": "run-0001", "started_at": "2026-01-01T00:00:13Z"}
        ]
    )
    assert store.job("run-0001") and store.turns()
    now[0] = parse_iso("2026-01-02T00:05:13Z")  # a day and a second after it finished
    assert store.purge() == 2
    assert store.job("run-0001") is None and store.turns() == {}


def test_percentile_is_nearest_rank_over_known_values():
    assert percentile([], 50) is None and percentile([None], 95) is None
    assert percentile([300.0, 570.0], 50) == 300.0
    assert percentile([300.0, None, 570.0], 95) == 570.0
    assert percentile(range(1, 101), 95) == 95


def test_rollup_per_profile_backend_and_lane(filled):
    filled.add_turns(
        [
            BLANK | {"turn_id": "t1", "gateway_tag": "run-0001", "started_at": "2026-01-01T00:00:13Z",
             "input_tokens": 20000, "output_tokens": 1500, "cache_read_tokens": 12000,
             "cost_usd": 0.0, "status": "success", "ttft_ms": 400, "duration_ms": 2100},
            BLANK | {"turn_id": "t2", "gateway_tag": "hnx-run-0002", "started_at": "2026-01-01T01:00:40Z",
             "input_tokens": 9000, "output_tokens": 400, "status": "failure"},
        ]
    )  # fmt: skip
    roll = filled.rollup(days=7)
    assert roll["schema"] == ROLLUP_SCHEMA and roll["window"]["days"] == 7
    by = {(g["profile"], g["backend"], g["lane"]): g for g in roll["groups"]}
    assert sorted(by) == [
        ("profile:triage", "-", "real"),
        ("profile:triage", "local-large", "real"),
        ("profile:triage", "local-small", "shadow"),
    ]
    g = by["profile:triage", "local-large", "real"]  # run-0001 (completed), run-0002 (failed)
    assert g["jobs"] == 2
    assert g["outcomes"] == {"completed": 1, "failed": 1, "cancelled": 0, "timeout": 0}
    assert g["failure_classes"] == {"backend-down": 1}
    assert g["wall_s"] == {"p50": 300.0, "p95": 570.0, "n": 2}
    assert g["queue_wait_s"] == {"p50": 12.0, "p95": 30.0, "n": 2}
    # each sum has its own unknown count: run-0002 reported no reasoning or cache-read tokens
    assert g["tokens"] == {
        "input": 50000, "output": 3600, "reasoning": 0, "cache_read": 28000,
        "jobs_unknown": {"input": 0, "output": 0, "reasoning": 1, "cache_read": 1},
    }  # fmt: skip
    # run-0002 did not report cache reads: the share is over run-0001 alone, never diluted
    assert g["cache_read_share"] == round(28000 / 41000, 4)
    assert g["cost_usd"] == {"total": 0.0, "jobs_unknown": 1}
    assert g["retries"] == {"of_earlier_run": 0, "auto_scheduled": 1}
    assert g["bytes"]["input"] == {"p50": 2048, "total": 4096}
    assert g["bytes"]["output"] == {"p50": 6144, "total": 6144, "n": 1}
    assert g["api_calls_per_job"] == {"p50": 3, "p95": 9, "n": 2}
    t = g["turns"]
    assert (t["count"], t["jobs_with_turns"], t["failures"]) == (2, 2, 1)
    assert (t["input_tokens"], t["output_tokens"], t["cache_read_tokens"]) == (29000, 1900, 12000)
    never = by["profile:triage", "-", "real"]  # run-0004: cancelled in the queue, no usage file
    assert never["wall_s"] == {"p50": None, "p95": None, "n": 0}
    assert never["tokens"] == {
        "input": None, "output": None, "reasoning": None, "cache_read": None,
        "jobs_unknown": {"input": 1, "output": 1, "reasoning": 1, "cache_read": 1},
    }  # fmt: skip
    assert never["cost_usd"] == {"total": None, "jobs_unknown": 1}
    assert never["bytes"]["output"] == {"p50": None, "total": None, "n": 0}
    assert never["turns"]["input_tokens"] is None  # no gateway data, not 0
    assert never["cache_read_share"] is None and never["retries"]["of_earlier_run"] == 1
    assert roll["days"] == [
        {"day": "2026-01-01", "profile": "profile:triage", "jobs": 4, "completed": 2,
         "not_completed": 2, "wall_s_p50": 300.0, "input_tokens": 89000, "output_tokens": 6500,
         "cost_usd": 0.0,
         "jobs_unknown": {"input_tokens": 1, "output_tokens": 1, "cost_usd": 2}},
    ]  # fmt: skip


def test_a_sum_with_no_known_value_is_unknown_not_zero():
    """A day, a group and the gateway turns whose values are all null sum to None with their
    unknown count, never to 0 (which reads as "free" or "no tokens")."""
    job = copy.deepcopy(examples()[0]["data"]) | {"usage": None}
    blank = {"input_tokens": None, "output_tokens": None, "cache_read_tokens": None}
    turns = {job["gateway_tag"]: [{"turn_id": "t1", **blank, "cost_usd": None}]}
    roll = rollup([job], turns, now=T0, days=7)
    (day,) = roll["days"]
    assert (day["input_tokens"], day["output_tokens"], day["cost_usd"]) == (None, None, None)
    assert day["jobs_unknown"] == {"input_tokens": 1, "output_tokens": 1, "cost_usd": 1}
    (g,) = roll["groups"]
    assert g["cost_usd"] == {"total": None, "jobs_unknown": 1} and g["tokens"]["output"] is None
    t = g["turns"]
    assert (t["input_tokens"], t["output_tokens"], t["cost_usd"]) == (None, None, None)
    assert t["turns_unknown"] == {
        "input_tokens": 1, "output_tokens": 1, "cache_read_tokens": 1, "cost_usd": 1,
    }  # fmt: skip
    # one known value is a sum, with the rest counted
    half = copy.deepcopy(job) | {"run_id": "run-h", "gateway_tag": "run-h"}
    nulls = ("input_tokens", "reasoning_tokens", "cache_read_tokens", "api_calls", "cost_usd")
    half["usage"] = dict.fromkeys(nulls) | {"output_tokens": 7}
    g2 = rollup([job, half], {}, now=T0, days=7)["groups"][0]
    assert g2["tokens"]["output"] == 7 and g2["tokens"]["jobs_unknown"]["output"] == 1
    assert g2["tokens"]["input"] is None and g2["tokens"]["jobs_unknown"]["input"] == 2


def test_the_day_trend_buckets_by_the_utc_day_not_the_sent_offset():
    """23:30 at -05:00 on Dec 31 is 04:30 UTC on Jan 1, the same day as a job sent in Z."""
    late = copy.deepcopy(examples()[0]["data"]) | {"finished_at": "2025-12-31T23:30:00-05:00"}
    utc = copy.deepcopy(examples()[1]["data"])  # finished 2026-01-01T01:...Z
    (day,) = rollup([late, utc], {}, now=T0, days=7)["days"]
    assert (day["day"], day["jobs"]) == ("2026-01-01", 2)


def test_rollup_window_leaves_out_older_jobs():
    jobs = [e["data"] for e in examples()]
    assert rollup(jobs, {}, now=parse_iso("2026-01-01T02:59:00Z"), days=1)["days"][0]["jobs"] == 3
    assert rollup(jobs, {}, now=parse_iso("2026-01-09T00:00:00Z"), days=7)["groups"] == []


#: the controller's own test event (llm-orchestrator), byte for byte; values fictional
CONTROLLER_EVENT = (
    '{"specversion":"1.0","id":"evt-0db579c95c808da59500536064c11648","source":"svc:llm-orchestrator",'
    '"type":"homelabnext.agent.job.finished","time":"2026-10-22T12:02:00Z","subject":"run-c1",'
    '"correlationid":"run-c1","data":{"run_id":"run-c1","profile":"profile:pipeline-health-analyst",'
    '"profile_revision":"rev-9","lane":"real","outcome":"completed","failure_class":null,'
    '"retry_of_run_id":null,"auto_retry_scheduled":false,"local_attempts":1,'
    '"cloud_fallback_used":false,"backend":"local-gateway","model":"custom/hermes-agent",'
    '"queued_at":"2026-10-22T12:00:00Z","started_at":"2026-10-22T12:00:30Z",'
    '"finished_at":"2026-10-22T12:02:00Z","queue_wait_s":30,"wall_s":90,"input_bytes":4,'
    '"output_bytes":10,"usage":{"input_tokens":1200,"output_tokens":0,"reasoning_tokens":null,'
    '"cache_read_tokens":800,"api_calls":3,"cost_usd":0.0125},"turn_exit_reason":"text_response",'
    '"gateway_tag":"run-c1"}}'
)


def test_the_controllers_own_event_is_accepted_as_sent(store):
    """The controller side's test event validates unchanged and is stored; the schema's
    ``controller`` example is the same event, so the contract tests publish and consume it too."""
    assert (EXAMPLES / CONTROLLER_EXAMPLE).read_text().strip() == CONTROLLER_EVENT
    assert store.consume(CONTROLLER_EVENT).status == "processed"
    assert store.job("run-c1")["model"] == "custom/hermes-agent"
    # a vLLM backend's model is its path: an opaque name, accepted as such
    path_model = CONTROLLER_EVENT.replace("custom/hermes-agent", "/srv/models/example-27b")
    path_model = path_model.replace("evt-0db5", "evt-1db5").replace('"run-c1"', '"run-c2"')
    assert store.consume(path_model).status == "processed"
    # a configured prefix may hold '/', the run id after it may not
    prefixed = CONTROLLER_EVENT.replace('"gateway_tag":"run-c1"', '"gateway_tag":"lab/hnx:run-c1"')
    prefixed = prefixed.replace("evt-0db5", "evt-2db5").replace('"run-c1"', '"run-c3"')
    assert store.consume(prefixed).status == "processed"


@pytest.mark.parametrize("backend", [".lab-gateway", "lab9", "node.7_gw-a"])
def test_a_backend_name_is_stored_as_the_controller_emits_it(store, backend):
    """Regression: the controller emits local_backend_used verbatim, and real names start with a
    dot or digits; a pattern that refused them sent every such record to the dead-letter stream.
    A ':' or '/' (a host:port or a URL) is still refused."""
    ev = json.loads((EXAMPLES / DOTTED_EXAMPLE).read_text())
    assert store.consume(body(ev)).status == "processed"
    ev = copy.deepcopy(ev) | {"id": f"evt-b-{len(backend)}"}
    run = f"run-b-{len(backend)}"
    ev["data"].update(run_id=run, gateway_tag=run, backend=backend)
    assert store.consume(body(ev)).status == "processed"
    assert store.job(f"run-b-{len(backend)}")["backend"] == backend
    for bad in ("gw.example.com:8000", "https://gw.example.com/v1", "a" * 65, ""):
        ev = copy.deepcopy(ev) | {"id": "evt-bad"}
        ev["data"].update(run_id="run-bad", gateway_tag="run-bad", backend=bad)
        with pytest.raises(EventError):
            store.consume(body(ev))


def test_turns_of_many_jobs_do_not_bind_a_variable_per_tag(store, monkeypatch):
    """Regression: the rollup bound one SQL variable per gateway tag, which fails past SQLite's
    limit ("too many SQL variables"; 999 on an old build).  The limit is lowered to 100 here and
    150 jobs are rolled up, on the store and on the page."""
    real_connect = sqlite3.connect

    def low_limit(*a, **kw):
        conn = real_connect(*a, **kw)
        conn.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 100)
        return conn

    template = examples()[0]
    for n in range(150):
        ev = copy.deepcopy(template) | {"id": f"evt-m{n:03d}"}
        ev["data"].update(run_id=f"run-m{n:03d}", gateway_tag=f"run-m{n:03d}")
        store.consume(body(ev))
    store.add_turns(
        [BLANK | {"turn_id": f"t{n}", "gateway_tag": f"run-m{n:03d}", "started_at": "2026-01-01T00:00:13Z",
          "input_tokens": 1} for n in range(150)]
    )  # fmt: skip
    monkeypatch.setattr(sqlite3, "connect", low_limit)
    roll = store.rollup(days=7)
    assert roll["groups"][0]["jobs"] == 150 and roll["groups"][0]["turns"]["input_tokens"] == 150
    assert len(store.turns((f"run-m{n:03d}" for n in range(120)), since=T0 - 86400)) == 120
    assert [t["turn_id"] for t in store.job_turns("run-m007")] == ["t7"]
    assert "150 jobs" in OrchestrationSite(store, clock=lambda: T0)._overview({})


def _earlier_release_store(path, *, shared_tags: int) -> None:
    """A store as an earlier release left it: a plain index on the tag, and ``shared_tags`` tags
    each held by a second job."""
    TelemetryStore(path, clock=lambda: T0).consume(body(examples()[0]))
    with sqlite3.connect(path) as db:
        db.execute("DROP INDEX jobs_gateway_tag")
        db.execute("CREATE INDEX jobs_tag ON jobs(gateway_tag)")
        for n in range(shared_tags):
            db.execute(
                "INSERT INTO jobs SELECT ?, ?, digest, profile, backend, lane, outcome, finished,"
                " gateway_tag, received, turns_settled, doc, event FROM jobs WHERE run_id = 'run-0001'",
                (f"run-copy-{n}", f"evt-copy-{n}"),
            )
    db.close()


def _indexes(path) -> set[str]:
    with sqlite3.connect(path) as db:
        names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    db.close()
    return names


def test_a_store_with_two_jobs_on_one_tag_is_refused_with_how_to_fix_it(tmp_path, capsys):
    """The unique index cannot be built over an earlier release's duplicates: every command is
    exit 2 naming the count and the fix, never an IntegrityError traceback; after the fix the
    store opens, with the old plain index gone."""
    db = tmp_path / "t.db"
    _earlier_release_store(db, shared_tags=2)
    for argv in (["report", "--db", str(db)], ["ingest", "--db", str(db), "-"]):
        assert cli.main(argv, clock=lambda: T0) == 2
        err = capsys.readouterr().err
        assert "1 gateway tag(s) are each held by more than one job (3 jobs)" in err
        assert "Traceback" not in err
    fix = _printed_fix(err, db)
    assert fix == dedupe_sql(T0 - DEFAULT_RETENTION_DAYS * 86400)
    with sqlite3.connect(db) as conn:
        conn.execute(fix)
    conn.close()
    store = TelemetryStore(db, clock=lambda: T0)
    assert [j["run_id"] for j in store.jobs()] == ["run-0001"]
    assert "jobs_gateway_tag" in _indexes(db) and "jobs_tag" not in _indexes(db)


def test_an_earlier_release_store_without_shared_tags_is_migrated(tmp_path):
    db = tmp_path / "t.db"
    _earlier_release_store(db, shared_tags=0)
    TelemetryStore(db, clock=lambda: T0)
    assert "jobs_gateway_tag" in _indexes(db) and "jobs_tag" not in _indexes(db)


def test_a_store_sqlite_cannot_open_is_exit_2_not_a_traceback(tmp_path, capsys):
    (tmp_path / "t.db").mkdir()  # a directory where the database should be
    assert cli.main(["report", "--db", str(tmp_path / "t.db")], clock=lambda: T0) == 2
    assert "hnx orchestration report: unable to open database file" in capsys.readouterr().err


def _printed_fix(err: str, db) -> str:
    """The statement the refusal prints, as the shell would pass it to sqlite3."""
    cmd = shlex.split(err.split("to keep the one received first: ", 1)[1].rsplit(")", 1)[0])
    assert cmd[:2] == ["sqlite3", str(db)] and len(cmd) == 3
    return cmd[2]


def _store_with_jobs(path, jobs: list[tuple[str, float]]) -> None:
    """An earlier release's store (a plain index on the tag) holding ``jobs`` (run id, finished
    and received at that time), all on one tag."""
    TelemetryStore(path, clock=lambda: T0)
    with sqlite3.connect(path) as db:
        db.execute("DROP INDEX jobs_gateway_tag")
        db.execute("CREATE INDEX jobs_tag ON jobs(gateway_tag)")
        for run, at in jobs:
            db.execute(
                "INSERT INTO jobs VALUES (?,?,'d','profile:x',NULL,'real','completed',?,'t',?,"
                "NULL,'{}',NULL)",
                (run, f"e-{run}", at, at),
            )
    db.close()


def _run_ids(path) -> list[str]:
    with sqlite3.connect(path) as db:
        ids = [r[0] for r in db.execute("SELECT run_id FROM jobs ORDER BY run_id")]
    db.close()
    return ids


DAY = 86400.0


@pytest.mark.parametrize(
    ("jobs", "left"),
    [
        ([("r1", T0 - 100 * DAY), ("r2", T0 - DAY)], ["r2"]),
        ([("r1", T0 - 100 * DAY), ("r2", T0 - 95 * DAY), ("r3", T0)], ["r3"]),
    ],
)
def test_an_expired_duplicate_is_purged_for_good_and_the_store_opens(tmp_path, jobs, left):
    """The purge at open used to roll back with the refusal: the message counted what was left
    after it, while the table still held the expired jobs."""
    db = tmp_path / "t.db"
    _store_with_jobs(db, jobs)
    TelemetryStore(db, clock=lambda: T0)
    assert _run_ids(db) == left


def test_the_printed_fix_keeps_the_live_job_received_first_never_an_expired_one(tmp_path, capsys):
    """Two live jobs and an expired one on one tag: the refusal names two jobs (the expired one is
    already gone), and its statement keeps the live job received first.  The old statement kept
    min(rowid), the expired job if it was still there, which the next open purged: every job on
    the tag was gone."""
    db = tmp_path / "t.db"
    _store_with_jobs(db, [("r1", T0 - 100 * DAY), ("r2", T0 - 2 * DAY), ("r3", T0)])
    assert cli.main(["report", "--db", str(db)], clock=lambda: T0) == 2
    err = capsys.readouterr().err
    assert "1 gateway tag(s) are each held by more than one job (2 jobs)" in err
    assert _run_ids(db) == ["r2", "r3"]  # the purge is committed despite the refusal
    fix = _printed_fix(err, db)
    with sqlite3.connect(db) as conn:  # the expired job is back, as if not yet purged
        conn.execute(
            "INSERT INTO jobs SELECT 'r1', 'e-r1', digest, profile, backend, lane, outcome, ?,"
            " gateway_tag, ?, turns_settled, doc, event FROM jobs WHERE run_id = 'r2'",
            (T0 - 100 * DAY, T0 - 100 * DAY),
        )
        conn.execute(fix)
    conn.close()
    assert _run_ids(db) == ["r2"]
    TelemetryStore(db, clock=lambda: T0)
    assert _run_ids(db) == ["r2"]


def test_the_printed_fix_quotes_a_path_the_shell_would_split(tmp_path, capsys):
    db = tmp_path / "a dir; with $(x)" / "t.db"
    db.parent.mkdir()
    _store_with_jobs(db, [("r1", T0), ("r2", T0)])
    assert cli.main(["report", "--db", str(db)], clock=lambda: T0) == 2
    fix = _printed_fix(capsys.readouterr().err, db)
    with sqlite3.connect(db) as conn:
        conn.execute(fix)
    conn.close()
    assert _run_ids(db) == ["r1"]


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_a_non_finite_number_is_poison_not_a_nan_in_the_rollup(store, literal):
    """Python's parser takes NaN, Infinity and 1e999 (an infinity); the schema's minimum: 0 does
    not reject NaN, so the record was stored and the rollup emitted NaN: not JSON."""
    ev = copy.deepcopy(examples()[0])
    raw = json.dumps(ev).replace(
        f'"wall_s": {json.dumps(ev["data"]["wall_s"])}', f'"wall_s": {literal}'
    )
    assert literal in raw
    with pytest.raises(EventError, match="not JSON"):
        store.consume(raw)
    assert store.jobs() == []
    json.dumps(store.rollup(now=T0), allow_nan=False)


@pytest.mark.parametrize("where", ["model", "extension", "key"])
def test_a_lone_surrogate_is_poison(store, where):
    """The model's pattern admits a lone surrogate (an escaped half pair, "\\ud800"): no Unicode
    text, so the record was stored and its job page failed to encode, dropping the connection."""
    ev = copy.deepcopy(examples()[0])
    if where == "model":
        ev["data"]["model"] = "mdl:triage-\ud800"
    elif where == "extension":
        ev["zz"] = ["\udfff"]
    else:
        ev["zz"] = {"\ud800": 1}
    raw = json.dumps(ev)
    assert "\\ud" in raw  # escaped, as a sender's encoder writes it
    with pytest.raises(EventError, match="lone surrogate"):
        store.consume(raw.encode())
    assert store.jobs() == []


def test_the_job_source_is_configuration_and_every_other_source_is_refused(tmp_path):
    """Which service fills the orchestration slot is a site fact: the store takes the source it
    is given (the example's controller id is only the default) and refuses every other one."""
    ev = copy.deepcopy(examples()[0]) | {"source": "svc:job-runner"}
    default = TelemetryStore(tmp_path / "a.db", clock=lambda: T0)
    with pytest.raises(EventError, match="only svc:llm-orchestrator reports jobs"):
        default.consume(body(ev))
    other = TelemetryStore(tmp_path / "b.db", clock=lambda: T0, sources=["svc:job-runner"])
    assert other.consume(body(ev)).status == "processed"
    with pytest.raises(EventError, match="only svc:job-runner reports jobs"):
        other.consume(body(examples()[1]))  # the example controller's id is not configured here
    for bad in ([], ["llm-orchestrator"], ["svc:Bad Name"], ["svc:x", ""]):
        with pytest.raises(ValueError, match="sources"):
            TelemetryStore(tmp_path / "c.db", clock=lambda: T0, sources=bad)


@pytest.mark.parametrize(
    "attrs, needle",
    [
        ({"comment": "fake free text: the prompt was ..."}, "comment"),
        ({"x": "1"}, "'x'"),
        ({"subject": "run-0001 and then the user prompt text"}, "subject"),
        ({"subject": "https://upstream.example.com/v1"}, "subject"),
    ],
)
def test_the_envelope_is_closed_an_extension_or_a_free_text_subject_is_poison(store, attrs, needle):
    """data is closed, and so is the envelope of this type: an extension attribute or a subject
    that is not a run id is refused (poison), so the stored and exported envelope is names and
    numbers only, as the data is."""
    ev = examples()[0] | attrs
    with pytest.raises(EventError) as exc:
        store.consume(body(ev))
    assert needle in "\n".join(exc.value.problems)
    assert store.jobs() == []
    for lines in export_lines(store):  # nothing of it is stored, so nothing is exported
        raise AssertionError(lines)


def test_every_envelope_attribute_an_example_sends_is_allowed(store):
    """The attributes the controller sends (subject as the run id, severity, correlationid) are
    the schema's own: closing the envelope refuses none of them."""
    ev = json.loads((EXAMPLES / CONTROLLER_EXAMPLE).read_text(encoding="utf-8"))
    assert store.consume(body(ev)).status == "processed"
    (line,) = export_lines(store)
    assert set(json.loads(line)["event"]) == {
        "specversion", "id", "source", "type", "time", "subject", "correlationid", "data",
    }  # fmt: skip


def test_the_allowed_envelope_attributes_are_the_envelope_schemas_own():
    from homelabnext.orchestration.store import ENVELOPE_ATTRIBUTES

    envelope = json.loads(
        (EXAMPLES.parents[0] / "envelope.schema.json").read_text(encoding="utf-8")
    )
    assert set(envelope["properties"]) == ENVELOPE_ATTRIBUTES


@pytest.mark.parametrize("days", [float("nan"), float("inf"), -5, 0, 0.5, 3651, 10_000, True, "90"])
def test_retention_is_a_finite_number_of_days_from_1_to_3650(tmp_path, days, capsys):
    """Every read window is bounded by retention: 10,000 days let a job started in 2001 be read as
    225,697 windows; nan, inf, 0 and a negative make every comparison meaningless."""
    with pytest.raises(ValueError, match="1 to 3650"):
        TelemetryStore(tmp_path / "t.db", clock=lambda: T0, retention_days=days)
    assert not (tmp_path / "t.db").exists()  # refused before anything is created
    if isinstance(days, str | bool):
        return
    argv = ["report", "--db", str(tmp_path / "t.db"), "--retention-days", str(days)]
    assert cli.main(argv, clock=lambda: T0) == 2
    assert "1 to 3650" in capsys.readouterr().err


@pytest.mark.parametrize("days", [1, 1.5, 90, 3650])
def test_retention_inside_the_range_is_accepted(tmp_path, days):
    assert TelemetryStore(tmp_path / "t.db", clock=lambda: T0, retention_days=days).retention_s == (
        days * 86400.0
    )
