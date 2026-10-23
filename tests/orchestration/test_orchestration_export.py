# SPDX-License-Identifier: Apache-2.0
"""``hnx orchestration export`` / ``import``: the store as neutral JSON lines
(``homelabnext.orchestration.export/1``) that round-trip into another store, re-import
idempotently by the same ids, and refuse what the bus consumer would refuse."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from orch_helpers import BLANK, T0, FakeSpendLogs, body, examples, turn_source

from homelabnext.orchestration import cli
from homelabnext.orchestration.export import EXPORT_SCHEMA, export_lines, import_lines
from homelabnext.orchestration.gateway import sync_turns
from homelabnext.orchestration.store import TelemetryStore
from homelabnext.status.model import iso


@pytest.fixture
def synced(filled) -> TelemetryStore:
    with FakeSpendLogs() as gw:
        sync_turns(filled, turn_source(gw), now=parse_now())
    return filled


def parse_now() -> float:
    from homelabnext.status.model import parse_iso

    return parse_iso("2026-01-01T03:01:00Z")  # run-0004 finished a minute ago: not settled


def _state(store: TelemetryStore) -> tuple:
    return (
        store.jobs(),
        store.turns(),
        sorted(j["run_id"] for j in store.unsettled()),
        store.rollup(days=7),
    )


def test_an_export_round_trips_into_another_store(synced, tmp_path):
    lines = list(export_lines(synced))
    recs = [json.loads(line) for line in lines]
    assert {r["schema"] for r in recs} == {EXPORT_SCHEMA}
    assert [r["kind"] for r in recs] == ["header"] + ["job"] * 4 + ["turn"] * 4  # then jobs, turns
    assert recs[1]["event"]["type"] == "homelabnext.agent.job.finished"
    other = TelemetryStore(tmp_path / "other.db", clock=lambda: T0)
    counts, refused = import_lines(other, lines)
    assert refused == [] and counts == {("job", "processed"): 4, ("turn", "processed"): 4}
    assert _state(other) == _state(synced)  # jobs, turns, what is still unsettled, the rollup
    assert list(export_lines(other)) == lines


def test_a_re_import_is_idempotent_by_the_same_ids(synced, tmp_path):
    lines = list(export_lines(synced))
    before = _state(synced)
    counts, refused = import_lines(synced, lines)  # into the store it came from
    assert refused == [] and counts == {("job", "duplicate"): 4, ("turn", "duplicate"): 4}
    assert _state(synced) == before
    other = TelemetryStore(tmp_path / "other.db", clock=lambda: T0)
    import_lines(other, lines)
    again, _ = import_lines(other, lines)
    assert again == {("job", "duplicate"): 4, ("turn", "duplicate"): 4}


def _line(**rec) -> str:
    return json.dumps({"schema": EXPORT_SCHEMA, **rec})


def test_an_import_refuses_what_the_consumer_refuses_and_keeps_the_rest(synced, tmp_path):
    good = list(export_lines(synced))
    event = json.loads(good[1])["event"]
    foreign = copy.deepcopy(event) | {"source": "svc:status-hub", "id": "evt-foreign"}
    text = copy.deepcopy(event) | {"id": "evt-text"}
    text["data"]["prompt"] = "fake task text"
    conflict = copy.deepcopy(event)
    conflict["data"]["output_bytes"] = 7  # the same id with another body
    turn = json.loads(good[-1])["turn"]
    bad = [
        _line(kind="job", event=foreign, turns_settled_at=None),
        _line(kind="job", event=text, turns_settled_at=None),
        _line(kind="job", event=conflict, turns_settled_at=None),
        _line(kind="job", event=None, turns_settled_at=None),
        _line(kind="turn", turn=turn | {"api_base": "https://upstream.example.com/v1"}),
        _line(kind="turn", turn=turn | {"input_tokens": -1}),
        _line(kind="secret", value="x"),
        json.dumps({"schema": "homelabnext.orchestration.export/2", "kind": "job"}),
        '{"schema": "' + EXPORT_SCHEMA + '", "kind": "turn", "turn": {"cost_usd": NaN}}',
        "not json",
        "[]",
    ]
    other = TelemetryStore(tmp_path / "other.db", clock=lambda: T0)
    counts, refused = import_lines(other, [*good, *bad])
    assert counts["refused"] == len(bad) == len(refused)
    first = len(good) + 1
    assert [n for n, _ in refused] == list(range(first, first + len(bad)))
    assert counts[("job", "processed")] == 4 and counts[("turn", "processed")] == 4
    assert _state(other)[:2] == _state(synced)[:2]  # the conflicting body never replaced it
    reasons = [why for _, why in refused]
    assert "not the controller's job record" in reasons[0]
    assert "conflicts with a stored one" in reasons[2]
    assert "fields outside the turn record: api_base" in reasons[4]
    assert "not JSON (NaN is not a JSON number)" in reasons[8]
    assert "upstream.example.com" not in other.path.read_bytes().decode("latin-1")


def test_a_turn_past_retention_is_expired_not_stored(tmp_path):
    store = TelemetryStore(tmp_path / "t.db", clock=lambda: T0, retention_days=1)
    old = BLANK | {
        "turn_id": "t-old",
        "gateway_tag": "run-0001",
        "started_at": "2025-01-01T00:00:00Z",
    }
    counts, _ = import_lines(store, [_line(kind="turn", turn=old)])
    assert counts == {("turn", "expired"): 1} and store.turns() == {}


def test_cli_export_reads_only_and_import_loads(synced, tmp_path, capsys):
    db, out = synced.path, tmp_path / "export.jsonl"
    before = db.read_bytes()
    assert cli.main(["export", "--db", str(db), "--out", str(out)], clock=lambda: T0) == 0
    assert db.read_bytes() == before  # nothing purged, migrated or written
    assert "8 record(s)" in capsys.readouterr().err
    other = tmp_path / "other.db"
    argv = ["import", str(out), "--db", str(other)]
    assert cli.main(argv, clock=lambda: T0) == 0
    assert capsys.readouterr().out.strip() == (
        "orchestration import: jobs 4 processed, 0 duplicate, 0 expired; "
        "turns 4 processed, 0 duplicate, 0 expired; 0 refused"
    )
    with out.open("a", encoding="utf-8") as f:
        f.write("not json\n")
    assert cli.main(argv, clock=lambda: T0) == 1
    out_, err = capsys.readouterr()
    assert "jobs 0 processed, 4 duplicate" in out_ and "export.jsonl:10: not JSON" in err
    assert cli.main(["export", "--db", str(tmp_path / "none.db")], clock=lambda: T0) == 2
    assert not (tmp_path / "none.db").exists()


def test_an_older_store_without_envelopes_exports_jobs_an_import_refuses(tmp_path):
    """A store written before exports kept only the record, not its envelope: the export says
    so per job (event null) and an import refuses those lines rather than inventing one."""
    store = TelemetryStore(tmp_path / "t.db", clock=lambda: T0)
    store.consume(body(examples()[0]))
    with store._db() as db:
        db.execute("UPDATE jobs SET event = NULL")
    _, line = export_lines(store)
    assert json.loads(line)["event"] is None
    counts, refused = import_lines(TelemetryStore(tmp_path / "o.db", clock=lambda: T0), [line])
    assert counts == {"refused": 1} and "carries its event" in refused[0][1]


@pytest.mark.parametrize(
    "line, needle",
    [
        ('{"schema":' + "[" * 100_000 + "]" * 100_000 + "}", "nested too deeply"),
        ('{"schema": 1' + "0" * 5000 + "}", "not JSON"),
        ('{"schema": 1e999}', "not a finite number"),
    ],
    ids=["deep", "bigint", "inf"],
)
def test_a_line_the_consumer_refuses_is_refused_not_a_crash(synced, tmp_path, line, needle):
    """A parser bomb or an integer past Python's digit limit is one refused line with its
    number, as the bus consumer refuses it, and the lines after it are still imported."""
    good = list(export_lines(synced))
    other = TelemetryStore(tmp_path / "other.db", clock=lambda: T0)
    counts, refused = import_lines(other, [good[0], line, *good[1:]])  # after the header
    assert counts["refused"] == 1 and refused[0][0] == 2 and needle in refused[0][1]
    assert counts[("job", "processed")] == 4 and counts[("turn", "processed")] == 4


def test_export_never_writes_over_its_own_store_or_through_a_symlink(synced, tmp_path, capsys):
    db = synced.path
    before = db.read_bytes()
    spelled = tmp_path / "sub" / ".." / db.name  # the store under another spelling
    (tmp_path / "sub").mkdir()
    for out in (db, spelled):
        assert cli.main(["export", "--db", str(db), "--out", str(out)], clock=lambda: T0) == 2
        assert "is the store itself" in capsys.readouterr().err
    assert db.read_bytes() == before
    target = tmp_path / "elsewhere.txt"
    target.write_text("keep me\n", encoding="utf-8")
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    assert cli.main(["export", "--db", str(db), "--out", str(link)], clock=lambda: T0) == 2
    assert "symlink" in capsys.readouterr().err
    assert target.read_text(encoding="utf-8") == "keep me\n" and link.is_symlink()


def test_export_replaces_its_output_whole_leaving_no_temporary_file(synced, tmp_path):
    out = tmp_path / "out" / "export.jsonl"
    out.parent.mkdir()
    out.write_text("an older export\n", encoding="utf-8")
    assert cli.main(["export", "--db", str(synced.path), "--out", str(out)], clock=lambda: T0) == 0
    assert out.read_text(encoding="utf-8") == "".join(f"{x}\n" for x in export_lines(synced))
    assert [p.name for p in out.parent.iterdir()] == ["export.jsonl"]


def test_hnx_help_names_export_and_import(capsys):
    """``hnx --help`` is the only map of the subcommands: the orchestration line names them all."""
    from homelabnext import cli as hnx

    hnx.main(["--help"])
    (line,) = [x for x in capsys.readouterr().out.splitlines() if "orchestration telemetry" in x]
    for sub in ("consume", "ingest", "turns", "report", "export", "import"):
        assert sub in line.split(":", 1)[1], sub


def test_an_export_starts_with_a_header_naming_its_store(synced):
    header = json.loads(next(iter(export_lines(synced))))
    assert header == {
        "schema": EXPORT_SCHEMA,
        "kind": "header",
        "sources": ["svc:llm-orchestrator"],
        "retention_days": 90,
        "exported_at": "2026-01-01T06:00:00Z",
    }


def test_an_import_into_a_store_of_other_sources_says_why_every_job_is_refused(synced, tmp_path):
    lines = list(export_lines(synced))
    other = TelemetryStore(tmp_path / "o.db", clock=lambda: T0, sources=["svc:other-ctl"])
    counts, refused = import_lines(other, lines)
    assert counts == {"refused": 8}  # the jobs, then their turns, which join no job
    assert all("no job holds gateway tag" in why for _, why in refused[4:])
    for _, why in refused[:4]:
        assert "not the controller's job record" in why
        assert "the export's store took svc:llm-orchestrator; this store takes svc:other-ctl" in why
    misplaced = [lines[1], lines[0]]  # a header is the first line or nothing
    counts, refused = import_lines(TelemetryStore(tmp_path / "p.db", clock=lambda: T0), misplaced)
    assert refused == [(2, "a header is the first line of an export")]
    bad = json.dumps(json.loads(lines[0]) | {"note": "x"})
    _, refused = import_lines(TelemetryStore(tmp_path / "q.db", clock=lambda: T0), [bad])
    assert refused and "not a header" in refused[0][1]


def test_export_of_records_an_import_would_refuse_warns_with_a_count_and_exits_1(tmp_path, capsys):
    """A pilot store from before exports: jobs kept without their envelope and turns written
    before the neutral record's rename.  The export still writes them, and says it, exit 1."""
    store = TelemetryStore(tmp_path / "t.db", clock=lambda: T0)
    for ev in examples()[:2]:
        store.consume(body(ev))
    old_turn = BLANK | {
        "turn_id": "t-old",
        "gateway_tag": "run-0001",
        "started_at": "2026-01-01T00:01:00Z",
    }
    store.add_turns([old_turn])
    with store._db() as db:
        db.execute("UPDATE jobs SET event = NULL WHERE run_id = 'run-0001'")
        doc = json.dumps(
            {k if k != "model_role" else "model_group": v for k, v in old_turn.items()}
        )
        db.execute("UPDATE turns SET doc = ?", (doc,))
    out = tmp_path / "e.jsonl"
    assert cli.main(["export", "--db", str(store.path), "--out", str(out)], clock=lambda: T0) == 1
    err = capsys.readouterr().err
    assert "3 record(s)" in err
    assert (
        "2 an import would refuse: 1 job(s) without an envelope the consumer takes, 1 turn(s) not a turn record"
        in err
    )
    assert len(out.read_text().splitlines()) == 4  # header + 3 records, all still written


def test_an_import_refuses_future_times_and_turns_of_no_job(synced, tmp_path):
    """A turn more than a day ahead of the store's clock would outlive retention by its forged
    start, a forged turns_settled_at keeps a job from ever being read, and a turn whose tag
    joins no job (stored, or imported before it) is cost added to nothing, or to a job it never
    belonged to once one takes the tag."""
    lines = list(export_lines(synced))
    jobs = [json.loads(x) for x in lines if '"kind": "job"' in x]
    turn = json.loads(lines[-1])["turn"]
    other = TelemetryStore(tmp_path / "o.db", clock=lambda: T0)
    future = _line(kind="job", event=jobs[0]["event"], turns_settled_at="2099-01-01T00:00:00Z")
    counts, refused = import_lines(other, [future])
    assert counts == {"refused": 1} and "turns_settled_at is in the future" in refused[0][1]
    assert other.jobs() == []  # refused before the job was consumed
    bad = [
        _line(kind="turn", turn=turn | {"turn_id": "t-fut", "started_at": "2099-01-01T00:00:00Z"}),
        _line(kind="turn", turn=turn | {"turn_id": "t-orphan", "gateway_tag": "no-such-job"}),
    ]
    counts, refused = import_lines(other, bad)
    assert counts == {"refused": 2}
    assert "started_at is in the future" in refused[0][1]
    assert "no job holds gateway tag 'no-such-job'" in refused[1][1]
    assert other.turns() == {}
    near = T0 + 3600  # an hour of clock skew between hosts is a record, not a forgery
    ok = _line(kind="turn", turn=turn | {"turn_id": "t-near", "started_at": iso(near)})
    counts, refused = import_lines(other, [*lines[1:5], ok])
    assert refused == [] and counts[("turn", "processed")] == 1


@pytest.mark.parametrize(
    "change",
    [
        {"sources": ["svc:evil\x1b[31mRED\x1b[0m\nline2"]},
        {"sources": ["not-a-service-id"]},
        {"sources": []},
        {"retention_days": "x"},
        {"retention_days": {"a": 1}},
        {"exported_at": "yesterday"},
    ],
)
def test_a_header_that_is_not_a_store_s_header_is_refused_and_never_printed(
    synced, tmp_path, change
):
    lines = list(export_lines(synced))
    bad = json.dumps(json.loads(lines[0]) | change)
    other = TelemetryStore(tmp_path / "o.db", clock=lambda: T0, sources=["svc:other-ctl"])
    _, refused = import_lines(other, [bad, *lines[1:]])
    assert refused[0][0] == 1 and "not a header" in refused[0][1]
    assert not any("\x1b" in why or "evil" in why for _, why in refused)


def test_an_import_never_rewrites_a_stored_turn_with_another_body(synced, tmp_path):
    """Jobs are refused when their id comes back with another body; so is a turn: a re-import
    with a rewritten cost or another job's tag would move it, or inflate that job's cost."""
    lines = list(export_lines(synced))
    rec = json.loads(lines[-1])
    stored = rec["turn"]
    other_tag = next(t for t in synced.turns() if t != stored["gateway_tag"])
    for change in ({"cost_usd": 999.0}, {"gateway_tag": other_tag}):
        line = json.dumps(rec | {"turn": stored | change})
        counts, refused = import_lines(synced, [line])
        assert counts == {"refused": 1} and "already stored with another body" in refused[0][1]
    assert synced.turn(stored["turn_id"]) == stored


def test_export_counts_a_stored_envelope_the_closed_rules_now_refuse(tmp_path, capsys):
    """A store a build before the closed envelope wrote can hold an extension or a free subject:
    the export writes it, an import would refuse it, so it is counted (exit 1)."""
    store = TelemetryStore(tmp_path / "t.db", clock=lambda: T0)
    ev = examples()[0]
    store.consume(body(ev))
    with store._db() as db:
        db.execute("UPDATE jobs SET event = ?", (json.dumps(ev | {"comment": "fake free text"}),))
    out = tmp_path / "e.jsonl"
    assert cli.main(["export", "--db", str(store.path), "--out", str(out)], clock=lambda: T0) == 1
    assert "1 an import would refuse: 1 job(s)" in capsys.readouterr().err


def test_every_export_line_validates_against_the_export_schema(synced):
    """export/1 is checkable by a third party: schemas/status/orchestration_export.schema.json
    (header, job or turn, each closed) accepts every line an export writes."""
    from jsonschema import Draft202012Validator

    from conformance.protocols.inference import LABEL_PATTERN, MODEL_PATTERN, TAG, TURN_ID
    from homelabnext.events.envelope import _registry

    root = Path(__file__).resolve().parents[2]
    path = root / "schemas" / "status" / "orchestration_export.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, registry=_registry())
    for line in export_lines(synced):
        errors = sorted(e.message for e in validator.iter_errors(json.loads(line)))
        assert errors == [], (line[:120], errors)
    turn = schema["$defs"]["turn"]["properties"]
    assert turn["model"]["pattern"] == f"^{MODEL_PATTERN}$(?!\\n)"
    assert (
        turn["model_role"]["pattern"] == turn["call_type"]["pattern"] == f"^{LABEL_PATTERN}$(?!\\n)"
    )
    assert turn["turn_id"]["pattern"] == f"^{TURN_ID.pattern}$(?!\\n)"
    assert turn["gateway_tag"]["pattern"] == f"^{TAG.pattern}$(?!\\n)"


def test_the_export_schemas_inlined_id_patterns_are_the_ids_patterns_plus_the_newline_guard():
    """The export schema inlines ids/logical-id's svc_id and ids/common's timestamp (a $ref
    could not add the trailing-newline guard); if ids/ changes, the copy must follow it."""
    root = Path(__file__).resolve().parents[2]
    load = lambda *p: json.loads(root.joinpath("schemas", *p).read_text(encoding="utf-8"))  # noqa: E731
    export = load("status", "orchestration_export.schema.json")
    svc = load("ids", "logical-id.schema.json")["$defs"]["svc_id"]
    stamp = load("ids", "common.schema.json")["$defs"]["timestamp"]
    guard = "(?!\\n)"
    sources = export["$defs"]["header"]["properties"]["sources"]["items"]
    assert sources["pattern"] == svc["pattern"] + guard
    assert sources["maxLength"] == svc["maxLength"]
    assert export["$defs"]["time"]["pattern"] == stamp["pattern"] + guard
    # turn.started_at is a third inlined timestamp pattern, left out on purpose: it is narrower
    # than ids/common's (Z only) and has no ids/ source to follow, so it must not be "fixed" here


@pytest.mark.parametrize(
    "change",
    [
        {"retention_days": 0},
        {"retention_days": 1e9},
        {"sources": ["svc:a\n"]},
        {"exported_at": "2026-01-01T06:00:00Z\n"},
    ],
)
def test_the_schema_and_the_import_refuse_the_same_headers(synced, tmp_path, change):
    """The export schema and import disagreed at the edges: a retention outside 1..3650 passed
    import, and a trailing newline passed the schema ($refs to ids/ patterns without (?!\\n))."""
    from jsonschema import Draft202012Validator

    from homelabnext.events.envelope import _registry

    root = Path(__file__).resolve().parents[2]
    path = root / "schemas" / "status" / "orchestration_export.schema.json"
    validator = Draft202012Validator(json.loads(path.read_text("utf-8")), registry=_registry())
    header = json.loads(next(iter(export_lines(synced)))) | change
    assert not validator.is_valid(header)
    other = TelemetryStore(tmp_path / "o.db", clock=lambda: T0)
    _, refused = import_lines(other, [json.dumps(header)])
    assert refused and "not a header" in refused[0][1]
