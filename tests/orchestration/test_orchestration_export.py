# SPDX-License-Identifier: Apache-2.0
"""``hnx orchestration export`` / ``import``: the store as neutral JSON lines
(``homelabnext.orchestration.export/1``) that round-trip into another store, re-import
idempotently by the same ids, and refuse what the bus consumer would refuse."""

from __future__ import annotations

import copy
import json

import pytest
from orch_helpers import BLANK, T0, FakeSpendLogs, body, examples, turn_source

from homelabnext.orchestration import cli
from homelabnext.orchestration.export import EXPORT_SCHEMA, export_lines, import_lines
from homelabnext.orchestration.gateway import sync_turns
from homelabnext.orchestration.store import TelemetryStore


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
    assert [r["kind"] for r in recs] == ["job"] * 4 + ["turn"] * 4  # jobs first, then turns
    assert recs[0]["event"]["type"] == "homelabnext.agent.job.finished"
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
    event = json.loads(good[0])["event"]
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
    assert "jobs 0 processed, 4 duplicate" in out_ and "export.jsonl:9: not JSON" in err
    assert cli.main(["export", "--db", str(tmp_path / "none.db")], clock=lambda: T0) == 2
    assert not (tmp_path / "none.db").exists()


def test_an_older_store_without_envelopes_exports_jobs_an_import_refuses(tmp_path):
    """A store written before exports kept only the record, not its envelope: the export says
    so per job (event null) and an import refuses those lines rather than inventing one."""
    store = TelemetryStore(tmp_path / "t.db", clock=lambda: T0)
    store.consume(body(examples()[0]))
    with store._db() as db:
        db.execute("UPDATE jobs SET event = NULL")
    (line,) = export_lines(store)
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
    counts, refused = import_lines(other, [line, *good])
    assert counts["refused"] == 1 and refused[0][0] == 1 and needle in refused[0][1]
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
