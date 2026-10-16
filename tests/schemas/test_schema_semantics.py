# SPDX-License-Identifier: Apache-2.0
"""Rules JSON Schema cannot express, enforced by tools/schema_check.py helpers."""

import json
from pathlib import Path

import schema_check as sc

ROOT = Path(__file__).resolve().parents[2]
FM = {"requesting_agent": "profile:triage", "created": "2026-01-01T00:00:00Z"}


def test_note_filename_ok():
    assert sc.check_note_filename("2026-01-01-triage-raise-threshold.md", FM) == []


def test_note_filename_rejects():
    assert sc.check_note_filename("raise-threshold.md", FM)  # no date
    assert sc.check_note_filename("2026-01-02-triage-x.md", FM)  # date disagrees with created
    assert sc.check_note_filename("2026-01-01-reader-x.md", FM)  # agent disagrees
    assert sc.check_note_filename("2026-01-01-triage.md", FM)  # no slug
    assert sc.check_note_filename("2026-01-01-triage-x.txt", FM)  # wrong extension


def test_markdown_frontmatter_round_trip_keeps_timestamps_as_strings():
    fm, body = sc.split_markdown((ROOT / "schemas/records/examples/note.proposal.md").read_text())
    assert fm["created"] == "2026-01-01T00:00:00Z"
    assert body.strip()


def board(*items):
    return list(items)


P = {
    "id": "PRJ-001",
    "title": "p",
    "column": "partial",
    "steps": [
        {"n": 1, "text": "a", "status": "done", "date": "2026-01-01", "result": "ok"},
        {"n": 2, "text": "b", "status": "open"},
    ],
}


def test_kanban_good_board():
    assert (
        sc.check_kanban_board(board(P, {"id": "PRJ-001.2", "title": "b", "column": "todo"})) == []
    )


def test_kanban_duplicate_ids():
    assert any("duplicate" in e for e in sc.check_kanban_board(board(P, dict(P))))


def test_kanban_new_placeholders_may_repeat():
    assert (
        sc.check_kanban_board(
            board(
                {"id": "PRJ-NEW", "title": "a", "column": "todo"},
                {"id": "PRJ-NEW", "title": "b", "column": "todo"},
            )
        )
        == []
    )


def test_kanban_step_card_must_reference_existing_open_step():
    assert any(
        "missing project" in e
        for e in sc.check_kanban_board(board({"id": "PRJ-009.1", "title": "x", "column": "todo"}))
    )
    assert any(
        "missing step" in e
        for e in sc.check_kanban_board(
            board(P, {"id": "PRJ-001.7", "title": "x", "column": "todo"})
        )
    )
    assert any(
        "already done" in e
        for e in sc.check_kanban_board(
            board(P, {"id": "PRJ-001.1", "title": "x", "column": "todo"})
        )
    )


def test_kanban_all_done_project_cannot_sit_in_partial():
    done = {
        **P,
        "steps": [{"n": 1, "text": "a", "status": "done", "date": "2026-01-01", "result": "ok"}],
    }
    assert any("all steps done" in e for e in sc.check_kanban_board(board(done)))
    assert sc.check_kanban_board(board({**done, "column": "done"})) == []


def test_profile_ceiling_subset():
    ok = json.loads((ROOT / "schemas/platform/examples/agent_profile.valid.json").read_text())
    assert sc.check_profile_ceiling(ok) == []
    assert sc.check_profile_ceiling({**ok, "mcp": ["lake", "shell"]})


def test_cli_exit_codes(tmp_path, capsys):
    assert sc.main(["--root", str(ROOT), "--dir", "ids", "--dir", "events"]) == 0
    import shutil

    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    (tmp_path / "schemas/ids/negative/logical-id.cap.json").write_text('"cap:lake-query"')
    assert sc.main(["--root", str(tmp_path), "--dir", "ids"]) == 1
    assert "ACCEPTED" in capsys.readouterr().out
