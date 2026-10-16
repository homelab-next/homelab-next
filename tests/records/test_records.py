# SPDX-License-Identifier: Apache-2.0
import ast
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from homelabnext.records import (
    LaneViolation,
    NoteError,
    Records,
    RecordsReader,
    check_filename,
    parse_note,
    validate_note,
)
from homelabnext.records.decider import Decider, init_tree

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 1, 1, 9, 30, tzinfo=UTC)
AGENT = "profile:triage"


@pytest.fixture
def tree(tmp_path):
    init_tree(tmp_path)
    return tmp_path


@pytest.fixture
def rec(tree):
    return Records(tree, lambda: NOW)


def proposal(**kw):
    n = {
        "title": "Raise auth burst threshold",
        "risk": "low",
        "rollback": "Revert the threshold and redeploy",
        "requesting_agent": AGENT,
    }
    n.update(kw)
    return n


def test_propose_writes_valid_note_in_inbox_with_convention_filename(rec, tree):
    p = rec.propose(proposal(), body="Because of noise.")
    assert p == tree / "inbox" / "2026-01-01-triage-raise-auth-burst-threshold.md"
    fm, body = parse_note(p.read_text())
    assert fm["type"] == "proposal" and fm["status"] == "proposed"
    assert fm["created"] == "2026-01-01T09:30:00Z" and body.strip() == "Because of noise."
    validate_note(fm)
    assert check_filename(p.name, fm) == []


def test_slug_override_and_no_overwrite(rec):
    p = rec.propose(proposal(), slug="auth-burst")
    assert p.name == "2026-01-01-triage-auth-burst.md"
    with pytest.raises(FileExistsError):
        rec.propose(proposal(), slug="auth-burst")
    assert not list(p.parent.glob(".*.tmp"))


@pytest.mark.parametrize(
    ("patch", "field"),
    [
        ({"rollback": None}, "rollback"),
        ({"risk": "extreme"}, "risk"),
        ({"requesting_agent": "Some Agent"}, "requesting_agent"),
        ({"title": ""}, "title"),
        ({"related": ["../secrets.md"]}, "related"),
        ({"type": "weather"}, "type"),
    ],
)
def test_invalid_notes_are_refused_naming_the_field_and_write_nothing(rec, tree, patch, field):
    n = proposal()
    for k, v in patch.items():
        if v is None:
            del n[k]
        else:
            n[k] = v
    with pytest.raises(ValueError, match=field):
        rec.propose(n)
    assert list((tree / "inbox").iterdir()) == []


def test_propose_refuses_other_types(rec):
    with pytest.raises(NoteError, match="type"):
        rec.propose({**proposal(), "type": "finding"})


def test_bad_slug_cannot_escape_the_lane(rec, tree):
    for slug in ("../evil", "a/b", "UPPER", ".."):
        with pytest.raises(NoteError):
            rec.propose(proposal(), slug=slug)
    assert list((tree / "inbox").iterdir()) == []


def test_write_path_refuses_any_lane_but_inbox(rec, tree):
    for lane in ("decided/approved", "decided/denied", "decided/completed", "../elsewhere", ""):
        with pytest.raises(LaneViolation):
            rec._write_note(lane, "x.md", "text")
    for name in ("../x.md", "a/b.md", "x.txt", ""):
        with pytest.raises(LaneViolation):
            rec._write_note("inbox", name, "text")
    assert not list((tree / "decided").rglob("*.md"))


def test_inbox_symlinked_outside_root_is_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / "inbox").symlink_to(outside)
    with pytest.raises(LaneViolation):
        Records(root, lambda: NOW).propose(proposal())
    assert list(outside.iterdir()) == []


def test_submit_finding_escalation_task(rec):
    f = rec.submit(
        {
            "type": "finding",
            "title": "Backup gap",
            "area": "backup",
            "severity": "medium",
            "requesting_agent": AGENT,
        }
    )
    assert "finding" in f.read_text()
    with pytest.raises(ValueError, match="done_when"):
        rec.submit(
            {
                "type": "task",
                "title": "t",
                "assigned_to": "executor",
                "expires": "2026-01-08T00:00:00Z",
                "requesting_agent": AGENT,
            }
        )
    with pytest.raises(NoteError, match="completion_request"):
        rec.submit({"type": "completion-request", "title": "t", "requesting_agent": AGENT})


def _approved(tree, rec):
    """Propose then have the operator approve; return the approved filename."""
    p = rec.propose(proposal())
    Decider(tree, decided_by="operator", clock=lambda: NOW).approve(p.name)
    return p.name


def test_full_lifecycle_propose_approve_complete(rec, tree):
    name = _approved(tree, rec)
    assert rec.reader.list("inbox") == [] and rec.reader.list("decided/approved") == [name]
    req = rec.completion_request([name], "Implemented and verified.", agent="triage")
    fm, _ = parse_note(req.read_text())
    assert fm["related"] == [f"decided/approved/{name}"] and fm["type"] == "completion-request"
    assert req.parent.name == "inbox"
    moved = Decider(tree, decided_by="operator", clock=lambda: NOW).complete(req.name)
    assert {m.parent.as_posix().split("decided/")[1] for m in moved} == {"completed"}
    assert rec.reader.list("decided/approved") == []
    assert sorted(rec.reader.list("decided/completed")) == sorted([name, req.name])
    assert rec.reader.list("inbox") == []
    audit = (tree / "decided/completed" / f"{name}.decision.json").read_text()
    assert '"decided_by": "operator"' in audit and req.name in audit


def test_deny_moves_to_denied_with_reason(rec, tree):
    p = rec.propose(proposal())
    Decider(tree, decided_by="operator", clock=lambda: NOW).deny(p.name, "too risky")
    assert rec.reader.list("decided/denied") == [p.name] and rec.reader.list("inbox") == []
    assert "too risky" in (tree / "decided/denied" / f"{p.name}.decision.json").read_text()


def test_completion_request_refuses_unapproved_or_bad_related(rec, tree):
    with pytest.raises(NoteError, match="does not exist"):
        rec.completion_request(["2026-01-01-triage-nothing.md"], "x", agent="triage")
    with pytest.raises(NoteError):
        rec.completion_request([], "x", agent="triage")
    with pytest.raises(NoteError):
        rec.completion_request(["inbox/2026-01-01-triage-x.md"], "x", agent="triage")
    with pytest.raises(NoteError):
        rec.completion_request(["../approved/x.md"], "x", agent="triage")


def test_complete_is_all_or_nothing_when_a_related_item_vanished(rec, tree):
    name = _approved(tree, rec)
    req = rec.completion_request([name], "done", agent="triage")
    (tree / "decided/approved" / name).unlink()
    with pytest.raises(NoteError, match="not in the approved lane"):
        Decider(tree, decided_by="op").complete(req.name)
    assert rec.reader.list("inbox") == [req.name]  # untouched


def test_decider_guards(rec, tree):
    d = Decider(tree, decided_by="op", clock=lambda: NOW)
    p = rec.propose(proposal())
    with pytest.raises(LaneViolation):
        d.approve("../inbox/" + p.name)
    with pytest.raises(FileNotFoundError):
        d.approve("2026-01-01-triage-missing.md")
    req_src = rec.reader.read("inbox", p.name)
    assert req_src.type == "proposal"
    with pytest.raises(NoteError, match="not a completion-request"):
        d.complete(p.name)
    with pytest.raises(ValueError):
        Decider(tree, decided_by="")


def test_decider_refuses_to_move_an_invalid_hand_dropped_file(tree):
    bad = tree / "inbox" / "2026-01-01-triage-bad.md"
    bad.write_text(
        "---\ntype: proposal\ntitle: t\nrisk: low\nrequesting_agent: profile:triage\ncreated: '2026-01-01T00:00:00Z'\n---\n"
    )
    with pytest.raises(NoteError, match="rollback"):
        Decider(tree, decided_by="op").approve(bad.name)
    assert bad.exists()


def test_filename_must_agree_with_frontmatter(tree):
    wrong = tree / "inbox" / "2026-02-02-triage-x.md"  # date != created
    wrong.write_text(
        "---\ntype: proposal\ntitle: t\nrisk: low\nrollback: r\nrequesting_agent: profile:triage\n"
        "created: '2026-01-01T00:00:00Z'\n---\n"
    )
    with pytest.raises(NoteError, match="date"):
        Decider(tree, decided_by="op").approve(wrong.name)


def test_reader_reads_all_lanes_and_filters_by_type(rec, tree):
    name = _approved(tree, rec)
    rec.submit(
        {
            "type": "finding",
            "title": "Gap",
            "area": "backup",
            "severity": "low",
            "requesting_agent": AGENT,
        }
    )
    r = RecordsReader(tree)
    assert [n.name for n in r.iter_notes("decided/approved", type="proposal")] == [name]
    assert [n.type for n in r.iter_notes("inbox")] == ["finding"]
    assert r.iter_notes("decided/denied", type="x") is not None and r.list("decided/denied") == []
    with pytest.raises(ValueError):
        r.list("secrets")
    with pytest.raises(ValueError):
        r.read("inbox", "../x.md")


def test_reader_has_no_write_methods():
    assert not [m for m in dir(RecordsReader) if m.lstrip("_").startswith(("write", "move", "put"))]


def test_agent_api_cannot_reach_the_operator_movers():
    code = (
        "import sys, homelabnext.records as r\n"
        "assert 'homelabnext.records.decider' not in sys.modules\n"
        "for n in ('Decider','init_tree','approve','deny','complete'):\n"
        "    assert not hasattr(r, n), n\n"
        "print('isolated')\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
        env={"PYTHONPATH": str(ROOT), "PATH": ""},
    )
    assert out.stdout.strip() == "isolated", out.stderr


def test_no_agent_side_module_imports_the_decider():
    pkg = ROOT / "homelabnext" / "records"
    for f in pkg.glob("*.py"):
        if f.name == "decider.py":
            continue
        src = f.read_text()
        for node in ast.walk(ast.parse(src)):
            names = []
            if isinstance(node, ast.ImportFrom):
                names = [node.module or "", *[a.name for a in node.names]]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            assert not any("decider" in n for n in names), f"{f.name} imports the decider"


def test_validate_note_rejects_non_mapping():
    with pytest.raises(NoteError):
        validate_note(["not", "a", "mapping"])


def test_repo_schema_examples_validate_and_negatives_fail():
    ex = sorted((ROOT / "schemas/records/examples").glob("*.md"))
    neg = sorted((ROOT / "schemas/records/negative").glob("*.md"))
    assert ex and neg
    for f in ex:
        validate_note(parse_note(f.read_text())[0])
    for f in neg:
        with pytest.raises(ValueError):
            validate_note(parse_note(f.read_text())[0])
