# SPDX-License-Identifier: Apache-2.0
"""The records decider re-creates a decided note instead of renaming the agent's file, refuses
symlinks and hard-linked notes, and has an operator command (``hnx records decide``)."""

import os
from datetime import UTC, datetime

import pytest

from homelabnext.cli import main as hnx
from homelabnext.records import LaneViolation, Records, parse_note
from homelabnext.records.decider import Decider, init_tree
from homelabnext.records.decider import main as decide_main

NOW = datetime(2026, 1, 1, 9, 30, tzinfo=UTC)
AGENT = "profile:triage"


@pytest.fixture
def tree(tmp_path):
    init_tree(tmp_path / "records")
    return tmp_path / "records"


@pytest.fixture
def rec(tree):
    return Records(tree, lambda: NOW)


def _propose(rec, slug="raise-threshold"):
    return rec.propose(
        {
            "title": "Raise auth burst threshold",
            "risk": "low",
            "rollback": "Revert the threshold",
            "requesting_agent": AGENT,
        },
        slug=slug,
    )


def _decider(tree):
    return Decider(tree, decided_by="op", clock=lambda: NOW)


def _ident(path):
    st = os.stat(path)
    return st.st_dev, st.st_ino


def test_approved_note_is_a_new_inode_and_the_inbox_entry_is_gone(rec, tree):
    p = _propose(rec)
    before = _ident(p)
    dest = _decider(tree).approve(p.name)
    assert _ident(dest) != before
    assert os.stat(dest).st_nlink == 1
    assert not os.path.lexists(p)
    assert parse_note(dest.read_text())[0]["rollback"] == "Revert the threshold"


def test_a_descriptor_the_agent_kept_cannot_rewrite_the_approved_note(rec, tree):
    p = _propose(rec)
    original = p.read_bytes()
    fd = os.open(p, os.O_WRONLY)  # the agent keeps its file open across the decision
    try:
        dest = _decider(tree).approve(p.name)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, original.replace(b"Revert the threshold", b"none, irreversible  "))
    finally:
        os.close(fd)
    assert dest.read_bytes() == original


def test_complete_reads_and_files_the_deciders_copy(rec, tree):
    p = _propose(rec)
    original = p.read_bytes()
    d = _decider(tree)
    fd = os.open(p, os.O_WRONLY)
    try:
        approved = d.approve(p.name)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, original.replace(b"Revert", b"Ignore"))
    finally:
        os.close(fd)
    approved_ident = _ident(approved)
    req = rec.completion_request([p.name], "Done.", agent="triage")
    completed = d.complete(req.name)[0]
    assert completed.parent.name == "completed"
    assert completed.read_bytes() == original
    assert _ident(completed) != approved_ident
    assert not os.path.lexists(approved)


def test_a_symlink_in_the_inbox_is_refused(rec, tree, tmp_path):
    p = _propose(rec)
    target = tmp_path / "elsewhere.md"
    os.rename(p, target)
    os.symlink(target, p)
    with pytest.raises(LaneViolation, match="regular file"):
        _decider(tree).approve(p.name)
    assert os.path.islink(p)
    assert not (tree / "decided" / "approved" / p.name).exists()


def test_a_hard_linked_note_is_refused(rec, tree, tmp_path):
    p = _propose(rec)
    os.link(p, tmp_path / "kept.md")  # the agent keeps a second name for the inode
    with pytest.raises(LaneViolation, match="hard links"):
        _decider(tree).approve(p.name)
    with pytest.raises(LaneViolation, match="hard links"):
        _decider(tree).deny(p.name)
    assert p.exists()
    assert not (tree / "decided" / "approved" / p.name).exists()


def test_a_symlink_in_the_approved_lane_is_refused_by_complete(rec, tree, tmp_path):
    p = _propose(rec)
    approved = _decider(tree).approve(p.name)
    target = tmp_path / "swap.md"
    os.rename(approved, target)
    os.symlink(target, approved)
    req = rec.completion_request([p.name], "Done.", agent="triage")
    with pytest.raises(LaneViolation):
        _decider(tree).complete(req.name)
    assert (tree / "inbox" / req.name).exists()


def test_operator_command_approve_deny_complete(rec, tree, capsys):
    a = _propose(rec, slug="one")
    b = _propose(rec, slug="two")
    root = str(tree)
    assert hnx(["records", "decide", "approve", a.name, "--root", root, "--by", "op"]) == 0
    assert capsys.readouterr().out.strip() == f"decided/approved/{a.name}"
    rc = decide_main(["deny", b.name, "--root", root, "--by", "op", "--reason", "too broad"])
    assert rc == 0
    assert (tree / "decided" / "denied" / b.name).exists()
    side = (tree / "decided" / "denied" / f"{b.name}.decision.json").read_text()
    assert "too broad" in side and '"op"' in side
    capsys.readouterr()
    req = rec.completion_request([a.name], "Done.", agent="triage")
    assert hnx(["records", "decide", "complete", req.name, "--root", root, "--by", "op"]) == 0
    out = capsys.readouterr().out.split()
    assert out == [f"decided/completed/{a.name}", f"decided/completed/{req.name}"]


def test_operator_command_refusals_and_usage(rec, tree, capsys):
    root = str(tree)
    assert decide_main(["approve", "2026-01-01-triage-x.md", "--root", root, "--by", "op"]) == 1
    assert "refused" in capsys.readouterr().err
    assert decide_main(["approve"]) == 2
    assert decide_main(["publish", "x.md", "--root", root, "--by", "op"]) == 2
    p = _propose(rec)
    assert decide_main(["approve", p.name, "--root", root, "--by", "op", "--reason", "x"]) == 2
    assert p.exists()


def test_records_router_still_reaches_the_identity_commands(capsys):
    assert hnx(["records", "uid", "-n", "2"]) == 0
    assert len(capsys.readouterr().out.split()) == 2
