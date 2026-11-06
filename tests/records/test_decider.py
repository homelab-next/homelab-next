# SPDX-License-Identifier: Apache-2.0
"""The records decider re-creates a decided note instead of renaming the agent's file, refuses
symlinks and hard-linked notes, and has an operator command (``hnx records decide``)."""

import errno
import os
import stat
from datetime import UTC, datetime

import pytest

from homelabnext.cli import main as hnx
from homelabnext.records import LaneViolation, NoteError, Records, parse_note
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


def test_a_crlf_note_approves_and_its_bytes_are_kept(rec, tree):
    p = _propose(rec)
    crlf = p.read_bytes().replace(b"\n", b"\r\n")
    p.write_bytes(crlf)
    dest = _decider(tree).approve(p.name)
    assert dest.read_bytes() == crlf


def test_a_note_swapped_after_it_was_read_files_the_read_bytes(rec, tree, monkeypatch, capsys):
    p = _propose(rec)
    original = p.read_bytes()
    d = _decider(tree)
    real_move = Decider._move

    def swap_then_move(self, note, *a, **kw):
        # a new inode renamed over the name (written first, so it cannot reuse the inode number)
        repl = p.with_name("replacement.tmp")
        repl.write_bytes(original.replace(b"Revert the threshold", b"none, irreversible"))
        os.rename(repl, p)
        return real_move(self, note, *a, **kw)

    monkeypatch.setattr(Decider, "_move", swap_then_move)
    dest = d.approve(p.name)
    assert dest.read_bytes() == original
    assert b"irreversible" in p.read_bytes()  # the replacement is left where it was
    assert "changed after it was read" in capsys.readouterr().err


def test_read_then_approve_files_what_read_returned(rec, tree):
    """A caller deciding on Decider.read's note files those bytes even if the inode changes."""
    p = _propose(rec)
    original = p.read_bytes()
    d = _decider(tree)
    note = d.read("inbox", p.name)
    assert note.frontmatter["rollback"] == "Revert the threshold"
    with open(p, "r+b") as fh:  # the agent rewrites its own inode after the decision was made
        fh.write(original.replace(b"Revert the threshold", b"none, irreversible  "))
    assert d.approve(p.name).read_bytes() == original


def _refuse_moving(monkeypatch, p):
    """The source may not be moved out of the inbox (a sticky inbox the decider does not own)."""
    real_rename = os.rename

    def refuse(src, *a, **kw):
        if str(src) == str(p):
            raise PermissionError(13, "Permission denied", str(src))
        return real_rename(src, *a, **kw)

    monkeypatch.setattr(os, "rename", refuse)


def test_a_refused_claim_leaves_nothing_in_the_decided_lane(rec, tree, monkeypatch):
    p = _propose(rec)
    _refuse_moving(monkeypatch, p)
    with pytest.raises(PermissionError):
        _decider(tree).approve(p.name)
    monkeypatch.undo()
    assert p.exists()
    assert os.listdir(tree / "decided" / "approved") == []
    assert _decider(tree).approve(p.name).exists()  # a retry, once permitted, goes through


def test_decided_notes_are_not_world_readable(rec, tree):
    old = os.umask(0o022)
    try:
        dest = _decider(tree).approve(_propose(rec).name)
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(dest).st_mode) == 0o640
    side = dest.with_name(dest.name + ".decision.json")
    assert stat.S_IMODE(os.stat(side).st_mode) == 0o640


def test_an_open_error_other_than_a_symlink_is_reported_as_itself(rec, tree, monkeypatch):
    p = _propose(rec)
    real_open = os.open

    def eacces(path, *a, **kw):
        if str(path) == str(p):
            raise PermissionError(errno.EACCES, "Permission denied", str(path))
        return real_open(path, *a, **kw)

    monkeypatch.setattr(os, "open", eacces)
    with pytest.raises(PermissionError) as exc:
        _decider(tree).approve(p.name)
    assert not isinstance(exc.value, LaneViolation)
    assert exc.value.errno == errno.EACCES


def test_complete_refuses_a_related_entry_outside_the_approved_lane(rec, tree):
    p = _propose(rec)
    d = _decider(tree)
    d.approve(p.name)
    other = _propose(rec, slug="other")
    d.deny(other.name)
    req = rec.completion_request([p.name], "Done.", agent="triage")
    text = req.read_text().replace(f"decided/approved/{p.name}", f"decided/denied/{other.name}")
    req.write_text(text)
    with pytest.raises(NoteError):
        d.complete(req.name)
    assert (tree / "decided" / "approved" / p.name).exists()
    assert req.exists()


def test_operator_command_reports_os_errors_and_an_empty_by(rec, tree, monkeypatch, capsys):
    p = _propose(rec)
    root = str(tree)
    assert decide_main(["approve", p.name, "--root", root, "--by", ""]) == 2
    assert "decided_by" in capsys.readouterr().err
    _refuse_moving(monkeypatch, p)
    assert decide_main(["approve", p.name, "--root", root, "--by", "op"]) == 1
    assert "refused" in capsys.readouterr().err


def test_of_an_approve_and_a_deny_raced_on_one_note_exactly_one_wins(rec, tree):
    """Both deciders load the note; the second to claim it finds it gone and files nothing."""
    p = _propose(rec)
    first, second = _decider(tree), _decider(tree)
    first.read("inbox", p.name)
    second.read("inbox", p.name)
    dest = first.approve(p.name)
    with pytest.raises(FileNotFoundError):
        second.deny(p.name, "raced")
    assert dest.exists()
    assert os.listdir(tree / "decided" / "denied") == []
    assert os.listdir(tree / "decided" / ".claims") == []


def test_a_swap_after_another_decider_filed_the_note_is_refused(rec, tree, capsys):
    """The inode read was taken by another decider and the agent wrote a new one at the name:
    the claim gets the replacement, which is put back, and this move fails."""
    p = _propose(rec)
    original = p.read_bytes()
    first, second = _decider(tree), _decider(tree)
    second.read("inbox", p.name)
    held = os.open(p, os.O_RDONLY)  # keeps the inode read alive, so the new one cannot reuse it
    try:
        first.approve(p.name)
        p.write_bytes(original)  # a new inode at the decided name
    finally:
        os.close(held)
    with pytest.raises(FileNotFoundError, match="decided meanwhile"):
        second.deny(p.name, "raced")
    assert p.read_bytes() == original
    assert os.listdir(tree / "decided" / "denied") == []


def test_a_move_failing_after_its_claim_puts_the_note_back(rec, tree, monkeypatch):
    p = _propose(rec)
    original = p.read_bytes()
    import homelabnext.records.decider as decider

    def fail(*a, **kw):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(decider, "_create", fail)
    with pytest.raises(OSError, match="No space"):
        _decider(tree).approve(p.name)
    monkeypatch.undo()
    assert p.read_bytes() == original
    assert os.listdir(tree / "decided" / "approved") == []
    assert os.listdir(tree / "decided" / ".claims") == []
    assert _decider(tree).approve(p.name).read_bytes() == original
