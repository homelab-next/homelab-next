# SPDX-License-Identifier: Apache-2.0
"""Write lanes: every escape attempt is refused with its machine reason and writes nothing, and the
same lane accepts the well-formed write next to it (fail on the bad input, pass on the good)."""

from __future__ import annotations

import os
import re

import pytest

from homelabnext.broker.lanes import Lane, LaneError, check_params, name_tag, write
from homelabnext.records.notes import check_filename, parse_note

NOW = "2026-01-15T10:00:00Z"
ACTOR = "profile:triage"


def _lane(**over):
    doc = {
        "name": "memory",
        "kind": "files",
        "root": "memory",
        "max_bytes": 64,
        "filename_pattern": r"^[a-z0-9][a-z0-9-]{0,30}\.md$",
    }
    doc.update(over)
    return Lane.from_doc(doc)


def _refused(lane, root, params, reason, actor=ACTOR):
    with pytest.raises(LaneError) as info:
        write(lane, root, actor, params, NOW)
    assert info.value.reason == reason, (info.value.reason, str(info.value))
    return info.value


def _files(root):
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())


def test_well_formed_write_lands_in_the_actors_own_dir(tmp_path):
    out = write(_lane(), tmp_path, ACTOR, {"name": "notes.md", "content": "hello\n"}, NOW)
    assert out["path"] == "memory/triage/notes.md" and out["bytes"] == 6
    assert (tmp_path / "memory/triage/notes.md").read_text() == "hello\n"
    assert out["digest"].startswith("sha256:")
    assert _files(tmp_path) == ["memory/triage/notes.md"], "a temp file was left behind"


@pytest.mark.parametrize(
    "name",
    [
        "../escape.md",
        "../../etc/cron.d/x",
        "/etc/passwd",
        "sub/dir.md",
        "a\\b.md",
        ".hidden.md",
        "..",
        "nul\x00.md",
        "",
        "UPPER.md",  # outside the lane's pattern
        "notes.txt",
        7,
    ],
)
def test_names_that_are_not_one_allowed_segment_are_refused(tmp_path, name):
    _refused(_lane(), tmp_path, {"name": name, "content": "x"}, "lane-name-invalid")
    assert _files(tmp_path) == []
    write(_lane(), tmp_path, ACTOR, {"name": "ok.md", "content": "x"}, NOW)  # control


def test_symlinked_actor_dir_cannot_redirect_the_write(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    data = tmp_path / "data"
    (data / "memory").mkdir(parents=True)
    os.symlink(outside, data / "memory" / "triage")
    _refused(_lane(), data, {"name": "x.md", "content": "x"}, "lane-path-escape")
    assert list(outside.iterdir()) == [], "the write followed the symlink out of the lane"
    write(_lane(), data, "profile:other", {"name": "x.md", "content": "x"}, NOW)  # control


def test_symlinked_lane_root_is_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    data = tmp_path / "data"
    data.mkdir()
    os.symlink(outside, data / "memory")
    _refused(_lane(), data, {"name": "x.md", "content": "x"}, "lane-path-escape")
    assert list(outside.iterdir()) == []


def test_lane_root_component_that_is_a_file_is_refused(tmp_path):
    (tmp_path / "memory").write_text("not a dir")
    _refused(_lane(), tmp_path, {"name": "x.md", "content": "x"}, "lane-path-escape")


def test_target_name_that_is_a_symlink_is_refused(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("original")
    d = tmp_path / "data" / "memory" / "triage"
    d.mkdir(parents=True)
    os.symlink(victim, d / "x.md")
    lane = _lane(overwrite=True)  # even a lane that may overwrite does not follow a link
    _refused(lane, tmp_path / "data", {"name": "x.md", "content": "pwned"}, "lane-symlink")
    assert victim.read_text() == "original"


def test_exclusive_create_by_default_and_atomic_overwrite_when_declared(tmp_path):
    params = {"name": "x.md", "content": "one"}
    write(_lane(), tmp_path, ACTOR, params, NOW)
    _refused(_lane(), tmp_path, {"name": "x.md", "content": "two"}, "lane-exists")
    assert (tmp_path / "memory/triage/x.md").read_text() == "one"
    write(_lane(overwrite=True), tmp_path, ACTOR, {"name": "x.md", "content": "two"}, NOW)
    assert (tmp_path / "memory/triage/x.md").read_text() == "two"
    assert _files(tmp_path) == ["memory/triage/x.md"]


def test_overwrite_lane_refuses_a_directory_in_the_way(tmp_path):
    (tmp_path / "memory/triage/x.md").mkdir(parents=True)
    _refused(_lane(overwrite=True), tmp_path, {"name": "x.md", "content": "y"}, "lane-path-escape")


def test_size_cap_is_enforced_before_any_write(tmp_path):
    err = _refused(_lane(), tmp_path, {"name": "x.md", "content": "x" * 65}, "lane-too-large")
    assert err.outcome == "invalid"
    assert _files(tmp_path) == []
    write(_lane(), tmp_path, ACTOR, {"name": "x.md", "content": "x" * 64}, NOW)  # at the cap


def test_shared_lane_writes_at_the_root(tmp_path):
    out = write(
        _lane(per_actor=False), tmp_path, "svc-anything", {"name": "x.md", "content": "y"}, NOW
    )
    assert out["path"] == "memory/x.md"


@pytest.mark.parametrize(
    ("params", "reason"),
    [
        ({"name": "x.md"}, "lane-content-invalid"),
        ({"name": "x.md", "content": "x", "mode": "0777"}, "lane-content-invalid"),
        ({"name": "x.md", "content": {"not": "text"}}, "lane-content-invalid"),
        ("not-a-mapping", "lane-content-invalid"),
    ],
)
def test_params_shape(tmp_path, params, reason):
    _refused(_lane(), tmp_path, params, reason)


def test_per_actor_lane_needs_a_profile_actor(tmp_path):
    _refused(
        _lane(), tmp_path, {"name": "x.md", "content": "x"}, "lane-actor-invalid", actor="../x"
    )


def _json_lane(**over):
    doc = {
        "format": "json",
        "filename_pattern": r"^[a-z0-9-]+\.json$",
        "max_bytes": 2048,
        "content_schema": "broker/approval",
    }
    return _lane(**{**doc, **over})


APPROVAL = {
    "approval_id": "appr-1",
    "request_id": "req-1",
    "request_digest": "sha256:" + "0" * 64,
    "decision": "approved",
    "approver": {"issuer": "sso", "subject": "operator-one"},
    "approved_at": NOW,
}


def test_json_lane_validates_against_its_content_schema(tmp_path):
    bad = dict(APPROVAL, decision="maybe")
    _refused(_json_lane(), tmp_path, {"name": "a.json", "content": bad}, "lane-content-invalid")
    _refused(_json_lane(), tmp_path, {"name": "a.json", "content": "text"}, "lane-content-invalid")
    big = dict(APPROVAL, note="x" * 500)
    _refused(
        _json_lane(max_bytes=200), tmp_path, {"name": "a.json", "content": big}, "lane-too-large"
    )
    assert _files(tmp_path) == []
    out = write(_json_lane(), tmp_path, ACTOR, {"name": "a.json", "content": APPROVAL}, NOW)
    assert out["path"] == "memory/triage/a.json"


def _inbox(**over):
    doc = {"name": "proposals", "kind": "records-inbox", "root": "records", "max_bytes": 4096}
    doc.update(over)
    return Lane.from_doc(doc)


NOTE = {"title": "Raise the drain timeout", "risk": "low", "rollback": "set it back"}


KEY = b"fake-lane-name-key"


def test_records_inbox_files_a_valid_note_bound_to_the_actor(tmp_path):
    out = write(_inbox(), tmp_path, ACTOR, {"note": dict(NOTE), "body": "Why."}, NOW, key=KEY)
    tag = name_tag(KEY, ACTOR, "2026-01-15", "raise-the-drain-timeout")
    assert re.fullmatch(r"[0-9a-f]{8}", tag)
    assert out["path"] == f"records/inbox/2026-01-15-triage-raise-the-drain-timeout-{tag}.md"
    text = (tmp_path / out["path"]).read_text()
    assert "requesting_agent: profile:triage" in text and "status: proposed" in text
    fm, _ = parse_note(text)
    assert check_filename(out["path"].rsplit("/", 1)[1], fm) == []  # the records convention


def test_records_inbox_dates_the_note_itself(tmp_path):
    """The broker's clock dates a note: a caller-chosen ``created`` (back- or forward-dated, the
    way to claim a future day's file name) is refused."""
    for created in ("2026-12-01T00:00:00Z", NOW):
        _refused(_inbox(), tmp_path, {"note": dict(NOTE, created=created)}, "lane-created-set")
    assert _files(tmp_path) == []
    out = write(_inbox(), tmp_path, ACTOR, {"note": dict(NOTE)}, NOW, key=KEY)
    fm, _ = parse_note((tmp_path / out["path"]).read_text())
    assert fm["created"] == NOW and out["path"].startswith("records/inbox/2026-01-15-")


def test_an_agent_whose_slug_prefixes_another_cannot_claim_its_file_name(tmp_path):
    """``triage`` filing slug ``lead-weekly-report`` used to take
    ``<date>-triage-lead-weekly-report.md``: exactly the name ``triage-lead``'s own
    ``weekly-report`` gets, which then answered ``lane-exists``."""
    squat = {"note": dict(NOTE, title="weekly report"), "slug": "lead-weekly-report"}
    first = write(_inbox(), tmp_path, "profile:triage", squat, NOW, key=KEY)
    own = {"note": dict(NOTE, title="weekly report"), "slug": "weekly-report"}
    second = write(_inbox(), tmp_path, "profile:triage-lead", own, NOW, key=KEY)
    assert first["path"] != second["path"]
    assert second["path"].startswith("records/inbox/2026-01-15-triage-lead-weekly-report-")
    # the same caller, slug and day: the same name again, so a retry never files twice
    with pytest.raises(LaneError) as info:
        write(_inbox(), tmp_path, "profile:triage-lead", own, NOW, key=KEY)
    assert info.value.reason == "lane-exists"


def test_a_callers_slug_leaves_room_for_the_tag(tmp_path):
    long = "a" * 52
    _refused(_inbox(), tmp_path, {"note": dict(NOTE), "slug": long}, "lane-content-invalid")
    out = write(_inbox(), tmp_path, ACTOR, {"note": dict(NOTE), "slug": long[:51]}, NOW, key=KEY)
    fm, _ = parse_note((tmp_path / out["path"]).read_text())
    assert check_filename(out["path"].rsplit("/", 1)[1], fm) == []


@pytest.mark.parametrize(
    ("params", "reason"),
    [
        ({"note": dict(NOTE, requesting_agent="profile:someone-else")}, "lane-identity-mismatch"),
        ({"note": dict(NOTE, type="task")}, "lane-content-invalid"),  # not in note_types
        ({"note": {"title": "No risk or rollback"}}, "lane-content-invalid"),
        ({"note": dict(NOTE), "body": 5}, "lane-content-invalid"),
        ({"note": dict(NOTE), "slug": "Not A Slug"}, "lane-content-invalid"),
        ({"note": dict(NOTE), "extra": 1}, "lane-content-invalid"),
        ({"note": dict(NOTE), "body": "x" * 5000}, "lane-too-large"),
    ],
)
def test_records_inbox_refusals(tmp_path, params, reason):
    _refused(_inbox(), tmp_path, params, reason)
    assert _files(tmp_path) == []


def test_records_inbox_needs_a_profile_actor(tmp_path):
    _refused(_inbox(), tmp_path, {"note": dict(NOTE)}, "lane-actor-invalid", actor="nobody")


def test_check_params_needs_no_filesystem(tmp_path):
    check_params(_lane(), ACTOR, {"name": "x.md", "content": "x"}, NOW)
    with pytest.raises(LaneError):
        check_params(_lane(), ACTOR, {"name": "../x.md", "content": "x"}, NOW)
    assert _files(tmp_path) == []


def test_lane_configuration_problems():
    assert _lane().problems() == []
    assert _lane(filename_pattern="(").problems()
    assert _lane(root="a//b").problems()
    assert _lane(content_schema="broker/approval").problems()  # text lane
    assert _json_lane(content_schema="broker/nope").problems()
    assert _inbox(per_actor=True).problems()


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_written_files_are_owner_only(tmp_path):
    """State and lane files can hold audit detail and agent memory: no group or other bits."""
    from homelabnext.broker.state import write_exclusive

    old = os.umask(0)
    try:
        assert write_exclusive(tmp_path / "rec.json", b"{}\n")
        write(_lane(), tmp_path, ACTOR, {"name": "note.md", "content": "hi\n"}, NOW)
    finally:
        os.umask(old)
    files = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert len(files) == 2
    for p in files:
        assert p.stat().st_mode & 0o077 == 0, (p, oct(p.stat().st_mode))
