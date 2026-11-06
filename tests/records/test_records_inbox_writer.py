# SPDX-License-Identifier: Apache-2.0
"""One writer of inbox notes: the agent library and the broker's records-inbox lanes both stamp a
note with ``records.inbox.stamp`` and put it on disk with ``records.inbox.write_inbox``, so the
note format and the atomicity rule cannot drift apart between the two paths."""

from __future__ import annotations

import importlib
import os
from datetime import UTC, datetime

import pytest

from homelabnext.broker import lanes
from homelabnext.records import Records, parse_note

NOW = "2026-01-15T10:00:00Z"
T0 = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
NOTE = {"title": "Raise the drain timeout", "risk": "low", "rollback": "set it back"}
AGENT = "profile:triage"


def _inbox():
    """The one inbox writer (imported here, so each test fails on its own without it)."""
    return importlib.import_module("homelabnext.records.inbox")


def _lane(**over):
    doc = {"name": "proposals", "kind": "records-inbox", "root": "records", "max_bytes": 4096}
    return lanes.Lane.from_doc({**doc, **over})


@pytest.fixture
def spy(monkeypatch):
    inbox = _inbox()
    calls: list[tuple[str, int]] = []
    real = inbox.write_inbox

    def write_inbox(dir_fd, name, data, **kw):
        calls.append((name, len(data)))
        return real(dir_fd, name, data, **kw)

    monkeypatch.setattr(inbox, "write_inbox", write_inbox)
    return calls


def test_the_agent_library_files_through_the_one_writer(tmp_path, spy):
    path = Records(tmp_path, lambda: T0, agent=AGENT).propose(dict(NOTE))
    assert spy == [(path.name, path.stat().st_size)]


def test_a_broker_lane_files_through_the_one_writer(tmp_path, spy):
    out = lanes.write(_lane(), tmp_path, AGENT, {"note": dict(NOTE)}, NOW, key=b"fake-key")
    name = out["path"].rsplit("/", 1)[-1]
    assert spy == [(name, out["bytes"])]


def test_both_paths_stamp_a_proposal_alike(tmp_path):
    lib = Records(tmp_path / "a", lambda: T0, agent=AGENT).propose(dict(NOTE))
    out = lanes.write(_lane(), tmp_path / "b", AGENT, {"note": dict(NOTE)}, NOW, key=b"fake-key")
    via_lane = tmp_path / "b" / out["path"]
    stamped = [parse_note(p.read_text(encoding="utf-8"))[0] for p in (lib, via_lane)]
    for fm in stamped:
        assert fm["requesting_agent"] == AGENT and fm["status"] == "proposed", fm
        assert fm["created"] == NOW, fm


def test_write_inbox_never_overwrites_nor_follows_a_symlink(tmp_path):
    (tmp_path / "taken.md").write_text("first\n")
    os.symlink(tmp_path / "elsewhere.md", tmp_path / "link.md")
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in ("taken.md", "link.md"):
            with pytest.raises(FileExistsError):
                _inbox().write_inbox(fd, name, b"second\n")
    finally:
        os.close(fd)
    assert (tmp_path / "taken.md").read_text() == "first\n"
    assert not (tmp_path / "elsewhere.md").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["link.md", "taken.md"], (
        "a temp file stayed"
    )


def test_a_records_inbox_lane_that_would_overwrite_is_refused():
    assert any("never overwrites" in p for p in _lane(overwrite=True).problems())
    assert not _lane().problems()


def test_neither_path_files_a_name_a_decided_lane_holds(tmp_path):
    """The library always refused it; the lane did not (ADR-0010's status note): a note the
    decider later moved would collide with the decided one of the same name."""
    params = {"note": dict(NOTE)}
    first = lanes.write(_lane(), tmp_path, AGENT, params, NOW, key=b"fake-key")
    name = first["path"].rsplit("/", 1)[-1]
    decided = tmp_path / "records" / "decided" / "approved"
    decided.mkdir(parents=True)
    (tmp_path / first["path"]).rename(decided / name)
    with pytest.raises(lanes.LaneError) as info:
        lanes.write(_lane(), tmp_path, AGENT, params, NOW, key=b"fake-key")
    assert info.value.reason == "lane-exists" and "decided/approved" in str(info.value)
    assert not (tmp_path / first["path"]).exists()

    lib = Records(tmp_path / "lib", lambda: T0, agent=AGENT)
    taken = lib.propose(dict(NOTE), slug="taken")
    (tmp_path / "lib" / "decided" / "denied").mkdir(parents=True)
    taken.rename(tmp_path / "lib" / "decided" / "denied" / taken.name)
    with pytest.raises(FileExistsError, match="decided/denied"):
        lib.propose(dict(NOTE), slug="taken")
