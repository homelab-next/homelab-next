# SPDX-License-Identifier: Apache-2.0
"""The notify pairs record (homelabnext.notify.record): what a running notifier writes for the
module census, how it is written so a planted link or a swapped path cannot redirect it, and how
the census reads it and tells a live record from a leftover."""

from __future__ import annotations

import json
import logging
import os
import re
import stat

import pytest

from homelabnext.notify import FakeSender, Notifier
from homelabnext.notify import record as nr
from homelabnext.notify.record import (
    MAX_BYTES,
    MAX_PAIRS,
    PairsRecord,
    Record,
    RecordError,
    parse_record,
    record_in,
    stale,
)
from homelabnext.state import StateStore

DISK = ("Disk almost full", "Disk space recovered")


def _notifier(tmp_path, record):
    return Notifier(FakeSender(), StateStore(tmp_path / "n.json"), record=record)


def _doc(path):
    return json.loads(path.read_text())


def _pairs_dir(tmp_path, name="pairs"):
    d = tmp_path / name
    d.mkdir(mode=0o755)
    os.chmod(d, 0o755)  # whatever the umask: writable by its owner only
    return d


def test_a_notifier_writes_what_it_holds_when_built_and_after_each_registration(tmp_path):
    d = _pairs_dir(tmp_path)
    rec = PairsRecord(d, "broker")
    assert rec.path == d / "broker" / "pairs.json"
    n = _notifier(tmp_path, rec)
    doc = _doc(rec.path)
    assert doc["schema_version"] == 2 and doc["owner"] == "broker" and doc["pairs"] == []
    assert doc["pid"] == os.getpid() and doc["boot_id"] == nr.boot_id()
    assert doc["started"] == nr.process_started(os.getpid())
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", doc["written_at"])
    n.register_pair(*DISK)
    n.register_pair("Sync stalled", "Sync moving", module="external-collector")
    assert _doc(rec.path)["pairs"] == [
        {"problem": "Disk almost full", "recovery": "Disk space recovered"},
        {"problem": "Sync stalled", "recovery": "Sync moving", "module": "external-collector"},
    ]
    # the census parses what the notifier wrote
    assert parse_record(rec.path.read_text(), "broker").pairs == _doc(rec.path)["pairs"]


def test_a_restarted_notifier_replaces_the_record_never_extends_it(tmp_path):
    d = _pairs_dir(tmp_path)
    old = _notifier(tmp_path, PairsRecord(d, "status"))
    old.register_pair(*DISK)
    old.register_pair("Gone", "Back")
    rec = PairsRecord(d, "status")
    new = _notifier(tmp_path, rec)  # a new process holds nothing until it registers
    assert _doc(rec.path)["pairs"] == []
    new.register_pair(*DISK)
    assert [p["problem"] for p in _doc(rec.path)["pairs"]] == ["Disk almost full"]


def test_the_record_is_written_whole_readable_and_leaves_no_temp_file(tmp_path):
    d = _pairs_dir(tmp_path)
    rec = PairsRecord(d, "broker")
    n = _notifier(tmp_path, rec)
    for i in range(20):
        n.register_pair(f"Problem {i}", f"Recovered {i}")
        _doc(rec.path)  # every intermediate state is a whole document
    assert stat.S_IMODE(os.stat(rec.path).st_mode) == 0o644  # titles, read by the census
    assert sorted(os.listdir(d / "broker")) == ["pairs.json"]  # no temp file, no lock file


def test_the_same_pair_repeats_but_never_for_another_module(tmp_path):
    rec = PairsRecord(_pairs_dir(tmp_path), "broker")
    n = _notifier(tmp_path, rec)
    n.register_pair(*DISK)
    n.register_pair(*DISK)  # the same registrant again: one pair
    assert len(_doc(rec.path)["pairs"]) == 1
    with pytest.raises(ValueError, match="already registered for the core"):
        n.register_pair(*DISK, module="external-collector")
    n.register_pair("Sync stalled", "Sync moving", module="external-collector")
    with pytest.raises(ValueError, match="already registered for external-collector"):
        n.register_pair("Sync stalled", "Sync moving")


class _Flaky:
    """A record whose writes fail while ``broken`` is set, keeping the last good set."""

    def __init__(self, broken=False):
        self.broken = broken
        self.written: dict | None = None

    def write(self, pairs):
        if self.broken:
            raise OSError("no space left on device")
        self.written = dict(pairs)


def test_a_failed_first_write_stops_the_notifier_from_starting_quietly(tmp_path):
    with pytest.raises(OSError):
        _notifier(tmp_path, _Flaky(broken=True))


def test_a_later_failed_write_keeps_alerting_and_is_written_again_until_it_succeeds(
    tmp_path, caplog
):
    rec = _Flaky()
    n = _notifier(tmp_path, rec)
    rec.broken = True
    with caplog.at_level(logging.ERROR, logger="homelabnext.notify"):
        n.register_pair(*DISK)  # held (alerting goes on), not recorded, logged
    assert n.is_registered(DISK[0]) and n.record_behind and rec.written == {}
    assert "notify pairs record not written" in caplog.text
    rec.broken = False
    n.register_pair(*DISK)  # a repeat registers nothing new, but catches the record up
    assert rec.written == {DISK[0]: (DISK[1], None)} and not n.record_behind
    rec.broken = True
    n.register_pair("Sync stalled", "Sync moving")
    rec.broken = False
    from homelabnext.notify import Message

    n.report("k", "ok", Message(key="k", title=DISK[0], body=""))  # a report catches up too
    assert set(rec.written) == {DISK[0], "Sync stalled"} and not n.record_behind


def test_without_a_record_nothing_is_written(tmp_path):
    d = _pairs_dir(tmp_path)
    n = _notifier(tmp_path, record_in(None, "broker"))
    n.register_pair(*DISK)
    assert os.listdir(d) == []


# ------------------------------------------------------------------- where it may be written
def test_a_record_names_a_known_owner_and_a_plain_directory(tmp_path):
    d = _pairs_dir(tmp_path)
    with pytest.raises(ValueError, match="owner is one of"):
        PairsRecord(d, "relay")
    with pytest.raises(ValueError, match="is not a directory reached without a link"):
        PairsRecord(tmp_path / "absent", "broker")
    with pytest.raises(ValueError, match="is not an absolute path"):
        PairsRecord("relative/pairs", "broker")
    (tmp_path / "link").symlink_to(d)
    with pytest.raises(ValueError, match="is not a directory reached without a link"):
        PairsRecord(tmp_path / "link", "broker")
    # a link anywhere on the way, not only the last step
    (tmp_path / "via").symlink_to(tmp_path)
    with pytest.raises(ValueError, match="is not a directory reached without a link"):
        PairsRecord(tmp_path / "via" / "pairs", "broker")
    # the owner's own directory, too
    (d / "status").symlink_to(_pairs_dir(tmp_path, "elsewhere"))
    with pytest.raises(ValueError, match="is not a directory reached without a link"):
        PairsRecord(d, "status")


def test_a_directory_others_may_write_is_refused(tmp_path):
    d = _pairs_dir(tmp_path)
    os.chmod(d, 0o775)
    with pytest.raises(ValueError, match="writable by no one else"):
        PairsRecord(d, "broker")
    os.chmod(d, 0o755)
    (d / "broker").mkdir()
    os.chmod(d / "broker", 0o757)
    with pytest.raises(ValueError, match="writable by no one else"):
        PairsRecord(d, "broker")
    os.chmod(d / "broker", 0o755)
    rec = PairsRecord(d, "broker")
    os.chmod(d / "broker", 0o775)  # loosened after start: the next write refuses
    with pytest.raises(ValueError, match="writable by no one else"):
        rec.write({})


def test_a_planted_link_or_fifo_never_redirects_or_blocks_a_write(tmp_path):
    d = _pairs_dir(tmp_path)
    target = tmp_path / "victim"
    target.write_text("untouched\n")
    (d / "broker").mkdir()
    # the record itself as a link: replaced, never written through
    (d / "broker" / "pairs.json").symlink_to(target)
    # the old lock file and a temp name as links, and a FIFO: there is no lock file any more,
    # and every write is relative to the opened directory with a fresh, exclusive temp name
    (d / "broker" / "pairs.json.lock").symlink_to(target)
    rec = PairsRecord(d, "broker")
    rec.write({DISK[0]: (DISK[1], None)})
    (d / "status").mkdir()
    os.mkfifo(d / "status" / "pairs.json.lock")  # opening this would block a writer forever
    os.mkfifo(d / "status" / "pairs.json")
    PairsRecord(d, "status").write({})
    assert stat.S_ISREG(os.lstat(d / "status" / "pairs.json").st_mode)
    assert target.read_text() == "untouched\n"
    assert not (d / "broker" / "pairs.json").is_symlink()
    assert (
        parse_record((d / "broker" / "pairs.json").read_text(), "broker").pairs[0]["problem"]
        == DISK[0]
    )


def test_a_directory_swapped_after_start_cannot_redirect_a_write(tmp_path):
    d = _pairs_dir(tmp_path)
    rec = PairsRecord(d, "broker")
    moved = tmp_path / "moved"
    d.rename(moved)
    elsewhere = _pairs_dir(tmp_path, "elsewhere")
    d.symlink_to(elsewhere)  # the old path now leads somewhere else
    rec.write({DISK[0]: (DISK[1], None)})
    assert os.listdir(elsewhere) == []
    assert (moved / "broker" / "pairs.json").exists()  # the directory it opened at start


# ------------------------------------------------------------------- reading and staleness
BOOT = "00000000-0000-4000-8000-000000000001"


def _rec(pairs, owner="broker", **over):
    doc = {
        "schema_version": 2, "owner": owner, "written_at": "2026-10-28T10:00:00Z",
        "boot_id": BOOT, "pid": 4242, "started": 1000, "pairs": pairs, **over,
    }  # fmt: skip
    return json.dumps(doc)


@pytest.mark.parametrize(
    "text, why",
    [
        ("{", "not JSON"),
        ("[]", "not {boot_id, owner, pairs, pid"),
        (_rec([], extra=1), "not {boot_id, owner, pairs, pid"),
        (_rec([], schema_version=1), "schema_version is not 2"),
        (_rec([], schema_version=True), "schema_version is not 2"),
        (_rec([], owner="status"), "written for another owner"),
        (_rec([], written_at="2026-10-28 10:00:00"), "written_at is not a UTC time"),
        (_rec([], written_at=1), "written_at is not a UTC time"),
        (_rec([], boot_id="not-a-boot"), "boot_id is not a boot id or null"),
        (_rec([], pid=0), "pid is not a process id"),
        (_rec([], pid=True), "pid is not a process id"),
        (_rec([], started=-1), "started is not a start time or null"),
        (_rec({}), "pairs is not a list"),
        (_rec([{"problem": "A"}]), "is not {problem, recovery, module?}"),
        (_rec([{"problem": "A", "recovery": "B", "x": 1}]), "is not {problem, recovery, module?}"),
        (_rec([{"problem": "", "recovery": "B"}]), "not one line of text"),
        (_rec([{"problem": "A\nB", "recovery": "B"}]), "not one line of text"),
        (_rec([{"problem": "A​B", "recovery": "B"}]), "not one line of text"),
        (_rec([{"problem": "A", "recovery": 3}]), "not one line of text"),
        (_rec([{"problem": "A", "recovery": "B", "module": "Bad_Id"}]), "not a module id"),
        (_rec([{"problem": "A", "recovery": "B", "module": None}]), "not a module id"),
        (
            _rec([{"problem": "A", "recovery": "B"}, {"problem": "A", "recovery": "C"}]),
            "repeats a problem title",
        ),
        (_rec([{"problem": f"P{i}", "recovery": "R"} for i in range(257)]), "at most 256"),
        (" " * (MAX_BYTES + 1), "over"),
    ],
)
def test_a_record_off_the_shape_is_refused(text, why):
    with pytest.raises(RecordError, match=re.escape(why)):
        parse_record(text, "broker")


def test_the_limits_are_inclusive():
    full = _rec([{"problem": f"P{i}", "recovery": "R"} for i in range(MAX_PAIRS)])
    assert len(parse_record(full, "broker").pairs) == MAX_PAIRS
    padded = _rec([]) + " " * (MAX_BYTES - len(_rec([])))
    assert len(padded.encode()) == MAX_BYTES
    assert parse_record(padded, "broker").pairs == []


def _record(owner="broker", started=1000, boot=BOOT, at=1_000_000.0):
    return Record(owner, at, boot, 4242, started, [])


@pytest.mark.parametrize(
    "record, host_boot, now, pid_started, why",
    [
        (_record(), BOOT, 1_000_100, 1000, None),  # the broker's process still runs
        (_record(), BOOT, 9_000_000, 1000, None),  # however long ago it wrote
        (_record(), BOOT, 1_000_100, None, "its process (pid 4242) is not running"),
        (_record(), BOOT, 1_000_100, 1001, "its process (pid 4242) is not running"),  # reused
        (_record(started=None), BOOT, 1_000_100, None, "its process (pid 4242) is not running"),
        (_record(), "00000000-0000-4000-8000-000000000002", 1_000_100, 1000, "last boot"),
        (_record(boot=None), BOOT, 1_000_100, 1000, "boot cannot be told"),
        (_record(), None, 1_000_100, 1000, "boot cannot be told"),
        (_record(), BOOT, 1_000_000 - 301, 1000, "written in the future"),
        (_record("status"), BOOT, 1_000_000 + 900, None, None),  # a pass inside its window
        (_record("status"), BOOT, 1_000_000 + 901, None, "written 901s ago, over 900s"),
    ],
)
def test_a_record_counts_only_while_it_says_what_runs(record, host_boot, now, pid_started, why):
    got = stale(record, host_boot, now, pid_started)
    assert got is None if why is None else why in got
