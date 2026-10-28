# SPDX-License-Identifier: Apache-2.0
"""The notify pairs record (homelabnext.notify.record): what a running notifier writes for the
module census, and how the census reads it."""

from __future__ import annotations

import json
import os
import re
import stat

import pytest

from homelabnext.notify import FakeSender, Notifier
from homelabnext.notify.record import (
    MAX_BYTES,
    PairsRecord,
    RecordError,
    parse_record,
    record_in,
)
from homelabnext.state import StateStore

DISK = ("Disk almost full", "Disk space recovered")


def _notifier(tmp_path, record):
    return Notifier(FakeSender(), StateStore(tmp_path / "n.json"), record=record)


def _doc(path):
    return json.loads(path.read_text())


def test_a_notifier_writes_what_it_holds_when_built_and_after_each_registration(tmp_path):
    rec = PairsRecord(tmp_path, "broker")
    n = _notifier(tmp_path, rec)
    assert _doc(rec.path) == {"schema_version": 1, "owner": "broker", "pairs": []}
    n.register_pair(*DISK)
    n.register_pair("Sync stalled", "Sync moving", module="external-collector")
    assert _doc(rec.path)["pairs"] == [
        {"problem": "Disk almost full", "recovery": "Disk space recovered"},
        {
            "problem": "Sync stalled",
            "recovery": "Sync moving",
            "module": "external-collector",
        },
    ]
    # the census parses what the notifier wrote
    assert parse_record(rec.path.read_text(), "broker") == _doc(rec.path)["pairs"]


def test_a_restarted_notifier_replaces_the_record_never_extends_it(tmp_path):
    rec = PairsRecord(tmp_path, "status")
    old = _notifier(tmp_path, rec)
    old.register_pair(*DISK)
    old.register_pair("Gone", "Back")
    # a new process (a new notifier) holds nothing until it registers: the leftover is gone
    new = _notifier(tmp_path, PairsRecord(tmp_path, "status"))
    assert _doc(rec.path)["pairs"] == []
    new.register_pair(*DISK)
    assert [p["problem"] for p in _doc(rec.path)["pairs"]] == ["Disk almost full"]


def test_the_record_is_written_whole_readable_and_leaves_no_temp_file(tmp_path):
    rec = PairsRecord(tmp_path, "broker")
    n = _notifier(tmp_path, rec)
    for i in range(20):
        n.register_pair(f"Problem {i}", f"Recovered {i}")
        _doc(rec.path)  # every intermediate state is a whole document
    assert stat.S_IMODE(os.stat(rec.path).st_mode) == 0o644  # titles, read by the census
    assert not [p for p in os.listdir(tmp_path) if p.endswith(".tmp")]


def test_the_same_pair_repeats_but_never_for_another_module(tmp_path):
    rec = PairsRecord(tmp_path, "broker")
    n = _notifier(tmp_path, rec)
    n.register_pair(*DISK)
    n.register_pair(*DISK)  # the same registrant again: one pair
    assert len(_doc(rec.path)["pairs"]) == 1
    with pytest.raises(ValueError, match="already registered for the core"):
        n.register_pair(*DISK, module="external-collector")
    n.register_pair("Sync stalled", "Sync moving", module="external-collector")
    with pytest.raises(ValueError, match="already registered for external-collector"):
        n.register_pair("Sync stalled", "Sync moving")


def test_a_failed_write_stops_the_notifier_from_starting_quietly(tmp_path):
    class Broken:
        def write(self, pairs):
            raise OSError("read-only file system")

    with pytest.raises(OSError):
        _notifier(tmp_path, Broken())


def test_without_a_record_nothing_is_written(tmp_path):
    n = _notifier(tmp_path, record_in(None, "broker"))
    n.register_pair(*DISK)
    assert not [p for p in os.listdir(tmp_path) if p in ("broker.json", "status.json")]


def test_a_record_names_a_known_owner_and_an_existing_plain_directory(tmp_path):
    with pytest.raises(ValueError, match="owner is one of"):
        PairsRecord(tmp_path, "relay")
    with pytest.raises(ValueError, match="is not a directory"):
        PairsRecord(tmp_path / "absent", "broker")
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    with pytest.raises(ValueError, match="is not a directory"):
        PairsRecord(tmp_path / "link", "broker")


def _rec(pairs, owner="broker", **over):
    return json.dumps({"schema_version": 1, "owner": owner, "pairs": pairs, **over})


@pytest.mark.parametrize(
    "text, why",
    [
        ("{", "not JSON"),
        ("[]", "not {schema_version, owner, pairs}"),
        (_rec([], extra=1), "not {schema_version, owner, pairs}"),
        (_rec([], schema_version=2), "schema_version is not 1"),
        (_rec([], schema_version=True), "schema_version is not 1"),
        (_rec([], owner="status"), "written for another owner"),
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
