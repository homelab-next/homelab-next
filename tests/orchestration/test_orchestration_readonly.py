# SPDX-License-Identifier: Apache-2.0
"""The hub reads the telemetry store as another user: the writers keep a rollback journal (no
-wal, no -shm), so a read-only open needs read access to the file and creates nothing, whether or
not the hub could write the directory."""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from orch_helpers import ROOT, T0, body, examples

from homelabnext._sqlite import is_wal
from homelabnext.orchestration.store import JOURNAL_MODE, TelemetryStore
from homelabnext.status import cli as status_cli


def _filled(path: Path) -> TelemetryStore:
    store = TelemetryStore(path, clock=lambda: T0)
    for ev in examples():
        store.consume(body(ev))
    return store


def test_the_writer_keeps_a_rollback_journal_and_a_read_only_open_creates_nothing(tmp_path):
    db = tmp_path / "t.db"
    _filled(db)
    assert not is_wal(db) and sorted(os.listdir(tmp_path)) == ["t.db"]
    hub = TelemetryStore(db, clock=lambda: T0, read_only=True)
    assert len(hub.jobs()) == 4 and hub.turns() == {} and hub.job("run-0001")
    assert sorted(os.listdir(tmp_path)) == ["t.db"]  # no -wal, -shm or -journal by the reader


def test_a_wal_store_is_refused_by_the_reader_and_converted_by_the_next_writer(tmp_path, capsys):
    """A database a WAL writer left would make the reader create -wal and -shm, so the hub refuses
    it with SQLite's reason (exit 2), creating nothing; the next writer pass converts it."""
    db = tmp_path / "t.db"
    _filled(db)
    with sqlite3.connect(db) as c:
        c.execute("PRAGMA journal_mode=WAL")
    c.close()
    assert is_wal(db) and sorted(os.listdir(tmp_path)) == ["t.db"]
    with pytest.raises(ValueError, match=r"cannot read the telemetry store .*WAL mode"):
        TelemetryStore(db, clock=lambda: T0, read_only=True)
    argv = ["serve", "--orchestration", str(db), "--port", "0"]
    assert status_cli.main(argv) == 2
    err = capsys.readouterr().err
    assert "WAL mode" in err and "not a telemetry store" not in err
    assert sorted(os.listdir(tmp_path)) == ["t.db"]
    TelemetryStore(db, clock=lambda: T0)  # a writer pass
    assert not is_wal(db)
    site = status_cli._orchestration_site(argparse.Namespace(orchestration=str(db)), lambda: T0)
    assert len(site.store.jobs()) == 4 and sorted(os.listdir(tmp_path)) == ["t.db"]


_CHILD = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location("_sqlite", sys.argv[1])
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
db, what = sys.argv[2], sys.argv[3]
if what == "read":
    with mod.transaction(db, read_only=True) as c:
        print(c.execute("SELECT count(*) FROM jobs").fetchone()[0])
else:
    with mod.transaction(db, journal_mode=sys.argv[4]) as c:
        c.execute("INSERT OR REPLACE INTO turns VALUES ('t-x', 'tag-x', 0, '{}')")
    print("wrote")
"""
WRITER, HUB = 65533, 65534  # two unprivileged users; neither is the other


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0 or not shutil.which("setpriv"),
    reason="runs the writer and the hub as two other users: needs root and setpriv",
)
@pytest.mark.parametrize("hub_can_write_dir", [False, True])
def test_the_hub_reads_as_another_user_and_the_writer_keeps_writing(hub_can_write_dir):
    """The deployment the docs describe: the writer owns the directory and the file, the hub user
    can only read the file (case a), or could also write the directory (case c).  Under WAL, (a)
    failed with "attempt to write a readonly database" and (c) left hub-owned -wal/-shm that
    locked the writer out."""
    base = Path(tempfile.mkdtemp(prefix="hnx-ro-"))
    try:
        base.chmod(0o755)
        lib = base / "lib"
        lib.mkdir(mode=0o755)
        shutil.copy(ROOT / "homelabnext" / "_sqlite.py", lib / "_sqlite.py")
        (lib / "child.py").write_text(_CHILD, "utf-8")
        for f in lib.iterdir():
            f.chmod(0o644)
        store = base / "store"
        store.mkdir()
        db = store / "t.db"
        _filled(db)
        for p in (store, db):
            os.chown(p, WRITER, WRITER)
        store.chmod(0o777 if hub_can_write_dir else 0o755)
        db.chmod(0o644)
        python = os.path.realpath(sys.executable)

        def run(uid: int, *args: str) -> str:
            cmd = ["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups", python, "-I"]
            got = subprocess.run(
                [*cmd, str(lib / "child.py"), str(lib / "_sqlite.py"), str(db), *args],
                capture_output=True, text=True, timeout=60, cwd="/",
            )  # fmt: skip
            assert got.returncode == 0, got.stderr
            return got.stdout.strip()

        assert run(HUB, "read") == "4"
        assert sorted(os.listdir(store)) == ["t.db"]
        assert run(WRITER, "write", JOURNAL_MODE) == "wrote"
        assert run(HUB, "read") == "4"
        assert run(WRITER, "write", JOURNAL_MODE) == "wrote"
        assert sorted(os.listdir(store)) == ["t.db"]
    finally:
        shutil.rmtree(base, ignore_errors=True)
