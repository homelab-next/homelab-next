# SPDX-License-Identifier: Apache-2.0
import json
import os
import signal
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from homelabnext.state import (
    SCHEMA_VERSION,
    KeyedState,
    StateCorruptError,
    StateStore,
    StateVersionError,
    quarantined_files,
)

ROOT = Path(__file__).resolve().parents[2]


def test_put_get_roundtrip_and_schema_version(tmp_path):
    p = tmp_path / "s.json"
    s = StateStore(p)
    assert s.get("a", "dflt") == "dflt"
    s.put("a", {"n": 1})
    assert StateStore(p).get("a") == {"n": 1}
    doc = json.loads(p.read_text())
    assert doc["schema_version"] == SCHEMA_VERSION
    assert doc["data"] == {"a": {"n": 1}}
    assert s.delete("a") and not s.delete("a")


def test_yaml_state_file(tmp_path):
    s = StateStore(tmp_path / "s.yml")
    s.put("k", [1, 2])
    assert StateStore(tmp_path / "s.yml").get("k") == [1, 2]


def test_corrupt_file_is_quarantined_not_fatal(tmp_path):
    p = tmp_path / "s.json"
    p.write_text('{"schema_version": 1, "data": {"a": ')  # truncated
    s = StateStore(p, clock=lambda: 0.0)
    assert s.get("a") is None
    q = quarantined_files(p)
    assert len(q) == 1 and q[0].read_text().startswith('{"schema_version"')
    s.put("a", 1)
    assert StateStore(p).get("a") == 1


@pytest.mark.parametrize("content", ["[]", '{"data": {}}', '{"schema_version": 1, "data": 3}', ""])
def test_wrong_shape_is_quarantined(tmp_path, content):
    p = tmp_path / "s.json"
    p.write_text(content)
    assert StateStore(p).items() == {}
    assert len(quarantined_files(p)) == 1


def test_quarantine_off_raises_and_leaves_the_file(tmp_path):
    p = tmp_path / "s.json"
    p.write_text("{not json")
    with pytest.raises(StateCorruptError, match="unusable"):
        StateStore(p, quarantine=False).get("a")
    assert p.read_text() == "{not json" and not quarantined_files(p)


def test_legacy_format_is_read_then_rewritten(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"version": 1, "rows": {"a": 1}}))

    def legacy(doc):
        return doc["rows"] if doc.get("version") == 1 else None

    s = StateStore(p, schema_version=2, migrations={1: lambda d: {**d, "m": True}}, legacy=legacy)
    assert s.items() == {"a": 1, "m": True}  # legacy data enters as version 1, then migrates
    s.put("b", 2)
    assert json.loads(p.read_text()) == {"schema_version": 2, "data": {"a": 1, "b": 2, "m": True}}
    p.write_text(json.dumps({"version": 7, "rows": {}}))  # unrecognised: the normal corrupt path
    assert StateStore(p, legacy=legacy).items() == {} and len(quarantined_files(p)) == 1


def test_newer_schema_is_refused_and_left_untouched(tmp_path):
    p = tmp_path / "s.json"
    original = json.dumps({"schema_version": 99, "data": {"a": 1}})
    p.write_text(original)
    s = StateStore(p)
    with pytest.raises(StateVersionError):
        s.get("a")
    with pytest.raises(StateVersionError):
        s.put("a", 2)
    assert p.read_text() == original and not quarantined_files(p)


def test_migration_upgrades_old_version(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"schema_version": 1, "data": {"old": 1}}))
    s = StateStore(p, schema_version=2, migrations={1: lambda d: {"new": d["old"]}})
    assert s.get("new") == 1
    s.put("x", 1)
    assert json.loads(p.read_text())["schema_version"] == 2


def test_missing_migration_is_an_error(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"schema_version": 1, "data": {}}))
    with pytest.raises(StateVersionError):
        StateStore(p, schema_version=3).get("a")


def test_threads_do_not_lose_updates(tmp_path):
    s = StateStore(tmp_path / "s.json")

    def work():
        for _ in range(25):
            s.update("n", lambda v: v + 1, 0)

    ts = [threading.Thread(target=work) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert s.get("n") == 100


_CHILD_COUNT = textwrap.dedent(
    """
    import sys
    from homelabnext.state import StateStore
    s = StateStore(sys.argv[1])
    for _ in range(int(sys.argv[2])):
        s.update("n", lambda v: v + 1, 0)
    """
)


def _run_child(code, *args, env_extra=None):
    env = {**os.environ, "PYTHONPATH": str(ROOT), **(env_extra or {})}
    return subprocess.run([sys.executable, "-c", code, *map(str, args)], env=env, check=False)


def test_processes_do_not_lose_updates(tmp_path):
    p = tmp_path / "s.json"
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _CHILD_COUNT, str(p), "30"],
            env={**os.environ, "PYTHONPATH": str(ROOT)},
        )
        for _ in range(3)
    ]
    assert [x.wait() for x in procs] == [0, 0, 0]
    assert StateStore(p).get("n") == 90


_KILL_BEFORE_RENAME = textwrap.dedent(
    """
    import os, signal, sys
    from homelabnext.state import StateStore
    s = StateStore(sys.argv[1])
    real = os.replace
    def boom(src, dst):          # the temp file is fully written and fsynced; die before the rename
        os.kill(os.getpid(), signal.SIGKILL)
    os.replace = boom
    s.put("a", "NEW")
    """
)


def test_kill9_between_write_and_rename_leaves_old_file_intact(tmp_path):
    p = tmp_path / "s.json"
    StateStore(p).put("a", "OLD")
    r = _run_child(_KILL_BEFORE_RENAME, p)
    assert r.returncode == -signal.SIGKILL
    assert StateStore(p).get("a") == "OLD"
    assert not quarantined_files(p)
    # the dead writer's orphan temp file is swept by the next write
    assert list(tmp_path.glob(".s.json.*.tmp"))
    StateStore(p).put("b", 1)
    assert not list(tmp_path.glob(".s.json.*.tmp"))


_KILL_FIRST_WRITE = _KILL_BEFORE_RENAME


def test_kill9_during_first_ever_write_leaves_no_partial_file(tmp_path):
    p = tmp_path / "s.json"
    r = _run_child(_KILL_FIRST_WRITE, p)
    assert r.returncode == -signal.SIGKILL
    assert not p.exists()
    assert StateStore(p).items() == {}


_WRITER_LOOP = textwrap.dedent(
    """
    import sys
    from homelabnext.state import StateStore
    s = StateStore(sys.argv[1])
    print("ready", flush=True)
    i = 0
    while True:
        i += 1
        s.put("blob", "x" * 200000 + str(i))
        s.put("i", i)
    """
)


def test_kill9_of_a_busy_writer_always_leaves_a_parseable_file(tmp_path):
    p = tmp_path / "s.json"
    for _ in range(3):
        proc = subprocess.Popen(
            [sys.executable, "-c", _WRITER_LOOP, str(p)],
            env={**os.environ, "PYTHONPATH": str(ROOT)},
            stdout=subprocess.PIPE,
            text=True,
        )
        assert proc.stdout.readline().strip() == "ready"
        # let it complete a few writes (progress is observable, not time-based)
        for _spin in range(200000):
            if p.exists() and json.loads(p.read_text() or "{}").get("data", {}).get("i", 0) >= 3:
                break
        proc.kill()
        proc.wait()
        doc = json.loads(p.read_text())  # must parse: never torn
        assert doc["schema_version"] == SCHEMA_VERSION
        assert not quarantined_files(p)
        StateStore(p).items()  # and loads without quarantine


def test_keyed_state_first_red_counters_and_last_seen(tmp_path):
    now = [100.0]
    k = KeyedState(StateStore(tmp_path / "s.json"), clock=lambda: now[0])
    assert k.last_seen("c1") is None and k.red_for("c1") == 0.0
    k.observe("c1", ok=False)
    now[0] = 160.0
    rec = k.observe("c1", ok=False)
    assert rec["first_red"] == 100.0 and rec["consecutive_red"] == 2
    assert k.red_for("c1") == 60.0 and k.last_seen("c1") == 160.0
    now[0] = 200.0
    rec = k.observe("c1", ok=True)
    assert rec["first_red"] is None and rec["consecutive_red"] == 0 and rec["last_green"] == 200.0
    now[0] = 300.0
    k.observe("c1", ok=False)
    assert k.first_red("c1") == 300.0  # a new red episode restarts the clock
    assert (
        k.incr("c1", "pages") == 1
        and k.incr("c1", "pages", 2) == 3
        and k.counter("c1", "pages") == 3
    )
    k.reset("c1")
    assert k.record("c1") == {}


def test_quarantine_is_logged_with_its_reason(tmp_path, caplog):
    p = tmp_path / "s.json"
    p.write_bytes(b'{"schema_version": 1, "data": {"a": \xff')
    with caplog.at_level("WARNING", logger="homelabnext.state"):
        assert StateStore(p).items() == {}
    assert len(quarantined_files(p)) == 1
    msg = caplog.records[-1].getMessage()
    assert "quarantined" in msg and "UnicodeDecodeError" in msg and str(p) in msg


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_new_file_is_0600_and_existing_mode_is_kept(tmp_path):
    old = os.umask(0o022)
    try:
        p = tmp_path / "s.json"
        StateStore(p).put("token", "x")
        assert p.stat().st_mode & 0o777 == 0o600
        os.chmod(p, 0o400)  # differs from the 0600 default; owner read-only
        StateStore(p).put("token", "y")
        assert p.stat().st_mode & 0o777 == 0o400
    finally:
        os.umask(old)
