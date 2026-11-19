# SPDX-License-Identifier: Apache-2.0
"""The session dispatcher (modules/orchestration/roles/orchestration/files/hnx-session-dispatch)
and the job side of its run file (``hnx-dispatch-read``), run as the controller's exec runner runs
the dispatcher (the session's HNX_* variables, the task on stdin, its own process group) against a
stand-in systemctl that plays a oneshot job unit whose first step is the real reader:

* an agent's session starts exactly its declared unit ``hnx-<set>@<job>-<lane>.service`` with
  ``start --wait``, after writing the run file the job reads itself, answers the unit's result and
  the part of the unit's log this run appended, and removes the run file when the run ends;
* a failed unit is exit 1 with its status and a ``reset-failed``; a unit already running is exit
  75 and is never started a second time; a cancel (SIGTERM to the group, twice) queues the stop
  with ``--no-block`` and still resets the failed state; a systemctl that hangs is a JSON answer;
* two sessions of the same instance run one after the other, never merged into one run;
* an unknown agent, a lane or run id that could not be a unit's or a file's name, a task over the
  bound and a table that its reader could rewrite are refused before anything is started;
* the reader refuses a link, a directory, a FIFO, a hard link, a file of another owner, an oversized
  or foreign run file and a run id consumed before, and reads nothing of what it refuses.
"""

from __future__ import annotations

import fcntl
import json
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

#: a unit instance's name ("<template>@<instance>"), built so no literal reads as an address
U = "{}@{}".format
ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "modules/orchestration/roles/orchestration/files"
DISPATCH = FILES / "hnx-session-dispatch"
READER = FILES / "hnx-dispatch-read"

# A oneshot unit, played by files under STATE: "active" is what is-active says (else the unit's
# state); a start runs the job's first step, the real reader, as the job would (its own process,
# its own checks), appends what it read to the unit's log, waits while "block" exists (until
# "release" or a stop), and ends with the status in "rc" (or the reader's refusal).
FAKE = r"""
import json, os, subprocess, sys, time
STATE = {state!r}
args = [a for a in sys.argv[1:] if a != "--no-ask-password"]
open(os.path.join(STATE, "calls.log"), "a").write(" ".join(args) + "\n")
def read(name, default=""):
    try:
        return open(os.path.join(STATE, name)).read().strip()
    except OSError:
        return default
def write(name, text):
    open(os.path.join(STATE, name), "w").write(text)
verb, unit = args[0], args[-1]
if verb == "show" and os.path.exists(os.path.join(STATE, "hang")):
    time.sleep(30)
if verb == "is-active":
    state = read("active") or read("state", "inactive")
    print(state)
    sys.exit(0 if state == "active" else 3)
if verb == "start":
    inst = unit.split("@", 1)[1].rsplit(".", 1)[0]
    s = unit.split("@")[0][4:]
    log = os.path.join({logs!r}, s, inst + ".log")
    r = subprocess.run([sys.executable, "-I", {reader!r}, "--dir", os.path.join({runs!r}, s),
                        "--instance", inst, "--owner-uid", str(os.getuid()),
                        "--consumed-dir", os.path.join(STATE, "consumed")],
                       capture_output=True, text=True)
    if r.returncode:
        open(log, "a").write(r.stderr)
        write("status", "1"); write("state", "failed")
        sys.exit(1)
    run = json.loads(r.stdout)
    with open(log, "a") as f:
        f.write("job " + run["job"] + " lane " + run["lane"] + " run " + run["run_id"] + "\n")
    deadline = time.time() + 20
    while os.path.exists(os.path.join(STATE, "block")) and time.time() < deadline:
        if os.path.exists(os.path.join(STATE, "release")) or os.path.exists(os.path.join(STATE, "stopped")):
            break
        time.sleep(0.02)
    rc = 1 if os.path.exists(os.path.join(STATE, "stopped")) else int(read("rc", "0"))
    write("status", str(rc))
    write("state", "failed" if rc else "inactive")
    sys.exit(rc)
if verb == "show":
    rc = int(read("status", "0"))
    print("ActiveState=" + read("state", "inactive"))
    print("Result=" + ("success" if rc == 0 else "exit-code"))
    print("ExecMainStatus=" + str(rc))
    print("ExecMainCode=1")
    sys.exit(0)
if verb == "stop":  # a oneshot stopped mid-run ends failed (its process was signalled)
    write("stopped", "")
    write("state", "failed")
    write("status", "143")
    sys.exit(0)
if verb == "reset-failed":
    write("state", "inactive")
    sys.exit(0)
sys.exit(1)
"""


class Rig:
    """A dispatch table, its directories, a stand-in systemctl and the dispatcher's invocation."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.state = tmp / "state"
        self.dispatch = tmp / "var" / "dispatch"
        self.runs = tmp / "var" / "hnx-dispatch"
        self.logs = tmp / "log" / "hnx-jobs"
        for d in (self.state / "consumed", self.dispatch / "cti", self.logs / "cti"):
            d.mkdir(parents=True)
        (self.runs / "cti").mkdir(parents=True)
        (self.runs / "cti").chmod(0o2750)
        self.systemctl = tmp / "systemctl"
        self.systemctl.write_text(
            f"#!{sys.executable}\n"
            + FAKE.format(
                state=str(self.state), runs=str(self.runs), logs=str(self.logs), reader=str(READER)
            )
        )
        self.systemctl.chmod(0o755)
        self.table = tmp / "dispatch.json"
        self.write_table()

    def write_table(self, **over):
        doc = {
            "version": 2,
            "dispatch_dir": str(self.dispatch),
            "run_root": str(self.runs),
            "systemctl": str(self.systemctl),
            "units": {
                "cti": {
                    "jobs": {
                        "cti-hourly": "fresh",
                        "cti-publish": "publish",
                        "cti-podcast": "podcast",
                    },
                    "lanes": ["real", "shadow"],
                    "log_dir": str(self.logs / "cti"),
                },
                "voice": {
                    "jobs": {"voice-check": "check"},
                    "lanes": ["shadow"],
                    "log_dir": str(self.logs / "voice"),
                },
            },
        }
        doc.update(over)
        self.table.write_text(json.dumps(doc))
        self.table.chmod(0o640)

    def env(self, agent="cti-hourly", lane="real", run_id="run-0001"):
        env = {"PATH": "/usr/bin:/bin"}
        for k, v in (("HNX_AGENT_KEY", agent), ("HNX_LANE", lane), ("HNX_RUN_ID", run_id)):
            if v is not None:
                env[k] = v
        return env

    def argv(self, owner=None, timeout=None):
        a = [sys.executable, "-I", str(DISPATCH), "--table", str(self.table),
             "--table-owner", str(os.getuid() if owner is None else owner)]  # fmt: skip
        return a + (["--systemctl-timeout", str(timeout)] if timeout else [])

    def run(self, task="the task", owner=None, timeout=None, **env):
        return subprocess.run(
            self.argv(owner, timeout), input=task, capture_output=True, text=True,
            env=self.env(**env), timeout=60, check=False,
        )  # fmt: skip

    def start(self, task="", **env):
        """The dispatcher in its own process group, as the exec runner starts a session, with the
        task written to its stdin and closed (stdin is then None: communicate() never touches it)."""
        p = subprocess.Popen(
            self.argv(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=self.env(**env), start_new_session=True,
        )  # fmt: skip
        p.stdin.write(task)
        p.stdin.close()
        p.stdin = None
        return p

    def calls(self) -> list[str]:
        p = self.state / "calls.log"
        return p.read_text().splitlines() if p.exists() else []

    def set(self, name, text=""):
        (self.state / name).write_text(text)

    def wait_for(self, pred, what, timeout=15.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if pred():
                return
            time.sleep(0.02)
        raise AssertionError(f"timed out waiting for {what}: calls {self.calls()}")


SHOW = "show --property=ActiveState,Result,ExecMainStatus,ExecMainCode"


@pytest.fixture
def rig(tmp_path) -> Rig:
    return Rig(tmp_path)


def test_a_session_starts_its_unit_which_reads_its_own_run_file_then_the_file_is_gone(rig):
    unit = U("hnx-cti", "fresh-real.service")
    (rig.logs / "cti" / "fresh-real.log").write_text("an older run's line\n")
    r = rig.run(task="refresh the feeds\n" + "x" * (60 << 10))
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["outcome"] == "done" and out["unit"] == unit and out["result"] == "success"
    assert out["exec_main_status"] == "0" and out["start_status"] == 0
    assert out["run_id"] == "run-0001" and out["lane"] == "real" and out["job"] == "fresh"
    # the job read its run file itself; only what this run appended is the answer
    assert out["log_tail"] == "job fresh lane real run run-0001\n"
    assert rig.calls() == [f"is-active {unit}", f"start --wait {unit}", f"{SHOW} {unit}"]
    # the run file is gone once the run ended: nothing is left to replay
    assert out["run_file_removed"] is True
    assert list((rig.runs / "cti").iterdir()) == []
    assert (rig.state / "consumed" / "run-0001").exists()
    assert r.stderr == ""


def test_the_run_file_is_group_readable_in_the_setgid_directory_while_the_unit_runs(rig):
    rig.set("block")
    p = rig.start(task="t")
    run = rig.runs / "cti" / "fresh-real.json"
    rig.wait_for(run.exists, "the run file")
    st = run.stat()
    assert stat.S_IMODE(st.st_mode) == 0o640 and st.st_nlink == 1
    assert st.st_gid == (rig.runs / "cti").stat().st_gid  # the set's group, by the setgid directory
    assert json.loads(run.read_text())["task"] == "t"
    rig.set("release")
    p.communicate(timeout=30)
    assert p.returncode == 0 and not run.exists()


def test_the_lane_is_the_instance_s_last_part(rig):
    r = rig.run(agent="cti-publish", lane="shadow", run_id="b7e1:shadow.2")
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["unit"] == U("hnx-cti", "publish-shadow.service")
    assert f"start --wait {U('hnx-cti', 'publish-shadow.service')}" in rig.calls()


def test_a_failed_unit_is_exit_1_with_its_status_and_its_failed_state_is_reset(rig):
    unit = U("hnx-cti", "fresh-real.service")
    rig.set("rc", "3")
    r = rig.run()
    assert r.returncode == 1 and r.stdout == ""
    out = json.loads(r.stderr)
    assert out["outcome"] == "failed" and out["result"] == "exit-code"
    assert out["exec_main_status"] == "3" and out["reset_failed"] is True
    assert (
        out["log_tail"] == "job fresh lane real run run-0001\n" and out["run_file_removed"] is True
    )
    assert rig.calls()[-1] == f"reset-failed {unit}"
    # a unit left failed starts again: the next run is a new start, not a refusal
    rig.set("rc", "0")
    assert rig.run(run_id="run-0002").returncode == 0


def test_a_start_with_no_dispatcher_finds_nothing_and_a_replayed_run_id_is_refused(rig):
    assert rig.run().returncode == 0
    # a start by hand after the run: the run file is gone, the job refuses
    fake = [str(rig.systemctl), "start", "--wait", U("hnx-cti", "fresh-real.service")]
    assert subprocess.run(fake, check=False).returncode == 1
    assert "cannot be opened" in (rig.logs / "cti" / "fresh-real.log").read_text()
    # the same run id dispatched again (a copied or stale run file): the job refuses it as consumed
    r = rig.run()
    assert r.returncode == 1
    assert "consumed before" in json.loads(r.stderr)["log_tail"]


def test_a_unit_already_running_is_a_wait_and_is_never_started_twice(rig):
    rig.set("active", "active")
    r = rig.run()
    assert r.returncode == 75
    out = json.loads(r.stderr)
    assert out["outcome"] == "busy" and out["active_state"] == "active"
    assert rig.calls() == [f"is-active {U('hnx-cti', 'fresh-real.service')}"]
    assert list((rig.runs / "cti").iterdir()) == []


def test_a_cancel_queues_the_stop_resets_the_failed_state_and_survives_a_second_signal(rig):
    unit = U("hnx-cti", "podcast-real.service")
    rig.set("block")
    p = rig.start(task="t", agent="cti-podcast")
    rig.wait_for(lambda: f"start --wait {unit}" in rig.calls(), "the start")
    os.killpg(p.pid, signal.SIGTERM)  # the runner's cancel: SIGTERM to the session's group
    os.killpg(p.pid, signal.SIGTERM)  # and a second one while the cancel is handled
    _, err = p.communicate(timeout=30)
    assert p.returncode == 143, err
    out = json.loads(err)
    assert out["outcome"] == "cancelled" and out["started"] is True and out["stop_status"] == 0
    assert out["reset_failed"] is True and out["run_file_removed"] is True
    calls = rig.calls()
    assert f"stop --no-block {unit}" in calls and calls[-1] == f"reset-failed {unit}"
    assert list((rig.runs / "cti").iterdir()) == []


def test_a_cancel_before_the_start_starts_nothing(rig):
    lock = rig.dispatch / "cti" / "fresh-real.lock"
    with open(lock, "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)  # another session of this instance holds it
        p = rig.start()
        time.sleep(0.3)
        os.killpg(p.pid, signal.SIGTERM)
        _, err = p.communicate(timeout=30)
    assert p.returncode == 143
    assert json.loads(err)["started"] is False
    assert rig.calls() == [] and list((rig.runs / "cti").iterdir()) == []


def test_a_systemctl_that_hangs_is_still_one_json_answer(rig):
    rig.set("hang")
    r = rig.run(timeout=1)
    assert r.returncode == 0, r.stderr  # start --wait succeeded; show timed out
    out = json.loads(r.stdout)
    assert out["outcome"] == "done" and out["result"] == ""


def test_two_sessions_of_one_instance_run_one_after_the_other(rig):
    unit = U("hnx-cti", "fresh-real.service")
    rig.set("block")
    first = rig.start(run_id="run-a")
    rig.wait_for(lambda: f"start --wait {unit}" in rig.calls(), "the first start")
    second = rig.start(run_id="run-b")
    time.sleep(0.5)
    assert second.poll() is None
    assert rig.calls().count(f"start --wait {unit}") == 1  # the second waits, never merges
    (rig.state / "block").unlink()
    rig.set("release")
    out_a, _ = first.communicate(timeout=30)
    out_b, _ = second.communicate(timeout=30)
    assert first.returncode == 0 and second.returncode == 0
    assert rig.calls() == [f"is-active {unit}", f"start --wait {unit}", f"{SHOW} {unit}"] * 2
    assert json.loads(out_a)["log_tail"] == "job fresh lane real run run-a\n"
    assert json.loads(out_b)["log_tail"] == "job fresh lane real run run-b\n"


def test_a_missing_log_is_said_and_the_result_still_answered(rig):
    rig.write_table(units={"cti": {"jobs": {"cti-hourly": "fresh"}, "lanes": ["real"],
                                   "log_dir": str(rig.tmp / "nowhere")}})  # fmt: skip
    r = rig.run()
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["log_tail"] == "" and "cannot be read" in out["log_note"]


REFUSED = [
    ("unknown agent", {"agent": "cti-nothing"}, None),
    ("no agent", {"agent": None}, None),
    ("lane", {"lane": "prod"}, None),
    ("lane the set does not run", {"agent": "voice-check", "lane": "real"}, None),
    ("run id with a newline", {"run_id": "run\nHNX_X=1"}, None),
    ("run id with a path", {"run_id": "../../etc/x"}, None),
    ("task over the bound", {}, "task"),
    ("table of another owner", {}, "owner"),
    ("group-writable table", {}, "mode"),
    ("table a link", {}, "link"),
    ("table of another version", {}, "version"),
]


@pytest.mark.parametrize("case,env,table", REFUSED, ids=[c for c, _, _ in REFUSED])
def test_a_refusal_starts_nothing(rig, case, env, table):
    owner, task = None, "the task"
    if table == "owner":
        owner = os.getuid() + 1
    elif table == "mode":
        rig.table.chmod(0o660)
    elif table == "link":
        real = rig.tmp / "real.json"
        rig.table.rename(real)
        rig.table.symlink_to(real)
    elif table == "version":
        rig.write_table(version=1)
    elif table == "task":
        task = "x" * ((64 << 10) + 1)  # refused whole, never cut short
    r = rig.run(task=task, owner=owner, **env)
    assert r.returncode == 2, r.stdout + r.stderr
    assert json.loads(r.stderr)["outcome"] == "refused"
    assert rig.calls() == [] and r.stdout == ""
    assert list((rig.runs / "cti").iterdir()) == []


# ----------------------------------------------------------------------------- the job's reader


def run_doc(**over) -> dict:
    doc = {"version": 1, "run_id": "r-1", "lane": "real", "agent_key": "cti-hourly",
           "job": "fresh", "unit": U("hnx-cti", "fresh-real.service"), "task": "t",
           "dispatched_at": "2026-11-19T00:00:00Z"}  # fmt: skip
    doc.update(over)
    return doc


def read_run(tmp: Path, owner_uid=None):
    (tmp / "consumed").mkdir(exist_ok=True)
    return subprocess.run(
        [sys.executable, "-I", str(READER), "--dir", str(tmp / "cti"), "--instance", "fresh-real",
         "--owner-uid", str(os.getuid() if owner_uid is None else owner_uid),
         "--consumed-dir", str(tmp / "consumed")],
        capture_output=True, text=True, timeout=30, check=False,
    )  # fmt: skip


@pytest.fixture
def runs(tmp_path) -> Path:
    (tmp_path / "cti").mkdir()
    return tmp_path


def test_the_reader_returns_a_good_run_file_once(runs):
    (runs / "cti" / "fresh-real.json").write_text(json.dumps(run_doc()))
    (runs / "cti" / "fresh-real.json").chmod(0o640)
    r = read_run(runs)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == run_doc()
    again = read_run(runs)
    assert again.returncode == 1 and "consumed before" in again.stderr and again.stdout == ""


SECRET = "the-secret-content-of-a-file-only-the-job-user-reads"


def plant(runs: Path, kind: str) -> None:
    path = runs / "cti" / "fresh-real.json"
    target = runs / "elsewhere.json"
    target.write_text(json.dumps(run_doc(task=SECRET)))
    target.chmod(0o640)
    if kind == "symlink":
        path.symlink_to(target)
    elif kind == "directory":
        path.mkdir()
        (path / "x").write_text(SECRET)
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "hardlink":
        os.link(target, path)
    elif kind == "socket":
        import socket

        s = socket.socket(socket.AF_UNIX)
        s.bind(str(path))
    elif kind == "writable":
        path.write_text(json.dumps(run_doc(task=SECRET)))
        path.chmod(0o662)
    elif kind == "oversized":
        path.write_text(json.dumps(run_doc(task="x" * (300 << 10))))
    elif kind == "another instance":
        path.write_text(
            json.dumps(run_doc(job="publish", unit=U("hnx-cti", "publish-real.service")))
        )
    elif kind == "another unit":
        path.write_text(json.dumps(run_doc(unit=U("hnx-tts", "fresh-real.service"))))
    elif kind == "bad run id":
        path.write_text(json.dumps(run_doc(run_id="../x")))
    elif kind == "not json":
        path.write_text("{" + SECRET)


PLANTED = ["symlink", "directory", "fifo", "hardlink", "socket", "writable", "oversized",
           "another instance", "another unit", "bad run id", "not json"]  # fmt: skip


@pytest.mark.parametrize("kind", PLANTED)
def test_the_reader_refuses_what_was_planted_and_reads_nothing_of_it(runs, kind):
    plant(runs, kind)
    r = read_run(runs)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "refused" in r.stderr and r.stdout == "" and SECRET not in r.stderr
    assert list((runs / "consumed").iterdir()) == []


def test_the_reader_refuses_a_run_file_of_another_owner(runs):
    (runs / "cti" / "fresh-real.json").write_text(json.dumps(run_doc()))
    (runs / "cti" / "fresh-real.json").chmod(0o640)
    r = read_run(runs, owner_uid=os.getuid() + 1)
    assert r.returncode == 1 and "not the controller's" in r.stderr and r.stdout == ""
