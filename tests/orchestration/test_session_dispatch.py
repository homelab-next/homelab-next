# SPDX-License-Identifier: Apache-2.0
"""The session dispatcher (modules/orchestration/roles/orchestration/files/hnx-session-dispatch),
run as the controller's exec runner runs it (the session's HNX_* variables, the task on stdin, its
own process group) against a stand-in systemctl that plays a oneshot job unit:

* an agent's session starts exactly its declared unit ``hnx-<set>@<job>-<lane>.service`` with
  ``start --wait``, after writing the run file the unit loads, and answers the unit's result and
  the part of the unit's log this run appended (never an older run's lines);
* a failed unit is exit 1 with its status and a ``reset-failed``; a unit already running is exit
  75 and is never started a second time; a cancel (SIGTERM to the group) stops the unit;
* two sessions of the same instance run one after the other, never merged into one run;
* an unknown agent, a lane or run id that could not be a unit's or a file's name, and a table that
  its reader could rewrite are refused before anything is started.
"""

from __future__ import annotations

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
DISPATCH = ROOT / "modules/orchestration/roles/orchestration/files/hnx-session-dispatch"

# A oneshot unit, played by files under STATE: "active" is what is-active says; a start appends
# the run file it was handed to the unit's log (as the unit would read its credential), waits while
# "block" exists (until "release" or a stop), and ends with the status in "rc".
FAKE = r"""
import json, os, sys, time
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
if verb == "is-active":
    print(read("active", "inactive"))
    sys.exit(0 if read("active", "inactive") == "active" else 3)
if verb == "start":
    inst = unit.split("@", 1)[1].rsplit(".", 1)[0]
    run = json.load(open(os.path.join({dispatch!r}, unit.split("@")[0][4:], inst + ".json")))
    log = os.path.join({logs!r}, unit.split("@")[0][4:], inst + ".log")
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
        self.logs = tmp / "log" / "hnx-jobs"
        for d in (self.state, self.dispatch / "cti", self.logs / "cti"):
            d.mkdir(parents=True)
        self.systemctl = tmp / "systemctl"
        self.systemctl.write_text(
            f"#!{sys.executable}\n"
            + FAKE.format(state=str(self.state), dispatch=str(self.dispatch), logs=str(self.logs))
        )
        self.systemctl.chmod(0o755)
        self.table = tmp / "dispatch.json"
        self.write_table()

    def write_table(self, **over):
        doc = {
            "version": 1,
            "dispatch_dir": str(self.dispatch),
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

    def argv(self, owner=None):
        return [sys.executable, "-I", str(DISPATCH), "--table", str(self.table),
                "--table-owner", str(os.getuid() if owner is None else owner)]  # fmt: skip

    def run(self, task="the task", owner=None, **env):
        return subprocess.run(
            self.argv(owner), input=task, capture_output=True, text=True,
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


def test_a_session_starts_its_declared_unit_and_answers_its_result_and_its_own_log(rig):
    unit = U("hnx-cti", "fresh-real.service")
    (rig.logs / "cti" / "fresh-real.log").write_text("an older run's line\n")
    r = rig.run(task="refresh the feeds\n" + "x" * (200 << 10))
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["outcome"] == "done" and out["unit"] == unit and out["result"] == "success"
    assert out["exec_main_status"] == "0" and out["start_status"] == 0
    assert out["run_id"] == "run-0001" and out["lane"] == "real" and out["job"] == "fresh"
    # only what this run appended: an older run's line is never part of the answer
    assert out["log_tail"] == "job fresh lane real run run-0001\n"
    assert rig.calls() == [f"is-active {unit}", f"start --wait {unit}", f"{SHOW} {unit}"]
    run = rig.dispatch / "cti" / "fresh-real.json"
    body = json.loads(run.read_text())
    assert body["run_id"] == "run-0001" and body["agent_key"] == "cti-hourly"
    assert body["task"].startswith("refresh the feeds\n") and len(body["task"]) == 64 << 10
    assert stat.S_IMODE(run.stat().st_mode) == 0o600
    assert r.stderr == ""


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
    assert out["log_tail"] == "job fresh lane real run run-0001\n"
    assert rig.calls()[-1] == f"reset-failed {unit}"
    # a unit left failed starts again: the next run is a new start, not a refusal
    rig.set("rc", "0")
    assert rig.run(run_id="run-0002").returncode == 0


def test_a_unit_already_running_is_a_wait_and_is_never_started_twice(rig):
    rig.set("active", "active")
    r = rig.run()
    assert r.returncode == 75
    out = json.loads(r.stderr)
    assert out["outcome"] == "busy" and out["active_state"] == "active"
    assert rig.calls() == [f"is-active {U('hnx-cti', 'fresh-real.service')}"]
    assert not (rig.dispatch / "cti" / "fresh-real.json").exists()


def test_a_cancel_stops_the_unit_and_resets_its_failed_state(rig):
    unit = U("hnx-cti", "podcast-real.service")
    rig.set("block")
    p = rig.start(task="t", agent="cti-podcast")
    rig.wait_for(lambda: f"start --wait {unit}" in rig.calls(), "the start")
    os.killpg(p.pid, signal.SIGTERM)  # the runner's cancel: SIGTERM to the session's group
    _, err = p.communicate(timeout=30)
    assert p.returncode == 143, err
    out = json.loads(err)
    assert out["outcome"] == "cancelled" and out["started"] is True and out["stop_status"] == 0
    calls = rig.calls()
    assert f"stop {unit}" in calls and calls[-1] == f"reset-failed {unit}"


def test_a_cancel_before_the_start_starts_nothing(rig):
    rig.set("active", "active")
    lock = rig.dispatch / "cti" / "fresh-real.lock"
    import fcntl

    with open(lock, "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)  # another session of this instance holds it
        p = rig.start()
        time.sleep(0.3)
        os.killpg(p.pid, signal.SIGTERM)
        _, err = p.communicate(timeout=30)
    assert p.returncode == 143
    assert json.loads(err)["started"] is False
    assert rig.calls() == []


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
    ("table of another owner", {}, "owner"),
    ("group-writable table", {}, "mode"),
    ("table a link", {}, "link"),
    ("table of another version", {}, "version"),
]


@pytest.mark.parametrize("case,env,table", REFUSED, ids=[c for c, _, _ in REFUSED])
def test_a_refusal_starts_nothing(rig, case, env, table):
    owner = None
    if table == "owner":
        owner = os.getuid() + 1
    elif table == "mode":
        rig.table.chmod(0o660)
    elif table == "link":
        real = rig.tmp / "real.json"
        rig.table.rename(real)
        rig.table.symlink_to(real)
    elif table == "version":
        rig.write_table(version=2)
    r = rig.run(owner=owner, **env)
    assert r.returncode == 2, r.stdout + r.stderr
    assert json.loads(r.stderr)["outcome"] == "refused"
    assert rig.calls() == [] and r.stdout == ""
    assert not any(rig.dispatch.rglob("*.json"))
