# SPDX-License-Identifier: Apache-2.0
"""The rotating restore drill (ADR-0042 decision 3): the drill command against fake backup-client,
loop and mount commands, the choice of guest and copy, and the role's timer task."""

from __future__ import annotations

import grp
import hashlib
import importlib.util
import json
import os
import re
import time
from pathlib import Path

import pytest
from rolerun import calls, fake, first_run, logging_fake, run_role

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ansible/roles/restore_drill/files/hnx-restore-drill.py"
NOW = 1_800_000_000.0


def load():
    spec = importlib.util.spec_from_file_location("hnx_restore_drill", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.LOOP = re.compile(r"^/.+\Z")  # the fake attaches a plain file, not /dev/loopN
    return mod


CLIENT = r"""
import json, os, sys
a = sys.argv[1:]
open(BASE + "/client.log", "a").write(" ".join(a) + "\n")
store = a[a.index("--repository") + 1].split(":")[-1]
if a[0] == "snapshot":
    rows = json.load(open(BASE + "/snapshots.json"))
    print(json.dumps(rows.get(store, [])))
elif a[0] == "restore":
    open(a[3], "wb").write(b"img")
"""
LOSETUP = r"""
import os, sys
a = sys.argv[1:]
flag = BASE + "/attached"
open(BASE + "/loop.log", "a").write(" ".join(a) + "\n")
if a[0] == "--find":
    open(flag, "w").write("x"); print(BASE + "/loopdev")
elif a[0] == "--detach":
    if os.path.exists(flag): os.unlink(flag)
else:
    sys.exit(0 if os.path.exists(flag) else 1)
"""
MOUNT = r"""
import shutil, sys
a = sys.argv[1:]
shutil.copytree(BASE + "/guestfs", a[-1], dirs_exist_ok=True)
"""


def sha(b):
    return hashlib.sha256(b).hexdigest()


def make_export(
    root, *, app="db", created=None, tamper=False, magic=b"PGDMP", stale=False, module_root=False
):
    where = "var/lib/hnx-modules" if module_root else "var/backups/compose"
    base = Path(root) / where / app / "export/db"
    (base / "db").mkdir(parents=True)
    body = magic + b"data" * 10
    (base / "db" / "app.dump").write_bytes(body)
    (base / "listing.sha256").write_text(f"{sha(body)}  db/app.dump\n")
    created = created or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW - 3600))
    meta = {
        "app": app,
        "created": created,
        "jobs": {
            "db": {
                "engine": "postgres",
                "files": ["app.dump"],
                **({"stale": True} if stale else {}),
            }
        },
    }
    (base / "manifest.json").write_text(json.dumps(meta))
    if tamper:
        (base / "db" / "app.dump").write_bytes(body + b"x")


def snap(vmid, age_h=2, state="ok"):
    return {
        "backup-type": "vm",
        "backup-id": str(vmid),
        "backup-time": int(NOW - age_h * 3600),
        "verification": {"state": state},
    }


@pytest.fixture
def lab(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (("backup-client", CLIENT), ("losetup", LOSETUP), ("mount", MOUNT)):
        fake(bindir / name, body.replace("BASE", repr(str(tmp_path))))
    fake(bindir / "umount", "")
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    (tmp_path / "guestfs/etc").mkdir(parents=True)
    (tmp_path / "guestfs/etc/os-release").write_text("ID=debian\n")
    (tmp_path / "snapshots.json").write_text(
        json.dumps({"primary": [snap(130), snap(131)], "second": [snap(130), snap(131)]})
    )
    cfg = {
        "client_cli": "backup-client",
        "authid": "drill@pbs!drill",
        "stores": ["primary", "second"],
        "namespace": "pm205",
        "host": "localhost",
        "guests": [
            {"id": "guest:app-a", "name": "app-a", "vmid": 130, "expect_export": True},
            {"id": "guest:app-b", "name": "app-b", "vmid": 131, "expect_export": False},
        ],
        "state_file": str(tmp_path / "state" / "drills.json"),
        "scratch_dir": str(tmp_path / "scratch"),
        "env_file": str(tmp_path / "drill.env"),
    }
    (tmp_path / "drill.env").write_text("PBS_PASSWORD='s'\n")
    (tmp_path / "cfg.json").write_text(json.dumps(cfg))
    return tmp_path


def drill(lab, *args):
    mod = load()
    return mod.main(["--config", str(lab / "cfg.json"), "--at", str(NOW), *args]), mod


def records(lab):
    return json.loads((lab / "state" / "drills.json").read_text())


def test_a_good_drill_verifies_records_and_leaves_no_scratch_behind(lab, capsys):
    make_export(lab / "guestfs")
    rc, _ = drill(lab, "guest:app-a", "app-a")
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["verified"] is True and out["snapshot"].startswith("vm/130/")
    rec = records(lab)
    assert rec["guests"]["guest:app-a"]["last_verified"].endswith("Z")
    svc = rec["services"]["db"]
    assert (
        svc["source"] == "export" and svc["fingerprint_match"] is True and svc["verified"] is True
    )
    assert not list((lab / "scratch").iterdir())
    assert not (lab / "attached").exists()
    assert "PBS_PASSWORD" not in json.dumps(rec)


def test_an_export_in_a_module_s_data_root_is_found_and_verified(lab, capsys):
    """The modules keep their export under <data root>/export/db, not under var/backups/compose."""
    make_export(lab / "guestfs", module_root=True)
    rc, _ = drill(lab, "guest:app-a", "app-a")
    assert rc == 0 and json.loads(capsys.readouterr().out)["verified"] is True
    assert records(lab)["services"]["db"]["verified"] is True


def test_no_export_in_a_guest_that_should_have_one_fails(lab, capsys):
    rc, _ = drill(lab, "guest:app-a", "app-a")
    assert (
        rc == 1
        and "should carry an application export" in json.loads(capsys.readouterr().out)["failure"]
    )
    assert records(lab)["guests"]["guest:app-a"]["last_failure"]


def test_a_guest_that_need_not_have_an_export_passes_without_one(lab):
    assert drill(lab, "guest:app-b", "app-b")[0] == 0


@pytest.mark.parametrize(
    ("kw", "msg"),
    [
        ({"tamper": True}, "does not match its checksum"),
        ({"magic": b"JUNK0"}, "not a custom-format dump"),
        ({"created": "2026-01-01T00:00:00Z"}, "h old"),
        ({"stale": True}, "stale dump"),
    ],
)
def test_a_bad_export_fails_the_drill_and_the_teardown_still_runs(lab, capsys, kw, msg):
    make_export(lab / "guestfs", **kw)
    rc, _ = drill(lab, "guest:app-a", "app-a")
    assert rc == 1 and msg in json.loads(capsys.readouterr().out)["failure"]
    assert not list((lab / "scratch").iterdir()) and not (lab / "attached").exists()


@pytest.mark.parametrize(
    ("rows", "msg"),
    [
        ({"primary": []}, "no snapshot"),
        ({"primary": [snap(130, age_h=80)]}, "h old"),
        ({"primary": [snap(130, state="failed")]}, "not verified"),
        ({"primary": [snap(131)]}, "no snapshot of vm/130"),
    ],
)
def test_a_missing_old_or_unverified_backup_fails(lab, capsys, rows, msg):
    (lab / "snapshots.json").write_text(json.dumps(rows))
    rc, _ = drill(lab, "guest:app-a", "app-a")
    assert rc == 1 and msg in json.loads(capsys.readouterr().out)["failure"]


def test_a_filesystem_that_is_not_a_guest_fails(lab, capsys):
    (lab / "guestfs/etc/os-release").unlink()
    rc, _ = drill(lab, "guest:app-b", "app-b")
    assert rc == 1 and "etc/os-release" in json.loads(capsys.readouterr().out)["failure"]


def test_rotation_takes_the_most_overdue_guest_and_alternates_the_copy(lab):
    make_export(lab / "guestfs")
    assert drill(lab, "rotate")[0] == 0
    assert drill(lab, "rotate")[0] == 0
    rec = records(lab)
    assert set(rec["guests"]) == {"guest:app-a", "guest:app-b"}  # a never-drilled guest goes first
    assert {rec["guests"][g]["store"] for g in rec["guests"]} == {"primary", "second"}
    log = (lab / "client.log").read_text()
    assert "drill@pbs!drill@localhost:primary" in log and "drill@pbs!drill@localhost:second" in log
    assert drill(lab, "rotate")[0] == 0 and rec["runs"] == 2 and records(lab)["runs"] == 3


def test_a_failed_guest_is_drilled_again_after_the_ones_that_passed(lab):
    make_export(lab / "guestfs")
    (lab / "snapshots.json").write_text(json.dumps({"primary": [snap(130)], "second": [snap(130)]}))
    drill(lab, "rotate")  # app-a, ok
    assert drill(lab, "rotate")[0] == 1  # app-b: no snapshot
    rec = records(lab)
    assert (
        "last_verified" not in rec["guests"]["guest:app-b"]
        and rec["guests"]["guest:app-b"]["last_failure"]
    )


def test_the_notice_goes_out_once_per_change_of_state(lab, monkeypatch):
    sent = []
    mod = load()
    monkeypatch.setattr(mod, "notify", lambda cfg, secrets, title, msg: sent.append(title))
    cfg = json.loads((lab / "cfg.json").read_text())
    for _ in range(3):  # fails three times: one notice
        mod.main(["--config", str(lab / "cfg.json"), "--at", str(NOW), "guest:app-a", "app-a"])
    assert len(sent) == 1 and sent[0].startswith("restore drill FAILED")
    make_export(lab / "guestfs")
    mod.main(["--config", str(lab / "cfg.json"), "--at", str(NOW), "guest:app-a", "app-a"])
    assert len(sent) == 2 and "recovered" in sent[1] and cfg


@pytest.mark.parametrize(
    "patch",
    [
        {"scratch_dir": "/x"},
        {"scratch_dir": "/a/../b/c"},
        {"stores": []},
        {"guests": [{"id": "g", "name": "n"}]},
    ],
)
def test_a_bad_config_is_refused_before_anything_runs(lab, patch):
    cfg = json.loads((lab / "cfg.json").read_text())
    cfg.update(patch)
    (lab / "cfg.json").write_text(json.dumps(cfg))
    assert load().main(["--config", str(lab / "cfg.json"), "rotate"]) == 2
    assert not (lab / "client.log").exists()


def test_an_unknown_guest_or_no_command_is_a_usage_error(lab):
    assert drill(lab, "guest:nope", "x")[0] == 2
    assert drill(lab)[0] == 2


# ------------------------------------------------------------------ the role's timer task
GUESTS = [
    {"id": "guest:app-a", "name": "app-a"},
    {"id": "guest:app-b", "name": "app-b"},
]


def role_vars(tmp_path, **kw):
    grp_name = grp.getgrgid(os.getgid()).gr_name
    d = {
        "restore_drill_guests": GUESTS,
        "restore_drill_timer": True,
        "restore_drill_client_cli": "backup-client",
        "restore_drill_pbs_authid": "drill@pbs!drill",
        "restore_drill_stores": ["primary", "second"],
        "restore_drill_namespace": "pm205",
        "restore_drill_vmids": {"guest:app-a": 130, "guest:app-b": 131},
        "restore_drill_expect_export": ["guest:app-a"],
        "restore_drill_secret_env": {"PBS_PASSWORD": "pw", "PBS_FINGERPRINT": "AA:BB"},
        "restore_drill_cli": str(tmp_path / "sbin" / "hnx-restore-drill"),
        "restore_drill_config_file": str(tmp_path / "etc" / "restore-drill.json"),
        "restore_drill_env_file": str(tmp_path / "etc" / "restore-drill.env"),
        "restore_drill_state_file": str(tmp_path / "var" / "drills.json"),
        "restore_drill_scratch_dir": str(tmp_path / "var" / "scratch"),
        "restore_drill_unit_dir": str(tmp_path / "units"),
        "restore_drill_systemctl_cli": logging_fake(tmp_path, "systemctl", out="disabled\n"),
        "restore_drill_last_run_dir": str(tmp_path / "last-run"),
        "restore_drill_last_run_group": grp_name,
        "restore_drill_last_run_writer": str(tmp_path / "libexec" / "hnx-last-run"),
        "restore_drill_run": False,
    }
    (tmp_path / "units").mkdir(exist_ok=True)
    d.update(kw)
    return d


def _first(tmp_path):
    return {"role": "restore_drill", "tasks_from": "timer", "extra_vars": role_vars(tmp_path)}


@first_run(_first)
def test_the_timer_task_installs_command_config_credentials_and_arms_the_timer(first):
    result, tmp = first
    assert result.returncode == 0, result.stdout + result.stderr
    cfg = json.loads((tmp / "etc" / "restore-drill.json").read_text())
    assert cfg["guests"] == [
        {"id": "guest:app-a", "name": "app-a", "vmid": 130, "expect_export": True},
        {"id": "guest:app-b", "name": "app-b", "vmid": 131, "expect_export": False},
    ]
    assert (
        cfg["stores"] == ["primary", "second"]
        and cfg["authid"] == "drill@pbs!drill"
        and "PBS_PASSWORD" not in json.dumps(cfg)
    )
    env = tmp / "etc" / "restore-drill.env"
    assert "PBS_PASSWORD='pw'" in env.read_text() and (env.stat().st_mode & 0o077) == 0
    assert (tmp / "sbin" / "hnx-restore-drill").stat().st_mode & 0o111
    assert "rotate" in (tmp / "units" / "hnx-restore-drill.service").read_text()
    assert "timer:restore_drill/drill" in (tmp / "units" / "hnx-restore-drill.service").read_text()
    assert "systemctl enable --now hnx-restore-drill.timer" in calls(tmp)
    assert "pw" not in result.stdout + result.stderr  # the secret never reaches the log


@pytest.mark.parametrize(
    "kw",
    [
        {"restore_drill_pbs_authid": "root"},
        {"restore_drill_client_cli": ""},
        {"restore_drill_stores": []},
        {"restore_drill_secret_env": {}},
        {"restore_drill_expect_export": ["guest:nope"]},
        {"restore_drill_guests": [{"id": "guest:x", "name": "x"}]},
    ],
)
def test_a_bad_timer_input_is_refused(tmp_path, kw):
    r = run_role(tmp_path, "restore_drill", "timer", role_vars(tmp_path, **kw))
    assert r.returncode != 0
    assert not (tmp_path / "units" / "hnx-restore-drill.timer").exists()


def test_the_deploy_time_run_keeps_what_the_timer_recorded(tmp_path):
    state = tmp_path / "var" / "drills.json"
    state.parent.mkdir(parents=True)
    state.write_text(
        json.dumps(
            {
                "guests": {},
                "services": {"db": {"verified": True}},
                "notified": {"guest:app-a": "ok"},
                "runs": 4,
            }
        )
    )
    r = run_role(tmp_path, "restore_drill", "main", role_vars(tmp_path, restore_drill_timer=False))
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads(state.read_text())
    assert (
        doc["services"] == {"db": {"verified": True}}
        and doc["runs"] == 4
        and doc["notified"] == {"guest:app-a": "ok"}
    )
