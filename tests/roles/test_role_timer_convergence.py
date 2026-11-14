# SPDX-License-Identifier: Apache-2.0
"""Scheduled scan timers are restored when disabled or stopped by hand."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import yaml
from rolerun import _invocation, calls, fake

ROOT = Path(__file__).resolve().parents[2]
ANSIBLE_ROLES = ROOT / "ansible" / "roles"
ROLES = ("needrestart", "lynis", "aide", "clamav", "rkhunter", "trivy")

FAKE_SYSTEMCTL = r"""
import os, sys
a = sys.argv[1:]
open(LOG, "a").write("systemctl " + " ".join(a) + "\n")
en, act = STATE + ".enabled", STATE + ".active"
if a[0] == "enable":
    open(en, "w").close()
    if "--now" in a:
        open(act, "w").close()
elif a[0] == "is-enabled":
    print("enabled" if os.path.exists(en) else "disabled")
    sys.exit(0 if os.path.exists(en) else 1)
elif a[0] == "is-active":
    print("active" if os.path.exists(act) else "inactive")
    sys.exit(0 if os.path.exists(act) else 3)
"""


def _run_tasks(tmp_path: Path, role: str):
    task_path = ANSIBLE_ROLES / role / "tasks" / "config.yml"
    config = yaml.safe_load(task_path.read_text())
    tasks = [
        task
        for task in config
        if task["name"].startswith("Ask whether the ")
        or task["name"].startswith("Reload systemd (units changed)")
    ]
    assert len(tasks) == 3, role

    cli = fake(
        tmp_path / "systemctl",
        FAKE_SYSTEMCTL.replace("LOG", repr(str(tmp_path / "calls.log"))).replace(
            "STATE", repr(str(tmp_path / role))
        ),
    )
    variables = {
        f"{role}_systemctl_cli": cli,
        f"{role}_units": {"changed": False},
    }
    playbook, env = _invocation(tmp_path, str(ANSIBLE_ROLES / role), "config", variables)
    play_path = Path(playbook[-1])
    play = yaml.safe_load(play_path.read_text())
    play[0]["tasks"] = tasks
    play_path.write_text(yaml.safe_dump(play))
    result = subprocess.run(playbook, capture_output=True, text=True, env=env, cwd=tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    return result


def _converged(result):
    return re.search(r"localhost\s*: ok=\d+\s+changed=0 ", result.stdout), result.stdout


def test_scan_timers_recover_manual_disable_and_stop_and_then_converge(tmp_path):
    for role in ROLES:
        timer = tmp_path / role
        enabled, active = timer.with_suffix(".enabled"), timer.with_suffix(".active")

        (tmp_path / "calls.log").unlink(missing_ok=True)
        _run_tasks(tmp_path, role)
        assert "systemctl enable --now hnx-" + role + ".timer" in calls(tmp_path)
        assert enabled.exists() and active.exists()

        (tmp_path / "calls.log").unlink()
        assert _converged(_run_tasks(tmp_path, role))[0]
        assert calls(tmp_path) == [
            f"systemctl is-enabled hnx-{role}.timer",
            f"systemctl is-active hnx-{role}.timer",
        ]

        enabled.unlink()
        active.unlink()
        (tmp_path / "calls.log").unlink()
        repaired = _run_tasks(tmp_path, role)
        assert "systemctl enable --now hnx-" + role + ".timer" in calls(tmp_path)
        assert enabled.exists() and active.exists()
        assert "changed=1 " in repaired.stdout

        active.unlink()
        (tmp_path / "calls.log").unlink()
        repaired = _run_tasks(tmp_path, role)
        assert "systemctl enable --now hnx-" + role + ".timer" in calls(tmp_path)
        assert active.exists()
        assert "changed=1 " in repaired.stdout

        (tmp_path / "calls.log").unlink()
        converged, output = _converged(_run_tasks(tmp_path, role))
        assert converged, output
        assert calls(tmp_path) == [
            f"systemctl is-enabled hnx-{role}.timer",
            f"systemctl is-active hnx-{role}.timer",
        ]
