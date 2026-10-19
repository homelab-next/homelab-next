# SPDX-License-Identifier: Apache-2.0
"""The shipped profile task files refuse inputs that would escape the path or file they build."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PROFILES = ROOT / "profiles"
pytestmark = pytest.mark.skipif(
    shutil.which("ansible-playbook") is None, reason="ansible-playbook not installed"
)


def run_tasks(tmp_path, tasks_file, extra_vars):
    play = [
        {
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "tasks": [{"ansible.builtin.include_tasks": str(tasks_file)}],
        }
    ]
    pb = tmp_path / "play.yml"
    pb.write_text(yaml.safe_dump(play))
    ev = tmp_path / "vars.json"
    ev.write_text(json.dumps(extra_vars))
    env = dict(
        os.environ,
        ANSIBLE_LOCALHOST_WARNING="False",
        ANSIBLE_HOME=str(tmp_path / ".ansible"),
        ANSIBLE_NOCOLOR="1",
    )
    return subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-e", f"@{ev}", str(pb)],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
    )


MODULE_TASKS = PROFILES / "board-sensor-driver" / "tasks" / "persist-module.yml"
BRIDGE_TASKS = PROFILES / "vlan-aware-bridge-verifier" / "tasks" / "verify-bridge.yml"


@pytest.mark.parametrize(
    "module", ["../../tmp/evil", "sensor chip", "sensor\nchip", "Sensor", "", "a/b"]
)
def test_board_sensor_driver_refuses_a_bad_module_name(tmp_path, module):
    r = run_tasks(
        tmp_path,
        MODULE_TASKS,
        {"board_sensor_driver_module": module, "board_sensor_driver_boards": []},
    )
    assert r.returncode != 0
    assert "board_sensor_driver_module must match" in r.stdout
    assert "Read the board product name" not in r.stdout


def test_board_sensor_driver_accepts_a_plain_module_name(tmp_path):
    r = run_tasks(
        tmp_path,
        MODULE_TASKS,
        {"board_sensor_driver_module": "sensorchip_x", "board_sensor_driver_boards": []},
    )
    # past validation; the DMI read may fail on a host without /sys/class/dmi, and an empty
    # allowlist means nothing is ever written
    assert "Read the board product name" in r.stdout, r.stdout


@pytest.mark.parametrize("bridge", ["vmbr0/../../../etc", "..", "a b", "x\ny", "a" * 16, ""])
def test_vlan_bridge_verifier_refuses_a_bad_bridge_name(tmp_path, bridge):
    r = run_tasks(tmp_path, BRIDGE_TASKS, {"vlan_aware_bridge_verifier_bridge": bridge})
    assert r.returncode != 0
    assert "must be an interface name" in r.stdout
    assert "Read bridge VLAN filtering state" not in r.stdout


def test_vlan_bridge_verifier_reads_through_argv_not_a_free_string():
    tasks = yaml.safe_load(BRIDGE_TASKS.read_text())
    for t in tasks:
        if "ansible.builtin.command" in t:
            assert isinstance(t["ansible.builtin.command"], dict)
            assert "argv" in t["ansible.builtin.command"]
