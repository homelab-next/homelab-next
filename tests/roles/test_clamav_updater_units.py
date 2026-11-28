# SPDX-License-Identifier: Apache-2.0
"""The scanner role masks both of the package's one-shot updater units. Masking only the timer left the
service enabled into multi-user.target, so it ran at every boot beside the update daemon and failed on
the log-file lock (three guests after the 2026-11-28 boot)."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "ansible" / "roles" / "clamav" / "tasks" / "main.yml"
UNITS = {"clamav-freshclam-once.timer", "clamav-freshclam-once.service"}


def _masked_units(tasks):
    out = set()
    for task in tasks:
        body = task.get("ansible.builtin.systemd_service") or task.get("systemd_service")
        if not isinstance(body, dict) or body.get("masked") is not True:
            continue
        name = body.get("name")
        if name == "{{ item }}":
            out.update(task.get("loop") or [])
        elif isinstance(name, str):
            out.add(name)
    return out


@pytest.mark.static
def test_both_one_shot_updater_units_are_masked():
    tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
    assert _masked_units(tasks) >= UNITS, f"not masked: {sorted(UNITS - _masked_units(tasks))}"
