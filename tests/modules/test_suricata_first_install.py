# SPDX-License-Identifier: Apache-2.0
"""modules/suricata on a first install: the configuration includes the address-groups file that
suricata_enroll writes only after the rules are fetched, and suricata-update reads the whole
configuration, so the role writes a placeholder include first, never over an existing one."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "modules/suricata/roles/suricata/tasks/main.yml"


def _block_tasks():
    doc = yaml.safe_load(TASKS.read_text())
    (gate,) = [t for t in doc if t.get("name") == "Rules, HOME_NET and the gate"]
    return gate["block"]


def test_a_placeholder_include_is_written_before_the_rules_are_fetched_and_never_over_one():
    tasks = _block_tasks()
    names = [t["name"] for t in tasks]
    seed = next(
        i for i, n in enumerate(names) if n.startswith("A placeholder address-groups include")
    )
    rules = names.index("Enable the rule sources and fetch the rules")
    enroll = next(i for i, n in enumerate(names) if n.startswith("Generate HOME_NET"))
    assert seed < rules < enroll
    copy = tasks[seed]["ansible.builtin.copy"]
    assert copy["force"] is False  # an existing (real) file is never replaced
    assert copy["dest"] == "{{ suricata_config_dir }}/{{ suricata_groups_file }}"
    body = yaml.safe_load(copy["content"])
    assert set(body) == {"HOME_NET", "EXTERNAL_NET"}  # parses as the include suricata.yaml expects


def test_the_include_the_configuration_names_is_the_placeholder_s_file():
    conf = (ROOT / "modules/suricata/roles/suricata/templates/suricata.yaml.j2").read_text()
    assert "include: {{ suricata_groups_file }}" in conf
