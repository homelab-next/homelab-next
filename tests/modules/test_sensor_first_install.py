# SPDX-License-Identifier: Apache-2.0
"""The network-sensor module on a first install: the configuration includes the address-groups file that
the enroll step writes only after the rules are fetched, and the rule updater reads the whole
configuration, so the role writes a placeholder include first, never over an existing one."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TASKS = next(
    t
    for t in sorted(ROOT.glob("modules/*/roles/*/tasks/main.yml"))
    if "A placeholder address-groups include" in t.read_text()
)
ROLE = TASKS.parents[1]
PFX = ROLE.name


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
    assert copy["dest"] == "{{ " + PFX + "_config_dir }}/{{ " + PFX + "_groups_file }}"
    body = yaml.safe_load(copy["content"])
    assert set(body) == {
        "HOME_NET",
        "EXTERNAL_NET",
    }  # parses as the include the sensor configuration expects


def test_the_include_the_configuration_names_is_the_placeholder_s_file():
    conf = next((ROLE / "templates").glob("*.yaml.j2")).read_text()
    assert "include: {{ " + PFX + "_groups_file }}" in conf
