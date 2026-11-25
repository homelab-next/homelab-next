# SPDX-License-Identifier: Apache-2.0
"""The network-sensor module on a first install: the configuration includes the address-groups file that
the enroll step writes only after the rules are fetched, and the rule updater reads the whole
configuration, so the role writes a placeholder include first, never over an existing one."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
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


def test_a_placeholder_include_is_written_before_the_rules_are_fetched_and_never_over_a_real_one():
    tasks = _block_tasks()
    names = [t["name"] for t in tasks]
    seed = next(
        i for i, n in enumerate(names) if n.startswith("A placeholder address-groups include")
    )
    rules = names.index("Enable the rule sources and fetch the rules")
    enroll = next(i for i, n in enumerate(names) if n.startswith("Generate HOME_NET"))
    assert seed < rules < enroll
    copy = tasks[seed]["ansible.builtin.copy"]
    assert copy["dest"] == "{{ " + PFX + "_config_dir }}/{{ " + PFX + "_groups_file }}"
    # written when missing, or when it is still a placeholder; a real (enrolled) file is never touched
    assert "not " + PFX + "_groups_now.stat.exists" in tasks[seed]["when"]
    assert "placeholder" in tasks[seed]["when"]


def _run_placeholder(tmp_path, existing=None):
    tasks = [
        t for t in _block_tasks() if t["name"] != "Enable the rule sources and fetch the rules"
    ]
    tasks = tasks[
        : next(i for i, t in enumerate(tasks) if t["name"].startswith("A placeholder")) + 1
    ]
    conf = tmp_path / "etc"
    conf.mkdir(parents=True)
    if existing is not None:
        (conf / "groups.yaml").write_text(existing)
    play = [
        {
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "vars": {
                PFX + "_config_dir": str(conf),
                PFX + "_groups_file": "groups.yaml",
                "role_path": str(ROLE),
            },
            "tasks": tasks,
        }
    ]
    (tmp_path / "p.yml").write_text(yaml.safe_dump(play))
    r = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", str(tmp_path / "p.yml")],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    return (conf / "groups.yaml").read_text()


@pytest.mark.requires_tool("ansible-playbook")
def test_the_placeholder_defines_every_standard_group_the_rules_name(tmp_path):
    body = yaml.safe_load(_run_placeholder(tmp_path))
    std = yaml.safe_load((ROOT / f"ansible/roles/{PFX}_enroll/vars/main.yml").read_text())[
        f"{PFX}_enroll_standard_groups"
    ]
    assert set(body) == {"HOME_NET", *std}
    assert body["HTTP_SERVERS"] == "$HOME_NET" and body["EXTERNAL_NET"] == "!$HOME_NET"


@pytest.mark.requires_tool("ansible-playbook")
def test_an_earlier_placeholder_is_replaced_and_a_real_file_is_not(tmp_path):
    old = f'%YAML 1.1\n---\n# placeholder (role {PFX}, first install): x\nHOME_NET: "[::1]"\n'
    assert "HTTP_SERVERS" in yaml.safe_load(_run_placeholder(tmp_path / "a", old))
    real = '%YAML 1.1\n---\n# the enrolled file (no placeholder marker)\nHOME_NET: "[::1]"\n'
    assert _run_placeholder(tmp_path / "b", real) == real


def test_the_ics_parsers_the_bundled_rules_name_are_enabled_for_detection():
    conf = yaml.safe_load(
        "\n".join(
            line
            for line in next((ROLE / "templates").glob("*.yaml.j2")).read_text().splitlines()
            if "{{" not in line and "{%" not in line and not line.startswith(("%", "{#"))
        )
    )
    protocols = conf["app-layer"]["protocols"]
    for name in ("modbus", "dnp3", "enip"):
        assert protocols[name]["enabled"] == "detection-only"


def test_the_include_the_configuration_names_is_the_placeholder_s_file():
    conf = next((ROLE / "templates").glob("*.yaml.j2")).read_text()
    assert "include: {{ " + PFX + "_groups_file }}" in conf


def test_the_command_socket_is_where_the_command_client_and_the_unit_look():
    """The command client's default path, which the distribution unit's reload and stop use too:
    a socket in a directory nothing creates fails to bind, and every client call misses it."""
    conf = yaml.safe_load(
        "\n".join(
            line
            for line in next((ROLE / "templates").glob("*.yaml.j2")).read_text().splitlines()
            if "{{" not in line and "{%" not in line and not line.startswith(("%", "{#"))
        )
    )
    assert conf["unix-command"]["filename"] == f"/run/{PFX}-command.socket"
