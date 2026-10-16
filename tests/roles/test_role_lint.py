# SPDX-License-Identifier: Apache-2.0
"""Linter fixtures: one compliant role and one defect fixture per rule."""

import importlib.util
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
FX = Path(__file__).parent / "fixtures"
_spec = importlib.util.spec_from_file_location("role_lint", ROOT / "tools" / "role_lint.py")
role_lint = importlib.util.module_from_spec(_spec)
import sys

sys.modules["role_lint"] = role_lint
_spec.loader.exec_module(role_lint)

ROLE_RULES = [
    "RL000",
    "RL001",
    "RL002",
    "RL003",
    "RL004",
    "RL005",
    "RL006",
    "RL007",
    "RL008",
    "RL009",
    "RL010",
]


def rules(findings):
    return {f.rule for f in findings}


def test_compliant_fixture_is_clean():
    assert role_lint.lint_role(FX / "compliant" / "roles" / "demo_role") == []


@pytest.mark.parametrize("rule", ROLE_RULES)
def test_each_defect_fixture_triggers_its_rule(rule):
    found = role_lint.lint_role(FX / rule / "roles" / "demo_role")
    assert rule in rules(found), found
    if rule != "RL002":  # RL002 fixture also (correctly) trips RL007
        assert rules(found) == {rule}, found


def test_every_rule_has_a_fixture():
    assert set(role_lint.RULES) == set(ROLE_RULES) | {"PB001", "PB002"}


@pytest.mark.parametrize("role", ["example_service", "compose_app"])
def test_shipped_roles_pass(role):
    assert role_lint.lint_role(ROOT / "ansible" / "roles" / role) == []


def test_loopback_and_unspecified_are_allowed(tmp_path):
    import shutil

    dst = tmp_path / "demo_role"
    shutil.copytree(FX / "compliant" / "roles" / "demo_role", dst)
    (dst / "defaults" / "main.yml").write_text(
        (dst / "defaults" / "main.yml").read_text()
        + 'demo_role_bind: "0.0.0.0"\ndemo_role_loop: "127.0.0.1"\n'
    )
    spec = yaml.safe_load((dst / "meta" / "argument_specs.yml").read_text())
    for k in ("demo_role_bind", "demo_role_loop"):
        spec["argument_specs"]["main"]["options"][k] = {"type": "str", "description": "x"}
    (dst / "meta" / "argument_specs.yml").write_text(yaml.safe_dump(spec))
    assert role_lint.lint_role(dst) == []


def test_playbook_targeting_a_hostname_fails():
    findings = role_lint.lint_playbook(FX / "PB001" / "playbook.yml", FX / "PB001" / "hosts.yml")
    assert rules(findings) == {"PB001"}


def test_playbook_targeting_a_capability_group_passes():
    assert role_lint.lint_playbook(FX / "PB001" / "good.yml", FX / "PB001" / "hosts.yml") == []


def test_every_shipped_playbook_targets_a_group():
    inv = ROOT / "ansible" / "inventory" / "example" / "hosts.yml"
    pbs = sorted((ROOT / "ansible" / "playbooks").glob("*.yml"))
    assert pbs
    for pb in pbs:
        assert role_lint.lint_playbook(pb, inv) == [], pb


def test_example_inventory_has_all_capability_groups():
    inv = ROOT / "ansible" / "inventory" / "example" / "hosts.yml"
    hosts, groups = role_lint._inventory_hosts(inv)
    expected = {
        "cap_" + c
        for c in [
            "siem",
            "lake",
            "query",
            "inference",
            "edge",
            "idp",
            "secrets",
            "orchestration",
            "broker",
            "cases",
            "tip",
            "monitoring",
            "decision",
            "nifi",
        ]
    }
    assert expected <= groups
    assert all(h.endswith(".example.internal") for h in hosts)


def test_cli_exit_codes(tmp_path, capsys):
    assert role_lint.main([str(FX / "compliant" / "roles" / "demo_role")]) == 0
    assert role_lint.main([str(FX / "RL003" / "roles" / "demo_role")]) == 1
    assert role_lint.main([str(tmp_path / "nope")]) == 2
    assert role_lint.main([]) == 2
