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
    "RL011",
    "RL012",
    "RL013",
    "RL014",
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


SHIPPED = [
    "chrony",
    "compose_app",
    "example_service",
    "greenbone_target",
    "os_hardening",
    "suricata_enroll",
    "tailscale_node",
    "unattended_upgrades",
    "wazuh_agent",
]


@pytest.mark.parametrize("role", SHIPPED)
def test_shipped_roles_pass(role):
    assert role_lint.lint_role(ROOT / "ansible" / "roles" / role) == []


def test_a_directory_of_roles_is_expanded_not_read_as_one_role(capsys):
    assert role_lint.main([str(ROOT / "ansible" / "roles")]) == 0
    assert "0 finding(s)" in capsys.readouterr().out
    assert [p.name for p in role_lint.expand_roles(ROOT / "ansible" / "roles")] == SHIPPED


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


# ------------------------------------------------- RL009 digest, RL011-RL014 (negative + positive)
DIGEST = "sha256:" + "ab" * 32


def mutate(tmp_path, *, main_tasks="", defaults="", template=None):
    """A copy of the compliant role with extra tasks/defaults/template appended."""
    import shutil

    dst = tmp_path / "demo_role"
    shutil.copytree(FX / "compliant" / "roles" / "demo_role", dst)
    if main_tasks:
        main = dst / "tasks" / "main.yml"
        main.write_text(main.read_text() + "\n" + main_tasks)
    if defaults:
        spec = yaml.safe_load((dst / "meta" / "argument_specs.yml").read_text())
        for k in yaml.safe_load(defaults):
            spec["argument_specs"]["main"]["options"][k] = {"type": "raw", "description": "x"}
        (dst / "meta" / "argument_specs.yml").write_text(yaml.safe_dump(spec))
        d = dst / "defaults" / "main.yml"
        d.write_text(d.read_text() + defaults)
    if template is not None:
        (dst / "templates").mkdir(exist_ok=True)
        (dst / "templates" / "x.j2").write_text(template)
    return role_lint.lint_role(dst)


@pytest.mark.parametrize(
    "ref, bad",
    [
        ("example/app:1.2.3", True),  # a tag alone is mutable
        ("example/app:1.2.3@sha256:abc", True),  # malformed digest
        ("example/app", True),
        ("example/app:latest@" + DIGEST, True),
        ("example/app:1.2.3@" + DIGEST, False),
        ("registry.example.internal:5000/app:1.2.3@" + DIGEST, False),
    ],
)
def test_rl009_requires_a_tag_and_a_digest(tmp_path, ref, bad):
    found = mutate(tmp_path, defaults=f'demo_role_image: "{ref}"\n')
    assert ("RL009" in rules(found)) is bad, found


SECRET_TASK = """- name: Write the token
  ansible.builtin.copy:
    dest: /tmp/t
    content: "{{ demo_role_api_token }}"
    mode: "0600"
"""


@pytest.mark.parametrize(
    "tasks, bad",
    [
        (SECRET_TASK, True),
        (SECRET_TASK + "  no_log: false\n", True),
        (SECRET_TASK + "  no_log: true\n", False),
        # inherited from the enclosing block
        ("- block:\n" + "".join("    " + ln + "\n" for ln in SECRET_TASK.splitlines())
         + "  no_log: true\n", False),
        # a loop echoes every item
        ("- name: Loop\n  ansible.builtin.debug:\n    msg: hi\n"
         '  loop: "{{ demo_role_db_password | list }}"\n', True),
        # conditions are evaluated, never echoed; quoted literals are not variables
        ("- name: Gate\n  ansible.builtin.debug:\n    msg: \"{{ lookup('env', 'TOKEN_FILE') }}\"\n"
         '  when: demo_role_secret_key is defined\n', False),
    ],
)  # fmt: skip
def test_rl011_secret_reference_needs_no_log(tmp_path, tasks, bad):
    assert ("RL011" in rules(mutate(tmp_path, main_tasks=tasks))) is bad


@pytest.mark.parametrize(
    "tasks, bad",
    [
        ("- name: s\n  ansible.builtin.shell: echo hi\n  changed_when: false\n", True),
        ("- name: s\n  shell: echo hi\n  changed_when: false\n", True),
        ("- name: r\n  ansible.builtin.raw: echo hi\n", True),
        ('- name: c\n  ansible.builtin.command: "cat /sys/class/net/{{ demo_role_bridge }}/x"\n',
         True),
        ('- name: c\n  ansible.builtin.command:\n    cmd: "ls {{ demo_role_data_dir }}"\n', True),
        ('- name: c\n  ansible.builtin.command: "ls {{ demo_role_data_dir }}"\n'
         "  args:\n    chdir: /\n", True),
        ("- name: c\n  ansible.builtin.command: uptime\n  changed_when: false\n", False),
        ('- name: c\n  ansible.builtin.command:\n    argv: [ls, "{{ demo_role_data_dir }}"]\n'
         "  changed_when: false\n", False),
    ],
)  # fmt: skip
def test_rl012_shell_and_templated_free_form_command(tmp_path, tasks, bad):
    assert ("RL012" in rules(mutate(tmp_path, main_tasks=tasks))) is bad


@pytest.mark.parametrize(
    "tasks, defaults, bad",
    [
        ("- name: u\n  ansible.builtin.uri:\n    url: /x\n    validate_certs: no\n", "", True),
        ('- name: u\n  ansible.builtin.get_url:\n    url: /x\n    dest: /tmp/x\n'
         '    validate_certs: "false"\n', "", True),
        ("", "demo_role_validate_certs: false\n", True),
        ("- name: u\n  ansible.builtin.uri:\n    url: /x\n    validate_certs: true\n", "", False),
        ("", "demo_role_validate_certs: true\n", False),
    ],
)  # fmt: skip
def test_rl013_certificate_validation_off(tmp_path, tasks, defaults, bad):
    found = mutate(tmp_path, main_tasks=tasks, defaults=defaults)
    assert ("RL013" in rules(found)) is bad, found


@pytest.mark.parametrize(
    "template, defaults, bad",
    [
        ("services:\n  a:\n    privileged: true\n", "", True),
        ("services:\n  a:\n    privileged: True\n", "", True),
        ("services:\n  a:\n    volumes: [/var/run/docker.sock:/var/run/docker.sock]\n", "", True),
        ("ExecStart=/usr/bin/docker run --privileged x\n", "", True),
        (None, 'demo_role_socket: "/var/run/docker.sock"\n', True),
        (None, "demo_role_privileged: yes\n", True),
        ("services:\n  a:\n    privileged: {{ x | bool | to_json }}\n", "", False),
        ("services:\n  a:\n    privileged: false\n", "", False),
        ("# privileged: true is refused by validate.yml\nservices: {}\n", "", False),
    ],
)  # fmt: skip
def test_rl014_privileged_and_docker_socket(tmp_path, template, defaults, bad):
    found = mutate(tmp_path, template=template, defaults=defaults)
    assert ("RL014" in rules(found)) is bad, found


def test_ansible_cfg_never_disables_host_key_checking():
    import configparser

    cfg = configparser.ConfigParser(inline_comment_prefixes=(";",))
    cfg.read(ROOT / "ansible" / "ansible.cfg")
    assert cfg.getboolean("defaults", "host_key_checking", fallback=True) is True
    for section in cfg.sections():
        for key, value in cfg.items(section):
            if "host_key" in key:
                assert value.strip().lower() not in ("false", "no", "0", "off"), (section, key)
            if key.endswith("ssh_args") or key.endswith("ssh_common_args"):
                assert "StrictHostKeyChecking=no" not in value, (section, key)
