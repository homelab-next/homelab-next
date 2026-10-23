# SPDX-License-Identifier: Apache-2.0
"""tools/workstation_refs.py (checklist F-17): runtime configs never point at the workstation."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import workstation_refs as lint

REPO = Path(__file__).resolve().parents[2]
# built from pieces so the leak scanner does not see a workstation path in this file
MAC_HOME = "/Use" + "rs/fake-admin/lab"
KEY = "id_" + "ed25519"


def _rules(rel: str, text: str) -> list[str]:
    return [f.rule for f in lint.scan_text(rel, text)]


@pytest.mark.parametrize(
    ("rel", "text", "rule"),
    [
        (
            "ansible/roles/x/templates/x.service.j2",
            "ExecStart=/home/fake-admin/bin/run\n",
            "home-path",
        ),
        ("compose/stack/docker-compose.yml", "volumes: ['~/lab-data:/data']\n", "home-path"),
        ("ansible/roles/x/defaults/main.yml", "x_dir: ${HOME}/x\n", "home-path"),
        ("examples/minimal/site.yml", f"key: {MAC_HOME}\n", "workstation-path"),
        ("ansible/roles/x/defaults/main.yml", f"x_key: /etc/x/{KEY}\n", "workstation-path"),
        (
            "ansible/inventory/example/hosts.yml",
            "ansible_host: admin-workstation.example.internal\n",
            "workstation-host",
        ),
        (
            "tests/fleet_units/golden/a.timer",
            "Description=sync from my-laptop\n",
            "workstation-host",
        ),
        (
            "ansible/roles/x/tasks/main.yml",
            "- name: fetch\n  delegate_to: localhost\n",
            "control-node",
        ),
        ("ansible/roles/x/tasks/main.yml", "- local_action: {module: copy}\n", "control-node"),
        ("ansible/playbooks/x.yml", "- hosts: localhost\n", "control-node"),
        ("ansible/inventory/example/hosts.yml", "ansible_connection: local\n", "control-node"),
    ],
)
def test_workstation_shapes_are_flagged(rel, text, rule):
    assert rule in _rules(rel, text), text


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("ansible/roles/x/templates/x.service.j2", "ExecStart=/opt/x/bin/run\nStateDirectory=x\n"),
        ("ansible/roles/x/tasks/main.yml", "# run from your laptop: ansible-playbook ...\n"),
        ("ansible/roles/x/tasks/main.yml", "- delegate_to: '{{ groups.mgmt[0] }}'\n"),
        ("compose/stack/docker-compose.yml", "volumes: ['x-data:/data']  # not ~/x\n"),
        (
            "ansible/roles/x/defaults/main.yml",
            "x_home: /home/{{ x_user }}  # workstation-ref: allow fake\n",
        ),
        ("examples/services.yml", "url: https://x.svc.example.internal/~/path\n"),
    ],
)
def test_fleet_shapes_comments_and_waivers_are_clean(rel, text):
    assert _rules(rel, text) == [], text


def test_scope_is_runtime_config_only():
    assert lint.in_scope("ansible/roles/x/templates/a.j2")
    assert lint.in_scope("tests/generators/golden/caddy/Caddyfile")
    assert not lint.in_scope("docs/architecture.md")
    assert not lint.in_scope("homelabnext/agent/pack.py")
    assert not lint.in_scope("examples/README.md")
    assert lint.in_scope("orchestrator/examples/controller.yaml")
    assert lint.in_scope("orchestrator/examples/profiles/collector.yaml")
    assert not lint.in_scope("orchestrator/internal/config/config.go")  # source, not config


def test_orchestrator_examples_are_runtime_config(tmp_path, capsys):
    _write(tmp_path, "orchestrator/examples/controller.yaml", "notes_root: /home/fake-user/notes\n")
    _write(tmp_path, "orchestrator/internal/config/config_test.go", "// see /home/fake-user\n")
    assert lint.main([str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "orchestrator/examples/controller.yaml:1: [home-path]" in err
    assert "config_test.go" not in err
    _write(tmp_path, "orchestrator/examples/controller.yaml", "notes_root: /srv/notes\n")
    assert lint.main([str(tmp_path)]) == 0


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_tree_fails_allowlist_passes_and_stale_entry_fails(tmp_path, capsys):
    _write(tmp_path, "compose/s/docker-compose.yml", "command: ['/home/fake-user/run']\n")
    assert lint.main([str(tmp_path)]) == 1
    assert "docker-compose.yml:1: [home-path]" in capsys.readouterr().err
    allow = tmp_path / "allow.yml"
    allow.write_text(
        "allow:\n  - {path: compose/s/docker-compose.yml, match: 'fake-user', reason: fake}\n"
    )
    assert lint.main([str(tmp_path), "--allowlist", str(allow)]) == 0
    allow.write_text(
        "allow:\n  - {path: compose/s/docker-compose.yml, match: 'nothing', reason: x}\n"
    )
    assert lint.main([str(tmp_path), "--allowlist", str(allow)]) == 1
    assert "stale" in capsys.readouterr().err
    allow.write_text("allow:\n  - {path: compose/s/docker-compose.yml}\n")
    assert lint.main([str(tmp_path), "--allowlist", str(allow)]) == 2


def test_the_repository_runtime_never_points_at_the_workstation():
    assert lint.main([str(REPO)]) == 0
