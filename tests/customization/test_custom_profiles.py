# SPDX-License-Identifier: Apache-2.0
"""The three shipped optional profiles: each lints clean, plans when enabled, stays inert when not."""

from __future__ import annotations

import pytest
import yaml
from cust_helpers import TODAY

from homelabnext.customization import build_plan, lint, load_tree
from homelabnext.customization.loader import REPO_ROOT

IDS = {
    "board-sensor-driver": "custom:board-sensor-driver",
    "vlan-aware-bridge-verifier": "custom:vlan-aware-bridge-verifier",
    "reverse-proxy-tunnel-workaround": "custom:reverse-proxy-tunnel-workaround",
}


@pytest.fixture(scope="module")
def shipped():
    items, problems = load_tree(REPO_ROOT / "profiles", "public")
    assert problems == []
    return {c.id: c for c in items}


def test_three_profiles_ship(shipped):
    assert set(shipped) == set(IDS.values())
    assert all(c.optional and c.origin == "public" for c in shipped.values())


def test_all_lint_clean(shipped, uni):
    assert lint(list(shipped.values()), uni, TODAY) == []


def test_inert_until_enabled(shipped, uni):
    plan = build_plan(list(shipped.values()), uni, TODAY)
    assert plan["ok"] and plan["items"] == []
    assert sorted(plan["inactive_optional"]) == sorted(IDS.values())


def test_board_sensor_driver_plan(shipped, uni):
    cid = IDS["board-sensor-driver"]
    plan = build_plan(list(shipped.values()), uni, TODAY, {cid: ["mon-core"]})
    assert plan["ok"], plan["findings"]
    prof = plan["resolved"]["profiles"]["board-sensor-driver"]
    assert prof["hosts"] == ["mon-core"]
    assert prof["vars"]["board_sensor_driver_module"] == "sensorchip_x"
    assert prof["tasks"][0]["file"] == "tasks/persist-module.yml"


def test_vlan_bridge_verifier_is_read_only(shipped, uni):
    c = shipped[IDS["vlan-aware-bridge-verifier"]]
    tasks = yaml.safe_load((c.base / "tasks" / "verify-bridge.yml").read_text())
    modules = {k for t in tasks for k in t if k not in ("name", "register", "changed_when")}
    assert modules <= {"ansible.builtin.command", "ansible.builtin.assert"}
    assert all(t.get("changed_when") is False for t in tasks if "ansible.builtin.command" in t)
    plan = build_plan([c], uni, TODAY, {c.id: ["edge-core"]})
    assert plan["ok"] and plan["resolved"]["profiles"]["vlan-aware-bridge-verifier"]["hosts"] == [
        "edge-core"
    ]


def test_tunnel_workaround_overlay_does_not_touch_core_template(shipped, uni, repo_root):
    c = shipped[IDS["reverse-proxy-tunnel-workaround"]]
    core = repo_root / "ansible/roles/example_service/templates/config.yml.j2"
    before = core.read_bytes()
    plan = build_plan([c], uni, TODAY, {c.id: []})
    assert plan["ok"], plan["findings"]
    (ov,) = plan["resolved"]["template_overlays"]["example_service"]["config.yml.j2"]
    assert ov["mode"] == "append" and len(ov["sha256"]) == 64
    assert core.read_bytes() == before


def test_every_profile_has_a_readme_and_spdx(shipped):
    for c in shipped.values():
        assert (c.base / "README.md").is_file()
        for p in c.base.rglob("*"):
            if p.is_file() and p.suffix in (".yml", ".j2"):
                assert "SPDX-License-Identifier: Apache-2.0" in p.read_text()
