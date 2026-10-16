# SPDX-License-Identifier: Apache-2.0
"""The customization planner over the shipped registry example and the shipped optional profiles."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from integration_golden import GOLDEN, UPDATE

from homelabnext.customization.cli import main as custom_main

ROOT = Path(__file__).resolve().parents[2]
TODAY = "2026-10-15"
PROFILES = (
    "custom:board-sensor-driver",
    "custom:reverse-proxy-tunnel-workaround",
    "custom:vlan-aware-bridge-verifier",
)


def _run(capsys, *args):
    code = custom_main(
        ["plan", "--today", TODAY, "--registry", str(ROOT / "examples/services.yml"), *args]
    )
    return code, json.loads(capsys.readouterr().out)


def test_shipped_profiles_are_inert_until_enabled(capsys):
    code, plan = _run(capsys)
    assert code == 0 and plan["ok"]
    assert plan["items"] == [] and sorted(plan["inactive_optional"]) == sorted(PROFILES)


def test_enabled_profiles_plan_cleanly_against_the_registry_example(capsys):
    args = [a for p in PROFILES for a in ("--enable", f"{p}=edge-core")]
    code, plan = _run(capsys, *args)
    assert code == 0 and plan["ok"], plan["findings"]
    assert plan["conflicts"] == [] and plan["findings"] == []
    assert sorted(i["id"] for i in plan["items"]) == sorted(PROFILES)
    for item in plan["items"]:
        assert item["applies_to"]["hosts"] == ["edge-core"]
    golden = GOLDEN / "customization-plan.json"
    text = json.dumps(plan, indent=2, sort_keys=True) + "\n"
    if UPDATE:
        golden.write_text(text, encoding="utf-8")
    assert text == golden.read_text(encoding="utf-8")


def test_enabling_a_profile_on_a_host_the_registry_lacks_fails_closed(capsys):
    code, plan = _run(capsys, "--enable", "custom:board-sensor-driver=no-such-host")
    assert code == 1 and not plan["ok"]
    assert plan["items"] == []
    assert any(f["severity"] == "error" for f in plan["findings"])


def test_a_shipped_profile_is_maintained_upstream_and_never_expires(capsys):
    code = custom_main(
        ["plan", "--today", "2030-01-01", "--enable", "custom:board-sensor-driver=edge-core"]
    )
    plan = json.loads(capsys.readouterr().out)
    # shipped profiles carry maintained_upstream: true, so a far-future date does not refuse them
    # (an expired overlay customization is still refused: tests/customization)
    assert code == 0 and plan["ok"]
    assert [i["id"] for i in plan["items"]] == ["custom:board-sensor-driver"]


@pytest.mark.parametrize("cmd", ["check", "list"])
def test_check_and_list_run_over_the_shipped_tree(cmd, capsys):
    assert custom_main([cmd, "--today", TODAY]) == 0
    assert "custom:" in capsys.readouterr().out or cmd == "check"
