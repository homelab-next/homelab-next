# SPDX-License-Identifier: Apache-2.0
"""``hnx broker validate`` refuses the operator's memory tools as broker actions (ADR-0037
decision 12): ``memory.retract``, ``memory.lift``, ``memory.purge`` and ``memory.dependents`` are
run by an operator through ``hnx agent memory``, and are never answered to a profile."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from homelabnext.broker.cli import main
from homelabnext.broker.service import MEMORY_ADMIN_ACTIONS, load_manifest, validate_manifest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "broker"


def test_the_names_are_the_four_the_adr_lists():
    assert {
        "memory.retract",
        "memory.lift",
        "memory.purge",
        "memory.dependents",
    } == MEMORY_ADMIN_ACTIONS


@pytest.mark.parametrize("name", sorted(MEMORY_ADMIN_ACTIONS))
def test_validate_refuses_an_action_named_for_a_memory_tool(name):
    manifest, _ = load_manifest(EXAMPLE / "manifest.yml")
    assert validate_manifest(manifest, EXAMPLE)[1] == []  # the example is clean
    named = copy.deepcopy(manifest)
    status = next(a for a in named["actions"] if a["action"] == "service.status")
    named["actions"].append({**status, "action": name})
    problems = validate_manifest(named, EXAMPLE)[1]
    assert f"actions: {name} is an operator memory tool, never a broker action" in " ".join(
        problems
    )


def test_the_cli_refuses_it_too(tmp_path, capsys):
    import yaml

    manifest, _ = load_manifest(EXAMPLE / "manifest.yml")
    status = next(a for a in manifest["actions"] if a["action"] == "service.status")
    manifest["actions"].append({**status, "action": "memory.retract"})
    path = EXAMPLE / "manifest.yml"
    out = tmp_path / "manifest.yml"
    out.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    # handler paths are relative to the manifest: validate it beside the example's handlers
    (tmp_path / "handlers").symlink_to(path.parent / "handlers")
    for doc in manifest.get("handler_docs", []):
        assert (tmp_path / doc).exists()
    assert main(["validate", str(out)]) == 1
    assert "memory.retract is an operator memory tool" in capsys.readouterr().out
