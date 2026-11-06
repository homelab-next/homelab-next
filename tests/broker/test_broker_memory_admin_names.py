# SPDX-License-Identifier: Apache-2.0
"""``hnx broker validate`` refuses the operator's memory tools as broker actions (ADR-0037
decision 12, amended 2026-11-06): the whole ``memory.*`` namespace but the notes lane's
``memory.write`` (``memory.retract``, ``lift``, ``purge``, ``dependents``, ``restamp`` and any
other) is run by an operator through ``hnx agent memory`` and never answered to a profile, in a
manifest's actions and in a handler document alike, and no handler may name the memory admin."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

from homelabnext.broker.cli import main
from homelabnext.broker.service import (
    MEMORY_ADMIN_ACTIONS,
    load_manifest,
    memory_admin_action,
    validate_manifest,
)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "broker"


def test_the_namespace_is_refused_but_the_notes_lane():
    assert {
        "memory.retract",
        "memory.lift",
        "memory.purge",
        "memory.dependents",
        "memory.restamp",
    } == MEMORY_ADMIN_ACTIONS
    assert all(memory_admin_action(n) for n in [*MEMORY_ADMIN_ACTIONS, "memory.anything"])
    assert not memory_admin_action("memory.write") and not memory_admin_action("service.status")


@pytest.mark.parametrize("name", [*sorted(MEMORY_ADMIN_ACTIONS), "memory.export"])
def test_validate_refuses_an_action_in_the_memory_namespace(name):
    manifest, _ = load_manifest(EXAMPLE / "manifest.yml")
    assert validate_manifest(manifest, EXAMPLE)[1] == []  # the example is clean
    named = copy.deepcopy(manifest)
    status = next(a for a in named["actions"] if a["action"] == "service.status")
    named["actions"].append({**status, "action": name})
    problems = validate_manifest(named, EXAMPLE)[1]
    assert f"actions: {name} is an operator memory tool, never a broker action" in " ".join(
        problems
    )


def _copy(tmp_path):
    shutil.copytree(EXAMPLE, tmp_path / "broker")
    return tmp_path / "broker"


def test_a_handler_document_for_a_memory_tool_is_refused(tmp_path):
    base = _copy(tmp_path)
    manifest, _ = load_manifest(base / "manifest.yml")
    doc_rel = next(d for d in manifest["handler_docs"] if "status" in d)
    doc = json.loads((base / doc_rel).read_text(encoding="utf-8"))
    doc["action"] = "memory.restamp"
    out = base / "handlers" / "memory-restamp.json"
    out.write_text(json.dumps(doc), encoding="utf-8")
    manifest["handler_docs"] = [*manifest["handler_docs"], "handlers/memory-restamp.json"]
    problems = validate_manifest(manifest, base)[1]
    assert any(
        p.startswith("handlers/memory-restamp.json: action memory.restamp is an operator")
        for p in problems
    ), problems


def test_a_handler_that_names_the_memory_admin_is_refused(tmp_path):
    base = _copy(tmp_path)
    manifest, _ = load_manifest(base / "manifest.yml")
    status = next(a for a in manifest["actions"] if a["action"] == "service.status")
    handler = base / status["handler"]
    handler.write_text(
        handler.read_text(encoding="utf-8") + "\n# python3 -m homelabnext.memory_admin.cli\n",
        encoding="utf-8",
    )
    problems = validate_manifest(manifest, base)[1]
    assert any("names homelabnext.memory_admin" in p for p in problems), problems


def test_the_cli_refuses_it_too(tmp_path, capsys):
    import yaml

    base = _copy(tmp_path)
    manifest, _ = load_manifest(base / "manifest.yml")
    status = next(a for a in manifest["actions"] if a["action"] == "service.status")
    manifest["actions"].append({**status, "action": "memory.retract"})
    (base / "manifest.yml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    assert main(["validate", str(base / "manifest.yml")]) == 1
    assert "memory.retract is an operator memory tool" in capsys.readouterr().out
