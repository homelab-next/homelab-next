# SPDX-License-Identifier: Apache-2.0
"""One name, one meaning (ADR-0039 decision 7): ``orchestration`` is the agent-orchestrator
contract only, so no example registry gives it to another product, and the product vocabulary
names a reference product for the ``automation`` slot and none for ``orchestration``."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
REGISTRIES = sorted(
    p.relative_to(ROOT).as_posix()
    for p in (ROOT / "examples").rglob("services.yml")
    if "services" in (yaml.safe_load(p.read_text(encoding="utf-8")) or {})
)


@pytest.mark.parametrize("path", REGISTRIES)
def test_orchestration_rows_are_the_orchestrator_contract_only(path):
    doc = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    wrong = {
        name: row.get("impl")
        for name, row in (doc.get("services") or {}).items()
        if isinstance(row, dict)
        and row.get("capability") == "orchestration"
        and row.get("impl") != "orchestrator"
    }
    assert wrong == {}, f"{path}: orchestration is the agent-orchestrator contract; use automation"


def test_the_lab_topology_soar_is_an_automation_row():
    doc = yaml.safe_load((ROOT / "examples/lab-topology/services.yml").read_text(encoding="utf-8"))
    row = doc["services"]["automation"]
    assert (row["capability"], row["impl"]) == ("automation", "example-soar")
    assert doc["hosts"][row["host"]]["role"] == "automation"
    guest = yaml.safe_load(
        (ROOT / "examples/lab-topology/guests" / f"{row['host']}.yml").read_text(encoding="utf-8")
    )
    assert guest["capability"] == "cap:automation"


def test_the_vocabulary_names_the_automation_slot_s_product_and_no_orchestration_product():
    doc = yaml.safe_load((ROOT / "tools/product_names.yml").read_text(encoding="utf-8"))
    whys = [str(e.get("why", "")) for e in doc["products"] if isinstance(e, dict)]
    assert any(w.startswith("the automation slot's reference product") for w in whys)
    assert not [w for w in whys if "orchestration" in w]
