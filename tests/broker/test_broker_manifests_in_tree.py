# SPDX-License-Identifier: Apache-2.0
"""Every broker manifest the tree names either loads through ``load_manifest`` (what ``hnx broker
validate`` and ``serve`` run) or is a listed decision table, and a served manifest can be checked
against a decision table (``hnx broker validate --decision-table``)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from homelabnext.broker import decision_table_problems
from homelabnext.broker.cli import main
from homelabnext.broker.service import ManifestError, load_manifest

ROOT = Path(__file__).resolve().parents[2]
#: manifests the repository checks other documents against, whose handlers are the site's: they
#: cannot be served as they are, and a served manifest is checked against them instead
DECISION_TABLES = {"workflows/broker.manifest.json"}
TABLE = ROOT / "workflows" / "broker.manifest.json"


def _named_manifests() -> set[str]:
    """Every manifest a pack's ``broker_manifest`` or a roster's ``brokers`` names, plus the
    broker examples: repository-relative paths."""
    out = {p.relative_to(ROOT).as_posix() for p in (ROOT / "examples" / "broker").glob("*.yml")}
    for pack in sorted((ROOT / "workflows" / "packs").glob("*.yml")):
        out.add(yaml.safe_load(pack.read_text())["broker_manifest"])
    for roster in sorted(ROOT.glob("examples/**/roster.yml")):
        for rel in yaml.safe_load(roster.read_text()).get("brokers", []):
            out.add((roster.parent / rel).resolve().relative_to(ROOT).as_posix())
    return out


def test_the_tree_names_the_manifests_this_checks():
    named = _named_manifests()
    assert named >= DECISION_TABLES, "a listed decision table nothing names: drop it"
    assert {"examples/broker/manifest.yml", "examples/broker/manifest.production.yml"} <= named


@pytest.mark.parametrize("rel", sorted(_named_manifests() - DECISION_TABLES))
def test_every_named_manifest_is_servable(rel):
    load_manifest(ROOT / rel)


@pytest.mark.parametrize("rel", sorted(DECISION_TABLES))
def test_a_decision_table_fails_only_for_the_handlers_the_site_supplies(rel):
    """The workflow manifest failed load_manifest six times over and no test noticed.  A
    decision table may lack exactly the handlers that are not in the tree; every handler that is
    in the tree is pinned by its document, and nothing else may be wrong with it."""
    path = ROOT / rel
    with pytest.raises(ManifestError) as info:
        load_manifest(path)
    doc = json.loads(path.read_text())
    absent = sorted(
        a["action"] for a in doc["actions"] if not (path.parent / a["handler"]).is_file()
    )
    assert absent, f"{rel}: every handler is in the tree; serve it and drop it from the list"
    want = [f"{a}: expected exactly one handler document, got 0" for a in absent]
    assert sorted(info.value.problems) == sorted(want)


def _table():
    return json.loads(TABLE.read_text())


def test_a_served_manifest_that_enforces_the_table_passes():
    served = _table()
    served["actions"] = [a for a in served["actions"] if a["action"] != "host.isolate"]
    assert decision_table_problems(served, _table()) == []


@pytest.mark.parametrize(
    "change, needle",
    [
        (lambda m: m["actions"][4].update(requires_approval=False), "requires approval"),
        (lambda m: m["actions"][0].update(tier="read"), "tier"),
        (lambda m: m["grants"][1]["actions"].append("host.isolate"), "granted host.isolate"),
        (lambda m: m["grants"][1].update(max_tier="privileged"), "max_tier"),
        (lambda m: m.update(allow_agent_approvers=True), "agent approvers"),
    ],
)
def test_a_served_manifest_less_strict_than_the_table_is_refused(change, needle):
    served = copy.deepcopy(_table())
    change(served)
    problems = decision_table_problems(served, _table())
    assert any(needle in p for p in problems), problems


def test_validate_checks_a_served_manifest_against_a_decision_table(tmp_path, capsys):
    served = tmp_path / "manifest.json"
    doc = _table()
    doc.pop("handler_docs")
    doc["actions"] = []
    doc["grants"] = [{"profile": "profile:workflow-agents", "actions": ["dns.block-domains"],
                      "max_tier": "execute"}]  # fmt: skip
    served.write_text(json.dumps(doc))
    assert main(["validate", str(served)]) == 0
    capsys.readouterr()
    assert main(["validate", str(served), "--decision-table", str(TABLE), "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert any("granted dns.block-domains" in p for p in out["problems"])
    assert any("max_tier" in p for p in out["problems"])
    assert main(["validate", str(served), "--decision-table", str(tmp_path / "none")]) == 1
