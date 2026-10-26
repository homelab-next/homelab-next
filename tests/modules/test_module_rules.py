# SPDX-License-Identifier: Apache-2.0
"""Unit tests of the loader rules' name helpers (homelabnext.modules.rules).  The contract tests
(tests/schemas/test_module_1_0.py) apply the full rule set to the fictional examples."""

from __future__ import annotations

from pathlib import Path

import pytest

from homelabnext.modules import rules as mr

ROOT = Path(__file__).resolve().parents[2]


def test_a_bound_name_needs_the_id_and_a_separator():
    assert mr._named("external-collector", "external-collector")
    assert mr._named("external-collector-analyst", "external-collector")
    assert not mr._named("external-collectorx", "external-collector")
    assert mr._named("external_collector_edge", "external-collector", "_")
    assert not mr._named("external-collector-edge", "external-collector", "_")


def test_lane_writes_are_bound_to_their_lane():
    assert mr._own_write_prefix("findings/m/", "m", "real")
    assert not mr._own_write_prefix("findings/m-shadow/", "m", "real")
    assert mr._own_write_prefix("findings/m-shadow/", "m", "shadow")
    assert not mr._own_write_prefix("findings/m/", "m", "shadow")
    assert mr._own_write_prefix("state/m-shadow/", "m")
    assert not mr._own_write_prefix("cases/m/", "m")
    assert not mr._own_write_prefix("findings/", "m")


def test_the_default_in_tree_root_is_the_checkouts_public_modules_tree_only():
    assert mr.public_module_roots() == (ROOT / "modules",)
    assert not hasattr(mr, "EXAMPLE_ROOTS"), "the examples' root is the tests' fixture"


def test_outside_a_checkout_there_is_no_default_root(monkeypatch, tmp_path):
    """Negative: an installed package has no public tree to trust, so the default refuses
    (NotACheckout) instead of guessing site-packages/modules."""
    monkeypatch.setattr(mr.paths, "checkout_root", lambda: None)
    with pytest.raises(mr.paths.NotACheckout):
        mr.public_module_roots()
    doc = {"id": "m", "kind": "feature", "origin": {"kind": "in-tree"}, "requires": {}}
    with pytest.raises(mr.paths.NotACheckout):
        mr.module_problems(doc, tmp_path / "m", {}, lambda p: {})
    assert "origin in-tree: the module is not in the public modules/ tree" in mr.module_problems(
        doc, tmp_path / "m", {}, lambda p: {}, (tmp_path / "modules",)
    )


def test_a_name_belongs_to_the_longest_module_id():
    ids = {"external", "external-collector"}
    assert mr._owner("external_collector_edge", ids, "_") == "external-collector"
    assert mr._owner("external_edge", ids, "_") == "external"
    assert mr._owner("other_edge", ids, "_") is None


# ------------------------------------------------------------- agents act only through the broker
def _load(path):
    import yaml

    return yaml.safe_load(Path(path).read_text())


def _collector(tmp_path):
    """A copy of the external-collector example module (its manifest, files and directory)."""
    import shutil

    mod = tmp_path / "external-collector"
    shutil.copytree(ROOT / "examples/modules/external-collector", mod)
    return _load(mod / "module.yml"), mod


def _write(path, doc):
    import yaml

    Path(path).write_text(yaml.safe_dump(doc, sort_keys=False))


def test_the_example_modules_act_only_through_the_broker():
    for manifest in sorted((ROOT / "examples/modules").glob("*/module.yml")):
        assert mr.broker_rule_problems(_load(manifest), manifest.parent, _load) == [], manifest


def test_a_module_contributes_no_acting_record_and_no_acts_via(tmp_path):
    """ADR-0030 for modules, under ADR-0027 (contributes, never authority): a contributed MCP
    record has no acting tool and declares no acts_via, broker or direct. The review's repro:
    an exec tool labelled acts_via: broker and listed for the module's own agent."""
    doc, mod = _collector(tmp_path)
    probe = mod / "mcp/external-collector-probe.yml"
    rec = _load(probe)
    rec["tools"].append({"name": "run_command", "classes": ["exec"], "approval": True})
    for via in ({}, {"acts_via": "broker"}, {"acts_via": "direct", "direct_reason": "why"}):
        _write(probe, {**rec, **via})
        got = mr.broker_rule_problems(doc, mod, _load)
        assert any("run_command act: a module contributes no authority" in p for p in got), got
        if via:
            assert any("declares acts_via" in p for p in got), got
    agent = doc["contributes"]["agents"][0]
    agent["tools"].append("external-collector-probe.run_command")
    spec_path = mod / agent["spec"]
    spec = _load(spec_path)
    _write(spec_path, {**spec, "mcp": ["external-collector-probe"]})
    _write(probe, {**rec, "acts_via": "broker"})
    got = "\n".join(mr.broker_rule_problems(doc, mod, _load))
    assert "tool external-collector-probe.run_command acts" in got
    assert "grants the module's acting MCP record external-collector-probe" in got
    probs = mr.module_problems(doc, mod, {}, _load, (tmp_path,))
    assert any("a module contributes no authority" in p for p in probs)
    # a record with no acting tool and no acts_via passes (the shipped probe)
    _write(
        probe, _load(ROOT / "examples/modules/external-collector/mcp/external-collector-probe.yml")
    )
    _write(spec_path, spec)
    agent["tools"].remove("external-collector-probe.run_command")
    assert mr.broker_rule_problems(doc, mod, _load) == []


def test_a_module_record_cannot_declare_an_acting_tool_down(tmp_path):
    """VERIFY1: the same record with run_command classed read passed both module rules, because
    "acting" was only what the record declared. Its classes are floored as the catalog's are."""
    doc, mod = _collector(tmp_path)
    probe = mod / "mcp/external-collector-probe.yml"
    rec = _load(probe)
    rec["tools"].append({"name": "run_command", "classes": ["read"], "approval": False})
    _write(probe, rec)
    needle = "tool run_command acts by its name"
    assert any(needle in p for p in mr.broker_rule_problems(doc, mod, _load))
    assert any(needle in p for p in mr.module_problems(doc, mod, {}, _load, (tmp_path,)))


def test_a_module_agent_holds_no_acting_grant(tmp_path):
    doc, mod = _collector(tmp_path)
    agent = doc["contributes"]["agents"][0]
    spec_path = mod / agent["spec"]
    spec = _load(spec_path)
    _write(spec_path, {**spec, "mcp": ["shell"], "capabilities": [*spec["capabilities"],
                                                                   "cap:hypervisor"],
                       "tier": "privileged"})  # fmt: skip
    got = "\n".join(mr.broker_rule_problems(doc, mod, _load))
    assert "agent external-collector-analyst: profile:external-collector-analyst" in got
    for needle in ("'shell' (exec)", "'cap:hypervisor' (exec)", "tier 'privileged'"):
        assert needle in got, needle
    # even the broker: a module grants its own agent no acting tool, capability or tier
    _write(spec_path, {**spec, "mcp": ["hnx-broker"], "capabilities": [*spec["capabilities"],
                                                                        "cap:broker"],
                       "tier": "execute"})  # fmt: skip
    got = "\n".join(mr.broker_rule_problems(doc, mod, _load))
    for needle in ("acting MCP server 'hnx-broker'", "holds cap:broker", "an acting tier"):
        assert needle in got, needle
