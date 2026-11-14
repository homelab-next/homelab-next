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


def _code_problems(tmp_path, *files):
    tmp_path.mkdir(exist_ok=True)
    doc, mod = _collector(tmp_path)
    for f in files:
        (mod / f).parent.mkdir(parents=True, exist_ok=True)
        (mod / f).write_text("")
    return [p for p in mr.module_problems(doc, mod, {}, _load, (tmp_path,)) if "python/" in p]


def test_a_module_code_tree_holding_only_its_own_package_passes(tmp_path):
    assert _code_problems(tmp_path / "a") == []  # no python/ at all
    assert _code_problems(tmp_path / "b", "python/hnx_modules/external_collector/probe.py") == []


@pytest.mark.parametrize(
    ("planted", "needle"),
    [
        ("python/hnx_modules/core_staff/__init__.py", "python/hnx_modules/core_staff"),
        ("python/hnx_modules/__init__.py", "it would end the namespace package"),
        ("python/homelabnext/__init__.py", "python/homelabnext: the code tree holds only"),
        ("python/sitecustomize.py", "python/sitecustomize.py: the code tree holds only"),
    ],
)
def test_a_module_shipping_code_that_is_not_its_own_is_refused(tmp_path, planted, needle):
    """Another module's package, the core, a top-level module or a namespace-ending
    ``__init__.py`` would shadow code that is not the module's once ``python/`` is importable."""
    probs = _code_problems(tmp_path, "python/hnx_modules/external_collector/probe.py", planted)
    assert any(needle in p for p in probs), probs


def test_a_symlink_in_a_module_code_tree_is_refused(tmp_path):
    doc, mod = _collector(tmp_path)
    pkg = mod / "python/hnx_modules/external_collector"
    pkg.mkdir(parents=True)
    (pkg / "probe.py").symlink_to(ROOT / "homelabnext/__init__.py")
    probs = mr.module_problems(doc, mod, {}, _load, (tmp_path,))
    assert any("a symlink in the module's code tree" in p for p in probs), probs


def test_a_requirement_names_only_the_module_s_own_host_roles(tmp_path):
    doc, mod = _collector(tmp_path)
    doc["requires"]["capabilities"][0]["hosts"] = ["receiver", "no-such-role"]
    probs = mr.module_problems(doc, mod, {}, _load, (tmp_path,))
    assert any("hosts: no-such-role is not one of the module's host roles" in p for p in probs)
    assert not any("hosts: receiver" in p for p in probs)


@pytest.mark.parametrize(
    ("adapter", "refused"),
    [
        ("conformance.fakes.agent_runner_launcher:make", False),
        ("vendor.launcher:make", True),  # a provider certifying its own launcher
    ],
)
def test_an_agent_runtime_providers_target_runs_under_the_reference_launcher(adapter, refused):
    """ADR-0051 decision 13: a runtime provider supplies its body and exit_classes; its target
    always runs them under the reference launcher (later the controller's runner/agent)."""
    import yaml

    root = Path(__file__).resolve().parents[2]
    mod = root / "examples" / "modules" / "example-agent-runtime"
    doc = yaml.safe_load((mod / "module.yml").read_text())
    target = {"name": "t", "capabilities": {"agent-runner": {"adapter": adapter}}}
    slots = yaml.safe_load((root / "examples" / "modules" / "slots.yml").read_text())["slots"]
    probs = [
        p
        for p in mr.module_problems(doc, mod, slots, lambda p: target, (mod.parent,))
        if "reference launcher" in p
    ]
    assert bool(probs) is refused, probs
