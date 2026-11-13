# SPDX-License-Identifier: Apache-2.0
"""Incumbent slots (ADR-0027 decision 9; docs/modules/selection.md, "Incumbents"): a selection may
declare a slot served outside modules, by a core role or a lab's existing service, naming the core
registry row that serves it.  An incumbent counts as selected for a required core slot and for a
module that requires the slot; it must name a real slot and the primary registry row of that
slot's capability, and a slot answered both by a module provider and an incumbent is refused.  A
selection that names neither is the same error as before.  Each rule is shown refusing a planted
defect."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from homelabnext.modules import rules as mr
from homelabnext.modules.providers import ProviderLookupError, provider_for
from homelabnext.registry.model import loads as load_registry

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "modules"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "selection.incumbents.yml"
SLOTS = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
ROLES = json.loads((ROOT / "examples" / "model_roles.json").read_text())["roles"]
REGISTRY = ld.load_yaml(ROOT / "examples" / "services.yml")
CORE, _ = ld.core_names(REGISTRY)
REQUIRED = sorted(s for s, d in SLOTS.items() if d.get("required_in_core"))


@pytest.fixture(scope="module")
def tree():
    tree, found = ld.discover(fixtures=EXAMPLES)
    assert found == []
    return tree


@pytest.fixture(scope="module")
def ins(tree):
    return ld.inputs(tree)


def fixture() -> dict:
    return ld.load_yaml(FIXTURE)


def problems(site, tree, ins, *, mods=None, rows=None, registry=CORE.rows, non_primary=()):
    return mr.site_problems(
        site, tree.mods if mods is None else mods, SLOTS,
        rows=ins.rows if rows is None else rows, units=ins.units,
        privileged_units=ins.privileged_units, roles=ROLES, registry=registry,
        non_primary=frozenset(non_primary),
    )  # fmt: skip


# ----------------------------------------------------------------------------- the fixture passes


def test_the_fixture_selection_passes_every_site_rule(tree, ins):
    site = fixture()
    assert set(site["incumbents"]) & set(REQUIRED) == set(site["incumbents"])
    assert not set(site["incumbents"]) & set(site["slots"])
    assert problems(site, tree, ins) == []


def test_the_fixture_selection_passes_the_loader_and_the_cli(tree, capsys):
    report = ld.check(
        tree, slots=SLOTS, roles=ROLES, in_tree_roots=(EXAMPLES,), core=CORE, site=fixture()
    )
    assert report.problems == []
    code = mcli.main(["check", "--root", str(ROOT), "--examples", "--site", str(FIXTURE)])
    out = capsys.readouterr().out
    assert code == 0, out
    assert out.rstrip().endswith("0 problem(s)")


def test_a_module_that_requires_an_incumbent_slot_is_served_by_it(tree, ins):
    """example-object-store requires cap:secrets; no module provides it in the fixture."""
    site = fixture()
    needs = {r["cap"] for r in tree.mods["example-object-store"]["requires"]["capabilities"]}
    assert "cap:secrets" in needs and "secrets" not in site["slots"]
    assert not [p for p in problems(site, tree, ins) if "cap:secrets" in p]


# ----------------------------------------------------------------------------- naming neither


def test_a_selection_that_names_neither_is_the_same_error_as_before(tree, ins):
    site = fixture()
    del site["incumbents"]
    got = problems(site, tree, ins)
    for slot in ("secrets", "idp", "dns", "events", "inference"):
        assert f"{slot}: a required core slot has no provider" in got
    assert "example-object-store: requires cap:secrets, which the site does not select" in got


# ----------------------------------------------------------------------------- planted defects


def _both(site):
    site["slots"]["secrets"] = [{"provider": "example-platform", "instance": "platform"}]


DEFECTS = {
    "an unknown slot": (
        lambda s: s["incumbents"].__setitem__("no-such-slot", {"service": "dns", "why": "x"}),
        "incumbents.no-such-slot: no such slot in the slot registry",
    ),
    "an unknown service": (
        lambda s: s["incumbents"]["secrets"].__setitem__("service", "vault-core"),
        "incumbents.secrets: service vault-core is not a row of the core registry",
    ),
    "a service of another capability": (
        lambda s: s["incumbents"]["secrets"].__setitem__("service", "idp"),
        "incumbents.secrets: service idp provides idp, not secrets",
    ),
    "a service of a near-miss capability": (
        lambda s: (
            s["slots"].pop("edge"),
            s["incumbents"].__setitem__(
                "edge", {"service": "edge-proxy", "why": "the lab's reverse proxy"}
            ),
        ),
        "incumbents.edge: service edge-proxy provides edge-proxy, not edge",
    ),
    "a module provider and an incumbent": (
        _both,
        "incumbents.secrets: the slot is also selected under slots (a module provider): one "
        "answer per slot",
    ),
    "none and an incumbent": (
        lambda s: s["slots"].__setitem__("idp", "none"),
        "incumbents.idp: the slot is also selected under slots (none): one answer per slot",
    ),
    "pass-through and an incumbent": (
        lambda s: s["slots"].__setitem__("dns", "pass-through"),
        "incumbents.dns: the slot is also selected under slots (pass-through): one answer per slot",
    ),
}


@pytest.mark.parametrize("name", sorted(DEFECTS))
def test_each_planted_incumbent_defect_is_refused(tree, ins, name):
    mutate, want = DEFECTS[name]
    site = fixture()
    mutate(site)
    assert want in problems(site, tree, ins)


def test_a_non_primary_row_is_never_an_incumbent(tree, ins):
    """An eval, retiring or legacy row serves no consumer (ADR-0039 decision 2)."""
    got = problems(fixture(), tree, ins, non_primary={"secrets"})
    assert got == [
        "incumbents.secrets: service secrets is not its capability's primary (an eval, "
        "retiring or legacy row serves no consumer)"
    ]


def test_without_a_registry_an_incumbent_is_never_taken_on_trust(tree, ins):
    got = problems(fixture(), tree, ins, registry=None)
    assert sorted(p for p in got if p.startswith("incumbents.")) == [
        f"incumbents.{s}: service {s} cannot be checked: no core registry was read"
        for s in ("dns", "events", "idp", "inference", "secrets")
    ]
    # the loader passes no registry when it read none
    report = ld.check(
        tree, slots=SLOTS, roles=ROLES, in_tree_roots=(EXAMPLES,), core=ld.CoreNames(),
        site=fixture(),
    )  # fmt: skip
    assert (
        "site: incumbents.secrets: service secrets cannot be checked: no core registry was read"
        in [str(p) for p in report.problems]
    )


def test_the_core_registry_names_its_non_primary_rows():
    reg = copy.deepcopy(REGISTRY)
    reg["services"]["secrets-next"] = {
        **reg["services"]["secrets"],
        "standing": {"tier": "eval", "until": "2099-01-01", "why": "a candidate"},
    }
    reg["services"]["idp"]["standing"] = {"tier": "primary"}
    reg["services"]["dns"]["standing"] = "eval"  # malformed: never read as primary
    core, _ = ld.core_names(reg)
    assert core.rows_known and core.non_primary == {"secrets-next", "dns"}
    assert not ld.core_names(None)[0].rows_known


def test_a_required_instance_of_an_incumbent_slot_is_its_registry_row(tree, ins):
    mods = copy.deepcopy(tree.mods)
    need = next(
        r
        for r in mods["example-object-store"]["requires"]["capabilities"]
        if r["cap"] == "cap:secrets"
    )
    need["instance"] = "secrets"
    assert problems(fixture(), tree, ins, mods=mods) == []
    need["instance"] = "platform"
    assert (
        "example-object-store: requires instance platform of cap:secrets, which is served "
        "outside modules by secrets"
    ) in problems(fixture(), tree, ins, mods=mods)


def test_an_upstream_to_an_incumbent_authority_slot_still_needs_its_grant(tree, ins):
    """idp is a granted upstream: an incumbent idp reached by a module's row needs
    grants.upstreams exactly as a module-provided one does."""
    rows = copy.deepcopy(ins.rows)
    rows["external-collector"] = {
        **rows.get("external-collector", {}),
        "collector-console": {"capability": "collector-console", "upstreams": ["idp"]},
    }
    site = fixture()
    assert (
        "external-collector: service collector-console upstream idp reaches idp without "
        "grants.upstreams"
    ) in problems(site, tree, ins, rows=rows)
    site["grants"]["upstreams"] = {"external-collector": ["cap:idp"]}
    assert not [p for p in problems(site, tree, ins, rows=rows) if "upstream" in p]


def test_an_incumbent_is_never_an_egress_target(tree, ins):
    """Neither its slot nor its row is a service a module's egress may name: the egress render
    cannot place an incumbent, so the check refuses what the render could not open."""
    mods = copy.deepcopy(tree.mods)
    for target in ("svc:secrets", "svc:idp"):
        mods["publishing"]["egress"] = [{"host": "publisher", "to": [target], "purpose": "x"}]
        site = fixture()
        site["features"]["publishing"] = {"placement": {"publisher": "core"}}
        site["grants"]["egress"]["publishing"] = {"publisher": [target]}
        got = problems(site, tree, ins, mods=mods)
        assert f"publishing: host publisher egresses to {target}, which is no service" in got


# ----------------------------------------------------------------------------- consumers


def test_provider_for_says_an_incumbent_slot_is_served_outside_modules(tree):
    with pytest.raises(ProviderLookupError, match="served outside modules by registry row secrets"):
        provider_for(fixture(), tree.mods, "cap:secrets")
    with pytest.raises(ProviderLookupError, match="does not name this slot"):
        provider_for(fixture(), tree.mods, "cap:cases")


def test_hnx_modules_providers_lists_the_incumbents(capsys):
    argv = ["providers", "--root", str(ROOT), "--examples", "--site", str(FIXTURE)]
    assert mcli.main([*argv, "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["incumbents"] == {s: s for s in ("dns", "events", "idp", "inference", "secrets")}
    assert mcli.main(argv) == 0
    assert "secrets: incumbent (registry row secrets, outside modules)" in capsys.readouterr().out


# ----------------------------------------------------------------------------- at deploy time


#: the core slots the example registry has no row of the same capability for
MISSING_ROWS = ("agent-runtime", "backup", "broker", "edge", "records")
#: a row is named by the lab, not by its slot: the example's orchestration row is "orchestrator"
ROW_OF = {s: "orchestrator" if s == "orchestration" else s for s in REQUIRED}


def _deploy_overlay(tmp_path: Path) -> Path:
    """A lab that takes up modules one at a time and so far selects none: every required core
    slot is an incumbent, each a row of the lab's own registry."""
    lab = tmp_path / "overlay" / "lab"
    (lab / "mcp").mkdir(parents=True)
    (lab / "keyring").mkdir()
    (lab / "keyring" / "keyring.json").write_text('{"principals": []}')
    shutil.copy(ROOT / "examples" / "model_roles.json", lab / "model_roles.json")
    reg = copy.deepcopy(REGISTRY)
    for i, cap in enumerate(MISSING_ROWS):
        reg["services"][cap] = {
            **copy.deepcopy(reg["services"]["secrets"]),
            "capability": cap,
            "impl": f"incumbent-{cap}",
            "port": 9100 + i,
            "health": {"kind": "tcp"},
            "tags": ["core"],
        }
    text = yaml.safe_dump(reg, sort_keys=False)
    load_registry(text)  # a valid registry, not just a mapping the loader reads
    (lab / "services.yml").write_text(text)
    site = {
        "profile": "incumbents-only",
        "hosts": {},
        "slots": {},
        "incumbents": {s: {"service": ROW_OF[s], "why": f"the lab's own {s}"} for s in REQUIRED},
    }
    (lab / "modules.yml").write_text(yaml.safe_dump(site, sort_keys=False))
    return lab.parent


def _deploy(capsys, ov: Path) -> tuple[int, dict]:
    code = mcli.main(["check", "--root", str(ROOT), "--overlay", str(ov), "--deploy", "--json"])
    return code, json.loads(capsys.readouterr().out)


def test_a_lab_whose_core_slots_are_all_incumbents_passes_the_deploy_check(tmp_path, capsys):
    ov = _deploy_overlay(tmp_path)
    code, doc = _deploy(capsys, ov)
    assert (code, doc["problems"]) == (0, [])
    # the same lab without one incumbent: exactly today's error, for that slot alone
    lab = ov / "lab"
    site = yaml.safe_load((lab / "modules.yml").read_text())
    del site["incumbents"]["notify"]
    (lab / "modules.yml").write_text(yaml.safe_dump(site))
    code, doc = _deploy(capsys, ov)
    assert (code, doc["problems"]) == (1, ["site: notify: a required core slot has no provider"])


def test_the_deploy_check_judges_incumbents_against_the_lab_s_registry(tmp_path, capsys):
    ov = _deploy_overlay(tmp_path)
    lab = ov / "lab"
    reg = yaml.safe_load((lab / "services.yml").read_text())
    del reg["services"]["broker"]
    (lab / "services.yml").write_text(yaml.safe_dump(reg, sort_keys=False))
    code, doc = _deploy(capsys, ov)
    assert (code, doc["problems"]) == (
        1,
        ["site: incumbents.broker: service broker is not a row of the core registry"],
    )
