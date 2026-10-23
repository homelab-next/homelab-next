# SPDX-License-Identifier: Apache-2.0
"""platform/module 1.0 (ADR-0025, docs/modules.md): the feature and provider module manifest.

Contract tests only; there is no loader yet. They prove the schema's own rules (each negative in
``schemas/platform/negative/module.*`` fails for the reason its name gives), that the example
modules in ``examples/modules/`` validate, that the records they contribute are files of the
existing record types and validate against those types, and that the example site selection only
names modules, slots, host roles and config keys the examples declare, satisfies every hard
requirement, and fits each host's memory less headroom (the lab-in-a-box budget rule).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
SCHEMA_PATH = ROOT / "schemas/platform/module.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text())
FROZEN = json.loads((ROOT / "schemas/_frozen/1.0/platform/module.schema.json").read_text())
MODULES_DIR = ROOT / "examples/modules"
MANIFESTS = sorted(MODULES_DIR.glob("*/module.yml"))
MODULES = {p.parent.name: yaml.safe_load(p.read_text()) for p in MANIFESTS}
SITES = {
    p.stem: yaml.safe_load(p.read_text()) for p in sorted((MODULES_DIR / "sites").glob("*.yml"))
}

# A negative's file name says which rule it breaks; the first error must be about that place.
NEGATIVES = {
    "agent-product-tool": "contributes/agents/0/tools/3",
    "agent-unknown-lane": "contributes/agents/0/prompts",
    "agent-without-charter": "contributes/agents/0",
    "feature-fills-a-slot": "provides",
    "feature-with-credentials": "$",
    "feature-with-product": "$",
    "file-escapes-module": "contributes/services/0/file",
    "lake-table-without-freshness": "contributes/lake_tables/0",
    "prefers-without-fallback": "prefers/capabilities/0",
    "host-without-footprint": "requires/hosts/0",
    "owned-data-native-format": "data/0/export/format",
    "owned-data-without-export": "data/0",
    "owned-data-without-retention": "data/0",
    "provider-conformance-and-provisional": "provides/0",
    "provider-in-bundle": "$",
    "provider-with-lanes": "$",
    "provider-without-licence": "$",
    "provider-without-product": "$",
    "provider-without-slot": "provides/0",
    "provisional-without-reason": "provides/0",
    "remove-without-audit": "lifecycle/remove",
    "requires-bare-capability": "requires/capabilities/0",
    "requires-product-not-slot": "requires/capabilities/0/cap",
    "retired-without-reason": "$",
    "config-literal-value": "config/batch_signing/default",
    "string-config-hides-reference": "config/edge_region/default",
    "subscription-without-expiry": "licence",
    "unknown-contribution": "contributes",
}

#: contributed files whose record type has a schema, and that schema
RECORD_SCHEMAS = {
    "mcp_servers": "schemas/platform/mcp_server.schema.json",
}
#: code and playbooks are named by the draft's examples but not shipped (there is no loader or
#: runtime yet); every declarative record they name is shipped and checked below
NOT_SHIPPED_PREFIXES = ("roles/", "playbooks/")


def _load(rel: str):
    return json.loads((ROOT / rel).read_text())


def test_version_is_1_0_and_frozen():
    assert SCHEMA["$id"].endswith("/platform/module/1.0")
    assert SCHEMA == FROZEN


def test_one_schema_both_kinds_strict():
    assert SCHEMA["properties"]["kind"]["enum"] == ["provider", "feature"]
    assert SCHEMA["additionalProperties"] is False
    for name, d in SCHEMA["$defs"].items():
        if d.get("type") == "object" and "properties" in d:
            assert d.get("additionalProperties") is False, name


@pytest.mark.parametrize("name", sorted(NEGATIVES))
def test_each_negative_fails_where_its_name_says(name):
    path = ROOT / f"schemas/platform/negative/module.{name}.yml"
    errors = sc.errors_for(SCHEMA, yaml.safe_load(path.read_text()), REG)
    assert errors, f"{name} was accepted"
    assert any(e.split(": ", 1)[0] == NEGATIVES[name] for e in errors), errors


def test_every_negative_file_is_listed():
    files = {p.stem.split(".", 1)[1] for p in (ROOT / "schemas/platform/negative").glob("module.*")}
    assert files == set(NEGATIVES)


@pytest.mark.parametrize("path", MANIFESTS, ids=lambda p: p.parent.name)
def test_example_modules_validate_and_id_is_the_directory(path):
    doc = yaml.safe_load(path.read_text())
    assert sc.errors_for(SCHEMA, doc, REG) == []
    assert doc["id"] == path.parent.name


def test_examples_cover_both_kinds_a_swap_and_a_provisional_slot():
    providers = [m for m in MODULES.values() if m["kind"] == "provider"]
    slots = [e["slot"] for p in providers for e in p["provides"]]
    assert any(m["kind"] == "feature" for m in MODULES.values())
    assert slots.count("cap:object-store") >= 2, "two providers for one slot show the swap"
    assert any(e.get("provisional") for p in providers for e in p["provides"])
    assert any(len(p["provides"]) > 1 for p in providers), "an all-in-one provider fills several"
    assert set(SITES) == {"single-box", "small-lab", "full"}


def _contributed_files(doc):
    for key, entries in doc.get("contributes", {}).items():
        for e in entries:
            if isinstance(e, dict):
                for field in ("file", "charter", "spec", "context_manifest", "sender"):
                    if field in e:
                        yield key, e[field]
                for f in e.get("prompts", {}).values():
                    yield "prompts", f
    if doc["kind"] == "feature":
        for i in doc.get("provides", {}).get("interfaces", []):
            if "schema" in i:
                yield "interfaces", i["schema"]
    else:
        for e in doc["provides"]:
            if "conformance" in e:
                yield "conformance", e["conformance"]["target"]


@pytest.mark.parametrize("name", sorted(MODULES))
def test_contributed_records_exist_in_the_module(name):
    missing = [
        f
        for _, f in _contributed_files(MODULES[name])
        if not f.startswith(NOT_SHIPPED_PREFIXES) and not (MODULES_DIR / name / f).is_file()
    ]
    assert missing == []


@pytest.mark.parametrize("name", sorted(MODULES))
def test_contributed_records_validate_against_their_record_type(name):
    root = MODULES_DIR / name
    doc = MODULES[name]
    for key, schema_rel in RECORD_SCHEMAS.items():
        for e in doc.get("contributes", {}).get(key, []):
            rec = yaml.safe_load((root / e["file"]).read_text())
            assert sc.errors_for(_load(schema_rel), rec, REG) == [], e["file"]
            assert rec["id"] == Path(e["file"]).stem
    row = {"$ref": _load("schemas/platform/service.json")["$id"] + "#/$defs/service"}
    host_roles = {h["role"] for h in doc["requires"].get("hosts", [])}
    declared_sources = set()
    for e in doc.get("contributes", {}).get("services", []):
        for svc, r in yaml.safe_load((root / e["file"]).read_text())["services"].items():
            assert sc.errors_for(row, r, REG) == [], svc
            assert r["host"] in host_roles, f"{svc}: host must be a module host role"
            declared_sources |= {"status:" + s["id"] for s in r.get("status_sources", [])}
    assert set(doc.get("contributes", {}).get("status_sources", [])) <= declared_sources
    template = _load("schemas/agent/prompt_template.schema.json")
    for agent in doc.get("contributes", {}).get("agents", []):
        assert set(agent["prompts"]) == {k for k in ("real", "shadow") if k in doc["lanes"]}
        for f in agent["prompts"].values():
            assert sc.errors_for(template, yaml.safe_load((root / f).read_text()), REG) == [], f
    for i in doc.get("provides", {}).get("interfaces", []) if doc["kind"] == "feature" else []:
        if "schema" in i:
            from jsonschema import Draft202012Validator

            Draft202012Validator.check_schema(json.loads((root / i["schema"]).read_text()))


@pytest.mark.parametrize("name", sorted(MODULES))
def test_data_exports_name_a_contributed_role(name):
    doc = MODULES[name]
    roles = {"role:" + Path(e["file"]).name for e in doc["contributes"].get("roles", [])}
    for ds in doc["data"]:
        assert {ds["export"]["via"], ds["import"]["via"]} <= roles, ds["id"]
    if doc["kind"] == "provider":
        formats = set()
        for e in doc["provides"]:
            assert {e["migration"]["export"], e["migration"]["import"]} <= roles
            formats.add(e["migration"]["format"])
        assert all(ds["export"]["format"] in formats for ds in doc["data"])


def test_required_interfaces_are_provided_by_some_example():
    offered = {
        (i["id"], i["version"])
        for m in MODULES.values()
        if m["kind"] == "feature"
        for i in m.get("provides", {}).get("interfaces", [])
    }
    for m in MODULES.values():
        wanted = m["requires"].get("interfaces", []) + m.get("prefers", {}).get("interfaces", [])
        for r in wanted:
            assert (r["interface"], r["version"]) in offered, (m["id"], r["interface"])


def test_only_publishing_requires_static_hosting():
    needs = [
        m["id"]
        for m in MODULES.values()
        if any(
            c["cap"] == "cap:static-hosting"
            for c in m["requires"].get("capabilities", [])
            + m.get("prefers", {}).get("capabilities", [])
        )
    ]
    assert needs == ["publishing"]


def _selected(site):
    """slot -> list of selections, or the string none / pass-through."""
    return site["slots"]


def _placements(site):
    """(module id, host role) -> site host, for every selected module that is in the examples."""
    out = {}
    for choice in _selected(site).values():
        if isinstance(choice, list):
            for c in choice:
                for role, host in c.get("placement", {}).items():
                    out[(c["provider"], role)] = host
    for name, sel in site["features"].items():
        for role, host in sel.get("placement", {}).items():
            out[(name, role)] = host
    return out


@pytest.mark.parametrize("profile", sorted(SITES))
def test_site_names_only_what_the_examples_declare(profile):
    site = SITES[profile]
    outside = set(site.get("outside_examples", []))
    for slot, choice in _selected(site).items():
        if choice in ("none", "pass-through"):
            continue
        instances = [c["instance"] for c in choice]
        assert len(instances) == len(set(instances)), slot
        for c in choice:
            if c["provider"] in outside:
                assert "placement" not in c, "an outside provider's footprint is not known here"
                continue
            mod = MODULES[c["provider"]]
            assert mod["kind"] == "provider"
            assert "cap:" + slot in {e["slot"] for e in mod["provides"]}, (slot, c["provider"])
            assert set(c.get("placement", {})) == {
                h["role"] for h in mod["requires"].get("hosts", [])
            }
    for name, sel in site["features"].items():
        mod = MODULES[name]
        assert mod["kind"] == "feature"
        assert set(sel.get("placement", {})) == {h["role"] for h in mod["requires"]["hosts"]}
        assert set(sel.get("config", {})) <= set(mod.get("config", {}))
    assert set(_placements(site).values()) <= set(site["hosts"])


@pytest.mark.parametrize("profile", sorted(SITES))
def test_site_satisfies_every_hard_requirement_and_every_fallback(profile):
    site = SITES[profile]
    sel = _selected(site)
    chosen = {"cap:" + s for s, c in sel.items() if isinstance(c, list)}
    selected = [MODULES[n] for n in site["features"]] + [
        MODULES[c["provider"]]
        for c in (c for v in sel.values() if isinstance(v, list) for c in v)
        if c["provider"] in MODULES
    ]
    for mod in selected:
        for req in mod["requires"].get("capabilities", []):
            assert req["cap"] in chosen, (profile, mod["id"], req["cap"])
        for pref in mod.get("prefers", {}).get("capabilities", []):
            to = pref["fallback"].get("to")
            if pref["cap"] not in chosen and to:
                assert to in chosen, (profile, mod["id"], pref["cap"], to)


@pytest.mark.parametrize("profile", sorted(SITES))
def test_none_and_pass_through_only_where_no_selected_module_needs_the_slot(profile):
    site = SITES[profile]
    empty = {"cap:" + s for s, c in _selected(site).items() if c in ("none", "pass-through")}
    for name in site["features"]:
        hard = {r["cap"] for r in MODULES[name]["requires"].get("capabilities", [])}
        assert not hard & empty, (profile, name, hard & empty)


def _fits(site):
    """The lab-in-a-box budget rule per host: placed footprints <= memory less headroom."""
    used: dict[str, int] = {}
    for (mod, role), host in _placements(site).items():
        fp = next(h for h in MODULES[mod]["requires"]["hosts"] if h["role"] == role)["footprint"]
        used[host] = used.get(host, 0) + fp["memory_mb"]
    for host, mb in used.items():
        h = site["hosts"][host]
        assert mb <= h["memory_mb"] - h["headroom_mb"], (host, mb)


@pytest.mark.parametrize("profile", sorted(SITES))
def test_site_footprints_fit_each_host(profile):
    _fits(SITES[profile])


def test_negative_an_overfull_host_is_refused():
    site = copy.deepcopy(SITES["single-box"])
    site["hosts"]["box"]["memory_mb"] = 4096
    with pytest.raises(AssertionError):
        _fits(site)


def test_feature_modules_carry_no_product_names():
    """The product-name lint's rule, on the examples: no provider's declared product name or alias
    occurs in a feature module's directory (comments included here, since the examples are new)."""
    names = set()
    for m in MODULES.values():
        if m["kind"] == "provider":
            p = m["product"]
            names |= {p["name"], p["display"].lower(), *p.get("aliases", [])}
    for name, m in MODULES.items():
        if m["kind"] != "feature":
            continue
        for f in (MODULES_DIR / name).rglob("*"):
            if f.is_file():
                text = f.read_text().lower()
                assert not [n for n in names if n in text], f
    for p in (MODULES_DIR / "sites").glob("*.yml"):
        text = p.read_text().lower()
        assert not [n for n in names if n in text], f"{p.name}: a site names provider modules"
