# SPDX-License-Identifier: Apache-2.0
"""platform/module 1.0, a DRAFT (ADR-0027, proposed; docs/modules.md): the module manifest.

Contract tests of the manifest and the rules (the loader itself, which runs them over discovered
manifests, is tested in ``tests/modules/test_module_loader.py``). They prove the schema's own rules (each negative in
``schemas/platform/negative/module.*`` fails where its name says), that every example module in
``examples/modules/`` validates and meets the loader rules (``homelabnext.modules.rules``: names bound to the
module, code and secrets in its own namespace, the slot registry's flags, owned interfaces), that
the records each contributes are files of existing record types and validate as such (MCP records,
service rows, prompt templates, lake tables, fleet_units specs, invariant criteria, agent specs
compiled against a ceiling policy, Sigma rules), and that the three site profiles satisfy every
requirement, grant, lane binding and footprint. Each loader rule is also shown refusing a planted
defect, so a rule that stopped working would fail here.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest
import schema_check as sc
import yaml

from homelabnext._yaml import UniqueKeyLoader
from homelabnext.modules import loader as ld
from homelabnext.modules import rules as mr
from homelabnext.modules import scope as ms
from homelabnext.schemas.module_manifest import NEVER_SHARED

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
SCHEMA_PATH = ROOT / "schemas/platform/module.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text())
LAKE_TABLE = json.loads((ROOT / "schemas/platform/lake_table.schema.json").read_text())
MODULES_DIR = ROOT / "examples/modules"


def load(path) -> dict:
    return yaml.load(Path(path).read_text(), Loader=UniqueKeyLoader)


MANIFESTS = sorted(MODULES_DIR.glob("*/module.yml"))
MODULES = {p.parent.name: load(p) for p in MANIFESTS}
SLOTS = load(MODULES_DIR / "slots.yml")["slots"]
SITES = {p.stem: load(p) for p in sorted((MODULES_DIR / "sites").glob("*.yml"))}
DIRS = {n: MODULES_DIR / n for n in MODULES}
#: the fictional examples count as in-tree only because the tests say so: the rules' default
#: public root is modules/ alone, so a loader copying the default never makes them available
ROOTS = (MODULES_DIR,)
#: the site rules' inputs, built the loader's way from the manifests' contributed files
_INPUTS = ld.inputs(ld.Tree(MODULES, DIRS, dict.fromkeys(MODULES, "fixture")))
ROWS, UNITS, ROOT_UNITS = _INPUTS.rows, _INPUTS.units, _INPUTS.privileged_units
MODEL_ROLES = json.loads((ROOT / "examples/model_roles.json").read_text())["roles"]


def site_problems(site, mods=None, *, rows=None, units=None, privileged=None, roles=None):
    """mr.site_problems with the example fixtures for every input not given (the rules take all
    of them, so none is skipped)."""
    return mr.site_problems(
        site, MODULES if mods is None else mods, SLOTS,
        rows=ROWS if rows is None else rows, units=UNITS if units is None else units,
        privileged_units=ROOT_UNITS if privileged is None else privileged,
        roles=MODEL_ROLES if roles is None else roles,
    )  # fmt: skip


SELECTION = json.loads((ROOT / "schemas/platform/module_selection.schema.json").read_text())

# A negative's file name says which rule it breaks; an error must be at that place.
NEGATIVES = {
    "adapter-any-callable": "provides/slots/object-store/adapter",
    "agent-ceiling": "contributes/agents/0",
    "agent-needs-an-authority-slot": "contributes/agents/0/needs/2/cap",
    "agent-tool-not-slot-named": "contributes/agents/0/tools/3",
    "agent-schedule-and-trigger": "contributes/agents/0",
    "agent-scope-everything": "contributes/agents/0/needs/0/scope/0",
    "agent-staff-code": "contributes/agents/0/roster",
    "agent-unknown-lane": "contributes/agents/0/prompts",
    "agent-without-charter": "contributes/agents/0",
    "agent-without-lanes": "contributes/agents/0",
    "config-credential-named-string": "config/admin_password/type",
    "config-enum-default-object": "config/mode/default",
    "config-literal-value": "config/batch_signing/default",
    "config-path-absolute": "config/data_dir/default",
    "config-path-traversal": "config/data_dir/default",
    "control-plane-reader-builtin": "control_plane/0/reader",
    "core-fetched": "origin/kind",
    "core-removable": "lifecycle",
    "core-retired": "status",
    "core-with-product": "$",
    "credential-without-holder": "credentials/0",
    "dataset-prefix-dot": "data/1/prefix",
    "dataset-tlp-unknown": "data/0/tlp",
    "dataset-tlp-not-canonical": "data/0/tlp",
    "dataset-honour-not-boolean": "data/0/honour_item_labels",
    "dataset-honour-without-tlp": "data/0",
    "egress-anywhere": "egress",
    "entry-point-any-callable": "contributes/entry_points/0/object",
    "entry-point-unknown-group": "contributes/entry_points/0/group",
    "feature-fills-a-slot": "provides",
    "feature-with-core-prefix": "id",
    "feature-with-credentials": "$",
    "feature-with-product": "$",
    "file-dot": "contributes/docs/1/file",
    "file-dot-git": "contributes/docs/1/file",
    "file-empty-segment": "contributes/docs/1/file",
    "fallback-data-without-to": "prefers/capabilities/2/fallback",
    "file-escapes-module": "contributes/services/0/file",
    "host-without-footprint": "requires/hosts/0",
    "hosts-without-lifecycle": "$",
    "interface-schema-not-json": "interfaces/0/schema",
    "interface-without-via": "provides/interfaces/0",
    "lake-table-dataset-without-table": "data/0",
    "lane-writes-dot": "contributes/agents/0/lanes/real/writes/2",
    "licence-kind-none": "licence/kind",
    "origin-git-dot-segments": "origin",
    "origin-git-unpinned": "origin",
    "owned-data-native-format": "data/0/export/formats/0",
    "owned-data-without-export": "data/0",
    "owned-data-without-retention": "data/0",
    "prefers-without-fallback": "prefers/capabilities/0",
    "provider-conformance-and-provisional": "provides/slots/object-store",
    "provider-in-bundle": "$",
    "provider-without-licence": "$",
    "provider-without-product": "$",
    "provider-without-slot": "provides",
    "provisional-requirement-with-version": "requires/capabilities/3",
    "provisional-without-reason": "provides/slots/static-hosting",
    "remove-discards-without-reason": "lifecycle/remove",
    "remove-without-audit": "lifecycle/remove",
    "requirement-without-version": "requires/capabilities/0",
    "requires-bare-capability": "requires/capabilities/0",
    "requires-product-not-slot": "requires/capabilities/0/cap",
    "requires-scope-unknown-part": "requires/scope/0/part",
    "reserved-id": "id",
    "retired-without-reason": "$",
    "reviews-inside-the-module": "$",
    "shadow-suffix-id": "id",
    "shared-config-into-a-trust-root": "contributes/shared_config/0/target",
    "slot-dataset-without-via": "data/0",
    "string-config-address-literal": "config/bind/default",
    "string-config-hides-reference": "config/edge_region/default",
    "string-config-hides-reference-uppercase": "config/edge_region/default",
    "string-config-other-scheme": "config/edge_region/default",
    "subscription-without-expiry": "licence",
    "tooling-contribution": "contributes",
    "unknown-contribution": "contributes",
    "without-author": "$",
    "without-manifest-version": "$",
}

#: code and playbooks are named by the examples but not shipped (no loader or runtime yet)
NOT_SHIPPED_PREFIXES = ("roles/", "playbooks/")


# ------------------------------------------------------------------ the schema itself
def test_a_draft_1_0_with_its_own_version_field():
    assert SCHEMA["$id"].endswith("/platform/module/1.0")
    assert sc.is_draft(SCHEMA) and "ADR-0027" in SCHEMA["x-draft"]
    assert not (ROOT / "schemas/_frozen/1.0/platform/module.schema.json").exists()
    assert SCHEMA["properties"]["manifest_version"]["const"] == "1.0"
    assert "manifest_version" in SCHEMA["required"]


def test_one_schema_three_kinds_strict():
    assert SCHEMA["properties"]["kind"]["enum"] == ["provider", "feature", "core"]
    assert SCHEMA["additionalProperties"] is False
    for name, d in SCHEMA["$defs"].items():
        if d.get("type") == "object" and "properties" in d:
            assert d.get("additionalProperties") is False, name


def test_defaults_keep_the_common_case_short():
    """upgrade defaults to install, exposure to internal, production to real, display to name,
    egress to none; purpose is optional except on a soft dependency."""
    d = SCHEMA["$defs"]
    assert d["lifecycle"]["required"] == ["install"]
    assert d["requirement_host"]["properties"]["exposure"]["default"] == "internal"
    assert d["requirement_host"]["required"] == ["role", "kind", "footprint"]
    assert d["lanes"]["properties"]["production"]["default"] == "real"
    assert d["lanes"]["required"] == ["real"]
    assert d["product"]["required"] == ["name", "version"]
    assert d["egress"]["default"] == "none"
    for name in ("requirement_capability", "requirement_model_role", "requirement_interface"):
        assert "purpose" not in d[name]["required"], name
    for name in ("preference_capability", "preference_interface"):
        assert "purpose" in d[name]["required"], name
    lean = copy.deepcopy(MODULES["example-inference"])
    assert "egress" not in lean and "upgrade" not in lean["lifecycle"]
    lean["product"].pop("display")
    lean["requires"]["hosts"][0].pop("purpose")
    assert sc.errors_for(SCHEMA, lean, REG) == []


def test_deferred_fields_are_gone():
    """tooling, inline reviews, lanes at module level and staff codes left the 1.0 draft."""
    contributes = SCHEMA["$defs"]["contributes"]["properties"]
    assert "tooling" not in contributes and "reviews" not in SCHEMA["properties"]
    assert "lanes" not in SCHEMA["properties"]
    assert "code" not in SCHEMA["$defs"]["agent"]["properties"]["roster"]["properties"]
    assert SCHEMA["$defs"]["entry_point"]["properties"]["group"]["enum"] == [
        "homelabnext.invariants.checks"
    ]


EVENT_IDS = sorted(
    json.loads(p.read_text())["$id"]
    for p in (ROOT / "schemas/events").glob("*.schema.json")
    if p.stem != "envelope.schema"
)


@pytest.mark.parametrize(
    "schema_id", [*EVENT_IDS, "https://schemas.example.internal/homelabnext/ids/logical-id/1.0"]
)
def test_schema_id_accepts_every_shipped_event_schema(schema_id):
    """The draft's pattern rejected every event $id (they contain dots); an event interface can
    now name its schema."""
    doc = copy.deepcopy(MODULES["external-collector"])
    doc["prefers"]["capabilities"][0]["formats"][0]["schema_id"] = schema_id
    doc.setdefault("interfaces", []).append(
        {
            "id": "case-feed",
            "version": "1.0",
            "kind": "event",
            "schema_id": schema_id,
            "description": "an event interface",
        }
    )
    assert sc.errors_for(SCHEMA, doc, REG) == []


def test_sixteen_event_schemas_were_checked():
    assert len(EVENT_IDS) == 16 and all("." in i.rsplit("/", 2)[1] for i in EVENT_IDS)


@pytest.mark.parametrize("name", sorted(NEGATIVES))
def test_each_negative_fails_where_its_name_says(name):
    path = ROOT / f"schemas/platform/negative/module.{name}.yml"
    errors = sc.errors_for(SCHEMA, sc.load_instance(path), REG)
    assert errors, f"{name} was accepted"
    assert any(e.split(": ", 1)[0] == NEGATIVES[name] for e in errors), errors


@pytest.mark.parametrize("target", NEVER_SHARED)
def test_no_module_merges_config_into_a_never_shared_component(target):
    """Every never-shared component, the Code Mode sandbox among them (a merged key could widen
    its egress or environment), is refused as a shared_config target."""
    path = ROOT / "schemas/platform/negative/module.shared-config-into-a-trust-root.yml"
    doc = sc.load_instance(path)
    doc["contributes"]["shared_config"][0]["target"] = target
    errors = sc.errors_for(SCHEMA, doc, REG)
    assert any(e.startswith("contributes/shared_config/0/target: ") for e in errors), errors


def test_the_code_mode_sandbox_is_never_shared():
    assert "cap:codemode-executor" in NEVER_SHARED


def test_every_negative_file_is_listed():
    files = {p.stem.split(".", 1)[1] for p in (ROOT / "schemas/platform/negative").glob("module.*")}
    assert files == set(NEGATIVES)


# ------------------------------------------------------------------ examples and loader rules
@pytest.mark.parametrize("path", MANIFESTS, ids=lambda p: p.parent.name)
def test_example_modules_validate(path):
    assert sc.errors_for(SCHEMA, load(path), REG) == []


@pytest.mark.parametrize("name", sorted(MODULES))
def test_example_modules_meet_the_loader_rules(name):
    assert mr.module_problems(MODULES[name], MODULES_DIR / name, SLOTS, load, ROOTS) == []


def test_the_examples_meet_the_rules_across_modules():
    assert mr.tree_problems(MODULES, DIRS, load) == []


def test_examples_cover_every_kind_a_swap_a_provisional_slot_and_an_event_agent():
    kinds = {m["kind"] for m in MODULES.values()}
    providers = [m for m in MODULES.values() if m["kind"] == "provider"]
    slots = [s for p in providers for s in p["provides"]["slots"]]
    assert kinds == {"provider", "feature", "core"}
    assert slots.count("object-store") >= 2, "two providers for one slot show the swap"
    assert any(e.get("provisional") for p in providers for e in p["provides"]["slots"].values())
    assert any(len(p["provides"]["slots"]) > 1 for p in providers)
    agents = [a for m in MODULES.values() for a in m.get("contributes", {}).get("agents", [])]
    assert any("trigger" in a for a in agents) and any("schedule" in a for a in agents)
    assert set(SITES) == {"single-box", "small-lab", "full"}


def test_every_slot_the_examples_name_is_in_the_slot_registry():
    named = set()
    for m in MODULES.values():
        named |= {r["cap"] for r in m["requires"].get("capabilities", [])}
        for p in m.get("prefers", {}).get("capabilities", []):
            named |= {p["cap"], p["fallback"].get("to", p["cap"])}
        named |= {"cap:" + s for s in m.get("provides", {}).get("slots", {})}
    assert {c.removeprefix("cap:") for c in named} <= set(SLOTS)


#: a slot registry entry is platform/slot 1.0, a draft (docs/modules.md, "The slot registry"): the
#: schema holds the registry's rules, so the draft data cannot drift from them
SLOT_SCHEMA = {"$ref": "https://schemas.example.internal/homelabnext/platform/slot/1.0"}
#: the trust roots docs/modules.md names: never provisional, always a conformance run and the
#: human review tier, so dropping the flag from one must fail here, not pass silently
PRIVILEGED = {"secrets", "idp", "edge", "broker", "orchestration", "records"}


@pytest.mark.parametrize("slot", sorted(SLOTS))
def test_a_slot_is_a_registry_entry_and_its_contract_is_a_real_protocol(slot):
    d = SLOTS[slot]
    assert sc.errors_for(SLOT_SCHEMA, d, REG) == []
    if d["contract"] is not None:
        assert (ROOT / "conformance/protocols" / d["contract"]).is_file()


def test_the_privileged_slots_are_the_documented_trust_roots_and_each_has_a_suite():
    from homelabnext.conform.registry import CAPABILITIES, EXTENDED

    assert {s for s, d in SLOTS.items() if d.get("privileged")} == PRIVILEGED
    assert set(CAPABILITIES) | set(EXTENDED) >= PRIVILEGED


@pytest.mark.parametrize(
    ("edit", "where"),
    [
        (lambda d: d.update(privileged=True, contract=None), "contract"),
        (lambda d: d.pop("export_formats"), "$"),
        (lambda d: d.update(stateful=False), "stateful"),
        (lambda d: d.update(pass_through=True, required_in_core=True), "required_in_core"),
        (lambda d: d.update(layer=4), "$"),
        (lambda d: d.pop("stage"), "$"),
    ],
)
def test_the_slot_schema_refuses_a_registry_entry_that_breaks_a_rule(edit, where):
    d = copy.deepcopy(SLOTS["secrets"])
    edit(d)
    errs = sc.errors_for(SLOT_SCHEMA, d, REG)
    assert errs and any(str(e).startswith(where) for e in errs), errs


_contributed_files = ld.contributed_files


@pytest.mark.parametrize("name", sorted(MODULES))
def test_contributed_records_exist_in_the_module_and_are_regular_files(name):
    root = MODULES_DIR / name
    for _, f in _contributed_files(MODULES[name]):
        if f.startswith(NOT_SHIPPED_PREFIXES):
            continue
        p = root / f
        assert p.is_file() and not p.is_symlink(), f
        assert p.resolve().is_relative_to(root.resolve()), f


@pytest.mark.parametrize("name", sorted(MODULES))
def test_contributed_records_validate_against_their_record_type(name):
    root, doc = MODULES_DIR / name, MODULES[name]
    c = doc.get("contributes", {})
    mcp = json.loads((ROOT / "schemas/platform/mcp_server.schema.json").read_text())
    for e in c.get("mcp_servers", []):
        rec = load(root / e["file"])
        assert sc.errors_for(mcp, rec, REG) == [], e["file"]
        assert rec["id"] == Path(e["file"]).stem
    row = {
        "$ref": json.loads((ROOT / "schemas/platform/service.json").read_text())["$id"]
        + "#/$defs/service"
    }
    for e in c.get("services", []):
        for svc, r in load(root / e["file"])["services"].items():
            if doc["kind"] == "provider":
                assert "version" not in r, "a provider's row takes its version from product.version"
                r = {**r, "version": str(doc["product"]["version"])}
            assert sc.errors_for(row, r, REG) == [], svc
    template = json.loads((ROOT / "schemas/agent/prompt_template.schema.json").read_text())
    for agent in c.get("agents", []):
        for f in agent["prompts"].values():
            assert sc.errors_for(template, load(root / f), REG) == [], f
    for e in c.get("lake_tables", []):
        rec = load(root / e["file"])
        assert sc.errors_for(LAKE_TABLE, rec, REG) == [], e["file"]
        assert rec["owner"] == name
    from jsonschema import Draft202012Validator

    for i in doc.get("interfaces", []):
        if "schema" in i:
            s = json.loads((root / i["schema"]).read_text())
            Draft202012Validator.check_schema(s)
            assert f"/modules/{name}/" in s["$id"], "the owning module's namespace"


@pytest.mark.parametrize(
    "name", sorted(n for n, m in MODULES.items() if m.get("contributes", {}).get("detections"))
)
def test_contributed_sigma_rules_load(name):
    from homelabnext.detections.sigma import load_rule

    for e in MODULES[name]["contributes"]["detections"]:
        rule = load_rule(MODULES_DIR / name / e["file"])
        assert any(t.startswith("attack.t") for t in rule.tags)


def _policy_and_library(spec):
    from homelabnext.agent.compiler import CeilingPolicy, PartsLibrary
    from homelabnext.ids import MappingResolver

    ids = [spec["persona"], *spec.get("capabilities", []), *spec.get("skills", [])]
    library = PartsLibrary(
        MappingResolver("module-examples", {i: i for i in ids}), lambda loc: f"part {loc}"
    )
    ceiling = {
        spec["id"]: {
            "mcp": [],
            "capabilities": spec["capabilities"],
            "tier": "read",
            "data_tier": spec["data_tier"],
            "model_role": spec["model_role"],
        }
    }
    return CeilingPolicy(ceiling, "the overlay's ceiling policy (fictional)"), library


AGENTS = [
    (n, a) for n, m in sorted(MODULES.items()) for a in m.get("contributes", {}).get("agents", [])
]


@pytest.mark.parametrize(("name", "agent"), AGENTS, ids=[a["key"] for _, a in AGENTS])
def test_agent_specs_compile_only_against_a_ceiling_policy(name, agent):
    from homelabnext.agent.compiler import compile_profile
    from homelabnext.agent.errors import AgentError

    spec = load(MODULES_DIR / name / agent["spec"])
    policy, library = _policy_and_library(spec)
    profile = compile_profile(spec, library, policy=policy)
    assert profile["id"] == agent["profile"]
    with pytest.raises(AgentError):
        compile_profile(
            spec, library
        )  # no policy: a module spec has no ceiling of its own to fall back on


# ------------------------------------------------------------------ loader rules refuse defects
def _rules(name, mutate):
    doc = copy.deepcopy(MODULES[name])
    mutate(doc)
    return mr.module_problems(doc, MODULES_DIR / name, SLOTS, load, ROOTS)


def _ag(d):
    return d["contributes"]["agents"][0]


MODULE_DEFECTS = {
    "a gate interface its owner does not consume": (
        "publishing",
        lambda d: d["prefers"].__setitem__("interfaces", []),
        "interface publishable-output: a gate interface; its owner requires or prefers it with gate: true",
    ),
    "a gate interface its owner consumes without the gate marker": (
        "publishing",
        lambda d: d["prefers"]["interfaces"][0].pop("gate"),
        "interface publishable-output: a gate interface; its owner requires or prefers it with gate: true",
    ),
    "a gate interface its owner consumes with gate: false": (
        "publishing",
        lambda d: d["prefers"]["interfaces"][0].__setitem__("gate", False),
        "interface publishable-output: a gate interface; its owner requires or prefers it with gate: true",
    ),
    "a gate interface defined by its producer": (
        "publishing",
        lambda d: d.setdefault("provides", {}).__setitem__(
            "interfaces",
            [
                {
                    "interface": "publishable-output",
                    "version": "1.0",
                    "via": {"cap": "cap:object-store", "prefix": "publishing/out/"},
                }
            ],
        ),
        "interface publishable-output: a gate interface its owner also provides",
    ),
    "a gate on an interface the module does not own": (
        "external-collector",
        lambda d: (
            d.setdefault("prefers", {})
            .setdefault("interfaces", [])
            .append(
                {
                    "interface": "publishable-output",
                    "version": "1.0",
                    "gate": True,
                    "purpose": "x",
                    "fallback": {"behaviour": "x"},
                }
            )
        ),
        "interface publishable-output: consumed with gate: true but not defined here",
    ),
    "a gate on an interface whose definition is not a gate": (
        "publishing",
        lambda d: d["interfaces"][0].pop("gate"),
        "interface publishable-output 1.0: consumed with gate: true, so its definition says gate: true",
    ),
    "a core module that owns a gate it does not consume": (
        "publishing",
        lambda d: (d.__setitem__("kind", "core"), d["prefers"].__setitem__("interfaces", [])),
        "interface publishable-output: a gate interface; its owner requires or prefers it with gate: true",
    ),
    "a module reading addresses without exclude.offensive": (
        "external-collector",
        lambda d: d["requires"].__setitem__("scope", [{"part": "trusted.wan"}]),
        "requires.scope: trusted.wan without exclude.offensive",
    ),
    "an unattended module reading addresses without exclude.unattended_mutation": (
        "external-collector",
        lambda d: d["requires"].__setitem__(
            "scope", [{"part": "target"}, {"part": "exclude.offensive"}]
        ),
        "requires.scope: target without exclude.unattended_mutation",
    ),
    "another profile's id (ceiling takeover)": (
        "external-collector",
        lambda d: _ag(d).__setitem__("profile", "profile:staff-validator"),
        "profile is profile:",
    ),
    "an agent key outside the module": (
        "external-collector",
        lambda d: _ag(d).__setitem__("key", "staff-validator"),
        "key starts with",
    ),
    "provisional on a contracted slot": (
        "example-object-store",
        lambda d: d["provides"]["slots"]["object-store"].update(provisional=True),
        "provisional on a slot that has a contract",
    ),
    "a privileged slot filled provisionally": (
        "example-static-host",
        lambda d: d["provides"]["slots"].__setitem__(
            "secrets",
            {
                "adapter": "hnx_modules.example_static_host.s:make",
                "provisional": True,
                "reason": "x",
            },
        ),
        "provisional on a slot that has a contract",
    ),
    "a requirement provisional on a contracted slot": (
        "external-collector",
        lambda d: d["requires"]["capabilities"][0].update(provisional=True),
        "has a contract",
    ),
    "a typo is not a new slot": (
        "external-collector",
        lambda d: d["requires"]["capabilities"][0].__setitem__("cap", "cap:object-stor"),
        "no such slot",
    ),
    "a stateless slot with a fake migration": (
        "example-siem-suite",
        lambda d: d["provides"]["slots"]["notify"].__setitem__(
            "migration",
            {
                "formats": ["jsonl"],
                "export": "role:example_siem_suite",
                "import": "role:example_siem_suite",
            },
        ),
        "stateless slot carries no migration",
    ),
    "a stateful slot without one": (
        "example-object-store",
        lambda d: d["provides"]["slots"]["object-store"].pop("migration"),
        "stateful slot carries a migration",
    ),
    "an adapter in another module's package": (
        "example-object-store",
        lambda d: d["provides"]["slots"]["object-store"].__setitem__(
            "adapter", "hnx_modules.publishing.gate:run"
        ),
        "own code or a shared adapter",
    ),
    "an entry point in another module's package": (
        "external-collector",
        lambda d: d["contributes"]["entry_points"][0].__setitem__(
            "object", "hnx_modules.publishing.gate:run"
        ),
        "own package",
    ),
    "a secret in another module's namespace": (
        "external-collector",
        lambda d: d["config"]["batch_signing"].__setitem__(
            "default", "secret:publishing/deploy-token"
        ),
        "own namespace",
    ),
    "a credential in a shared namespace": (
        "example-object-store",
        lambda d: d["credentials"][0].__setitem__("secret", "secret:object-store/access-key"),
        "own namespace",
    ),
    "a table in the core's namespace": (
        "external-collector",
        lambda d: d["data"][0].__setitem__("table", "table:core.alerts"),
        "table namespace",
    ),
    "a data prefix in another module's": (
        "external-collector",
        lambda d: d["data"][1].__setitem__("prefix", "publishing/x/"),
        "prefix starts with",
    ),
    "a lane writing the whole records tree": (
        "external-collector",
        lambda d: _ag(d)["lanes"]["real"]["writes"].append("findings/"),
        "outside <root>/",
    ),
    "a write scope outside the module": (
        "external-collector",
        lambda d: _ag(d)["needs"][1].__setitem__("scope", ["findings/other/"]),
        "write scope",
    ),
    "another module's role timer": (
        "external-collector",
        lambda d: d["contributes"]["scheduler_jobs"].append({"timer": "timer:publishing_gate/run"}),
        "does not contribute",
    ),
    "replaced_by itself": (
        "external-collector",
        lambda d: d.update(status="deprecated", reason="x", replaced_by="external-collector"),
        "itself",
    ),
    "an enum default outside its values": (
        "external-collector",
        lambda d: d["config"]["mode"].__setitem__("default", "loud"),
        "enum default",
    ),
    "needs disagreeing with the spec": (
        "external-collector",
        lambda d: _ag(d)["needs"].pop(1),
        "exactly the spec's capabilities",
    ),
    "a trigger on an interface it does not consume": (
        "example-sandbox",
        lambda d: _ag(d).__setitem__("trigger", {"interface": "publishable-output"}),
        "does not consume",
    ),
    "egress from a host role it does not have": (
        "external-collector",
        lambda d: d["egress"].append({"host": "ghost", "to": ["svc:external-collector-receiver"]}),
        "egress host ghost",
    ),
    "a dataset via a cap it neither requires nor prefers": (
        "external-collector",
        lambda d: d["data"][1].__setitem__("via", {"cap": "cap:hot-index"}),
        "neither requires nor prefers",
    ),
    "a dataset via an instance it does not require": (
        "external-collector",
        lambda d: d["data"][1]["via"].__setitem__("instance", "objects"),
        "via instance objects",
    ),
    "a dataset via a cap without the instance it requires": (
        "external-collector",
        lambda d: d["data"][1]["via"].pop("instance"),
        "via names the instance it requires",
    ),
    "fallback data for a dataset that does not exist": (
        "external-collector",
        lambda d: d["prefers"]["capabilities"][0]["fallback"]["data"].append(
            {"dataset": "nope", "retention": {"days": 1}}
        ),
        "dataset nope does not exist",
    ),
    "fallback data for a dataset living in another slot": (
        "external-collector",
        lambda d: d["prefers"]["capabilities"][0]["fallback"]["data"].append(
            {"dataset": "samples", "retention": {"days": 1}}
        ),
        "dataset samples does not live in it",
    ),
    "fallback data formats outside the fallback slot's export formats": (
        "external-collector",
        lambda d: d["prefers"]["capabilities"][0]["fallback"]["data"][0].__setitem__(
            "formats", ["zone-file"]
        ),
        "export formats ['jsonl']",
    ),
    "the shadow lane writing where consumers read": (
        "external-collector",
        lambda d: _ag(d)["lanes"]["shadow"]["writes"].append("findings/external-collector/"),
        "lane shadow writes findings/external-collector/",
    ),
    "the real lane writing the shadow prefix": (
        "external-collector",
        lambda d: _ag(d)["lanes"]["real"]["writes"].append("findings/external-collector-shadow/"),
        "lane real writes findings/external-collector-shadow/",
    ),
    "a tool on a slot the agent does not need": (
        "external-collector",
        lambda d: _ag(d)["tools"].append("broker.execute"),
        "tool broker.execute",
    ),
    "a product-named tool": (
        "external-collector",
        lambda d: _ag(d)["tools"].append("northwind-objects.query"),
        "tool northwind-objects.query",
    ),
    "a fetched origin on a module in the public tree": (
        "external-collector",
        lambda d: d.__setitem__(
            "origin",
            {"kind": "git", "url": "https://git.example.internal/m/c", "commit": "a" * 64},
        ),
        "a module in the public modules/ tree is in-tree",
    ),
}


def test_a_loader_rule_refuses_the_defect(case):
    name, mutate, needle = MODULE_DEFECTS[case]
    assert any(needle in p for p in _rules(name, mutate)), _rules(name, mutate)


def test_spec_ceiling_and_unit_and_criterion_and_record_rules(tmp_path):
    """Rules on contributed files, with each file replaced by a broken copy."""
    import shutil

    mod = tmp_path / "external-collector"
    shutil.copytree(MODULES_DIR / "external-collector", mod)
    doc = copy.deepcopy(MODULES["external-collector"])
    spec = load(mod / _ag(doc)["spec"])
    (mod / _ag(doc)["spec"]).write_text(yaml.safe_dump({**spec, "ceiling": {"tier": "admin"}}))
    crit = load(mod / "invariants/criteria.yml")
    crit["criteria"][0]["id"] = "X-NEW"
    (mod / "invariants/criteria.yml").write_text(yaml.safe_dump(crit))
    det = load(mod / "detections/external-collector-credential-reuse.yml")
    (mod / "detections/external-collector-credential-reuse.yml").write_text(
        yaml.safe_dump({**det, "det": "det:ssh-authorized-key-added"})
    )
    mcp = load(mod / "mcp/external-collector-probe.yml")
    (mod / "mcp/external-collector-probe.yml").write_text(
        yaml.safe_dump({**mcp, "id": "probe", "capabilities": ["cap:external-collector"]})
    )
    rows = load(mod / "registry/services.yml")
    rows["services"]["external-collector-receiver"].update(
        public_hostname="collector.example.org", auth="none"
    )
    (mod / "registry/services.yml").write_text(yaml.safe_dump(rows))
    (mod / "units").mkdir()
    (mod / "units/fleet_units.yml").write_text(
        yaml.safe_dump(
            [
                {
                    "name": "freshness",
                    "description": "d",
                    "exec": "/usr/local/libexec/x",
                    "on_calendar": "*-*-* 01:00:00 UTC",
                    "user": "root",
                    "run_as_root": True,
                    "hardening_opt_out": ["ProtectHome"],
                    "pages_directly": True,
                }
            ]
        )
    )
    doc["contributes"]["scheduler_jobs"].append({"file": "units/fleet_units.yml"})
    probs = "\n".join(mr.module_problems(doc, mod, SLOTS, load, (tmp_path,)))
    for needle in (
        "carries no ceiling",
        "is external-collector/<slug>",
        "det id starts with",
        "MCP record id starts with",
        "only a provider's MCP record fronts a slot",
        "public route needs auth",
        "unit freshness: name starts with",
        "pages only through notify",
    ):
        assert needle in probs, needle


def test_row_status_sources_equal_the_listed_ones(tmp_path):
    """Negative: a status source declared only on a row (not in contributes.status_sources) is
    refused, and with directories it joins name ownership (so a longer module id's name is caught)."""
    import shutil

    mod = tmp_path / "external-collector"
    shutil.copytree(MODULES_DIR / "external-collector", mod)
    rows = load(mod / "registry/services.yml")
    src = copy.deepcopy(rows["services"]["external-collector-receiver"]["status_sources"][0])
    src["id"] = "external-collector-sub-fresh"
    rows["services"]["external-collector-receiver"]["status_sources"].append(src)
    (mod / "registry/services.yml").write_text(yaml.safe_dump(rows))
    probs = mr.module_problems(MODULES["external-collector"], mod, SLOTS, load, (tmp_path,))
    assert (
        "status:external-collector-sub-fresh: declared on a service row but not listed in "
        "contributes.status_sources" in probs
    )
    mods = copy.deepcopy(MODULES)
    mods["external-collector-sub"] = {
        **copy.deepcopy(MODULES["core-modules"]),
        "id": "external-collector-sub",
        "kind": "feature",
        "contributes": {},
    }
    probs = mr.tree_problems(mods, {**DIRS, "external-collector": mod}, load)
    assert (
        "status source external-collector-sub-fresh: named under module external-collector-sub, "
        "not external-collector" in probs
    )


def test_contributed_row_rules(tmp_path):
    """Service rows: an upstream is never secrets, and is a slot the module uses or an instance it
    requires."""
    import shutil

    mod = tmp_path / "external-collector"
    shutil.copytree(MODULES_DIR / "external-collector", mod)
    rows = load(mod / "registry/services.yml")
    rows["services"]["external-collector-receiver"]["upstreams"] += ["secrets", "cases"]
    (mod / "registry/services.yml").write_text(yaml.safe_dump(rows))
    probs = "\n".join(
        mr.module_problems(MODULES["external-collector"], mod, SLOTS, load, (tmp_path,))
    )
    assert "upstream secrets: secrets are read by name" in probs
    assert "upstream cases is neither a slot it requires or prefers" in probs


def test_interface_schema_is_the_owners_json_schema(tmp_path):
    import shutil

    mod = tmp_path / "publishing"
    shutil.copytree(MODULES_DIR / "publishing", mod)
    f = mod / "interfaces/publishable-item.schema.json"
    s = json.loads(f.read_text())
    s["$id"] = s["$id"].replace("/modules/publishing/", "/modules/external-collector/")
    f.write_text(json.dumps(s))
    probs = mr.module_problems(MODULES["publishing"], mod, SLOTS, load, (tmp_path,))
    assert any("schema $id is in .../modules/publishing/" in p for p in probs), probs


def test_origin_and_kind_core_are_bound_to_where_the_module_lives(tmp_path):
    """Negative: a module copied out of the public tree (an overlay or a download) cannot call
    itself in-tree, and a core module lives only in the public tree, so a third party's manifest
    never becomes core (and auto-selected) by declaring it."""
    import shutil

    for name in ("external-collector", "core-staff"):
        shutil.copytree(MODULES_DIR / name, tmp_path / name)
    probs = mr.module_problems(
        MODULES["external-collector"], tmp_path / "external-collector", SLOTS, load
    )
    assert "origin in-tree: the module is not in the public modules/ tree" in probs
    probs = mr.module_problems(MODULES["core-staff"], tmp_path / "core-staff", SLOTS, load)
    assert "kind core: a core module lives in the public modules/ tree" in probs
    fetched = copy.deepcopy(MODULES["external-collector"])
    fetched["origin"] = {
        "kind": "git",
        "url": "https://git.example.internal/m/c",
        "commit": "b" * 64,
    }
    assert sc.errors_for(SCHEMA, fetched, REG) == [], "a sha256-format commit pins a module"
    assert mr.module_problems(fetched, tmp_path / "external-collector", SLOTS, load) == []


def test_the_examples_are_not_in_tree_by_default():
    """Negative: with the default public root (modules/ only) the fictional examples are not
    in-tree, and core-staff is not a core module a site could select."""
    assert mr.public_module_roots() == (ROOT / "modules",)
    probs = mr.module_problems(MODULES["core-staff"], MODULES_DIR / "core-staff", SLOTS, load)
    assert "kind core: a core module lives in the public modules/ tree" in probs
    assert "origin in-tree: the module is not in the public modules/ tree" in probs


def test_cross_module_rules_refuse_two_owners_overlap_and_shared_ids():
    mods = copy.deepcopy(MODULES)
    mods["external-collector"]["interfaces"] = [copy.deepcopy(mods["publishing"]["interfaces"][0])]
    mods["example-sandbox"]["data"].append(
        {**mods["external-collector"]["data"][1], "id": "steal", "prefix": "external-collector/"}
    )
    mods["publishing"]["contributes"]["agents"] = [
        copy.deepcopy(mods["external-collector"]["contributes"]["agents"][0])
    ]
    probs = "\n".join(mr.tree_problems(mods))
    assert "one owner per id" in probs
    assert "contains external-collector/samples/" in probs
    assert "external-collector-analyst: claimed by" in probs


def test_interface_ownership_is_per_id_not_per_version():
    """Negative: a producer cannot define the next version of a consumer's interface."""
    mods = copy.deepcopy(MODULES)
    nxt = copy.deepcopy(mods["publishing"]["interfaces"][0])
    nxt["version"] = "1.1"
    mods["external-collector"]["interfaces"] = [nxt]
    probs = mr.tree_problems(mods)
    assert any("publishable-output: defined by" in p and "one owner per id" in p for p in probs)


def test_a_name_belongs_to_the_longest_module_id_it_is_named_under():
    """Negative: module `external` cannot claim `external-collector`'s roles, agent keys or MCP
    ids just because `external_` is a prefix of them."""
    mods = copy.deepcopy(MODULES)
    mods["external"] = {
        **copy.deepcopy(MODULES["core-modules"]),
        "id": "external",
        "kind": "feature",
        "contributes": {"roles": [{"file": "roles/external_collector_edge"}]},
    }
    probs = mr.tree_problems(mods)
    assert (
        "role external_collector_edge: named under module external-collector, not external" in probs
    )


def test_names_in_contributed_files_are_compared_across_modules(tmp_path):
    """With the module directories, MCP ids, det ids, units and rows join the uniqueness check."""
    import shutil

    sandbox = tmp_path / "example-sandbox"
    shutil.copytree(MODULES_DIR / "example-sandbox", sandbox)
    (sandbox / "mcp").mkdir()
    shutil.copy(
        MODULES_DIR / "external-collector/mcp/external-collector-probe.yml", sandbox / "mcp"
    )
    mods = copy.deepcopy(MODULES)
    mods["example-sandbox"]["contributes"]["mcp_servers"] = [
        {"file": "mcp/external-collector-probe.yml"}
    ]
    probs = "\n".join(mr.tree_problems(mods, {**DIRS, "example-sandbox": sandbox}, load))
    assert "MCP record external-collector-probe: named under module external-collector" in probs
    assert "MCP record external-collector-probe: claimed by" in probs


def test_identifiers_and_write_prefixes_are_unique_across_modules():
    mods = copy.deepcopy(MODULES)
    mods["other-object-store"]["identifiers"] = [
        {"kind": "dns-name", "name": "siem", "on_remove": "keep"}
    ]
    _ag(mods["example-sandbox"])["lanes"]["real"]["writes"].append("findings/external-collector/x/")
    probs = "\n".join(mr.tree_problems(mods))
    assert "identifier dns-name/siem: claimed by example-siem-suite and other-object-store" in probs
    assert (
        "write prefix findings/external-collector/x/ (example-sandbox) overlaps "
        "findings/external-collector/ (external-collector)" in probs
    )


def test_a_gate_is_owned_by_the_module_that_gates_on_it():
    """Negative, across manifests: a producer cannot take over the interface a gate checks, by
    defining it with or without gate: true; the gate consumer must own it."""
    mods = copy.deepcopy(MODULES)
    taken = copy.deepcopy(mods["publishing"]["interfaces"][0])
    taken.pop("gate")
    mods["external-collector"]["interfaces"] = [taken]
    mods["publishing"]["interfaces"] = []
    probs = mr.tree_problems(mods)
    assert (
        "publishing: gates on interface publishable-output, which ['external-collector'] defines"
        in probs
    )
    mods["external-collector"]["interfaces"][0]["gate"] = True
    probs = mr.tree_problems(mods)
    assert (
        "publishing: gates on interface publishable-output, which ['external-collector'] defines"
        in probs
    )
    assert "external-collector: provides interface publishable-output, a gate it owns" in probs


def test_a_gate_whose_definition_is_not_a_gate_is_refused_across_manifests():
    mods = copy.deepcopy(MODULES)
    mods["publishing"]["interfaces"][0].pop("gate")
    assert (
        "publishing: gates on interface publishable-output, whose definition lacks gate: true"
        in mr.tree_problems(mods)
    )


def _two_versions(first_gate, second_gate):
    mods = copy.deepcopy(MODULES)
    v1 = mods["publishing"]["interfaces"][0]
    v2 = {**copy.deepcopy(v1), "version": "1.1"}
    for d, g in ((v1, first_gate), (v2, second_gate)):
        if g is None:
            d.pop("gate", None)
        else:
            d["gate"] = g
    mods["publishing"]["interfaces"].append(v2)
    return mods


@pytest.mark.parametrize("first,second", [(None, True), (True, None), (False, True), (True, False)])
def test_every_version_of_a_gate_interface_is_marked_whatever_the_order(first, second):
    """Negative: gate ownership is per id, every version; an unmarked version is refused in
    either order, by the module rules and across manifests."""
    mods = _two_versions(first, second)
    doc = mods["publishing"]
    probs = mr.module_problems(doc, MODULES_DIR / "publishing", SLOTS, load, ROOTS)
    bad = "1.0" if first is not True else "1.1"
    assert any(
        p.startswith(f"interface publishable-output {bad}: consumed with gate: true") for p in probs
    ), probs
    assert (
        "interface publishable-output: gate: true on some versions only; every version of a gate "
        "says it" in mr.tree_problems(mods)
    )


def test_an_unconsumed_version_mix_is_refused_too():
    mods = _two_versions(None, True)
    doc = mods["publishing"]
    doc["prefers"]["interfaces"][0].pop("gate")
    probs = mr.module_problems(doc, MODULES_DIR / "publishing", SLOTS, load, ROOTS)
    assert (
        "interface publishable-output 1.0: another version is a gate, so every version says "
        "gate: true" in probs
    )


def test_every_version_marked_is_accepted():
    mods = _two_versions(True, True)
    doc = mods["publishing"]
    probs = mr.module_problems(doc, MODULES_DIR / "publishing", SLOTS, load, ROOTS)
    assert not [p for p in probs if "gate" in p], probs
    assert not [p for p in mr.tree_problems(mods) if "gate" in p]


@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"requires": None, "prefers": {"interfaces": None}},
        {"requires": {"interfaces": ["x", {"gate": True}, {"interface": 5, "gate": True}]}},
        {"prefers": {"interfaces": [{"interface": "a", "gate": "yes"}]}},
        [],
    ],
)
def test_reading_gated_interfaces_tolerates_a_malformed_manifest(doc):
    assert mr._gated_interfaces(doc) == set()


def test_a_producer_may_own_and_provide_an_interface_that_is_not_a_gate():
    """Positive: without gate (or with gate: false) owning and providing is ordinary."""
    for gate in (None, False):
        doc = copy.deepcopy(MODULES["external-collector"])
        own = {
            "id": "collector-feed",
            "version": "1.0",
            "kind": "object-prefix",
            "schema_id": "https://homelab-next.invalid/schemas/platform/sidecar/1.0",
            "description": "x",
        }
        if gate is not None:
            own["gate"] = gate
        doc["interfaces"] = [own]
        doc["provides"]["interfaces"].append(
            {
                "interface": "collector-feed",
                "version": "1.0",
                "via": {
                    "cap": "cap:object-store",
                    "instance": "samples",
                    "prefix": "external-collector/feed/",
                },
            }
        )
        probs = mr.module_problems(doc, MODULES_DIR / "external-collector", SLOTS, load, ROOTS)
        assert not [p for p in probs if "collector-feed" in p], probs
        mods = {**copy.deepcopy(MODULES), "external-collector": doc}
        assert not [p for p in mr.tree_problems(mods) if "collector-feed" in p]


def test_an_interface_with_no_owner_is_refused():
    mods = copy.deepcopy(MODULES)
    del mods["publishing"]
    assert any("interface publishable-output 1.0 has no owner" in p for p in mr.tree_problems(mods))


# ------------------------------------------------------------------ site profiles
@pytest.mark.parametrize("profile", sorted(SITES))
def test_site_profile_meets_every_rule(profile):
    assert site_problems(SITES[profile]) == []


@pytest.mark.parametrize("profile", sorted(SITES))
def test_site_profile_validates_against_the_selection_schema(profile):
    assert sc.is_draft(SELECTION)
    assert sc.errors_for(SELECTION, SITES[profile], REG) == []


SELECTION_NEGATIVES = {
    "grants-misspelt": "$",
    "unknown-grant-kind": "grants",
    "choice-without-instance": "slots/notify",
    "lane-binding-without-real": "features/external-collector/agents/external-collector-analyst/lanes",
    "scope-empty-list": "scope/trusted/wan",
    "scope-malformed-cidr": "scope/target/0",
    "scope-unknown-part": "scope/trusted",
    "addresses-network": "hosts/data/addresses/0",
    "upstream-grant-not-authority": "grants/upstreams/publishing/0",
    "cloud-model-not-a-role": "grants/cloud_models/publishing/0",
    "lab-namespace-without-why": "lab_table_namespaces/0",
    "lab-namespace-not-a-name": "lab_table_namespaces/0/namespace",
    "tlp-reader-unknown-ceiling": "tlp_readers/0/ceiling",
    "tlp-reader-without-why": "tlp_readers/0",
    "tlp-reader-not-an-id": "tlp_readers/0/reader",
    "tlp-reader-write-not-boolean": "tlp_readers/2/write",
    "tlp-readers-without-catalog": "$",
}


#: scope entries -> (the schema accepts, the reader accepts).  The two agree on every entry's text
#: (one pattern, ENTRY_PATTERN); the reader alone refuses what a pattern cannot say.
D1, D2 = "192.0.2", "198.51.100"
SCOPE_ENTRIES = {
    f"{D1}.0/24": (True, True),
    f"{D2}.128/25": (True, True),
    "2001:db8:30::/48": (True, True),
    "2001:DB8::1": (True, True),
    # text: refused by both
    "2001:db8::1%eth0": (False, False),  # zone id
    f"::ffff:{D1}.0/120": (False, False),  # IPv4 written inside IPv6
    ":".join(("", "", "ffff", "c000", "200/120")): (False, False),  # IPv4-mapped, hex
    ":".join(("64", "ff9b", "", "c000", "201")): (False, False),  # NAT64
    ":".join(("0", "0", "0", "0", "0", "ffff", "c000", "201")): (False, False),  # mapped, long
    ":::::::": (False, False),
    "1::2::3": (False, False),
    f"{D1}.1/24": (False, False),  # IPv4 host bits
    f"{D1}.0/024": (False, False),  # leading zeros
    f" {D1}.0/24": (False, False),
    f"{D1}.0/24\n": (False, False),
    # meaning: the schema's pattern cannot say it, the reader refuses
    "2001:db8::1/64": (True, False),  # IPv6 host bits
    "0.0.0.0/0": (True, False),
    ".".join(("224", "0", "0", "0/4")): (True, False),  # multicast
    "fe80::/64": (True, False),
}


@pytest.mark.parametrize("entry", sorted(SCOPE_ENTRIES))
def test_the_schema_and_the_reader_agree_on_a_scope_entry(entry):
    """Negative and positive: the schema never accepts less than the reader, and refuses exactly
    the entry texts the reader refuses (the semantic rows are the reader's alone)."""
    site = copy.deepcopy(SITES["full"])
    site["scope"]["target"] = [entry]
    schema_ok = not any(e.startswith("scope/") for e in sc.errors_for(SELECTION, site, REG))
    try:
        ms.parse_entry(entry, "target")
        reader_ok = True
    except ValueError:
        reader_ok = False
    assert (schema_ok, reader_ok) == SCOPE_ENTRIES[entry]


@pytest.mark.parametrize("value", ["0.0.0.0", "::", ".".join("2104"), "cafe::beef", f"{D1}.10"])
def test_a_site_config_value_that_is_no_site_address_is_accepted(value):
    """S7: a bind address, a version, a label or a documentation address is not refused."""
    site = copy.deepcopy(SITES["single-box"])
    site["features"]["external-collector"]["config"]["edge_region"] = value
    assert site_problems(site) == []


def test_an_explicit_empty_exclusion_and_a_dynamic_wan_source_are_valid_shapes():
    """S3: "nothing excluded" is an explicit [] (absent still fails closed), and trusted.wan may
    name a dynamic source; the schema takes both, so freezing it later is not a breaking change.
    The rules accept the empty exclusion and refuse the dynamic source until a reader exists."""
    site = copy.deepcopy(SITES["full"])
    site["scope"]["exclude"] = {"offensive": [], "unattended_mutation": []}
    assert sc.errors_for(SELECTION, site, REG) == []
    assert site_problems(site) == []
    site["scope"]["trusted"]["wan"] = [{"source": "wan-dhcp"}]
    assert sc.errors_for(SELECTION, site, REG) == []
    assert any("specified, not implemented" in p for p in site_problems(site))
    site["scope"]["trusted"]["nets"] = [{"source": "wan-dhcp"}]  # only trusted.wan has the form
    assert any(e.startswith("scope/trusted/nets") for e in sc.errors_for(SELECTION, site, REG))


def test_the_selection_schema_scope_is_generated_from_the_parts():
    """The schema's scope leaves are exactly SCOPE_PARTS, as is the manifest's requires.scope
    enum: adding a part to one cannot leave the other behind."""
    scope = SELECTION["properties"]["scope"]["properties"]
    leaves = set()
    for group, d in scope.items():
        if d.get("type") == "object":
            leaves |= {f"{group}.{k}" for k in d["properties"]}
        else:
            leaves.add(group)
    assert leaves == set(ms.SCOPE_PARTS)
    enum = SCHEMA["$defs"]["requirement_scope"]["properties"]["part"]["enum"]
    assert enum == list(ms.SCOPE_PARTS)
    assert SELECTION["$defs"]["scope_entry"]["pattern"] == ms.ENTRY_PATTERN


def test_every_selection_negative_file_is_listed():
    found = (ROOT / "schemas/platform/negative").glob("module_selection.*")
    assert {p.stem.split(".", 1)[1] for p in found} == set(SELECTION_NEGATIVES)


@pytest.mark.parametrize("name", sorted(SELECTION_NEGATIVES))
def test_each_selection_negative_fails_where_its_name_says(name):
    path = ROOT / f"schemas/platform/negative/module_selection.{name}.yml"
    errors = sc.errors_for(SELECTION, sc.load_instance(path), REG)
    assert any(e.split(": ", 1)[0] == SELECTION_NEGATIVES[name] for e in errors), errors


def _site(profile, mutate):
    site = copy.deepcopy(SITES[profile])
    mods = copy.deepcopy(MODULES)
    mutate(site, mods)
    return "\n".join(site_problems(site, mods))


SITE_DEFECTS = {
    "a selected provider without a manifest": (
        "full",
        lambda s, m: s["slots"]["lake-query"].append(
            {"provider": "example-unknown", "instance": "q2"}
        ),
        "without a manifest",
    ),
    "a required core slot left out": (
        "single-box",
        lambda s, m: s["slots"].__setitem__("backup", "none"),
        "required core slot",
    ),
    "pass-through where it is not allowed": (
        "single-box",
        lambda s, m: s["slots"].__setitem__("cases", "pass-through"),
        "may not be pass-through",
    ),
    "pass-through whose neighbours do not meet": (
        "single-box",
        lambda s, m: m["example-siem-suite"]["provides"]["slots"]["siem-source"].__setitem__(
            "formats", [{"format": "cloudevents", "version": "1.0"}]
        ),
        "meets nothing",
    ),
    "a hard requirement unselected": (
        "small-lab",
        lambda s, m: s["slots"].__setitem__("object-store", "none"),
        "requires cap:object-store",
    ),
    "a required instance missing": (
        "full",
        lambda s, m: s["slots"]["object-store"][1].__setitem__("instance", "bulk"),
        "requires instance samples",
    ),
    "static hosting without the publish grant": (
        "full",
        lambda s, m: s["grants"].__setitem__("publish", []),
        "publish grant",
    ),
    "static hosting reached by a fallback": (
        "full",
        lambda s, m: (
            m["example-sandbox"]
            .setdefault("prefers", {})
            .setdefault("capabilities", [])
            .append(
                {
                    "cap": "cap:cases",
                    "version": "1.0",
                    "purpose": "p",
                    "fallback": {"to": "cap:static-hosting", "behaviour": "b"},
                }
            )
        ),
        "example-sandbox: reaches cap:static-hosting",
    ),
    "internet egress without a grant": (
        "full",
        lambda s, m: s["grants"].__setitem__("egress", {}),
        "without a grant",
    ),
    "a lane bound to no instance": (
        "single-box",
        lambda s, m: s["features"]["external-collector"]["agents"]["external-collector-analyst"][
            "lanes"
        ].pop("shadow"),
        "exactly one orchestration instance",
    ),
    "a lane bound to an unselected instance": (
        "single-box",
        lambda s, m: s["features"]["external-collector"]["agents"]["external-collector-analyst"][
            "lanes"
        ].__setitem__("shadow", "orchestrator"),
        "unselected instance",
    ),
    "a core agent without a lane binding": (
        "small-lab",
        lambda s, m: s.__setitem__("core", {}),
        "core-staff-scorecard",
    ),
    "a secret grant for a credential not granted": (
        "full",
        lambda s, m: s["grants"]["secrets"].__setitem__(
            "external-collector", ["secret:other-object-store/admin-token"]
        ),
        "may not read",
    ),
    "a dataset whose slot fell back without its data": (
        "single-box",
        lambda s, m: m["external-collector"]["prefers"]["capabilities"][0]["fallback"].pop("data"),
        "dataset sessions",
    ),
    "an interface on an instance it does not require": (
        "full",
        lambda s, m: m["external-collector"]["provides"]["interfaces"][0]["via"].__setitem__(
            "instance", "objects"
        ),
        "is not the one it requires",
    ),
    "an overfull host (memory)": (
        "single-box",
        lambda s, m: s["hosts"]["box"]["capacity"].__setitem__("memory_mb", 8192),
        "box: memory_mb",
    ),
    "an overfull host (cpu)": (
        "single-box",
        lambda s, m: s["hosts"]["box"]["capacity"].__setitem__("cpu", 4),
        "box: cpu",
    ),
    "an overfull host (disk)": (
        "single-box",
        lambda s, m: s["hosts"]["box"]["capacity"].__setitem__("disk_gb", 100),
        "box: disk_gb",
    ),
    "an overfull host (GPU memory)": (
        "single-box",
        lambda s, m: s["hosts"]["box"]["capacity"].__setitem__("gpu_memory_mb", 1024),
        "box: gpu_memory_mb",
    ),
    "two exclusive GPU users on one card": (
        "single-box",
        lambda s, m: m["example-siem-suite"]["requires"]["hosts"][0]["footprint"].__setitem__(
            "resources", [{"kind": "gpu", "exclusive": True}]
        ),
        "exclusive gpu",
    ),
    "an internal role on an external host": (
        "single-box",
        lambda s, m: s["features"]["external-collector"]["placement"].__setitem__(
            "receiver", "collector-edge"
        ),
        "external role",
    ),
    "an isolated role on a lab host": (
        "full",
        lambda s, m: s["features"]["example-sandbox"]["placement"].__setitem__(
            "detonation", "data-core"
        ),
        "isolated role",
    ),
    "a host role left unplaced": (
        "full",
        lambda s, m: s["features"]["publishing"].__setitem__("placement", {}),
        "every host role is placed",
    ),
}


def _host(role, **fp):
    return {
        "role": role,
        "kind": "any",
        "footprint": {"cpu": 0.1, "memory_mb": 16, "disk_gb": 0, **fp},
    }


SITE_DEFECTS.update(
    {
        "egress to an authority service without a grant": (
            "full",
            lambda s, m: m["external-collector"]["egress"].append(
                {"host": "receiver", "to": ["svc:secrets", "svc:broker"]}
            ),
            "host receiver egresses to svc:secrets without a grant",
        ),
        "an egress grant for a role that does not name the target": (
            "full",
            lambda s, m: m["external-collector"]["egress"][0]["to"].extend(
                ["internet", "svc:secrets"]
            ),
            "host edge egresses to internet without a grant",
        ),
        "an internet-facing role inside the lab without a grant": (
            "full",
            lambda s, m: m["external-collector"]["requires"]["hosts"][1].__setitem__(
                "exposure", "internet-facing"
            ),
            "host role receiver is internet-facing inside the lab without grants.internet_facing",
        ),
        "an external host role without an egress grant": (
            "full",
            lambda s, m: s["grants"]["egress"].pop("external-collector"),
            "host role edge is external",
        ),
        "a site config value naming another module's secret": (
            "full",
            lambda s, m: s["features"]["external-collector"]["config"].__setitem__(
                "batch_signing", "secret:example-static-host/deploy-token"
            ),
            "is not external-collector's own and not granted to it",
        ),
        "a site config key the module does not declare": (
            "single-box",
            lambda s, m: s["features"]["external-collector"]["config"].__setitem__("moed", "full"),
            "declares no such key",
        ),
        "a secret reference in a non-secret config key": (
            "single-box",
            lambda s, m: s["features"]["external-collector"]["config"].__setitem__(
                "edge_region", "secret:external-collector/ingest-token"
            ),
            "a secret reference in a non-secret key",
        ),
        "a lane binding for an agent the module does not have": (
            "full",
            lambda s, m: s["features"]["external-collector"]["agents"].__setitem__(
                "ghost-agent", {"lanes": {"real": "platform"}}
            ),
            "agents.ghost-agent: the module contributes no such agent",
        ),
        "a module bound under another kind's section": (
            "full",
            lambda s, m: s["core"].__setitem__("publishing", {}),
            "core.publishing: a feature module is bound under features",
        ),
        "a core module's host left unplaced": (
            "small-lab",
            lambda s, m: m["core-staff"]["requires"].__setitem__("hosts", [_host("scorer")]),
            "core-staff (core): every host role is placed",
        ),
        "a core module's footprint counted": (
            "single-box",
            lambda s, m: (
                m["core-staff"]["requires"].__setitem__(
                    "hosts", [_host("scorer", memory_mb=99999)]
                ),
                s["core"]["core-staff"].__setitem__("placement", {"scorer": "box"}),
            ),
            "box: memory_mb",
        ),
        "a shared user of a GPU held exclusively": (
            "full",
            lambda s, m: m["publishing"]["requires"]["hosts"][0]["footprint"].__setitem__(
                "resources", [{"kind": "gpu", "exclusive": False}]
            ),
            "every gpu is held exclusively",
        ),
        "a resource kind the host does not have": (
            "full",
            lambda s, m: m["publishing"]["requires"]["hosts"][0]["footprint"].__setitem__(
                "resources", [{"kind": "tpu", "exclusive": False}]
            ),
            "no tpu named",
        ),
        "a module requiring a scope part, with no scope block": (
            "single-box",
            lambda s, m: s.pop("scope"),
            "external-collector: requires scope.trusted.wan, which the site leaves missing",
        ),
        "a module requiring a scope part the block leaves out": (
            "full",
            lambda s, m: s["scope"]["trusted"].pop("wan"),
            "external-collector: requires scope.trusted.wan",
        ),
        "an empty scope part (its reader fails closed)": (
            "full",
            lambda s, m: s["scope"]["trusted"].__setitem__("wan", []),
            "scope.trusted.wan: empty",
        ),
        "a malformed CIDR in the scope": (
            "full",
            lambda s, m: s["scope"]["target"].__setitem__(0, f"{D2}.0/33"),
            f"scope.target[0]: '{D2}.0/33' is not a usable address or network",
        ),
        "a scope network with host bits set": (
            "full",
            lambda s, m: s["scope"]["exclude"]["offensive"].__setitem__(0, f"{D1}.1/28"),
            "has host bits set",
        ),
        "a dynamic WAN source (specified, not implemented)": (
            "full",
            lambda s, m: s["scope"]["trusted"].__setitem__("wan", [{"source": "wan-dhcp"}]),
            "dynamic WAN sources are specified, not implemented",
        ),
        "an empty trusted part (only an exclusion may be [])": (
            "full",
            lambda s, m: s["scope"]["trusted"].__setitem__("nets", []),
            "scope.trusted.nets: empty (only an exclusion may be an explicit [])",
        ),
        "a scope network listed twice": (
            "small-lab",
            lambda s, m: s["scope"]["trusted"]["tooling"].append(f"{D1}.200/32"),
            "scope.trusted.tooling: a network is listed twice",
        ),
        "an address literal as a site config value": (
            "single-box",
            lambda s, m: s["features"]["external-collector"]["config"].__setitem__(
                "edge_region", ".".join(("10", "20", "0", "1"))
            ),
            "edge_region: an address literal (" + ".".join(("10", "20", "0", "1")) + "): a lab "
            "address belongs in the selection's scope block",
        ),
        "a zero-padded address as a site config value": (
            "single-box",
            lambda s, m: s["features"]["external-collector"]["config"].__setitem__(
                "edge_region", "010.020.000.001"
            ),
            "edge_region: an address literal (010.020.000.001)",
        ),
        "count multiplies the footprint": (
            "single-box",
            lambda s, m: m["external-collector"]["requires"]["hosts"][1].__setitem__("count", 16),
            "box: cpu",
        ),
        # ADR-0033 decision 9: green is not public
        "green publishing without an audience": (
            "full",
            lambda s, m: (
                s["features"]["publishing"]
                .setdefault("config", {})
                .update(tlp_allowed="green", access_control="the community's sign-in")
            ),
            "features.publishing.config.tlp_allowed: green is not public (ADR-0033 decision 9): "
            "it needs audience: community (not 'public')",
        ),
        "green publishing without an access control": (
            "full",
            lambda s, m: (
                s["features"]["publishing"]
                .setdefault("config", {})
                .update(tlp_allowed="green", audience="community", access_control="  ")
            ),
            "it needs access_control naming what restricts it to that community",
        ),
        "amber publishing, even for a named community": (
            "full",
            lambda s, m: (
                m["publishing"]["config"]["tlp_allowed"]["values"].append("amber"),
                s["features"]["publishing"]
                .setdefault("config", {})
                .update(
                    tlp_allowed="amber",
                    audience="community",
                    access_control="the partner community's sign-in",
                ),
            ),
            "features.publishing.config.tlp_allowed: amber is never published (ADR-0033 "
            "decision 9): the most a publication may carry is green",
        ),
        "green publishing with a placeholder access control": (
            "full",
            lambda s, m: (
                s["features"]["publishing"]
                .setdefault("config", {})
                .update(tlp_allowed="green", audience="community", access_control="N/A")
            ),
            "it needs access_control naming what restricts it to that community",
        ),
        "a manifest whose default publishes green without either": (
            "full",
            lambda s, m: m["publishing"]["config"]["tlp_allowed"].__setitem__("default", "green"),
            "it needs audience: community (not 'public') and access_control",
        ),
    }
)


def test_green_publishing_with_a_community_and_its_access_control_is_accepted():
    """Both declared, by the selection (or by the manifest's defaults), and green passes."""
    site, mods = copy.deepcopy(SITES["full"]), copy.deepcopy(MODULES)
    site["features"]["publishing"]["config"] = {
        "tlp_allowed": "green",
        "audience": "community",
        "access_control": "the partner community's sign-in on the static host",
    }
    assert site_problems(site, mods) == []
    site["features"]["publishing"]["config"] = {"tlp_allowed": "clear", "audience": "public"}
    assert site_problems(site, mods) == []


def test_a_site_rule_refuses_the_defect(case):
    """Parametrised by pytest_generate_tests from the final SITE_DEFECTS, so an entry added
    anywhere in this module is collected."""
    profile, mutate, needle = SITE_DEFECTS[case]
    assert needle in _site(profile, mutate)


def test_a_provider_agent_is_bound_under_providers():
    """A provider may contribute an agent; its lanes are bound under providers.<id>, not core."""
    site, mods = copy.deepcopy(SITES["full"]), copy.deepcopy(MODULES)
    a = copy.deepcopy(_ag(mods["external-collector"]))
    a.update(key="example-lake-curator", profile="profile:example-lake-curator")
    a["lanes"] = {"real": {"writes": ["findings/example-lake/"]}}
    mods["example-lake"]["contributes"]["agents"] = [a]
    probs = "\n".join(site_problems(site, mods))
    assert "example-lake-curator: each lane is bound to exactly one orchestration instance" in probs
    site["providers"] = {
        "example-lake": {"agents": {"example-lake-curator": {"lanes": {"real": "platform"}}}}
    }
    # the copied agent reads the lake, so the site gives it a ceiling (ADR-0033 decision 6)
    site["tlp_readers"].append(
        {"reader": "profile:example-lake-curator", "ceiling": "red", "why": "the lake's curator"}
    )
    assert site_problems(site, mods) == []
    assert sc.errors_for(SELECTION, site, REG) == []


def _rows_site(profile, mutate_rows, mutate_site=lambda s: None):
    site, rows = copy.deepcopy(SITES[profile]), copy.deepcopy(ROWS)
    mutate_rows(rows["external-collector"]["external-collector-receiver"])
    mutate_site(site)
    return "\n".join(site_problems(site, rows=rows))


def test_a_granted_target_and_an_internet_facing_grant_are_accepted():
    """The positive side: the grant names exactly what the manifest reaches."""
    site, mods = copy.deepcopy(SITES["full"]), copy.deepcopy(MODULES)
    mods["external-collector"]["egress"][0]["to"].append("internet")
    mods["external-collector"]["requires"]["hosts"][1]["exposure"] = "internet-facing"
    site["grants"]["egress"]["external-collector"]["edge"].append("internet")
    site["grants"]["internet_facing"] = {"external-collector": ["receiver"]}
    assert site_problems(site, mods) == []
    assert sc.errors_for(SELECTION, site, REG) == []


def test_an_egress_grant_listing_roles_only_grants_nothing():
    """Negative: the old shape (a list of roles) grants no target; it is refused, never read as
    granting every target of those roles."""
    site = copy.deepcopy(SITES["full"])
    site["grants"]["egress"]["external-collector"] = ["edge", "receiver"]
    probs = site_problems(site)
    assert (
        "grants.egress.external-collector: names {<role>: [targets]}, not a list of roles" in probs
    )
    assert any("host role edge is external" in p for p in probs)
    assert sc.errors_for(SELECTION, site, REG)


def test_grants_name_selected_modules_their_roles_and_used_targets_only():
    """Negative: a grant for a module that is not selected, for a role it does not have, or for a
    target it does not use is refused, so no grant waits for a manifest change to switch it on."""
    site = copy.deepcopy(SITES["full"])
    eg = site["grants"]["egress"]
    eg["example-unknown"] = {"x": ["internet"]}
    eg["external-collector"]["ghost"] = ["internet", "svc:secrets"]
    eg["external-collector"]["edge"].append("internet")
    site["grants"]["internet_facing"] = {
        "example-unknown": ["x"],
        "external-collector": ["edge", "receiver", "ghost"],
    }
    probs = site_problems(site)
    for needle in (
        "grants.egress.example-unknown: the module is not selected; remove the grant",
        "grants.egress.external-collector.ghost: not one of the module's host roles; remove the grant",
        "grants.egress.external-collector.edge: internet is granted but not used; remove the grant",
        "grants.internet_facing.example-unknown: the module is not selected; remove the grant",
        "grants.internet_facing.external-collector.ghost: not one of the module's host roles; remove the grant",
        "grants.internet_facing.external-collector.edge: the role is not an internet-facing role inside the lab; remove the grant",
        "grants.internet_facing.external-collector.receiver: the role is not an internet-facing role inside the lab; remove the grant",
    ):
        assert needle in probs, (needle, probs)


def test_every_grant_kind_names_a_selected_module_and_what_it_uses():
    """Negative: public_routes, publish, secrets, units and shared_config grants for an
    unselected module, a public route for a row that does not exist or is not public, publish for
    a module that does not reach static hosting, and a secret no selected module holds are all
    refused, so no grant waits for an upgrade to switch it on."""
    site = copy.deepcopy(SITES["full"])
    g = site["grants"]
    g["public_routes"] = {
        "example-unknown": ["x"],
        "external-collector": ["external-collector-future", "external-collector-receiver"],
    }
    g["publish"] += ["example-unknown", "external-collector"]
    g["secrets"]["example-unknown"] = ["secret:example-static-host/deploy-token"]
    g["secrets"]["publishing"].append("secret:example-unknown/token")
    g["units"] = {"example-unknown": ["x"]}
    g["shared_config"] = {"example-unknown": ["cap:edge"]}
    g["upstreams"] = {"example-unknown": ["cap:idp"]}
    g["cloud_models"] = {"example-unknown": ["mdl:main-reasoner"]}
    probs = site_problems(site)
    for needle in (
        "grants.public_routes.example-unknown: the module is not selected; remove the grant",
        "grants.public_routes.external-collector.external-collector-future: not one of the "
        "module's service rows; remove the grant",
        "grants.public_routes.external-collector.external-collector-receiver: the row has no "
        "public_hostname; remove the grant",
        "grants.publish.example-unknown: the module is not selected; remove the grant",
        "grants.publish.external-collector: the module does not reach cap:static-hosting; "
        "remove the grant",
        "grants.secrets.example-unknown: the module is not selected; remove the grant",
        "grants.secrets.publishing: secret:example-unknown/token is no selected module's "
        "credential; remove the grant",
        "grants.units.example-unknown: the module is not selected; remove the grant",
        "grants.shared_config.example-unknown: the module is not selected; remove the grant",
        "grants.upstreams.example-unknown: the module is not selected; remove the grant",
        "grants.cloud_models.example-unknown: the module is not selected; remove the grant",
    ):
        assert needle in probs, (needle, probs)


def test_units_shared_config_and_secrets_grants_name_what_exists():
    """Negative: a units grant for a unit the module does not ship, a shared_config grant for a
    target the module declares none for, and a grant of the module's own secret (which needs
    none) are refused; publishing's real unit is accepted."""
    site = copy.deepcopy(SITES["full"])
    g = site["grants"]
    g["units"] = {"publishing": ["publishing-run", "publishing-gone"]}
    g["shared_config"] = {"publishing": ["cap:edge"]}
    g["secrets"]["publishing"].append("secret:publishing/deny-list")
    probs = site_problems(site)
    assert probs == [
        "grants.secrets.publishing: secret:publishing/deny-list is the module's own secret, "
        "which needs no grant; remove the grant",
        "grants.units.publishing.publishing-run: the unit neither runs as root nor opts out of "
        "hardening; remove the grant",
        "grants.units.publishing.publishing-gone: not one of the module's units; remove the grant",
        "grants.shared_config.publishing: the module declares no shared_config for cap:edge; "
        "remove the grant",
    ], probs


def _granted(site, mods, **kw):
    """site_problems with every optional input, and the selection's own schema errors."""
    return site_problems(site, mods, **kw), sc.errors_for(SELECTION, site, REG)


def test_a_root_or_opt_out_unit_needs_grants_units():
    """grants.units (ADR-0027 follow-up 4): a module may ship a unit that runs as root or opts out
    of hardening, and the site refuses it until the overlay grants that unit by name."""
    site, mods = copy.deepcopy(SITES["full"]), copy.deepcopy(MODULES)
    priv = {**ROOT_UNITS, "publishing": {"publishing-run"}}
    probs, _ = _granted(site, mods, privileged=priv)
    assert (
        "publishing: unit publishing-run runs as root or opts out of hardening without grants.units"
        in probs
    ), probs
    site["grants"]["units"] = {"publishing": ["publishing-run"]}
    probs, errors = _granted(site, mods, privileged=priv)
    assert probs == [] and errors == [], (probs, errors)


def test_the_module_rules_leave_privilege_to_the_site(tmp_path):
    """A root unit and edge or idp shared_config are no longer module defects: the grant is the
    overlay's to give, so module_problems is silent and site_problems decides."""
    import shutil

    mod = tmp_path / "publishing"
    shutil.copytree(MODULES_DIR / "publishing", mod)
    doc = copy.deepcopy(MODULES["publishing"])
    units = load(mod / doc["contributes"]["scheduler_jobs"][0]["file"])
    units[0].update(run_as_root=True, user="root")
    (mod / doc["contributes"]["scheduler_jobs"][0]["file"]).write_text(yaml.safe_dump(units))
    doc["contributes"]["shared_config"] = [
        {"target": "cap:edge", "file": "edge.yml", "reason": "a proxy header"}
    ]
    (mod / "edge.yml").write_text("headers: {}\n")
    probs = mr.module_problems(doc, mod, SLOTS, load, (tmp_path,))
    assert not [p for p in probs if "grant" in p], probs
    assert mr._privileged_units(doc, mod, load) == {units[0]["name"]}


def test_edge_or_idp_shared_config_needs_grants_shared_config():
    site, mods = copy.deepcopy(SITES["full"]), copy.deepcopy(MODULES)
    mods["publishing"]["contributes"]["shared_config"] = [
        {"target": "cap:idp", "file": "idp.yml", "reason": "a client"},
        {"target": "cap:edge", "file": "edge.yml", "reason": "a header"},
    ]
    probs, _ = _granted(site, mods)
    assert "publishing: shared_config cap:idp without grants.shared_config" in probs
    assert "publishing: shared_config cap:edge without grants.shared_config" in probs
    site["grants"]["shared_config"] = {"publishing": ["cap:edge"]}
    probs, errors = _granted(site, mods)
    assert probs == ["publishing: shared_config cap:idp without grants.shared_config"]
    assert errors == []


def test_a_broker_idp_or_remote_admin_upstream_needs_grants_upstreams():
    """An upstream naming an authority slot, or an instance that fills one, needs the grant; a
    grant no row uses is stale."""
    site, mods, rows = copy.deepcopy(SITES["full"]), copy.deepcopy(MODULES), copy.deepcopy(ROWS)
    row = rows["external-collector"]["external-collector-receiver"]
    row["upstreams"] = [*row["upstreams"], "idp"]
    probs, _ = _granted(site, mods, rows=rows)
    assert (
        "external-collector: service external-collector-receiver upstream idp reaches idp "
        "without grants.upstreams"
    ) in probs, probs
    row["upstreams"] = [*row["upstreams"][:-1], "platform"]  # the instance filling broker and idp
    probs, _ = _granted(site, mods, rows=rows)
    for a in ("broker", "idp"):
        assert (
            f"external-collector: service external-collector-receiver upstream platform reaches "
            f"{a} without grants.upstreams"
        ) in probs, probs
    site["grants"]["upstreams"] = {"external-collector": ["cap:broker", "cap:idp"]}
    probs, errors = _granted(site, mods, rows=rows)
    assert probs == [] and errors == [], (probs, errors)
    site["grants"]["upstreams"]["external-collector"].append("cap:remote-admin")
    probs, _ = _granted(site, mods, rows=rows)
    assert probs == [
        "grants.upstreams.external-collector: no service row of the module reaches remote-admin; "
        "remove the grant"
    ], probs


def test_an_upstream_that_falls_back_to_an_authority_slot_needs_the_grant():
    """An upstream is judged by what traffic reaches: a preferred slot the site leaves out
    resolves to its fallback, so a fallback to idp needs grants.upstreams, and a grant used only
    through that fallback is not stale."""
    site, mods = copy.deepcopy(SITES["full"]), copy.deepcopy(MODULES)
    pref = mods["external-collector"]["prefers"]["capabilities"][0]
    assert pref["cap"] == "cap:lake-catalog"  # the receiver row names lake-catalog upstream
    pref["fallback"]["to"] = "cap:idp"
    site["slots"]["lake-catalog"] = "none"
    probs, _ = _granted(site, mods)
    want = (
        "external-collector: service external-collector-receiver upstream lake-catalog reaches "
        "idp without grants.upstreams"
    )
    assert want in probs, probs
    site["grants"]["upstreams"] = {"external-collector": ["cap:idp"]}
    probs, errors = _granted(site, mods)
    assert not [p for p in probs if "upstreams" in p], probs
    assert errors == []
    site["slots"]["lake-catalog"] = SITES["full"]["slots"]["lake-catalog"]  # no fallback now
    probs, _ = _granted(site, mods)
    assert (
        "grants.upstreams.external-collector: no service row of the module reaches idp; "
        "remove the grant"
    ) in probs, probs


def test_a_unit_privileged_by_hardening_or_by_user_alone_is_privileged():
    for unit in ({"hardening_opt_out": ["ProtectHome"]}, {"user": "root"}, {"run_as_root": True}):
        assert mr.privileged_unit({"name": "x", **unit}), unit
    assert not mr.privileged_unit({"name": "x", "user": "svc-x"})


def test_cloud_roles_follow_the_fallback_chain_and_stop_on_a_cycle_or_a_dangling_fallback():
    local = {"backend": "svc:inference", "model_id": "example-local-1"}
    remote = {**local, "leaves_lab": True}
    roles = {
        "a": {"bindings": [local], "fallback": "mdl:b"},
        "b": {"bindings": [local], "fallback": "mdl:a"},  # a cycle with no cloud binding
        "c": {"bindings": [local], "fallback": "mdl:gone"},  # a dangling fallback
        "d": {"bindings": [local], "fallback": "mdl:e"},
        "e": {"bindings": [remote], "fallback": "mdl:d"},  # a cycle through a cloud binding
    }
    assert mr.cloud_roles(roles) == {"mdl:d", "mdl:e"}


def test_an_agent_model_role_is_one_the_module_requires(tmp_path):
    """An agent's spec names a model role; it must be one of requires.model_roles, so the site's
    cloud-model grant covers the agent's prompts too."""
    import shutil

    tmp = tmp_path
    mod = tmp / "external-collector"
    shutil.copytree(MODULES_DIR / "external-collector", mod)
    doc = copy.deepcopy(MODULES["external-collector"])
    spec_path = mod / _ag(doc)["spec"]
    spec = load(spec_path)
    spec_path.write_text(yaml.safe_dump({**spec, "model_role": "mdl:fast-classifier"}))
    probs = mr.module_problems(doc, mod, SLOTS, load, (tmp,))
    key = _ag(doc)["key"]
    assert (
        f"agent {key}: model role mdl:fast-classifier is not one of the module's "
        "requires.model_roles"
    ) in probs, probs
    doc["requires"]["model_roles"].append({"role": "mdl:fast-classifier"})
    assert not [p for p in mr.module_problems(doc, mod, SLOTS, load, (tmp,)) if "model role" in p]
    spec_path.write_text(yaml.safe_dump({**spec, "model_role": ["mdl:main-reasoner"]}))
    probs = mr.module_problems(doc, mod, SLOTS, load, (tmp,))  # refused, never a crash
    assert [p for p in probs if "is not one of the module's requires.model_roles" in p], probs


def test_a_role_whose_prompts_can_leave_the_lab_needs_grants_cloud_models():
    """A binding marked leaves_lab (model_roles 1.3), on the role or down its fallback chain,
    makes every module requiring the role need grants.cloud_models; a grant for a role the module
    does not require, or one that stays in the lab, is stale."""
    site, mods = copy.deepcopy(SITES["full"]), copy.deepcopy(MODULES)
    roles = copy.deepcopy(MODEL_ROLES)
    roles["fast-classifier"]["bindings"].append(
        {"backend": "svc:cloud-inference", "model_id": "example-remote-1", "leaves_lab": True}
    )
    assert mr.cloud_roles(roles) == {"mdl:fast-classifier", "mdl:main-reasoner"}  # by fallback
    probs, _ = _granted(site, mods, roles=roles)
    needing = sorted(
        m for m in ("core-staff", "example-sandbox", "external-collector") if m in mr.selected(site, mods)
    )  # fmt: skip
    assert needing and all(
        f"{m}: requires mdl:main-reasoner, whose prompts can leave the lab (a binding marked "
        "leaves_lab), without grants.cloud_models" in probs
        for m in needing
    ), probs
    site["grants"]["cloud_models"] = {m: ["mdl:main-reasoner"] for m in needing}
    probs, errors = _granted(site, mods, roles=roles)
    assert probs == [] and errors == [], (probs, errors)
    probs, _ = _granted(site, mods)  # the reference table stays in the lab: the grant is stale
    assert (
        f"grants.cloud_models.{needing[0]}: mdl:main-reasoner has no binding that leaves the lab; "
        "remove the grant"
    ) in probs, probs
    site["grants"]["cloud_models"][needing[0]] = ["mdl:fast-classifier"]
    probs, _ = _granted(site, mods, roles=roles)
    assert (
        f"grants.cloud_models.{needing[0]}: the module does not require mdl:fast-classifier; "
        "remove the grant"
    ) in probs, probs


def test_a_role_table_ceiling_the_rules_refuse_fails_the_site():
    """ADR-0033 decision 10: amber and above are never a cloud role's ceiling, and green needs the
    provider's terms on every binding that leaves the lab; a raised role still needs the grant."""
    site, mods = copy.deepcopy(SITES["full"]), copy.deepcopy(MODULES)
    roles = copy.deepcopy(MODEL_ROLES)
    remote = {"backend": "svc:cloud-inference", "model_id": "example-remote-1", "leaves_lab": True}
    roles["fast-classifier"]["bindings"].append(remote)
    roles["fast-classifier"]["tlp_ceiling"] = "amber"
    probs, _ = _granted(site, mods, roles=roles)
    assert any(p.startswith("mdl:fast-classifier: tlp_ceiling amber") for p in probs), probs
    roles["fast-classifier"]["tlp_ceiling"] = "green"
    probs, _ = _granted(site, mods, roles=roles)
    assert any("records no provider_terms" in p for p in probs), probs
    remote["provider_terms"] = {"retention": "none", "training": "none", "ref": "terms, 2026-09"}
    roles["main-reasoner"]["tlp_ceiling"] = "green"  # it falls back to fast-classifier
    probs, _ = _granted(site, mods, roles=roles)
    assert not any("tlp_ceiling" in p for p in probs), probs
    assert any("without grants.cloud_models" in p for p in probs), probs
    assert mr.role_ceiling(roles, "mdl:main-reasoner") is mr.RAISED_CEILING


def test_an_egress_service_target_names_a_real_service():
    """svc:secret (a typo of svc:secrets) is refused; a selected feature's own row is a service."""
    site, mods = copy.deepcopy(SITES["full"]), copy.deepcopy(MODULES)
    mods["external-collector"]["egress"][0]["to"] += [
        "svc:secret",
        "svc:external-collector-receiver",
    ]
    probs = site_problems(site, mods)
    assert "external-collector: host edge egresses to svc:secret, which is no service" in probs
    assert not any("svc:external-collector-receiver" in p for p in probs)


def test_an_egress_service_target_must_exist():
    site, mods = copy.deepcopy(SITES["full"]), copy.deepcopy(MODULES)
    mods["external-collector"]["egress"][0]["to"].append("svc:no-such-service")
    probs = site_problems(site, mods)
    assert (
        "external-collector: host edge egresses to svc:no-such-service, which is no service"
        in probs
    )


def test_a_public_row_needs_grants_public_routes_whatever_its_auth():
    public = lambda r: r.update(public_hostname="collector.example.org", auth="idp")  # noqa: E731
    assert "is public without grants.public_routes" in _rows_site("full", public)
    grant = lambda s: s["grants"].__setitem__(  # noqa: E731
        "public_routes", {"external-collector": ["external-collector-receiver"]}
    )
    assert "public" not in _rows_site("full", public, grant)


def test_an_upstream_follows_the_fallback():
    """lake-catalog resolves to its fallback (hot-index) on single-box; with neither selected the
    upstream is refused, and an instance upstream must be selected."""
    assert _rows_site("single-box", lambda r: None) == ""
    no_index = lambda s: s["slots"].__setitem__("hot-index", "none")  # noqa: E731
    assert "upstream lake-catalog is not selected, nor a fallback" in _rows_site(
        "single-box", lambda r: None, no_index
    )
    bulk = lambda r: r["upstreams"].append("bulk")  # noqa: E731
    assert "upstream bulk is not a selected instance" in _rows_site("full", bulk)


def test_a_swap_reports_core_and_feature_dependants():
    """Rule 2: the dependants re-check sees the core consumers (B3), not only features."""
    assert mr.dependants("cap:cases", MODULES) == {"core-staff": "prefers"}
    deps = mr.dependants("cap:object-store", MODULES, SITES["full"])
    assert {"external-collector", "example-sandbox", "publishing", "example-lake"} <= set(deps)


def test_feature_and_core_modules_and_sites_carry_no_product_names():
    """The product-name lint's rule, on the examples: no provider's product name or alias occurs
    in a feature or core module's directory or in a site profile (comments included)."""
    names = set()
    for m in MODULES.values():
        if m["kind"] == "provider":
            p = m["product"]
            names |= {p["name"], p.get("display", p["name"]).lower(), *p.get("aliases", [])}
    paths = [
        f
        for n, m in MODULES.items()
        if m["kind"] != "provider"
        for f in (MODULES_DIR / n).rglob("*")
        if f.is_file()
    ]
    paths += [*(MODULES_DIR / "sites").glob("*.yml"), MODULES_DIR / "slots.yml"]
    for f in paths:
        text = f.read_text().lower()
        assert not [n for n in names if n in text], f


#: test function -> the dict its cases come from, read at collection time (after the whole module
#: ran), so a case added after the test is still collected; there is no separate guard, since the
#: cases are generated from the final dicts and cannot drift from them
DEFECT_TABLES = {
    "test_a_site_rule_refuses_the_defect": lambda: SITE_DEFECTS,
    "test_a_loader_rule_refuses_the_defect": lambda: MODULE_DEFECTS,
}


def pytest_generate_tests(metafunc):
    table = DEFECT_TABLES.get(metafunc.function.__name__)
    if table is not None:
        metafunc.parametrize("case", sorted(table()))


# ------------------------------------------------------- egress slots are on the list (ADR-0033)
def test_the_registry_flags_exactly_the_listed_egress_slots():
    """The example registry flags as egress exactly the slots the egress list names, and each of
    them appears in docs/modules.md's "Egress points" table."""
    flagged = {s for s, d in SLOTS.items() if d.get("egress")}
    assert flagged == mr.EGRESS_SLOTS
    docs = (ROOT / "docs" / "modules.md").read_text()
    section = docs.split("### Egress points", 1)[1].split("\n### ", 1)[0]
    rows = [r for r in section.splitlines() if r.startswith("| ") and "---" not in r][1:]
    # the static host is the publishing gate's row (its grant, not a cap, opens it)
    named = (
        {"static-hosting"} if any(r.startswith("| the publishing gate") for r in rows) else set()
    )
    for r in rows:
        grant = r.split(" | ")[2]
        named |= {c.removeprefix("cap:") for c in re.findall(r"cap:[a-z-]+", grant)}
    assert named == mr.EGRESS_SLOTS


def test_a_listed_egress_slot_the_registry_does_not_flag_is_refused():
    """Negative: the flag and the list are one fact, so a registry that drops the flag from a
    listed slot is refused where a module reaches it."""
    slots = copy.deepcopy(SLOTS)
    del slots["notify"]["egress"]
    name = "external-collector"
    probs = mr.module_problems(MODULES[name], MODULES_DIR / name, slots, load, ROOTS)
    assert "cap:notify: on the egress list, but the slot registry does not flag it egress" in probs


def _with_unlisted_egress() -> dict:
    slots = copy.deepcopy(SLOTS)
    slots["outbound-hook"] = {"stage": None, "contract": "notify.py", "stateful": False}
    slots["outbound-hook"]["egress"] = True
    return slots


@pytest.mark.parametrize("how", ["requirement", "preference fallback", "provider"])
def test_a_module_reaching_an_unlisted_egress_slot_is_refused(how):
    """Negative: a slot flagged egress that is not on the egress list is refused wherever a module
    reaches it (a requirement, a preference's fallback target) or provides it."""
    slots = _with_unlisted_egress()
    if how == "provider":
        name = "example-siem-suite"
        doc = copy.deepcopy(MODULES[name])
        doc["provides"]["slots"]["outbound-hook"] = copy.deepcopy(
            doc["provides"]["slots"]["notify"]
        )
    else:
        name = "external-collector"
        doc = copy.deepcopy(MODULES[name])
        if how == "requirement":
            doc["requires"]["capabilities"][1]["cap"] = "cap:outbound-hook"
        else:
            doc.setdefault("prefers", {}).setdefault("capabilities", []).append(
                {
                    "cap": "cap:notify",
                    "version": "1.0",
                    "purpose": "x",
                    "fallback": {"to": "cap:outbound-hook"},
                }
            )
    probs = mr.module_problems(doc, MODULES_DIR / name, slots, load, ROOTS)
    assert any(
        p.startswith("cap:outbound-hook: an egress slot not on the egress list") for p in probs
    )
    assert mr.module_problems(MODULES[name], MODULES_DIR / name, slots, load, ROOTS) == []
