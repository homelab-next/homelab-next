# SPDX-License-Identifier: Apache-2.0
"""platform/module 1.0, a DRAFT (ADR-0027, proposed; docs/modules.md): the module manifest.

Contract tests only; there is no loader yet. They prove the schema's own rules (each negative in
``schemas/platform/negative/module.*`` fails where its name says), that every example module in
``examples/modules/`` validates and meets the loader rules (``module_rules``: names bound to the
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
from pathlib import Path

import pytest
import schema_check as sc
import yaml

from homelabnext._yaml import UniqueKeyLoader
from homelabnext.modules import rules as mr

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
ROOTS = mr.EXAMPLE_ROOTS
ROWS = {n: mr._rows(m, DIRS[n], load) for n, m in MODULES.items()}
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


def test_fifteen_event_schemas_were_checked():
    assert len(EVENT_IDS) == 15 and all("." in i.rsplit("/", 2)[1] for i in EVENT_IDS)


@pytest.mark.parametrize("name", sorted(NEGATIVES))
def test_each_negative_fails_where_its_name_says(name):
    path = ROOT / f"schemas/platform/negative/module.{name}.yml"
    errors = sc.errors_for(SCHEMA, sc.load_instance(path), REG)
    assert errors, f"{name} was accepted"
    assert any(e.split(": ", 1)[0] == NEGATIVES[name] for e in errors), errors


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


@pytest.mark.parametrize("slot", sorted(SLOTS))
def test_a_slot_with_a_contract_names_a_real_protocol(slot):
    d = SLOTS[slot]
    if d.get("contract"):
        assert (ROOT / "conformance/protocols" / d["contract"]).is_file()
    assert not (d.get("privileged") and not d.get("contract")), "a privileged slot has a contract"
    assert bool(d.get("export_formats")) == bool(d.get("stateful"))


def _contributed_files(doc):
    c = doc.get("contributes", {})
    for key, entries in c.items():
        for e in entries:
            if isinstance(e, dict):
                for field in ("file", "charter", "spec", "context_manifest"):
                    if field in e:
                        yield key, e[field]
                yield from (("prompts", f) for f in e.get("prompts", {}).values())
    for i in doc.get("interfaces", []):
        if "schema" in i:
            yield "interfaces", i["schema"]
    for e in doc.get("provides", {}).get("slots", {}).values():
        if "conformance" in e:
            yield "conformance", e["conformance"]["target"]


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
    "edge or idp config without a grant": (
        "example-object-store",
        lambda d: d["contributes"].__setitem__(
            "shared_config",
            [{"target": "cap:edge", "file": "edge.yml", "reason": "a proxy header"}],
        ),
        "overlay grant",
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
        "root or a hardening opt-out",
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
    assert mr.PUBLIC_MODULE_ROOTS == (ROOT / "modules",)
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


def test_an_interface_with_no_owner_is_refused():
    mods = copy.deepcopy(MODULES)
    del mods["publishing"]
    assert any("interface publishable-output 1.0 has no owner" in p for p in mr.tree_problems(mods))


# ------------------------------------------------------------------ site profiles
@pytest.mark.parametrize("profile", sorted(SITES))
def test_site_profile_meets_every_rule(profile):
    assert mr.site_problems(SITES[profile], MODULES, SLOTS, ROWS) == []


@pytest.mark.parametrize("profile", sorted(SITES))
def test_site_profile_validates_against_the_selection_schema(profile):
    assert sc.is_draft(SELECTION)
    assert sc.errors_for(SELECTION, SITES[profile], REG) == []


SELECTION_NEGATIVES = {
    "grants-misspelt": "$",
    "unknown-grant-kind": "grants",
    "choice-without-instance": "slots/notify",
    "lane-binding-without-real": "features/external-collector/agents/external-collector-analyst/lanes",
}


@pytest.mark.parametrize("name", sorted(SELECTION_NEGATIVES))
def test_each_selection_negative_fails_where_its_name_says(name):
    path = ROOT / f"schemas/platform/negative/module_selection.{name}.yml"
    errors = sc.errors_for(SELECTION, sc.load_instance(path), REG)
    assert any(e.split(": ", 1)[0] == SELECTION_NEGATIVES[name] for e in errors), errors


def _site(profile, mutate):
    site = copy.deepcopy(SITES[profile])
    mods = copy.deepcopy(MODULES)
    mutate(site, mods)
    return "\n".join(mr.site_problems(site, mods, SLOTS))


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
        "count multiplies the footprint": (
            "single-box",
            lambda s, m: m["external-collector"]["requires"]["hosts"][1].__setitem__("count", 16),
            "box: cpu",
        ),
    }
)


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
    probs = "\n".join(mr.site_problems(site, mods, SLOTS))
    assert "example-lake-curator: each lane is bound to exactly one orchestration instance" in probs
    site["providers"] = {
        "example-lake": {"agents": {"example-lake-curator": {"lanes": {"real": "platform"}}}}
    }
    assert mr.site_problems(site, mods, SLOTS) == []
    assert sc.errors_for(SELECTION, site, REG) == []


def _rows_site(profile, mutate_rows, mutate_site=lambda s: None):
    site, rows = copy.deepcopy(SITES[profile]), copy.deepcopy(ROWS)
    mutate_rows(rows["external-collector"]["external-collector-receiver"])
    mutate_site(site)
    return "\n".join(mr.site_problems(site, MODULES, SLOTS, rows))


def test_a_granted_target_and_an_internet_facing_grant_are_accepted():
    """The positive side: the grant names exactly what the manifest reaches."""
    site, mods = copy.deepcopy(SITES["full"]), copy.deepcopy(MODULES)
    mods["external-collector"]["egress"][0]["to"].append("internet")
    mods["external-collector"]["requires"]["hosts"][1]["exposure"] = "internet-facing"
    site["grants"]["egress"]["external-collector"]["edge"].append("internet")
    site["grants"]["internet_facing"] = {"external-collector": ["receiver"]}
    assert mr.site_problems(site, mods, SLOTS, ROWS) == []
    assert sc.errors_for(SELECTION, site, REG) == []


def test_an_egress_grant_listing_roles_only_grants_nothing():
    """Negative: the old shape (a list of roles) grants no target; it is refused, never read as
    granting every target of those roles."""
    site = copy.deepcopy(SITES["full"])
    site["grants"]["egress"]["external-collector"] = ["edge", "receiver"]
    probs = mr.site_problems(site, MODULES, SLOTS, ROWS)
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
    probs = mr.site_problems(site, MODULES, SLOTS, ROWS)
    for needle in (
        "grants.egress.example-unknown: the module is not selected",
        "grants.egress.external-collector.ghost: not one of the module's host roles",
        "grants.egress.external-collector.edge: internet is granted but not used",
        "grants.internet_facing.example-unknown: the module is not selected",
        "grants.internet_facing.external-collector.ghost: not one of the module's host roles",
        "grants.internet_facing.external-collector.edge: the role is not an internet-facing role inside the lab",
        "grants.internet_facing.external-collector.receiver: the role is not an internet-facing role inside the lab",
    ):
        assert needle in probs, (needle, probs)


def test_an_egress_service_target_must_exist_without_rows_too():
    """svc:secret (a typo of svc:secrets) is refused without rows; a name bound to a selected
    feature stands in for its row until the rows are given."""
    site, mods = copy.deepcopy(SITES["full"]), copy.deepcopy(MODULES)
    mods["external-collector"]["egress"][0]["to"].append("svc:secret")
    probs = mr.site_problems(site, mods, SLOTS)
    assert "external-collector: host edge egresses to svc:secret, which is no service" in probs
    assert not any("svc:external-collector-receiver" in p for p in probs)


def test_an_egress_service_target_must_exist():
    site, mods = copy.deepcopy(SITES["full"]), copy.deepcopy(MODULES)
    mods["external-collector"]["egress"][0]["to"].append("svc:no-such-service")
    probs = mr.site_problems(site, mods, SLOTS, ROWS)
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
#: ran), so a case added after the test is still collected
DEFECT_TABLES = {
    "test_a_site_rule_refuses_the_defect": lambda: SITE_DEFECTS,
    "test_a_loader_rule_refuses_the_defect": lambda: MODULE_DEFECTS,
}


def pytest_generate_tests(metafunc):
    table = DEFECT_TABLES.get(metafunc.function.__name__)
    if table is not None:
        metafunc.parametrize("case", sorted(table()))


def test_every_defect_case_is_collected(request):
    """Exact guard: every collected case set equals its final dict (a table whose test was
    deselected entirely is not compared)."""
    names = {i.name for i in request.session.items if i.module is request.module}
    for fn, table in DEFECT_TABLES.items():
        got = {n for n in names if n.startswith(fn + "[")}
        if got:
            assert got == {f"{fn}[{c}]" for c in table()}, fn
