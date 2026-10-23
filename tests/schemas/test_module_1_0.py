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

import module_rules as mr
import pytest
import schema_check as sc
import yaml

from homelabnext._yaml import UniqueKeyLoader

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

# A negative's file name says which rule it breaks; an error must be at that place.
NEGATIVES = {
    "adapter-any-callable": "provides/slots/object-store/adapter",
    "agent-ceiling": "contributes/agents/0",
    "agent-needs-an-authority-slot": "contributes/agents/0/needs/2/cap",
    "agent-product-tool": "contributes/agents/0/tools/3",
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
    "core-removable": "lifecycle",
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
    "file-escapes-module": "contributes/services/0/file",
    "host-without-footprint": "requires/hosts/0",
    "hosts-without-lifecycle": "$",
    "interface-without-via": "provides/interfaces/0",
    "lake-table-dataset-without-table": "data/0",
    "lane-writes-dot": "contributes/agents/0/lanes/real/writes/2",
    "licence-kind-none": "licence/kind",
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
    "shared-config-into-a-trust-root": "contributes/shared_config/0/target",
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
    assert mr.module_problems(MODULES[name], MODULES_DIR / name, SLOTS, load) == []


def test_the_examples_meet_the_rules_across_modules():
    assert mr.tree_problems(MODULES) == []


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
    return mr.module_problems(doc, MODULES_DIR / name, SLOTS, load)


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
    "edge or idp config without a grant": (
        "example-object-store",
        lambda d: d["contributes"].__setitem__(
            "shared_config",
            [{"target": "cap:edge", "file": "edge.yml", "reason": "a proxy header"}],
        ),
        "overlay grant",
    ),
}


@pytest.mark.parametrize("case", sorted(MODULE_DEFECTS))
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
    probs = "\n".join(mr.module_problems(doc, mod, SLOTS, load))
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
    assert "one owner only" in probs
    assert "contains external-collector/samples/" in probs
    assert "external-collector-analyst: claimed by" in probs


def test_an_interface_with_no_owner_is_refused():
    mods = copy.deepcopy(MODULES)
    del mods["publishing"]
    assert any("publishable-output', '1.0') has no owner" in p for p in mr.tree_problems(mods))


# ------------------------------------------------------------------ site profiles
@pytest.mark.parametrize("profile", sorted(SITES))
def test_site_profile_meets_every_rule(profile):
    assert mr.site_problems(SITES[profile], MODULES, SLOTS) == []


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


@pytest.mark.parametrize("case", sorted(SITE_DEFECTS))
def test_a_site_rule_refuses_the_defect(case):
    profile, mutate, needle = SITE_DEFECTS[case]
    assert needle in _site(profile, mutate)


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
            names |= {p["name"], p["display"].lower(), *p.get("aliases", [])}
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
