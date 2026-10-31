# SPDX-License-Identifier: Apache-2.0
"""The module manifest's schema-directory examples and negatives, generated from ``examples/modules``.

Each negative is one of the shipped example modules with exactly one rule broken; its file name
says which (``tests/schemas/test_module_1_0.py`` pins the JSON path each must fail at).  The
examples under ``schemas/platform/examples/`` are copies of shipped modules, so ``schema_check``
validates the same documents the contract tests read.  Needs PyYAML (the ``yaml`` extra).
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any

__all__ = ["EXAMPLES", "NEGATIVES", "SELECTION_NEGATIVES", "render"]

HDR = "# SPDX-License-Identifier: Apache-2.0\n"

#: schema-directory example label -> (example module, comment)
EXAMPLES = {
    "provider": (
        "example-object-store",
        "A provider module (fictional product), as examples/modules/example-object-store/module.yml.",
    ),
    "feature": (
        "external-collector",
        "The external data collector as a feature module, as examples/modules/external-collector/module.yml.",
    ),
    "multi-slot-provider": (
        "example-siem-suite",
        "An all-in-one provider that fills several slots, as examples/modules/example-siem-suite/module.yml.",
    ),
    "provisional-provider": (
        "example-static-host",
        "A hosted provider of a slot with no contract yet, as examples/modules/example-static-host/module.yml.",
    ),
    "core": (
        "core-staff",
        "A core module, the home of the staff agents, as examples/modules/core-staff/module.yml.",
    ),
}

Doc = dict[str, Any]


def _agent(d: Doc) -> Doc:
    return d["contributes"]["agents"][0]


def _slot(d: Doc, name: str = "object-store") -> Doc:
    return d["provides"]["slots"][name]


def _set(path: tuple, value: Any) -> Callable[[Doc], None]:
    def go(d: Doc) -> None:
        cur = d
        for k in path[:-1]:
            cur = cur[k]
        cur[path[-1]] = value

    return go


def _pop(path: tuple) -> Callable[[Doc], None]:
    def go(d: Doc) -> None:
        cur = d
        for k in path[:-1]:
            cur = cur[k]
        cur.pop(path[-1])

    return go


def _do(*fns: Callable[[Doc], None]) -> Callable[[Doc], None]:
    def go(d: Doc) -> None:
        for f in fns:
            f(d)

    return go


def _add_config(key: str, spec: Doc) -> Callable[[Doc], None]:
    return lambda d: d["config"].__setitem__(key, spec)


def _add_doc(path: str) -> Callable[[Doc], None]:
    return lambda d: d["contributes"].setdefault("docs", []).append({"file": path})


P, F, V, S, C = (
    "example-object-store",
    "external-collector",
    "example-static-host",
    "example-siem-suite",
    "core-staff",
)

#: negative name -> (base example module, mutation, comment)
NEGATIVES: dict[str, tuple[str, Callable[[Doc], None], str]] = {
    # kinds and identity
    "without-manifest-version": (
        F,
        _pop(("manifest_version",)),
        "A manifest says which manifest schema version it is.",
    ),
    "without-author": (F, _pop(("author",)), "A manifest names who wrote it."),
    "reviews-inside-the-module": (
        F,
        _set(("reviews",), [{"by": "human:example-operator", "kind": "human", "role": "approve"}]),
        "Reviews live in the overlay, keyed by the module's tree digest, never inside the module.",
    ),
    "reserved-id": (F, _set(("id",), "core"), "A module may not take a reserved id."),
    "feature-with-core-prefix": (
        F,
        _set(("id",), "core-collector"),
        "Only a core module's id starts with core-.",
    ),
    "core-with-product": (
        C,
        _set(
            ("product",),
            {"name": "northwind-objects", "display": "Northwind Objects", "version": "1.0"},
        ),
        "A core module names no product.",
    ),
    "core-removable": (
        C,
        _set(
            ("lifecycle",),
            {
                "install": {"playbook": "playbooks/install.yml"},
                "upgrade": {"playbook": "playbooks/upgrade.yml"},
                "remove": {"playbook": "playbooks/remove.yml", "audit": ["contributions"]},
            },
        ),
        "A core module is never removed.",
    ),
    "core-retired": (
        C,
        lambda d: d.update(status="retired", reason="a core module is never retired"),
        "A core module is never retired.",
    ),
    "core-fetched": (
        C,
        _set(
            ("origin",),
            {"kind": "git", "url": "https://git.example.internal/modules/core", "commit": "a" * 40},
        ),
        "A core module is in-tree: a fetched module never becomes core (and so is never auto-selected).",
    ),
    "shadow-suffix-id": (
        F,
        _set(("id",), "external-collector-shadow"),
        "The -shadow suffix names an agent's shadow lane, never a module.",
    ),
    "origin-git-dot-segments": (
        F,
        _set(
            ("origin",),
            {
                "kind": "git",
                "url": "https://git.example.internal/modules/../../other",
                "commit": "a" * 40,
            },
        ),
        "A fetched module's URL has no '.' or '..' segment.",
    ),
    "origin-git-unpinned": (
        F,
        _set(("origin",), {"kind": "git", "url": "https://git.example.internal/modules/collector"}),
        "A fetched module pins its commit.",
    ),
    "retired-without-reason": (F, _set(("status",), "retired"), "A retired module says why."),
    # providers
    "provider-without-slot": (P, _set(("provides",), {}), "A provider names the slots it fills."),
    "provider-without-product": (P, _pop(("product",)), "A provider names its product."),
    "provider-without-licence": (P, _pop(("licence",)), "A provider states its product's licence."),
    "licence-kind-none": (
        P,
        _set(("licence",), {"kind": "none"}),
        "A provider's licence is open-source, commercial, trial or subscription.",
    ),
    "subscription-without-expiry": (
        V,
        _pop(("licence", "expires")),
        "A subscription, trial or commercial licence states when it lapses.",
    ),
    "provider-in-bundle": (
        P,
        _set(("bundle",), {"id": "soc", "group": "threat-intel"}),
        "A provider joins a bundle through its slots, not by membership.",
    ),
    "provider-conformance-and-provisional": (
        P,
        lambda d: _slot(d).update({"provisional": True, "reason": "x" * 50}),
        "A provider entry is proved by a conformance target or provisional, not both.",
    ),
    "provisional-without-reason": (
        V,
        _pop(("provides", "slots", "static-hosting", "reason")),
        "A provisional provider entry says why it has no conformance target.",
    ),
    "adapter-any-callable": (
        P,
        lambda d: _slot(d).__setitem__("adapter", "subprocess:Popen"),
        "An adapter is the module's own code or a shared conformance adapter, never any importable callable.",
    ),
    "control-plane-reader-builtin": (
        V,
        lambda d: d["control_plane"][0].__setitem__("reader", "builtins:exec"),
        "A control-plane reader is the module's own code.",
    ),
    "credential-without-holder": (
        P,
        lambda d: d["credentials"][0].pop("holder"),
        "A credential says who may read it: the provider, per-consumer issues, or an overlay grant.",
    ),
    "hosts-without-lifecycle": (
        P,
        _pop(("lifecycle",)),
        "A module that places something on a host names its playbooks.",
    ),
    # features
    "feature-with-product": (
        F,
        _set(
            ("product",),
            {"name": "northwind-objects", "display": "Northwind Objects", "version": "1.0"},
        ),
        "A feature module never names a product.",
    ),
    "feature-with-credentials": (
        F,
        _set(
            ("credentials",),
            [
                {
                    "secret": "secret:external-collector/x",
                    "identity": "token",
                    "holder": "provider",
                    "purpose": "features keep secrets as config keys",
                }
            ],
        ),
        "Product credentials belong to a provider.",
    ),
    "feature-fills-a-slot": (
        F,
        lambda d: d["provides"].__setitem__(
            "slots",
            {
                "object-store": {
                    "adapter": "hnx_modules.external_collector.s:make",
                    "provisional": True,
                    "reason": "x" * 20,
                }
            },
        ),
        "A feature module never fills a slot.",
    ),
    # requirements
    "requires-bare-capability": (
        F,
        _set(("requires", "capabilities"), ["object-store"]),
        "A requirement is {cap: cap:<name>, ...}, not a bare word.",
    ),
    "requires-product-not-slot": (
        F,
        lambda d: d["requires"]["capabilities"][0].__setitem__("cap", "northwind-objects"),
        "A requirement names a slot, never a product.",
    ),
    "requirement-without-version": (
        F,
        lambda d: d["requires"]["capabilities"][0].pop("version"),
        "A requirement on a contracted slot names the contract version.",
    ),
    "provisional-requirement-with-version": (
        F,
        lambda d: d["requires"]["capabilities"][3].__setitem__("version", "1.0"),
        "A provisional requirement has no contract to version.",
    ),
    "prefers-without-fallback": (
        F,
        lambda d: d["prefers"]["capabilities"][0].pop("fallback"),
        "A soft dependency states its fallback.",
    ),
    "fallback-data-without-to": (
        F,
        lambda d: d["prefers"]["capabilities"][2]["fallback"].__setitem__(
            "data", [{"dataset": "sessions", "retention": {"days": 1}}]
        ),
        "Fallback data moves to the fallback slot, so it needs a to.",
    ),
    "slot-dataset-without-via": (
        F,
        lambda d: d["data"][0].pop("via"),
        "A dataset in a slot names the requirement it lives in, so a fallback can move it.",
    ),
    "interface-schema-not-json": (
        F,
        lambda d: d.__setitem__(
            "interfaces",
            [
                {
                    "id": "collector-batch",
                    "version": "1.0",
                    "kind": "object-prefix",
                    "schema": "docs/external-collector.md",
                    "description": "a batch of sessions",
                }
            ],
        ),
        "An interface's item schema is a JSON Schema file, never a Markdown page.",
    ),
    "host-without-footprint": (
        F,
        lambda d: d["requires"]["hosts"][0].pop("footprint"),
        "A host role states the footprint it places.",
    ),
    "interface-without-via": (
        F,
        lambda d: d["provides"]["interfaces"][0].pop("via"),
        "A provided interface says which slot instance carries it.",
    ),
    "egress-anywhere": (
        F,
        lambda d: d["egress"][0].__setitem__("to", ["anywhere"]),
        "Egress names registry services or internet, nothing else.",
    ),
    # contributions and authority
    "unknown-contribution": (
        F,
        lambda d: d["contributes"].__setitem__("ceilings", [{"file": "policy.yml"}]),
        "Authority (ceilings, broker actions, review policy) is never contributed.",
    ),
    "tooling-contribution": (
        F,
        lambda d: d["contributes"].__setitem__(
            "tooling", [{"kind": "settings", "file": "settings.json"}]
        ),
        "Tooling settings, hooks and instructions are not contributable (deferred to the tooling catalog).",
    ),
    "shared-config-into-a-trust-root": (
        F,
        lambda d: d["contributes"].__setitem__(
            "shared_config", [{"target": "cap:secrets", "file": "secrets.yml", "reason": "a quirk"}]
        ),
        "No module merges configuration into the secret store.",
    ),
    "entry-point-unknown-group": (
        F,
        lambda d: d["contributes"]["entry_points"][0].__setitem__(
            "group", "homelabnext.broker.handlers"
        ),
        "An entry point uses a group that exists.",
    ),
    "entry-point-any-callable": (
        F,
        lambda d: d["contributes"]["entry_points"][0].__setitem__("object", "os:system"),
        "Entry-point code is in the module's own package.",
    ),
    "file-escapes-module": (
        F,
        lambda d: d["contributes"]["services"][0].__setitem__(
            "file", "../other/registry/services.yml"
        ),
        "A contributed file stays inside the module's directory.",
    ),
    "file-dot-git": (F, _add_doc(".git/config"), "A contributed path has no dot-file segment."),
    "file-empty-segment": (F, _add_doc("docs//x.md"), "A contributed path has no empty segment."),
    "file-dot": (
        F,
        _add_doc("."),
        "A contributed path is a file or directory inside the module, never the module itself.",
    ),
    # agents
    "agent-without-charter": (
        F,
        lambda d: _agent(d).pop("charter"),
        "An agent is one block: its charter is part of it.",
    ),
    "agent-unknown-lane": (
        F,
        lambda d: _agent(d)["prompts"].__setitem__("canary", "prompts/x.yml"),
        "Agent prompts are keyed by the lanes real and shadow only.",
    ),
    "agent-tool-not-slot-named": (
        F,
        lambda d: _agent(d)["tools"].append("query"),
        "Agent tools are slot-named (<slot>.<tool>); a product-named one is a loader rule (the tool's slot is one the agent needs).",
    ),
    "agent-staff-code": (
        F,
        lambda d: _agent(d)["roster"].__setitem__("code", "X1"),
        "A staff code is the overlay roster's, never the manifest's.",
    ),
    "agent-ceiling": (
        F,
        lambda d: _agent(d).__setitem__("ceiling", "profile:admin"),
        "A ceiling is never part of an agent block.",
    ),
    "agent-needs-an-authority-slot": (
        F,
        lambda d: _agent(d)["needs"].append(
            {"cap": "cap:secrets", "access": "write", "scope": ["external-collector/"]}
        ),
        "An agent is never granted an authority slot.",
    ),
    "agent-scope-everything": (
        F,
        lambda d: _agent(d)["needs"][0].__setitem__("scope", ["table:"]),
        "A scope is a full table id or a prefix, never a bare kind.",
    ),
    "agent-without-lanes": (F, lambda d: _agent(d).pop("lanes"), "An agent declares its lanes."),
    "agent-schedule-and-trigger": (
        F,
        lambda d: _agent(d).__setitem__("trigger", {"interface": "sample-handoff"}),
        "An agent runs on a calendar or on a trigger, not both.",
    ),
    "lane-writes-dot": (
        F,
        lambda d: _agent(d)["lanes"]["real"]["writes"].append("./"),
        "A lane writes under named prefixes, never '.'.",
    ),
    # data
    "owned-data-without-export": (
        F,
        lambda d: d["data"][0].pop("export"),
        "Owned data needs a neutral export.",
    ),
    "owned-data-native-format": (
        F,
        lambda d: d["data"][0]["export"].__setitem__("formats", ["native-dump"]),
        "Exports use neutral formats, never a product's own.",
    ),
    "owned-data-without-retention": (
        F,
        lambda d: d["data"][0].pop("retention"),
        "Owned data states its retention.",
    ),
    "lake-table-dataset-without-table": (
        F,
        lambda d: d["data"][0].pop("table"),
        "A lake-table dataset names its table.",
    ),
    "dataset-prefix-dot": (
        F,
        lambda d: d["data"][1].__setitem__("prefix", "."),
        "A dataset prefix names a directory, never the root.",
    ),
    "dataset-tlp-unknown": (
        F,
        lambda d: d["data"][0].__setitem__("tlp", "black"),
        "A dataset's TLP label is one of the five TLP 2.0 labels (ADR-0033 decision 1).",
    ),
    "dataset-tlp-not-canonical": (
        F,
        lambda d: d["data"][0].__setitem__("tlp", "TLP:AMBER"),
        "A declared TLP label is written in its canonical spelling.",
    ),
    "dataset-honour-not-boolean": (
        F,
        lambda d: d["data"][0].__setitem__("honour_item_labels", "yes"),
        "honour_item_labels is true or false, never a string that reads as true.",
    ),
    "dataset-honour-without-tlp": (
        F,
        lambda d: d["data"][0].__setitem__("honour_item_labels", True),
        "honour_item_labels needs a tlp declaration beside it: an undeclared dataset is red.",
    ),
    "remove-without-audit": (
        F,
        lambda d: d["lifecycle"]["remove"].pop("audit"),
        "Removal names the decommission planes it must come back clean on.",
    ),
    "remove-discards-without-reason": (
        F,
        lambda d: d["lifecycle"]["remove"].__setitem__("export_first", False),
        "Removing without an export states why the data may go.",
    ),
    # config
    "config-literal-value": (
        F,
        lambda d: d["config"]["batch_signing"].__setitem__("default", "plain-value"),
        "A secret key's default is a secret name, never a value.",
    ),
    "string-config-hides-reference": (
        F,
        lambda d: d["config"]["edge_region"].__setitem__("default", "secret:external-collector/x"),
        "A secret reference belongs in a secret-typed key.",
    ),
    "string-config-hides-reference-uppercase": (
        F,
        lambda d: d["config"]["edge_region"].__setitem__("default", "SECRET:external-collector"),
        "The reference check ignores case.",
    ),
    "string-config-other-scheme": (
        F,
        lambda d: d["config"]["edge_region"].__setitem__("default", "vault:kv/data/x"),
        "A string default carries no reference of any scheme.",
    ),
    "requires-scope-unknown-part": (
        F,
        lambda d: d["requires"]["scope"][0].__setitem__("part", "trusted.wans"),
        "A module requires a scope part the selection defines, never a new one.",
    ),
    "string-config-address-literal": (
        F,
        _add_config(
            "bind",
            {"type": "string", "description": "d", "default": "0.0.0.0", "overlay": "optional"},
        ),
        "A string default is not an address literal.",
    ),
    "config-credential-named-string": (
        F,
        _add_config(
            "admin_password",
            {"type": "string", "description": "d", "default": "changeme", "overlay": "optional"},
        ),
        "A key named like a credential is of type secret.",
    ),
    "config-path-absolute": (
        P,
        lambda d: d["config"]["data_dir"].__setitem__("default", "/etc/shadow"),
        "A path default is relative to the module's data root.",
    ),
    "config-path-traversal": (
        P,
        lambda d: d["config"]["data_dir"].__setitem__("default", "../../x"),
        "A path default never leaves the module's data root.",
    ),
    "config-enum-default-object": (
        F,
        lambda d: d["config"]["mode"].__setitem__("default", {"a": 1}),
        "An enum default is one of its values, a string.",
    ),
}


def _rename(key: str, new: str) -> Callable[[Doc], None]:
    return lambda d: d.__setitem__(new, d.pop(key))


#: documentation-range scope entries the selection negatives plant
MALFORMED_CIDR = "198.51.100.0/33"  # no-raw-endpoint: allow a documentation-range negative
DOC_NET = "192.0.2.0/24"  # no-raw-endpoint: allow a documentation-range negative

#: selection negative name -> (base site profile, mutation, comment)
SELECTION_NEGATIVES: dict[str, tuple[str, Callable[[Doc], None], str]] = {
    "grants-misspelt": (
        "full",
        _rename("grants", "grant"),
        "A misspelt grants key is refused, never read as no grants.",
    ),
    "unknown-grant-kind": (
        "full",
        lambda d: d["grants"].__setitem__("public_route", {"publishing": ["publishing-site"]}),
        "A grant kind that does not exist is refused, never ignored.",
    ),
    "choice-without-instance": (
        "single-box",
        lambda d: d["slots"]["notify"][0].pop("instance"),
        "A slot choice names its instance.",
    ),
    "lane-binding-without-real": (
        "single-box",
        lambda d: d["features"]["external-collector"]["agents"]["external-collector-analyst"][
            "lanes"
        ].pop("real"),
        "Every agent's real lane is bound.",
    ),
    "scope-empty-list": (
        "full",
        lambda d: d["scope"]["trusted"].__setitem__("wan", []),
        "A scope part is a non-empty list: an empty one would read as no trusted addresses.",
    ),
    "scope-malformed-cidr": (
        "full",
        lambda d: d["scope"]["target"].__setitem__(0, MALFORMED_CIDR),
        "A scope entry is an address or a CIDR network.",
    ),
    "addresses-network": (
        "small-lab",
        lambda d: d["hosts"]["data"].__setitem__("addresses", [DOC_NET]),
        "A host address is one address, never a network.",
    ),
    "scope-unknown-part": (
        "full",
        lambda d: d["scope"]["trusted"].__setitem__("lan", [DOC_NET]),
        "A misspelt scope part is refused, never read as an extra list nobody reads.",
    ),
    "upstream-grant-not-authority": (
        "full",
        lambda d: d["grants"].__setitem__("upstreams", {"publishing": ["cap:secrets"]}),
        "grants.upstreams names only broker, idp or remote-admin (secrets is never an upstream).",
    ),
    "lab-namespace-without-why": (
        "full",
        lambda d: d["lab_table_namespaces"][0].pop("why"),
        "A lab table namespace says why it is the lab's.",
    ),
    "lab-namespace-not-a-name": (
        "full",
        lambda d: d["lab_table_namespaces"][0].__setitem__("namespace", "Archive.old"),
        "A lab table namespace is one catalog name of the inventory's shape.",
    ),
    "tlp-reader-unknown-ceiling": (
        "full",
        lambda d: d["tlp_readers"][0].__setitem__("ceiling", "TLP:RED"),
        "A reader's TLP ceiling is one of the five labels in its canonical spelling.",
    ),
    "tlp-reader-without-why": (
        "full",
        lambda d: d["tlp_readers"][0].pop("why"),
        "Every lake reader says who it is and why it needs its ceiling.",
    ),
    "tlp-reader-not-an-id": (
        "full",
        lambda d: d["tlp_readers"][0].__setitem__("reader", "everyone"),
        "A reader is a profile, module, user or group id.",
    ),
    "cloud-model-not-a-role": (
        "full",
        lambda d: d["grants"].__setitem__("cloud_models", {"publishing": ["main-reasoner"]}),
        "grants.cloud_models names model roles as mdl:<role>.",
    ),
}


def _dump(doc: Doc, comment: str) -> str:
    import yaml

    return HDR + "# " + comment + "\n" + yaml.safe_dump(doc, sort_keys=False, width=100)


def render(root: Path) -> dict[str, str]:
    """Repository-relative path -> text, for every schema-directory example and negative."""
    import yaml

    ex = Path(root) / "examples" / "modules"
    base = {
        m: yaml.safe_load((ex / m / "module.yml").read_text(encoding="utf-8"))
        for m in {P, F, V, S, C}
    }
    out: dict[str, str] = {}
    for label, (mod, comment) in EXAMPLES.items():
        out[f"schemas/platform/examples/module.{label}.yml"] = _dump(base[mod], comment)
    for name, (mod, mutate, comment) in NEGATIVES.items():
        d = copy.deepcopy(base[mod])
        mutate(d)
        out[f"schemas/platform/negative/module.{name}.yml"] = _dump(d, comment)
    sites = {
        p.stem: yaml.safe_load(p.read_text(encoding="utf-8"))
        for p in sorted((ex / "sites").glob("*.yml"))
    }
    for name, site in sites.items():
        out[f"schemas/platform/examples/module_selection.{name}.yml"] = _dump(
            site, f"Site profile {name}, as examples/modules/sites/{name}.yml."
        )
    for name, (profile, mutate, comment) in SELECTION_NEGATIVES.items():
        d = copy.deepcopy(sites[profile])
        mutate(d)
        out[f"schemas/platform/negative/module_selection.{name}.yml"] = _dump(d, comment)
    lake = yaml.safe_load((ex / F / "lake" / "sessions.table.yml").read_text(encoding="utf-8"))
    out["schemas/platform/examples/lake_table.module-owned.yml"] = _dump(
        lake,
        "A module's lake table, as examples/modules/external-collector/lake/sessions.table.yml.",
    )
    gates = {}
    for owner, iid in (("publishing", "publishable-output"), ("example-sandbox", "sample-handoff")):
        doc = yaml.safe_load((ex / owner / "module.yml").read_text(encoding="utf-8"))
        gates[iid] = next(i for i in doc["interfaces"] if i["id"] == iid)
        out[f"schemas/platform/examples/interface.{iid}.yml"] = _dump(
            gates[iid], f"A gate interface, as examples/modules/{owner}/module.yml defines it."
        )
    iface = gates["publishable-output"]
    for name, mutate, comment in (
        ("no-item-schema", lambda d: d.pop("schema"), "An interface names its item schema."),
        (
            "unknown-kind",
            lambda d: d.__setitem__("kind", "queue"),
            "An interface kind is one of four.",
        ),
        ("gate-not-boolean", lambda d: d.__setitem__("gate", "yes"), "gate is true or false."),
    ):
        d = copy.deepcopy(iface)
        mutate(d)
        out[f"schemas/platform/negative/interface.{name}.yml"] = _dump(d, comment)
    bad = dict(lake)
    bad.pop("freshness")
    out["schemas/platform/negative/lake_table.without-freshness.yml"] = _dump(
        bad, "A lake table states its freshness expectation."
    )
    return out
