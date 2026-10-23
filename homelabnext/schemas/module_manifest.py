# SPDX-License-Identifier: Apache-2.0
"""The module manifest schema (``platform/module`` 1.0, a DRAFT) and the draft lake-table record.

ADR-0027 (proposed) and ``docs/modules.md`` are the specification; this module is the one place the
schema is written.  It is a draft (``x-draft``): it has no frozen baseline and may change until a
loader and the first pilot exist.  Rules JSON Schema cannot express (a name bound to the module's
own id, uniqueness against the core, grants in the overlay, the slot registry's flags) are loader
rules: ``docs/modules.md`` lists them and ``tests/schemas/test_module_1_0.py`` applies them to the
examples.

``python -m homelabnext.schemas`` writes the files; ``--check`` compares them (see the package doc).
"""

from __future__ import annotations

import json
from typing import Any

from homelabnext.modules.scope import (
    DYNAMIC_PARTS,
    EMPTY_ALLOWED,
    ENTRY_PATTERN,
    PART_DOCS,
    SCOPE_PARTS,
    scope_tree,
)

__all__ = [
    "RESERVED_IDS",
    "lake_table_schema",
    "module_schema",
    "module_selection_schema",
    "render",
]

G = "$(?!\\n)"
BASE = "https://schemas.example.internal/homelabnext/"
COMMON = BASE + "ids/common/1.0#/$defs/"
LID = BASE + "ids/logical-id/1.0#/$defs/"
SLUG = "[a-z][a-z0-9]*(?:-[a-z0-9]+)*"
#: ids no module may take (the loader also refuses an overlay id that shadows a shipped one)
RESERVED_IDS = (
    "all", "any", "core", "hnx", "hnx-modules", "homelabnext", "lab", "module", "modules",
    "none", "overlay", "pass-through", "self", "shared", "site",
)  # fmt: skip
#: slots a module agent may never be granted directly: authority stays with its owner
AUTHORITY_SLOTS = (
    "cap:broker",
    "cap:secrets",
    "cap:idp",
    "cap:edge",
    "cap:remote-admin",
    "cap:mcp-catalog",
)
#: shared components whose configuration a module can never merge into (no grant opens these)
NEVER_SHARED = ("cap:secrets", "cap:broker", "cap:mcp-catalog", "cap:records", "cap:orchestration")
#: interchange formats a dataset or a stateful slot exports in (a draft list; additive)
NEUTRAL_FORMATS = (
    "parquet", "jsonl", "csv", "json", "markdown-tree", "object-tree", "zone-file", "sigma",
    "stix", "sarif", "ics",
)  # fmt: skip
ENTRY_POINT_GROUPS = ("homelabnext.invariants.checks",)


def pat(p: str, desc: str | None = None, maxlen: int = 128) -> dict[str, Any]:
    d: dict[str, Any] = {"type": "string", "maxLength": maxlen, "pattern": "^" + p + G}
    if desc:
        d["description"] = desc
    return d


def obj(props, required=(), desc=None, **extra) -> dict[str, Any]:
    d: dict[str, Any] = {"type": "object", "additionalProperties": False}
    if required:
        d["required"] = list(required)
    d["properties"] = props
    if desc:
        d["description"] = desc
    d.update(extra)
    return d


def arr(items, desc=None, min_items=None) -> dict[str, Any]:
    d: dict[str, Any] = {"type": "array", "uniqueItems": True, "items": items}
    if min_items:
        d["minItems"] = min_items
    if desc:
        d["description"] = desc
    return d


def ref(name: str, desc: str | None = None) -> dict[str, Any]:
    d: dict[str, Any] = {"$ref": "#/$defs/" + name}
    if desc:
        d["description"] = desc
    return d


def text(maxlen: int = 300, desc: str | None = None) -> dict[str, Any]:
    d: dict[str, Any] = {"type": "string", "minLength": 1, "maxLength": maxlen}
    if desc:
        d["description"] = desc
    return d


def file_entry(desc: str) -> dict[str, Any]:
    return obj({"file": ref("rel_path"), "note": text(200)}, ["file"], desc)


def _not_kind(*keys: str) -> list[dict[str, Any]]:
    return [{"not": {"required": [k]}} for k in keys]


#: a path segment starts with a letter, digit or underscore: no '.', '..', '.git', '' (from '//')
SEGMENT = "[A-Za-z0-9_][A-Za-z0-9._-]*"
#: a data prefix: lower-case segments, each starting alphanumeric, ending in '/'
PREFIX = "[a-z0-9][a-z0-9_-]*(?:/[a-z0-9][a-z0-9_.-]*)*/"
TABLE = "table:[a-z][a-z0-9]*(?:_[a-z0-9]+)*\\.[a-z][a-z0-9]*(?:_[a-z0-9]+)*"
SCHEMA_ID = "https://schemas\\.example\\.internal/homelabnext/[a-z0-9_/.-]+/[0-9]+\\.[0-9]+"
OWN_CODE = "hnx_modules\\.[a-z_][a-z0-9_]*(?:\\.[a-z_][a-z0-9_]*)+:[A-Za-z_][A-Za-z0-9_]*"
SHARED_ADAPTER = "homelabnext\\.conform\\.adapters\\.[a-z_][a-z0-9_]*:[A-Za-z_][A-Za-z0-9_]*"
SECRET = "secret:" + SLUG + "(?:/[a-z][a-z0-9_-]*)+"
#: an https URL whose path segments each start alphanumeric: no '.', '..' or dot-file segment
URL = "https://[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)+"


def _defs() -> dict[str, Any]:
    d: dict[str, Any] = {
        "slug": pat(SLUG, maxlen=64),
        "module_id": {
            "allOf": [
                pat(SLUG, None, 48),
                {"not": {"enum": list(RESERVED_IDS)}},
                {"not": {"pattern": "-shadow$"}},
            ],
            "description": "A module id: its directory name, never a reserved word, never ending in -shadow (the suffix names an agent's shadow lane, <root>/<id>-shadow/). Every name the module claims (tables, det ids, units, roles, data prefixes, secrets, agent and profile ids, criteria) is bound to it; the loader checks the binding.",
        },
        "rel_path": pat(
            SEGMENT + "(?:/" + SEGMENT + ")*/?",
            "A path inside the module's directory: no leading slash, no empty, '.' or '..' segment, no dot-file (.git). The loader also resolves it (realpath) inside the module directory and refuses symlinks and non-regular files.",
            256,
        ),
        "cap_ref": {"$ref": LID + "cap_id"},
        "mdl_ref": {"$ref": LID + "mdl_id"},
        "svc_ref": {"$ref": LID + "svc_id"},
        "profile_ref": {"$ref": LID + "profile_id"},
        "table_ref": pat(
            TABLE,
            "A full lake table id, table:<namespace>.<name>; a module's namespace is its id with - as _.",
            128,
        ),
        "role_ref": pat(
            "role:[a-z][a-z0-9_]*",
            "An Ansible role as a graph node id (role:<name>); the name starts with the module id (- as _).",
            96,
        ),
        "status_ref": pat(
            "status:" + SLUG,
            "A status source as a graph node id, declared on one of the module's own service rows.",
            96,
        ),
        "interface_id": pat(
            SLUG,
            "An inter-module interface, named by what it carries; exactly one module (or the core) defines each id and version.",
            64,
        ),
        "contract_version": pat(
            "[0-9]+\\.[0-9]+",
            "MAJOR.MINOR of a contract: met by the same major and an equal or higher minor.",
            16,
        ),
        "schema_id": {
            "type": "string",
            "maxLength": 200,
            "pattern": "^" + SCHEMA_ID + G,
            "description": "The $id of a shipped schema (an event type such as events/case.opened/1.0, an OCSF class, ids/logical-id/1.0).",
        },
        "adapter_ref": pat(
            "(?:" + OWN_CODE + "|" + SHARED_ADAPTER + ")",
            "The factory that binds the product to the slot's contract: the module's own code (hnx_modules.<own id>.) or one of the shared adapters (homelabnext.conform.adapters.); the loader binds the package to the module's id.",
            200,
        ),
        "own_code_ref": pat(
            OWN_CODE,
            "Code in the module's own package, hnx_modules.<own id with - as _>.<module>:<attr>; the loader puts only that package on the import path.",
            200,
        ),
        "secret": pat(
            SECRET,
            "A secret-store name in the module's own namespace (secret:<module id>/...), never a value; another module's secret is read only through an overlay grant.",
            128,
        ),
        "neutral_format": {
            "enum": list(NEUTRAL_FORMATS),
            "description": "A format no product owns. parquet: lake rows; jsonl/csv/json: records; markdown-tree: Markdown with front matter and relative links; object-tree: keys and bytes plus a JSONL listing (key, size, sha256, metadata); zone-file: RFC 1035; sigma: Sigma rules; stix: STIX 2.1 bundles; sarif: SARIF 2.1.0 logs; ics: RFC 5545 calendars.",
        },
        "neutral_formats": arr(
            ref("neutral_format"),
            "One or more neutral formats (cases export JSONL plus Markdown).",
            1,
        ),
        "format_ref": obj(
            {
                "format": pat(
                    SLUG,
                    "An interchange format at a boundary: ocsf, sigma, cloudevents, action-request, sql, s3, openai-compatible, markdown-records, stix, sarif, ics.",
                    32,
                ),
                "version": pat(
                    "[0-9A-Za-z][0-9A-Za-z.-]*",
                    "The format's own version (ocsf 1.3.0, cloudevents 1.0, the S3 API 2006-03-01).",
                    32,
                ),
                "schema_id": ref("schema_id"),
                "classes": arr(
                    pat("[a-z][a-z0-9_.-]*", None, 64),
                    "The subset in use (OCSF classes, event types).",
                ),
            },
            ["format", "version"],
            "A neutral format at a boundary: the conformance suite checks field meanings in it.",
        ),
        "formats": arr(ref("format_ref")),
        "features": arr(
            ref("slug"),
            "Optional contract abilities as the suite names them; a semantic property a dependant relies on is a feature it can require (alert-promotes-case).",
        ),
        "requirement_capability": obj(
            {
                "cap": ref("cap_ref"),
                "version": ref("contract_version"),
                "features": ref("features"),
                "formats": ref("formats"),
                "provisional": {
                    "const": True,
                    "description": "The slot has no contract yet (the slot registry says so; the loader refuses this where a contract exists). No version then.",
                },
                "instance": pat(
                    SLUG,
                    "Which instance of the slot, when a site selects several providers of it.",
                    64,
                ),
                "purpose": text(200),
            },
            ["cap"],
            "One slot the module cannot work without (hard); never a product.",
            allOf=[
                {
                    "if": {"required": ["provisional"]},
                    "then": {"not": {"required": ["version"]}},
                    "else": {"required": ["version"]},
                }
            ],
        ),
        "requirement_model_role": obj(
            {"role": ref("mdl_ref"), "purpose": text(200)},
            ["role"],
            "A model role alias (ADR-0007), never a model id.",
        ),
        "requirement_interface": obj(
            {
                "interface": ref("interface_id"),
                "version": ref("contract_version"),
                "cardinality": {
                    "enum": ["one", "all"],
                    "description": "one (default): exactly one selected module provides it; all: consume every selected provider.",
                },
                "purpose": text(200),
            },
            ["interface", "version"],
            "An interface another module provides; the requiring module never names it.",
        ),
        "fallback_data": obj(
            {
                "dataset": ref(
                    "slug", "One of the module's own data ids, living in this preference (loader)."
                ),
                "retention": ref("retention"),
                "formats": ref(
                    "neutral_formats", "A subset of the fallback slot's export formats (loader)."
                ),
            },
            ["dataset"],
            "How an owned dataset changes when the fallback slot holds it instead (retention, export formats).",
        ),
        "fallback": obj(
            {
                "to": ref(
                    "cap_ref",
                    "The lighter slot used instead, when the site selects it; datasets bound to the preferred slot move with it.",
                ),
                "behaviour": text(
                    300,
                    "What the module does, and what stops working, without the preferred slot or interface.",
                ),
                "data": arr(ref("fallback_data")),
            },
            ["behaviour"],
            "Without the preferred slot: what stops working, optionally the lighter slot used instead (to) and how owned datasets change there (data, which needs a to: data cannot move nowhere).",
            dependentRequired={"data": ["to"]},
        ),
        "preference_capability": obj(
            {
                "cap": ref("cap_ref"),
                "version": ref("contract_version"),
                "features": ref("features"),
                "formats": ref("formats"),
                "provisional": {"const": True},
                "instance": pat(SLUG, None, 64),
                "purpose": text(200),
                "fallback": ref("fallback"),
            },
            ["cap", "purpose", "fallback"],
            "A slot used when the site has it (soft), with its fallback, so removal impact is computable.",
            allOf=[
                {
                    "if": {"required": ["provisional"]},
                    "then": {"not": {"required": ["version"]}},
                    "else": {"required": ["version"]},
                }
            ],
        ),
        "preference_interface": obj(
            {
                "interface": ref("interface_id"),
                "version": ref("contract_version"),
                "cardinality": {"enum": ["one", "all"]},
                "purpose": text(200),
                "fallback": ref("fallback"),
            },
            ["interface", "version", "purpose", "fallback"],
        ),
        "prefers": obj(
            {
                "capabilities": arr(ref("preference_capability")),
                "interfaces": arr(ref("preference_interface")),
            },
            desc="Soft dependencies, each with its fallback behaviour.",
        ),
        "footprint": obj(
            {
                "cpu": {"type": "number", "minimum": 0.1, "maximum": 256},
                "memory_mb": {"type": "integer", "minimum": 16},
                "disk_gb": {"type": "integer", "minimum": 0},
                "gpu_memory_mb": {"type": "integer", "minimum": 0},
                "resources": arr(
                    obj(
                        {
                            "kind": ref("slug", "The kind of a named host resource (gpu)."),
                            "exclusive": {"type": "boolean"},
                        },
                        ["kind", "exclusive"],
                    ),
                    "Named resources the placement binds to the host's own (gpu0); an exclusive one is never shared.",
                ),
            },
            ["cpu", "memory_mb", "disk_gb"],
            "What the module places on one host role. A site sums every footprint on a host over cpu, memory, disk and GPU memory against the host's capacity less its headroom, and the generated units and guests take them as limits (MemoryMax, CPUQuota), never as hints.",
        ),
        "requirement_host": obj(
            {
                "role": pat(
                    SLUG,
                    "The module's name for this host; the site's placement maps it to a host.",
                    64,
                ),
                "kind": {
                    "enum": ["vm", "lxc", "host", "external", "any"],
                    "description": "external: placement and footprint only; its compute model is deferred to the collector pilot.",
                },
                "count": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 16,
                    "default": 1,
                    "description": "Copies of this host role; the footprint and its resources count once per copy.",
                },
                "exposure": {
                    "enum": ["internal", "internet-facing", "isolated"],
                    "default": "internal",
                    "description": "Default internal. internet-facing: only on a kind external role, or with the overlay's grants.internet_facing. isolated: no route to the lab and no egress, enforced by the generated network policy; it lands only on a host the site marks isolated.",
                },
                "footprint": ref("footprint"),
                "roles": arr(ref("role_ref"), "The module's own Ansible roles on this host."),
                "purpose": text(200),
            },
            ["role", "kind", "footprint"],
            "A host or guest the module needs, by role, never by name.",
        ),
        "requires": obj(
            {
                "capabilities": arr(ref("requirement_capability")),
                "model_roles": arr(ref("requirement_model_role")),
                "interfaces": arr(ref("requirement_interface")),
                "hosts": arr(ref("requirement_host")),
                "scope": arr(ref("requirement_scope")),
            },
            desc="Everything the module needs, by slot, role, interface or part of the site's network scope; never a product.",
        ),
        "requirement_scope": obj(
            {
                "part": {
                    "enum": list(SCOPE_PARTS),
                    "description": "A part of the site selection's scope block. The module reads the addresses from the selection, never from its own config, and only the parts it declares here (homelabnext.modules.scope.scope_networks refuses any other): a selection that enables it with the part missing, empty (an exclusion may be an explicit []) or malformed is refused (loader), and its reader fails closed. A module that reads target also requires exclude.offensive, and exclude.unattended_mutation when it runs unattended (loader).",
                },
                "purpose": text(200),
            },
            ["part"],
            "A part of the site's network scope the module needs (the external data collector's trusted.wan, so it never reports the lab's own addresses).",
        ),
        "migration": obj(
            {
                "formats": ref("neutral_formats"),
                "export": ref(
                    "role_ref", "The role whose export hook writes the slot's neutral format."
                ),
                "import": ref(
                    "role_ref", "The role whose import hook reads it (role interface v1.1)."
                ),
            },
            ["formats", "export", "import"],
            "The slot's neutral export/import. Required exactly when the slot registry marks the slot stateful (a loader rule); a stateless slot carries none.",
        ),
        "provider_slot": obj(
            {
                "formats": ref("formats"),
                "adapter": ref("adapter_ref"),
                "features": ref("features"),
                "conformance": obj(
                    {
                        "target": ref(
                            "rel_path",
                            "A conformance target file in the module; its features equal the entry's.",
                        ),
                        "strict": {
                            "type": "boolean",
                            "description": "true: SHOULD checks fail the run too.",
                        },
                    },
                    ["target"],
                    "How the provider is proved; the evidence is the report kept in the swap record, never copied here.",
                ),
                "provisional": {
                    "const": True,
                    "description": "The slot has no contract yet. Refused where the slot has one, and always for a privileged slot.",
                },
                "reason": text(300),
                "calibration": arr(
                    file_entry(
                        "Per (decision spec x provider) thresholds and input limits, refitted by the conformance replay."
                    )
                ),
                "migration": ref("migration"),
            },
            ["adapter"],
            "One slot the provider fills, keyed by the slot's name in provides.slots, so a slot cannot be claimed twice.",
            oneOf=[
                {"required": ["conformance"], "not": {"required": ["provisional"]}},
                {"required": ["provisional", "reason"], "not": {"required": ["conformance"]}},
            ],
        ),
        "interface_definition": obj(
            {
                "id": ref("interface_id"),
                "version": ref("contract_version"),
                "kind": {
                    "enum": ["object-prefix", "event", "lake-table", "service"],
                    "description": "object-prefix: objects under a prefix of an object-store instance; event: an event type; lake-table: a table others read; service: a registry service's API.",
                },
                "formats": ref("formats"),
                "schema": pat(
                    SEGMENT + "(?:/" + SEGMENT + ")*\\.json",
                    "The JSON Schema of one item (a .json file), in this (the owning) module; the loader reads it as a JSON Schema whose $id is in .../modules/<owner>/.",
                    256,
                ),
                "schema_id": ref("schema_id"),
                "description": text(300),
            },
            ["id", "version", "kind", "description"],
            "An interface this module OWNS (platform/interface, docs/modules.md): one definition per id and version across every manifest, the core included. The consumer owns a gate interface.",
            oneOf=[{"required": ["schema"]}, {"required": ["schema_id"]}],
        ),
        "interface_provided": obj(
            {
                "interface": ref("interface_id"),
                "version": ref("contract_version"),
                "via": obj(
                    {
                        "cap": ref("cap_ref"),
                        "instance": pat(SLUG, "The slot instance it is carried on.", 64),
                        "prefix": pat(
                            PREFIX, "Under the module's own data namespace (<module id>/...).", 200
                        ),
                        "table": ref("table_ref"),
                        "service": ref("svc_ref"),
                    },
                    desc="Where it is carried: a slot instance and its prefix or table, or a service.",
                ),
                "description": text(300),
            },
            ["interface", "version", "via", "description"],
            "An interface this module provides; the definition (schema) is the owner's.",
        ),
        "provides": obj(
            {
                "slots": {
                    "type": "object",
                    "minProperties": 1,
                    "propertyNames": {"pattern": "^" + SLUG + G, "maxLength": 64},
                    "additionalProperties": ref("provider_slot"),
                    "description": "Provider only: one entry per slot it fills, keyed by slot name.",
                },
                "interfaces": arr(ref("interface_provided")),
            },
            desc="What the module offers: slots (provider only) and interfaces (any kind).",
        ),
        "egress": {
            "description": "Where the module's hosts may connect beyond the slots they require: none (the default when absent), or per host role (one of the module's own) a list of registry services and internet. Every internet target and every authority or privileged service (svc:secrets, svc:broker, ...) needs an overlay grant naming it (grants.egress.<module>.<role>), and so does every kind: external host role (external). Enforcement by a generated network policy is specified, not implemented.",
            "default": "none",
            "oneOf": [
                {"const": "none"},
                arr(
                    obj(
                        {
                            "host": pat(SLUG, "One of the module's host roles.", 64),
                            "to": arr({"oneOf": [ref("svc_ref"), {"const": "internet"}]}, None, 1),
                            "purpose": text(200),
                        },
                        ["host", "to"],
                    ),
                    None,
                    1,
                ),
            ],
        },
        "lake_table_entry": file_entry(
            "A platform/lake_table record (draft 1.0) in the module: its id's namespace is the module id."
        ),
        "notify_pair": obj(
            {
                "problem": text(160, "The problem title."),
                "recovery": text(160, "Its recovery title."),
            },
            ["problem", "recovery"],
            "A recovery pair. The notifier loads pairs from manifests: this is their only source.",
        ),
        "agent_need": obj(
            {
                "cap": {
                    "allOf": [ref("cap_ref"), {"not": {"enum": list(AUTHORITY_SLOTS)}}],
                    "description": "Never an authority slot (broker, secrets, idp, edge, remote-admin, mcp-catalog).",
                },
                "access": {"enum": ["read", "write"]},
                "scope": arr(
                    pat("(?:" + TABLE + "|" + PREFIX + ")", None, 200),
                    "Full table ids or prefixes (each ending in /). A write scope sits under the module's own namespace (<root>/<module id>[-shadow]/), and never overlaps another module's (loader).",
                    1,
                ),
            },
            ["cap", "access", "scope"],
            "A scoped grant on a slot; the cap set equals the spec's capabilities.",
        ),
        "lane": obj(
            {
                "writes": arr(
                    pat(PREFIX, None, 200),
                    "The records prefixes this lane writes: the real lane under <root>/<module id>/, the shadow lane under <root>/<module id>-shadow/ (loader).",
                    1,
                ),
                "compare_to": {
                    "enum": ["real"],
                    "description": "The lane a shadow lane is graded against.",
                },
                "description": text(200),
            },
            ["writes"],
        ),
        "lanes": obj(
            {
                "production": {
                    "enum": ["real", "shadow"],
                    "default": "real",
                    "description": "The lane consumers read (default real). The selection binds each lane to exactly one orchestration instance.",
                },
                "real": ref("lane"),
                "shadow": ref("lane"),
            },
            ["real"],
            "The agent's lanes. Each needs a prompt, and the selection binds each to one orchestration instance, so a cutover runs the real lane on the old instance and the shadow on the new one, never both on both.",
        ),
        "agent": obj(
            {
                "key": pat(
                    SLUG,
                    "The agent key; starts with the module id and is unique against the core's and every module's.",
                    64,
                ),
                "profile": ref(
                    "profile_ref",
                    "profile:<key>: owned by the module; never another profile's id (ceilings are keyed by it).",
                ),
                "charter": ref("rel_path", "The one copy of the agent's standing instructions."),
                "spec": ref(
                    "rel_path",
                    "The profile spec (docs/agent.md): the one source of model role and capabilities. It carries no ceiling: a module agent compiles only with the overlay's ceiling policy.",
                ),
                "needs": arr(ref("agent_need")),
                "tools": arr(
                    pat("[a-z][a-z0-9-]*\\.[a-z][a-z0-9_]*", None, 96),
                    "Slot-named tools (<slot>.<tool>); a product's tool name is caught by the product-name lint, not by this pattern.",
                ),
                "context_manifest": ref("rel_path"),
                "prompts": {
                    "type": "object",
                    "minProperties": 1,
                    "propertyNames": {"enum": ["real", "shadow"]},
                    "additionalProperties": ref("rel_path"),
                    "description": "Per lane, an agent/prompt_template record; exactly the agent's lanes.",
                },
                "schedule": obj(
                    {
                        "on_calendar": pat(
                            "[A-Za-z0-9*:/,. -]+ UTC", "A systemd calendar ending in UTC.", 64
                        )
                    },
                    ["on_calendar"],
                ),
                "trigger": {
                    "oneOf": [
                        obj(
                            {
                                "event": pat(
                                    "homelabnext\\.[a-z][a-z0-9_]*(?:\\.[a-z][a-z0-9_]*)+",
                                    "An event type (schemas/events).",
                                    96,
                                )
                            },
                            ["event"],
                        ),
                        obj({"interface": ref("interface_id")}, ["interface"]),
                    ],
                    "description": "Event-driven instead of a calendar: an event type, or an item arriving on an interface the module consumes.",
                },
                "state": arr(
                    pat("[a-z0-9][a-z0-9_.-]*\\.json", None, 96),
                    "State files, per lane under the module's state prefix.",
                ),
                "roster": obj(
                    {
                        "recall": {
                            "type": "boolean",
                            "description": "true: the incident recall addresses this agent. Staff codes are the overlay roster's, never the manifest's.",
                        }
                    }
                ),
                "handoffs": arr(
                    ref("rel_path"),
                    "agent/handoff records; their broker actions must be a subset of the operator's broker manifest and are never added to it.",
                ),
                "lanes": ref("lanes"),
            },
            ["key", "profile", "charter", "spec", "prompts", "lanes"],
            "One agent as ONE block: profile, tool wiring, scheduler entry, state paths and roster are generated from it.",
            oneOf=[
                {"required": ["schedule"], "not": {"required": ["trigger"]}},
                {"required": ["trigger"], "not": {"required": ["schedule"]}},
            ],
        ),
        "entry_point": obj(
            {
                "group": {
                    "enum": list(ENTRY_POINT_GROUPS),
                    "description": "An existing entry-point group; the proposed ones (docs/modules.md, migration path) join when they exist.",
                },
                "name": pat("[a-z][a-z0-9_]*", "Starts with the module id (- as _).", 64),
                "object": ref("own_code_ref"),
            },
            ["group", "name", "object"],
            "Code the module plugs into the core.",
        ),
        "scheduler_job": {
            "oneOf": [
                file_entry(
                    "A fleet_units spec in the module: unit names start with the module id; no run_as_root or hardening_opt_out without an overlay grant; no direct paging."
                ),
                obj(
                    {
                        "timer": pat(
                            "timer:[a-z][a-z0-9_]*/" + SLUG,
                            "A timer of one of the module's OWN roles (timer:<role>/<name>).",
                            128,
                        )
                    },
                    ["timer"],
                ),
            ]
        },
        "shared_config": obj(
            {
                "target": {
                    "allOf": [ref("cap_ref"), {"not": {"enum": list(NEVER_SHARED)}}],
                    "description": "The shared component; never secrets, broker, mcp-catalog, records or orchestration, and edge or idp only with an overlay grant.",
                },
                "file": ref("rel_path"),
                "reason": text(300),
            },
            ["target", "file", "reason"],
            "A quirk in a shared component, as typed keys that component's generator merges, never an edit to its own config.",
        ),
        "contributes": obj(
            {
                "roles": arr(
                    file_entry(
                        "An Ansible role directory in the module (role interface v1); its name starts with the module id."
                    )
                ),
                "services": arr(
                    file_entry(
                        "platform/service rows; names start with the module id (a provider's row is keyed by its slot and renamed to the instance). A public_hostname needs auth other than none and an overlay grant."
                    )
                ),
                "status_sources": arr(ref("status_ref")),
                "notify_pairs": arr(ref("notify_pair")),
                "scheduler_jobs": arr(ref("scheduler_job")),
                "lake_tables": arr(ref("lake_table_entry")),
                "preflight": arr(
                    obj(
                        {"role": ref("role_ref"), "hook": {"enum": ["readiness", "health"]}},
                        ["role", "hook"],
                        "A role's own readiness or health hook.",
                    )
                ),
                "mcp_servers": arr(
                    file_entry("A platform/mcp_server record; its id starts with the module id.")
                ),
                "agents": arr(ref("agent")),
                "invariants": arr(
                    file_entry(
                        "Criteria in the register's shape with ids <module id>/<slug> (registers/invariant 1.1)."
                    )
                ),
                "entry_points": arr(ref("entry_point")),
                "detections": arr(
                    file_entry("A Sigma rule; its det: id starts with the module id.")
                ),
                "workflow_packs": arr(file_entry("A workflow pack.")),
                "docs": arr(file_entry("A Markdown page the docs index lists under the module.")),
                "shared_config": arr(ref("shared_config")),
            },
            desc="Entries the module adds to registries the core builds. The core keeps no list. Authority (ceilings, broker actions, review policy, grants, tooling settings, hooks, instructions) is never contributed.",
        ),
        "retention": {
            "oneOf": [
                obj({"days": {"type": "integer", "minimum": 1, "maximum": 3650}}, ["days"]),
                obj({"keep": {"enum": ["forever", "transient"]}}, ["keep"]),
            ]
        },
        "data_io": obj(
            {"formats": ref("neutral_formats"), "via": ref("role_ref")}, ["formats", "via"]
        ),
        "dataset": obj(
            {
                "id": ref("slug"),
                "kind": {
                    "enum": [
                        "lake-table",
                        "object-prefix",
                        "records-prefix",
                        "files",
                        "database",
                        "state",
                    ]
                },
                "table": ref("table_ref"),
                "prefix": pat(
                    PREFIX, "Under the module's own namespace in the slot it lives in.", 200
                ),
                "via": obj(
                    {"cap": ref("cap_ref"), "instance": pat(SLUG, None, 64)},
                    ["cap"],
                    desc="The requirement or preference it lives in (required for a dataset in a slot; files, database and state live on the module's own host). It names only a cap, and an instance, the module requires or prefers; when the site resolves that slot to its fallback, the dataset moves there (with the fallback's data override).",
                ),
                "description": text(300),
                "export": ref(
                    "data_io",
                    "Its exit copy, written by that role's export hook (relative to the module's data root).",
                ),
                "import": ref(
                    "data_io",
                    "Its import; the role validates traversal, symlinks and sizes in the tree it reads.",
                ),
                "retention": ref("retention"),
            },
            ["id", "kind", "description", "export", "import", "retention"],
            "One dataset the module owns: removing the module exports it first, and never touches another module's data.",
            allOf=[
                {
                    "if": {"properties": {"kind": {"const": "lake-table"}}},
                    "then": {"required": ["table"], "not": {"required": ["prefix"]}},
                },
                {
                    "if": {
                        "properties": {
                            "kind": {"enum": ["object-prefix", "records-prefix", "files"]}
                        }
                    },
                    "then": {"required": ["prefix"], "not": {"required": ["table"]}},
                },
                {
                    "if": {"properties": {"kind": {"enum": ["database", "state"]}}},
                    "then": {"allOf": _not_kind("table", "prefix")},
                },
                {
                    "if": {
                        "properties": {
                            "kind": {"enum": ["lake-table", "object-prefix", "records-prefix"]}
                        }
                    },
                    "then": {"required": ["via"]},
                },
            ],
        ),
        "config_key": obj(
            {
                "type": {
                    "enum": [
                        "string",
                        "integer",
                        "boolean",
                        "duration_s",
                        "path",
                        "svc",
                        "secret",
                        "enum",
                    ]
                },
                "description": text(200),
                "default": {
                    "description": "A fictional default; a real value comes from the overlay."
                },
                "values": arr({"type": "string", "maxLength": 64}, None, 1),
                "overlay": {
                    "enum": ["required", "optional"],
                    "description": "required: a site must set it.",
                },
            },
            ["type", "description", "overlay"],
            allOf=[
                {
                    "if": {"properties": {"type": {"const": "secret"}}},
                    "then": {"properties": {"default": ref("secret")}},
                },
                {
                    "if": {"properties": {"type": {"const": "svc"}}},
                    "then": {"properties": {"default": ref("svc_ref")}},
                },
                {
                    "if": {"properties": {"type": {"const": "integer"}}},
                    "then": {"properties": {"default": {"type": "integer"}}},
                },
                {
                    "if": {"properties": {"type": {"const": "duration_s"}}},
                    "then": {"properties": {"default": {"type": "integer", "minimum": 0}}},
                },
                {
                    "if": {"properties": {"type": {"const": "boolean"}}},
                    "then": {"properties": {"default": {"type": "boolean"}}},
                },
                {
                    "if": {"properties": {"type": {"const": "string"}}},
                    "then": {"properties": {"default": ref("plain_string")}},
                },
                {
                    "if": {"properties": {"type": {"const": "path"}}},
                    "then": {"properties": {"default": ref("rel_path")}},
                },
                {
                    "if": {"properties": {"type": {"const": "enum"}}},
                    "then": {
                        "required": ["values"],
                        "properties": {"default": {"type": "string", "maxLength": 64}},
                    },
                    "else": {"not": {"required": ["values"]}},
                },
            ],
            desc="A configuration key. An enum default is one of values (loader); a path default is relative to the module's data root.",
        ),
        "plain_string": {
            "type": "string",
            "maxLength": 256,
            "description": "A string default carries no reference of any scheme (secret:, vault:, any <scheme>:, in any case) and no address literal: those have typed keys or come from the registry.",
            "allOf": [
                {"not": {"pattern": "^[A-Za-z][A-Za-z0-9+.-]*:"}},
                {"not": {"pattern": "[Ss][Ee][Cc][Rr][Ee][Tt]:"}},
                {"not": {"pattern": "^[0-9]{1,3}(\\.[0-9]{1,3}){3}$|::"}},
            ],
        },
        "playbook": obj({"playbook": ref("rel_path"), "note": text(300)}, ["playbook"]),
        "lifecycle": obj(
            {
                "install": ref("playbook"),
                "upgrade": ref("playbook"),
                "remove": obj(
                    {
                        "playbook": ref("rel_path"),
                        "export_first": {
                            "type": "boolean",
                            "description": "Default true: every owned dataset is exported before removal.",
                        },
                        "discard_reason": text(
                            300,
                            "Why owned data may go without an export (required when export_first is false).",
                        ),
                        "audit": arr(
                            ref("slug"),
                            "Decommission planes (homelabnext/decommission/planes.py's registry; the loader checks the names) plus the contributions plane.",
                            1,
                        ),
                    },
                    ["playbook", "audit"],
                    allOf=[
                        {
                            "if": {
                                "properties": {"export_first": {"const": False}},
                                "required": ["export_first"],
                            },
                            "then": {"required": ["discard_reason"]},
                        }
                    ],
                ),
            },
            ["install"],
            "Playbooks in the module. Required when the module places anything on a host; a hosted or config-only provider needs none. upgrade defaults to install (roles are idempotent).",
        ),
        "origin": {
            "description": "Where the module comes from. in-tree: shipped in this repository (reviewed by its own pull requests). git or archive: fetched; the overlay pins its tree digest (sha256 over every file of the module directory, code and roles included) and keeps the reviews keyed by it, so an unpinned or changed module is not loadable.",
            "oneOf": [
                obj({"kind": {"const": "in-tree"}}, ["kind"]),
                obj(
                    {
                        "kind": {"const": "git"},
                        "url": pat(URL, None, 300),
                        "commit": pat(
                            "[0-9a-f]{40}(?:[0-9a-f]{24})?",
                            "A full commit id: 40 hex (sha1 repositories) or 64 hex (sha256).",
                            64,
                        ),
                    },
                    ["kind", "url", "commit"],
                ),
                obj(
                    {
                        "kind": {"const": "archive"},
                        "url": pat(URL, None, 300),
                        "sha256": pat("[0-9a-f]{64}", None, 64),
                    },
                    ["kind", "url", "sha256"],
                ),
            ],
        },
        "product": obj(
            {
                "name": ref("slug", "The product's name as the product-name lint matches it."),
                "display": text(80, "Default: name."),
                "aliases": arr(ref("slug"), "Other spellings the lint matches."),
                "version": pat(
                    "[0-9A-Za-z][0-9A-Za-z.+_-]*",
                    "The pinned product version; the provider's service rows take it from here.",
                    64,
                ),
            },
            ["name", "version"],
        ),
        "licence": obj(
            {
                "kind": {"enum": ["open-source", "commercial", "trial", "subscription"]},
                "spdx": pat("[A-Za-z0-9.+-]+", None, 64),
                "tier": text(80, "The feature tier the site relies on."),
                "expires": {
                    "$ref": COMMON + "date",
                    "description": "The licence probe warns 30 days ahead, pages the owner through notify at 7, and turns red on the day.",
                },
                "renewal": text(200),
            },
            ["kind"],
            allOf=[
                {
                    "if": {
                        "properties": {"kind": {"enum": ["trial", "subscription", "commercial"]}}
                    },
                    "then": {"required": ["expires"]},
                },
                {
                    "if": {"properties": {"kind": {"const": "open-source"}}},
                    "then": {"required": ["spdx"]},
                },
            ],
        ),
        "credential": obj(
            {
                "secret": ref("secret"),
                "identity": pat(
                    SLUG,
                    "api-key, service-account, sso-app, key-pair, token, password, ... (a slug; the loader knows the kinds).",
                    32,
                ),
                "holder": {
                    "enum": ["provider", "consumers", "granted"],
                    "description": "provider: only the provider's own roles read it; consumers: a template the provider issues one credential per consumer from at bind time (never shared); granted: readable only by modules the overlay's grants.secrets names.",
                },
                "purpose": text(200),
            },
            ["secret", "identity", "holder", "purpose"],
        ),
        "identifier": obj(
            {
                "kind": pat(
                    SLUG,
                    "hostname, dns-name, vmid, lake-namespace, bucket, iac-variable, secret-name (a slug).",
                    32,
                ),
                "name": pat("[a-z0-9][a-z0-9._-]*", None, 128),
                "on_remove": {
                    "enum": ["release", "keep", "tombstone"],
                    "description": "tombstone: never reused. The loader refuses an identifier another module or the core holds.",
                },
            },
            ["kind", "name", "on_remove"],
        ),
    }
    return d


def module_schema() -> dict[str, Any]:
    defs = _defs()
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": BASE + "platform/module/1.0",
        "x-draft": "ADR-0027 (proposed): no loader or pilot yet; not frozen, may change before acceptance",
        "title": "Module manifest",
        "description": "One provider, feature or core module (ADR-0027, proposed; docs/modules.md): <modules>/<id>/module.yml. A provider fills slots with one product (the only place a product name may appear); a feature is an optional, removable mission naming slots, model roles, interfaces and host roles; a core module (id core-*) is always installed and is the home of the staff agents and other core consumers, so a swap's dependants re-check sees them. Every name a module claims is bound to its id; authority is never contributed. The loader that enforces the rules JSON Schema cannot express does not exist yet; docs/modules.md lists them.",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "manifest_version",
            "id",
            "kind",
            "title",
            "description",
            "owner",
            "author",
            "status",
            "version",
            "origin",
            "requires",
        ],
        "properties": {
            "manifest_version": {
                "const": "1.0",
                "description": "The manifest schema's version, so a loader can tell a 1.0 manifest from a later one.",
            },
            "id": ref("module_id"),
            "kind": {"enum": ["provider", "feature", "core"]},
            "title": text(80),
            "description": text(500),
            "owner": ref("slug", "Owning team; the licence probe pages it."),
            "author": {
                "type": "string",
                "pattern": "^[a-z][a-z0-9_-]*:[A-Za-z0-9._@-]+" + G,
                "description": "issuer:subject of whoever wrote the manifest. Reviews are never in the manifest: the overlay holds them, keyed by the module's tree digest.",
            },
            "status": {"enum": ["draft", "active", "deprecated", "retired"]},
            "reason": text(300, "Why it is deprecated or retired."),
            "replaced_by": ref("module_id", "Another module (never itself; loader)."),
            "version": pat(
                "[0-9]+\\.[0-9]+\\.[0-9]+", "The module's own version (semantic versioning).", 32
            ),
            "origin": ref("origin"),
            "bundle": obj(
                {"id": ref("slug"), "group": ref("slug")},
                ["id", "group"],
                "Feature only: membership of a bundle the site installs together (on the member, never a list).",
            ),
            "product": ref("product"),
            "licence": ref("licence"),
            "credentials": arr(
                ref("credential"),
                "Provider only: every credential the product holds or is given, in the module's own secret namespace.",
            ),
            "control_plane": arr(
                obj(
                    {"kind": ref("slug"), "reader": ref("own_code_ref"), "description": text(300)},
                    ["kind", "reader", "description"],
                ),
                "Provider only: configuration the vendor holds outside the repository, read by the module's own code for the conformance run.",
            ),
            "identifiers": arr(ref("identifier"), "Identifiers that are state, not code."),
            "requires": ref("requires"),
            "prefers": ref("prefers"),
            "interfaces": arr(ref("interface_definition"), "Interfaces this module owns."),
            "provides": ref("provides"),
            "egress": ref("egress"),
            "contributes": ref("contributes"),
            "data": arr(ref("dataset"), "Datasets the module owns."),
            "config": {
                "type": "object",
                "propertyNames": {"pattern": "^[a-z][a-z0-9_]{0,63}" + G},
                "patternProperties": {
                    "(?:^|_)(?:password|passwd|token|secret|credential|credentials|key|api_?key|private_?key)(?:_|$)": {
                        "properties": {"type": {"const": "secret"}},
                        "description": "A key named like a credential is of type secret: its default is a secret name, never a literal.",
                    }
                },
                "additionalProperties": ref("config_key"),
                "description": "Configuration keys with fictional defaults; the overlay sets the real values.",
            },
            "lifecycle": ref("lifecycle"),
        },
        "allOf": [
            {
                "if": {
                    "properties": {"status": {"enum": ["deprecated", "retired"]}},
                    "required": ["status"],
                },
                "then": {"required": ["reason"]},
            },
            {
                "if": {
                    "properties": {
                        "requires": {
                            "properties": {"hosts": {"minItems": 1}},
                            "required": ["hosts"],
                        }
                    },
                    "required": ["requires"],
                },
                "then": {"required": ["lifecycle"]},
            },
            {
                "if": {"properties": {"kind": {"const": "provider"}}, "required": ["kind"]},
                "then": {
                    "required": ["product", "licence", "provides"],
                    "properties": {
                        "provides": {"required": ["slots"]},
                        "id": {"not": {"pattern": "^core-"}},
                    },
                    "allOf": _not_kind("bundle"),
                },
            },
            {
                "if": {"properties": {"kind": {"const": "feature"}}, "required": ["kind"]},
                "then": {
                    "properties": {
                        "provides": {"not": {"required": ["slots"]}},
                        "id": {"not": {"pattern": "^core-"}},
                    },
                    "allOf": _not_kind("product", "licence", "credentials", "control_plane"),
                },
            },
            {
                "if": {"properties": {"kind": {"const": "core"}}, "required": ["kind"]},
                "then": {
                    "properties": {
                        "id": {"pattern": "^core-"},
                        "origin": {"properties": {"kind": {"const": "in-tree"}}},
                        "status": {"not": {"const": "retired"}},
                        "provides": {"not": {"required": ["slots"]}},
                        "lifecycle": {"not": {"required": ["remove"]}},
                    },
                    "allOf": _not_kind(
                        "product",
                        "licence",
                        "credentials",
                        "control_plane",
                        "bundle",
                        "replaced_by",
                    ),
                },
            },
        ],
        "$defs": defs,
    }


def lake_table_schema() -> dict[str, Any]:
    retention = {"type": "integer", "minimum": 1, "maximum": 3650}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": BASE + "platform/lake_table/1.0",
        "x-draft": "ADR-0027 (proposed): promoted from the module manifest's inline lake tables; not frozen",
        "title": "Lake table declaration",
        "description": "One lake table's operational declaration (docs/modules.md): owner, schema, retention, maintenance and freshness. A module contributes its own tables (namespace = its id, - as _); the core declares its OCSF tables the same way, so lake maintenance enumerates records instead of keeping a list. Columns are never here: they come from the table schema (x-lake).",
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "owner", "retention_days", "freshness"],
        "properties": {
            "id": pat(TABLE, "table:<namespace>.<name>.", 128),
            "owner": pat(SLUG, "The owning module id (core-* for a core table).", 48),
            "schema_id": {"type": "string", "maxLength": 200, "pattern": "^" + SCHEMA_ID + G},
            "schema": pat(
                SEGMENT + "(?:/" + SEGMENT + ")*",
                "A table schema with an x-lake block, in the owning module.",
                256,
            ),
            "retention_days": retention,
            "maintenance": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "compact": {"type": "boolean"},
                    "expire_snapshots_days": {"type": "integer", "minimum": 1, "maximum": 365},
                },
            },
            "freshness": {
                "type": "object",
                "additionalProperties": False,
                "required": ["cadence", "stale_after_s"],
                "properties": {
                    "cadence": {
                        "enum": ["continuous", "batch"],
                        "description": "batch: judged against the table's own load schedule.",
                    },
                    "stale_after_s": {"type": "integer", "minimum": 60},
                },
            },
        },
        "oneOf": [{"required": ["schema_id"]}, {"required": ["schema"]}],
    }


def scope_entry_schema() -> dict[str, Any]:
    """One entry of a scope part: the pattern :func:`homelabnext.modules.scope.parse_entry`
    matches too, so the schema and the reader agree on every entry's text."""
    return {
        "type": "string",
        "maxLength": 64,
        "pattern": ENTRY_PATTERN,
        "description": "An IPv4 or IPv6 address or CIDR network: no host bits (IPv4 here, IPv6 in the loader), no leading zeros, no zone id, no whitespace, no IPv4 written inside or embedded in IPv6 (mapped, compatible, NAT64). The loader also refuses /0, special-use blocks (loopback, link-local, multicast, unspecified, reserved), a trusted network broader than /8 (IPv4) or /32 (IPv6), and a network listed twice.",
    }


def scope_source_schema() -> dict[str, Any]:
    """A dynamic source for a part's addresses (trusted.wan only): specified, not implemented."""
    return obj(
        {"source": pat(SLUG, "The name of the source that knows the current addresses.", 64)},
        ["source"],
        "A dynamic source instead of a literal network (a DHCP or CGNAT WAN, a delegated IPv6 prefix that changes). Specified, not implemented: the shape is fixed now so freezing it later is additive, and the loader refuses it until a reader exists (docs/modules.md).",
    )


def scope_schema() -> dict[str, Any]:
    """The selection's ``scope`` object, generated from ``SCOPE_PARTS`` (one source of truth)."""

    def part(name: str) -> dict[str, Any]:
        if name in EMPTY_ALLOWED:
            desc = PART_DOCS[name] + " An explicit [] means nothing is excluded; absent is not."
            return arr(ref("scope_entry"), desc)
        if name in DYNAMIC_PARTS:
            items = {"oneOf": [ref("scope_entry"), ref("scope_source")]}
            return arr(items, PART_DOCS[name], 1)
        return arr(ref("scope_entry"), PART_DOCS[name], 1)

    props: dict[str, Any] = {}
    for group, leaves in scope_tree().items():
        if leaves is None:
            props[group] = part(group)
        else:
            props[group] = obj(
                {leaf: part(f"{group}.{leaf}") for leaf in leaves},
                desc=PART_DOCS[group],
                minProperties=1,
            )
    return obj(
        props,
        desc="The site's network scope: the one place a selection holds addresses (module config refuses address literals). It lives in the private overlay; public examples use documentation ranges only (RFC 5737, 2001:db8::/32, 3fff::/20), which tools/private_leak_check.py enforces. A module declares the parts it needs (requires.scope); a part a selected module needs is present (loader), and every reader fails closed.",
        minProperties=1,
    )


def module_selection_schema() -> dict[str, Any]:
    """A site's module selection (docs/modules.md): hosts, slot choices, bindings, grants, scope.

    Only the shape: every cross-reference (a provider fills the slot, an agent key exists, a grant
    is allowed) is a loader rule (``homelabnext/modules/rules.py``, ``site_problems``)."""
    mid = {
        "allOf": [pat(SLUG, None, 48), {"not": {"pattern": "-shadow$"}}],
        "description": "A module id.",
    }
    by_module = lambda items, desc: {  # noqa: E731
        "type": "object",
        "propertyNames": mid,
        "additionalProperties": arr(items, None, 1),
        "description": desc,
    }
    role_map = {
        "type": "object",
        "propertyNames": pat(SLUG, None, 64),
        "additionalProperties": pat(SLUG, None, 64),
        "description": "<host role> -> <site host>.",
    }
    config = {
        "type": "object",
        "propertyNames": {"pattern": "^[a-z][a-z0-9_]{0,63}" + G},
        "additionalProperties": {"type": ["string", "integer", "boolean"]},
        "description": "Real values for the module's config keys; a secret-typed value is a secret name in the module's own namespace or one it is granted in grants.secrets (loader).",
    }
    agents = {
        "type": "object",
        "propertyNames": pat(SLUG, None, 64),
        "additionalProperties": obj(
            {
                "lanes": obj(
                    {"real": pat(SLUG, None, 64), "shadow": pat(SLUG, None, 64)},
                    ["real"],
                    "Each lane bound to exactly one orchestration instance.",
                )
            },
            ["lanes"],
        ),
        "description": "Per agent key the module contributes (an unknown key is refused by the loader).",
    }
    binding = obj(
        {"placement": role_map, "config": config, "agents": agents},
        desc="One module's placement, real config values and lane bindings.",
    )
    capacity = obj(
        {
            "cpu": {"type": "number", "minimum": 0.1},
            "memory_mb": {"type": "integer", "minimum": 16},
            "disk_gb": {"type": "integer", "minimum": 0},
            "gpu_memory_mb": {"type": "integer", "minimum": 0},
        },
        ["cpu", "memory_mb", "disk_gb"],
    )
    host = obj(
        {
            "kind": {"enum": ["vm", "lxc", "host", "external"]},
            "isolated": {"type": "boolean"},
            "capacity": capacity,
            "resources": arr(
                obj({"name": pat(SLUG, None, 32), "kind": pat(SLUG, None, 32)}, ["name", "kind"])
            ),
            "headroom": obj({"memory_mb": {"type": "integer", "minimum": 0}}),
        },
        ["kind", "capacity"],
        "A site host; capacity stands in for its platform/guest resources.",
    )
    choice = obj(
        {
            "provider": mid,
            "instance": pat(SLUG, None, 64),
            "placement": role_map,
            "config": config,
        },
        ["provider", "instance"],
    )
    grants = obj(
        {
            "publish": arr(
                mid, "Modules that may require, prefer or fall back to cap:static-hosting."
            ),
            "egress": {
                "type": "object",
                "propertyNames": mid,
                "additionalProperties": {
                    "type": "object",
                    "propertyNames": pat(SLUG, None, 64),
                    "additionalProperties": arr(
                        {
                            "oneOf": [
                                {"enum": ["internet", "external"]},
                                {"$ref": LID + "svc_id"},
                            ]
                        },
                        None,
                        1,
                    ),
                },
                "description": "<module>: {<host role>: [targets]}: each internet or authority-service target the role may reach, and external for a role that runs outside the lab. A grant names its targets, so a manifest cannot widen a granted role's egress.",
            },
            "internet_facing": by_module(
                pat(SLUG, None, 64),
                "Host roles inside the lab (not kind external) that may be internet-facing.",
            ),
            "secrets": by_module(
                pat(SECRET, None, 128), "Granted credentials (holder: granted) a module may read."
            ),
            "public_routes": by_module(
                pat(SLUG, None, 64), "Service rows that may carry a public_hostname."
            ),
            "shared_config": by_module(
                {"enum": ["cap:edge", "cap:idp"]},
                "Privileged shared components a module may configure.",
            ),
            "units": by_module(
                pat(SLUG, None, 64), "Units that may run as root or opt out of hardening."
            ),
        },
        desc="Authority a module cannot give itself. A misspelt grant kind is refused, never read as no grant.",
    )
    scope = scope_schema()
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": BASE + "platform/module_selection/1.0",
        "x-draft": "ADR-0027 (proposed): the shape only, no loader yet; not frozen",
        "title": "Module selection",
        "description": "A site's selection of modules (docs/modules.md): hosts, providers per slot with placement, feature, core and provider bindings, the grants a module cannot give itself and the site's network scope. In an overlay it is lab/modules.yml; the public example profiles are examples/modules/sites/.",
        "type": "object",
        "additionalProperties": False,
        "required": ["profile", "hosts", "slots"],
        "properties": {
            "profile": pat(SLUG, None, 64),
            "hosts": {
                "type": "object",
                "propertyNames": pat(SLUG, None, 64),
                "additionalProperties": host,
            },
            "slots": {
                "type": "object",
                "propertyNames": pat(SLUG, None, 64),
                "additionalProperties": {
                    "oneOf": [{"enum": ["none", "pass-through"]}, arr(choice, None, 1)]
                },
            },
            "features": {"type": "object", "propertyNames": mid, "additionalProperties": binding},
            "core": {"type": "object", "propertyNames": mid, "additionalProperties": binding},
            "providers": {
                "type": "object",
                "propertyNames": mid,
                "additionalProperties": obj({"agents": agents}),
                "description": "Lane bindings for a selected provider's agents (its placement and config are per slot instance).",
            },
            "grants": grants,
            "scope": scope,
        },
        "$defs": {"scope_entry": scope_entry_schema(), "scope_source": scope_source_schema()},
    }


def _dump(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2) + "\n"


def render() -> dict[str, str]:
    """Repository-relative path -> committed text of each schema this module generates."""
    return {
        "schemas/platform/module.schema.json": _dump(module_schema()),
        "schemas/platform/lake_table.schema.json": _dump(lake_table_schema()),
        "schemas/platform/module_selection.schema.json": _dump(module_selection_schema()),
    }
