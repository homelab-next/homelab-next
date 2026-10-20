# SPDX-License-Identifier: Apache-2.0
"""The node kinds and edge types the readers emit, with where each comes from.

The single table behind the package docstring, ``docs/graph.md`` and the generated
``docs/graph/README.md``; a test fails when a reader emits a kind or type missing here.
"""

from __future__ import annotations

#: kind -> (id form, defined by)
NODE_KINDS: dict[str, tuple[str, str]] = {
    "svc": ("svc:<service>", "examples/services.yml services"),
    "host": ("host:<host>", "examples/services.yml hosts"),
    "zone": ("zone:<zone>", "examples/services.yml zones (also keyring network principals)"),
    "product": ("product:<impl>", "registry impl; compose images"),
    "cap": (
        "cap:<name>",
        "conformance list + extended suites, registry, capabilities.yml, tool_classes.yml, "
        "inventory cap_* groups, profile provenance",
    ),
    "check": ("check:<cap>/<check-id>", "conformance/suites/<cap>.py SUITE.specs"),
    "adapter": (
        "adapter:<module>:<factory>",
        "target files (conformance/targets, compose/*/targets), client adapters a contract "
        "imports, each suite's make_fake",
    ),
    "compose": ("compose:<stack>/<service>", "compose/<stack>/docker-compose.yml"),
    "schema": ("schema:<path>", "schemas/<family>/*.json"),
    "make": ("make:<target>", "Makefile rules"),
    "ci": ("ci:<workflow>/<job>", ".github/workflows/*.yml jobs"),
    "pre-commit": ("pre-commit:<hook>", ".pre-commit-config.yaml hooks"),
    "pkg": ("pkg:homelabnext[.<sub>]", "homelabnext/ packages"),
    "script": ("script:<id>", "docs/scripts/catalog.json"),
    "lesson": ("lesson:LL-NNN", "examples/registers/lessons.yml"),
    "runbook": ("runbook:RB-NNN", "examples/registers/runbooks.yml"),
    "inv": ("inv:<criterion>", "examples/registers/invariants.yml criteria"),
    "system": ("system:<tag>", "lesson/runbook systems tags"),
    "test": ("test:<path>", "a lesson's retired_by naming a test file"),
    "profile": (
        "profile:<name>",
        "keyring sources' profile specs; keyring agent principals without a spec",
    ),
    "human": ("<issuer>:<subject>", "keyring human principals (broker approvers)"),
    "skill": ("skill:<name>", "a compiled profile's provenance (parts library)"),
    "persona": ("persona:<name>", "a compiled profile's provenance (parts library)"),
    "mdl": ("mdl:<role>", "examples/model_roles.json roles"),
    "mcp": ("mcp:<slug>", "tool_classes.yml mcp; registry mcp.name"),
    "manifest": ("manifest:<id>", "context manifests found by the agent lint"),
    "broker": ("broker:<manifest_id>", "the keyring sources' broker manifest"),
    "action": ("action:<name>", "broker manifest actions"),
    "custom": ("custom:<name>", "profiles/*/customization.yml"),
    "role": ("role:<name>", "ansible/roles/*"),
    "playbook": ("playbook:<name>", "ansible/playbooks/*.yml"),
    "doc": ("doc:<path>", "tracked Markdown pages (not tests, examples or docs/graph/)"),
    "adr": ("adr:<slug>", "docs/adr/NNNN-<slug>.md"),
    "status": ("status:<source>", "examples/services.yml status_sources (the status hub's menu)"),
}

#: type -> (from kind(s), to kind(s), asserted by)
EDGE_TYPES: dict[str, tuple[str, str, str]] = {
    "provides": ("svc, compose", "cap", "registry capability; a compose service named after a cap"),
    "runs": ("svc, compose", "product", "registry impl; compose image"),
    "runs_on": ("svc", "host", "registry host"),
    "in_zone": ("host", "zone", "registry hosts.zone"),
    "depends_on": ("svc", "svc", "registry upstreams"),
    "serves": ("svc", "zone", "registry clients"),
    "exposes": ("svc", "mcp", "registry mcp"),
    "implements": ("adapter", "cap", "target binding, contract import, make_fake"),
    "faked_by": ("cap", "adapter", "suite make_fake"),
    "for": ("adapter", "product", "a compose stack's target file + that stack's image"),
    "checked_by": ("cap", "check", "suite specs"),
    "loads_schema": ("cap", "schema", "schema paths the contract's code loads"),
    "refs": ("schema", "schema", "$ref"),
    "triggered_by": (
        "script",
        "make, ci, pre-commit, compose, script, pkg",
        "catalog trigger",
    ),
    "enforces": ("script", "inv", "catalog invariant"),
    "reads": ("script", "any node owning the path", "catalog inputs"),
    "about": ("lesson, runbook", "system", "systems tags"),
    "resolves_to": ("system", "svc, cap, product", "a tag exactly equal to the name"),
    "operates": ("runbook", "svc", "a systems tag resolving to a service"),
    "controlled_by": ("lesson", "runbook, inv, lesson", "an id in preventive_control"),
    "mentions": ("lesson, runbook", "lesson, runbook, inv", "an id in another text field"),
    "verified_by": ("lesson", "script, pkg, make", "verification.observable command"),
    "invokes": ("runbook", "script, pkg, make", "commands in step do/verify"),
    "checks": ("inv", "script, pkg, make", "observable command; plugin owner"),
    "retired_by": ("lesson", "inv, test", "retired_by"),
    "superseded_by": ("lesson", "lesson", "superseded_by"),
    "incorporated_into": ("lesson", "runbook, doc", "incorporated_into"),
    "from_lesson": ("runbook", "lesson", "from_lessons (runbook or step)"),
    "uses": ("profile, manifest", "skill, persona, cap, mcp", "parts, persona, skills, tools"),
    "uses_model": ("profile", "mdl", "model_role"),
    "backed_by": ("mdl", "svc", "model role bindings[].backend"),
    "falls_back_to": ("mdl", "mdl", "model role fallback"),
    "defines": ("broker", "action", "broker manifest actions"),
    "grants": (
        "profile, human, zone",
        "cap, mcp, action, svc, broker",
        "keyring principals[].grants (attrs: level, approval)",
    ),
    "applies_to": ("custom", "cap, svc, host", "customization scope"),
    "governed_by": ("custom", "adr", "customization contract"),
    "links": ("custom, doc, adr", "any", "customization links; Markdown and [[wiki]] links"),
    "documents": ("doc", "svc, cap", "docs/systems/<svc>.md, docs/capabilities/<cap>.md"),
    "targets": ("playbook", "cap", "a cap_<name> hosts group"),
    "applies": ("playbook", "role", "play roles"),
    "observes": (
        "status",
        "svc, cap",
        "registry status_sources (declaring service, its capability)",
    ),
    "polls": ("status", "svc", "registry status_sources target.service"),
}
