---
summary: 'Module manifest reference: what a module contributes and who approves it, the trust tiers selection grants, names bound to the module, agents.'
summary_of: outline:sha256:d17934edc2dfe962
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: contributions, trust tiers, names and agents

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed).

## `contributes:` and who approves what

The core builds each registry from every selected module's entries; **the core keeps no list.**

| Key | Record type | Replaces |
|---|---|---|
| `roles` | an Ansible role (role interface v1) | hand-kept role lists |
| `services` | `platform/service` rows; host names a module host role | hand-kept rows; health, metrics, front-door routes, DNS, topology, dataflow derive from them |
| `status_sources` | `status:<id>` declared on the module's own rows; the list and the rows' sources are equal | collector lists |
| `notify_pairs` | inline `{problem, recovery}`: **the notifier's only source** (code stops registering pairs) | a title-keyed dictionary |
| `scheduler_jobs` | a `fleet_units` spec file, or `timer:<own role>/<name>` | per-feature scheduler blocks |
| `lake_tables` | a `platform/lake_table` record file (draft 1.0); the core's OCSF tables get the same records | the lake-maintenance list |
| `preflight` | `{role, hook: readiness\|health}` | a preflight monolith with product branches |
| `mcp_servers` | a `platform/mcp_server` record | per-runtime client configs |
| `agents` | one block per agent (below) | ~15 definition sites per agent |
| `invariants` | criteria, ids `<module>/<slug>` | criteria in one central register |
| `entry_points` | `{group, name, object}`; `group` is an existing group only (`homelabnext.invariants.checks`) | core dicts of adapters |
| `detections` | a Sigma rule with its `det:` id | rule numbers in charters |
| `workflow_packs` | a workflow pack | — |
| `docs` | a Markdown page | a hand-edited docs index |
| `shared_config` | `{target, file, reason}` typed keys the target's generator merges | quirks in shared config |

Derived rather than contributed: **backup membership** (from `data` and stateful slots), **network
flows and firewall edges** (from `requires`, service `upstreams` and `egress`), **install order**
(from `requires`). Alert rules and dashboards are a follow-up contribution key.

### Trust tiers: what selecting a module grants

Selecting a module runs its code in core processes and its playbooks as root on its hosts. Each
contribution class maps to the gate and approver that already exist; none adds authority by itself.

| Contribution class | What it can do | Gate | Approver |
|---|---|---|---|
| roles, playbooks, lifecycle | root on the module's placed hosts | role_lint; the review tier below | human (all modules) |
| adapters, control-plane readers, entry points | code in core CLIs and runners | own package or the shared-adapter allowlist; tree digest | human: `entry_points` and `control_plane` are always human-approve, and so is any file no contribution names (code, an adapter); a slot the module provides, requires, prefers or falls back to is human when it is a privileged slot, owner otherwise (`review_tier.py`) |
| fleet units | scheduled jobs | `fleet_units` rules (dynamic user, full hardening); M-02/M-04 through the loader; a unit with `run_as_root`, `user: root` or `hardening_opt_out` needs `grants.units.<module>: [<unit>]` (a site rule: the module rules no longer refuse it, the overlay decides) | overlay owner |
| service rows | routes, DNS, firewall edges | `public_hostname` needs `auth` other than `none` **and** `grants.public_routes`, whatever the auth; an upstream is a slot the module requires or prefers (following its fallback) or an instance it requires, and never `secrets`; a `broker`, `idp` or `remote-admin` upstream, or an instance that fills one of those slots, needs `grants.upstreams.<module>: [cap:broker\|cap:idp\|cap:remote-admin]`, judged by what the upstream reaches on the site (through a fallback too) | overlay owner |
| model roles | prompts sent to a model | a role the module requires is an alias (ADR-0007), and a contributed agent's spec names only a role the module requires (so the grant covers the agent too); a role with a binding marked `leaves_lab` (`platform/model_roles` 1.3: a backend outside the lab), on the role or down its fallback chain, needs `grants.cloud_models.<module>: [mdl:<role>]` | overlay owner |
| agents | an agent's profile | the overlay's `CeilingPolicy` (CODEOWNERS); compiled **only** with a policy | policy owner |
| MCP records | tools for agents | the catalog review policy from the core/overlay, never a policy beside the module | catalog reviewers |
| handoffs | broker actions | actions are a subset of the operator's broker manifest; never added to it | broker manifest owner |
| shared_config | keys in a shared component | never secrets, broker, mcp-catalog, records, orchestration, codemode-executor, codemode-runner; idp, edge or remote-admin only with `grants.shared_config.<module>: [cap:idp\|cap:edge\|cap:remote-admin]` (a site rule) | overlay owner |
| egress | traffic beyond required slots (a required or preferred slot is reached without a grant, by the roles its `hosts` names or every role; a privileged one is gated by the review tier, human) | `egress:` declared, from the module's own host roles, to services that exist; each internet or authority-service target, and `external` for a `kind: external` host role, is named in `grants.egress.<module>.<role>`; an internet-facing role inside the lab needs `grants.internet_facing`; static hosting needs `grants.publish` | overlay owner |
| secrets | credentials | own namespace; cross-module reads need `grants.secrets` | overlay owner |

**Never contributed**: ceilings, broker actions and approvers, review policy, grants, and runtime
**tooling settings, hooks and instruction files** (left out of the schema until the tooling catalog
ADR defines reviewed kinds for them). `contributes.ceilings` and `contributes.tooling` are schema
errors.

**Manifests join the review policy** (`review-policy.yml` kinds `module-provider`, `module-feature`,
`module-core`) with the human-approve tier for any change to `credentials`, `control_plane`, agent
`needs` (data grants), `egress`, or a privileged slot. The kinds exist for fetched modules (state
`locked` in `lab/modules.lock`, see [Supply chain](supply-chain.md#supply-chain)), where the example policy asks a
human approve of every one, flatter and stricter than this per-field tier. For **in-tree**
modules, which this repository's pull requests review, `homelabnext.modules.review_tier`
classifies every changed path under `modules/` and `examples/modules/` by the table above: a
change is **human-approve** when it reaches anything the table gives an approver other than the
module's owner (`credentials`, `control_plane`, `egress`, `data`, `lifecycle`, `interfaces`, an
agent (its definition, or `needs` that grow), roles, entry points, fleet units, service rows, MCP
records, `shared_config`, preflight hooks and workflow packs, a privileged slot it provides,
requires, prefers or falls back to, `requires.hosts` (which host roles its roles run on as root,
and their exposure and footprint) and `requires.scope` (the scope parts it may act on)), or the
module's `id`, `kind` or `origin`; a file in the module
takes the tier of the contributions that name it (directly or as a directory above it) **in the base
manifest**, and a file no contribution names there (code, an adapter) is human-approve. A file new
in the pull request is human-approve unless the base names a directory above it; the head's
manifest can only add human-rated names, never make a file owner, so a pull request cannot name
its own unreviewed file as docs. An interface schema, and the conformance target of a module that
provides a privileged slot, are human-approve files. Detections, docs, criteria, lake
tables, paging pairs and status sources, and every other field, are **owner**. It fails closed: a
new, removed or renamed manifest, one it cannot read (parsed like the loader: aliases, deep nesting
and size refused), a symbolic link anywhere on a changed path, a key the module schema does not
define, a list it cannot key, keys it cannot compare, a path outside a module directory, and,
without a readable slot registry at both ends, every slot change are human-approve. The inputs
that decide the tier are read **as of the base commit**: the module schema; the slot registry (the
union of the base's and the head's privileged slots, so neither side can drop one); and
CODEOWNERS. A change to any of those, to the two `review_tier.py` files, or to what runs it
(`homelabnext/gitbase.py`, `tools/schema_check.py`, `.github/workflows/ci.yml`) is itself
human-approve, and so is a change to the code they import directly from this repository, which
decides what they decide: `homelabnext/modules/loader.py` (`parse_yaml`, `contributed_files`,
`read_tree_file`), `swap_evidence.py` (the base reader and the swap gate), `swap.py`, `rules.py`,
`homelabnext/golden/pins.py`, `homelabnext/models/store.py` and `homelabnext/registry/models.py`;
to the commands that run them and set the exit code (`homelabnext/cli.py`,
`homelabnext/modules/cli.py`, `homelabnext/network/cli.py`); and to the readers every parse goes
through (`homelabnext/_yaml.py`, `homelabnext/modules/scope.py`). `GOVERNANCE` in `review_tier.py`
lists them all, and a test derives the direct imports of the two tiers, `swap_evidence.py` and
`swap.py`, so a new import that is not listed fails the suite. Their wider import tree is not
listed: CI runs the gates with the base commit's code (the `trusted-gates` job), so a pull request
cannot weaken its own gate through them, though it can still edit the workflow that runs the job
(below, "What runs the gate"). A change to what sets up CI's interpreter and packages
(`.github/actions/python-deps/action.yml`, `constraints/bootstrap.txt`, `constraints/ci.txt`,
`pyproject.toml`) and to the release transforms (`homelabnext/status/release_transforms.yml`,
`homelabnext/status/release.py`; ADR-0033 decision 7) is human-approve too. So is a change to what vouches for a model a swap rebinds to (the model store, the
evaluation reports, `examples/model-evals/` (the path the code reads; the directory does not exist
until a first vetting change adds a report) and the golden suites; see "Swap record 1.2"), and so
is a change to the model role table (`examples/model_roles.json`) or to a swap record
(`examples/swaps/`): `leaves_lab` and `fallback` are in no pin, yet they decide which modules need
`grants.cloud_models`, and a role's `tlp_ceiling` and a binding's `provider_terms` decide the role's
TLP ceiling (raising one is human-approve; see [Model-role ceilings](tlp.md#model-role-ceilings-adr-0033-decision-10)).
The overlay's equivalents (`lab/model_roles.json`, `lab/swaps/`) are rated by
`hnx site review-tier` ([private-overlay.md](../private-overlay.md)).

`hnx modules review-tier --base REV | --ci-base` prints each changed path's tier and fields (and
the job summary in CI, where the `trusted-gates` job runs it with the base commit's own code;
`--ci-base` takes the base by `homelabnext.gitbase.ci_base`, the rule `tools/schema_check.py
--ci-base` takes). The human approval is the pull request's **code-owner review**: the command fails when a
human-approve change has no valid owner (`@user`, `@org/team` or an email) in CODEOWNERS as of
the base, matched by GitHub's rules (the last matching line wins, `*` within a segment, `**`
across them, no character classes). It does not read approvals, so the guarantee is only as
strong as the branch ruleset's "Require review from Code Owners". **Today the check is
near-vacuous**: `main`'s ruleset requires the CI checks but no review at all, so the approval is
given by convention, not enforced; and CODEOWNERS's first line, `*`, gives every path an owner,
and the one owner reviews everything; the tier is the record of what needs care, and it starts to bite when ownership is
split. `make modules-review-tier` runs it locally against `BASE` (default `origin/main`); it is not
part of `make gates`, which has no base to compare with. The gates this table marks as implemented are rules
(`homelabnext/modules/rules.py`) that the loader runs (`hnx modules check`, over the examples in
`make gates` and CI, and at deploy time in the private overlay's deploy workflow).

### Names are bound to the module

| Name | Form |
|---|---|
| roles, entry-point names | `<id_>` or `<id_>_...` (`-` as `_`) |
| units, service rows, status sources, MCP records, agent keys, det ids | `<id>` or `<id>-...` (a provider's service row is keyed by its slot and renamed to the instance at bind time) |
| profiles | `profile:<agent key>` |
| tables | `table:<id_>.<name>` |
| data and interface prefixes | `<id>/...` in the slot they live in |
| records writes (lanes, write scopes, records-prefix data) | `<root>/<id>/` or `<root>/<id>-shadow/` (`findings`, `state`, `proposals`, `memory`) |
| secrets | `secret:<id>/...` |
| criteria | `<id>/<slug>` (registers/invariant 1.1) |

Reserved ids: `core`, `homelabnext`, `hnx`, `hnx-modules`, `lab`, `site`, `overlay`, `none`,
`pass-through`, `module`, `modules`, `all`, `any`, `self`, `shared`; and no id ends in `-shadow`
(the suffix names a shadow lane). "Starts with the id" means the id followed by a separator
(`-`, or `_` in the underscore forms), and a name belongs to the **longest** module id it is named
under: module `external` cannot claim `external_collector_edge` from `external-collector`. Across
modules, roles, entry-point names, agent keys, profiles, status sources, tables, identifiers, data
prefixes, MCP record ids, det ids, unit names and feature service rows are unique (a provider's
row is keyed by its slot and renamed to its instance), data prefixes do not overlap, and records
write prefixes (lanes, write scopes, records-prefix data) do not overlap. **Uniqueness against the
core's existing names** (its tables, units, det ids, profiles, roster keys) is specified, not
implemented: the core has no inventory of them for a rule to read.

### Agents: one block

```yaml
agents:
  - key: external-collector-analyst              # starts with the module id
    profile: profile:external-collector-analyst  # owned; never another profile (ceilings key on it)
    charter: agents/external-collector-analyst.md
    spec: agents/external-collector-analyst.spec.yml   # the one source of model role and capabilities
    needs:                                       # scopes only; caps == the spec's capabilities
      - {cap: cap:lake-query, access: read, scope: ['table:external_collector.sessions']}
      - {cap: cap:records, access: write, scope: [findings/external-collector/]}
    tools: [lake-query.query, records.write_note, external-collector-probe.last_batch]
    prompts: {real: prompts/....real.yml, shadow: prompts/....shadow.yml}
    schedule: {on_calendar: '*-*-* 06:10:00 UTC'}       # or trigger: {event: ...} | {interface: ...}
    roster: {recall: true}                       # staff codes are the overlay roster's
    lanes:
      real:   {writes: [findings/external-collector/, state/external-collector/]}   # production: real (default)
      shadow: {writes: [findings/external-collector-shadow/], compare_to: real}
```

- `needs` never names an authority slot (broker, secrets, idp, edge, remote-admin, mcp-catalog).
  Scopes are full table ids or prefixes with alphanumeric segments; write scopes are in the module's
  own namespace. A reader of untrusted text holds no acting capability (the compiler's reader rule:
  the object store is file-write), so the collector's analyst sees sample sidecars through the
  module's own read-only probe.
- **Lanes are per agent**: the real lane writes only `<root>/<id>/` and the shadow lane only
  `<root>/<id>-shadow/`, so shadow output never lands where consumers read. The selection binds
  each lane to exactly one orchestration instance (`features.<module>.agents.<key>.lanes: {real:
  platform, shadow: orchestrator}`; a core module's agents under `core.<id>`, a provider's under
  `providers.<id>`), and a binding for an agent key the module does not contribute is refused. A
  cutover is "real on the old instance, shadow on the new, then flip": expressible, and never a dual
  run.
- Tools are slot-named (`<slot>.<tool>`), and the slot is one the agent `needs` or one of the
  module's own MCP record ids, so a product-named tool (`northwind-objects.query`) is refused; the
  selected provider's MCP record implements them (its `capabilities` is the hook).
- The spec carries **no ceiling**: a module agent compiles only with the overlay's `CeilingPolicy`
  (the contract tests compile every example spec against one, and show compiling without one fails).
