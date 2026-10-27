---
summary: Products live only in provider modules filling slots from a slot registry; optional missions are feature modules.
summary_of: outline:sha256:e2334f5f35796d84
---
# ADR-0027: Build the lab from provider, feature and core modules, each declared by one manifest

- **Status:** proposed
- **Date:** 2026-10-23
- **Related:** ADR-0002, ADR-0004, ADR-0005, ADR-0007, ADR-0008, ADR-0017, ADR-0018, ADR-0021,
  ADR-0024, ADR-0025 (orchestration telemetry, merged) and ADR-0026 (the orchestrator as a component,
  planned): the manifest relies on the former's job record for the orchestration export and on the
  latter for the `agent-runtime` slot. `schemas/platform/module.schema.json` (draft),
  [modules](../modules.md), [swap kit](../swap.md), [conformance](../conformance.md),
  [decommission audit](../decommission.md), [private overlay](../private-overlay.md)

## Context

A lab changes its products often: a resolver, a case manager, several project trackers, a
classifier replaced four times in ten days, models and agent runtimes, a lake query engine, an
object store. Each swap in a lab that grew without a boundary cost the same things: product names
and endpoints copied into dozens of shared files, defaults left pointing at the retired product, a
deploy chain that missed the new one, a scorecard still measuring the old system, a licence lapse
no check watched, and history dropped because no slot defined a neutral export. Features are
scattered the same way: one cloud-hosted collector's pieces sat in about 22 places across three
repositories, and one agent was defined in about 15. The core keeps hand-edited lists (recovery
pairs, scheduler entries, preflight branches, topology data, lake tables, runtime homes); a cutover
that edits most of them makes no noise about the rest, and one left a duplicate timer running and a
production lane writing where no consumer read.

This repository already has most sockets: capability contracts with conformance suites and fakes,
registry rows and generators, the role interface with its hooks, `fleet_units`, notify recovery
pairs, status sources, invariant plugins (the one entry-point group), agent profiles with a
compiler and a separately owned ceiling policy, workflow packs, detections as code, the MCP catalog,
the broker's approval gate, the private overlay, the swap kit and the decommission audit. What it
lacks is the boundary: adapter code lives inside core packages, a dozen CLIs pick their product in
code, no contract defines export or import, nothing binds a feature's pieces together, and nothing
says what selecting someone else's module grants it.

## Decision

1. **No layer is tied to a product, the core included.** The lab is described by slots and
   modules: a swap is a configuration change, a conformance run and a data migration, never a code
   change in the core or in a feature module.
2. **Slots are capabilities with a registry.** Each slot has a descriptor (capability descriptor
   1.1, a prerequisite): its contract or none (then it is provisional, by declaration, so a typo is
   not a new slot), pipeline stage and boundary formats, whether it is stateful and in which neutral
   formats it exports, whether the core requires it, whether it is privileged, and whether it may be
   pass-through. Which modules implement a slot is derived from their manifests.
3. **Three module kinds, one manifest schema**, `platform/module` 1.0, a **draft** (`x-draft`, not
   frozen until a loader and the collector pilot have run), with a `manifest_version` field:
   - a **provider** fills slots with one product and is the only place a product name may appear;
   - a **feature** is an optional, removable mission that names slots, model roles, interfaces and
     host roles;
   - a **core** module (`core-*`) is always installed and never removed; it is the home of the staff
     agents and of the core consumers, so a swap's dependants re-check sees them.
4. **Dependencies are declared, hard or soft**, by slot, model role, interface and host role, with
   footprints over cpu, memory, disk and GPU memory (enforced as limits) and named exclusive
   resources. A soft dependency names its fallback, and a dataset bound to that slot moves with the
   fallback (with its own retention and formats there).
5. **Interfaces have one owner.** An interface (id and version, kind, item schema) is defined once,
   by the owning module or the core (the consumer, for a gate interface); providers reference it.
6. **The core keeps no list of features.** Modules contribute entries as records of existing types
   in their directory. **Authority is never contributed**: ceilings, broker actions, review policy,
   grants, tooling settings, hooks and instructions stay with their owners. A trust-tier table maps
   each contribution class to the gate and the approver it already has, and the overlay holds the
   grants a module cannot give itself: egress (including `publish`, the only way to reach the
   static-hosting slot), cross-module secret reads, public routes, privileged shared configuration
   and root units.
7. **Every name a module claims is bound to its id** (tables, det ids, units, roles, data and record
   prefixes, secrets, agent and profile ids, MCP records, criteria `<module>/<slug>`), reserved ids
   are refused, and an overlay module may not shadow a shipped one. Code is the module's own
   (`hnx_modules.<id>.`) or an allowlisted shared adapter.
8. **Every owned dataset has a neutral export and import**; every stateful slot's contract gains a
   round-trip check, and X-07 becomes slot-keyed. A removal never touches another module's data.
9. **Selection is site configuration in the private overlay** (`platform/module_selection` 1.0):
   providers per slot as instances, `none` or `pass-through` where the registry allows, placement,
   lane-to-orchestration-instance bindings, real configuration values, the grants, and the
   site's **network scope** (trusted, target and excluded addresses: the one place a selection
   holds addresses; a module declares the parts it reads and its reader fails closed). Consumers
   resolve a slot with `provider_for(slot, instance)` from the selection, never a product name.
   The public repository holds the selection schema, fictional profiles in the documentation
   ranges and the enforcement, never a real scope.
10. **Supply chain**: a module declares its origin (in-tree, a pinned git commit or a hashed
    archive); the overlay pins a fetched module's tree digest and keeps its reviews keyed by it, and
    manifests join the review policy with a human tier for credentials, control planes, data grants
    and egress.
11. **A product-name lint** enforces decision 3, model identifiers included.
12. **A swap is a phased record**, swap record 1.2: keyed on module ids, slots and instances (one
    record may link several slots), with export/import and a boundary check, a dependants re-check
    that includes the core, recorded meaning changes, revoked credentials, start-empty only with a
    reason, and routes that may be unchanged or not network routes at all.

## Consequences

- A swap touches the selection and a provider module; a removal touches one directory and is
  audited against its own manifest. Adding a feature edits no shared file.
- Today's gaps become data: provisional slots, missing export/import, product-shaped contracts.
- Work it obliges, in order: capability descriptor 1.1 (the slot registry); swap record 1.2;
  `platform/module_selection` 1.0; registers/invariant 1.1 (module criterion ids); service 2.7
  (the status hub's `module` field becomes `group`); role interface 1.1 with an import hook; the
  loader with its two-way check, grant checks and tree digests; contracts for the privileged slots
  that lack one; the product-name lint and its baseline; moving about 28 adapter-shaped files out of
  core packages; `provider_for(slot, instance)` in place of a dozen hard-coded selections.
- Harder: a quick experiment now needs a manifest. That cost is the point: a piece nobody declared is
  exactly the piece a cutover misses.
- The schema stays a draft and may change without a version bump until the ADR is accepted; then it
  is frozen and evolves additively like every other.

### What exists, and what is specified but not implemented

**Exists in this draft:** the draft schemas `platform/module` 1.0, `platform/module_selection` 1.0
and `platform/lake_table` 1.0 (`x-draft`; `tools/schema_check.py` refuses `x-draft` on any major
that has a frozen baseline, found by the `$id` name; that holds while the baselines are kept, which
its `--base` check enforces in CI by keeping `schemas/_frozen/` append-only: against a pull
request's base (unreadable is an error), or a push's previous tip, or `HEAD^` when that tip is zero
or gone (a new branch, a force-push), so a push compared with `HEAD^` sees only its last commit;
`main` has no branch protection, so these gates are advisory until it does), their generator (`python -m homelabnext.schemas`, checked in CI), the
fictional examples, and the loader's rules as pure functions applied to those examples by the
contract tests (`homelabnext/modules/rules.py`), each shown refusing a planted defect. There is no
loader: nothing reads a manifest at deploy time.

**Specified, not implemented** (described in [modules](../modules.md#specified-not-implemented-the-follow-ups),
with no schema, generator or check in any form):

1. capability descriptor 1.1 (the slot registry): its fields and rules are now the draft schema
   `platform/slot` 1.0, against which `examples/modules/slots.yml` is validated; the descriptor
   itself stays 1.0 until acceptance;
2. swap record 1.2: its additions (`legs`, `selection_diff`, the dependants report) are now the
   draft schema `platform/module_swap` 1.0 with its rules, and the documented swap runs through
   them in a test; the record and the swap kit stay 1.1 until acceptance;
3. `platform/interface` 1.0: the shape of a manifest `interfaces:` entry, published as a draft
   schema; `gate: true` on a gate interface's definition and on its gate's consuming entry, with
   the rules that the gate module owns it and never provides it (no standalone loader yet);
4. the trust-tier grants: implemented as site rules (`grants.units`, `grants.shared_config`,
   `grants.upstreams` for broker, idp and remote-admin, and `grants.cloud_models` for a model role
   with a `leaves_lab` binding, model roles 1.3); the loader passes the units, rows and role table
   they read; and the per-field review tier for in-tree manifests (`hnx modules review-tier` in
   CI classifies each changed module path and requires a valid code owner, as of the base, for
   every human-approve one, whose pull-request review is the approval, near-vacuous while one `*`
   owner owns everything; fetched modules keep the flat tier of follow-up 5);
5. the supply chain: implemented (`homelabnext.modules.supply`: the tree digest, the draft schema
   `platform/module_lock` 1.0 for `lab/modules.lock`, and reviews keyed by the digest against the
   new review-policy kinds `module-provider`, `module-feature` and `module-core`); the loader runs
   the check;
6. the egress generator: implemented (`homelabnext.modules.egress`: an nftables ruleset per lab
   host that lets each module role's slice open connections only to its DNS, its required and
   preferred slots, its `svc:` targets and, when declared, global unicast outside the lab;
   isolated roles reach nothing; inbound, loopback, containers in their own network namespace and
   root processes are not covered); hosts carry `addresses` in the selection, and `hnx modules
   render` writes it;
7. import validation: the MUST is implemented as a library (`homelabnext.modules.importcheck`),
   the draft schema `platform/export_manifest` 1.0 and the extended `migration` suite. Beyond
   traversal, links and oversize trees it also refuses hard links, other filesystems and mount
   points (failing closed on an unreadable mount table) and case-folding collisions. No provider
   proves it yet: no slot protocol has `export` and `import_`, so the suite runs only the
   reference importer, labelled as each stateful slot;
8. footprint limits: implemented for fleet units and data roots (`homelabnext.modules.limits`: a
   slice per placed host role with `CPUQuota`, `MemoryHigh`, `MemoryMax` and no swap, the module's
   fleet units in it, and a reserved disk cap per data root by ZFS `refquota` or an allocated image
   mount); a role's own services join by `Slice=`, and `hnx modules render` writes them;
9. the loader: implemented (`homelabnext.modules.loader`, `hnx modules check|render`, in `make
   gates` and CI over the example lab): discovery with the overlay-shadowing refusal, schema
   validation before any rule, every rule with every input, uniqueness against the core's own
   names (its registry rows, MCP catalog ids, keyring agent keys and OCSF tables), the supply
   chain, and the two-way check against a hand-written inventory (the draft
   `platform/module_inventory` 1.0), recovery pairs included. Not done: running it at deploy time,
   gathering the inventory from the hosts, and the core's own units, which have no source;
10. the product-name lint: implemented (`tools/product_name_lint.py`, invariant X-11, in `make
    gates` and CI), with the core's existing product names as a baseline that only shrinks.

These are the follow-ups. The ADR is not accepted, and the schemas are not frozen, until the loader
has run at deploy time and the collector pilot has run.

## Alternatives

- **One module per VM.** Rejected: a host is placement, not a feature. One host runs several
  features, one feature spans an edge host outside the lab and a receiver inside it, and a host
  move would then be a module rewrite instead of one placement line.
- **Product-specific modules** (a module per product with its features inside it). Rejected: every
  swap would rewrite the feature's module, which is the coupling this decision removes.
- **No manifest** (conventions plus the existing registries and lints). Rejected: the conventions
  already exist and the scatter happened anyway; without one declaration per module there is
  nothing to compare a running system with.
- **A bundle record listing its members.** Rejected in favour of membership on the member: a list is
  what the core must not keep.
- **Staff agents inside the agent-runtime provider.** Rejected: a runtime swap would take the staff
  with it, and the dependants check would not see them; they live in a core module.
- **Module-contributed egress rules.** Rejected: a rule shipped by the module it protects leaves with
  that module; egress is an overlay grant checked by a core criterion.
- **Freezing 1.0 now.** Rejected: the loader has not run at deploy time and there is no pilot, and
  the pilot is where the first corrections will come from.
