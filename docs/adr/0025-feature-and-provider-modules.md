# ADR-0025: Build the lab from feature and provider modules, each declared by one manifest

- **Status:** proposed
- **Date:** 2026-10-23
- **Related:** ADR-0002, ADR-0004, ADR-0005, ADR-0008, ADR-0018, ADR-0021, ADR-0024,
  `schemas/platform/module.schema.json`, [modules](../modules.md), [swap kit](../swap.md),
  [conformance](../conformance.md), [decommission audit](../decommission.md),
  [private overlay](../private-overlay.md)

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
compiler, workflow packs, detections as code, the MCP catalog, the private overlay, the swap kit
and the decommission audit. What it lacks is the boundary: adapter code lives inside core packages,
a dozen CLIs pick their product in code, no contract defines export or import, and nothing binds a
feature's pieces together.

## Decision

1. **No layer is tied to a product, the core included.** The lab is described by slots and
   modules: a swap is a configuration change, a conformance run and a data migration, never a code
   change in the core or in a feature module.
2. **Slots are capabilities**: a contract, a conformance suite and adapters. Where a standard
   interface exists, the contract is that interface. A slot without a contract may be required and
   filled **provisionally**: named and checked, proven by attestation only, and visible as such.
3. **Two module kinds, one manifest schema**, `platform/module` 1.0, one `module.yml` per module
   directory, id equal to the directory name:
   - a **provider module** fills one or more slots with one product, and is the only place a product
     name may appear; it declares per slot its adapter, interchange formats, conformance target (or
     provisional reason) and neutral migration, plus the product's licence, credentials by secret
     name, vendor-held control-plane configuration and per-binding calibration;
   - a **feature module** is an optional, removable mission that names slots, model roles,
     interfaces and host roles, never products, and may belong to a bundle (membership on the
     member, never a bundle list).
4. **Dependencies are declared, hard or soft.** `requires` (capabilities with contract version,
   features and formats; model roles; interfaces other modules offer; hosts by role with a
   footprint) and `prefers` (each with a fallback behaviour and optionally a lighter slot), so the
   impact of removing or not selecting anything is computable. A feature offers interfaces to other
   modules by name and version, never by module.
5. **The core keeps no list of features.** Modules contribute their entries through the manifest
   (roles, registry rows, status sources, recovery pairs, scheduler jobs, lake tables, preflight
   hooks, MCP records, agents as one block each, tooling records, invariants, entry points,
   detections, workflow packs, docs, shared-component quirks), each a record of an existing type in
   the module directory. Authority (ceilings, broker actions, approvers, review policy) is never
   contributed. A loader will fail on a declared piece that is missing and on a running piece no
   manifest declares.
6. **Every owned dataset has a neutral export and import** and a retention; every stateful slot's
   contract gains export/import with a round-trip check, and X-07 becomes slot-keyed.
7. **Selection is site configuration in the private overlay**: which provider fills which slot (several
   per slot as instances, `none` or `pass-through` where allowed), where each module's host roles land,
   and the real configuration values. Consumers resolve a slot through one lookup, never a product
   name. The public repository ships fictional examples only, including three reference profiles.
8. **A product-name lint** enforces decision 3: product names (from provider manifests and an
   allowlist file) only inside provider modules, site configuration, ADRs, the changelog and prose;
   comments are skipped; existing findings are a baseline that only shrinks.
9. **A swap is a phased record** on the existing swap kit: plan from the selection change,
   conformance of the incumbent then the candidate (data plane and field meanings), dependants and
   downstream consumers re-checked, export/import with a parallel run, cutover, decommission audit
   including the module's own contributions, close.

## Consequences

- A swap touches one selection line and a provider module; a removal touches one directory and is
  audited against its own manifest. Adding a feature edits no shared file.
- The manifest makes today's gaps visible as data: provisional slots, missing export/import, and
  product-shaped contracts become a punch list rather than folklore.
- Work it obliges: the loader and its two-way check; entry-point groups for generators, status
  collectors, compute and network targets, detection backends, serving engines, MCP clients,
  conformance adapters and capabilities; moving about 28 adapter-shaped files out of core packages;
  `provider_for(slot)` in place of a dozen hard-coded selections; export/import and meaning checks in
  every stateful contract; role interface v1.1 with an import hook; the product-name lint and its
  baseline; a selection schema; namespaced module criterion ids.
- Harder: a quick experiment now needs a manifest. That cost is the point: a piece nobody declared is
  exactly the piece a cutover misses.
- The schema is strict and versioned like every other (frozen baseline, additive minors), so the
  manifest shape can grow without breaking existing modules.

## Alternatives

- **One module per VM.** Rejected: a host is placement, not a feature. One host runs several
  features, one feature spans an edge host outside the lab and a receiver inside it, and a host
  move would then be a module rewrite instead of one placement line.
- **Product-specific modules** (a module per product with its features inside it). Rejected: every
  swap would rewrite the feature's module, which is the coupling this decision removes, and a
  product that fills several slots would drag unrelated features with it.
- **No manifest** (conventions plus the existing registries and lints). Rejected: the conventions
  already exist and the scatter happened anyway; without one declaration per module there is
  nothing to compare a running system with, so a missed piece stays silent.
- **A bundle record listing its members.** Rejected in favour of membership on the member: a list is
  what the core must not keep, and removing a member would leave it stale.
