---
summary: 'Module manifest reference: prerequisite record changes, the migration path, per-slot contract follow-ups, each follow-up''s status and open questions.'
summary_of: outline:sha256:59ec989c77b36c2c
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: record changes, migration and follow-ups

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed).

## Prerequisite record changes

| Record | Change | State |
|---|---|---|
| `platform/capability` 1.1 | the slot registry fields above; derived `implementations` | **draft schema** `platform/slot` 1.0 holds the fields and rules; `examples/modules/slots.yml` is validated against it; capability stays 1.0 until acceptance |
| `platform/swap_record` 1.2 | above | **draft schema** `platform/module_swap` 1.0 holds the additions and their rules; the record stays 1.1 until acceptance |
| `platform/module_selection` 1.0 | above | **draft schema** (the three example profiles are its examples) |
| `platform/interface` 1.0 | the owned interface record (inline in the owner's manifest) | **draft schema**: the shape of a manifest `interfaces:` entry, generated from it and changing with it until acceptance; no standalone loader; `gate` on the definition and on the gate's consuming entry |
| `platform/lake_table` 1.0 | owner, schema, retention, maintenance, freshness | **draft schema** |
| `registers/invariant` 1.1 | ids `^[A-Z]-NN$` **or** `<module id>/<slug>`, never a pillar letter in a module | specified |
| `platform/service` 2.7 | status source `module` renamed `group`, `module` kept as a deprecated alias for one minor | specified |
| `platform/role_interface` 1.1 | `tasks/import.yml`; `provides`/`requires` optional and derived from the manifest (hooks kept) | specified |
| `platform/guest` | several modules per guest (today one `capability` per guest) | follow-up |

## Migration path (no code moves in this draft)

1. Product-shaped code in core packages (about 28 adapter-shaped files) moves to provider modules
   one slot at a time behind the existing contract: lake, projects, automation, detection backends,
   status collectors (renamed to slot kinds), the front-door, metrics, identity and gateway
   renderers, serving engines, compute and network targets, notify senders, the conformance
   adapters, the secrets lookup's backend. Standard-contract slots first.
2. Contracts that import from adapters (`inference.py`, `classifier.py`) are inverted first.
3. Hard-coded selections become `provider_for(slot, instance)`.
4. Central lists become contributions; new entry-point groups are added as each lands (generators,
   status collectors, compute targets, network adapters, detection backends, serving engines, MCP
   clients, conformance adapters, capabilities), never promised in the schema first.
5. Agents: each feature agent's definition sites collapse into its block; staff agents into
   `core-staff`; the runtime dependency moves behind `agent-runtime`.
6. Pilots: the external data collector, then a greenfield module, then the sandbox (the first real
   interface). The schema is frozen when the ADR is accepted after the pilot.

## Contract follow-ups (per slot)

| Slot | Follow-up |
|---|---|
| `events` | State the contract over CloudEvents with bus semantics as features. |
| `dns` | The DNS protocol and RFC 2136 as the contract, zone files as export; promote `dns`, `edge` and `backup` from extended suites. |
| `idp` | OIDC (discovery, JWKS, introspection). |
| `edge` | It is the front door and a privileged slot: its extended suite becomes a full contract before any provider is selected through a module. |
| `secrets` | Keep the semantics, add a neutral encrypted export. |
| `notify` | The `Sender`/`Message.click` contract is ntfy-shaped (one product's priorities, tags and click actions); state it over neutral fields with product mapping in providers. The 100+ files that name the product are migration-path work. |
| `lake-catalog` | The Iceberg REST catalog as the contract. |
| `records` | "Markdown files with front matter and relative links". |
| `inference`, `fast-classifier` | Result types out of the adapters; generic load and parse-error signals; a classifier error field named by the contract, not by one product; decision-spec tiers named by `fast-classifier` **instance**, never by product. |
| `orchestration` | Neutral JSONL job records (a superset of the job-finished record), neutral session fields. |
| `agent-runtime` | New slot: dispatch with prompt, tool grant and deadline; usage, exit reason, session id. |
| every suite | A MUST that tests field **meanings** in the boundary format; semantic differences become features a dependant can require. |
| provisional slots | `metrics`, `siem-source`, `hot-index`, `soar`, `threat-intel`, `ioc-enrichment`, `remote-admin`, `exposure-management`, `static-hosting`, `compute`, `network`, `status`, `mcp-catalog`, `agent-runtime`: start from Prometheus, OCSF, STIX/TAXII, SARIF. |

Out of scope here: merging the several "product store" MCP servers into one mechanism (one
mechanism, one server) belongs to the MCP catalog.

## The follow-ups: each one's status

Each item below is a follow-up before the ADR can be accepted, or is listed as deferred. Most are
now implemented (a schema, a generator or a check, named in the item): items 4 to 10 are, and items
1 to 3 are implemented as draft schemas and rules, with folding into the released records waiting
for acceptance. What remains is stated in each item as "Not done" or "waits for acceptance": the
standalone interface loader (3), a provider that proves import validation (7), a run at a real
lab's deploy (9), and the slot-level export/import round trip with a slot-keyed X-07 (listed at the
end of this section, and in [`data:` and lifecycle safety](data.md#data-and-lifecycle-safety)). The
sections marked **specified, not implemented** on these pages are the ones that still
exist in no form.

1. **Capability descriptor 1.1**: the fields and rules exist as the draft `platform/slot` 1.0, and `slots.yml` is validated against it; folding them into the descriptor waits for acceptance.
2. **Swap record 1.2**: `legs`, `selection_diff` and `dependants.report` are defined in the draft
   `platform/module_swap` 1.0 and one swap is driven through its rules end to end in a test;
   folding it into the swap record and the swap kit (`hnx swap`) waits for acceptance.
3. **`platform/interface` 1.0**: the shape of a manifest `interfaces:` entry, published as a draft
   schema generated from the manifest's definition (it changes with it until acceptance, then only
   with a version bump); `gate: true` on the definition and on the gate's consuming entry, with the
   rules that the gate module owns the interface and never provides it (see
   [Interfaces: one owner](slots.md#interfaces-one-owner-platforminterface-10-a-draft-schema)). Not done:
   a loader for standalone records (the shape has no owner field), and any check on an interface
   nobody marks as a gate.
4. **Trust-tier grants**: implemented as site rules (`homelabnext.modules.rules.site_problems`, see
   [Trust tiers](contributes.md#trust-tiers-what-selecting-a-module-grants)): `grants.units` for a unit that runs
   as root or opts out of hardening, `grants.shared_config` for edge or idp config,
   `grants.upstreams` for a broker, idp or remote-admin upstream, and `grants.cloud_models` for a
   required model role whose prompts can leave the lab (`leaves_lab` on a binding, model roles
   1.3). An upstream is judged by what it reaches on the site, through a fallback or an instance;
   a contributed agent's model role is one its module requires. Each grant names only what a
   selected module uses, or it is refused as stale. The site rules take the units, rows and role
   table as required inputs, so none is skipped; the loader passes them. The per-field review tier
   for in-tree manifests is implemented as a classification and a code-owner check
   (`homelabnext.modules.review_tier`, `hnx modules review-tier`, run in CI; see
   [Trust tiers](contributes.md#trust-tiers-what-selecting-a-module-grants)); the approval itself is the pull
   request's code-owner review as of the base, so it is only as strong as the branch ruleset that
   requires it: today's ruleset requires the CI checks but no review, and with the `*` owner line
   it would be near-vacuous even if it did.
5. **Supply chain**: implemented (see [Supply chain](supply-chain.md#supply-chain)); the loader runs the check.
6. **The egress generator**: implemented (see [Egress and publishing](egress.md#egress-and-publishing));
   `hnx modules render` writes it for a site that checks clean.
7. **Import validation**: implemented as a library, a draft schema and the `migration` suite (see
   [`data:` and lifecycle safety](data.md#data-and-lifecycle-safety)); no provider proves it until its
   slot protocol gains `export` and `import_`.
8. **Footprint limits**: implemented for fleet units and data roots (see
   [Footprint and resources](slots.md#footprint-and-resources)); `hnx modules render` writes them.
9. **The loader**: implemented (see [What the loader checks](loader.md#what-the-loader-checks)):
   discovery with the overlay-shadowing refusal, schema validation first, every rule with every
   input, uniqueness against the core's own names (reserved ids, registry service rows, the core
   MCP catalog's ids, the keyring's agent keys, the core's OCSF tables and their namespace, and
   the core's notify pair titles), the supply chain, and the two-way check against an inventory
   of what runs, recovery pairs included; `hnx modules check|render`, run over the example lab in
   `make gates` and CI, and at deploy time by the private overlay's deploy workflow (`--deploy`,
   before the deploy, and again after it against the fleet units gathered from the hosts by role
   `module_census` and `hnx modules gather`; see
   [The loader at deploy time](loader-deploy.md#the-loader-at-deploy-time)). Not done: it has not run at a real
   lab's deploy yet; service rows are not gathered by name (a gathered inventory names them in
   `not_gathered` and judges each by what its host listens on); the agents come from the running
   broker, the MCP servers from the installed client configurations, the lake tables from the
   catalog on its own host (where the overlay names one) and the recovery pairs from the notifiers'
   records. The core's own
   units are read from its roles and generators, so a running unit that is no module's or the
   core's is a problem.
10. **The product-name lint**: implemented (see [The product-name lint](name-lint.md#the-product-name-lint-rule-1));
    the core's existing product names are a baseline that only shrinks.
11. **The slot-level round trip** (ADR-0027 decision 8): not done. Only the migration protocol
    has `export` and `import_` (`conformance/protocols/migration.py`); no stateful slot's protocol
    does, there is no MUST round-trip check per slot, and X-07 is not slot-keyed. See
    [`data:` and lifecycle safety](data.md#data-and-lifecycle-safety).

## Open questions

The operator answered the twelve questions of the first draft provisionally (2026-10-23), and
question 13 since; this draft applies those answers, and the operator may override any of them.

| # | Question | Provisional answer, as applied |
|---|---|---|
| 1 | ADR number | **0027**: 0025 is orchestration telemetry (merged); 0026 (the orchestrator component) is held by planned work and the ADR log test lists it as reserved |
| 2 | Selection schema | its own **`platform/module_selection` 1.0** (specified above) |
| 3 | Core components | **`kind: core`**, also the home of the staff agents and core consumers |
| 4 | Module criterion ids | **`<module>/<slug>`**, registers/invariant 1.1; the examples no longer use placeholders |
| 5 | Inline records | `lake_tables` promoted to **`platform/lake_table`** (draft schema); `notify_pairs` stays inline as **the notifier's only source** |
| 6 | Slot declarations | **capability descriptor 1.1** as a prerequisite (stage, formats, stateful + export formats, provisional, required in core; implementations derived) |
| 7 | External hosts | **deferred to the pilot**; `kind: external` is placement and footprint only |
| 8 | Exclusive resources | **named on the site host** (`gpu0`), requested by kind with `exclusive: true` |
| 9 | Status `module` field | renamed **`group`** in service 2.7 with a deprecated alias (spec only) |
| 10 | Where modules live | **`modules/<id>/`** and overlay **`lab/modules/<id>/`**, `hnx_modules` namespace package, no shadowing |
| 11 | Licence probes | **warn at 30 days, page the owner at 7, red on expiry** (**specified, not implemented**: no probe reads `licence.expires` yet) |
| 12 | Reviews | manifests **join the review policy**; human approval for credentials, control plane, data grants, egress and privileged slots |
| 13 | Where the site's network scope lives | in the **private overlay's selection** (`scope:` in `lab/modules.yml`); the public repository holds the schema, documentation-range examples and the enforcement ([the network scope](network-scope.md#the-network-scope); decided 2026-10-23) |

Still open:

- **The licence-expiry probe** (decision 11): specified, not implemented. No invariant, rule or
  timer reads `licence.expires`; build it as an invariant before relying on it.
- **Downtime migrations and derived-data rebuilds.** Some swaps need ordered downtime, and some data
  is rebuilt rather than exported (an embedder swap invalidates every vector, which must be
  re-embedded from the source records). Candidate fields: `migration.downtime: true` and
  `dataset.rebuild_from: <dataset>`, with the swap record gating on the rebuild's completion.
- **The ntfy-shaped notify contract**: the follow-up above needs its own design before notify
  providers become modules.
- **Which layer-1 slots are strictly required** once revision 3's carve-down applies: the draft
  marks secrets, idp, edge, dns, backup, notify, events, broker, orchestration, records,
  agent-runtime and inference as required, and the lake as optional (single-box falls back to the
  hot index).
- **Contracts for privileged slots that lack one** (`edge` has only an extended suite): until they
  exist no module can provide them, by the privileged-slot rule.
- **The loader's own trust boundary**: whether module code runs in-process (as specified) or in a
  sandboxed worker for third-party origins.
- The `contributions` decommission plane is specified, not implemented: the loader accepts it in
  `lifecycle.remove.audit`, but `hnx decommission` has no such plane, so nothing audits it yet.
