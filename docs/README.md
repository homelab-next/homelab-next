---
summary: 'Documentation home: the map of the docs, grouped by choosing a tool, running the systems, and decisions, status and scripts, plus use as an Obsidian vault.'
summary_of: outline:sha256:702487320cdddfa8
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Documentation home

The map of the documentation: start here on GitHub, or open this `docs/` folder as an
[Obsidian](https://obsidian.md) vault and use this page as its home. Every generated page links
both ways, with a relative Markdown link (for GitHub) and a path-qualified `[[folder/page|label]]`
wiki-link (for Obsidian), so the graph view shows how capabilities, systems, decisions and scripts
relate.

The sections, order and grouping below are authored; the description after each link is
generated from that page's front-matter `summary:` (`hnx docs index generate`, checked by
`hnx docs index check` in `make gates` and CI), so the index cannot drift from the pages. To change
a description, change the page's summary. The [ADR log](adr/README.md)'s one-line column is
generated and checked the same way.

## Choosing and integrating a tool

- [Capabilities](capabilities/README.md) ([[capabilities/README|Capabilities]]): <!-- hnx:gen:summary:capabilities/README.md -->Every capability contract: what it is for, how many operations and checks it has, and which adapters and services provide it.<!-- /hnx:gen -->
- [Conformance harness](conformance.md) ([[conformance]]): <!-- hnx:gen:summary:conformance.md -->The conformance harness: one suite per capability run against any target, how mutants prove a suite can fail, adding a suite, and the X-10 exporter.<!-- /hnx:gen -->
- [Swap procedure](swap.md) ([[swap]]): <!-- hnx:gen:summary:swap.md -->The swap kit for replacing a product behind a capability: nine steps, swap record, parity, dual-write, registry flip and promotion, decommission, rehearsal.<!-- /hnx:gen -->
- [Interface index](interfaces.md) ([[interfaces]]): <!-- hnx:gen:summary:interfaces.md -->The interface index: ownership map, package layout and signatures, command line, library surfaces, registry naming, logical ids, schemas and version policy.<!-- /hnx:gen -->

## Running the systems

- [Per-system SOP pages](systems.md) ([[systems]]): <!-- hnx:gen:summary:systems.md -->Per-system SOP pages: one operator page per registry service, how a page is built and generated, the check that keeps them current, and reviews.<!-- /hnx:gen -->
- [Architecture](architecture.md) ([[architecture]]): <!-- hnx:gen:summary:architecture.md -->Thirteen capability layers, the v0 slice, the spine, the swap procedure, the reference environment, Ansible host trust, and what is built versus needs a server.<!-- /hnx:gen -->
- [Build order](build-order.md) ([[build-order]]): <!-- hnx:gen:summary:build-order.md -->The build order: public phases P0-P9 provable in CI with fakes, server phases S1-S10, the v0 slice, experimental and frozen components, reading status.<!-- /hnx:gen -->
- [Network model](network-model.md) ([[network-model]]): <!-- hnx:gen:summary:network-model.md -->The vendor-neutral site model (site.yml): zones, router, switches, firewall intent and DNS policy, validation, rule order and adapters, with the UniFi dry run.<!-- /hnx:gen -->
- [Compute model](compute-model.md) ([[compute-model]]): <!-- hnx:gen:summary:compute-model.md -->The compute model: one vendor-neutral file per guest, its validation, generators for IaC, cloud-init, inventory, firewall and baselines, and applying them.<!-- /hnx:gen -->
- [Role interface](role-interface.md) ([[role-interface]]): <!-- hnx:gen:summary:role-interface.md -->Role interface version 1: argument specs, entry-point hooks, defaults, registry service names, inventory groups, compose_app, linter rules, timers, scaffolds.<!-- /hnx:gen -->
- [Log pipeline](log-pipeline.md) ([[log-pipeline]]): <!-- hnx:gen:summary:log-pipeline.md -->The log-pipeline contract: hnx_runtime from the guest model by the address the collector saw, hnx_tlp from the route's declaration; never the event.<!-- /hnx:gen -->
- [Events](events.md) ([[events]]): <!-- hnx:gen:summary:events.md -->The event seam: what goes on the bus, the envelope, validation, the idempotent publisher, forwarder contract, consumers, contract tests, deploy events.<!-- /hnx:gen -->
- [Detections](detections.md) ([[detections]]): <!-- hnx:gen:summary:detections.md -->Detections authored in a Sigma subset: layout, ATT&CK coverage counted only from tested rules, ATT&CK-id validation, known-id snapshots and writing tests.<!-- /hnx:gen -->
- [Behavioural novelty](novelty.md) ([[novelty]]): <!-- hnx:gen:summary:novelty.md -->The behavioural novelty analyzer: profiles in a spec, the scoring arithmetic, cold start, TLP labels, the novelty_finding table and corroboration.<!-- /hnx:gen -->
- [Workflows](workflows.md) ([[workflows]]): <!-- hnx:gen:summary:workflows.md -->Workflows as code: the YAML workflow pack, what hnx workflows validate checks, and deploying only pinned digests from passing commits.<!-- /hnx:gen -->
- [StackStorm](stackstorm.md) ([[stackstorm]]): <!-- hnx:gen:summary:stackstorm.md -->StackStorm decides when workflow packs run: ownership, pack mapping, automations, approved requests, redeliveries, coalescing, shadow mode, secrets, install.<!-- /hnx:gen -->
- [Decisions and models](decide.md) ([[decide]]): <!-- hnx:gen:summary:decide.md -->The decision cascade (floor, small, large, llm, then a human) and the model roles it calls, with the guarantees each rule keeps.<!-- /hnx:gen -->
- [LLM gateway](llm-gateway.md) ([[llm-gateway]]): <!-- hnx:gen:summary:llm-gateway.md -->The LLM gateway, where a role becomes a backend and model id: generated config, the locality rule, TLP labels on requests, lab-in-a-box, conformance, LiteLLM.<!-- /hnx:gen -->
- [The lab's own gateway](gateway.md) ([[gateway]]): <!-- hnx:gen:summary:gateway.md -->The lab's own LLM gateway, orchestrator/cmd/gateway (ADR-0038, ADR-0026): routes, flags, behaviour, limits, usage records, conformance in CI and cutover.<!-- /hnx:gen -->
- [Model serving](model-serving.md) ([[model-serving]]): <!-- hnx:gen:summary:model-serving.md -->Model serving behind the gateway: one model store, the serving spec, the model_store, vllm_server and open_webui roles, adding a model and GPU notes.<!-- /hnx:gen -->
- [LLM orchestrator](orchestration-controller.md) ([[orchestration-controller]]): <!-- hnx:gen:summary:orchestration-controller.md -->The orchestration controller: adapter, holds, history, gateway calls, optional features, its core in orchestrator/ and the controller binary.<!-- /hnx:gen -->
- [Orchestration telemetry](orchestration-telemetry.md) ([[orchestration-telemetry]]): <!-- hnx:gen:summary:orchestration-telemetry.md -->Orchestration telemetry: the agent job finished event contract, the names-and-numbers privacy rule, data flow, turn sources, hub page, export, recommendations.<!-- /hnx:gen -->
- [Code Mode build plan](codemode.md) ([[codemode]]): <!-- hnx:gen:summary:codemode.md -->The Code Mode build plan for ADR-0031: phase 1 read-only steps CM-1 to CM-6, phase 2 hardening, later phases, open questions, and which steps are built.<!-- /hnx:gen --> Proposed (ADR-0031).
- [Agent profiles](agent.md) ([[agent]]): <!-- hnx:gen:summary:agent.md -->Agent profiles compiled under a policy ceiling, schemas, the context-pack assembler, session access block, include rules, keyring, memory and broker contracts.<!-- /hnx:gen -->
- [Broker service](broker.md) ([[broker]]): <!-- hnx:gen:summary:broker.md -->The broker service: named actions decided allow, deny or needs-approval, lanes, exec handlers, approvals, state, Code Mode tokens, running it and its MCP tools.<!-- /hnx:gen -->
- [Scope guard](scope.md) ([[scope]]): <!-- hnx:gen:summary:scope.md -->The scope guard writer tools call before writing about a target, so throwaway or scratch targets are skipped: policy as data, resolution then decision.<!-- /hnx:gen -->
- [Customization](customization.md) ([[customization]]): <!-- hnx:gen:summary:customization.md -->Customizations: first-class records of lab or vendor deviations with an owner, reason and review date, their file, links, conflicts, lifecycle and upstreaming.<!-- /hnx:gen -->
- [Decommission audit](decommission.md) ([[decommission]]): <!-- hnx:gen:summary:decommission.md -->The read-only decommission audit: hnx decommission check, its statuses, the planes it inspects, adapters and fakes, and a positive control.<!-- /hnx:gen -->

## Decisions, status and scripts

- [Status hub](status.md) ([[status]]): <!-- hnx:gen:summary:status.md -->The read-only status hub: sources, views, the status.json contract, events, agent activity, the mTLS edge hop from both sides and the Approvals page.<!-- /hnx:gen -->
- [Status source catalog](status/sources.md) ([[status/sources|status sources]]): <!-- hnx:gen:summary:status/sources.md -->The status hub menu: every status source a service offers, with its module, kind, interval, stale-after window and what it reports.<!-- /hnx:gen -->
- [Architecture decision log](adr/README.md) ([[adr/README|ADRs]]): <!-- hnx:gen:summary:adr/README.md -->Index of the architecture decision log: how ADRs are numbered and checked, with a one-line entry per decision.<!-- /hnx:gen -->
- [A four-box lab, end to end](four-box-lab.md) ([[four-box-lab]]): <!-- hnx:gen:summary:four-box-lab.md -->A worked four-machine lab (hypervisor, physical sensor, detonation box, secondary DNS) that validates and renders end to end, and how to make it yours.<!-- /hnx:gen -->
- [Public repository and private overlay](private-overlay.md) ([[private-overlay]]): <!-- hnx:gen:summary:private-overlay.md -->The public repo and the private overlay: where data lives, how hnx finds it, encryption, bootstrap, reviews, the pinned commit, deploys and SSH certificates.<!-- /hnx:gen -->
- [Checklist](checklist.md) ([[checklist]]): <!-- hnx:gen:summary:checklist.md -->The completeness checklist: continuously true properties with runnable observables, in sixteen groups (F to X), each row PUBLIC-NOW or SERVER.<!-- /hnx:gen -->
- [Dated examples](example-dates.md) ([[example-dates]]): <!-- hnx:gen:summary:example-dates.md -->Every dated example and the day it falls due: CI judges some against the real date, so move the date or work the record in a reviewed change first.<!-- /hnx:gen -->
- [Strategy to task](strategy.md) ([[strategy]]): <!-- hnx:gen:summary:strategy.md -->Strategy to task: the record model, enforced link rules, registers machinery, doctrine policy, measures, RFIs from gaps, graph and hub, real strategy location.<!-- /hnx:gen -->
- [Strategy example index](strategy/README.md) ([[strategy/README|strategy index]]): <!-- hnx:gen:summary:strategy/README.md -->Generated index of the example strategy records: priorities of work, the objective cascade, requirements and RFIs, each shown by its computed number.<!-- /hnx:gen -->
- [Projects](projects.md) ([[projects]]): <!-- hnx:gen:summary:projects.md -->Projects as the sixteenth capability: the model and board rules, the Markdown reference, hub page, events, links to strategy records, the OpenProject adapter.<!-- /hnx:gen -->
- [Registers](registers.md) ([[registers]]): <!-- hnx:gen:summary:registers.md -->The registers of lessons, runbooks and invariants: uids, one file per record, the record format, links, events, status changes and lessons as backlog.<!-- /hnx:gen -->
- [Script catalog](scripts/catalog.md) ([[scripts/catalog|Script catalog]]): <!-- hnx:gen:summary:scripts/catalog.md -->Every script in the tree, read from its hnx-script header: id, path, kind, owner, purpose, triggers, invariant and exit codes.<!-- /hnx:gen -->
- [How the script catalog is kept true](scripts.md) ([[scripts]]): <!-- hnx:gen:summary:scripts.md -->Scripts: what counts as one, the hnx-script header, how triggers are discovered, the checks that keep the catalog true and the reviewed allowlist.<!-- /hnx:gen -->
- [Knowledge graph](graph.md) ([[graph]]): <!-- hnx:gen:summary:graph.md -->The knowledge graph of everything in the repo that names something else: commands, querying, node kinds, edge types and what is not in the graph yet.<!-- /hnx:gen -->
- [MCP server](mcp.md) ([[mcp]]): <!-- hnx:gen:summary:mcp.md -->The read-only stdio MCP server (hnx mcp serve) over this checkout: its tools, documents served in levels, its security model and the broker's tool server.<!-- /hnx:gen -->
- [MCP catalog](mcp-catalog.md) ([[mcp-catalog]]): <!-- hnx:gen:summary:mcp-catalog.md -->The MCP catalog, one record per MCP server: the record, fatal rules, adding a server, instances, rendering client configs, importing a lab and reviews.<!-- /hnx:gen -->
- [Feature and provider modules](modules.md) ([[modules]]): <!-- hnx:gen:summary:modules.md -->Draft module manifest for provider, feature and core modules (ADR-0027, proposed): why, words, layout, the manifest, the three kinds and its reference pages.<!-- /hnx:gen --> Draft (ADR-0027, proposed).
  - [Module loader checks](modules/loader.md) ([[modules/loader|module loader checks]]): <!-- hnx:gen:summary:modules/loader.md -->Module manifest reference: every rule the module loader checks over the manifests, the slot registry and a site's selection.<!-- /hnx:gen -->
  - [Loader at deploy time](modules/loader-deploy.md) ([[modules/loader-deploy|loader at deploy time]]): <!-- hnx:gen:summary:modules/loader-deploy.md -->Module manifest reference: the module loader at deploy time, the census of what runs and the notify pairs a notifier records.<!-- /hnx:gen -->
  - [Module apply path](modules/apply.md) ([[modules/apply|module apply path]]): <!-- hnx:gen:summary:modules/apply.md -->Module manifest reference: the apply path, from a checked selection to the per-module inventory groups and the install and check playbooks.<!-- /hnx:gen -->
  - [Module selection](modules/selection.md) ([[modules/selection|module selection]]): <!-- hnx:gen:summary:modules/selection.md -->Module manifest reference: a site's module selection (draft platform/module_selection 1.0): hosts, slots, incumbents, planned slots, bindings and grants.<!-- /hnx:gen -->
  - [Planned core slots](modules/planned.md) ([[modules/planned|planned core slots]]): <!-- hnx:gen:summary:modules/planned.md -->Module manifest reference: planned core slots, the required core slots a staged lab does not serve yet, each a warning with a review date.<!-- /hnx:gen -->
  - [Module registry rows](modules/registry-rows.md) ([[modules/registry-rows|module registry rows]]): <!-- hnx:gen:summary:modules/registry-rows.md -->Module manifest reference: registry equality, each selected module's service rows checked against the lab registry as the site binds them.<!-- /hnx:gen -->
  - [Slot registry](modules/slots.md) ([[modules/slots|slot registry]]): <!-- hnx:gen:summary:modules/slots.md -->Module manifest reference: the slot registry, requires and prefers, footprints, one-owner interfaces and the interchange formats of the SOC bundle.<!-- /hnx:gen -->
  - [Module contributions](modules/contributes.md) ([[modules/contributes|module contributions]]): <!-- hnx:gen:summary:modules/contributes.md -->Module manifest reference: what a module contributes and who approves it, the trust tiers selection grants, names bound to the module, agents.<!-- /hnx:gen -->
  - [Module data and lifecycle](modules/data.md) ([[modules/data|module data and lifecycle]]): <!-- hnx:gen:summary:modules/data.md -->Module manifest reference: the data block and lifecycle safety (export, import, retention), and how config, credentials and identifiers are declared.<!-- /hnx:gen -->
  - [Module egress](modules/egress.md) ([[modules/egress|module egress]]): <!-- hnx:gen:summary:modules/egress.md -->Module egress reference: declared egress as network policy, the publishing gate, ADR-0033 egress points and follow-ups for labelled requests.<!-- /hnx:gen -->
  - [Module TLP labels](modules/tlp.md) ([[modules/tlp|module TLP labels]]): <!-- hnx:gen:summary:modules/tlp.md -->Module manifest reference: TLP labels on module data, model-role ceilings, labelled model requests and the ceilings of agent profiles and MCP servers.<!-- /hnx:gen -->
  - [Network scope](modules/network-scope.md) ([[modules/network-scope|network scope]]): <!-- hnx:gen:summary:modules/network-scope.md -->Module manifest reference: the site's network scope, its parts, the strict reader and how module egress and references are judged against it.<!-- /hnx:gen -->
  - [Module supply chain](modules/supply-chain.md) ([[modules/supply-chain|module supply chain]]): <!-- hnx:gen:summary:modules/supply-chain.md -->Module manifest reference: placement and isolation of module code, and the supply chain of fetched modules (lock, digest, review).<!-- /hnx:gen -->
  - [Module swap flow](modules/swap-flow.md) ([[modules/swap-flow|module swap flow]]): <!-- hnx:gen:summary:modules/swap-flow.md -->Module manifest reference: how a module swap works end to end, the draft swap record 1.2, its evidence and the overlay's gate.<!-- /hnx:gen -->
  - [Product-name lint](modules/name-lint.md) ([[modules/name-lint|product-name lint]]): <!-- hnx:gen:summary:modules/name-lint.md -->Module manifest reference: the product-name lint (rule 1), its vocabulary, allowlist and shrinking baseline.<!-- /hnx:gen -->
  - [Module census](modules/census.md) ([[modules/census|module census]]): <!-- hnx:gen:summary:modules/census.md -->Module manifest reference: what the census gathers from hosts (agents, MCP servers, lake tables, service rows) and why other kinds are not gathered.<!-- /hnx:gen -->
  - [Module follow-ups](modules/follow-ups.md) ([[modules/follow-ups|module follow-ups]]): <!-- hnx:gen:summary:modules/follow-ups.md -->Module manifest reference: prerequisite record changes, the migration path, per-slot contract follow-ups, each follow-up's status, follow-up ADRs, open items.<!-- /hnx:gen -->
- [Glossary](glossary.md) ([[glossary]]): <!-- hnx:gen:summary:glossary.md -->Glossary of the project's terms, such as capability, seam, contract, fake and conformance, each defined in a short entry.<!-- /hnx:gen -->
- [Terms and scope](terms.md) ([[terms]]): <!-- hnx:gen:summary:terms.md -->What the project's words mean and its scope: our activity and how we use threat vocabulary, shared by every agent and reader.<!-- /hnx:gen -->

## Opening `docs/` as an Obsidian vault

1. In Obsidian choose **Open folder as vault** and pick this `docs/` directory (not the repository
   root: the links are written relative to `docs/`).
2. Open this page and pin it, or set it as the vault's home note.
3. Open **Graph view**. Capability pages link to the systems that provide them, systems link to
   their capability, their upstreams and their dependants.

Obsidian keeps its settings in `docs/.obsidian/`; that folder is ignored by git and never
committed. Links to source files (`../conformance/...`) leave the vault and only resolve on GitHub.

The generated pages, and the generated facts inside authored pages (`fact:NAME` spans, the same
comment markers as the systems pages: the capability names and counts, the tool classes, every
schema's version; `hnx docs facts generate` rewrites them), are checked in `make check` and CI:

```
hnx docs capabilities check                                # docs/capabilities/ is current
hnx docs systems check examples/services.yml docs/systems  # docs/systems/ matches the registry
hnx docs index check docs/README.md docs/adr/README.md    # index and ADR log descriptions match page summaries
hnx docs facts check                                       # capability names, tool classes, schema versions in pages
hnx scripts catalog --check                                # docs/scripts/catalog.* is current
hnx graph check                                            # no dangling edge or duplicate id
```
