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
- [Swap procedure](swap.md) ([[swap]]): <!-- hnx:gen:summary:swap.md -->The swap kit for replacing a product behind a capability: nine steps, swap record, parity tools, dual-write, registry flip, decommission check and rehearsal.<!-- /hnx:gen -->
- [Interface index](interfaces.md) ([[interfaces]]): <!-- hnx:gen:summary:interfaces.md -->The interface index: ownership map, package layout and signatures, command line, library surfaces, registry naming, logical ids, schemas and version policy.<!-- /hnx:gen -->

## Running the systems

- [Per-system SOP pages](systems.md) ([[systems]]): <!-- hnx:gen:summary:systems.md -->Per-system SOP pages: one operator page per registry service, how a page is built and generated, the check that keeps them current, and reviews.<!-- /hnx:gen -->
- [Architecture](architecture.md) ([[architecture]]): <!-- hnx:gen:summary:architecture.md -->Thirteen capability layers, the spine, the swap procedure, the reference environment, Ansible host trust, and what is built versus needs a server.<!-- /hnx:gen -->
- [Build order](build-order.md) ([[build-order]]): <!-- hnx:gen:summary:build-order.md -->The build order: public phases P0-P9 provable in CI with fakes, server phases S1-S10 needing a real deployment, and how to read status.<!-- /hnx:gen -->
- [Network model](network-model.md) ([[network-model]]): <!-- hnx:gen:summary:network-model.md -->The vendor-neutral site model (site.yml): zones, router, switches, firewall intent and DNS policy, validation, rule order and adapters, with the UniFi dry run.<!-- /hnx:gen -->
- [Compute model](compute-model.md) ([[compute-model]]): <!-- hnx:gen:summary:compute-model.md -->The compute model: one vendor-neutral file per guest, its validation, and generators that render IaC, cloud-init, inventory, firewall, backups and baselines.<!-- /hnx:gen -->
- [Role interface](role-interface.md) ([[role-interface]]): <!-- hnx:gen:summary:role-interface.md -->Role interface version 1: argument specs, entry-point hooks, defaults, registry service names, inventory groups, compose_app, linter rules, timers, scaffolds.<!-- /hnx:gen -->
- [Log pipeline](log-pipeline.md) ([[log-pipeline]]): <!-- hnx:gen:summary:log-pipeline.md -->The log-pipeline slot contract: the hnx_runtime label set from a table generated from the guest model, joined on the address the collector saw, never the event.<!-- /hnx:gen -->
- [Events](events.md) ([[events]]): <!-- hnx:gen:summary:events.md -->The event seam: the CloudEvents-style envelope, validation, the idempotent publisher, forwarder contract, consumers, seam contract tests, deploy events.<!-- /hnx:gen -->
- [Detections](detections.md) ([[detections]]): <!-- hnx:gen:summary:detections.md -->Detections authored in a Sigma subset: layout, ATT&CK coverage counted only from tested rules, ATT&CK-id validation, known-id snapshots and writing tests.<!-- /hnx:gen -->
- [Workflows](workflows.md) ([[workflows]]): <!-- hnx:gen:summary:workflows.md -->Workflows as code: the YAML workflow pack, what hnx workflows validate checks, and deploying only pinned digests from passing commits.<!-- /hnx:gen -->
- [StackStorm](stackstorm.md) ([[stackstorm]]): <!-- hnx:gen:summary:stackstorm.md -->StackStorm decides when workflow packs run: ownership, pack mapping, automations, approved requests, redeliveries, coalescing, shadow mode, secrets, install.<!-- /hnx:gen -->
- [Decisions and models](decide.md) ([[decide]]): <!-- hnx:gen:summary:decide.md -->The decision cascade (floor, small, large, llm, then a human) and the model roles it calls, with the guarantees each rule keeps.<!-- /hnx:gen -->
- [LLM gateway](llm-gateway.md) ([[llm-gateway]]): <!-- hnx:gen:summary:llm-gateway.md -->The LLM gateway where a model role becomes a backend and model id: generated config, the locality rule, lab-in-a-box, conformance and running LiteLLM.<!-- /hnx:gen -->
- [Model serving](model-serving.md) ([[model-serving]]): <!-- hnx:gen:summary:model-serving.md -->Model serving behind the gateway: one model store, the serving spec, the model_store, vllm_server and open_webui roles, adding a model and GPU notes.<!-- /hnx:gen -->
- [LLM orchestrator](orchestration-controller.md) ([[orchestration-controller]]): <!-- hnx:gen:summary:orchestration-controller.md -->The LLM orchestrator measured as the orchestration capability: adapter, holds, result at a pinned commit, gateway model calls and checks, optional features.<!-- /hnx:gen -->
- [Orchestration telemetry](orchestration-telemetry.md) ([[orchestration-telemetry]]): <!-- hnx:gen:summary:orchestration-telemetry.md -->Orchestration telemetry: the agent job finished event contract, the names-and-numbers privacy rule, data flow, turn sources, hub page, export, recommendations.<!-- /hnx:gen -->
- [Code Mode build plan](codemode.md) ([[codemode]]): <!-- hnx:gen:summary:codemode.md -->The Code Mode build plan for ADR-0031: phase 1 read-only steps CM-1 to CM-6, phase 2 hardening, later phases, open questions, and which steps are built.<!-- /hnx:gen --> Proposed (ADR-0031).
- [Agent profiles](agent.md) ([[agent]]): <!-- hnx:gen:summary:agent.md -->Agent profiles compiled under a policy ceiling, schemas, the context-pack assembler, session access block, include rules, keyring, memory and broker contracts.<!-- /hnx:gen -->
- [Broker service](broker.md) ([[broker]]): <!-- hnx:gen:summary:broker.md -->The broker service: named actions decided allow, deny or needs-approval, lanes, exec handlers, approvals, state, Code Mode tokens, running it and its MCP tools.<!-- /hnx:gen -->
- [Scope guard](scope.md) ([[scope]]): <!-- hnx:gen:summary:scope.md -->The scope guard writer tools call before writing about a target, so throwaway or scratch targets are skipped: policy as data, resolution then decision.<!-- /hnx:gen -->
- [Customization](customization.md) ([[customization]]): <!-- hnx:gen:summary:customization.md -->Customizations: first-class records of lab or vendor deviations with an owner, reason and review date, their file, links, conflicts, lifecycle and upstreaming.<!-- /hnx:gen -->
- [Decommission audit](decommission.md) ([[decommission]]): <!-- hnx:gen:summary:decommission.md -->The read-only decommission audit: hnx decommission check, its statuses, the planes it inspects, adapters and fakes, and a positive control.<!-- /hnx:gen -->

## Decisions, status and scripts

- [Status hub](status.md) ([[status]]): <!-- hnx:gen:summary:status.md -->The read-only status hub: registering sources, collecting, views, the page and status.json contract, events, agent activity and the broker Approvals page.<!-- /hnx:gen -->
- [Status source catalog](status/sources.md) ([[status/sources|status sources]]): <!-- hnx:gen:summary:status/sources.md -->The status hub menu: every status source a service offers, with its module, kind, interval, stale-after window and what it reports.<!-- /hnx:gen -->
- [Architecture decision log](adr/README.md) ([[adr/README|ADRs]]): <!-- hnx:gen:summary:adr/README.md -->Index of the architecture decision log: how ADRs are numbered and checked, with a one-line entry per decision.<!-- /hnx:gen -->
- [A four-box lab, end to end](four-box-lab.md) ([[four-box-lab]]): <!-- hnx:gen:summary:four-box-lab.md -->A worked four-machine lab (hypervisor, physical sensor, detonation box, secondary DNS) that validates and renders end to end, and how to make it yours.<!-- /hnx:gen -->
- [Public repository and private overlay](private-overlay.md) ([[private-overlay]]): <!-- hnx:gen:summary:private-overlay.md -->The public repo and the private overlay: where data lives, how hnx finds it, encryption, bootstrap, the runner, reviews, review tiers and deploys.<!-- /hnx:gen -->
- [Checklist](checklist.md) ([[checklist]]): <!-- hnx:gen:summary:checklist.md -->The completeness checklist: continuously true properties with runnable observables, in sixteen groups (F to X), each row PUBLIC-NOW or SERVER.<!-- /hnx:gen -->
- [Strategy to task](strategy.md) ([[strategy]]): <!-- hnx:gen:summary:strategy.md -->Strategy to task: the record model, enforced link rules, registers machinery, doctrine policy, measures, RFIs from gaps, graph and hub, real strategy location.<!-- /hnx:gen -->
- [Strategy example index](strategy/README.md) ([[strategy/README|strategy index]]): <!-- hnx:gen:summary:strategy/README.md -->Generated index of the example strategy records: priorities of work, the objective cascade, requirements and RFIs, each shown by its computed number.<!-- /hnx:gen -->
- [Projects](projects.md) ([[projects]]): <!-- hnx:gen:summary:projects.md -->Projects as the sixteenth capability: the model and board rules, the Markdown reference, hub page, events, links to strategy records, the OpenProject adapter.<!-- /hnx:gen -->
- [Registers](registers.md) ([[registers]]): <!-- hnx:gen:summary:registers.md -->The registers of lessons, runbooks and invariants: uids, one file per record, the record format, links, events, status changes and lessons as backlog.<!-- /hnx:gen -->
- [Script catalog](scripts/catalog.md) ([[scripts/catalog|Script catalog]]): <!-- hnx:gen:summary:scripts/catalog.md -->Every script in the tree, read from its hnx-script header: id, path, kind, owner, purpose, triggers, invariant and exit codes.<!-- /hnx:gen -->
- [How the script catalog is kept true](scripts.md) ([[scripts]]): <!-- hnx:gen:summary:scripts.md -->Scripts: what counts as one, the hnx-script header, how triggers are discovered, the checks that keep the catalog true and the reviewed allowlist.<!-- /hnx:gen -->
- [Knowledge graph](graph.md) ([[graph]]): <!-- hnx:gen:summary:graph.md -->The knowledge graph of everything in the repo that names something else: commands, querying, node kinds, edge types and what is not in the graph yet.<!-- /hnx:gen -->
- [MCP server](mcp.md) ([[mcp]]): <!-- hnx:gen:summary:mcp.md -->The read-only stdio MCP server (hnx mcp serve) over this checkout: its tools, documents served in levels, its security model and the broker's tool server.<!-- /hnx:gen -->
- [MCP catalog](mcp-catalog.md) ([[mcp-catalog]]): <!-- hnx:gen:summary:mcp-catalog.md -->The MCP catalog, one record per MCP server: the record, fatal rules, adding a server, instances, rendering client configs, importing a lab and reviews.<!-- /hnx:gen -->
- [Feature and provider modules](modules.md) ([[modules]]): <!-- hnx:gen:summary:modules.md -->Draft module manifest for provider, feature and core modules (ADR-0027, proposed): why, words, layout, the manifest, slot registry and requires and prefers.<!-- /hnx:gen --> Draft (ADR-0027, proposed).
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

The generated pages are checked in `make check` and CI:

```
hnx docs capabilities check                                # docs/capabilities/ is current
hnx docs systems check examples/services.yml docs/systems  # docs/systems/ matches the registry
hnx docs index check docs/README.md docs/adr/README.md    # index and ADR log descriptions match page summaries
hnx scripts catalog --check                                # docs/scripts/catalog.* is current
hnx graph check                                            # no dangling edge or duplicate id
```
