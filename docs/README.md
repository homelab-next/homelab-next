<!-- SPDX-License-Identifier: Apache-2.0 -->
# Documentation home

The map of the documentation: start here on GitHub, or open this `docs/` folder as an
[Obsidian](https://obsidian.md) vault and use this page as its home. Every generated page links
both ways, with a relative Markdown link (for GitHub) and a path-qualified `[[folder/page|label]]`
wiki-link (for Obsidian), so the graph view shows how capabilities, systems, decisions and scripts
relate.

## Choosing and integrating a tool

- [Capabilities](capabilities/README.md) ([[capabilities/README|Capabilities]]): one generated
  reference page per capability: what it does, every operation with its signature, the data shapes
  in and out (field tables, errors, the JSON Schemas it loads), the conformance checks, the
  built-in fake, the real-product adapters and their recorded limits, the registry services that
  use it, and the steps to integrate a new product. The index is a capability x (operations,
  checks, adapters, services) matrix for tool choice.
- [Conformance harness](conformance.md) ([[conformance]]): suites, targets and `hnx conform`.
- [Swap procedure](swap.md) ([[swap]]): replacing one product with another behind a capability.
- [Interface index](interfaces.md) ([[interfaces]]): the contracts, Python interfaces and owners.

## Running the systems

- [Per-system SOP pages](systems.md) ([[systems]]): how the pages in `systems/` are built; each
  service page links to its capability page, its upstreams and its dependants. The
  [capabilities index](capabilities/README.md) lists every registry service.
- [Architecture](architecture.md) ([[architecture]]), [build order](build-order.md)
  ([[build-order]]), [network model](network-model.md) ([[network-model]]),
  [compute model](compute-model.md) ([[compute-model]]), [role interface](role-interface.md)
  ([[role-interface]]).
- [Events](events.md) ([[events]]), [detections](detections.md) ([[detections]]),
  [workflows](workflows.md) ([[workflows]]),
  [StackStorm](stackstorm.md) ([[stackstorm]]), [decisions and models](decide.md) ([[decide]]),
  [LLM gateway](llm-gateway.md) ([[llm-gateway]]),
  [model serving](model-serving.md) ([[model-serving]]),
  [LLM orchestrator](orchestration-controller.md) ([[orchestration-controller]]),
  [orchestration telemetry](orchestration-telemetry.md) ([[orchestration-telemetry]]),
  [agent profiles](agent.md) ([[agent]]), [broker service](broker.md) ([[broker]]),
  [scope guard](scope.md) ([[scope]]),
  [customization](customization.md) ([[customization]]),
  [decommission audit](decommission.md) ([[decommission]]).

## Decisions, status and scripts

- [Status hub](status.md) ([[status]]): the read-only primary UI over every registered status
  source; the [source catalog](status/sources.md) ([[status/sources|status sources]]) is the menu.
- [Architecture decision log](adr/README.md) ([[adr/README|ADRs]]).
- [Public repository and private overlay](private-overlay.md) ([[private-overlay]]): where a real
  lab's data, credentials and keys live, how hnx reads the overlay, the bootstrap order, the
  protected-Environment deploy, rotation and the threat model.
- [Checklist](checklist.md) ([[checklist]]): what is done, public now, or needs a server.
- [Strategy to task](strategy.md) ([[strategy]]): a strategy, its objective cascade
  (SO -> OO -> TO -> TT) measured by MOPs and MOEs bound to invariants, status sources and
  records, the requirements it answers (CCIR, FFIR, PIR) and the RFIs its gaps raise; the
  [example index](strategy/README.md) ([[strategy/README|strategy index]]).
- [Registers](registers.md) ([[registers]]): lessons and runbooks as one file per record, the
  lesson lifecycle (pitfalls retire into mechanisms, practices are incorporated into runbooks),
  the shared review model and `hnx registers review`.
- [Script catalog](scripts/catalog.md) ([[scripts/catalog|Script catalog]]), generated from the
  script headers; [how the catalog is kept true](scripts.md) ([[scripts]]).
- [Knowledge graph](graph.md) ([[graph]]): every service, capability, adapter, check, schema,
  register record, script, agent profile and page as typed nodes and edges read from the source
  files; `hnx graph build` writes a local index (`docs/graph/`, one page per node kind, not
  committed), and `hnx graph related <id|path>` lists what a task should pull in.
- [MCP server](mcp.md) ([[mcp]]): `hnx mcp serve`, read-only structured answers for agents
- [MCP catalog](mcp-catalog.md) ([[mcp-catalog]]): one record per MCP server; classes, graph, pages and every client config generated from it; import an existing lab
  (contracts, schemas, services, the graph, scoped context, review and invariant status) over
  stdio, scoped by a compiled agent profile.
- [Glossary](glossary.md) ([[glossary]]).
- [Terms and scope](terms.md) ([[terms]]): what auditing, an audit review, an auditing tool and an
  internal assessment mean, the authorized scope (the operator's own lab) and how threat
  vocabulary is used (external threats only); every agent session's context pack carries it.

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
hnx scripts catalog --check                                # docs/scripts/catalog.* is current
hnx graph check                                            # no dangling edge or duplicate id
```
