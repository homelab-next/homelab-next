---
summary: 'Index of the architecture decision log: how ADRs are numbered and checked, with a one-line entry per decision.'
summary_of: outline:sha256:3aed43cc1d6f8123
---
# Architecture decision log

One file per decision, numbered from 0001, with a stable slug. Every ADR carries exactly the
five headings **Status, Context, Decision, Consequences, Alternatives** (checked by
`tools/tests/test_adr_log.py`). Copy `_template.md` to start one. Public ADRs use placeholders
only (`example.internal`, RFC 5737 addresses); see `CONTRIBUTING.md`.

The one-line column is each ADR's front-matter `summary:`, written by
`hnx docs index generate docs/adr/README.md` and checked in CI; edit the summary, not the row.
An ADR's status is the **Status** line in its own file.

| ADR | Slug | One line (the ADR's `summary:`, generated) |
|---|---|---|
| [0001](0001-schemas-in-git-additive-evolution.md) | schemas-in-git-additive-evolution | <!-- hnx:gen:summary:0001-schemas-in-git-additive-evolution.md -->Contracts are JSON Schema files in git, vendor schemas are pinned, and schemas evolve additively only.<!-- /hnx:gen --> |
| [0002](0002-registry-and-dns-aliases.md) | registry-and-dns-aliases | <!-- hnx:gen:summary:0002-registry-and-dns-aliases.md -->A service registry plus DNS capability aliases are the only source of addresses; nothing hard-codes a host.<!-- /hnx:gen --> |
| [0003](0003-shared-client-libraries.md) | shared-client-libraries | <!-- hnx:gen:summary:0003-shared-client-libraries.md -->One shared client library per data seam; a private copy of a client fails CI.<!-- /hnx:gen --> |
| [0004](0004-role-interface-and-capability-groups.md) | role-interface-and-capability-groups | <!-- hnx:gen:summary:0004-role-interface-and-capability-groups.md -->Service roles ship argument specs and five tagged task sets; inventory capability groups are what playbooks target, never host names.<!-- /hnx:gen --> |
| [0005](0005-swap-procedure-and-conformance.md) | swap-procedure-and-conformance | <!-- hnx:gen:summary:0005-swap-procedure-and-conformance.md -->Every swap of a product follows one procedure, and every capability has a passing swap conformance test.<!-- /hnx:gen --> |
| [0006](0006-detections-as-code.md) | detections-as-code | <!-- hnx:gen:summary:0006-detections-as-code.md -->Detections are authored once in Sigma and cited by logical id, not copied per product.<!-- /hnx:gen --> |
| [0007](0007-model-role-aliases.md) | model-role-aliases | <!-- hnx:gen:summary:0007-model-role-aliases.md -->Consumers name model roles; only the LLM gateway maps a role to a backend model.<!-- /hnx:gen --> |
| [0008](0008-export-hooks.md) | export-hooks | <!-- hnx:gen:summary:0008-export-hooks.md -->Every stateful product ships an export hook that a restore drill exercises.<!-- /hnx:gen --> |
| [0009](0009-bus-only-at-the-reaction-seam.md) | bus-only-at-the-reaction-seam | <!-- hnx:gen:summary:0009-bus-only-at-the-reaction-seam.md -->A message bus only at the reaction seam; telemetry stays direct and control stays typed RPC.<!-- /hnx:gen --> |
| [0010](0010-records-lifecycle-as-an-api.md) | records-lifecycle-as-an-api | <!-- hnx:gen:summary:0010-records-lifecycle-as-an-api.md -->The records lifecycle (propose, find, complete) is written only through the records library, not by moving files; broker handlers come later.<!-- /hnx:gen --> |
| [0011](0011-public-private-split-and-licensing.md) | public-private-split-and-licensing | <!-- hnx:gen:summary:0011-public-private-split-and-licensing.md -->Public repo is greenfield with fictional example data and a three-layer leak defence; real inventory, detections and credentials stay private.<!-- /hnx:gen --> |
| [0012](0012-hypervisor-is-not-modular.md) | hypervisor-is-not-modular | <!-- hnx:gen:summary:0012-hypervisor-is-not-modular.md -->Hypervisor, physical network and base storage are a fixed substrate, not a swappable seam; hardware moves are a re-render plus DNS flips.<!-- /hnx:gen --> |
| [0013](0013-status-hub.md) | status-hub | <!-- hnx:gen:summary:0013-status-hub.md -->One read-only status hub over status sources registered in the registry; views pick from that menu.<!-- /hnx:gen --> |
| [0014](0014-conflict-free-writes.md) | conflict-free-writes | <!-- hnx:gen:summary:0014-conflict-free-writes.md -->Machine state is append-only sidecar events and status changes are intents a decider applies, so writes never conflict.<!-- /hnx:gen --> |
| [0015](0015-strategy-to-task.md) | strategy-to-task | <!-- hnx:gen:summary:0015-strategy-to-task.md -->A strategy, its objective cascade, measures and requirements are register records measured from what the lab observes.<!-- /hnx:gen --> |
| [0016](0016-guest-baselines-and-defense-layers.md) | guest-baselines-and-defense-layers | <!-- hnx:gen:summary:0016-guest-baselines-and-defense-layers.md -->Guests name product-neutral defense baselines of controls in six layers; each control binds to a product role in one place.<!-- /hnx:gen --> |
| [0017](0017-broker-service.md) | broker-service | <!-- hnx:gen:summary:0017-broker-service.md -->Agents ask a broker for named actions: default deny, pinned handlers, approvals bound to the request digest, every outcome audited.<!-- /hnx:gen --> |
| [0018](0018-generated-maps.md) | generated-maps | <!-- hnx:gen:summary:0018-generated-maps.md -->Topology, dataflow, architecture and roadmap pages are generated from the repository models, never drawn by hand.<!-- /hnx:gen --> |
| [0019](0019-record-uids-computed-numbers.md) | record-uids-computed-numbers | <!-- hnx:gen:summary:0019-record-uids-computed-numbers.md -->Records get UUIDv7 uids; the number shown with a record is computed from type, parent and order, never stored.<!-- /hnx:gen --> |
| [0020](0020-project-management-and-openproject.md) | project-management-and-openproject | <!-- hnx:gen:summary:0020-project-management-and-openproject.md -->Project management is a capability with board rules as MUSTs; OpenProject mirrors strategy one way and the repo wins.<!-- /hnx:gen --> |
| [0021](0021-public-and-private-repositories.md) | public-and-private-repositories | <!-- hnx:gen:summary:0021-public-and-private-repositories.md -->A real lab lives in a private overlay read through existing lookups; credentials only in OpenBao; deploys are dispatched by hand.<!-- /hnx:gen --> |
| [0022](0022-llm-gateway-litellm.md) | llm-gateway-litellm | <!-- hnx:gen:summary:0022-llm-gateway-litellm.md -->LiteLLM, run the supported way, is the LLM gateway; its config is generated from the role table and profiles.<!-- /hnx:gen --> |
| [0023](0023-model-serving-one-store-few-engines.md) | model-serving-one-store-few-engines | <!-- hnx:gen:summary:0023-model-serving-one-store-few-engines.md -->One model store, each model once, pinned by commit and sha256; vLLM serves production from it, a few engines elsewhere.<!-- /hnx:gen --> |
| [0024](0024-mcp-catalog-single-source.md) | mcp-catalog-single-source | <!-- hnx:gen:summary:0024-mcp-catalog-single-source.md -->One record per MCP server is the single source for the class table, graph, system pages and hub views.<!-- /hnx:gen --> |
| [0025](0025-orchestration-telemetry.md) | orchestration-telemetry | <!-- hnx:gen:summary:0025-orchestration-telemetry.md -->Each agent job usage is one closed, text-free agent.job.finished event; per-turn records come from the gateway spend-log API.<!-- /hnx:gen --> |
| [0027](0027-feature-and-provider-modules.md) | feature-and-provider-modules | <!-- hnx:gen:summary:0027-feature-and-provider-modules.md -->Products live only in provider modules filling slots from a slot registry; optional missions are feature modules.<!-- /hnx:gen --> |
| [0028](0028-veritas-single-source-of-truth.md) | veritas-single-source-of-truth | <!-- hnx:gen:summary:0028-veritas-single-source-of-truth.md -->Veritas names the single source of truth: authored files a generator or gate reads as the standard or copy source; every other copy is generated or checked.<!-- /hnx:gen --> |
| [0029](0029-holds-released-by-liveness.md) | holds-released-by-liveness | <!-- hnx:gen:summary:0029-holds-released-by-liveness.md -->A slot, lease or token/KV reservation exists only while its worker is alive and is released on every exit; TTL is a backstop.<!-- /hnx:gen --> |
| [0030](0030-agents-act-only-through-the-broker.md) | agents-act-only-through-the-broker | <!-- hnx:gen:summary:0030-agents-act-only-through-the-broker.md -->Every agent action goes through the broker; only the broker's own MCP front may hold acting tools, plus per-profile direct exceptions a human reviews.<!-- /hnx:gen --> |
| [0031](0031-code-mode-through-the-broker.md) | code-mode-through-the-broker | <!-- hnx:gen:summary:0031-code-mode-through-the-broker.md -->Agents may compose broker actions as short programs in a credential-free sandbox that reaches only the broker.<!-- /hnx:gen --> |
| [0032](0032-agent-context-is-authored-markdown-in-levels.md) | agent-context-is-authored-markdown-in-levels | <!-- hnx:gen:summary:0032-agent-context-is-authored-markdown-in-levels.md -->No context database; agent context stays authored Markdown/YAML in git, served in levels (summary, outline, one section).<!-- /hnx:gen --> |
