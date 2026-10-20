# Architecture decision log

One file per decision, numbered from 0001, with a stable slug. Every ADR carries exactly the
five headings **Status, Context, Decision, Consequences, Alternatives** (checked by
`tools/tests/test_adr_log.py`). Copy `_template.md` to start one. Public ADRs use placeholders
only (`example.internal`, RFC 5737 addresses); see `CONTRIBUTING.md`.

| ADR | Slug | One line |
|---|---|---|
| [0001](0001-schemas-in-git-additive-evolution.md) | schemas-in-git-additive-evolution | Contracts are JSON Schema files in git; vendor schemas are pinned; evolution is additive |
| [0002](0002-registry-and-dns-aliases.md) | registry-and-dns-aliases | A service registry plus DNS capability aliases are the only source of addresses |
| [0003](0003-shared-client-libraries.md) | shared-client-libraries | One shared client library per data seam; private copies fail CI |
| [0004](0004-role-interface-and-capability-groups.md) | role-interface-and-capability-groups | Roles declare an interface; inventory groups are capabilities |
| [0005](0005-swap-procedure-and-conformance.md) | swap-procedure-and-conformance | Every swap follows one procedure; every capability has a passing swap test |
| [0006](0006-detections-as-code.md) | detections-as-code | Detections are authored in Sigma and cited by logical id |
| [0007](0007-model-role-aliases.md) | model-role-aliases | Consumers name model roles; only the gateway maps roles to backends |
| [0008](0008-export-hooks.md) | export-hooks | Every stateful product ships an export hook exercised by a restore drill |
| [0009](0009-bus-only-at-the-reaction-seam.md) | bus-only-at-the-reaction-seam | A bus only at the reaction seam; telemetry stays direct, control stays typed RPC |
| [0010](0010-records-lifecycle-as-an-api.md) | records-lifecycle-as-an-api | The records lifecycle and register edits are an API, not file moves |
| [0011](0011-public-private-split-and-licensing.md) | public-private-split-and-licensing | What is public, what stays private, and the licence rule |
| [0012](0012-hypervisor-is-not-modular.md) | hypervisor-is-not-modular | The hypervisor layer is deliberately not a swappable seam |
| [0013](0013-status-hub.md) | status-hub | One read-only status hub over status sources registered in the registry; views pick from that menu |
| [0014](0014-conflict-free-writes.md) | conflict-free-writes | Machine state is append-only sidecar events; status changes are intents a decider applies |
| [0015](0015-strategy-to-task.md) | strategy-to-task | A strategy, its objective cascade, measures and requirements are register records, measured from what the lab observes |
| [0016](0016-guest-baselines-and-defense-layers.md) | guest-baselines-and-defense-layers | Guests name product-neutral defense baselines; products bind per control through its role; with a set, every guest needs a baseline or an exemption |
