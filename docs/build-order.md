---
summary: 'The build order: public phases P0-P9 provable in CI with fakes, server phases S1-S10, the v0 slice, experimental and frozen components, reading status.'
summary_of: outline:sha256:24b0f4a8e75d9901
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Build order

The order in which the platform is built, and what can be proven where. Phases **P0-P9** are
tagged **PUBLIC-NOW**: they are decidable on a laptop or a CI runner with fakes, fixtures, goldens
and containers, and they are what this repository contains. Phases **S1-S10** are tagged
**SERVER**: they need a real deployment, are documented here, and are not implemented or tested
in this repository.

The rule that shapes the order: **contracts before services, and every service gets a passing
conformance test before it goes live.** Each SERVER phase consumes an artefact that already
passed CI here: a role passes the role linter, a service gets a registry row before it gets a
host, and a capability goes live only when its incumbent-independent conformance test passes
against it on staging.

```
P0 CI and skeleton
 +-> P1 schemas (contracts) --+-> P3 libraries --> P4 conformance harness --> P8 swap kit --> P9 lab-in-a-box
 +-> P2 registry and names ---+
                              +-> P5 role interface --> P6 detections, model roles
                              +-> P7 registers and invariants
P9 --> S2.6 staging on the real server --> S3.. capability swaps --> S8 cutover
```

## PUBLIC-NOW phases

| Phase | Goal | Contract / artefact | How it is proven without hardware | Where | Checklist |
|---|---|---|---|---|---|
| P0 | CI, skeleton and the leak gate | licence, CI workflow, ADR log, leak scan | CI itself; the scan has positive and negative fixtures | `.github/workflows/`, `tools/`, `docs/adr/` | F, F-08, Q |
| P1 | Contracts: schemas in git | logical ids, event envelope, pinned OCSF subsets, agent, broker and records schemas | every schema has examples and negatives; additive evolution is checked against frozen baselines | `schemas/`, `tools/schema_check.py` | T, X-03 |
| P2 | Names: registry, aliases, generators | `services.yml`, resolver, generated DNS/hosts/scrape targets, the no-raw-endpoint gate | golden outputs from a synthetic example lab | `homelabnext/registry/`, `examples/` | X-01, X-11 |
| P3 | One shared client library per seam | lake, notify, state, records, events, decision cascade | each ships an in-memory fake; crash-safety and idempotency tests | `homelabnext/` | S, O, P, R, A, K |
| P4 | Conformance harness | one swap test per capability, each with a fake | the suites pass against fakes in CI | `conformance/` | X-04, X-10 |
| P5 | Role interface and IaC conventions | role argument spec and hooks, capability inventory groups, scaffolds | role and playbook linter with passing and failing roles | `ansible/`, `tools/role_lint.py` | X-05, X-09 |
| P6 | Detections as code, model-role aliases | Sigma plus fixtures, logical-id map, role resolver, golden tasks | fixture runner against an engine adapter; a fake inference server | `detections/`, `homelabnext/golden/` | D, G, X-06 |
| P7 | Registers and invariants | generated registers, an invariants runner, the modularity-pillar checks | fixture pass and fail for each check | `homelabnext/registers/`, `homelabnext/invariants/` | L, M |
| P8 | Swap procedure kit | the nine-step checklist runner, parity tools, flip and decommission checks | the whole flow against two fake lakes | `homelabnext/swap/`, `homelabnext/parity/`, `homelabnext/decommission/` | X-08 |
| P9 | Lab-in-a-box | a compose stack of real containers for the seams, a smoke script, a nightly workflow | `docker compose config` in tests; the smoke script and nightly job bring it up for real | `compose/lab-in-a-box/`, `.github/workflows/nightly.yml` | - |

### P9 in detail

| Step | Deliverable | Exit criterion |
|---|---|---|
| P9.1 | `compose/lab-in-a-box/`: object store, Iceberg REST catalog with Postgres, query engine, event bus, secrets (dev mode), notifications, plus the project's fakes, all behind `<capability>.svc.example.internal` aliases and inside a 4 GB RAM budget | `make lab-smoke` passes locally; the nightly workflow is green for seven consecutive days before any SERVER cutover relies on it |
| P9.2 | The first rehearsal of the swap procedure in CI: a fake lake replaced by the query engine in the box through the swap kit (shadow, parity, flip, rollback) | the run produces a swap record and rollback restores the incumbent |

## SERVER phases

These phases are documented, not implemented here. Each lists what it consumes from the public
phases, so the public work is a prerequisite and not a duplicate.

| Phase | Goal | Consumes | Checklist |
|---|---|---|---|
| S1 | Hardware bring-up: hypervisor, storage, network zones, sensor feed, recovery basics (escrow, break-glass, dead-man check, backup jobs) before anything runs | P5, checklist rows F-01, F-09-F-11 | F-01, F-02, F-09-F-11, F-13, F-14, C |
| S2 | Foundation services in order: secrets, identity, edge, monitoring, DNS aliases pointing at the incumbents, then the staging slice running the P9.1 compose definitions | P2, P4, P9 | F-03, F-04, F-06, F-12, F-16, F-24 |
| S3 | Data platform: object store, catalog, query engine; run the recorded TLP label backfill of every table holding rows from before its `tlp` column (S-09) before the copy, then copy (not in-place swap) the data, or record a fresh start on the cutover ledger (ADR-0043 decision 7); first real swap rehearsal of `lake-query` in shadow | P3, P8 | S, S-09 |
| S4 | SIEM and detection: manager and rules compiled from the detection layout; writers consume the raw stream and the OCSF schemas; dual-write during the window | P1, P6 | D, T |
| S5 | Reaction and control plane: event bus and forwarder, the broker with approvals bound to a request digest, the decision service, workflows deployed disabled and in shadow | P1, P3, P4 | P, R, K |
| S6 | Agent runtime, then the accelerator window: profile compiler live, budgets enforced, model roles resolved by the gateway; exit when every model role and agent profile has a TLP ceiling and model requests leave only at or below it (O-12) | P3, P6 | A, G, M, O-12 |
| S7 | Outputs: case system, threat intelligence, exposure management, operator console; every stateful product gets an export hook | P2, P5 | O |
| S8 | Cutover: capability flips in order, each through the swap procedure | P8 | E, X |
| S9 | Decommission and consolidation (operator-gated), each through the decommission check | P8 | - |
| S10 | Assurance loop and publish-back: restore drills, every surprise becomes a lesson plus a checklist step plus (where generic) a fix in this repository | P7 | L |

## The v0 slice

The first lab the platform runs is a deliberately small slice (operator decision, 2026-10-31).
Effort goes to these, in roughly this order, before anything outside them is built further:

- **registry and aliases**: `services.yml`, `<capability>.svc.<domain>` names, the generators and
  the no-raw-endpoint gate (P2; ADR-0002);
- **OpenBao**, the secrets slot (lab-in-a-box `secrets`; the overlay's SSH certificates use it);
- **the lake**: Garage (object store), Lakekeeper (Iceberg REST catalog) and Trino (query), with
  the pinned OCSF tables (P3, S3);
- **Sigma detections** as code, with fixtures and `det:` ids ([detections.md](detections.md);
  P6, ADR-0006);
- **the broker**, the one way agents and workflows act ([broker.md](broker.md); ADR-0017,
  ADR-0030);
- **notify**, state-diffed paging (the `notify` capability and its suite);
- **the status hub** ([status.md](status.md); ADR-0013);
- **SSO** through Keycloak (ADR-0034, in flight).

The deployed LLM gateway is LiteLLM (ADR-0022, amended 2026-10-31: the Bifrost adapter is
removed); the own gateway in `orchestrator/` (`orchestrator/cmd/gateway`, ADR-0038 and ADR-0026)
replaces it at the gateway cutover. The lessons, runbooks and invariants registers stay. Projects
and tasks live in OpenProject only.

## Experimental and frozen components

`tools/experimental.yml` is the one reviewed list of the components taken out of the blocking set
without being deleted. A listed component keeps its code and its tests, and they still run, in
`make experimental` and CI's `experimental` job (allowed to fail, needed by no other job); what it
loses is the power to block a merge: `make check`, `make test` and CI's required jobs run none of
its gates and deselect its tests (`-m "not live and not experimental"`; the marker comes from the
list, `tests/experimental_marker.py`), and `make invariants` (CI's invariants job) skips the
criteria it owns.
`tools/tests/test_experimental.py` holds the Makefile, CI and the invariants register to the list.
The list only shrinks: CI's `trusted-gates` job runs the base's `tools/experimental.py ratchet`,
and a change that adds a component, a test or code path, a gate, an invariant or a conformance
capability fails unless the operator applied the `experimental-growth` label
([CONTRIBUTING.md](../CONTRIBUTING.md), "Experimental and frozen components").
Today it lists:

- **StackStorm**, *experimental* until a lab host runs it ([stackstorm.md](stackstorm.md)). The
  workflow packs stay a product-neutral spec and `hnx workflows validate` stays blocking; the
  orchestration controller stays the agent-session scheduler (the two do different jobs:
  [workflows.md](workflows.md)).
- **Code Mode**, *frozen* at its current step until the core lab runs (CM-7 and CM-8 not built;
  [codemode.md](codemode.md), ADR-0031).
- **The strategy stack** (objectives, requirements, RFIs, measures), *frozen*
  ([strategy.md](strategy.md)).
- **The home-built projects store**, *frozen*, not removed: it is the `projects` suite's reference
  target and the hub and the graph read it ([projects.md](projects.md)).

To bring a component back, delete its entry, put its gates back into `make check` and CI, and
take its criteria out of the Makefile's `EXPERIMENTAL_INVARIANTS`, in one change.

## Reading the status

- Each phase's **Checklist** cell names its criteria in [checklist.md](checklist.md): a section
  letter (`Q`: that section's rows with the phase's own tag), a row id (`X-03`) or a range
  (`F-09-F-11`); `-` names none. The status hub's Roadmap page reads these tables (no copy) and
  shows each criterion's invariant result and a progress bar per phase
  ([status hub](status.md#generated-maps-topology-dataflow-architecture-roadmap)); a test fails
  when a cell names no row or a row is named by no phase.

- What is built and tested today is listed in the README status section and in
  [checklist.md](checklist.md) (rows tagged PUBLIC-NOW).
- A row tagged SERVER is a property to be proven on the real deployment; this repository ships
  the interface and a fake, not a claim.
- The sizing convention used above is S (days), M (a week or two), L (a month of evenings). P4
  and P9 are the two L-sized public phases because each needs a fake and a real container per
  capability.
