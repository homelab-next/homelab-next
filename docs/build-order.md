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

| Phase | Goal | Contract / artefact | How it is proven without hardware | Where |
|---|---|---|---|---|
| P0 | CI, skeleton and the leak gate | licence, CI workflow, ADR log, leak scan | CI itself; the scan has positive and negative fixtures | `.github/workflows/`, `tools/`, `docs/adr/` |
| P1 | Contracts: schemas in git | logical ids, event envelope, pinned OCSF subsets, agent, broker and records schemas | every schema has examples and negatives; additive evolution is checked against frozen baselines | `schemas/`, `tools/schema_check.py` |
| P2 | Names: registry, aliases, generators | `services.yml`, resolver, generated DNS/hosts/scrape targets, the no-raw-endpoint gate | golden outputs from a synthetic example lab | `homelabnext/registry/`, `examples/` |
| P3 | One shared client library per seam | lake, notify, state, records, events, decision cascade | each ships an in-memory fake; crash-safety and idempotency tests | `homelabnext/` |
| P4 | Conformance harness | one swap test per capability, each with a fake | the suites pass against fakes in CI | `conformance/` |
| P5 | Role interface and IaC conventions | role argument spec and hooks, capability inventory groups, scaffolds | role and playbook linter with passing and failing roles | `ansible/`, `tools/role_lint.py` |
| P6 | Detections as code, model-role aliases | Sigma plus fixtures, logical-id map, role resolver, golden tasks | fixture runner against an engine adapter; a fake inference server | `detections/`, `homelabnext/golden/` |
| P7 | Registers and invariants | generated registers, an invariants runner, the modularity-pillar checks | fixture pass and fail for each check | `homelabnext/registers/`, `homelabnext/invariants/` |
| P8 | Swap procedure kit | the nine-step checklist runner, parity tools, flip and decommission checks | the whole flow against two fake lakes | arrives with the swap kit |
| P9 | Lab-in-a-box | a compose stack of real containers for the seams, a smoke script, a nightly workflow | `docker compose config` in tests; the smoke script and nightly job bring it up for real | `compose/lab-in-a-box/`, `.github/workflows/nightly.yml` |

### P9 in detail

| Step | Deliverable | Exit criterion |
|---|---|---|
| P9.1 | `compose/lab-in-a-box/`: object store, Iceberg REST catalog with Postgres, query engine, event bus, secrets (dev mode), notifications, plus the project's fakes, all behind `<capability>.svc.example.internal` aliases and inside a 4 GB RAM budget | `make lab-smoke` passes locally; the nightly workflow is green for seven consecutive days before any SERVER cutover relies on it |
| P9.2 | The first rehearsal of the swap procedure in CI: a fake lake replaced by the query engine in the box through the swap kit (shadow, parity, flip, rollback) | the run produces a swap record and rollback restores the incumbent |

## SERVER phases

These phases are documented, not implemented here. Each lists what it consumes from the public
phases, so the public work is a prerequisite and not a duplicate.

| Phase | Goal | Consumes |
|---|---|---|
| S1 | Hardware bring-up: hypervisor, storage, network zones, sensor feed, recovery basics (escrow, break-glass, dead-man check, backup jobs) before anything runs | P5, checklist rows F-01, F-09-F-11 |
| S2 | Foundation services in order: secrets, identity, edge, monitoring, DNS aliases pointing at the incumbents, then the staging slice running the P9.1 compose definitions | P2, P4, P9 |
| S3 | Data platform: object store, catalog, query engine; copy (not in-place swap) the data; first real swap rehearsal of `lake-query` in shadow | P3, P8 |
| S4 | SIEM and detection: manager and rules compiled from the detection layout; writers consume the raw stream and the OCSF schemas; dual-write during the window | P1, P6 |
| S5 | Reaction and control plane: event bus and forwarder, the broker with approvals bound to a request digest, the decision service, workflows deployed disabled and in shadow | P1, P3, P4 |
| S6 | Agent runtime, then the accelerator window: profile compiler live, budgets enforced, model roles resolved by the gateway | P3, P6 |
| S7 | Outputs: case system, threat intelligence, exposure management, operator console; every stateful product gets an export hook | P2, P5 |
| S8 | Cutover: capability flips in order, each through the swap procedure | P8 |
| S9 | Decommission and consolidation (operator-gated), each through the decommission check | P8 |
| S10 | Assurance loop and publish-back: restore drills, every surprise becomes a lesson plus a checklist step plus (where generic) a fix in this repository | P7 |

## Reading the status

- What is built and tested today is listed in the README status section and in
  [checklist.md](checklist.md) (rows tagged PUBLIC-NOW).
- A row tagged SERVER is a property to be proven on the real deployment; this repository ships
  the interface and a fake, not a claim.
- The sizing convention used above is S (days), M (a week or two), L (a month of evenings). P4
  and P9 are the two L-sized public phases because each needs a fake and a real container per
  capability.
