---
summary: The old lab cuts over through a ledger, one record per service, flow, agent, timer and dataset, each moved old to retired by gated, recorded transitions.
summary_of: outline:sha256:e66f33ebadfab4c7
---
# ADR-0043: The cutover from the old lab is a ledger, one row per service

- **Status:** proposed
- **Date:** 2026-11-07
- **Related:** ADR-0005 (the swap procedure), ADR-0008 (export hooks), ADR-0010 (the records
  lifecycle), ADR-0011 (what is public), ADR-0013 (the status hub), ADR-0014 (conflict-free
  writes), ADR-0019 (record uids), ADR-0020 (projects), ADR-0021 (the private overlay), ADR-0033
  (TLP), ADR-0035 (coordinator memory), ADR-0036 (novelty baselines), ADR-0037 (agent memory);
  this batch: ADR-0039 (one primary per capability), ADR-0040 (modules are replaceable by
  construction), ADR-0041 (versioned capability contracts), ADR-0042 (tested restores and cold
  start), ADR-0044 (the broker carries the vault's lifecycle), ADR-0045 (per-principal, short-lived
  credentials), ADR-0046 (repository governance), ADR-0047 (agent runs traced, budgeted and
  evaluated), ADR-0048 (verification beyond one reviewer), ADR-0049 (the SOC data plane and the
  lab's checks move as modules) and the ADR-0026 amendment (placing what the split left unplaced);
  [build order](../build-order.md) S3, S8 and S9, [decommission](../decommission.md),
  [registers](../registers.md), [broker](../broker.md), `homelabnext/registers/transitions.py`,
  `homelabnext/registers/events.py`, `homelabnext/modules/swap.py`,
  `homelabnext/modules/lake_access.py`, `homelabnext/decommission/`,
  `homelabnext/compute/validate.py`
- **Depends-on:** ADR-0005, ADR-0014, ADR-0019, ADR-0039, ADR-0040, ADR-0042, ADR-0044, ADR-0046,
  ADR-0049
- **Amends:** ADR-0026

## Context

The operator's lab runs today on the old stack: a private repository of Ansible roles, playbooks
and systemd timers, plus the private orchestrator and the agent runtime's plugin. homelab-next is
meant to replace it, and the private overlay (ADR-0021) holds the lab's first data translation. A
read-only parity audit of all of them (2026-11-07) asked what the lab would lose if it cut over
today. In order, the answer was:

- the whole agent fleet, because the controller is at ADR-0026 stage 2 of 6 and has no runner;
- the SOC data plane beyond the agents;
- the detector and collector timers;
- the vault's approval history and every vault note that is not a proposal;
- the lessons, runbooks, invariants and kanban cards;
- most application deploys, since only a small fraction of the old roles has a counterpart here.

The sizes behind each line are lab inventory, so they are overlay data (ADR-0011) and are not
repeated here. They are large: the ledger below has several hundred rows.

The pieces that would replace the old governance machinery exist here as tested code: the broker
and its Approvals page, the records lifecycle, the registers tooling, the invariants runner with
state-diffed paging, the status hub, the fleet-units generator and the projects adapter. None of
them is deployed, and none holds the lab's data.

Nothing tracks the move itself:

- **There is no per-service record of where each thing stands.** The swap kit (`hnx swap`,
  `homelabnext/swap/machine.py`) and the module swap record (`schemas/platform/module_swap.schema.json`,
  gated by `cutover_problems` and `decommission_problems` in `homelabnext/modules/swap.py`) prove one
  swap. Nothing lists the several hundred things that must each be swapped, dropped or archived,
  or says which of them are done. Checklist row E-12 ("Migration from the previous stack is
  complete") has no observable that could be run.
- **The old repository keeps growing.** Every feature added there is one more row to port, and
  the parity audit is out of date the day after it is written.
- **What happens to each dataset is undecided, or decided only in conflicting places.** A card in
  the old repository's tracker, closed 2026-11-05, records that the old stack is not kept and the
  new lab starts fresh. The build order's S3 phase here says the lake data is copied, after a TLP
  label backfill. No document says which history is abandoned, which is archived, and which comes
  across.
- **Credentials have no exit.** The principals audit found many credential names in the old stack
  with no name in homelab-next and no owner for revocation, and many of them are issued outside
  the lab. An orphaned credential still works at its issuer until somebody revokes it.
  `docs/decommission.md` is per host and greps secret *names*, so it cannot retire a whole stack.
  ADR-0026 stage 6 archives the private repository with no revocation step.
- **There are three agent rosters.** The agent plugin's charters, the orchestrator's profiles and
  the old repository's deployed agents each have names the others lack (naming audit), and agent
  keys are stored in the controller's job rows, so a key renamed by accident orphans history.
- **A known validation failure is being carried as accepted.** The overlay records that `hnx
  guests validate` fails, on purpose, for some of the lab's hosts under one of the model-runtime
  rules in `_model_runtime_problems` (`homelabnext/compute/validate.py`); the details are overlay
  data. The failure is honest, but a failure that is accepted is no longer a gate.

## Decision

1. **The cutover is a ledger: one record per service, flow, agent, timer and dataset.**
   - The ledger lives in the overlay, because its rows name lab systems. Rows are records of the
     register `cutover`, at `<overlay>/lab/registers/cutover/<uid>.md`. The register's name is its
     directory's name, as the registers library already reads it. Each row is one record file with
     YAML front matter and sidecar events, in the register format of [registers](../registers.md):
     a UUIDv7 `uid` (ADR-0019), its machine state as append-only events in `<uid>.events/`
     (ADR-0014), and display numbers computed, not stored. Evidence files live outside the
     register, at `<overlay>/lab/cutover/evidence/<uid>/`, next to `lab/cutover/policy.yml`.
   - The row's schema is `schemas/registers/cutover_row.schema.json` 1.0, with fictional examples
     under `examples/registers/cutover/`. Its fields:
     - `kind`: one of `service`, `flow`, `agent`, `timer` or `dataset`;
     - `old`: what runs in the old lab, as a list of names from the old inventory's exports
       (decision 4);
     - `new`: the successor. That is a registry row (with its ADR-0039 standing), a module id, an
       agent key, a fleet-unit id or a dataset. It is `null` only while `disposition` is
       `undecided`, or when it is `drop` or `retire`;
     - `disposition`: one of `undecided`, `carry` (the same function on the new platform), `replace`
       (a different product behind the capability), `drop` (the function is removed now, before
       the cut, because nobody uses it), `retire` (the function ends with the old lab, and nothing
       replaces it) or `archive` (data only: kept read-only, not imported);
     - `capability` and `contract`: the capability and the contract version (ADR-0041) the new
       side must pass, when the capability has a suite;
     - `gate`: the evidence the row's kind requires (decision 3);
     - `requires`: the uids of rows that must be `new-primary` first;
     - `governed_by`: the ADR whose mechanism moves it, for example ADR-0026 for the controller,
       ADR-0044 for the vault or ADR-0049 for a SOC writer;
     - `rollback_days`: the length of the rollback window, 14 by default;
     - `data`: for a `dataset` row, the decision of decision 7;
     - `carried_fixes`: fixes made on the old side that the new side also needs (decision 6).
   - Components that move together are one row, and coarse rows are encouraged: one row per timer
     family, per role group that deploys one service, or per agent cell where its members move
     together. A component is never covered by two rows: `hnx cutover check` refuses an `old` name
     that two rows claim.
   - These state and disposition names are the batch's vocabulary. The other ADRs of this batch
     and the ADR-0026 amendment use them as written here: `new-shadow`, `new-primary`,
     `old-retired`, and `retire` for a function that ends with the old lab.
2. **Each row moves through one state machine: `old`, then `new-shadow`, then `new-primary`, then
   `old-retired`.**
   - `old`: only the old lab serves the function.
   - `new-shadow`: the new side runs beside the old and **acts on nothing**. A service is an
     `eval` row (ADR-0039) bound to no consumer. An agent's profile has only `shadow` lanes
     (ADR-0040 decision 5, step 2). A timer's notifier is a dry-run sender. A dataset is written
     in parallel and read by nobody. This is what stops a page or an action from firing twice
     while both sides run.
   - `new-primary`: consumers use the new side. The old side is stopped for writes and kept
     restorable for `rollback_days`.
   - `old-retired`: the old side is decommissioned and its credentials are revoked. Its data is
     archived, migrated or deliberately dropped, as decision 7 records.

   Two more transitions are allowed:
   - **rollback**, from `new-primary` back to `new-shadow`, while the window is open;
   - **close**, from `old` straight to `old-retired`, only with `disposition: drop` or `retire`
     and the operator's approval.

   No row changes state by editing a field. The state is derived from the row's `transition`
   events (`schemas/registers/register_event.schema.json`). An actor files a
   `register-transition` intent through the records library, and `hnx registers decide`
   (`homelabnext/registers/transitions.py`) applies it under its lock and review policy, as it
   moves lessons. The overlay's review policy for the ledger requires a current human `approve`
   review for every move into `new-primary`, `old-retired` and `verified` (decision 8). A stale
   `from` is denied, so two people cannot both move one row.

   **A review in the files is not authentication, so the decider's inputs are protected.** The
   registers library says so itself: anyone with write access can type a review event, and agents
   act on the overlay with the operator's own token. Therefore:
   - The ledger's decider runs only on the overlay's protected main branch, in its checks job or by
     the operator. It never runs on a pull request branch.
   - A `human:` review counts only if it arrived in an operator-merged commit, or through the
     broker's authenticated approval flow (ADR-0044).
   - Until ADR-0046's agent bot identity exists, every ledger change, its evidence and its reviews
     are operator-merged. The decider refuses a review event whose introducing commit is not on
     main.

   **One intent may move a batch.** One `register-transition` intent may move many rows of one
   kind through one transition, as one vault completion note batches many approved items. It lists
   each row with its evidence, and one human `approve` covers the batch's digest. The decider then
   applies or denies each row individually, with its own gate, so one row's missing evidence does
   not move or block the others.
3. **Every transition is gated on evidence, and the evidence is fixed by its digest.**
   - The decider calls a new per-register gate, `homelabnext.cutover.gates.transition_problems(row,
     to, evidence)`, on the "would leave an invalid record" path it already has. The intent names
     each evidence file by its path under `lab/cutover/evidence/<uid>/` and its sha256, and the
     transition event records them (`evidence: [{path, sha256}]`, register_event 1.4).
   - Evidence must exist at the named path, with the named sha256, in a commit on main that is a
     strict ancestor of the commit that adds the intent. An intent and its evidence in the same
     commit are refused, so a change cannot vouch for itself.

   | Transition | Required evidence |
   |---|---|
   | `old` to `new-shadow` | `new` is named and `disposition` is `carry` or `replace`. For a service, `hnx registry bindings` (ADR-0039) shows no consumer bound to the new side. The non-acting declaration of decision 2 is present. Every guest the new side runs on is free of guest-subject problems in `validate_fleet` (decision 10). |
   | `new-shadow` to `new-primary` | Every row in `requires` is `new-primary` or `old-retired`. The kind's proof below passes. The data decision has been carried out: a migration manifest, or a recorded fresh start (decision 7). For a service, the ADR-0039 promotion diff (`plan_promote`) is merged. |
   | `new-primary` to `old-retired` | `rollback_days` have passed since the switch. `hnx decommission check` exits 0 for the old component. Every revocation record that names this row as a consumer is `verified` (decision 8). An `archive` dataset has its frozen manifest (decision 7). |
   | rollback | The window is open, and a reason is given. |
   | close | `disposition: drop` or `retire`, a reason, and the same decommission and revocation evidence as `old-retired`. |

   The kind's proof, for the move into `new-primary`:
   - **service**: a `homelabnext.conform.report/1` JSON in which the row's capability has verdict
     `pass` at `contract`, run with `--strict` against the lab target. Where the slot declares an
     equivalence, a compare report from `homelabnext.parity` or `hnx golden pins check` is also
     required (ADR-0040 decision 5, step 4). Where the service holds state, a passing service
     restore drill of its new home (ADR-0042 decision 3). A capability without a suite cannot pass
     this gate. Its row says so with `gate: none-yet`, which the check counts as a blocker, not as
     a pass.
   - **flow**: an end-to-end canary for the flow (checklist group E), or an event-stream parity
     report (`homelabnext.parity.compare_event_streams`) over the shadow period.
   - **agent**: the agent-runner suite once it exists (ADR-0026 stage 3), the profile's task-level
     eval (ADR-0047) and at least three consecutive successful shadow runs.
   - **timer**: at least three consecutive successful runs in the status hub's `job-last-run`
     records. A detector also needs its **positive control**: an evidence file showing that it
     caught a seeded instance of what it detects. A detector that has never fired is unproven, not
     clean.
   - **dataset**: decision 7.
4. **The ledger is complete before anything is retired, and it closes.**
   - The old lab is described by **names-only inventory exports**, one per grain: roles,
     playbooks, timers, MCP servers, generated pages, scripts, agents (decision 9), datasets
     (decision 7) and credentials (decision 8). The exports live in the overlay. They hold names,
     never contents.
   - `hnx cutover seed` makes an `old`, `undecided` row for each name in the exports that no row
     claims yet, and adds the overlay registry's rows (including ADR-0039 `legacy` rows). A second
     run adds no duplicate and changes no existing row. Seeding adds, from every agent row, a
     `requires` entry on each inference row that serves the agent's models, so an inference
     blocker (decision 10) propagates to the agents that use those models.
   - `hnx cutover check` refuses the following:
     - a duplicate uid, or an `old` name two rows claim;
     - a `requires` cycle;
     - a `requires` entry that names no row;
     - a row whose derived state disagrees with its events;
     - an `undecided` row once `lab/cutover/policy.yml` says decisions are due;
     - a lake access grant to any principal but the operator on an archive catalog (decision 7).
   - `hnx cutover check --old-inventory DIR` diffs every export in DIR against the rows' `old`
     names and fails on any name no row claims, as `revocations check --old-names` does for
     credentials (decision 8). A role, MCP server or script nobody seeded is therefore a failure,
     not an invisible gap. The ADR-0026 amendment's completeness check is this one.
   - `hnx cutover check --archive-gate` is the observable for checklist row E-12. It runs the
     inventory diff, and it exits 0 only when that diff is empty, every row is `old-retired` and
     every revocation record is `verified`.
   - `hnx cutover check --archive-gate --rows <uids>` is the same gate scoped to the named rows: it
     exits 0 only when each named row is `old-retired`, every revocation record whose `consumers`
     include a named row is `verified`, and no `requires` entry of a named row names a row outside
     the set that is not `old-retired`. A named uid that is no row is a failure. It is the gate for
     archiving one old repository whose components are only some of the ledger's rows (decision 8).
5. **homelab-next renders the ledger, and the status hub shows it.**
   - `hnx cutover render ROOT --out DIR` writes `cutover.json` (schema `homelabnext.cutover.report/1`)
     and a self-contained HTML page. It shows counts by state and kind, each row's blockers, open
     rollback windows and datasets that are still warming (decision 7).
   - The status hub reads that JSON through a `poll-file` source with a builtin mapping,
     `cutover-ledger`, which makes one item per row. The file reaches the hub by the results
     transport of ADR-0049 (the hub's read-only pull of a status directory), with no transport of
     its own:
     - `ok` for `old-retired`, and for `new-primary` once its window has closed;
     - `warn` for `new-shadow`, an open window, or a dataset still warming;
     - `fail` for a row whose gate has a blocker past its row's target date, or an `undecided`
       row once decisions are due.
   - Status sources carry no TLP label; ceilings live on menu entries and views (views schema
     1.10). The `cutover-ledger` source is listed only on private-group views, and `hnx status
     views check` refuses it on any view whose ceiling is below amber. A notification from its
     `fail` items goes through the notify channel's ceiling (ADR-0033 decision 6). The renderer and
     the mapping are public code with fictional fixtures. The data stays in the overlay.
6. **The old lab's repository is frozen for features from this ADR's acceptance: fixes only.**
   **Decided 2026-11-08 (operator):** the freeze starts at acceptance, for every kind of feature,
   although the controller cannot cut over before ADR-0026 stage 3; there is no later date for
   agent and timer features.
   - **Allowed:** a fix, a security fix, and register content. Lessons, runbooks and invariants may
     still be written in the old repository until their dataset row reaches `new-primary`; after
     that, its register files are read-only.
   - **Refused:** any commit that adds a role, a playbook, a timer unit, a generated page, an MCP
     server or an agent, or that changes a register's schema, unless its message carries a
     `Cutover-Fix: <ledger uid>` trailer naming a row in `old` or `new-shadow`.
   - **The freeze is enforced where it cannot be skipped.** A client-side commit hook is skipped by
     `--no-verify`, is absent from a fresh clone, and agents there commit straight to the default
     branch. The enforcement is a check on push or in CI in the old repository, or, where that
     repository has neither, a scheduled detector that pages on any post-freeze feature commit
     without the trailer. A commit hook may be added as a convenience. Either is an
     operator-merged change there; this repository does not reach it.
   - **One trailer, one evidence format.** The ADR-0026 amendment freezes the private orchestrator
     repository too, and its backports carry `Backport-Of:` naming the pull request here that
     carries the same fix. The two trailers answer different questions, so both stay: `Cutover-Fix:`
     names the ledger row a fix belongs to, and `Backport-Of:` names the fix's source here when the
     fix went the other way. A commit to either frozen repository carries `Cutover-Fix:`, plus
     `Backport-Of:` when it is a backport. Each `carried_fixes` entry has one shape: `{repo,
     commit, backport_of?}`, read from those trailers, so the gate reads one format for both
     repositories.
   - New work goes to homelab-next and the overlay, or waits.
7. **Each dataset's decision is recorded on its row.** The `data` block takes one of five forms:
   - `migrate`: import into the new side, with a manifest of counts and digests;
   - `in-place`: the product keeps its own store;
   - `archive`: kept read-only, not imported;
   - `fresh`: the new side starts empty, the old data is archived, and the block records `reason`
     and `decided_by`, like a module swap's `start_empty`;
   - `drop`: deleted, with the operator's approval.

   The proposed dataset rows. Each is seeded `disposition: undecided`, with the `data` form below
   proposed; the operator's review sets it. Where the operator has already decided (2026-11-08:
   the lake, the vault's case notes, the tracker's done cards), the review applies that decision.

   | Dataset | Proposed `data` | Mechanism and gate |
   |---|---|---|
   | The lake (archive events, OCSF tables, CTI reporting, the honeypot, sandbox, agent-health and metrics-bridge tables, frozen shadow tables) | **`fresh`**, as the operator chose (2026-11-07: "start fresh unless you tell me that's a bad idea"), with the old lake kept read-only as an **archive**; **confirmed 2026-11-08 (operator)** | See "The lake" below. |
   | Vault: proposals, decisions, completion history, findings, tasking queue and holds, deconfliction ledger, recall markers and acks | `migrate`, to the broker | ADR-0044 owns the mapping and the importer. This row's gate is that importer's manifest: per zone, the counts in, the counts out and the lost-record check. |
   | Vault: agent memory | `migrate`, to agent memory (ADR-0037) | Its own row and its own importer, governed by ADR-0037, not ADR-0044. Each memory arrives with its source and history, as ADR-0037 requires; a memory with no recoverable source arrives retracted, not as fact. The gate is the importer's manifest. |
   | Vault: case notes | `migrate`, to the cases capability (**decided 2026-11-08, operator**) | An importer into the `cases` primary through its adapter (ADR-0049 decision 5), built in ADR-0049 step 9a (`hnx cases import-notes`). The gate is the importer's manifest: the counts in, the counts out and the lost-record check. Until the importer exists the row cannot pass its gate. |
   | Vault: detector machine state | `archive` | The new detectors rebuild their working state on their first runs (ADR-0049), so nothing is imported; the old state is kept read-only as a `files` export so its history stays answerable. |
   | Vault: per-agent continuity files | `archive` | The new coordinator memory is a folded ledger (ADR-0035) that starts from the migrated records, not from the old files. |
   | Lessons and runbooks | `migrate` | `hnx registers split`, then `hnx records assign-uids` (the old numbered codes go to `aliases.yml`, so every citation in the tracker, the invariants, code and memory still resolves), then `hnx registers events migrate`. The check is that the record count equals the source count. A key the schema refuses is mapped in the import's map file or carried into the record's `Notes` section, never dropped. Lessons that use `match` validate against lesson schema 2.2. The import is **re-runnable**, keyed by the old codes in `aliases.yml`: register content may still be written on the old side until `new-primary` (decision 6), so each run adds what is new and changes nothing it already imported. The `new-shadow` to `new-primary` gate is a final re-import whose record count equals the source count at the named source commit. |
   | Invariants | `migrate` | Into the overlay's invariant register (`schemas/registers/invariant.schema.json`), re-homed as `lab-invariants/<old id>` in the overlay's `lab-invariants` module (ADR-0049), with the old ids in `aliases.yml` so every citation still resolves. Each becomes `evidence: auto` with its lab-side `check`, run by `homelabnext.invariants` under a fleet unit, paging newly red only (`page_changes`). **An imported `check` is code, not data:** each lands under the human review tier, and it runs under a least-privilege invariant-runner principal of its own (ADR-0045 decision 1), never under the old stack's deploy account. A check that needs root is listed on the row and reviewed individually. The results history is archived, not imported. |
   | The old task tracker (projects, cards) | `migrate`, to the `projects` capability (ADR-0020) | A new `hnx projects import-kanban`. It runs the old board's own validator first and refuses a board that fails. It is a dry run by default and idempotent by the card's old id, which it keeps as an external reference. Project cards become projects and step cards become steps. **Done cards are not imported (decided 2026-11-08, operator):** they stay in the old board's archive page, which is archived with the old repository. |
   | Threat-intel platform, case store, CTI graph | `in-place` | Each product keeps its own data, and the cutover moves its deployment, not its store. The gate is the product's export hook (ADR-0008), taken and restore-tested (ADR-0042) before the redeploy. |
   | The legacy case store, kept read-only | `archive` | A `jsonl` and `markdown-tree` export, then retire (ADR-0039: `legacy`). |
   | The agent-audit trail | `archive` | A sealed export whose tamper-evident chain is verified at export time. New audit is the broker's audit trail and the run traces (ADR-0047). |
   | The controller's database | `migrate` | The store migration that already exists, behind a verified backup (`docs/orchestration-controller.md`). The usage files are archived. |
   | Application data (household and office apps) | `in-place` | The role interface's `export.yml`/`restore.yml` hooks, restore-tested before each redeploy. |
   | Secrets | never carried | Each is reissued under its new name (`hnx secrets plan|seed`) or revoked (decision 8). No old value is imported, so an old consumer can never become a new admin. |

   **The lake.**
   - The new lake ingests from the cut, in pinned OCSF subsets with a `tlp` column from the first
     row, so the TLP backfill (S-09) and the old format debt do not come across.
   - **The cut date is the lake row's `new-primary` transition**, not the start of shadow writes.
     Shadow writes before it warm the new lake but are not counted as its history.
   - **At `new-primary`** the old lake's writers are stopped, and an `object-tree` manifest (a
     digest per object) is taken, so that later rot or tampering is detectable. The manifest is
     stored in the overlay as the row's evidence, never beside the archive it describes.
   - **At `old-retired`** the old lake's write credentials are revoked. Until then a rollback can
     restart the old writers. A rollback leaves a gap in the old lake for the days it was stopped;
     the new lake holds those days.
   - The archive is a **separate catalog or bucket** whose read credential is issued only to the
     operator principal. The lake access grants (`lake-access.json`, `homelabnext/modules/lake_access.py`)
     give no agent principal any rule on it, and `hnx cutover check` refuses a grant that does
     (decision 4). That is what makes "no agent reads the archive" true rather than asserted: a
     local model role's `red` ceiling (ADR-0033) does not reach a catalog it holds no rule for.
   - The archive is drilled under ADR-0042 decision 3: restored in full once at freeze, verified
     against its manifest on the drill interval, and restored in full every 365 days.
   - **Where and how long (decided 2026-11-08, operator).** The archive is kept for one year from
     the cut date, read-only, on the lab's NAS, and only the operator can query it. At the end of
     the year it is deleted, as a `drop` with the operator's approval.
   - **Archive access (decided 2026-11-08, operator).** Every archive this ledger makes is
     readable by the operator principal only: the old lake, the agent-audit trail, the legacy case
     store, the vault's detector state and continuity files, the vault repository archived at the
     broker switch (ADR-0044 decision 12), and the old lab's repository archived at the archive
     gate (decision 8), with its board's archive page of done cards. No other person and no agent
     is given a view of any of them.
   - `warm_until` is overlay data on the row: the cut date plus the longest look-back of any
     detection or baseline that reads the lake. Each detection's look-back is read from its
     detection metadata (ADR-0049), and the baselines' from the ADR-0036 window setting. A
     detection that declares none is listed on the row as unknown, and the operator's review sets
     `warm_until` by hand. Until then the status hub shows the lake as warming (decision 5).
   - ADR-0042 and ADR-0049 build on a fresh lake, which the operator confirmed on 2026-11-08. Were
     the lake row ever restamped `migrate`, the old lake would be copied as build order S3
     describes, after the TLP backfill, and ADR-0049 would gain a backfill path; neither ADR's
     other decisions would change.
   - The build order's S3 text changes to "copy the data, or record a fresh start on the ledger".
     Copying stays the generic default.

   **What a fresh lake costs.** The operator confirmed the fresh start with these costs on
   2026-11-08:
   - **Behavioural baselines re-learn.** The novelty analyzer's first-seen window (ADR-0036) starts
     empty, so for one window nearly everything is first-seen. Its findings are advisory and
     never escalate alone, so this is noise, not false alarms. The source census needs its
     cadence window before it can call a source quiet.
   - **Long look-back detections are blind until their window fills.** A correlation over N days
     sees only data from after the cut.
   - **Forensic and incident history from before the cut exists only in the archive.** It is
     queried separately, with no join to new tables, and open cases' evidence links point into it.
     Only the operator can query it.
8. **A revocation ledger: every credential of the old stack is revoked or reissued, and the archive
   waits for it.** This amends ADR-0026 decision 8, stage 6. It is this ADR's mechanism; ADR-0045
   governs only the new credentials.
   - One record per old credential name, as records of the register `cutover-revocations` at
     `<overlay>/lab/registers/cutover-revocations/<uid>.md`, schema
     `schemas/registers/cutover_revocation.schema.json` 1.0. Its fields:
     - `name`: the name only, never a value. The schema has no field that could hold one, and the
       check refuses a string that looks like a key;
     - `issuer`: `lab`, or an external issuer class;
     - `consumers`: ledger row uids;
     - `action`: `revoke`, `reissue` (with `as: secret:<new name>`) or `expire` (the issuer offers no
       revocation; `expires_on` must be recorded). `reissue` means the new credential is issued
       **and** the old one is revoked; some issuers keep an old token valid after a new one is
       issued, so issuing alone proves nothing;
     - `verified_by`: how the old credential was checked, under the rules below. The old value is
       never presented anywhere to test it.
   - **What counts as verification.**
     - Refusal evidence counts only when it comes from the credential's issuer itself. A new
       gateway or broker refusing an old key proves only that the new side refuses it; the old
       side may still accept it.
     - An external issuer needs a dated capture of the issuer's own listing or API showing the key
       absent or revoked.
     - For `reissue`, `verified` checks the old credential, not the new one.
     - An `expire` record is `verified` only after its `expires_on` date has passed.
   - Each record moves `held`, then `revoked` or `reissued`, then `verified`, through the same
     decider, under the same branch and review rules (decision 2).
   - `hnx cutover revocations check --old-names FILE` diffs the names-only credential export
     (decision 4) against the records and fails on any name without one. The export covers the
     vault's names and the credentials found outside the vault; the list itself is overlay data.
   - A module swap's `credentials_revoked` (`decommission_problems`) moves a record to `revoked`,
     never to `verified`. It is a name list the swap asserts, so a component that moves by `hnx
     modules replace` is not revoked twice, but it is still verified at its issuer.
   - **The archive of the old lab's repository runs only after `hnx cutover check --archive-gate`
     exits 0. ADR-0026 stage 6 (archive the private orchestrator repository) runs only after the
     scoped form exits 0 over the rows whose `old` names a component of that repository**
     (`--rows`, decision 4; the ADR-0026 amendment's decision 19 lists them). The lab-wide gate
     would hold that archive on services that share nothing with it, such as DNS or the lake.
     Lifetimes, rotation drills and per-principal issuance for the new credentials belong to
     ADR-0045.
9. **One agent roster of record.**
   - `<overlay>/lab/agents/roster-of-record.yml`, schema `schemas/registers/agent_roster.schema.json`
     1.0, is authoritative for **agent keys and membership** only. For each agent it holds:
     - its key, which is the lab's existing key, never renamed, because job rows reference it;
     - its charter;
     - its profile;
     - its schedule;
     - its ledger row.

     Compiled profiles, broker manifests and keyring sources stay authoritative for their own
     fields. The status hub's roster (`schemas/status/roster.schema.json`) is a display and is a
     different file.
   - `hnx cutover roster check` reads names-only lists of the charters, the profiles and the
     deployed agents, and the status hub's roster and the keyring's agent names. It fails on any
     name in any of them that the roster of record neither lists nor marks `dropped` with a reason.
   - The agents' operating context, now two diverged copies, becomes one file named by the roster.
     The other copies are deleted when the agent rows reach `new-primary`.
10. **The inference hosts without default-deny egress are a cutover blocker to fix, not a failure
    to accept.** **Decided 2026-11-08 (operator):** each inference host gets real default-deny
    egress (the first fix below), and none gets a recorded exemption. No new allowlist or
    accepted-failure list is added to `hnx guests validate`. Decision 3 refuses `new-shadow` for any
    row whose new side runs on a guest with a problem in `validate_fleet` whose subject is that
    guest. The gate reads those per-guest problems, not the command's exit code, because a site-wide
    exit would block every row. In general an inference host gets one of three fixes, and the
    operator's decision takes the first for every host:
    - real default-deny egress (`policy_out` DROP or REJECT, an allow list, and a baseline that
      defines `egress-filter`), after which the overlay's documented failure is removed;
    - a recorded `network.firewall_exemption` whose `filtered_by` names a zone whose
      `egress.internet` is deny, with its `review_by`. That is the existing mechanism, and the
      validator already checks it. An exemption without such a zone is not a fix;
    - or, if the host stops running models, it leaves the inference rows and the validator stops
      applying to it.

    Through the `requires` edges seeding adds (decision 4), a blocked inference row also blocks the
    agents whose models it serves.

### Out of scope

- Which product is primary for each capability (ADR-0039). How a single replacement is planned,
  shadowed, compared and switched (ADR-0040). Contract versions and their numbering (ADR-0041).
- Restore drills, off-site copies and cold-start order (ADR-0042). The ledger cites their evidence
  and does not run them.
- How the vault's records map onto the broker, and the import itself (ADR-0044). Agent memory's
  import (ADR-0037).
- New credentials: their issuance, lifetimes and rotation (ADR-0045); repository identities and
  who may merge the overlay's ledger changes (ADR-0046).
- Run tracing and the evals an agent row's gate cites (ADR-0047); review beyond one model
  (ADR-0048).
- Porting the SOC data plane, the detection rules and the lab's detector and collector checks
  (ADR-0049); the items the orchestrator split left unplaced (the ADR-0026 amendment). Those ADRs
  move rows. This one only tracks them.
- The successor of the interactive-session runbook gate (a future ADR, named as a follow-up by
  ADR-0049) and the runbook skill generation.
- Roles for the household apps, which are overlay-only by design. They get rows, not designs here.
- Cutover dates. A row's target date is overlay data.

## Consequences

- "Where is the migration?" has one answer: a rendered page, and a status item per row. E-12 gets
  an observable that can be run. A row cannot be called done without evidence a stranger can
  re-check, and a row nobody has decided shows as undecided, not as silence.
- Completeness fails closed: a name in the old inventory that no row claims fails the archive
  gate, so a forgotten role or script cannot slip through.
- The ledger runs on machinery that already exists here: record files, sidecar events, the
  transition decider, conformance reports, parity reports, the decommission audit and the module
  swap gates. The new code is the register additions, the gates, the checks, the renderer and the
  importers.
- Several hundred rows is real bookkeeping. Seeding makes the rows, coarse rows keep the count
  down, and batched intents keep the approvals to one per batch rather than two per row. Deciding
  the rows is still the operator's work, and that is the point.
- Until ADR-0046's bot identity exists, every ledger change waits for the operator's merge. That
  is slower, and it is the only way a review in a file means anything while agents share the
  operator's token.
- The fresh lake loses look-back. The costs are written above. The archive stays readable by the
  operator only, on the lab's NAS, for one year from the cut.
- The old repository stops gaining features, so every new idea lands in homelab-next or waits.
  Fixes still flow, and each fix the new side also needs is carried on its row.
- Nothing is archived while one old credential still works at its issuer. That may hold the
  archive back by however long an external issuer takes to revoke.
- Agent keys are frozen as they are. Neutral names come from profiles, not from renaming keys.

### Implementation plan

Each step is one pull request: in this repository unless marked, merged green after a design review
and a security audit. Overlay and old-repository pull requests are merged by the operator.

1. **This ADR** (`docs:`), with its index row and summary stamp, the reciprocal `Amended-by:
   ADR-0043` line and an amendment note on ADR-0026's stage 6, and the build-order S3 wording
   (decision 7). E-12's observable changes in step 11, with the checklist's tests. Tests: the ADR
   log test (headings, `Depends-on`, the reciprocal pair).
2. **Schemas**: `cutover_row.schema.json` 1.0, `cutover_revocation.schema.json` 1.0 and
   `agent_roster.schema.json` 1.0, with positive examples under `examples/registers/cutover/` and
   negatives under `schemas/registers/negative/`. Negatives include: a `null` `new` with a
   `carry` or `replace` disposition; a `fresh` dataset without `decided_by`; a revocation record
   with a value-looking field; an `expire` record without `expires_on`. Tests:
   `tools/schema_check.py --strict`.
3. **The registers library learns the ledger.** register_event 1.4 (additive): an optional
   `evidence: [{path, sha256}]` on a transition. `cutover` and `cutover-revocations` join
   `LIFECYCLE_REGISTERS` in `homelabnext/registers/events.py`, with their state vocabularies, and
   `current_status`/`apply_transition` take a register's vocabulary instead of assuming the
   lesson and runbook states. Tests: a transition on either register is accepted with evidence
   and refused without it; a transition on an unlisted register is still refused; the existing
   lesson and runbook transitions are unchanged.
4. **`homelabnext/cutover`: the model and `hnx cutover check`**, over the `cutover` register read
   with the registers library. State is derived from `transition` events. Tests: one fixture per
   refusal in decision 4 (duplicate uid, a doubly claimed `old`, a cycle, a dangling `requires`, a
   state that disagrees with its events, `undecided` past due, an agent principal granted on the
   archive catalog), each failing on the parent. `--old-inventory`: a role in the export with no
   row fails, and a fully claimed export passes. The fictional examples pass.
5. **The gates** (`gates.py` under `homelabnext/cutover/`), wired into `TransitionDecider` as a
   per-register gate, plus the ledger's review policy and its branch rule. Tests, one per row of
   decision 3's table, refused on missing or failing evidence:
   - a conform report with verdict `fail`, or the wrong contract version;
   - a stateful service without a passing restore drill;
   - a decommission JSON with exit 1;
   - a revocation not yet `verified`;
   - a `requires` row not yet primary;
   - an open rollback window;
   - a new side on a guest with a guest-subject `validate_fleet` problem, and a pass when its
     only problem is elsewhere in the fleet;
   - a timer with two runs instead of three;
   - a detector without its positive control;
   - evidence whose digest differs from the ancestor commit's file;
   - an intent and its evidence added in the same commit;
   - a `human:` review whose introducing commit is not on main;
   - a batch intent with one row missing evidence: that row is denied and the others applied.

   With full evidence, each transition is applied.
6. **Revocations and the archive gate**: `hnx cutover revocations check --old-names FILE` and
   `hnx cutover check --archive-gate`, with its `--rows` filter. Tests: a name with no record
   fails; an unverified record fails the archive gate; with `--rows`, a named row not
   `old-retired`, an unverified record one of them consumes, a named row that `requires` an
   unretired row outside the set and an unknown uid each fail, while an unretired row outside the
   set that nothing named requires does not; a swap record's `credentials_revoked` moves a record to `revoked` and
   not to `verified`; an `expire` record before its date cannot be `verified`; a `reissue` with
   only the new credential's evidence cannot be `verified`; a refusal log from a non-issuer is
   refused as evidence; a non-empty inventory diff fails the archive gate.
7. **The roster check**: `hnx cutover roster check`. Tests: a name that only one source has fails;
   a `dropped` name with a reason passes; a renamed key is refused when job-row fixtures cite the
   old one; a keyring name the roster of record lacks fails.
8. **Render and the status hub mapping**: `hnx cutover render`, schema
   `homelabnext.cutover.report/1`, and the `cutover-ledger` builtin mapping. The views check
   (`hnx status views check`, views schema unchanged) gains the rule that this source sits only on
   views whose ceiling is amber or above. Tests: a golden render of the fictional ledger; item
   states for every case in decision 5; the source is refused on a public view.
9. **Seeding**: `hnx cutover seed` from names-only exports of every grain in decision 4 (roles,
   playbooks, timers, MCP servers, generated pages, scripts, agents, datasets, credentials) and
   the registry. Tests: a second run is byte-identical; an existing row is untouched; a `legacy`
   registry row produces a row; an agent row gets `requires` on its inference rows.
10. **The kanban importer**: `hnx projects import-kanban`, against the projects fake and the
    OpenProject adapter's recorded target. Tests: a board that fails the old board's validator is
    refused; a dry run writes nothing; a re-run adds nothing; a done card is not imported.
11. **The checklist**: E-12's observable becomes `hnx cutover check --archive-gate`, and a new
    Modularity row, X-13 ("the cutover ledger is well formed"; X-12 is ADR-0039's), runs `hnx
    cutover check` as a plugin criterion. Tests: the examples pass, a broken fixture fails, and
    the checklist totals are restamped.
12. **Overlay: the ledger seeded** (operator merges). This adds `lab/registers/cutover/`,
    `lab/registers/cutover-revocations/`, `lab/cutover/` (policy, review policy, the inventory
    exports, evidence) and `lab/agents/roster-of-record.yml`. It adds the dataset rows of decision
    7, each `undecided` with its proposed `data`, and the operator's 2026-11-08 decisions (the lake,
    the case notes, the done cards) ready for the review to apply. It adds `hnx cutover check
    --old-inventory` to `checks.yml`, running on main only for the decider. Validated with this
    repository's CLI at the pinned ref and clean under `private_leak_check.py private`.
13. **Overlay: the registers imported** (operator merges): lessons and runbooks split, given uids
    and events-migrated, and the invariants converted, each imported `check` under the human
    review tier and the invariant-runner principal. Tests: the counts match, `check_lost` is
    clean, a re-run adds nothing, and `python3 -m homelabnext.registers build` exits 0 over
    `lab/registers/`. It is re-run before the dataset rows' `new-primary` transitions.
14. **Old repository: the feature freeze** (operator merges there): the push or CI check of
    decision 6, or its scheduled detector. Tests there: a commit that adds a timer without the
    trailer is refused (or paged); a fix passes; a commit pushed with `--no-verify` is still
    caught.
15. **Overlay: inference egress** (operator merges): real default-deny egress on each inference
    host, with no recorded exemption (decision 10). The overlay's documented failure is
    deleted. Test: `hnx guests validate lab/guests --site
    lab/site.yml` exits 0.

After step 15, rows move by transition intents, singly or in batches, each row with its own
evidence, as the work of ADR-0026, ADR-0044 and ADR-0049 lands.

## Alternatives

- **Track the cutover on the projects board or the old tracker.** A card can move without
  evidence, and the board has no gate or derived state. It would also put the tracker in the tool
  being migrated.
- **One module swap record per component and nothing else.** Swap records prove a single swap
  well. But most rows are timers, agents, flows and datasets that never pass through `hnx modules
  replace`, and the swap records give no completeness: nothing would say what has *no* record.
  Rows cite swap records where they exist.
- **Keep the parity audit as the tracker and re-run it.** An audit is a snapshot read by a person.
  Nothing gates on it, and it cannot record a decision.
- **One human approval per row and transition.** Simple, but it means hundreds of separate reviews
  for one operator, and approvals that many are skimmed. A batch with one digest is reviewed once
  and still decided row by row.
- **Copy the lake** (build order S3 as written). It keeps baselines and look-back, but it carries the
  old formats, the unlabelled rows and the backfill across. The operator chose a fresh start with an
  archive, and the costs are recorded above.
- **Delete the old lake.** It would remove the only pre-cut forensic history, and it saves only the
  disk space the archive takes.
- **Revoke credentials host by host with `hnx decommission`.** That audit works per host and by name
  pattern. Externally issued keys have no host, and a pattern cannot tell whether a key was
  revoked.
- **Accept the inference hosts' validation failure until after cutover.** The failure guards the
  boundary that keeps model-written actions inside the lab. Accepting it at cutover would mean
  migrating the gap.

### Operator decisions (2026-11-08)

The operator answered this ADR's open questions on 2026-11-08 ("use defaults"). The ADR stays
proposed; the answers are applied in decisions 6, 7 and 10 and in the implementation plan.

1. **The lake.** Decided: a fresh start, with the costs in decision 7. The old lake is kept for
   one year from the cut, read-only, on the lab's NAS, and only the operator can query it.
2. **The accepted validation failure.** Decided: every inference host the overlay lists under it
   gets real default-deny egress. No exemption is recorded.
3. **The freeze date.** Decided: the old repository is frozen for new features at this ADR's
   acceptance (fixes only), with no later date for agent and timer features.
4. **Done tracker cards.** Decided: not imported; they stay in the old board's archive page.
5. **Archive access.** Decided: only the operator reads the archives, the vault repository and
   the old repository with its done-card archive page included; no other view is made.
6. **Vault case notes.** Decided: imported into the cases capability.
