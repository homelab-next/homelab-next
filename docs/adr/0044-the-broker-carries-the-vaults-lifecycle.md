---
summary: Agents leave the file vault for the broker only once it carries the whole lifecycle (decisions, holds, tasks, findings, ledger, recalls) and its history.
summary_of: outline:sha256:f41c0d8d7bbfb8bc
---
# ADR-0044: The broker carries the vault's lifecycle

- **Status:** proposed
- **Date:** 2026-11-07
- **Related:** ADR-0001 (schema versions), ADR-0010 (the records lifecycle), ADR-0014
  (append-only events, derived state), ADR-0017 (the broker), ADR-0019 (record uids and aliases),
  ADR-0025 (the job-finished record), ADR-0029 (holds released by liveness: a different kind of
  hold, see decision 6), ADR-0030 (agents act only through the broker), ADR-0033 (TLP), ADR-0034
  (SSO identity), ADR-0035 (the coordinator's folded ledger), ADR-0037 (agent memory); this batch:
  ADR-0039 (one primary per capability), ADR-0040 (replaceable modules, state classes), ADR-0041
  (versioned contracts), ADR-0042 (tested restores), ADR-0043 (the cutover ledger), ADR-0045
  (per-principal credentials), ADR-0046 (agents are not the operator), ADR-0047 (traced, budgeted
  runs, and the controller's part of a recall), ADR-0048 (verification beyond one reviewer),
  ADR-0049 (the SOC data plane and the lab's checks as modules) and the ADR-0026 amendment that
  places what the split left unplaced; [broker](../broker.md), [status hub](../status.md),
  `schemas/records/`, `schemas/broker/`, `homelabnext/broker/`, `homelabnext/records/`
- **Depends-on:** ADR-0017, ADR-0030
- **Amends:** ADR-0010, ADR-0017, ADR-0026

## Context

The operator's agents run today against a file-based vault: a git repository of Markdown notes
whose directories are the workflow, a guard hook that decides which directories an agent may
write, a dashboard where the operator approves, and a sync job that moves files. ADR-0017 and
ADR-0030 replace that pattern with the broker, and the operator has agreed to move the agents
onto it **on one condition: the broker must do everything the vault does, and the vault's history
must come across.** Read for the audit of 2026-11-07, the vault does seven things, and the broker
does about one and a half of them:

| What the vault does | What the broker has today |
|---|---|
| **Propose, then approve or deny.** An agent writes a note into the one zone it may write; the operator approves or denies in a dashboard, which moves the note into an operator-only directory. | `proposal.file`, a `records-inbox` lane (`homelabnext/broker/lanes.py`) that validates the note, binds `requesting_agent` to the authenticated caller and names the file. The decision is a second, separate path: `hnx records decide approve\|deny NAME --by WHO` (`homelabnext/records/decider.py`), where `WHO` is a string the person running it types. The hub's Approvals page, which does authenticate a person (ADR-0017 decision 13), decides broker **action requests** only, never records notes. |
| **Completion requests that batch.** One note with a `related:` list of approved items asks the operator to close them all; on approval the sync job moves every one to `completed/`. | `Decider.complete` moves every `related:` item all-or-nothing, and the records schema has the `completion-request` type. No lane accepts that type (`examples/broker/manifest.production.yml` lists `note_types: [proposal]`), and nothing but the CLI's asserted `--by` can run the move. |
| **A tasking queue with holds.** Tasks addressed to an agent, updated and closed; and **holds**, entries that say "not now" about an item. A lesson the lab paid for: an item can be approved and held at the same time, an agent that checked only approval fired a costly, hard-to-undo exercise days into a hold that asked for a week, and the rule since is that every approved item is checked against the holds independently. | The records schema's `task` type (`assigned_to`, `done_when`, `expires`, `status`); no lane files one and nothing updates one. No hold of this kind exists anywhere (ADR-0029's holds are capacity reservations tied to a live worker, a different thing). The audit's parity table: "missing (tasking bus); hold semantics differ". |
| **One finding note per run, even when clean.** A missing note is indistinguishable from a failed run, so every run writes exactly one. | `finding.write`, a free-form `files` lane: no schema, no severity, nothing that notices a run that wrote none. |
| **A red/blue deconfliction ledger.** Before any adversary emulation, the offensive agent registers an entry (techniques, targets, a window, the telemetry and detections it expects, an instruction to the defenders); defensive agents check a suspicious event against the ledger before calling it hostile; the entry is closed with a verdict (detected, missed, partial, blocked, cancelled) and a time to detect. An entry grants no authority to act, and a window that runs out never closes an entry. | Nothing. |
| **Incident recall markers with per-agent acks.** A marker in a known directory with an active status diverts every addressed agent from its routine pass; each writes one ack file of its own (one file per agent, because agents appending to one file raced and lost acks) and names the recall in its finding. The rule exists because a real recall once fired and none of the addressed agents acknowledged it. | Nothing, beyond a manifest flag (`agents[].roster.recall` in `schemas/platform/module.schema.json`) that says an agent is addressed. |
| **Requester provenance in the name.** Filenames are `<date>-<requesting agent>-<slug>.md`, so who filed an item shows without opening it. | Built and stronger: `<date>-<agent>-<slug>-<tag>.md`, where the agent is the caller the kernel authenticated and the tag a broker-keyed hash, so no agent can file under another's name. |

Identity is weak on both sides of the vault. The requester is a label each agent's MCP process
sets in its own configuration, "no role in scope decisions", so any agent process can claim any
name, and the approval trail cannot prove which agent filed a proposal. The approver is whoever
reached the dashboard: the dashboard's backend holds one API key shared by its ingest sources,
its UI and its approval route, so it sees a key, not a person. The broker already does both
halves properly for actions: the caller is a system user mapped by `SO_PEERCRED` to one profile,
and the approver is `{issuer, subject}` from the SSO front door judged against a per-person
allowlist that refuses self-approval and agent approvers. It does neither for records.

History is the other half of the condition. `hnx broker import-proposals` (ADR-0017 decision 17)
imports only the `proposed/` directory, re-files each note as the importing caller with the
original requester kept as provenance, and skips completion requests. The approved, denied and
completed history, the approved-but-unbuilt backlog, findings, the tasking queue and its holds,
the ledger and the recall acks have no path ("No" in every row of the audit's data-migration
table but one).

Finally, ADR-0026 decision 6 says the private repository's vault and tasking-queue MCP servers
(and the deconfliction one beside them) become overlay modules. Those servers front the very
directories this ADR retires. The audit records it as an open inconsistency: ported as they are,
they would keep the vault alive behind a module, with its self-asserted identity.

## Decision

1. **Parity first, then the move, gated by a suite.** The agents' grants switch from the vault to
   the broker only when a **lifecycle-parity conformance suite** passes, with one scenario per
   row of the table above and one per refusal named below, and when the history import of
   decision 10 has reconciled. The lifecycle is new behaviour of the existing `records`
   capability, so under ADR-0041 decision 1 it is a **minor of the `records` contract**, not a
   second contract: the target protocol `RecordsLifecycleTarget` extends `RecordsTarget` in
   `conformance/protocols/records.py`, the scenarios are added to `conformance/suites/records.py`
   tagged with that minor, and `conformance/fakes/records_target.py` grows to match.
   `conformance/targets/broker-reference.yml` gains `records: {adapter:
   homelabnext.broker.service:make}`, so the reference broker claims that minor. ADR-0040's
   export and import for `records` (its decision 6) carry the `.events/` sidecars and the new
   directories of decision 2. The suite is the operator's condition written as tests; ADR-0043's
   ledger row for the vault moves to `new-primary` only with both green. No agent prompt is
   changed before then.

2. **One records tree, one writer, derived state.** Everything the vault held lives in the
   broker's **records tree**, `<data-root>/records/`, as **records notes** (`schemas/records/note`,
   ADR-0010), in fixed directories: `inbox/` and `decided/{approved,denied,completed}/` (as
   today), and new `findings/`, `tasks/`, `holds/`, `incidents/` (recalls and their acks) and
   `deconfliction/`. A note is created once and never edited: what changes is an **event**
   appended beside it (`<name>.events/`, one file per event, created exclusively, ADR-0014),
   validated by a new `schemas/records/record_event.schema.json`. The current state of a note (a
   task's `open`/`closed`/`expired`, a hold's `open`/`released`, a recall's `active`/`resolved`, a
   ledger entry's `planned`/`active`/`overdue`/`closed`) is **folded from its events by code**
   (`state.py` under `homelabnext/records/`) and never stored. The fold generalises
   `homelabnext/registers/events.py`'s `derive()`, which today folds register status transitions
   only, into a fold over any event kind with a per-type transition table; the registers keep
   their behaviour and their tests. A time that passes changes a derived view (a task past
   `expires` reads `expired`), never a note. The broker's process is the only writer of the tree,
   and agents have no filesystem access to it: `<data-root>/records/` is owned by the broker's
   user with mode `0700`, and `hnx broker validate --data-root` checks that directory and refuses
   it otherwise. Other lanes under the data root keep their documented modes (agents may still
   read their own memory where the operator grants it, [broker](../broker.md); memory itself is
   ADR-0037's).
   **The broker is the single trusted component for records decisions, as it already is for
   action decisions.** The decider's separate-user rule ([broker](../broker.md), "Migrating", and
   the `homelabnext/records/decider.py` docstring) existed because agents could read and write
   the lane directories from disk; with the tree closed to them, the inode and ownership risks it
   guards against no longer reach an agent, and a separate decider user would guard only against
   a compromised broker, which can already forge any action approval. `Decider` keeps every load
   and move check it has, runs inside the broker service (decision 5), and stays out of the agent
   API's imports; implementation step 5 rewrites the docstring's trust paragraph to say this and
   extends its pinning test: the agent API still does not import it, and among the agent-facing
   packages only `homelabnext.broker.service` does.

3. **The records schema grows, additively** (`note` 1.5): types `hold`, `recall`, `recall-ack`
   and `deconfliction`; `kind` on `task` (`task` or `rfi`, default `task`); `escalate` (boolean)
   on `finding`; an optional `tlp` on every note (ADR-0033: absent reads `red`); and an
   `imported` block (`{from, legacy_id, sha256, identity: asserted}`) that only the importer of
   decision 10 may set (a lane refuses it: `lane-imported-set`). Each new type has positive and
   negative examples under `schemas/records/` checked by `tools/schema_check.py`. Versions follow
   ADR-0001.

4. **The broker's lanes generalise to the records tree** (manifest 1.10). Lane kind `records`
   takes a `dir` (one of the fixed directories above; `hnx broker validate` refuses any other, and
   two lanes over one directory as it already does for roots), `note_types` and the event kinds
   it accepts (`transitions`). `records-inbox` stays as the name of `{kind: records, dir: inbox}`.
   Every write keeps today's lane rules (caller-bound `requesting_agent`, broker clock, keyed name
   tag, per-actor shares, write rates, no-follow paths), and an event is accepted only from the
   note's author, its addressee or a relay (per kind, below), refused `record-event-not-allowed`
   otherwise.
   **Quotas fit a tree that is never pruned.** Records lanes set `max_files: null`, with
   `max_total_bytes` sized for the import plus a number of years the overlay states (today's
   per-lane defaults of 4096 files and 64 MiB would be reached within months by one finding per
   run per agent plus the history). A capacity invariant (checklist row G-16) warns at 80% of each
   records directory's byte cap, so the cap is raised before `finding.file` starts refusing and
   decision 8's invariant turns red fleet-wide. The importer writes as the broker and is not bound
   by lane rate or quota limits, but its report (decision 10) states the resulting usage of every
   directory against its cap.

5. **Decisions on records are made by a person, through a relay, and say who.** The approval
   relay protocol (ADR-0017 decision 10) gains `records-pending` (the inbox's notes, each with
   its sha256 and, for a completion request, its resolved `related:` items) and `records-decide`
   (`approve`, `deny` or `complete`, with `name`, the `sha256` the person saw, an optional note,
   and `approver: {issuer, subject}`). The broker judges the approver by the manifest's
   `approvers` exactly as for actions (allowlist, `approval-self-approved`), refuses an agent
   approver **unconditionally** for records (`records-agent-decider`, whatever
   `allow_agent_approvers` says; the principle is ADR-0017's and ADR-0030's, and with ADR-0045
   decision 7 an agent's identity is its system user, never a label), refuses a digest that no
   longer matches the note (`records-digest-mismatch`), and then runs
   `homelabnext.records.decider.Decider` inside the broker service with `decided_by` set to
   `issuer:subject`. The decision sidecar names the person and the relay peer (`via`), and the
   broker writes an audit record per decision. `complete` keeps the decider's all-or-nothing
   preflight, so one completion request still closes many approved items in one decision.
   - **The Approvals page** lists records notes beside action requests and decides them with the
     same front door, approver group, CSRF token and digest check (ADR-0017 decisions 13 to 15).
     It shows a note's body only when the note's TLP is at or under the viewer's ceiling (ADR-0033
     hub ceilings), otherwise its name, type, requester and the hidden label; deciding a note
     needs an approver whose ceiling covers it, refused `records-ceiling` otherwise.
   - **The CLI is development and break-glass only.** On a served tree (the broker holds the
     state directory's lock, `<state>/broker.lock`), `hnx records decide` refuses unless
     `--break-glass` is given. With the flag it takes the decider's lock, writes `channel: cli`
     in the sidecar, and the decisions invariant (decision 11) is red at once and pages; it stays
     red while any CLI decision on a served tree is unreviewed or any decision names an approver
     not in the manifest.

6. **Holds are records, checked where an action runs, independently of approval.**
   - **What a hold names.** A `hold` note names a `target` (an approved record's name, a broker
     request id or an action name), a `reason` and an optional `until`. It is open until a
     `released` event (or past `until`).
   - **Who may place one.** An agent's hold (`hold.place`) may target only a record or request it
     authored or is addressed by, or an action it is itself granted. A hold on an action name for
     everyone, or on another actor's item, is placed by a person (relay op `hold-place`) and is
     refused from an agent (`hold-target-not-allowed`), because a hold an injected agent places on
     `service.restart` or a containment action would stop incident response until a person found
     it. Agent holds count against the `holds/` lane's per-actor share. A hold placed by a person
     is released only by a person (`hold-release`); an agent's own hold by that agent or a person.
   - **Linking an action to the record it carries out.** An action request that carries out an
     approved records note names it in a request-level `related` field (`schemas/broker/request`
     1.2, covered by the request digest). For actions whose manifest entry sets `requires:
     {approved_record: true}`, `decide()` refuses a request without one (`record-unlinked`), and
     refuses one whose note is not in `decided/approved`, is already completed, or is held
     (`record-held`). The Approvals page shows the linked note beside the request. **An approved
     records note authorizes no action by itself:** each action keeps its own tier and approval.
   - **Where holds bite**, each a refusal with a reason and an audit record: `decide()` refuses
     `run` of an approved request, and `call` of an action, while an open hold names the request,
     the action, or the record in the request's `related` (`record-held`), **at run time**, so a
     hold placed after the approval still stops it; `records.read` returns every approved note
     with its open holds (`held_by`), so the read an agent works from carries the answer; and
     `records-decide complete` is unaffected (closing a held item is allowed). A held privileged
     request appears on the Approvals page with the holder and the reason.
   - This is not ADR-0029's hold, which is a capacity reservation that lives only while its worker
     does; `docs/broker.md` says so in one line where both words appear.

7. **The tasking queue is `task` notes in `tasks/`.** `task.file` validates `assigned_to` against
   the manifest's mapped profiles (`task-assignee-unknown`), so a task cannot be addressed to a
   name that no agent answers to; the vault's queue grew a class of tasks addressed to names
   that resolved to nobody, which read as "assigned and stuck" for weeks. `task.update` appends
   an update event (the author or the assignee), `task.close` a closing event with the
   `done_when` evidence. Requests for information are `task` notes with `kind: rfi`. Ids are the
   note's name (ADR-0019: the number shown is computed), so there is no next-id allocator to
   race. Expiry is derived (decision 2). The vault's queue validator, sweeps and stale-task check
   become one read, `records.read` over `tasks/` with the folded state, and a hub view.

8. **Findings are `finding` notes, one per run, and a missing one is red.**
   - `finding.file` writes a validated `finding` note into `findings/` (`area`, `severity`,
     optional `escalate`, `evidence` and `tlp`).
   - **Escalation pages, never silently.** A note with `escalate: true` and severity `high` or
     above is paged through the broker's notifier, on the agent's own notifier budget. The page
     carries the body only when the note's TLP is at or under the channel's ceiling
     (`--notify-ceiling`, ADR-0033); otherwise it carries the note's name, severity and the hub
     link. It is never dropped for its label (a finding with no `tlp` reads `red`, so without this
     rule most escalations would be withheld).
   - **The per-run invariant fails closed.** `findings` defaults to `per-run` for every caller
     with a scheduler entry; opting out takes `findings: none` with a `reason`, shown on the
     invariant page. A new invariant joins the controller's `agent.job.finished` records
     (ADR-0025) with `findings/`: a finished run of a `per-run` profile with no finding by that
     profile inside the run's window is red, two or more is a warning, and the invariant pages
     only when newly red.
   - The free-form `finding.write` lane stays for one release beside it and is then removed from
     the example manifests.

9. **The ledger and the recall are records with gates.**
   - **Deconfliction entries.** `deconfliction.register` writes a `deconfliction` entry (`mode`,
     `window_start`, `window_end` at most 90 days later, `targets` as registry or guest ids,
     ATT&CK technique ids, `sources` (the addresses or guests the activity comes from), expected
     telemetry and detections, `blue_instruction`, `blind`) with `executed_by` bound to the
     caller. Its folded state is `planned` before `window_start`, `active` from `window_start` to
     `window_end`, `overdue` after `window_end` while unclosed (a window that runs out never
     closes an entry), and `closed` once `deconfliction.close` appends the verdict (`detected`,
     `missed`, `partial`, `blocked`, `cancelled`), the time to detect and the outcome, with an
     `expected_revision` (the folded state's sha256) so two closes cannot both land
     (`record-revision-conflict`).
   - **No entry, no activity.** A new action precondition (manifest 1.10 `requires:
     {deconflicted: <target param>}`) refuses an emulation action whose target has no `active`
     entry by the same caller covering now (`deconfliction-missing`), enforced where the action
     runs, not instructed. Because an opt-in gate fails open, `hnx broker validate` refuses an
     action the manifest marks `class: emulation`, or whose handler targets a range guest, without
     `requires.deconflicted`. Target matching, here and below, is by exact registry or guest id.
   - **Matching an event.** `deconfliction.match({target?, technique?, source?}, at)` requires at
     least one of target, technique or source besides the time, as the vault's check does, and
     answers the entries whose window covers `at` and that share any of them.
   - **Blind tests are tasked, not self-declared.** `blind: true` is accepted only when the entry
     cites, in `related`, an approved records note or a task filed by a profile in the manifest's
     `deconfliction.graders` (`deconfliction-blind-untasked`). `match` on a blind entry answers
     no-match to every caller except its author and the graders until it is closed; the operator
     always sees it on the hub, and the hub flags any containment request whose target is under an
     active blind entry. An entry grants nothing: a ledger write is a `record-write`, never an
     approval.
   - **Recall.** A person raises a recall through the relay (`recall-raise`: `title`, the parts
     per role in plain language, `drill`, an optional `exercise_id`), or an agent requests one as
     an approval-gated action (`incident.recall`, tier `privileged`). Callers whose manifest
     entry says `recall: true` (from the module roster flag) are addressed. While a recall is
     `active`, every broker answer to an addressed agent carries `recall: <name>`, and
     `recall.status` returns the recall and that agent's part. The broker **refuses that agent's
     `finding.file`** until it has filed its ack (`recall-unacked`) and unless the finding names
     the recall (`recall: <name>`). `recall.ack` writes one `recall-ack` note per agent per recall
     (`recalled_at` from the recall, the broker's clock for the ack, the agent's part), so a
     second ack is `lane-exists`, not a race; the link from the ack to the finding is a derived
     join, never a field an agent fills. A person resolves it (`recall-resolve`); only `active`
     diverts. Waking the addressed agents, and the invariant that every addressed agent has acked
     an active recall within `ack_within_s` (checklist row R-11), are ADR-0047 decision 12's; this
     ADR adds no second ack-coverage criterion. Together they close the silent non-response the
     vault's rule was written after: an addressed agent that ran cannot file its finding without
     acking, one that did not ack in time is red under ADR-0047's criterion, and one that did not
     run at all is red under decision 8.

10. **The history comes across, every item accounted for.** `hnx broker import-vault DIR`
    (extending `homelabnext/broker/importer.py`; `import-proposals` becomes its `proposed/`
    mapping) imports proposals, the approved, denied and completed history with its completion
    requests, findings, the tasking queue with its holds, the deconfliction entries and their
    closures, and the recall markers with their acks.
    - **Offline, as the broker.** It refuses to run while the broker serves the same state
      directory (it takes `<state>/broker.lock`, which the serving broker holds), writes as the
      broker's user, and is a dry run unless `--apply`.
    - **Identity stays asserted.** A **map file** (`--map FILE`, overlay data) turns each legacy
      agent name into its profile in an `agents:` section, and names hold targets the importer
      cannot resolve in a `holds:` section; an unmapped name stops the import. Every imported note
      carries `imported: {from, legacy_id, sha256, identity: asserted}`, and an imported
      decision's sidecar says `decided_by: legacy:<what the vault recorded>` with
      `channel: import`, so nothing imported can pass for a broker-bound requester or an
      SSO-authenticated approver. A hold whose target resolves neither to an imported item nor
      through the map's `holds:` stops the import (a hold that silently drops is the very failure
      decision 6 exists for).
    - **Keyed by item, not by file.** The import key is (source kind, legacy item id or path,
      sha256). The tasking queue is one file edited in place holding many items, so the importer
      splits it into items by their legacy ids (`RFI-`, `TASK-`, `HOLD-<date>-<nn>`): a changed
      item becomes an update or close event on its existing task or hold, never a duplicate. A
      note seen in a new vault directory (approved to completed, say) becomes the matching
      decision event on the record it already is. Each item's legacy id is kept in
      `imported.legacy_id` and resolves through the tree's aliases (ADR-0019), so charters and
      notes that cite it still find it.
    - **Reconciled.** The import writes a **reconciliation report** (`<state>/imports/<run>.json`):
      every source file and queue item, its sha256 and either the record or event it became or the
      reason it was skipped, plus each directory's usage against its cap (decision 4); exit status
      1 while any item is neither. Because of the key, `--apply --incremental` during the shadow
      period (decision 12) adds only what changed. Broker audit `operation: import`, one record per
      item.

11. **The agent-facing tool surface: the broker's own MCP front, by function.** `homelabnext/
    broker/mcp_tools.py` registers, beside today's tools, thin calls to the actions above:
    `finding_file`, `proposal_file` (now any type its lane allows: `proposal`,
    `completion-request`, `escalation`), `records_read` and `records_list` (by directory and
    state, capped, at or below the caller's TLP ceiling, approved notes with `held_by`),
    `task_file`, `task_update`, `task_close`, `hold_place`, `hold_release`,
    `deconfliction_register`, `deconfliction_close`, `deconfliction_match`, `recall_status` and
    `recall_ack`. No tool takes an identity (ADR-0017 decision 11). Their catalog record
    (`examples/mcp/hnx-broker.yml`) classes the reads `read` and the rest `record-write`, and
    ADR-0030's structural front check (`servers.broker_front_problems`) covers them because they
    are the module's own registered tools.
    - **What changes in a prompt.** Each vault tool is replaced by a broker tool, and its
      arguments are mapped in the same table. An agent's prompt changes by that table of tool
      names, plus deleting the rules the broker now enforces or that no longer apply (vault
      paths and the absolute-path and read-only-command rules, the hold check against the queue,
      ack file paths, filename conventions). Both the table and the deletions are overlay data
      (ADR-0026 stage 5).
    - The vault's proposal-validator verdict becomes a `finding` with `area: proposal-review` and
      the proposal in `related:`, shown beside the proposal on the hub.
    - Three invariants hold it (checklist rows G-14 to G-16, reserved by this batch; G-12 stays
      unused): G-14 "every
      records decision on a served tree came through a relay from an allowlisted person" (a scan
      of decision sidecars against the manifest; imported decisions are counted apart), G-15 "every
      finished run left exactly one finding" (decision 8), and G-16, the records capacity warning
      (decision 4). Recall ack coverage is ADR-0047's R-11.

12. **Shadow, then switch, then archive.**
    - **Shadow.** The vault stays the agents' system of record, the import runs `--incremental`,
      and `hnx broker import-vault --compare` folds both sides and reports every difference in
      the states that matter (approved and not completed, held, active recalls, open tasks, open
      ledger entries). This compares the vault with an import of the vault: it proves the
      importer and the fold, not the broker in live use. So for the last days of the shadow
      period **one canary profile** runs on the broker tools instead of the vault tools, with its
      decisions made on the hub, so the first real records decision through the relay is not made
      on switch day.
    - **Switch.** It needs a run of days with no difference and the canary's clean days (both
      lengths are the operator's). Then the agents' profiles are granted the broker tools and lose
      the vault tools in one reviewed overlay change, the guard hook's writable zones are emptied,
      the dashboard's approval route is turned off (its shared key's revocation is ADR-0045's),
      and the vault repository is archived read-only, never deleted.

13. **ADR-0026 decision 6 is amended: the vault, tasking-queue and deconfliction MCP servers are
    not ported as overlay modules.** Their functions are the broker's records actions (decisions
    4 to 11); their code is archived with the private repository at ADR-0026 stage 6. The other
    lab-only servers that decision names keep its plan. This is the decision of record; the
    ADR-0026 amendment's decision 20 points here. ADR-0026 gains this amendment in its
    **Amended:** line and **Amended-by:** ADR-0044.

14. **ADR-0010 and ADR-0017 are amended.** ADR-0010 decision 3's "`records.complete` ... may
    follow" is decided: records decisions are relay operations of the broker (decision 5), and
    its lanes are the records tree of decision 2. ADR-0017 decision 10's relay operations gain
    the records, hold and recall operations, and decision 17's import becomes decision 10's.
    Both gain **Amended-by:** ADR-0044.

**Schema versions this ADR claims:** records `note` 1.5 and the new `record_event` 1.0 (unique to
this ADR); broker manifest 1.10 (unique); broker `request` 1.2 for `related`, which ADR-0047 also
claims for `trace`; broker `audit`'s next minor for the operations `import`, `records-decide`,
`hold-place`, `hold-release`, `recall-raise` and `recall-resolve`, where ADR-0047 claims audit 1.5
for its trace fields. Both shared bumps are additive, so whichever pull request lands second takes
the following minor (request 1.3, audit 1.6) and says so in its schema description.

### Out of scope

- Agent memory and its migration (ADR-0037 owns both); the controller's own store (ADR-0026
  stage 2). ADR-0043's vault row should list only the zones of this ADR, with agent memory on its
  own row pointing at ADR-0037.
- The vault's non-lifecycle zones, each of which needs its own ADR-0043 row: case notes (the
  `cases` capability), machine state written by detectors such as the fleet health verdict
  (ADR-0049 moves the checks), per-agent continuity files (ADR-0035's folded ledger replaces
  them).
- The registers, the kanban and the invariants register: their own importers (`hnx registers`).
- Credentials: the agents' system users and SSH-forwarded sockets exist (ADR-0017 stage 2a); issuing
  them per principal, short-lived, and revoking the dashboard's shared key are ADR-0045's. The
  agents' GitHub identity is ADR-0046's; tracing a broker call back to its run, and the
  controller's part of a recall, are ADR-0047's.
- The agent-runner contract and the Hermes provider (ADR-0026 stage 3), which launch the agents
  under their own users.
- Any change to what an approval of an **action** means; decision 6 adds refusals, nothing else.

## Consequences

- The operator approves proposals and completions where action requests are approved, as a
  person the front door named, and the trail says who. An agent's name on a note is a fact the
  kernel attests, not a label it chose.
- The lesson about approved-but-held items stops being a rule an agent must remember: the broker
  refuses a held run wherever the request is linked to the held item or the hold names the action
  or request, and for actions that require a linked record an unlinked request is refused too. An
  action that needs no linked record and is not itself held is not stopped by a hold on a records
  note: the manifest must mark the actions that carry out approved work. Likewise "no ledger
  entry, no activity" and "ack the recall" stop being instructions.
- The broker becomes the store of record for governance, so its records tree is a stateful
  dataset: `git` is no longer its history. In ADR-0040's terms the broker is state class
  `private` (the tree is a `state` dataset on its own host), and it needs an ADR-0042 recovery
  entry with the `record-tree` dump method, a drill and an off-site copy. Records are never
  pruned; the audit trail's retention (manifest `retention.audit_days`) stays as it is, and the
  capacity invariant of decision 4 is what keeps "never pruned" from becoming "full".
- The broker's availability matters more again: with it down, agents can neither propose nor file
  findings, and decision 8's invariant turns red for every run in the gap.
- The broker now holds the records decider in the same process that serves agents. That is the
  trust it already carries for action decisions, stated rather than implied (decision 2).
- One more vocabulary to keep stable: the record types and event kinds are versioned with the
  records schema (ADR-0001), the lifecycle is a minor of the `records` contract (ADR-0041), and
  that contract is what a second implementation would have to pass.
- The import marks every historical requester and approver as asserted, permanently. That is
  honest and slightly ugly: old history can never claim the identity guarantees new history has.

### Implementation plan (each step one pull request, in order)

1. **This ADR**, with **Amended-by:** lines in ADR-0010, ADR-0017 and ADR-0026, an **Amended:**
   line on each naming the decisions it changes, a pointer at ADR-0026 decision 6, and the index
   regenerated. Tests: `tools/tests/test_adr_log.py` accepts the reciprocal pairs; the docs index
   check passes.
2. **Records schema 1.5 and the event schema**: the new types, `task.kind`, `escalate`, `tlp`,
   `imported`, `record_event`; examples and negatives. Tests: each example validates; each
   negative fails for its named reason (a hold with no target, a ledger window over 90 days, a
   lane-filed note carrying `imported`); the frozen 1.4 copy is unchanged.
3. **The fold** (`state.py` under `homelabnext/records/`, generalising `derive()`). Tests: the same events
   in any file order fold to the same state; a task past `expires` reads `expired` with no file
   written; an expired ledger window reads `overdue`, never `closed`; a close with a stale
   `expected_revision` is refused; the registers' existing fold tests pass unchanged.
4. **Manifest 1.10 lanes and preconditions, request 1.2 `related`**: kind `records`, `dir`,
   `transitions`, `max_files: null`, `requires.deconflicted`, `requires.approved_record`,
   `findings` (default `per-run`) and `recall` on callers, `deconfliction.graders`, the records
   tree ownership check. Tests: each lane refusal by reason; a hold placed after an approval makes
   the approved `run` fail `record-held` and leaves the approval unused; a gated action submitted
   without `related` is refused `record-unlinked`; an agent's hold on an action it is not granted
   is `hold-target-not-allowed`; an emulation action with no active entry is
   `deconfliction-missing`; `validate` refuses an unknown `dir`, a world-readable records tree, and
   a `class: emulation` action without `requires.deconflicted`; a caller with a scheduler entry
   and no `findings` key reads `per-run`, and `findings: none` without a `reason` is refused.
5. **Relay operations and the decider in the broker**: `records-pending`, `records-decide`,
   `hold-place`, `hold-release`, `recall-raise`, `recall-resolve`; the Approvals page lists and
   decides notes under the viewer's ceiling; the CLI's `--break-glass`; the `decider.py`
   docstring's trust paragraph rewritten and its pinning test extended (decision 2). Tests: an
   unlisted person, self-approval and an agent approver (with `allow_agent_approvers: true`) are
   refused; a digest that changed after display is refused and the hub answers 409; a note above
   the viewer's ceiling shows no body and is `records-ceiling` to decide; a completion with one
   missing related item moves nothing; the sidecar names `issuer:subject` and `via`; `hnx records
   decide` on a locked tree without `--break-glass` is refused; the agent API does not import the
   decider.
6. **The MCP tools** and their catalog record. Tests: the broker-front check passes with exactly
   the registered tools; a reader profile cannot hold a write tool; no tool signature has an
   identity parameter; each tool maps to one action in `broker_actions`.
7. **Findings and recall gates**, the escalate page, invariants G-14 to G-16. Tests: an addressed
   agent's finding is `recall-unacked` until it acks; every answer to it carries `recall:` while
   the recall is active; a second ack is `lane-exists`; an escalation over the channel ceiling
   pages with name, severity and link and no body; a finished run with no finding is red and
   pages once; a break-glass CLI decision turns the decisions invariant red at once; a records
   directory at 80% of its byte cap warns.
8. **The `records` contract minor** (`RecordsLifecycleTarget`, the scenarios in
   `conformance/suites/records.py`, the fake, `broker-reference.yml`'s `records` entry, and the
   `.events/` sidecars in the `records` export and import). Tests: every scenario of decision 1
   passes against the reference broker; deleting any one of steps 4 to 7's refusals makes a named
   scenario fail; an export and import round trip keeps every event.
9. **`hnx broker import-vault`** with the map file, the reconciliation report, `--incremental`
   and `--compare`, over a synthetic vault fixture. Tests: a round trip accounts for every file and
   queue item; a dropped file exits 1; an unresolved hold stops the import and a `holds:` entry
   resolves it; a second `--apply` adds nothing; editing one queue item and re-running
   `--incremental` adds exactly one event; a note moved from approved to completed becomes one
   completion event, not a new record; a legacy id resolves through the aliases; the importer
   refuses while the state lock is held; imported decisions read `channel: import`, which the
   decisions invariant counts and reports apart from relay decisions and never treats as
   relay-authenticated.
10. **Overlay** (operator-merged, ADR-0026 stage 5): the lab's manifest lanes, quotas and grants,
    the map file, the tool-name table and rule deletions for the charters, the shadow run;
    ADR-0043's vault row moves to `new-shadow`.
11. **The canary** (overlay, operator-merged): one profile on the broker tools for the last shadow
    days, deciding on the hub.
12. **The switch** (overlay, operator-merged): the profile change of decision 12, the guard's
    zones emptied, the dashboard route off, the vault archived; ADR-0043's row to `new-primary`,
    then `old-retired`. Its evidence: the `records` contract run, the clean reconciliation, the
    shadow comparison's clean days and the canary's clean days with its decisions made on the hub.

## Alternatives

- **Port the vault's MCP servers as overlay modules** (ADR-0026 decision 6 as written). It is the
  least work and keeps the agents' prompts untouched, and it keeps everything the broker was built
  to remove: self-asserted requesters, an approver the backend cannot name, directories as the
  workflow and a second store of record beside the broker.
- **Re-point the old tools at the broker without changing their names.** Prompts would not change
  at all, but ADR-0030 lets only the broker's own front hold acting tools, and a lab-specific
  alias layer on it is a second front by another name. A name table in the overlay costs one
  substitution per charter.
- **Put the tasking queue in the `projects` capability.** Project boards are for people's work and
  mirror strategy one way (ADR-0020); agent tasks, holds and their refusals need to bite inside the
  broker's decision, which a tracker cannot do. ADR-0039 keeps them apart.
- **Leave holds as an agent's duty to check.** That is today's rule, written after it failed once;
  a refusal at run time is the only form of it that does not depend on the agent remembering.
- **Keep the decider as a separate process under its own user**, called by the broker over a pipe
  with the judged approver. It keeps the docstring's separation, but the broker would still be the
  component that judges the approver, so a compromised broker could forge the call; the separate
  user would add a process and a user to deploy without removing that trust.
- **Import only the open items and archive the rest read-only.** Cheaper, and the operator may yet
  choose it for findings (open question); the approved-but-unbuilt backlog and the holds on it
  cannot be left behind, because completing them is the agents' default work.
- **A database for the records.** One file per fact under one writer already gives exactly-once and
  conflict-free writes (ADR-0014, ADR-0017 decision 5); a database would add a datastore to back
  up and swap without adding a guarantee.
