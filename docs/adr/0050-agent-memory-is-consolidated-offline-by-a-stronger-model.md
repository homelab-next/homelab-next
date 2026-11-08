---
summary: A scheduled pass, run by a stronger model, checks each agent's memory against its transcripts and promotes, corrects or retires it as sourced revisions.
summary_of: outline:sha256:3653d497888b0e51
---
# ADR-0050: Agent memory is consolidated offline, by a stronger model

- **Status:** proposed
- **Date:** 2026-11-08
- **Related:** ADR-0013 (the activity detail tier), ADR-0026 (prompt assembly, PR 2.4; the
  agent-runner contract, stage 3), ADR-0032 (context in levels), ADR-0035 (the coordinator's
  ledger), ADR-0038 (the gateway), ADR-0043 (the agent gate), ADR-0045 (the pass's
  principal), ADR-0047 (traces, budgets, task evals), [Agent profiles](../agent.md)
  ("Agent memory (M-09)"), [orchestration controller](../orchestration-controller.md) ("A job's
  prompt"), `homelabnext/agent/memory.py`, `homelabnext/agent/pack.py`,
  `homelabnext/agent/report.py`, `orchestrator/internal/prompt`, `tests/agent/replay/`; Anthropic,
  [The components of agent memory](https://www.anthropic.com/research/components-of-agent-memory)
  (2026-11-06)
- **Depends-on:** ADR-0033, ADR-0037
- **Amends:** ADR-0037

## Context

ADR-0037 made an agent's memory trustworthy as a record. `MemoryStore` takes only the
`memory_updates` of a report checked against the pack it ran on. Every update appends a change
record (`at`, `scope`, `key`, `op`, `rev`, `value_digest`, `pack_id`, `sources`, `checked`,
`tlp`, `closure`), and the entries are a fold of that log. Reads are owner-scoped and cut at the
reader's ceiling. An operator can retract a bad source and everything built on it. The store
also has a `Verifier` protocol with no implementation, so every entry is stale under any
`stale_after`.

It does not make memory useful, and nothing decides what memory is *for*:

- **Nothing renders memory to the model.** `assemble_pack` takes `memory=`
  (`memory_block_input`), but only ADR-0035's ledger renderer is planned to fill it. The
  controller's `prompt.Build` has `[own-state]` and `[prior-cursor]` blocks built from state
  files and the cursor store, not from `MemoryStore`.
- **Only the agent that wrote a note can ever change it,** and only mid-task, while it is
  busy with something else. Nothing reviews notes after the fact: a wrong note stays until a
  run happens to notice it, or an operator retracts its source.
- **Nothing tells a guess from a checked fact.** `verify` is a model's reassertion, and
  `verified_at` waits for a verifier that does not exist.
- **Nothing bounds what a profile would be shown,** apart from the controller's 1 MiB prompt cap
  and the state blocks' 12,000 bytes.
- **The lab's agents run on local models** much smaller than the frontier models that most
  memory research uses.

Anthropic's article [The components of agent memory](https://www.anthropic.com/research/components-of-agent-memory)
(2026-11-06) reports experiments that bear directly on these gaps:

- **A hierarchy.** It describes four layers: transcripts (a searchable log of what happened),
  notes the model writes, representations built from them (wiki or topic pages), and injected
  context loaded into every session. It calls offline consolidation **dreaming**: reflecting on
  logs, fixing mistakes, writing notes, building representations and choosing what is preloaded,
  with the transcript as ground truth.
- **Correction against the transcript works.** In one run, a wrong note about a location sent the
  agent back down a failing route three times before it gave up. Dreaming checked the note
  against the transcript and rewrote it, and the corrected run went on to progress.
- **Purpose beats rules for strong models; weaker ones need steering.** A rule such as "record
  only failures" cost strong models much of their gain from memory. An older model often did not
  read its memory at all, and prompting it to read memory first and to test its theories nearly
  doubled its score.
- **What to keep.** Keep verified facts, with how they were known, and strategy. Keep out
  state a tool can read again: such notes went stale. Keep out untested guesses left as notes.
- **Small injected context.** The article's own harness injects only an index, the first 200
  lines or 25 KB of one file. Long injected files lower adherence and spread errors.
- **One page per entity.** Parallel writers to one shared table kept 41 of 57 graded facts; one
  page per entity kept all 57.
- **Failure modes.** Wrong notes trusted, drift, indiscriminate writing, guesses kept as facts,
  loops, and a wiki that grew larger than its sources and "abstracted nothing".
- **Measurement.** Results were compared with memory on and off, per model.

**The article tested Claude models only**, across several generations. Whether consolidation
helps the small local models this lab runs is not shown. It is a hypothesis this ADR's
measurement (decision 6) has to test, and the design must be cheap to switch off per profile if
it does not hold.

Two things already hold here that the article had to add. Every fact is one key with its own
history, so there is no shared table to lose writes from. Every write is sourced and retractable,
so a consolidation that is wrong can be traced and undone.

## Decision

### The pass

1. **Consolidation is a scheduled job of the owning profile, run on a stronger model, and its
   output is ordinary revisions.**
   - **Configured per profile.** A profile spec gains `memory_consolidation` (`agent/profile`
     1.8, additive): `model_role` (required: an `mdl:` role, normally a stronger one than the
     profile's own, though it may be the same), `every` (default 24 hours), `budgets` (ADR-0047's run budgets, which the ceiling policy caps
     as it caps the profile's own), `hypothesis_ttl` (decision 3), `index` (decision 4) and
     `size_ratio_alert` (decision 6). A profile without it is never consolidated, and nothing
     else in this ADR changes it.
   - **A job, never the agent mid-task.** The controller's scheduler (ADR-0026 stage 2 PR 2.6)
     submits a job with `purpose: consolidate` for each such profile when `every` has passed and
     the owner has notes newer than its last pass. It never runs while another run of the same
     profile is running. `hnx agent memory consolidate <profile>` submits one on demand. The run
     is traced, tagged and budgeted like any other (ADR-0047 decisions 1 to 8), and its spans
     carry `purpose: consolidate`.
   - **The purpose is the platform's, never the model's.** The assembler writes the job's
     purpose into the pack (`pack["purpose"]`), beside the `profile` binding ADR-0037 already
     records. The store reads it from the session's own pack, which the runner holds. The
     consolidation-only fields of decisions 3 and 4 are refused from any pack whose purpose is
     not `consolidate`.
   - **Transcripts are the ground truth.** The pass's pack renders as input items the owner's
     own runs since its last pass. Each run has its report, the pack it ran on, and its
     activity detail record (ADR-0013's private detail tier, joined by ADR-0047's trace id). A new
     reader `resolve_input_uids(rows, source="agent-transcripts")` resolves each run's identity,
     so each item is a platform-issued source (ADR-0037 decision 7). Its memory block renders
     the owner's live entries in its model-written scopes, with their `rev`s. The reader returns
     only the owner's runs. A transcript the detail tier has already aged out is absent, and a
     note with no transcript left is judged on its record alone (decision 3).
   - **What it writes.** It writes the same `report_result` as any run, applied by
     `apply_report` with every ADR-0037 check: sources, label floor, closure cap, deny list,
     caps and history. A **correction** is a `replace` citing the transcript that contradicts
     the note. A **retraction** of the agent's own note is a `retire`. A **merge** retires
     duplicates and `add`s or `replace`s one survivor citing each merged revision as a `mem:`
     source. **Promotion** and **demotion** change `layer` (decision 4). **Confirmation** changes
     `standing` (decision 3). Each such record carries a `reason` (`report_result` 1.3,
     additive) from a closed set: `corrected`, `duplicate`, `merged`, `promoted`, `demoted`,
     `confirmed`, `hypothesis-expired`, `live-state`, `contradicted`. The pass edits nothing in
     place, so `history` and `as_of` show what it changed and why, and `dependents` and `retract`
     reach what it wrote.
   - **It never overwrites what it did not see.** Every update from a consolidation pack names
     `expect_rev`, the `rev` its memory block showed for that key (or none for a new key), and
     the store refuses a batch in which any key has moved since. A refused pass changes nothing
     and is counted (decision 6). The next pass starts from the new state.
   - **Where it resumes.** After the pass's report applies, platform code writes the transcript
     cursor (`through`, the newest run it rendered) to the platform scope
     `memory-consolidation`, unchecked as ADR-0037 decision 7 allows, with a `keep_last` pattern
     so it stays bounded. The compiler adds that scope to every profile with
     `memory_consolidation`.
   - **Not consolidated:** platform scopes, which a report can never write. ADR-0035's
     `fleet-ledger` stays folded by code, never by a model. Its `coordinator-notes` scope is
     model-written and may be consolidated like any other.

### What a run is shown

2. **Memory reaches the model by injection, and the prompt says what memory is for.**
   - **The index is injected, not fetched.** A weaker model often does not open its memory, so
     reading memory is not left to a tool call. `prompt.Build` gains a `[memory-index]` block
     after `[own-state]`, enabled by `prompt_context.memory_index: true` (`orchestrator_profile`,
     a draft, changed in place).
   - **Its input is platform-rendered.** The block's input is a per-profile index file that
     platform code renders after every applied report and every pass (`hnx agent memory index
     render`, from `memory_block_input` and `read`). The file sits in a directory no agent can
     write, under the rules for state files: `safefs`, opened without following a link, a regular
     file only. It holds the rendered text, its memory block (`{scope, key, rev, value_digest,
     tlp, closure}` per entry, the shape `assemble_pack(memory=)` takes) and the text's digest.
   - **What the block does with it.** It quotes the text as data, behind the framing line the
     state blocks use. `Build` returns the index's digest among what it quoted, and a session's
     pack records the index's memory block, so a `mem:` source naming an indexed entry is valid
     (ADR-0037 decision 11). Carrying that block into the session's pack is a requirement the
     stage-3 agent-runner contract inherits, as ADR-0047 decision 2's trace is. Until then, a
     profile reads its index only through a pack assembled with `memory=` from the same block.
   - **The prompt states memory's purpose.** A fourth built-in contract, `[memory-purpose]`
     (`prompt.DefaultContracts`), is emitted only when the index is on. It says what memory is
     for: to carry across runs what this agent has verified, and the strategies that worked, so
     it does not have to re-derive them. It says to read the index before acting, and to test a
     hypothesis before relying on it and say which ones were tested. It says to record how a fact
     was known, and not to record what a tool can read again. It sets no rule about what to
     record. A site replaces it as it replaces any contract (`prompt_contracts`).
   - **Structure lives in code, not in the prompt.** Fields, layers, standing, caps and live
     sources are enforced by `validate_report`, `MemoryStore` and the renderer, never by
     instructions the model is trusted to follow. A test holds that the contract's text names no
     field of `report_result`.

### Standing and layers

3. **A note is a hypothesis until a pass confirms it with evidence, and an unconfirmed one
   expires.**
   - **The field.** A record and its entry gain `standing`: `hypothesis` or `established`
     (`report_result` 1.3 adds it to a memory update). It is not the entry's lifecycle `status`
     (`live` or `retired`). It is not `verified_at` either: a `Verifier` (ADR-0037 decision 15)
     can still stamp an established fact, and staleness is still judged on `verified_at`.
   - **A run's writes.** An ordinary run's `add` or `replace` is a `hypothesis` unless it says
     `established` and cites at least one non-`mem:` source its pack rendered. Code refuses
     `established` without one. A run may not change an existing hypothesis to `established`:
     **only a consolidation pack confirms**, with `reason: confirmed`, and only by citing a
     transcript item, a non-`mem:` source the pack rendered.
   - **Shown as unconfirmed.** The index and every memory block render a hypothesis marked
     `unconfirmed`, so the model sees the difference.
   - **Expiry.** A hypothesis expires `hypothesis_ttl` (default 14 days) after the key first
     became one since its last `add`. A `replace` or `verify` does not restart the clock, so a
     guess cannot be kept alive by repeating it. An expired hypothesis is left out of the index
     and of every memory block, in code, whether or not a pass runs, so nothing can cite it. The
     next pass retires it (`reason: hypothesis-expired`) unless it confirms it.
   - **Migration.** Stored entries fold, without being rewritten, to `established` when their
     record has non-empty `sources` and to `hypothesis` otherwise. Their clock starts on the
     release that ships this ADR, so nothing expires on the day of the upgrade.

4. **Memory climbs a ladder, only the pass moves it up, and the top rung has a hard cap.**
   - **The rungs.** A record and its entry gain `layer`: `note`, `topic` or `index`. Transcripts
     are the rung below, outside the store.
     - **`note`:** what a run writes. Every update from an ordinary pack is a note, and code
       refuses any other `layer` from one, or any update to a key whose layer is `topic` or
       `index`. A run that finds an indexed fact wrong writes a note citing it (`mem:`), and
       the next pass acts on it. An urgent case is `MemoryAdmin.retract`, or a pass on demand.
     - **`topic`:** one entry per entity or subject, written only by a pass. Its value starts
       with a one-line summary of at most 160 characters, the L0 rule of ADR-0032, which the
       store checks.
     - **`index`:** the facts and strategies loaded into every run. Only a pass writes them, and
       only an `established` entry may be promoted to `topic` or `index`.
   - **Promotion and demotion** are `replace`s by a pass carrying `reason: promoted` or
     `demoted`, so the ladder is history like everything else.
   - **The index renderer** fills in this order and stops at the cap:
     1. `index` entries in full;
     2. `topic` entries by key and summary line;
     3. the newest notes written since the last pass, under a heading saying they are
        unconsolidated, each hypothesis marked.

     It then states how many of each were left out. Entries labelled above the profile's ceiling
     are counted as withheld, as `read` counts them, and live-only notes (decision 5) are not
     rendered at all.
   - **The cap.** `memory_consolidation.index` holds `max_bytes` (default 25,000) and
     `max_entries` (default 200), near the article's 200 lines or 25 KB. The ceiling policy caps
     both, at 65,536 bytes and 512 entries by default. The cap is enforced twice: the renderer
     never writes an index over it, and `prompt.Build` (and `assemble_pack` for the pack path)
     refuses an index over it. A refused index is left out of the prompt with a logged notice
     and is **never cut**, as `MaxPromptBytes` is never cut. A cut would drop entries unseen.
     The run's record notes `memory_index: refused`.

### What memory must not hold

5. **No memory of state a tool can read again.** A note copied from live state is stale the
   next time that state moves, so the platform knows which sources are live:
   - **How a source is declared live.** Three ways:
     - a context manifest input section declares `live: true` (`context_manifest` 1.4,
       additive), for example a section fed by the fleet-health verdict, a lake row count or a
       queue's state;
     - the controller's `[deterministic-facts]`, `[own-state]`, `[prior-cursor]` and
       `[known-incidents]` blocks are live by definition;
     - an MCP catalog record declares `live: true` (`platform/mcp_server` 1.5, additive) for a
       server whose tools return current state.
   - **Tagged at write time.** An update whose every non-`mem:` source is an item of a live
     section is stored with `live_only: true`, set by the store, never by the model. The
     renderer never puts it in the index, and it can never be promoted. The next pass retires it
     with `reason: live-state` unless it rewrites it as a lasting rule that cites more than live
     state.
   - **Judged by the pass.** A note that restates what a live tool returned without citing it
     (the transcript shows the tool call) is for the pass's model to find. It retires the note
     with `reason: live-state` and `live_source`, naming the declared section or catalog id. The
     store refuses `live-state` whose `live_source` names no live source the profile declares,
     so the reason cannot be used to remove arbitrary notes without saying which source makes
     them redundant.

### Measurement

6. **Memory has to earn its place, per model, and every pass is counted.**
   - **Memory on and off.** ADR-0047's task evals (`schemas/agent/task_eval`, a draft until that
     ADR lands) gain a `memory` block: the arms to run (`off`, `on`, and `on-no-contract` to
     measure the steering of decision 2) and a fixture memory state to seed. `hnx evals run`
     runs every task in every arm against each model role the profile binds, including the
     consolidation role, and the report (`hnx-agent-eval/1`) records the score per arm and the
     gain, `on` minus `off`. `hnx evals check` fails a profile with `memory_consolidation` whose
     suite has no memory arms, or whose stored report is stale.
   - **The gain is reported, not gated, at first.** A negative gain on a live report is shown on
     the agent's row of ADR-0043's cutover ledger. The operator then turns the index or the pass
     off for that profile, by removing `memory_index` or `memory_consolidation` in reviewed
     configuration. A threshold that fails the gate is a later amendment, once there is data.
   - **Does a representation abstract anything?** After each pass, platform code computes the
     profile's **size ratio**: the bytes of its live `topic` and `index` values over the bytes of
     the note values their closures cite (values still in the log; compacted or purged ones
     count zero and are reported). Invariant **"consolidated memory abstracts"** is red for a
     profile whose ratio exceeds its `size_ratio_alert` (default 1.0) and pages only when newly
     red (`page_changes`). A ratio above 1 means the representation grew larger than its
     sources: the article's "abstracted nothing".
   - **Outcomes counted.** Each pass emits `agent.memory.consolidated` 1.0, a closed event of
     names and numbers only. It carries the profile, run id, trace id, the count per `reason`,
     the counts refused (with the refusal class), withheld and expired, and the size ratio. The
     status hub's agent page shows the last pass per profile.
   - **The replay judges the pass.** ADR-0037's memory replay (`tests/agent/replay/`) gains a
     consolidation fixture: a scripted reply from the deterministic fake for the consolidation
     role, with golden answers. The answers cover which keys are corrected, merged, promoted and
     expired; that a promotion without a transcript source is refused; that an `expect_rev`
     conflict refuses the batch; and that the index stays within its cap.

### Safety

7. **A pass has exactly the owner's reach, and no more.**
   - **Same principal.** The pass runs as the owning profile: the same `VerifiedProfile`, system
     user, per-run gateway key and run tokens (ADR-0045 decisions 6 and 7), the same
     `memory_scopes` and the same ceiling. No consolidator principal exists, and none can read two
     profiles' memory or transcripts (M-09, ADR-0035 decision 2). `hnx gen gateway render`
     adds the consolidation role to the profile's key's allowed roles and nothing else.
   - **It reads untrusted text and can do nothing else.** Transcripts quote feed items and tool
     output. The pass is dispatched with no toolsets and no MCP or broker grants: its only
     effect is its report's memory updates, and they are sourced, labelled and retractable. A
     poisoned transcript can steer what the pass writes into that one profile's memory. It
     cannot act, and `retract` on the transcript's identity reaches what it caused (ADR-0037
     decision 13).
   - **Labels only rise.** The pass's pack takes the strictest label of what it renders, and
     every record it writes takes ADR-0037 decision 8's floor. A merge's survivor is therefore
     never looser than anything merged into it. A batch that names a scope the profile does not
     hold, or a `mem:` revision outside its block, is refused whole, as for any run.
   - **A cloud role sees only what it may.** When `model_role` leaves the lab, ADR-0033 decision
     11 already refuses any request from a profile whose ceiling is above the role's, so the
     compiler refuses that pairing outright rather than leave it to fail at the gateway. For a
     profile at or below the role's ceiling, the assembler renders only transcripts and entries
     at or below it and counts the rest as withheld. Since all memory is `red` until ADR-0037's
     follow-up 6 ships, **in practice the stronger model is a stronger model in the lab**.

### Amendment and scope

8. **ADR-0037 is amended** (it lists this ADR under **Amended-by**):
   - **Decisions 1 and 2:** a record and an entry gain `standing`, `layer`, `reason` (no longer
     only on operator records), `live_only` and, on a consolidation record, `expect_rev`. The
     fold reproduces all of them, on both backends.
   - **Decision 7:** a pack records its `purpose`, and the store refuses consolidation-only
     fields from any other pack. `report_result` 1.3 adds `standing`, `layer`, `reason`,
     `live_source` and `expect_rev` to a memory update, additively.
   - **Decision 15:** `standing` sits beside staleness and does not replace it. The pass is not
     a `Verifier`: it confirms against the profile's own transcripts, while a `Verifier` checks
     against something other than the agent's runs. Both may stamp the same entry.
   - **Decision 16:** the replay gains the consolidation fixture of decision 6.
   - **Consequences ("a model-written scope only grows"):** still true. A pass adds records and
     removes none; consolidation is not compaction, which stays ADR-0037's follow-up 3.

9. **Out of scope.**
   - Memory inside the model (weights, recurrent state): ADR-0035 rejected it, for the same
     reasons.
   - Retrieval by embedding or semantic search over memory or transcripts.
   - A memory shared across profiles, or a fleet wiki. Promotion to the shared knowledge the
     records and pages hold stays a human-reviewed change in git (ADR-0032).
   - The broker's free-form `memory.write` lane, still open in docs/agent.md. It carries none
     of this.
   - Fine-tuning or training on transcripts.
   - Choosing the stronger model. That is a role binding in the overlay, made with the model
     goldens and canary like any rebind.
   - Interactive operator sessions, as in ADR-0047 decision 14.

## Consequences

- **Easier:**
  - A wrong note stops steering runs within one pass of the transcript that disproves it,
    without an operator noticing it first. The correction is a revision that names its evidence.
  - A weak local model sees its most useful memory without having to decide to look, inside a
    budget it cannot exceed, with guesses visibly marked as guesses.
  - Whether memory helps a given model is a number per profile and per model role, not a belief.
- **Harder:**
  - A pass is a model run per profile per day on the stronger role. It competes with the fleet
    for the lab's local inference, inside ADR-0047's budgets. The scheduler should run passes in
    quiet hours, and `every` is per profile.
  - New notes reach the index only through the "unconsolidated" tail until a pass runs, so a
    lesson learned this morning is weaker this afternoon than it would be in a free-form file.
  - The pass's own judgement can be wrong. Its writes are traced and retractable, and the eval
    arms and the size ratio catch a pass that makes memory worse, but only after the fact.
  - Transcripts age out of the detail tier. A pass that does not run inside the retention
    window loses its ground truth, and those notes can then only be kept, merged or retired,
    never confirmed.
  - All memory is `red` today, so a cloud role is no option for consolidation until labels
    exist (ADR-0037 follow-up 6). The "stronger model" is the strongest local one.
  - An entry now has three axes beside its value: `status`, `standing` and `layer`. The docs
    and the renderer have to keep them distinct.
- **Obliges us to maintain:** the consolidation-only checks in the store, the index renderer and
  both cap checks, the `[memory-purpose]` contract text, the live-source declarations, the
  memory arms in every memory profile's suite, the size-ratio invariant and the replay's
  consolidation fixture.

### Implementation plan

Each step is one pull request, in this order. Steps 2 to 5 need nothing outside this repository's
Python and Go. Step 6 waits for ADR-0026 stage 2 PR 2.6 (the scheduler) and step 8 for ADR-0047's
task evals (its step 10).

1. **This ADR** (docs only), with the **Amended-by** line on ADR-0037 and the index row. Its tests
   prove the ADR log passes (`tools/tests/test_adr_log.py`: the reciprocal pair, `Depends-on`
   ids), the summaries are stamped and the docs index is current.
2. **Contracts.** `report_result` 1.3, `agent/profile` 1.8 (`memory_consolidation`, with the
   ceiling policy's caps on `index` and `budgets`), `context_manifest` 1.4 (`live`),
   `platform/mcp_server` 1.5 (`live`), `orchestrator_profile`'s `prompt_context.memory_index` in
   place, and the draft event `agent.memory.consolidated` 1.0. Its tests prove each schema's
   examples pass and its negatives fail. The negatives include an unknown `reason`, a
   `live-state` reason without `live_source`, an `index.max_bytes` above the policy cap and an
   event carrying a value or a key.
3. **The store.** `standing`, `layer`, `reason`, `live_only`, `expect_rev`, the pack's `purpose`
   and hypothesis expiry, in `homelabnext/agent/memory.py` and `report.py`. Its tests prove, on
   both backends:
   - an ordinary pack's update with `layer: topic`, `reason`, or `established` without a
     non-`mem:` source is refused whole;
   - a run's update to a `topic` or `index` key is refused;
   - a consolidation pack's confirmation or promotion without a transcript source is refused;
   - a moved `expect_rev` refuses the batch and writes nothing;
   - an expired hypothesis is absent from `memory_block_input` and a `mem:` source naming it is
     refused;
   - an update sourced only from a `live` section is stored `live_only`;
   - folding the log reproduces every new field, and the migration folds sourced entries to
     `established` without rewriting them.
4. **The index renderer.** `homelabnext.agent.memory_index` and `hnx agent memory index render`.
   Its tests prove:
   - the cap holds against adversarial memory (10,000 entries of 2,000 characters, CJK text
     included), by bytes and by entries;
   - the fill order and the left-out counts are as decision 4 states;
   - withheld, live-only, expired and platform-scope entries are never rendered;
   - every rendered entry is in the file's memory block, with the `rev` and digest of the
     entry it shows;
   - `assemble_pack` refuses an index section over the cap.
5. **The controller's block and contract** (`orchestrator/internal/prompt`). Its tests prove:
   - an index file over the cap is left out with a notice, never cut, and the dispatch goes on;
   - a link, a FIFO or a file in an agent-writable directory is refused, as for state files;
   - the text sits behind the data framing, and a stored value cannot close the block;
   - `[memory-purpose]` appears exactly when `memory_index` is on;
   - `Build` returns the index's digest;
   - the contract's text names no `report_result` field.
6. **The pass.** The compiler's checks, the transcript reader, the consolidation pack, the
   scheduler entry and `hnx agent memory consolidate`. Its tests prove:
   - the compiler refuses a cloud `model_role` on a profile whose ceiling is above the role's;
   - a consolidation job is dispatched with empty toolsets and grants;
   - the transcript reader refuses another profile's runs;
   - a transcript above the role's ceiling is not rendered and is counted withheld;
   - no pass is admitted while a run of the same profile is running;
   - the `memory-consolidation` cursor advances only after the report applies, so a pass that
     dies is replayed;
   - platform scopes, `fleet-ledger` included, are never in a consolidation pack's memory block.
7. **Counting.** The `agent.memory.consolidated` event, the size ratio, the invariant and the
   status hub's row, plus the replay's consolidation fixture and golden answers. Its tests prove
   the ratio on fixtures above and below the threshold, the invariant goes red and pages once
   (`page_changes`), and `make memory-replay` passes with the new answers.
8. **Memory arms in the task evals.** The `memory` block in `task_eval`, the arms in `hnx evals
   run`, and the check. Its tests prove `hnx evals check` fails a memory profile with no arms
   or with a stale report, and the report records each arm's score and the gain per model role
   against the deterministic fake.
9. **Docs** land with each step: docs/agent.md's memory section and
   docs/orchestration-controller.md's "A job's prompt" are updated by the step that changes them.

## Alternatives

- **Let the agent curate its own memory during its runs** (the status quo, and the article's
  baseline). The model curates while it works on something else, on the weaker model, with no
  ground truth beside it. The article's failure modes (indiscriminate writing, untested guesses
  kept, drift) are what that produces. Rejected for a separate pass.
- **One consolidator agent over every profile's memory.** It would need cross-profile reads,
  which M-09 refuses and ADR-0035 kept refused, and one credential able to read every agent's
  transcripts. Rejected for a pass per profile, as the profile.
- **Consolidate in code only** (deduplicate by digest, expire by age). Code does what it can here:
  expiry, live-only tagging, caps and ordering. But a correction needs someone to read the
  transcript and see that the note is wrong, which is a model's work. Rejected as the whole
  answer, kept as the floor.
- **Tell the model what to record** ("record only failures", fixed templates). The article
  measured this costing strong models their gain. Rejected for a stated purpose (decision 2),
  with structure enforced in code instead of described in the prompt.
- **A memory read tool instead of injection.** A weaker model often does not call it. Rejected
  for an injected index, with topic pages available in levels beside it.
- **Let the pass edit or delete notes in place.** It would erase the history ADR-0037 exists to
  keep, and a bad pass could not be undone. Rejected for revisions.
- **Run the pass on the profile's own model by default.** It is allowed, but `model_role` must be
  named on purpose: the pass's judgement is the part that needs a stronger model, and the
  article's weaker models were the ones that left guesses as notes.
- **No cap, or a cap that truncates.** Long injected context lowers adherence and spreads
  errors, and a cut drops entries unseen. Rejected for a hard cap the renderer fills to and the
  prompt refuses past.
