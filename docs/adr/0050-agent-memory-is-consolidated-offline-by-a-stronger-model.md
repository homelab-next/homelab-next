---
summary: A scheduled pass, run by a stronger model, checks each agent's memory against its transcripts and promotes, corrects or retires it as sourced revisions.
summary_of: outline:sha256:4a97af4f457e7328
---
# ADR-0050: Agent memory is consolidated offline, by a stronger model

- **Status:** proposed
- **Date:** 2026-11-08
- **Related:** ADR-0026 (stage 3, the agent-runner contract; prompt assembly, PR 2.4), ADR-0032
  (context in levels), ADR-0035 (the coordinator's ledger), ADR-0038 (the gateway), ADR-0045 (the
  pass's credential), ADR-0047 (traces, run tokens, budgets, task evals), [Agent
  profiles](../agent.md) ("Agent memory (M-09)", G-03), [orchestration
  controller](../orchestration-controller.md) ("A job's prompt"), [status hub](../status.md),
  `homelabnext/agent/memory.py`, `homelabnext/agent/pack.py`, `homelabnext/agent/report.py`,
  `homelabnext/status/agents/`, `orchestrator/internal/prompt`, `tests/agent/replay/`; Anthropic,
  [The components of agent memory](https://www.anthropic.com/research/components-of-agent-memory)
  (2026-11-06)
- **Depends-on:** ADR-0033, ADR-0037
- **Amends:** ADR-0013, ADR-0037

## Context

ADR-0037 made an agent's memory trustworthy as a record. `MemoryStore` takes only the
`memory_updates` of a report checked against the pack it ran on. Every update appends a change
record (`at`, `scope`, `key`, `op`, `rev`, `value_digest`, `pack_id`, `sources`, `checked`,
`tlp`, `closure`), and the entries are a fold of that log. Reads are owner-scoped and cut at the
reader's ceiling. An operator can retract a bad source and everything built on it. The store
has a `Verifier` protocol with no implementation, so every entry is stale under any
`stale_after`.

It does not make memory useful, and nothing decides what memory is *for*:

- **Nothing renders memory to the model.** `assemble_pack` takes `memory=`
  (`memory_block_input`), but only ADR-0035's ledger renderer is planned to fill it. The
  controller's `prompt.Build` has `[own-state]` (at most 6,000 bytes) and `[prior-cursor]`
  blocks, built from state files and the cursor store, not from `MemoryStore`.
- **Only the agent that wrote a note can change it,** and only mid-task, while it is busy with
  something else. A wrong note stays until a run happens to notice it, or an operator retracts
  its source.
- **Nothing tells a guess from a checked fact.** `verify` is a model's reassertion, and
  `verified_at` waits for a verifier that does not exist.
- **The lab's agents run on local models,** much smaller than the frontier models most memory
  research uses.

Anthropic's article [The components of agent memory](https://www.anthropic.com/research/components-of-agent-memory)
(2026-11-06) reports experiments that bear on these gaps:

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
- **What to keep.** Keep verified facts, with how they were known, and strategy. Keep out state a
  tool can read again, which went stale, and untested guesses left as notes.
- **Small injected context.** The article's own harness injects only an index, the first 200
  lines or 25 KB of one file. Long injected files lower adherence and spread errors.
- **One page per entity.** Parallel writers to one shared table kept 41 of 57 graded facts; one
  page per entity kept all 57.
- **Failure modes.** Wrong notes trusted, drift, indiscriminate writing, guesses kept as facts,
  loops, and a wiki that grew larger than its sources and "abstracted nothing".
- **Measurement.** Results were compared with memory on and off, per model.

Three limits of that evidence shape this ADR:

- **The article tested Claude models only,** across several generations. Whether consolidation
  helps the small local models this lab runs is not shown.
- **In the article each model dreamed over its own memory.** Running the pass on a *stronger*
  model than the agent's own is this ADR's hypothesis, not the article's finding.
- **The article's agents were not reading hostile input.** Here most profiles are readers of
  untrusted content (G-03: `reads_untrusted` is true unless a spec says otherwise), and their
  transcripts quote feed items and tool output. A pass that turns transcript text into text
  every later run is shown is a path for injected content to persist. The defaults below are
  set for that threat first and for helpfulness second.

So decision 6 must measure both hypotheses, per profile, and either part must be cheap to switch
off.

Two things already hold here that the article had to add. Every fact is one key with its own
history, so there is no shared table to lose writes from. Every write is sourced and retractable,
so a wrong consolidation can be traced and undone.

## Decision

### The pass

1. **Consolidation is a job of the owning profile, on a configured model role, and its output is
   ordinary revisions.**
   - **Configured per profile.** A profile spec gains `memory_consolidation` (`agent/profile`
     1.8, additive):
     - `model_role`: required, an `mdl:` role. It may be the profile's own role (decision 6
       compares the two).
     - `every`: default 24 hours.
     - `budgets`: ADR-0047's run budgets, capped by the ceiling policy as the profile's own are.
     - `hypothesis_ttl`: default 14 days (decision 3).
     - `max_runs` (default 20), `max_promotions` (default 10) and `max_retires` (default 20) per
       pass.
     - `auto_promote`: default false (decision 4).

     A profile without the block is never consolidated, and nothing else in this ADR changes it.
     The compiler adds the platform scope `memory-consolidation` to both its `memory_scopes` and
     its `platform_scopes`, and refuses a spec that declares that scope itself.
   - **Only the platform starts a pass.** A systemd timer (`hnx-memory-consolidate.timer`, from
     the deploy) runs `hnx agent memory consolidate --due` as the platform's memory user. It
     submits a job with `purpose: consolidate` for each profile whose `every` has passed and
     whose owner has runs since its last pass. An operator may run the same command for one
     profile (`hnx agent memory consolidate <profile>`). The controller's job API accepts
     `purpose` only from those two principals: the timer's user and an operator. It refuses it
     from an agent principal, from the coordinator's actor and from any other caller. A retry
     under `max_attempts` keeps the purpose. A resubmit (`retry_of_run_id`) can neither add a
     purpose nor change one. No pass is admitted while another run of the same profile is
     running.
   - **A pass is a fixed job, not a task.** It carries no free-form task text: the prompt is a
     template in code. It is dispatched with empty toolsets, no MCP grants and no broker grant,
     enforced at dispatch, and the pack records `purpose: consolidate` and the empty grants. Its
     only effect is its report's memory updates. A poisoned transcript can steer what the pass
     writes into one profile's memory. It cannot act.
   - **The purpose is bound end to end.** The assembler writes the job's purpose into the pack
     (`pack["purpose"]`), beside the `profile` binding ADR-0037 already records. The store reads
     it from the session's own pack, which the runner holds, and refuses the consolidation-only
     fields of decisions 3 and 4 from any other pack. The controller adds `purpose` to the run
     tokens' claims (ADR-0047 decision 5). The gateway serves the consolidation role to a
     profile's key only under a token whose `purpose` is `consolidate`, and serves a
     `consolidate` token only that role. This holds even when the profile's key may otherwise use
     that role. So an ordinary run cannot spend the stronger role's budget, and a pass cannot
     reach the profile's other roles.
   - **What it writes.** It writes a `report_result` like any run, applied by `apply_report` with
     every ADR-0037 check: sources, label floor, closure cap, deny list, caps and history.
     - Every update in a consolidation batch carries `consolidation_reason`, a closed enum
       separate from ADR-0037's operator `reason`: `corrected`, `confirmed`, `merged`,
       `duplicate`, `promoted`, `demoted`, `contradicted` or `live-state`.
     - Every update, a `retire` included, cites at least one transcript item its pack rendered,
       the evidence that moved it.
     - A **correction** is a `replace`. A **merge** retires the duplicates and `replace`s one
       survivor, citing each merged revision as a `mem:` source. A pass's `add` is at most a
       `note` (decision 4).
     - The pass edits nothing in place, so `history` and `as_of` show what it changed and why,
       and `dependents` and `retract` reach what it wrote.
   - **One update per key, and none that it did not see.** Every update names `expect_rev`, the
     `rev` its memory block showed for the key (absent for a new key). The store refuses the
     batch when any key has moved since, or when a batch carries more than one update for a key.
     A `retire` and an `add` of the same key in one batch therefore cannot reset the key's
     history. That last rule applies to every checked batch, not only a pass's.
   - **Per-pass caps.** A batch with more promotions than `max_promotions` or more retirements
     than `max_retires` is refused whole. A refused pass changes nothing, and the next pass starts
     from the new state.
   - **Where it resumes.** The pass renders at most `max_runs` of the owner's runs, oldest first,
     from its cursor. After its report applies, platform code advances the cursor (`through`, the
     newest run rendered) in the `memory-consolidation` scope, unchecked as ADR-0037 decision 7
     allows, with a `keep_last` pattern so it stays bounded. A backlog drains over several passes.
     If the same window is refused three times in a row, the operator is paged (pair
     `AGENT_MEMORY_CONSOLIDATION_STUCK`, keyed by the profile, naming no key). `hnx agent memory
     consolidate <profile> --skip-window --reason <text>` then advances the cursor past the
     window, and the skip is recorded.
   - **Not consolidated:** platform scopes, which a report can never write. ADR-0035's
     `fleet-ledger` stays folded by code, never by a model. Its `coordinator-notes` scope is
     model-written and may be consolidated like any other.

2. **The transcript is ground truth, and every one is bound to its run and its sources.**
   - **What a transcript is.** For each of the owner's finished runs, the transcript is the run's
     report and the pack it ran on, plus its activity detail records (ADR-0013). Those records
     are `schemas/status/agent_activity_detail` 1.0: `event_id`, `session_id`, `time`,
     `prompt`, `command`, `tool_input`, `tool_output`, `error`, `approval`, `truncated` and
     `redactions`. They carry no trace id. Secrets are redacted, and every field is cut to its
     cap before storage. A transcript is therefore partial ground truth: a record marked
     `truncated` or with redactions is shown as such, and cannot be the only evidence for a
     confirmation (decision 3).
   - **The owner comes from the controller, never from the record.** A new reader,
     `homelabnext.agent.transcripts.read_runs`, starts from the controller's job rows. It takes
     the run ids whose `profile` is the owner, then joins detail records by `session_id` equal to
     the run id. It accepts a detail record only when the collector that delivered it is bound to
     that run's system user (the run's own spool, ADR-0045 decisions 6 and 7). A pushed record, or
     a record whose sender is any other principal, is refused, even when its `session_id` names
     the owner's run.
   - **Identities come from the platform.** The reader passes the rows it read to
     `resolve_input_uids(rows, source="agent-transcripts")`. That is a function over rows a
     reader stored, not a reader itself. Each transcript then becomes an input item with a
     platform-issued identity (ADR-0037 decision 7), and its `run_id` and `finished_at` are
     recorded in the pack.
   - **A transcript carries what its run saw.** Each transcript item carries, as its `pairs` and
     closure, the identifiers its run's own pack rendered (that pack's provenance block), so:
     - a record that cites a transcript has those identifiers in its closure, and `dependents`
       and `retract` reach it through the transcript (ADR-0037 decisions 10 and 13);
     - a transcript whose run rendered any denied source is dropped from the pass's pack before
       rendering. It is counted, and the rest of the window goes on, so one retraction never
       halts consolidation. A retracted feed item cannot be laundered back into memory through
       the transcript of a run that read it.
   - **Retention.** The detail tier keeps 14 days by default (`retention_days`), the same as the
     default `hypothesis_ttl`. `hnx agent memory consolidate` refuses a profile whose
     `hypothesis_ttl` is longer than the detail tier's retention, so that no hypothesis outlives
     the evidence that could confirm it. Where a run's detail records are gone, its report and
     pack still are, and a pass may judge from those alone. They can never confirm.
   - **ADR-0013 is amended:** the detail tier gains one reader beyond the hub's trusted front
     door. That reader is `read_runs`, in platform code, as the owning profile only, feeding that
     profile's own consolidation pack, at the profile's ceiling. No other model reader of the
     detail tier is allowed.

### What a run is shown

3. **Nothing is established until a pass says so.** An entry's place is one field, `rung`
   (`report_result` 1.3 adds it to a memory update; it is folded into the entry):
   `hypothesis`, `note`, `topic` or `index`, plus a `pending` flag (decision 4). `rung` is
   separate from the lifecycle `status` (`live` or `retired`) and from `verified_at`. A
   `Verifier` (ADR-0037 decision 15) may still stamp any rung, and staleness is still judged on
   `verified_at`.
   - **A run writes hypotheses only.** Every `add` or `replace` from an ordinary pack is stored as
     `hypothesis`, whatever it asks for. A run's `replace` of a `note` makes it a `hypothesis`
     again, until a pass judges it. A run may not change a `topic` or `index` entry at all. A run
     that finds an indexed fact wrong writes a hypothesis citing it (`mem:`), and the next pass
     acts on it. An urgent case is `MemoryAdmin.retract`, or a pass on demand.
   - **Only a pass confirms** (`hypothesis` to `note`, `consolidation_reason: confirmed`). A
     confirmation must cite a transcript of a **later run** than the one that wrote the
     hypothesis's current revision, and that transcript must lie outside the entry's own closure.
     A run cannot confirm what it wrote, and a source cannot vouch for itself. A transcript that is
     truncated or redacted cannot be the only cite.
   - **Shown as unconfirmed.** A hypothesis is never rendered as a fact (decision 4).
   - **Expiry.** A hypothesis expires `hypothesis_ttl` after the key became one. A `replace` or
     `verify` does not restart the clock, and the one-update-per-key rule stops a `retire` and
     `add` in one batch. An expired hypothesis is left out of every memory block, in code, so
     nothing can cite it. When a consolidation report applies, the store retires every expired
     hypothesis of the owner in the same transaction. Those records carry `expired: true` and are
     the one exception to decision 1's rule that a pass's record cites a transcript. That is the
     only write to a model-written scope that does not come from a report, and it only retires. It holds whether or not
     the pass's model notices the entry.
   - **Migration.** Every stored entry folds, without being rewritten, to `hypothesis`, its clock
     starting at a constant, `MIGRATION_CLOCK_START`, stamped in code with the release date.
     *Why every entry and not only well-sourced ones:* an ADR-0037 source is something the
     platform rendered, which proves the model saw it, not that it was right. A record source can
     be one a reader of untrusted content chose to cite. One rule is simpler to test, and an
     entry worth keeping is confirmed by its first passes.

4. **Memory climbs a ladder; only a pass moves it up, and only the operator lets it be shown.**
   - **The ladder.** `hypothesis` (a run's write), `note` (confirmed by a pass), `topic` (one entry
     per entity or subject; its value starts with a summary line of at most 160 characters, the
     L0 rule of ADR-0032, which the store checks), and `index` (the facts and strategies loaded
     into every run). Transcripts are the rung below, outside the store.
   - **Promotion** is a pass's `replace` of an existing entry, one rung at a time, with
     `consolidation_reason: promoted`. `demoted` moves an entry down. An `add` above `note` is
     refused, so nothing enters the index except by climbing. An entry cannot be promoted by the
     pass that put it on its current rung, nor by any pass whose cursor window began before it
     got there, so each step waits at least one pass. An entry whose closure exceeds 32
     identifiers cannot be promoted to `index`, so the index file stays within its bound.
   - **Promotion to `topic` or `index` creates a pending entry. A pass that creates or changes a
     `topic` or `index` value also creates a pending entry.** A pending entry renders nowhere
     until the operator approves it with `hnx agent memory review <profile>`. That command is a
     `MemoryAdmin` method taking an `OperatorPrincipal` (ADR-0037 decision 12). It lists each
     pending entry with its value, evidence and diff, and appends an operator record that
     approves it or rejects it. A rejection returns the entry to `note`. Removing an entry from
     the index (`demoted`, or a `retire`) takes effect without review: it reduces what runs see,
     and decision 7's restore covers a wrong removal.
   - **Auto-promotion is an opt-in, not for readers.** `auto_promote: true` skips the pending step
     for that profile. The compiler refuses it on a profile with `reads_untrusted: true`.
   - **The index.** A profile spec gains `memory_index` (`agent/profile` 1.8), which the compiler
     carries into `orchestrator_profile.prompt_context.memory_index`. It holds:
     - `max_bytes`: default 25,000, the UTF-8 bytes of the rendered index text, framing lines
       excluded;
     - `max_entries`: default 200;
     - `tail`: `off` (default) or `keys`.

     The ceiling policy caps `max_bytes` at 65,536 and `max_entries` at 512 by default. The
     renderer fills in order, stops at the cap and states how many entries it left out:
     1. approved `index` entries, value in full;
     2. approved `topic` entries, summary line only;
     3. with `tail: keys`, the **keys only** of hypotheses and notes written since the last pass,
        under a heading saying they are unconfirmed.

     The compiler refuses `tail: keys` on a profile with `reads_untrusted: true`, and the renderer
     never shows a tail to such a profile whatever its configuration says. Entries above the
     profile's ceiling are counted as withheld, as `read` counts them. Live-only entries
     (decision 5) are never rendered.
   - **The cap holds in three places.** The renderer never writes an index over it.
     `assemble_pack` refuses an index section over it. `prompt.Build` refuses an index file over
     it. A refused index is left out of the prompt with a logged notice and is **never cut**, as
     `MaxPromptBytes` is never cut: a cut would drop entries unseen. The run's record notes
     `memory_index: refused`.

5. **The index reaches the model by injection, from a file only the platform writes.**
   - **Injected, not fetched.** A weaker model often does not open its memory, so reading memory
     is not left to a tool call. With `prompt_context.memory_index` set, `prompt.Build` adds a
     `[memory-index]` block after `[own-state]`.
   - **The file.** `hnx agent memory index render` writes one index file per profile, after
     every applied report and every pass. It holds the rendered text, its memory block (`{scope,
     key, rev, value_digest, tlp, closure}` per entry, the shape `assemble_pack(memory=)` takes),
     the profile's id, its compiled digest and its ceiling, and the text's digest.
   - **Who owns it.** The file is owned by the platform's memory user, which is none of the
     profiles' users. Every directory above it is owned by root or that user, and nothing in the
     chain is writable by group or other. `hnx agent memory index check` and the controller both
     check this. The file is written to a temporary name in the same directory and renamed into
     place, so a reader never sees half a file.
   - **What `prompt.Build` checks.** Before parsing, it checks the file's size by `fstat`
     against a bound computed from the caps: `max_bytes`, plus `max_entries` times one entry's
     block at 32 closure identifiers. It refuses a file larger than that, a file that names
     another profile, a profile digest other than the loaded one, or a ceiling other than the
     profile's. It opens the file with the state-file rules (`safefs`, no link followed, a
     regular file only). The text's digest detects corruption only, not tampering: tampering is
     prevented by ownership, and only by ownership.
   - **How it is quoted.** As data, behind the framing line the state blocks use. `Build`'s
     result gains `memory_index: {profile, digest}`, beside the uids and the text digest it
     already returns. The session's pack records the index's memory block, so a `mem:` source
     naming an indexed entry is valid (ADR-0037 decision 11). Carrying that block into the pack
     needs the stage-3 runner contract (decision 9).
   - **The purpose.** With the index on, a profile-conditional `[memory-purpose]` block is
     appended beside `[memory-index]`. It is not one of `prompt.DefaultContracts`. It says what
     memory is for: to carry across runs what this agent has verified, and strategies that
     worked, so it does not have to re-derive them. It asks for two habits: read the index before
     acting, and test a hypothesis before relying on it, saying which were tested. It says to
     state how a fact was known, and not to record what a tool can read again. It sets no rule
     about *what* to record. Its text is in code, and a site may replace it in reviewed
     configuration.
   - **Structure lives in code.** Rungs, pending, caps and live sources are enforced by
     `validate_report`, `MemoryStore`, the renderer and `prompt.Build`, never by instructions the
     model is trusted to follow. A test holds that the purpose text names no field of
     `report_result`.

### What memory must not hold

6. **No memory of state a tool can read again, declared narrowly.** In v1 a source is live only
   when a context manifest input section declares `live: true` (`context_manifest` 1.4,
   additive): a section fed by a fleet-health verdict, a lake row count or a queue's state, for
   example.
   - **Tagged at write time.** The store sets `live_only: true` on a record that cites at least
     one non-`mem:` source, every one of them an item of a live section. It also sets it on a
     record whose only sources are `mem:` revisions that are all `live_only`. The tag is inherited
     through `mem:` closures this way, so restating a live-only fact does not wash it. The model
     never sets it. A live-only entry is never rendered and never promoted.
   - **Retired by the pass.** `consolidation_reason: live-state` is accepted only on a `retire` of
     an entry tagged `live_only`. A note that paraphrases live state without citing it is judged
     like any other note: the pass retires or corrects it with `contradicted` or `duplicate`,
     citing the transcript.
   - **Deferred:** declaring MCP servers live, and treating the controller's `[deterministic-facts]`,
     `[own-state]` and `[prior-cursor]` blocks as live. Neither is a pack item today, so neither
     could be checked at write time.

### Measurement

7. **Memory has to earn its place, per model, and every pass is counted and undoable.**
   - **Arms.** ADR-0047's task evals (`schemas/agent/task_eval`) gain a `memory` block that names
     the arms to run, each seeded from a fixture memory state:
     - `off`: no memory;
     - `unconsolidated`: the fixture's hypotheses as runs left them, with the index built from
       approved entries only;
     - `consolidated`: the same fixture after a recorded pass, once by the profile's own role and
       once by its `model_role`, so the stronger-model hypothesis is tested, not assumed;
     - `consolidated-no-purpose`: the same, without `[memory-purpose]`.

     `hnx evals run` runs each task in each arm against each model role the profile binds. The
     report (`hnx-agent-eval/1`) records the score per arm and the gains. `hnx evals check` fails
     a profile with `memory_consolidation` whose suite has no memory arms, or whose stored report
     is stale.
   - **The gain is reported, not gated.** It is shown in the eval report and on the status hub's
     agent page. A negative gain is the operator's cue to switch the index or the pass off for
     that profile, in reviewed configuration. A threshold that fails a gate is a later amendment,
     once there is data.
   - **Each pass emits `agent.memory.consolidated` 1.0.** It is a closed event of names and
     numbers, labelled `red`:
     - the profile, run id and trace id;
     - the count per `consolidation_reason`;
     - expired, pending and approved counts;
     - refusals by class, a closed enum (`expect-rev`, `per-key`, `per-pass-cap`, `record-cap`,
       `byte-cap`, `deny`, `source`, `label`, `schema`, `budget`);
     - transcripts dropped for a denied source;
     - each scope's record-cap headroom;
     - the size ratio.

     The ratio and the withheld counts are computed only over what the profile's own ceiling
     reads.
   - **The size ratio.** The bytes of the profile's live `topic` and `index` values, over the
     bytes of everything their closures cite: note values and the rendered transcript items.
     Values the log no longer holds (compacted or purged) cannot be measured. The ratio is then
     reported `partial` with that count, never computed as if they were empty. A ratio above 1
     means the representation grew larger than its sources: the article's "abstracted nothing".
     In v1 it is reported in the event and on the hub. An invariant over it is a later amendment.
   - **Undoable.** `MemoryAdmin.retract` gains restoration: when a retraction's reach includes
     the transcript a pass's `retire` cited, it appends a re-add of the retired value at
     `hypothesis` (operator record, `reason: restored:<deny id>`). That holds where the log still
     holds the value; it is counted where it does not. So a poisoned transcript that talked a pass
     into deleting good memory is undone by the same retraction.
   - **The replay judges the pass.** ADR-0037's memory replay (`tests/agent/replay/`) gains a
     consolidation fixture: a scripted reply from the deterministic fake for the consolidation
     role, with golden answers (implementation step 7).

### Safety

8. **A pass has exactly the owner's reach.**
   - **Same principal.** The pass runs as the owning profile: the same `VerifiedProfile` and
     system user. It uses the profile's own gateway key, delivered per run to the run's uid
     (ADR-0045 decision 6), with run tokens whose `purpose` claim binds the consolidation role
     (decision 1). It has the same `memory_scopes` and the same ceiling. No consolidator principal
     exists, and none reads two profiles' memory or transcripts (M-09, ADR-0035 decision 2).
     `hnx gen gateway render` adds the consolidation role to the profile's key, marked
     `purpose: consolidate`, and nothing else.
   - **Labels only rise.** The pass's pack takes the strictest label of what it renders, and
     every record it writes takes ADR-0037 decision 8's floor. A merge's survivor is never looser
     than anything merged into it.
   - **A cloud role sees only what it may.** ADR-0033 decision 11 refuses any request from a
     profile whose ceiling is above a cloud role's. So when `model_role` leaves the lab, the
     compiler refuses that pairing outright, rather than leave it to fail at the gateway. Since all
     memory is `red` until ADR-0037's follow-up 6 ships, **in practice the stronger model is a
     stronger model in the lab**.

### Amendments, dependencies, defaults and scope

9. **Amendments and dependencies.**
   - **ADR-0037 is amended** (it lists this ADR under **Amended-by**):
     - **Decisions 1 and 2:** a record and an entry gain `rung`, `pending`, `live_only`,
       `expired`, `consolidation_reason` and `expect_rev`. The fold reproduces them on both
       backends.
     - **Decision 7:** a pack records its `purpose`. `report_result` 1.3 adds `rung`,
       `consolidation_reason` and `expect_rev` to a memory update. A checked batch carries at most
       one update per key. The consolidation apply path's expiry retirements are a narrow
       exception to "only platform scopes take unchecked writes" (decision 3).
     - **Decision 12:** `MemoryAdmin` gains `review` (decision 4).
     - **Decision 13:** `retract` gains restoration (decision 7).
     - **Decision 15:** `rung` sits beside staleness and does not replace it. A pass is not a
       `Verifier`: it confirms against the profile's own later transcripts, while a `Verifier`
       checks against something other than the agent's runs.
     - **Decision 16:** the replay gains the consolidation fixture.
     - **Consequences ("a model-written scope only grows"):** still true. A pass adds records and
       removes none.
   - **ADR-0013 is amended** for the one new detail-tier reader (decision 2). It lists this ADR
     under **Amended-by**.
   - **Dependencies.** The pass needs the stage-3 agent-runner contract (ADR-0026): a session
     that holds its pack, applies its report through `apply_report`, and dispatches with the
     grants the pack records. Its run budgets need ADR-0047's gateway budgets, which follow the
     controller binary (ADR-0026 PR 2.7). Until both land, decisions 3 to 6 can ship and be
     tested on their own: rungs, the renderer, the index file and the live tag.
   - **Schema versions this ADR claims.**
     - `agent/profile` 1.8 (`memory_consolidation`, `memory_index`), `report_result` 1.3,
       `context_manifest` 1.4 and `agent.memory.consolidated` 1.0 (a draft) are unique to this
       ADR.
     - `platform/agent_profile` is a different schema. ADR-0047 takes its 1.3, and this ADR does
       not touch it.
     - `orchestrator_profile` is a draft and changes in place.
     - `task_eval` is ADR-0047's draft 1.0. The `memory` block goes into it in place if it is
       still a draft when this lands, and is 1.1 otherwise.
     - `agent.job.finished` gains `purpose`: in ADR-0047's 1.3 if that is not yet released,
       otherwise 1.4.
     - The run tokens' `purpose` claim is added to ADR-0047's shared vectors.

10. **Defaults decided for the operator.** The lead decided these on 2026-11-08 as defaults. The
    operator may change any of them by amending this ADR.
    - Promotion to `topic` or `index` waits for operator review. Auto-promotion is a per-profile
      opt-in, refused for readers.
    - The unconsolidated tail is off, shows keys only when on, and is never shown to a reader.
    - The consolidation role has no default. The overlay names one per profile. A role leaving the
      lab is refused for any profile above its ceiling, and with all memory `red`, that is every
      profile.
    - `hypothesis_ttl` 14 days; `every` 24 hours; `max_runs` 20; `max_promotions` 10;
      `max_retires` 20; index 25,000 bytes and 200 entries, under policy caps of 65,536 and 512.
    - The memory gain and the size ratio are reported, not gated.

11. **Out of scope.**
    - Memory inside the model (weights, recurrent state): ADR-0035 rejected it, for the same
      reasons.
    - Retrieval by embedding or semantic search over memory or transcripts.
    - A memory shared across profiles, or a fleet wiki. Promotion to shared records and pages
      stays a human-reviewed change in git (ADR-0032).
    - The broker's free-form `memory.write` lane, still open in docs/agent.md. It carries none of
      this.
    - Fine-tuning or training on transcripts.
    - Choosing the stronger model: that is a role binding in the overlay, made with the model
      goldens and canary like any rebind.
    - Live declarations beyond context manifest sections (decision 6).
    - ADR-0037's follow-up 3 (wider compaction), and interactive operator sessions (as in ADR-0047
      decision 14).

## Consequences

- **Easier:**
  - A wrong note stops being confirmed or shown within one pass of a later transcript that
    disproves it. The correction is a revision that names its evidence.
  - A weak local model sees a small, operator-approved index without having to decide to look,
    inside a budget it cannot exceed.
  - Content injected into one run cannot reach a later prompt without being confirmed and
    promoted over at least two passes, each citing a later run's transcript, and then approved
    by a person.
  - Whether memory helps a given model, and whether a stronger pass model helps more than the
    agent's own, are numbers per profile, not beliefs.
- **Harder:**
  - **The default is slow, on purpose.** Nothing a run writes is shown to later runs until a
    pass confirms it, later passes promote it, and the operator approves it. For a reader
    profile, memory helps only as fast as the operator reviews. The pending list is work, and it
    is the price of not letting transcripts write prompts.
  - A pass is a model run per profile per day on the consolidation role. It competes for the
    lab's local inference inside ADR-0047's budgets, and the timer should run in quiet hours.
  - The pass's judgement can be wrong. Its writes are traced, capped per pass and retractable,
    with restoration, and the eval arms catch a pass that makes memory worse, but only after the
    fact.
  - Transcripts are redacted and capped, and kept 14 days. A pass that cannot run in that window
    loses its evidence, and notes can then be kept, merged or retired, never confirmed.
  - Every pass adds records to a scope that only grows. The event reports headroom. ADR-0037's
    follow-up 3 (wider compaction) is not ordered before the pass: one pass adds at most
    `max_promotions + max_retires` records plus its corrections, bounded by the batch's 64
    updates, and the headroom figure says when compaction is due.
  - All memory is `red`, so a cloud role is no option until labels exist (ADR-0037 follow-up 6).
- **Obliges us to maintain:**
  - the consolidation checks in the store (purpose, rungs, later-transcript confirmation,
    per-key, per-pass caps, expiry, restoration);
  - the transcript reader's binding of owner and sender;
  - the index renderer, the index file's ownership and bound, and the three cap checks;
  - the run tokens' `purpose` claim at the gateway;
  - the `[memory-purpose]` text;
  - the memory arms in every consolidated profile's suite;
  - the replay's consolidation fixture.

### Implementation plan

Each step is one pull request, in this order. Steps 2 to 5 need nothing outside this repository's
Python and Go. Step 6 waits for ADR-0026 stage 3 and ADR-0047's gateway budgets (after PR 2.7).
Step 8 waits for ADR-0047's task evals (its step 10).

1. **This ADR** (docs only), with the **Amended:** and **Amended-by** lines on ADR-0013 and
   ADR-0037 and the index row. Its tests prove the ADR log passes (`tools/tests/test_adr_log.py`:
   the reciprocal pairs, `Depends-on` ids), the summaries are stamped and the docs index is
   current.
2. **Contracts.** `agent/profile` 1.8 with the compiler's rules, `report_result` 1.3,
   `context_manifest` 1.4, `orchestrator_profile`'s `prompt_context.memory_index` in place, and
   the draft event. Its tests prove:
   - each schema's examples pass and its negatives fail, including an unknown
     `consolidation_reason`, a refusal class outside the enum, and an event carrying a value or a
     key;
   - the compiler refuses `auto_promote` or `tail: keys` on a reader, a spec declaring
     `memory-consolidation`, a cloud `model_role` on a profile above its ceiling, and an index
     cap above the policy's;
   - the compiler puts `memory-consolidation` in both scope lists, and carries `memory_index`
     into the orchestrator profile.
3. **The store** (`homelabnext/agent/memory.py`, `report.py`). Its tests prove, on both backends:
   - an ordinary pack's `add` or `replace` is stored `hypothesis` whatever it asks, a run's
     `replace` of a note makes it a hypothesis, and a run's update to a topic or index entry is
     refused;
   - a second update for one key in a batch, and a `retire` with an `add` of one key, are
     refused whole;
   - a confirmation citing only an earlier or same run's transcript, one inside the entry's
     closure, or only a truncated record, is refused;
   - an `add` above `note`, a promotion skipping a rung, and a promotion within the pass that set
     the rung are refused;
   - an entry with more than 32 closure identifiers cannot reach `index`;
   - a promotion to topic or index is stored pending, and `review` approves or rejects it under
     an `OperatorPrincipal` only;
   - a moved `expect_rev` refuses the batch; caps over `max_promotions` or `max_retires` refuse
     it; a pass update with no transcript source is refused;
   - an expired hypothesis is absent from `memory_block_input`, and is retired when a
     consolidation report applies;
   - `live_only` needs a non-`mem:` live source and is inherited through `mem:` sources, and
     `live-state` on an untagged entry is refused;
   - `retract` of a transcript restores what a pass retired citing it;
   - folding reproduces every new field, and the migration folds every entry to `hypothesis` at
     `MIGRATION_CLOCK_START`.
4. **The renderer and the index file** (`homelabnext.agent.memory_index`, `hnx agent memory index
   render|check`). Its tests prove:
   - the cap holds against adversarial memory (10,000 entries of 2,000 characters, CJK included),
     by bytes and by entries;
   - the fill order and left-out counts match decision 4;
   - pending, hypothesis, withheld, live-only, expired and platform-scope entries are never
     rendered as values;
   - the tail is keys only, and absent for a reader even when configured;
   - every rendered entry is in the file's block with its `rev` and digest;
   - the file is renamed into place;
   - `check` refuses a file or directory writable by a profile's user, a group or others;
   - `assemble_pack` refuses an index section over the cap.
5. **The controller's blocks** (`orchestrator/internal/prompt`). Its tests prove:
   - a file over the computed bound is refused before parsing;
   - a file naming another profile, digest or ceiling is refused;
   - a link, a FIFO or a file in a writable directory is refused;
   - an index over the cap is left out with a notice, never cut, and the dispatch goes on;
   - a stored value cannot close the data block;
   - `[memory-purpose]` appears exactly when `memory_index` is set and is not among
     `DefaultContracts`;
   - `Build` returns `memory_index: {profile, digest}`;
   - the purpose text names no `report_result` field.
6. **The pass** (`homelabnext.agent.transcripts`, `hnx agent memory consolidate`, the timer, the
   job API, the gateway's purpose check). Its tests prove:
   - the job API refuses `purpose` from an agent principal and from the coordinator's actor, a
     resubmit cannot add or change it, and a retry keeps it;
   - a consolidation job is dispatched with empty toolsets, grants and MCP servers, and its pack
     records them, along with a task text from the template only;
   - the gateway refuses the consolidation role under a token without `purpose: consolidate`, and
     any other role under one with it;
   - `test_transcript_owner_comes_from_the_job_row`: a detail record whose `session_id` names
     another profile's run is never rendered;
   - `test_a_foreign_senders_detail_record_for_the_owners_run_is_refused`: a pushed record for
     the owner's run is refused;
   - `test_a_transcript_whose_run_rendered_a_denied_source_is_dropped`: the transcript is
     dropped, counted, and the rest of the window is consolidated;
   - the window holds at most `max_runs` runs oldest first; the cursor advances only after the
     report applies, so a pass that dies is replayed; three refusals of one window page once,
     and `--skip-window` advances it with a record;
   - a profile whose `hypothesis_ttl` exceeds the detail tier's retention is refused;
   - no pass is admitted while a run of the same profile runs;
   - platform scopes are never in a pass's memory block.
7. **Counting and the replay.** The event, the hub's row, the size ratio and the consolidation
   fixture with its golden answers. Its tests prove:
   - the ratio on fixtures above and below 1, and `partial` with compacted values;
   - the counts per reason, refusal class, dropped transcript and headroom;
   - the ratio and withheld counts honour the ceiling;
   - `make memory-replay` passes with answers for corrected, merged, promoted (pending), expired
     and restored keys.
8. **Memory arms in the task evals.** The `memory` block, the arms in `hnx evals run`, the check
   and the hub's gain column. Its tests prove that `hnx evals check` fails a consolidated profile
   with no arms or a stale report, and that the report records each arm's score per model role,
   both consolidation roles included, against the deterministic fake.
9. **Docs** land with each step: docs/agent.md's memory section, docs/orchestration-controller.md's
   "A job's prompt" and docs/status.md's detail-tier readers.

## Alternatives

- **Let the agent curate its own memory during its runs** (the status quo, and the article's
  baseline). The model curates while it works on something else, on the weaker model, with no
  ground truth beside it. The article's failure modes are what that produces. Rejected for a
  separate pass.
- **One consolidator agent over every profile's memory.** It would need cross-profile reads,
  which M-09 refuses, and one credential able to read every agent's transcripts. Rejected for a
  pass per profile, as the profile.
- **Consolidate in code only** (deduplicate by digest, expire by age). Code does what it can here:
  rungs, expiry, live tagging, caps and ordering. A correction needs someone to read the
  transcript and see that a note is wrong, which is a model's work. Rejected as the whole answer,
  kept as the floor.
- **Let the pass publish to the index directly.** It is faster, and it lets one hostile
  transcript reach every later prompt after enough passes with no person in the loop. Kept only
  as the opt-in `auto_promote` for profiles that read no untrusted content.
- **Show unconsolidated notes in full.** It helps a weak model soonest, and it turns any run's
  injected text into the next run's prompt. Rejected for keys only, off by default, never for
  readers.
- **Tell the model what to record** ("record only failures", fixed templates). The article
  measured this costing strong models their gain. Rejected for a stated purpose, with structure
  enforced in code.
- **A memory read tool instead of injection.** A weaker model often does not call it. Rejected
  for an injected index.
- **Let the pass edit or delete in place.** It would erase the history ADR-0037 keeps, and a bad
  pass could not be undone. Rejected for revisions and restoration.
- **Separate `standing` and `layer` fields.** That gives two axes with four forbidden
  combinations. Rejected for one ladder.
- **A separate gateway key for the pass.** It adds a credential per profile to ADR-0045's
  inventory. Rejected for the run token's `purpose` claim on the key the profile already has.
- **No cap, or a cap that truncates.** Long injected context lowers adherence, and a cut drops
  entries unseen. Rejected for a hard cap that is filled to and refused past.
