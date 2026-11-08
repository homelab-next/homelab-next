---
summary: A scheduled pass, run by a stronger model, checks each agent's memory against its transcripts and promotes, corrects or retires it as sourced revisions.
summary_of: outline:sha256:20385de93a54679b
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
reader's ceiling. An operator can retract a bad source and everything built on it.

It does not make memory useful:

- **Nothing renders memory to the model.** `assemble_pack` takes `memory=`
  (`memory_block_input`), but only ADR-0035's ledger renderer is planned to fill it. The
  controller's `prompt.Build` has `[own-state]` (at most 6,000 bytes) and `[prior-cursor]`
  blocks, built from state files and the cursor store, not from `MemoryStore`.
- **Only the agent that wrote a note can change it,** mid-task, while busy with something else.
- **Nothing tells a guess from a checked fact.** `verify` is a model's reassertion, and
  `verified_at` waits for a `Verifier` that does not exist.
- **The lab's agents run on small local models.**

Anthropic's article [The components of agent memory](https://www.anthropic.com/research/components-of-agent-memory)
(2026-11-06) reports experiments that bear on these gaps:

- **A hierarchy.** Transcripts (a log of what happened), notes the model writes, representations
  built from them (wiki or topic pages), and injected context loaded into every session. It calls
  offline consolidation **dreaming**: reflecting on logs, fixing mistakes, building
  representations and choosing what is preloaded, with the transcript as ground truth.
- **Correction works.** A wrong note about a location sent an agent down a failing route three
  times. Dreaming checked the note against the transcript and rewrote it, and the corrected run
  progressed.
- **Purpose beats rules for strong models; weaker ones need steering.** A rule such as "record
  only failures" cost strong models much of their gain. An older model often did not read its
  memory, and prompting it to read memory first and test its theories nearly doubled its score.
- **What to keep.** Verified facts with how they were known, and strategy. Not state a tool can
  read again, which went stale, and not untested guesses.
- **Small injected context.** Its harness injects an index of at most 200 lines or 25 KB. Long
  injected files lower adherence and spread errors.
- **One page per entity.** Parallel writers to one shared table kept 41 of 57 graded facts; one
  page per entity kept all 57.
- **Failure modes.** Wrong notes trusted, drift, indiscriminate writing, guesses kept as facts,
  loops, and a wiki larger than its sources that "abstracted nothing".
- **Measurement.** Memory on against memory off, per model.

Three limits of that evidence shape this ADR:

- **The article tested Claude models only.** That consolidation helps small local models is not
  shown.
- **In the article each model dreamed over its own memory.** Running the pass on a *stronger*
  model is this ADR's own hypothesis.
- **The article's agents were not reading hostile input.** Most profiles here are readers of
  untrusted content (G-03: `reads_untrusted` is true unless a spec says otherwise), and their
  transcripts quote feed items and tool output. A pass that turns transcript text into text
  later runs are shown is a path for injected content to persist. The defaults are set for that
  threat first.

So decision 7 measures both hypotheses per profile, and both parts switch off per profile.

## Decision

### Who it applies to

1. **Only profiles that opt in.** A profile spec gains `memory_consolidation` and `memory_index`
   (`agent/profile` 1.8, additive). Everything in this ADR applies only to a profile with
   `memory_consolidation`. For every other profile, the coordinator's `coordinator-notes`
   included, `MemoryStore` behaves exactly as ADR-0037 says: no rung, no expiry and no
   migration. The only change such a profile sees is that a checked batch carries at most one
   update per key (decision 4).

### The pass

2. **Consolidation is a job of the owning profile, started only by the platform, with no tools.**
   - **Configuration.** `memory_consolidation` holds:
     - `model_role`: required, an `mdl:` role. It may be the profile's own role, and decision 7
       compares the two.
     - `every`: default 24 hours.
     - `budgets`: ADR-0047's run budgets. The run tokens of a pass carry these, not the profile's
       ordinary budgets: budgets are picked by purpose.
     - `hypothesis_ttl`: default 14 days.
     - `max_runs` (default 20) and `max_retires` (default 20) per pass, and `max_pending`
       (default 10, decision 5).
     - `auto_promote`: default false (decision 5).

     The compiler adds the platform scope `memory-consolidation` to both `memory_scopes` and
     `platform_scopes`, and refuses a spec that declares that scope itself.
   - **Started only by the platform.** A deployed systemd timer, `hnx-memory-consolidate.timer`,
     runs `hnx agent memory consolidate --due` as the platform's memory user. It submits a job
     with `purpose: consolidate` for each profile that is due and has runs since its last pass.
     An operator may run the same command for one profile. The controller's job API accepts
     `purpose` only from those two principals. A retry keeps the purpose. A resubmit
     (`retry_of_run_id`) can neither add nor change it.
   - **One at a time, both ways.** A pass is not admitted while a run of its profile runs, and
     no run of the profile is admitted while its pass runs.
   - **A fixed job.** It has no free-form task text: the prompt is a template in code. It is
     dispatched with empty toolsets, MCP grants and broker grants, enforced at dispatch, and its
     pack records `purpose: consolidate` and those empty grants. The assembler writes the purpose
     into the pack; the store reads it from the session's own pack and refuses the
     consolidation-only fields of decisions 4 and 5 from any other pack.
   - **Bound at the gateway.** The run tokens (ADR-0047 decision 5) gain a `purpose` claim. `hnx
     gen gateway render` adds the consolidation role to the profile's own key, marked `purpose:
     consolidate`. The gateway serves that role only under a token whose `purpose` is
     `consolidate`, and serves such a token no other role. That role requires a token from the
     first day: it is never `run_binding: optional`, and the render refuses a purpose-marked role
     on any key whose run binding is not required. So an ordinary run cannot spend the pass's
     budget or role, and a pass cannot reach the profile's other roles. Opting a profile in
     therefore makes its whole gateway key require run tokens, so its ordinary runs need them
     too.
   - **The pass's tokens die with it.** They are delivered in the pass unit's
     `$CREDENTIALS_DIRECTORY` (ADR-0045 decision 6), which goes away when the unit stops. Their
     `exp` is the pass's own deadline plus ADR-0047's grace. No other run of the profile runs
     beside the pass (the exclusion above), and the pass has no tools, so nothing holds a copy
     once the unit has stopped.
   - **What it writes.** A `report_result`, applied by `apply_report` with every ADR-0037 check.
     Each update carries `consolidation_reason`, a closed enum separate from ADR-0037's operator
     `reason`: `corrected`, `confirmed`, `merged`, `duplicate`, `promoted`, `demoted`,
     `contradicted` or `live-state`. Each cites at least one transcript its pack rendered, and
     names `expect_rev`. The memory block shows each entry's head `rev` (its latest revision) and,
     for an entry with a shadow (decision 4), the shadow's `{rev, value_digest}` beside it.
     `expect_rev` is checked against the head, never against the shadow, and is absent for a new
     key. The store refuses the batch when any head has moved since. A batch with more retirements
     than `max_retires` is refused whole. The pass edits nothing in place, so `history`, `as_of`,
     `dependents` and `retract` all see what it did.
   - **Where it resumes.** The pass renders at most `max_runs` of the owner's runs, oldest
     first, from its cursor. After its report applies, platform code advances the cursor
     (`through`, the newest run rendered) in `memory-consolidation`, unchecked as ADR-0037
     decision 7 allows, with a `keep_last` pattern. If the same window is refused three times in
     a row, the operator is paged (pair `AGENT_MEMORY_CONSOLIDATION_STUCK`, keyed by the profile,
     naming no key). The page has no skip command. A poisoned window is cleared by retracting its
     source, since denied transcripts are dropped (decision 3); a window that is too large is
     cleared by lowering `max_runs` in reviewed configuration. A benign transcript that makes
     every pass fail can be cleared only by retracting it, with the reach that has (decision 3).
   - **Not consolidated:** platform scopes, which a report can never write. ADR-0035's
     `fleet-ledger` stays folded by code.

3. **A transcript is bound to its run, its owner and what its run saw.**
   - **What a transcript is.** For each of the owner's finished runs: its report, the pack it ran
     on, and its activity detail records (ADR-0013, `schemas/status/agent_activity_detail` 1.0:
     `event_id`, `session_id`, `time`, `prompt`, `command`, `tool_input`, `tool_output`,
     `error`, `approval`, `truncated` and `redactions`). They have no trace id, are redacted by a
     shape-based screen and are cut to their caps before storage. The reader drops the
     `approval` payload, keeping only the fact that an approval happened.
   - **The binding.** A new reader, `homelabnext.agent.transcripts.read_runs`, starts from the
     controller's job rows whose `profile` is the owner. It joins detail records on the job row's
     `SessionID`, the runner's own id for the session. It accepts a session only when the
     activity store holds it under the `via` of that profile's run spool (`spool:<the profile's
     spool directory>`), as owner (`ActivityStore.add(..., owner=True)` keeps any other `via`
     from adding to a session it does not own). A session stored via a push sender, or any other
     `via`, is refused. Within a bound session, any row stored under a foreign `via` is dropped,
     and the pass's event counts it. The collectors change to make this hold: one spool source
     per profile, and `drain_spool` calling `add` with `owner=True`. Push ingest already does
     (`owner=True`).
   - **The residual risk.** The binding reaches the profile's system user, not the single run.
     Runs of one profile share that uid (ADR-0045 decision 7), so one run, or anything else
     running as that uid, can write records into a sibling run's session. That stays inside the
     one profile whose memory is at stake, and is no stronger than what that profile's own report
     could claim.
   - **Identities.** The reader hands its rows to `resolve_input_uids(rows,
     source="agent-transcripts")`, a function over stored rows, not a reader. Each transcript
     becomes **one** input item with a platform-issued identity (ADR-0037 decision 7), with its
     `run_id` and `finished_at` recorded in the pack. Its run's rendered identifiers are **not**
     copied into the closure of records that cite it. They stay where they are, in that run's
     pack provenance. Two things follow:
     - **Retract reaches through them.** When a pass's batch applies, the store records each cited
       transcript's rendered identifiers in its exposure table, keyed by the transcript's uid
       and charged to the owner's `exposure_bytes` budget (ADR-0037 decision 6). They are held
       durably there, so the walk does not depend on the run's pack outliving its retention.
       `dependents` and `retract` follow that edge: from a source, to the transcripts whose runs
       rendered it, to the records citing those transcripts. It is an exposure edge, not a
       closure entry: citing a transcript costs a record one closure identifier.
     - **The edge is coarse, on purpose.** A retraction that follows it retires every record
       citing the transcript, good ones too, and that is not undone. A transcript's run read
       everything at once, and the platform cannot tell which record leaned on the bad item. The
       dry run (`dependents`, with its confirm digest) shows that reach before anything is
       retired.
     - **Denied runs are dropped.** A transcript whose run's pack rendered a denied source is
       dropped from the pass's pack before rendering. It is counted, and the rest of the window
       goes on. So a retracted item cannot be laundered back through the transcript of a run that
       read it, and one retraction never halts consolidation.
   - **Retention.** The detail tier keeps 14 days by default, the same as the default
     `hypothesis_ttl`. `consolidate` refuses a profile whose `hypothesis_ttl` is longer than that
     retention. Once detail records age out, the report and the pack remain; they can inform a
     judgement but never confirm.
   - **ADR-0013 is amended** for this one new reader of the detail tier: platform code, for the
     owning profile's own pass, at that profile's ceiling. It means detail content reaches a
     model for the first time, including any secret the shape-based redaction missed. Two things
     bound that: the role is in the lab (decision 8), and the store's secret screen refuses such
     a value before it can be written to memory (ADR-0037 decision 4).

### Rungs and review

4. **Nothing is established until a pass says so, and nothing is shown until the operator says
   so.** An entry gains `rung`: `hypothesis`, `note` or `index`. An `index` entry also has a
   `kind`, either `fact` or `topic`. A topic is one entity's page, and its value starts with a
   summary line of at most 160 characters, the L0 rule of ADR-0032. `rung` is separate from the
   lifecycle `status` and from `verified_at`: a `Verifier` may still stamp any rung.
   - **A run writes hypotheses.** Every `add` or `replace` from an ordinary pack lands at
     `hypothesis`. A run may not change an `index` entry. A run's `replace` of a `note` keeps the
     confirmed revision as the entry's **shadow**, `{rev, value_digest}`. The shadow stays the
     confirmed value, for promotion and for the memory block, until a pass confirms the new value
     or reverts to the shadow. A pass's `replace` back to the shadow's exact value
     (`consolidation_reason: corrected`, `expect_rev` the head) restores the entry at `note` and
     clears the shadow: it is not a value change, so it does not demote. If the new hypothesis
     expires instead, the entry reverts to the shadow at `note`, by the same expiry write, rather
     than being retired.
   - **A pass's value is a hypothesis too.** A pass's `add`, and any pass `replace` that changes
     a value, lands at `hypothesis`. That includes a correction and a merge survivor whose value
     changed. A merge survivor whose value did not change takes the lowest rung among the entries
     merged into it. The only way up is a separate, value-preserving update.
   - **Confirmation** (`hypothesis` to `note`) is a pass's update with `consolidation_reason:
     confirmed`. It must cite a transcript of a run that finished after the hypothesis's current
     record was written. Neither that transcript's identity nor any of its aliases (its `pairs`)
     may already be in the entry's closure. A transcript marked truncated or redacted cannot be
     the only cite.
   - **One update per key per batch.** This holds for every checked batch, so a run cannot
     `retire` and `add` a key in one report. A retire in one run and an add in a later one is
     still allowed. It starts a new hypothesis on a new clock, which the pass sees in `history`.
     Confirming and promoting a key are therefore two passes at least.
   - **Expiry.** A hypothesis expires `hypothesis_ttl` after the key became one. A `replace` or
     `verify` does not restart the clock. An expired hypothesis leaves every memory block at
     once, in code. Platform code retires expired hypotheses after a pass's report has applied,
     in their own transaction, in batches of at most 500, with `expired: true`. An entry with a
     shadow reverts to it instead. These writes count against neither `max_retires` nor the
     scope's record and byte caps; each adds one record per expired key. The pass's event counts
     them.
   - **Migration.** On a profile's first pass, its existing entries fold, without being
     rewritten, to `hypothesis`. Their clocks start at that pass's cursor time, spread by a hash
     of the key across one `hypothesis_ttl`, so a large memory does not all expire on one day.

5. **Promotion to the index waits for the operator.**
   - **Promotion** is a pass's value-preserving `replace` of a `note`, moving it to `index` with
     `consolidation_reason: promoted` and a `kind`. An `add` at `index` is refused, as is
     anything above `note` that is not a promotion. Every write that creates or changes an
     `index` entry is refused when the entry's closure has more than 32 identifiers. That check
     runs again at review.
   - **Pending.** A promotion, and any pass change to an `index` value, creates a **pending**
     revision. A profile holds at most `max_pending` of them (default 10, in
     `memory_consolidation`). While the queue is full, the store drops each update that would add
     one, applies the rest of the batch, and reports the drops; the event counts them
     (`pending-full`). The next pass may propose them again once the operator has reviewed. `hnx
     agent memory review <profile>`, a `MemoryAdmin` method taking an `OperatorPrincipal` (ADR-0037
     decision 12), lists each pending revision with its evidence and diff. Approving it appends an
     operator record bound to that revision's `(rev, value_digest)`. Only an approved pair is ever
     rendered. While a change is pending, the entry's last approved value keeps rendering.
     Rejecting returns a promotion to `note`. The same value cannot be proposed again; a new
     proposal needs a changed value.
   - **Removal is not reviewed.** A demotion or a `retire` of an index entry takes effect at once.
     It only reduces what runs see, and decision 7's restoration covers a wrong one.
   - **Auto-promotion** (`auto_promote: true`) skips review for a profile. The compiler refuses
     it on a profile with `reads_untrusted: true`.
   - **For readers, review is the barrier.** For a reader profile, the transcript a confirmation
     cites may quote the same attacker as the hypothesis did. So "a later run" is independence in
     name only. What stops injected content from reaching later prompts is the operator's review,
     and this ADR does not claim more.

### What a run is shown

6. **A small index, injected from a file only the platform writes.**
   - **The cap.** `memory_index` holds:
     - `max_bytes`: default 25,000, the UTF-8 bytes of the rendered index text, framing lines
       excluded;
     - `max_entries`: default 200;
     - `tail`: `off` by default, or `keys`.

     The ceiling policy caps the two numbers at 65,536 and 512. The compiler carries the block
     into `orchestrator_profile.prompt_context.memory_index`.
   - **The fill.** The renderer writes, in order, and stops at the cap:
     1. approved `index` facts, value in full;
     2. approved topics, summary line only;
     3. with `tail: keys`, the keys of entries written since the last pass, under a heading saying
        they are unconfirmed.

     It says how many entries it left out. The compiler refuses `tail: keys` on a reader, and the
     renderer never shows a tail to one. The renderer applies the deny check (ADR-0037 decision 14)
     to the approved revision it shows, not only to the head, so an approved value whose closure
     reaches a denied source is left out. Entries above the ceiling count as withheld, and
     live-only entries (below) are never rendered.
   - **The file.** `hnx agent memory index render` writes one file per profile:
     - **When:** after every applied report, after every pass and approval, on deploy and on
       every recompile of the profile.
     - **What:** the text; a memory block row (`{scope, key, rev, value_digest, tlp, closure}`)
       for each index entry and none for tail keys, which cannot be cited; the profile's id,
       compiled digest and ceiling; and the text's digest.
     - **How:** written to a temporary name and renamed into place. It is owned by the platform's
       memory user, which is none of the profiles' users. Every directory above it is owned by
       root or that user, and nothing in the chain is group- or world-writable. `hnx agent
       memory index check` and the controller both check that.
   - **What `prompt.Build` does.** With `memory_index` set, it adds `[memory-index]` after
     `[own-state]`. Before parsing, it checks the file's size by `fstat` against a bound computed
     from the caps: `max_bytes`, plus one block row per entry, sized for 32 closure identifiers.
     Tail keys carry no row. It refuses a larger file, one naming another profile, digest or
     ceiling, and anything the state-file rules refuse (`safefs`, no link, a regular file only).
     The digest detects corruption, not tampering: tampering is prevented by ownership alone.
   - **Never cut.** The cap holds in three places: the renderer never writes over it,
     `assemble_pack` refuses an index section over it, and `Build` refuses a file over it. A
     refused index is left out with a logged notice and never cut, as `MaxPromptBytes` is never
     cut.
   - **Quoted as data.** The block sits behind the framing line the state blocks use. `Build`'s
     result gains `memory_index: {profile, digest}`. The session's pack records the file's memory
     block, so a `mem:` source naming an index entry is valid (ADR-0037 decision 11). That needs
     the stage-3 runner contract (decision 9).
   - **The purpose.** Beside `[memory-index]`, a profile-conditional `[memory-purpose]` block (not
     one of `prompt.DefaultContracts`) says what memory is for: to carry across runs what this
     agent has verified, and strategies that worked. It asks for two habits: read the index
     before acting, and test a hypothesis before relying on it. It sets no rule about what to
     record. Structure lives in code, and a test holds that the text names no `report_result`
     field.
   - **No live state, narrowly.** A context manifest input section may declare `live: true`
     (`context_manifest` 1.4), for example a fleet-health verdict or a queue's state. The store
     sets `live_only` on a record that has at least one non-`mem:` source, every one of them a
     live item. It also sets it on a record whose only sources are live-only `mem:` revisions.
     The model never sets it. A live-only entry is never rendered or promoted, and
     `consolidation_reason: live-state` is accepted only on retiring one.

### Measurement and undo

7. **Memory has to earn its place, per model, and a pass can be undone.**
   - **Arms.** ADR-0047's task evals gain a `memory` block. It names the arms, each seeded from a
     fixture memory state:
     - `off`: no memory;
     - `unconsolidated`: the fixture as runs left it;
     - `consolidated`: the same fixture after a recorded pass, once by the profile's own role and
       once by its `model_role`.

     `hnx evals run` runs each task in each arm against each model role the profile binds. The
     report records the score per arm, and the gains are shown in the report and on the status
     hub's agent page. `hnx evals check` fails a consolidated profile with no memory arms, or
     with a stale report. A negative gain is the operator's cue to turn the index or the pass
     off. It does not fail a gate.
   - **Counting.** Each pass emits `agent.memory.consolidated` 1.0, a closed event of names and
     numbers, labelled `red`. It carries:
     - the profile, run id and trace id;
     - the count per `consolidation_reason`;
     - the pending, expired and dropped-transcript counts;
     - refusals by a closed class (`expect-rev`, `per-key`, `retire-cap`, `record-cap`,
       `byte-cap`, `deny`, `source`, `label`, `schema`, `budget`, `pending-full`);
     - the rows dropped for a foreign `via`;
     - each scope's record-cap headroom;
     - the size ratio: the bytes of approved index values over the bytes of everything their
       closures cite that is still held, notes and transcripts alike. Detail records age out
       after 14 days, so the ratio is usually reported `partial`, with the count it could not
       measure. Its use is its trend. A ratio above 1 is the article's "abstracted nothing".

     The counts and the ratio cover only what the profile's ceiling reads. Neither gates anything
     yet.
   - **Restoration.** When a retraction reaches the transcript a pass's `retire` cited,
     `MemoryAdmin.retract` appends a re-add of the retired value at `hypothesis` (an operator
     record, `reason: restored:<deny id>`). It does so only where the log still holds the value
     and the value's closure reaches no denied source. Otherwise it reports the entry and does not
     restore it. A poisoned transcript that talked a pass into deleting good memory is thus undone
     by the same retraction.

8. **A pass has exactly the owner's reach.** It runs as the owning profile: the same
   `VerifiedProfile` and system user, its own gateway key delivered per run to the run's uid
   (ADR-0045 decision 6), its `memory_scopes` and its ceiling. No consolidator principal exists,
   and none reads two profiles' memory or transcripts (M-09). Labels only rise (ADR-0037 decision
   8), so a merge survivor is never looser than what it merged. ADR-0033 decision 11 refuses a
   cloud role to a profile whose ceiling is above it, so the compiler refuses that pairing. Since
   all memory is `red` until ADR-0037's follow-up 6, **the stronger model is in practice a stronger
   model in the lab**.

### Amendments, dependencies, defaults and scope

9. **Amendments and dependencies.**
   - **ADR-0037 is amended** (it lists this ADR under **Amended-by**), for opted-in profiles
     unless a line says otherwise:
     - **Decision 6:** the exposure table also holds transcript exposures, keyed by transcript
       uid, charged to `exposure_bytes`.
     - **Decisions 1 and 2:** records and entries gain `rung`, `kind`, `shadow`, `pending`,
       `live_only`, `expired`, `consolidation_reason` and `expect_rev`, and the fold reproduces
       them.
     - **Decision 7:** a pack records its `purpose`, and `report_result` 1.3 adds `rung`, `kind`,
       `consolidation_reason` and `expect_rev`. For every profile, a checked batch carries at most
       one update per key. A consolidation batch drops, and reports, updates past `max_pending`,
       as an unchecked batch drops a denied update; it is otherwise all or nothing. Expiry
       retirements are a platform write to a model-written scope; they only retire.
     - **Decision 12:** `MemoryAdmin` gains `review`.
     - **Decision 13:** `dependents` and `retract` follow the transcript exposure edge, and
       `retract` restores.
     - **Decision 15:** a pass is not a `Verifier`.
     - **Decision 16:** the replay gains a consolidation fixture.
   - **ADR-0013 is amended** for the one new detail-tier reader (decision 3).
   - **Dependencies.** The pass needs ADR-0026's stage-3 agent-runner contract (a session that
     holds its pack, applies its report and dispatches with the grants the pack records). It also
     needs ADR-0047's gateway budgets and run tokens, which follow the controller binary (PR 2.7).
     Rungs, the index, its file and `[memory-index]` can ship before either.
   - **Schema versions this ADR claims.**
     - `agent/profile` 1.8, `report_result` 1.3, `context_manifest` 1.4 and the draft
       `agent.memory.consolidated` 1.0.
     - `platform/agent_profile` is a different schema; ADR-0047 takes its 1.3.
     - `orchestrator_profile` is a draft and changes in place.
     - The `memory` block goes into ADR-0047's `task_eval` in place while that is a draft, and as
       1.1 after.
     - `agent.job.finished` gains `purpose`, in ADR-0047's 1.3 if that is unreleased, else 1.4.
     - The `purpose` claim joins ADR-0047's run-token vectors.

10. **Defaults decided for the operator.** The lead set these on 2026-11-08. The operator changes
    any of them by amending this ADR.
    - Promotion waits for review, and auto-promotion is an opt-in that readers cannot take.
    - The tail is off. When on it shows keys only, and never to a reader.
    - The consolidation role has no default; the overlay names one per profile.
    - `hypothesis_ttl` 14 days, `every` 24 hours, `max_runs` 20, `max_retires` 20.
    - The index is capped at 25,000 bytes and 200 entries, under policy caps of 65,536 bytes and
      512 entries.
    - Memory gain and size ratio are reported, not gated.

11. **Out of scope:**
    - memory inside the model (ADR-0035);
    - embedding retrieval;
    - memory shared across profiles, or a fleet wiki (promotion into shared records and pages
      stays a reviewed change in git, ADR-0032);
    - the broker's `memory.write` lane;
    - fine-tuning on transcripts;
    - choosing the stronger model (a role binding in the overlay, made with the goldens and the
      canary);
    - live declarations beyond manifest sections (MCP servers, controller blocks);
    - ADR-0037's follow-up 3 (wider compaction);
    - interactive operator sessions.

## Consequences

- **Easier:**
  - A wrong note stops being confirmed or promoted within one pass of a later transcript that
    disproves it, and the correction names its evidence.
  - A weak local model sees a small, operator-approved index without deciding to look.
  - Content that one run writes cannot reach a later prompt unless it has been confirmed and then
    promoted. That takes at least two passes, because a batch holds one update per key and any
    value change lands at `hypothesis`. It then has to be approved by a person (or, for a
    non-reader with `auto_promote`, not).
  - Whether memory helps a model, and whether a stronger pass model helps more than the agent's
    own, are numbers per profile.
- **Harder:**
  - **The default is slow on purpose.** For a reader, memory helps only as fast as the operator
    reviews. The pending list is work, and it is the price of not letting transcripts write
    prompts.
  - A pass is a model run per profile per day on the consolidation role, inside ADR-0047's
    budgets. The profile cannot run while its pass does, so the timer should fire in quiet hours.
  - The pass can judge wrongly. Its retirements are capped and restorable, and its promotions are
    reviewed, but a bad pass is found after the fact, by the arms and the counts.
  - Transcripts are redacted, capped and kept 14 days. A pass that falls behind loses its
    evidence, and those notes can no longer be confirmed.
  - Every pass adds records to a scope that only grows. The event reports headroom. ADR-0037's
    follow-up 3 is not ordered first, because one pass adds at most 64 updates plus its expiry
    retirements, and the headroom figure says when compaction is due.
- **Obliges us to maintain:**
  - the consolidation checks in the store;
  - the transcript reader's binding and the exposure join;
  - the renderer, the index file's ownership and bound, and the three cap checks;
  - the gateway's `purpose` rule and its render check;
  - the `[memory-purpose]` text;
  - the memory arms;
  - the replay fixture.

### Implementation plan

Each step is one pull request, in this order. Steps 2 to 5 need nothing outside this repository.
Step 6 waits for ADR-0026 stage 3 and ADR-0047's run tokens and budgets (after PR 2.7). Step 8
waits for ADR-0047's task evals.

1. **This ADR** (docs only), with the **Amended:** and **Amended-by** lines on ADR-0013 and
   ADR-0037 and the index row. Its tests prove that `tools/tests/test_adr_log.py` passes (the
   reciprocal pairs and `Depends-on`), that the summaries are stamped and that the docs index is
   current.
2. **Contracts.** `agent/profile` 1.8 with the compiler's rules, `report_result` 1.3,
   `context_manifest` 1.4, `prompt_context.memory_index` in place, and the draft event. Its tests
   prove:
   - each schema's examples pass and its negatives fail, including an unknown reason or refusal
     class, and an event carrying a value or a key;
   - the compiler refuses `auto_promote` or `tail: keys` on a reader, a spec declaring
     `memory-consolidation`, a cloud `model_role` above the profile's ceiling, and caps above the
     policy's;
   - it fills both scope lists and carries `memory_index` through.
3. **The store** (`memory.py`, `report.py`). Its tests prove, on both backends:
   - a profile without `memory_consolidation` folds no rung and expires nothing;
   - a run's `add` or `replace` lands at `hypothesis`;
   - a run's `replace` of a note keeps the shadow in `memory_block_input`, beside the head `rev`
     that `expect_rev` is checked against;
   - a pass's `replace` back to the shadow's `(rev, value_digest)` restores `note` without a
     demotion (`test_a_revert_to_the_shadow_restores_note`);
   - an expiring hypothesis with a shadow reverts to the shadow at `note` instead of being retired
     (`test_an_expired_hypothesis_reverts_to_its_shadow`);
   - with `max_pending` pending revisions held, a new proposal is dropped and reported, and the
     rest of the batch applies;
   - transcript exposures are stored keyed by uid and charged to `exposure_bytes`, and
     `retract` still reaches the records citing a transcript after that run's pack is purged
     (`test_retract_reaches_through_a_transcript_after_its_pack_is_purged`);
   - a run's update to an index entry is refused;
   - a pass's value change lands at `hypothesis`, and a merge survivor whose value did not change
     takes the lowest merged rung;
   - two updates for one key in a batch, or a `retire` and an `add` of it, are refused;
   - a confirmation citing an earlier run, a transcript whose pairs are in the closure, or only a
     truncated record is refused;
   - an `add` at `index` is refused, as is an index write with more than 32 closure identifiers;
   - a promotion is stored pending, `review` approves `(rev, value_digest)` under an
     `OperatorPrincipal` only, the old approved value renders while a change is pending, and a
     rejected value cannot be proposed again;
   - a moved `expect_rev`, more than `max_retires` retirements, or a pass update with no
     transcript cite refuses the batch;
   - `replace` and `verify` do not restart the expiry clock;
   - expired hypotheses leave `memory_block_input` and are retired in batches of 500 outside the
     pass's caps;
   - migration spreads clocks across one TTL;
   - `live_only` needs a non-`mem:` live source and is inherited through `mem:` sources;
   - `retract` of a transcript restores a pass's retirement, and refuses a restore whose closure
     reaches a denied source;
   - the fold reproduces every new field.
4. **The renderer and the index file** (`homelabnext.agent.memory_index`, `hnx agent memory index
   render|check`). Its tests prove:
   - the cap holds against adversarial memory (10,000 entries of 2,000 characters, CJK included);
   - the fill order and left-out counts are as decided;
   - pending, hypothesis, withheld and live-only values are never rendered, and an approved
     revision whose closure reaches a denied source is left out;
   - the tail is keys only, with no block rows, and absent for a reader;
   - the file is renamed into place, and is re-rendered after an applied report, an approval, a
     deploy and a recompile (a hook test for each);
   - `check` refuses a chain writable by a profile's user, a group or others;
   - `assemble_pack` refuses an index section over the cap.
5. **The controller's blocks** (`orchestrator/internal/prompt`). Its tests prove:
   - a file over the computed bound is refused before parsing;
   - a file naming another profile, digest or ceiling is refused;
   - a link, a FIFO or a writable directory is refused;
   - an index over the cap is left out with a notice and never cut;
   - a stored value cannot close the data block;
   - `[memory-purpose]` appears exactly with `memory_index` and is not among `DefaultContracts`;
   - `Build` returns `memory_index: {profile, digest}`;
   - the purpose text names no `report_result` field.
6. **The pass** (`homelabnext.agent.transcripts`, `hnx agent memory consolidate`, the timer, the
   job API, the gateway). Its tests prove:
   - the job API refuses `purpose` from an agent principal and from the coordinator's actor; a
     resubmit cannot add it; a retry keeps it;
   - a pass is dispatched with empty grants and a template task, recorded in its pack, and its
     tokens carry the consolidation budgets;
   - a pass waits for a running run of its profile, and a run waits for a running pass;
   - the gateway refuses the consolidation role without `purpose: consolidate` and any other role
     with it, and `hnx gen gateway render` refuses a purpose-marked role on a key whose run
     binding is optional;
   - `test_transcript_session_is_joined_on_the_job_rows_session_id`;
   - the collectors register one spool source per profile, and `drain_spool` calls `add` with
     `owner=True`, so a second `via` cannot add to a spooled session;
   - a row under a foreign `via` inside a bound session is dropped and counted;
   - the pass's tokens are delivered only in the unit's `$CREDENTIALS_DIRECTORY`, with `exp` at
     the pass's deadline plus grace, and an ordinary run started after the pass holds none;
   - `test_a_session_stored_under_another_via_is_refused`, covering a push sender's record for the
     owner's run;
   - `test_a_transcript_whose_run_rendered_a_denied_source_is_dropped`, the rest of the window
     still consolidated;
   - `dependents` reaches a record citing a transcript through the exposure join, with one
     closure identifier;
   - the window holds at most `max_runs` runs, oldest first; the cursor advances only after the
     report applies; three refusals page once;
   - a `hypothesis_ttl` longer than retention is refused;
   - the `approval` payload never reaches the pack;
   - platform scopes are never in a pass's memory block.
7. **Counting and the replay.** The event, the hub's row and the consolidation fixture with golden
   answers. Its tests prove:
   - the counts per reason, per refusal class, and for expiry and headroom;
   - the ratio and its `partial` case, within the ceiling;
   - `make memory-replay` passes with answers for corrected, merged, pending, approved, expired
     and restored keys.
8. **Memory arms in the task evals.** Its tests prove that `hnx evals check` fails a consolidated
   profile with no arms or a stale report, and that the report records each arm per model role,
   both consolidation roles included, against the deterministic fake.
9. **Docs** land with each step: docs/agent.md, docs/orchestration-controller.md ("A job's
   prompt") and docs/status.md (detail-tier readers).

## Alternatives

- **Let the agent curate its own memory during its runs.** That is the status quo, and the
  article's failure modes are what it produces. Rejected for a separate pass.
- **One consolidator agent over every profile.** It would need cross-profile reads, which M-09
  refuses, and one credential that reads every agent's transcripts. Rejected.
- **Consolidate in code only.** Code does the rungs, expiry, live tagging and caps. A correction
  needs a model to read the transcript. Code-only rejected as the whole answer, kept as the floor.
- **Let the pass publish to the index directly.** One hostile transcript would reach every later
  prompt with no person in the loop. Kept only as `auto_promote` for non-readers.
- **Show unconsolidated notes in full.** It would turn one run's injected text into the next
  run's prompt. Rejected for keys only, off by default, never for readers.
- **Tell the model what to record.** The article measured that costing strong models their gain.
  Rejected for a stated purpose and structure in code.
- **A memory read tool instead of injection.** A weaker model often does not call it. Rejected.
- **Copy a transcript's rendered identifiers into closures.** Every citing record would hit the
  256-identifier closure cap, and one record would collide with another. Rejected for an exposure
  join at operator time.
- **A mandatory topic rung.** It adds a pass and a review for every fact. Rejected: topic is a
  kind of index entry.
- **An operator skip for a stuck window.** It would be a second cursor writer. Retraction and
  `max_runs` cover the cases. Rejected.
- **A separate gateway key for the pass.** One more credential per profile. Rejected for a
  `purpose` claim on the key the profile has.
- **No cap, or a cap that truncates.** Long injected context lowers adherence, and a cut drops
  entries unseen. Rejected.
