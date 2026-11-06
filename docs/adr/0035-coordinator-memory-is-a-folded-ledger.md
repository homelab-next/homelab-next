---
summary: The coordinator keeps a bounded ledger of fleet work, folded by code from outputs; a reader keeps it, an actor acts on its handoff; no memory in model state.
summary_of: outline:sha256:d1336261c3f7712e
---
# ADR-0035: The coordinator remembers the fleet as a ledger folded from outputs

- **Status:** proposed
- **Date:** 2026-11-04
- **Related:** ADR-0009 (bus), ADR-0013 (status hub), ADR-0014 (conflict-free writes),
  ADR-0020 (projects), ADR-0025 (orchestration telemetry), ADR-0026 (reserved: the orchestrator
  as a component), [Agent profiles](../agent.md) ("Agent memory (M-09)", the reader -> actor
  handoff, G-04), [Broker](../broker.md), [Orchestration controller](../orchestration-controller.md)
- **Depends-on:** ADR-0030, ADR-0032, ADR-0033
- **Amended:** 2026-11-05 by ADR-0037 (memory entries carry sources, history, a TLP label and
  revision, and an operator can retract a source and everything built on it; ADR-0037 decision 17
  lists what changes in decisions 4, 5, 7, 8 and 10)
- **Amended:** 2026-11-06 (review 2, by the operator's decision: the warm and cold tiers are live
  keys, which ADR-0037's compaction keeps whole, so ADR-0037 needs no opt-out; the coordinator is
  two profiles, a reader that owns the ledger and an actor that acts through the broker, joined by
  a G-04 handoff; see the amendments under decisions 1, 3, 5, 7, 8, 9, 11 and 13 and under
  Consequences and Alternatives)
- **Amended-by:** ADR-0037

## Context

The fleet is moving from many independently scheduled agents to one **coordinator** profile that
dispatches the others as profiles, each run a session the orchestration controller admits. The
coordinator has to know what is going on across the fleet: what is in flight right now and what
happened recently. It must not need a full read of every profile's output to find that out.

The shape of the evidence from the previous estate:

- A lead agent that rebuilt the fleet's state from scratch on every run issued hundreds of lake
  queries inside about a thousand tool calls. It hit its wall-clock timeout and produced nothing.
  The backend was idle. The cost was model round-trips, not queries.
- The coordination failures that did happen were all faults in what the shared state *said*:
  - a task addressed to a role nothing resolved;
  - queue items that were answered but never closed;
  - a hold recorded in one place and the approval in another.

  Each was found and fixed by reading a file.

Three things in this repository bear on the design:

- **M-09 refuses cross-agent memory reads** (`homelabnext/agent/memory.py`). "Remember what every
  agent is doing" therefore cannot mean reading the other agents' memory.
- **The pieces a ledger needs already exist:**
  - `MemoryStore`: scoped keys; `add`, `replace` and `retire`, with retired keys kept as
    tombstones; values of at most 2,000 characters; all-or-nothing `apply_updates`.
  - The projects change feed, `changes_since(cursor)` (ADR-0020).
  - The `homelabnext.agent.job.finished` event (ADR-0025).
  - Every profile's `report_result`: `pack_id`, `status`, cites and a structured `output`.
  - The broker's audit trail (ADR-0017, ADR-0030).
  - Context served in levels (ADR-0032).
- **The broker's `memory.write` lane** writes free-form notes outside `MemoryStore`. Whether to keep
  it or route it through `MemoryStore` is recorded as an open decision in docs/agent.md.

There is also outside pressure to keep agent memory inside the model. Research systems compile
memory into model layers, write it to recurrent state such as linear-attention state used as
addressable RAM, and save and restore that state between conversations. Their benchmarks show
in-model memory edging out an external tool store. That memory is opaque, tied to one model
checkpoint, overwritten in place with no history, and limited by the size of the state.
ADR-0032 rejected a model-compiled context database because it cannot be reviewed like a record.
The same objection applies here, more strongly.

## Decision

1. **The coordinator is a profile like any other.** It is compiled under the policy ceiling, verified
   against the lock, and acts only through the broker (ADR-0030). It is not the orchestration
   controller, which admits sessions, and not the component reserved as ADR-0026.

   *Amendment (2026-11-06, review 2):* the coordinator is **two profiles joined by a G-04
   handoff** ([Agent profiles](../agent.md), G-03 and G-04), not one. Opening another profile's
   report text in levels (decision 5) reads free text that a reader of untrusted content may have
   been talked into writing, so the profile that does it is a reader (G-03): it may hold no
   `reader_forbidden` class, and `hnx-broker` is `record-write` and `exec`. The compiler cannot
   infer that: it knows a reader only by the `reads_untrusted` flag (absent means `true`) and by a
   context manifest's `source: input` sections, and a report opened by digest is neither. So each
   spec declares it:
   - **`coordinator`, the reader: `reads_untrusted: true`.** It owns `fleet-ledger` and
     `coordinator-notes`, is the profile the fold writes as (decision 4), sees the ledger and
     opens reports in levels (decisions 5 and 6). It holds no broker grant. What it wants done it
     states in its `report_result.output`, which must satisfy the handoff's closed
     `output_schema`.
   - **`coordinator-actor`, the actor: `reads_untrusted: false`.** It holds the broker grants
     that dispatching profiles and decisions 9 and 11 need, and nothing else: no `source: input`
     section, no memory scope, no read of reports, the ledger or the context store. Its only input
     is the reader's output that `homelabnext.agent.handoff.accept` accepted, and it acts only
     through `act`, on params `build_request` computes from that output.
   - **The handoff** (`schemas/agent/handoff`) binds every action's params with `$output.<path>`
     references to constrained fields only: item ids, profile ids, ledger keys and report digests
     as closed patterns; statuses and pattern kinds as enums; counts as integers. A `summary`, an
     `unknowns` entry or any other unconstrained string never becomes a param.
     `declaration_problems` checks it offline: the reader passes G-03, the actor is
     `reads_untrusted: false`, the actor's receive ceiling is `red` like the reader's (decision
     12), and every action is in the broker manifest and granted to the actor at its tier.
   - **Cited identifiers must exist.** A closed pattern says a ledger key or report digest is
     well formed, not that it names anything. Before `build_request`, code checks that every
     ledger key and report digest the output cites is among the identifiers rendered into the
     reader's pack for that cycle, which the pack record holds as identifiers only; an output
     citing one that is not is refused whole. So a poisoned report cannot send the human who
     approves a proposal to some other report, or to nothing. This is code reading identifiers;
     the actor still reads no text.
   - **Replays file nothing new.** The actor derives each `request_id` from the accepted report's
     digest (`Accepted.report_digest`) and the action name, never from a clock or a counter. A
     handoff replayed after a crash between `accept` and `act` names `request_id`s the broker
     already holds, and the actor files nothing for a `request_id` the broker has, so a proposal
     or journal note is never filed twice for one report.
   - **What this does not stop.** A poisoned report can still steer what the reader asks for,
     within those enums and patterns: which item to dispatch, which keys to cite. It cannot put
     words into a request, and a risky action still needs its bound approval (every record does,
     decision 9). That residue is the G-04 bound, stated here so it is not read as a guarantee.

   Elsewhere in this ADR, "the coordinator" is the reader unless a decision names the actor.
2. **No cross-agent memory reads.** M-09 stays as built, and the coordinator is granted no read of
   another profile's `MemoryStore`. It learns what other profiles do only from their outputs:
   - the projects change feed;
   - `homelabnext.agent.job.finished` events;
   - their `report_result`s;
   - the broker's audit trail.
3. **The ledger is the coordinator's own `MemoryStore`, scope `fleet-ledger`.** It holds:
   - one live key per in-flight item (`task-<uid>`, `run-<id>`);
   - one key per source cursor (`cursor-<source>`).

   An item's key is retired when the item closes. Its tombstone is the recent history.

   *Amendment (2026-11-06, review 2):* a tombstone is **not** the recent history. ADR-0037
   (decision 6) compacts a retired key in a platform scope whole, to one tombstone that keeps the
   value digests but not the values, and ages tombstones out oldest first, whatever the item was.
   A tombstone therefore has nothing to classify or render. When an item closes, the fold, in the
   same `apply_updates` call, retires its hot key and **adds a warm key** holding the closed value
   (decision 8, amended). The scope's keys are:
   - hot: `task-<uid>`, `run-<id>` and `cursor-<source>`;
   - warm: `warm-` and the hot key (`warm-task-<uid>`, `warm-run-<id>`);
   - cold: `rollup-<profile>-<period>`, and `exc-` and the hot key (`exc-task-<uid>`).

   Tombstones stay what ADR-0037 makes them: history for `history`, `as_of` and `dependents`. The
   fold and the renderer never read them.
4. **Code folds the ledger, not the model.** Each cycle, a library function:
   - reads every source from its stored cursor;
   - computes the updates;
   - applies them with `MemoryStore.apply_updates` as the coordinator profile, together with the
     advanced cursors, in the same all-or-nothing call.

   A cycle that dies before the call leaves the old cursors, so the next cycle replays the same
   input. The same inputs always give the same ledger. The fold makes no model call.
5. **A ledger value carries only constrained fields.** Each value is the canonical JSON
   (`homelabnext.agent.digest.canonical_json`) of a closed object:
   - item id or uid;
   - assigned profile id;
   - status, from a closed enum;
   - UTC timestamps;
   - the last report's `pack_id` and digest;
   - `blocked_on` (an item id);
   - `tlp`.

   The fold never copies a report's `summary`, its `unknowns` or any unconstrained string. Those
   are free text that a reader of untrusted content can be talked into writing (G-04, the same
   rule as a handoff's parameters). The coordinator reaches a report's text through its digest and
   cite, in levels.

   *Amendment (2026-11-06, review 2):* that reach is why the coordinator is a reader (decision 1,
   amended). A warm value adds `class` (`keep` or `count`, decision 8) and `closed_at`; a hot
   value adds `reopened`, how many times the item reopened. An exception key's value is the
   one-line object of decision 8: id, status, `closed_at` and its last report's digest. All are
   constrained fields; the rule above is unchanged.
6. **The model sees the ledger in levels.** The coordinator's context pack carries a rendered
   summary of the ledger:
   - counts by status;
   - entries changed since the last cycle;
   - entries that are blocked or overdue.

   Below the summary, each live entry is one line. Opening a report, a record or a document goes
   through ADR-0032's summary, outline and section. A full dump of the ledger is never the default.
7. **The pack's history is limited by size and filled by priority, not limited by age.** The
   ledger gets its own share of the context manifest's character budget. The renderer fills that
   share in this order and stops when it is full:
   1. live entries that are blocked, overdue or failed;
   2. entries changed since the last cycle;
   3. other live entries;
   4. retired entries kept as exceptions (decision 8);
   5. routine work, as counts per profile per period, never one line per item.

   Within a level, newer entries go first: age only breaks ties. When entries are left out, the
   pack says how many and at which level (M-08: never cut silently).

   *Amendment (2026-11-06, review 2):* level 4 is the live `warm-*` keys of class `keep` and the
   `exc-*` keys (decision 8, amended), and level 5 is the `rollup-*` keys and the `count` warm
   keys, as counts. The renderer reads live keys only (`read` without `include_retired`), never a
   tombstone.
8. **What the ledger keeps is limited by size, removed by priority, and classified by code.**
   - **Retention class.** The fold gives every retired entry one class, computed from its
     constrained fields; the model never sets it:
     - `keep`: the item failed, was denied, went overdue, recurred or was reopened, or is linked
       to an incident or an approval;
     - `count`: it completed routinely;
     - `drop`: a later state of the same item replaced it.
   - **Hot tier.** The live keys. They are bounded by the work in flight.
   - **Warm tier.** Retired entries, capped at a number of entries (a profile budget). When the
     cap is passed, the fold removes `drop` entries first, then `count`, then `keep`, oldest first
     within a class.
   - **Cold tier.** A `count` entry leaving warm is added to a rollup key per profile and period
     (`rollup-<profile>-<period>`: closed counts by status), so volume stays visible after the
     items are gone. A `keep` entry leaving warm becomes a one-line exception key: id, status,
     date and the digest of its last report. The cold tier has its own entry cap. When that is
     full, the oldest rollups are merged into coarser periods; exception keys are never merged.
   - **Model nominations.** The coordinator's model may nominate an item for `keep` by writing the
     item's key into `coordinator-notes` (decision 10). The fold reads only the key, never text,
     so a nomination cannot put free text into the ledger.

   *Amendment (2026-11-06, review 2):* the tiers are defined on what ADR-0037 keeps. Every tier is
   **live keys**, and "removes" means what ADR-0037 decision 17 says: the fold retires the key,
   and ADR-0037 compacts it whole. No tier lives in a tombstone, so ADR-0037's whole compaction
   and its oldest-first tombstone age-out need no opt-out, and the age-out order does not touch
   what the tiers keep.
   - **Hot tier.** Live `task-*` and `run-*` keys, as before, and the `cursor-*` keys, which have
     a `keep_last` pattern (ADR-0037 decision 17).
   - **Warm tier.** Live `warm-*` keys, added at each close of an item and never replaced while
     live, so they need no `keep_last`; a retired warm key is added again at the item's next
     close (M-09 allows an `add` on a retired key). The fold computes the class at close from the
     closing value and the hot value's `reopened` count; a nomination counts as at close. `drop`
     is no longer a class that sits in warm. Past the warm cap the fold picks victims by class,
     `count` before `keep`, oldest `closed_at` first within a class, and in the same call retires
     each and writes its cold form.
   - **Reopen.** When an item reopens, the fold, in the call that adds the hot key again and
     raises `reopened`, retires the item's live `warm-<hot key>` and its live `exc-<hot key>`,
     whichever exist, so the item's next close is `keep` and its next eviction adds its cold form
     to a retired key, never to a live one. (That is "drop first" at its limit: a superseded state
     leaves at once.) Without this, an item evicted, reopened, closed and evicted again would
     `add` a live `exc-*` key; M-09 refuses that, the batch is refused whole with its cursors,
     and because the fold is deterministic it would replay the same refusal every cycle. A rollup
     counts **closes**, not items: an item that closes, rolls up, reopens and closes again is
     counted at each close, which is what happened, so a reopen does not touch a rollup.
   - **Cold tier.** Live `rollup-<profile>-<period>` keys, replaced on every count that lands, so
     the profile gives `rollup-*` a `keep_last` pattern; and live `exc-*` keys, added when a
     `keep` item leaves warm. Both count against the cold entry cap. When the cap is reached the
     fold first merges rollups into a coarser period (it retires the finer keys and adds or
     replaces the coarser one in one call); exception keys are never merged. When no merge is
     left and the cold tier still has no room, the fold retires the oldest `exc-*` key by
     `closed_at` and adds it to its profile's rollup for that period as an `exceptions` count, in
     the same call, and its cycle report and journal note say how many it folded (M-08: never cut
     silently). So the cold tier stays within its cap however many `keep` items close, and the
     fold never writes past the store's caps. Apart from a reopen and this overflow, the fold
     never retires an `exc-*` key. An operator's `retract` or `purge` may retire any of these
     keys; the fold does not add one back (ADR-0037 decision 14).
   - **Nominations are bounded.** The fold honours at most a fixed number of nominations per
     cycle (a profile budget), and only for items that close in that same fold; it ignores any
     other nominated key. The reader, which opens untrusted text, therefore cannot turn the warm
     and cold tiers into `keep` entries faster than items actually close.
   - **Sizing.** `fleet-ledger`'s record cap (ADR-0037 decision 6) must hold the work in flight,
     the warm and cold caps, `keep_last` + 1 records for each replaced key, and the tombstone
     budget. The profile sets `memory_limits.records`, `tombstones`, `bytes` and `keep_last` for
     the scope beside the warm and cold caps, and a test checks that the caps fit under the record
     and byte caps. Because every tier is capped (the cold one by the overflow rule above), the
     fold meets its own caps before the store refuses a write.
9. **Permanent memory is a record, and a human approves it.** The coordinator's memory is not
   where lasting knowledge lives. When the fold sees a pattern, such as the same kind of exception
   recurring past a threshold in the warm or cold tier, the coordinator files a proposal for a
   lesson or another record through the broker's `proposal.file` lane (the records inbox,
   ADR-0010). The proposal cites the ledger keys and report digests it rests on. **A human
   approves each one before it becomes a record.** The coordinator gets no grant that files a
   record without approval. Loosening this later is a change to the broker manifest's grants and
   tiers, recorded by amending this ADR.

   *Amendment (2026-11-06, review 2):* the actor files the proposal (decision 1, amended), from
   the reader's output: the pattern kind (an enum), the ledger keys and the report digests. Code
   builds the proposal's text from those fields. The reader's reasoning reaches the human only by
   the digest of the reader's report, which the proposal cites, never as text in the request.
10. **Judgements are written apart from tracking.** The coordinator's model may keep its own notes
   (what to try next, what to watch) in a second scope, `coordinator-notes`, through the
   `memory_updates` of its own report, as M-09 already allows. It cannot write `fleet-ledger`: the
   fold is the only writer of that scope, and a report's update that names the scope is refused.
11. **Every cycle leaves a journal note.** The coordinator files one Markdown note per cycle through
   the broker's finding lane. It carries a `summary:` line (ADR-0032 decision 6 rules) and names
   the ledger keys it acted on and the broker requests it filed. The ledger records *what* changed;
   the journal records *why*. A cycle that did nothing still files a note.

   *Amendment (2026-11-06, review 2):* the actor files the journal note. Code builds it, its
   `summary:` line included, from the accepted output's constrained fields and the broker
   requests the actor filed, and it cites the digest of the reader's report that the handoff
   accepted. The *why* is that report, opened in levels, not text copied into the note. A cycle
   whose output asks for nothing still hands off, and the actor still files the note.
12. **TLP.** The ledger and the journal take the strictest label among their inputs (ADR-0033
    decision 4). With the lab's own data that is `red`, so the coordinator's ceiling is `red`, and
    anything it passes on goes through the reader filters.
13. **The coordinator has no `memory.write` grant.** Its durable state lives only in `MemoryStore`.
    The general decision on the `memory.write` lane stays open for other profiles.

    *Amendment (2026-11-06, review 2):* neither profile has one. The reader holds no broker grant
    at all, and the actor has broker grants but no memory.
14. **Agent memory is never kept in model state.** Weights, recurrent state and a key-value cache
    saved between sessions are not memory backends. An engine feature that offers them is not used
    for agent memory. A `MemoryBackend` (`InMemoryBackend` or `FileBackend` today) is the only
    backend.

## Consequences

- **Easier:**
  - Knowing what is going on fleet-wide is one read of one scope. The pack's share is a fixed
    size and the store's tiers are capped, however many profiles run and however long the fleet
    runs.
  - What survives is chosen by what happened, not by when: an old failure outlives a new routine
    success, and routine volume survives as counts.
  - The fold is deterministic, so it can be tested with the fakes that already exist:
    `InMemoryBackend`, the projects reference store, and event and report fixtures.
  - Changing or upgrading the coordinator's model loses no memory.
  - An auditor reads the ledger's tombstones and the journal; nothing is hidden in model state.
- **Harder:**
  - The ledger knows only what the sources report. A profile that works without filing a report or
    emitting `agent.job.finished` is invisible, which is intended: a missing note cannot be told
    apart from a failed run. So the fold must mark an admitted run with no finished event past its
    deadline as `overdue`, rather than leaving it `running`.
  - Each new source needs a cursor and fold rules, in code.
  - The value object must fit in 2,000 characters.
  - The caps and the pattern threshold have to be tuned from use. Caps that are too small evict
    exceptions; a threshold that is too low floods the operator with lesson proposals.
  - A `count` entry gives up per-item detail once it leaves warm. Its last report is still in the
    broker's data and the projects history, but the coordinator no longer points at it.
  - Every lesson the coordinator proposes waits for a human. That is deliberate for now (decision
    9); if approvals become the bottleneck, loosening it is an amendment, not a setting.
- **Obliges us to maintain the following, none of it built yet:**
  - the fold library and its tests (replay from an old cursor, all-or-nothing with the cursors, no
    free text copied);
  - a draft schema for a ledger value;
  - the pack renderer for decisions 6 and 7 (priority fill, reported omissions);
  - retention classes, tier caps, eviction order and rollup merging (decision 8), with tests that
    an entry is never removed before a lower class and that exception keys survive every merge;
    and the warm and cold cap fields in the profile;
  - the pattern threshold and the proposal it files (decision 9);
  - the refusal in decision 10, whether the policy expresses it or `MemoryStore` gains it.
- **Open:**
  - Whether the context store indexes the broker's data root, so that journal notes are served in
    levels like files in the checkout.
  - The `memory.write` lane for other profiles.
- *Amendment (2026-11-06, review 2):*
  - **Easier:** the coordinator meets G-03 and G-04 as built. The profile that reads other
    profiles' text holds no acting grant, and the profile that acts never reads it, so the
    compiler, `verify_profile` and `hnx agent lint` check the split with the rules every profile
    already passes. The tiers keep their values in live keys, so ADR-0037's compaction and
    retraction apply to them unchanged. An auditor reads the ledger's history with ADR-0037's
    `history` and `as_of`, not its tombstones, whose values are gone.
  - **Harder:** two profiles, a handoff and its closed output schema to keep in step; each new
    action the coordinator needs is a reviewed handoff change. A poisoned report can still choose
    among the actions and values the schema allows (decision 1, amended). Each warm entry is a
    live key, so the warm cap counts against the scope's record cap (decision 8, amended).
  - **Obliges us to maintain, none of it built yet:** the two specs with `reads_untrusted`
    declared; the handoff and its output schema; a test that the reader holds no
    `reader_forbidden` class and that `declaration_problems` is empty for the handoff; the warm,
    cold, reopen, overflow and nomination rules of decision 8 (amended), with tests that the
    renderer and the fold read no tombstone, that a reopened item's warm and exception keys are
    retired in the same call, that "evict, reopen, close, evict again" for one item is accepted by
    the store, that a cold tier full of exception keys folds the oldest into a rollup count and
    says so, and that the caps fit under the scope's record and byte caps; the membership check on
    cited ledger keys and report digests (decision 1, amended), with a test that an output citing
    a well-formed but absent key is refused; and a deterministic `request_id`, with a test that a
    handoff replayed after a crash files nothing new.

## Alternatives

- **Grant the coordinator cross-agent reads.** This breaks M-09. It exposes every profile's
  scratch notes to the profile with the widest reach, and the volume read grows with the fleet.
  Rejected.
- **Let the coordinator's model write the ledger through its report's `memory_updates`.** This is
  possible today. But it spends model turns on bookkeeping, status written by a model drifts from
  the sources, and anything injected into what the model read could become ledger state. Rejected
  for tracking. Kept for judgements (decision 10).
- **Keep memory in model state** (recurrent state used as RAM, saved and restored between
  sessions). The memory would be tied to one checkpoint, unreadable, without history, and limited
  by the size of the state. Rejected, as ADR-0032 rejected a compiled context store.
- **Re-derive fleet state each cycle by querying the sources.** The evidence above shows the cost:
  model round-trips until the timeout. Rejected; the cursors make each cycle read only what
  changed.
- **Limit history by age (a fixed window of days).** A window holds a busy week's routine items
  and drops an older failure that matters more, and its size depends on how busy the fleet was.
  Rejected for a size budget filled by priority (decisions 7 and 8).
- **Let the model choose what to keep.** It would spend turns on housekeeping, and what it chose to
  keep would depend on prompts and could be steered by injected text. Rejected; the model may only
  nominate a key (decision 8).
- **File lessons from patterns without approval.** It would be faster, but a lesson changes what
  every later session reads, so a wrong one spreads. Rejected for now (decision 9).
- **Give ADR-0037 an opt-out** (review 2): a per-scope switch that keeps a retired key's values
  through whole compaction, and a tombstone age-out that knows retention classes. The memory store
  would learn a ledger's classes, and its bound would have a scope where it does not hold.
  Rejected for live warm and cold keys (decision 8, amended).
- **One coordinator profile** (review 2). As a reader it may hold no broker grant, so decisions 9
  and 11 cannot be built. As an actor (`reads_untrusted: false`) it would open text a reader of
  untrusted content wrote and act on what it read, which is the steering G-04 exists to stop, and
  the compiler would not notice. Rejected for a reader and an actor joined by a handoff (decision
  1, amended).
- **A vector store over all fleet output.** This brings semantic recall over a corpus that is
  already structured by ids and status. ADR-0032's reasoning applies. Rejected.
