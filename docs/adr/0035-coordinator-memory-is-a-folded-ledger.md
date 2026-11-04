---
summary: The coordinator keeps a bounded ledger of fleet work, folded by code from outputs; no cross-agent memory reads, no memory kept in model state.
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
9. **Permanent memory is a record, and a human approves it.** The coordinator's memory is not
   where lasting knowledge lives. When the fold sees a pattern, such as the same kind of exception
   recurring past a threshold in the warm or cold tier, the coordinator files a proposal for a
   lesson or another record through the broker's `proposal.file` lane (the records inbox,
   ADR-0010). The proposal cites the ledger keys and report digests it rests on. **A human
   approves each one before it becomes a record.** The coordinator gets no grant that files a
   record without approval. Loosening this later is a change to the broker manifest's grants and
   tiers, recorded by amending this ADR.
10. **Judgements are written apart from tracking.** The coordinator's model may keep its own notes
   (what to try next, what to watch) in a second scope, `coordinator-notes`, through the
   `memory_updates` of its own report, as M-09 already allows. It cannot write `fleet-ledger`: the
   fold is the only writer of that scope, and a report's update that names the scope is refused.
11. **Every cycle leaves a journal note.** The coordinator files one Markdown note per cycle through
   the broker's finding lane. It carries a `summary:` line (ADR-0032 decision 6 rules) and names
   the ledger keys it acted on and the broker requests it filed. The ledger records *what* changed;
   the journal records *why*. A cycle that did nothing still files a note.
12. **TLP.** The ledger and the journal take the strictest label among their inputs (ADR-0033
    decision 4). With the lab's own data that is `red`, so the coordinator's ceiling is `red`, and
    anything it passes on goes through the reader filters.
13. **The coordinator has no `memory.write` grant.** Its durable state lives only in `MemoryStore`.
    The general decision on the `memory.write` lane stays open for other profiles.
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
- **A vector store over all fleet output.** This brings semantic recall over a corpus that is
  already structured by ids and status. ADR-0032's reasoning applies. Rejected.
