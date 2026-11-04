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
7. **Recent history is a window.** Retired entries older than the coordinator's history budget
   leave the pack, not the store. The budget defaults to 7 days and is a profile budget. Anything
   older is answered from git, the records and the projects history.
8. **Judgements are written apart from tracking.** The coordinator's model may keep its own notes
   (what to try next, what to watch) in a second scope, `coordinator-notes`, through the
   `memory_updates` of its own report, as M-09 already allows. It cannot write `fleet-ledger`: the
   fold is the only writer of that scope, and a report's update that names the scope is refused.
9. **Every cycle leaves a journal note.** The coordinator files one Markdown note per cycle through
   the broker's finding lane. It carries a `summary:` line (ADR-0032 decision 6 rules) and names
   the ledger keys it acted on and the broker requests it filed. The ledger records *what* changed;
   the journal records *why*. A cycle that did nothing still files a note.
10. **TLP.** The ledger and the journal take the strictest label among their inputs (ADR-0033
    decision 4). With the lab's own data that is `red`, so the coordinator's ceiling is `red`, and
    anything it passes on goes through the reader filters.
11. **The coordinator has no `memory.write` grant.** Its durable state lives only in `MemoryStore`.
    The general decision on the `memory.write` lane stays open for other profiles.
12. **Agent memory is never kept in model state.** Weights, recurrent state and a key-value cache
    saved between sessions are not memory backends. An engine feature that offers them is not used
    for agent memory. A `MemoryBackend` (`InMemoryBackend` or `FileBackend` today) is the only
    backend.

## Consequences

- **Easier:**
  - Knowing what is going on fleet-wide is one read of one scope, at a size bounded by the items in
    flight and the window, however many profiles run.
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
- **Obliges us to maintain the following, none of it built yet:**
  - the fold library and its tests (replay from an old cursor, all-or-nothing with the cursors, no
    free text copied);
  - a draft schema for a ledger value;
  - the pack renderer for decisions 6 and 7;
  - the history budget field in the profile;
  - the refusal in decision 8, whether the policy expresses it or `MemoryStore` gains it.
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
  for tracking. Kept for judgements (decision 8).
- **Keep memory in model state** (recurrent state used as RAM, saved and restored between
  sessions). The memory would be tied to one checkpoint, unreadable, without history, and limited
  by the size of the state. Rejected, as ADR-0032 rejected a compiled context store.
- **Re-derive fleet state each cycle by querying the sources.** The evidence above shows the cost:
  model round-trips until the timeout. Rejected; the cursors make each cycle read only what
  changed.
- **A vector store over all fleet output.** This brings semantic recall over a corpus that is
  already structured by ids and status. ADR-0032's reasoning applies. Rejected.
