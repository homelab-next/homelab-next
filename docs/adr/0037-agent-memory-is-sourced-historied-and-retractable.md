---
summary: Every agent memory entry records its sources, TLP and revision history; an operator retracts a bad source and everything built on it.
summary_of: outline:sha256:25d3f9bd2a8f46eb
---
# ADR-0037: Agent memory is sourced, historied and retractable

- **Status:** proposed
- **Date:** 2026-11-05
- **Related:** ADR-0001 (additive schemas, `x-draft`), ADR-0014 (append-only events), ADR-0017
  and ADR-0030 (the broker and its approvals), ADR-0032 (context in levels), [Agent
  profiles](../agent.md) ("Agent memory (M-09)"), `homelabnext/agent/memory.py`,
  `schemas/agent/report_result.schema.json`
- **Depends-on:** ADR-0033, ADR-0035
- **Amends:** ADR-0035

## Context

`MemoryStore` (M-09) holds an agent's distilled facts: scoped keys whose values the platform
applies from the `memory_updates` of the agent's own report, validated and all or nothing.
ADR-0035 makes it the coordinator's ledger as well. What an entry is today:

- An entry is `{status, op, value, pack_id?}`. There are no timestamps.
- **`replace` overwrites the value.** The earlier value is gone, so "what did this agent believe
  last Tuesday" has no answer.
- `retire` keeps a tombstone, but nothing says why the fact was retired.
- **Provenance runs one way only:** entry → `pack_id` → the pack's `knowledge` block, which lists
  the digests of what the agent was shown. Nothing records which of those the fact rests on, and
  nothing indexes the other way. When a source turns out to be wrong (a poisoned feed item, a
  page edited by an attacker, a lesson later withdrawn), nobody can find the facts built from it.
- Entries carry no TLP label. A fact distilled from an `amber` report and read back into a
  profile whose ceiling is `green` moves `amber` content into a lower context. ADR-0033 decision
  4 already says derived data takes its strictest input; memory is derived data, so it needs a
  label like any other.
- A fact can be built on another fact: an agent reads its own memory and distils a newer fact
  from it. Retracting a source then has to follow that chain, or the second-level fact survives
  the first one's retirement.
- **Reads are owner-scoped.** A cross-agent read raises `MemoryAccessError`. That is the property
  ADR-0035 rests on, and it stays.

The failure this guards against is concrete: a fact the fleet learned from a bad source keeps
steering every later run, because nothing can tell which facts came from it. A reviewable record
of *where each fact came from, what it said before, and who retracted it* fixes that, and it has
to be built from code the platform owns, not from what a model says about its own sources.

## Decision

1. **Every applied update appends a change record.** The store keeps an append-only change log
   per owner. Each record holds:
   - `at`: UTC time;
   - `scope`, `key`, `op` and the resulting `rev`;
   - `value` (absent for `retire`) and `value_digest` (sha256 of the canonical value);
   - `pack_id` and `sources` (decision 5);
   - `tlp` (decision 7);
   - `reason`, set only by a retraction or a lift (decision 11).

   The record and the entry are written in the **same backend transaction**: a batch that fails
   writes neither an entry nor a change record. This holds for `InMemoryBackend` and
   `FileBackend` alike, and a test proves it for both.
2. **An entry carries its revision and time.** An entry gains `rev` (an integer: 1 for the first
   `add`, plus one per later change, including `retire`) and `updated_at`. `replace` no longer
   loses the earlier value: it is in the log.
3. **The clock is injected.** The store takes `now=` (a callable returning a UTC time). `_apply`
   reads no clock of its own, so tests are deterministic.
4. **History is read through the owner's scope.** `MemoryStore.history(profile, scope, key)`
   returns that key's change records in order. `MemoryStore.as_of(profile, scope, t)` returns the
   scope's live entries as they stood at time `t`, rebuilt from the log. Both are owner-scoped
   exactly like `read`: `owner=` naming another profile raises `MemoryAccessError`.
5. **An update names its sources.** A `memory_updates` item gains an optional `sources`: a list of
   strings, each one of:
   - a content digest (`sha256:<64 hex>`);
   - a record uid;
   - another memory entry at a revision: `mem:<owner>/<scope>/<key>@<rev>` (decision 8).

   This is an additive minor bump of `report_result` to 1.2, marked `x-draft` while this ADR is
   proposed (ADR-0001). An update with no `sources` is stored with `sources: []`, and a read can
   report such an entry as `unsourced`.
6. **A source must be something the agent was actually given.** When a report is validated
   against its pack (`validate_report`), every source must be:
   - a digest or uid listed in the pack's `knowledge` block or named by one of the report's cites
     into the pack; or
   - a `mem:` reference to a revision of the profile's own memory that was in the pack.

   Otherwise the whole report is refused. A model cannot invent provenance, and it cannot cite
   memory it was not shown. When a report is applied without its pack (schema check only), its
   sources are stored but the entry is marked `sources_unchecked`, so a reader can tell.
7. **An entry is labelled the strictest label of its sources.** Each change record and entry
   carries `tlp`, computed by the store, never by the model:
   - the label of each source, from the pack (a knowledge item's label, a cited section's label)
     or from the referenced entry (`mem:`);
   - a source with no label, an unsourced entry, and a `sources_unchecked` entry are `red`
     (ADR-0033 decision 2);
   - a label is never lowered by a later update: `replace` takes the strictest of the new sources
     and the entry's current label. Only a release transform (ADR-0033 decision 7) declassifies.

   Reads honour the reader's TLP ceiling. `read`, `history` and `as_of` take the reader's
   ceiling (the profile's `tlp_ceiling`, or its `data_tier`-derived ceiling, as the compiler
   attests it) and return an entry above it as withheld: its key and that it was withheld, never
   its value. A context pack built from memory carries the strictest label it includes.
8. **Memory can cite memory.** A `mem:<owner>/<scope>/<key>@<rev>` source names one revision of
   one entry. The owner part names the store's owner, so the reference is unambiguous across the
   reverse index; it does not grant a read (decision 10). A profile may cite only its own
   memory, and only a revision it was shown (decision 6).
9. **The reverse index answers "what was built from this".** The store keeps an index from each
   source to every change record that cites it, across owners. `dependents(source)` returns every
   live entry and change record that cites `source`, directly or through `mem:` references and
   through records' `derived_from` (ADR-0033 decision 4), to any depth. Cycles are visited once.
   The index is rebuilt from the change logs on demand, so it can never disagree with them.
10. **Retraction is a platform operation, not a profile read.** `retract(source, reason,
    by=<operator principal>)`:
    - retires every live dependent entry, across owners;
    - writes a change record for each with `op: retire` and `reason: retracted:<source>`;
    - returns the affected owners, scopes and keys.

    It is not a method a profile can reach. It takes an operator principal, not a
    `VerifiedProfile`, and grants no profile a cross-agent read: M-09's test passes unchanged. If
    it is exposed through the broker at all, it is an operator-only action in the broker manifest:
    `kind: human` issuer, an approval required, and no agent grant (ADR-0030). Retracting a source
    twice changes nothing the second time.
11. **A retraction sticks.** A retracted source goes on the store's deny list, with the reason,
    the principal and the time. Afterwards, any update whose `sources` (or whose `mem:` chain)
    reaches a denied source is refused, so a later report cannot quietly re-add the fact. Only an
    operator lifts a retraction, with `lift(source, reason, by=<operator principal>)`, which is
    recorded with its own reason. A lift restores nothing by itself: retired entries stay retired
    until a new report adds them.
12. **Staleness is visible.** An entry gains `verified_at`, set at write time. A later update with
    `op: verify` re-confirms the value from the same or new sources (validated as in decision 6)
    and refreshes `verified_at` without changing the value. `read(..., stale_after=)` marks
    entries not verified within that budget as stale. The ADR-0035 pack renderer, when built,
    ranks stale entries lower; until then the flag is only exposed. Re-checking a value against
    its sources is not in scope: a `Verifier` protocol is defined and no implementation ships.
13. **Memory is judged by replay.** A fixture history of reports, with timestamps, sources and a
    retraction partway through, is replayed into a fresh `MemoryStore`. Golden questions have
    exact expected answers:
    - the value of key K as of time T;
    - the history of K;
    - what `dependents(S)` returns;
    - what is retired after `retract(S)`, and that a later report citing S is refused;
    - which entries are unsourced, unchecked or stale;
    - which entries a reader at a given ceiling sees withheld.

    The replay lives under `tests/agent/` and runs in `make check`, so a later change to the
    memory design is judged by the same replay.
14. **Delivery.** Decisions 1 to 13 ship as five pull requests, each from `main`:
    1. history (decisions 1–4);
    2. sources and their check (decisions 5–6), with TLP labels (decision 7);
    3. memory citing memory, the reverse index, retraction and the deny list (decisions 8–11);
    4. staleness (decision 12);
    5. the replay evals (decision 13).

## Consequences

- **Easier:**
  - Every fact can be traced to what the agent was shown, and back again: from a bad source to
    every fact built on it, at any depth.
  - A wrong source is withdrawn in one operator action, and stays withdrawn.
  - "What did the fleet believe at time T" has an exact answer, for incident review.
  - Memory no longer moves `amber` or `red` content into a lower context unseen.
  - A model cannot fabricate provenance: every source is checked against the pack.
  - The replay turns "is the memory design better" into a test.
- **Harder:**
  - Every write costs one more record, and the log grows without bound until compaction is
    decided (follow-up 3).
  - The ledger's 2,000-character value limit still applies; sources and labels live beside the
    value, not inside it.
  - An agent that does not name sources gets `red`, `unsourced` entries. That is deliberate: the
    cheapest path must also be the most conservative one.
  - `retract` crosses owners. It has to stay out of every profile's reach; the tests in decision
    10 hold that line.
  - A source that many facts depend on makes `dependents` expensive; the index is rebuilt from the
    logs rather than kept in a second store, trading speed for never disagreeing.
- **Obliges us to maintain:**
  - the change log and its all-or-nothing tests on both backends;
  - `report_result` 1.2 (`x-draft` until this ADR is accepted) and the source check in
    `validate_report`;
  - the TLP computation, the withheld read, and ceiling tests;
  - `dependents`, `retract`, `lift`, the deny list, and the test that no profile can reach them;
  - the replay fixture and its golden answers.
- **Follow-ups** (named here, decided later, each by amending this ADR):
  1. **Two meanings of "as of".** `as_of(T)` as decided returns what was believed at T,
     including facts retracted later. A second mode that also removes facts retracted since T is
     what normal reads want; incident review wants the first.
  2. **Tamper-evident history.** Each change record could carry the hash of the previous one, so
     an edit to the log is detectable.
  3. **Limits on history.** A cap per owner or per key, or compaction that folds old revisions
     into a snapshot keeping their sources, so the append-only log does not grow forever.
  4. **No secrets in memory.** Run the existing secret and leak patterns on each `value` at write
     time and refuse a match.
  5. **Staleness by scope.** A default `stale_after` per scope (for example `ops` 7 days,
     `profile` 90 days), so callers do not each choose their own.
- **Open:**
  - Whether `retract` is exposed through the broker or stays a platform command only.
  - The broker's free-form `memory.write` lane (still an open decision in docs/agent.md) gets none
    of these guarantees; routing it through `MemoryStore` would.

## Alternatives

- **Let the model state its sources freely.** Cheap, but the sources would be whatever the model
  wrote: a fabricated digest is indistinguishable from a real one. Rejected for decision 6's check.
- **Record only `pack_id` and treat the whole pack as the source.** It already exists. But a
  retraction would then retire every fact from every run that was shown the bad source, including
  facts that never used it. Rejected; per-update sources make retraction precise.
- **Keep history in a separate store or the lake.** A second store can disagree with the first,
  and a crash between the two writes leaves an entry with no history. Rejected for one transaction
  (decision 1).
- **Let profiles retract their own sources.** A retraction crosses owners by nature, and a
  profile that could retract could also be steered into retracting a good source. Rejected for an
  operator-only operation (decision 10).
- **Retract without a deny list.** The next report citing the same source would put the fact
  back. Rejected (decision 11).
- **Label memory with the reader's ceiling instead of its sources.** It would make every write
  depend on who might read it later, and a label must be recomputable from inputs (ADR-0033
  decision 4). Rejected.
- **Expire facts by age instead of tracking verification.** Age says nothing about whether a
  fact is still true; `verified_at` and the `Verifier` protocol leave room to check it. Rejected
  as the only mechanism; per-scope defaults are a follow-up.
