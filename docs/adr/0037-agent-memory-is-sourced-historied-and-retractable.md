---
summary: Every agent memory entry records its sources, TLP and revision history; an operator retracts a bad source and everything built on it.
summary_of: outline:sha256:659df10cd6ad9e61
---
# ADR-0037: Agent memory is sourced, historied and retractable

- **Status:** proposed
- **Date:** 2026-11-05
- **Related:** ADR-0001 (additive schemas), ADR-0014 (append-only events, derived state), ADR-0017
  and ADR-0030 (the broker), ADR-0032 (context in levels), [Agent profiles](../agent.md) ("Agent
  memory (M-09)"), `homelabnext/agent/memory.py`, `homelabnext/agent/pack.py`,
  `homelabnext/agent/knowledge.py`, `schemas/agent/report_result.schema.json`
- **Depends-on:** ADR-0033, ADR-0035
- **Amends:** ADR-0035

## Context

`MemoryStore` (M-09) holds an agent's distilled facts: scoped keys whose values the platform
applies from the `memory_updates` of the agent's own report, validated and all or nothing.
ADR-0035 makes it the coordinator's ledger too. What an entry is today:

- An entry is `{status, op, value, pack_id?}`, with no timestamps.
- **`replace` overwrites the value.** "What did this profile believe last Tuesday" has no answer.
- `retire` keeps a tombstone, but nothing says why.
- **Provenance runs one way only:** entry → `pack_id` → the pack's `knowledge` block (the ids
  and digests of the records and pages the agent was shown). Nothing records which of them a fact
  rests on, nothing indexes the other way, and an input section (where a feed item arrives) has no
  identity in the pack at all. When a source turns out to be wrong (a poisoned feed item, a page
  edited by an attacker, a lesson withdrawn), nobody can find the facts built from it.
- **Nothing in a pack carries a TLP label.** Knowledge items carry ids and digests; sections carry
  a name, tier and text. ADR-0033 decision 4 says derived data takes the strictest of everything
  that went into it, including a model's context. Memory is derived data. A profile already holds
  whatever it distilled, so the leak is not to the profile itself: it is a fact rendered into a
  later model request whose label cannot account for it, and a fact read after the profile's
  ceiling was lowered.
- **Memory is never in a pack.** `assemble_pack` records only the names of `memory_scopes`. No
  code renders entries into a section yet; ADR-0035's renderer will be the first.
- `MemoryBackend` has `load(owner)` and `transact(owner, fn)` and no way to list owners.
- **Reads are owner-scoped.** A cross-agent read raises `MemoryAccessError`. ADR-0035 rests on
  that, and it stays.

The threat is concrete: a fact learned from a bad source keeps steering later runs, because
nothing can tell which facts came from it. The design has to hold when the model that wrote the
fact is the one that was misled, so provenance must come from what the platform knows the model
was shown, never from what the model says about its sources.

## Decision

### History (PR 1)

1. **Every applied update appends a change record.** Per owner, the store keeps an append-only
   log. A record holds `at` (apply time, from the injected clock; not the report's `finished_at`),
   `scope`, `key`, `op`, the resulting `rev`, `value` (absent for `retire` and `verify`),
   `value_digest` (sha256 of the value), `pack_id`, `sources`, `exposed` (decision 9), `tlp`, the
   base-source closure (decision 10), `checked` (decision 7) and `reason` (only on records the
   operator causes). The entry and its records are written in the **same backend
   transaction**: a batch that fails writes neither an entry nor a record, on `InMemoryBackend`
   and `FileBackend` alike, and a test proves it for both.
2. **Entries are derived from the log.** Per owner, the stored value becomes `{entries, log}`; the
   entries are a cache of the log, and a test proves that folding the log reproduces them on both
   backends (ADR-0014's derived state). An entry gains `rev` and `updated_at`. `rev` starts at 1
   on a key's first `add`, rises by one on every record for that key, and **never restarts**,
   even after `retire` and a later `add`, so `@rev` names one value for the store's whole life.
   Existing entries migrate once to `rev: 1`, `checked: false`, `tlp: red`, `sources: []`.
3. **The clock is injected.** The store takes `now=` (a callable returning UTC). `_apply` reads no
   clock of its own.
4. **No secret enters the log.** Before the transaction, every `value` is run through the
   platform's secret screen (`homelabnext.agent.screen`, secret types) and the leak-scan shapes.
   A match refuses the whole batch; the refusal names the key and the type, never the value. An
   append-only log would otherwise make a leaked credential permanent (ADR-0033 decision 14).
5. **History is read through the owner's scope.** `history(profile, scope, key)` returns the key's
   records in order. `as_of(profile, scope, t)` returns the scope's live entries as they stood at
   `t`, rebuilt from the log; it shows what the profile believed at `t`, including facts retracted
   later (follow-up 1). Both are owner-scoped like `read` (`owner=` naming another profile raises
   `MemoryAccessError`) and both apply the reader's ceiling at the time of the read (decision 8).
   They are read-only; `MemoryStore`'s public API becomes `{apply_updates, apply_report, read,
   history, as_of}`, and `test_the_store_has_no_unvalidated_write_path` changes only by those two.
6. **The log is bounded.** Each owner has a hard cap on records, set in the profile. At the cap a
   write is refused and the operator is paged; nothing is dropped silently. A key may declare
   `keep_last: N` (ADR-0035's cursor keys use it), and only that key's oldest records beyond N are
   compacted, keeping their `value_digest`, `sources` and `tlp`. Every write also emits the
   owner's log-head digest (sha256 of the last record) into the event outbox, so a later
   tamper-evident chain (follow-up 2) has an outside anchor. Until then the log is a record of
   what the platform wrote, not proof against someone who can edit the state file.

### Sources and labels (PR 2)

7. **An update names its sources, and only identifiers the platform wrote count.** A
   `memory_updates` item gains an optional `sources` list. `report_result` becomes **1.2**, an
   additive minor that also adds `verify` to `op` (decision 14) and bounds the lists:
   `memory_updates` at most 64 items, `cites` at most 128, `sources` at most 16 unique items,
   each matching exactly one of:
   - a content digest, `^sha256:[0-9a-f]{64}$`;
   - a canonical record uid (UUIDv7), never a legacy record code;
   - a memory revision, `mem:<profile id>/<scope>/<key>@<rev>`.

   Patterns are anchored as in `ids/common`. 1.2 is a normal frozen minor (ADR-0001 decisions 3
   and 4: a released major cannot be `x-draft`), so PR 2 merges only after this ADR is accepted.

   When a report is applied with its pack, every source must equal an identifier the **pack
   assembler** wrote into the pack's structured records, for something the pack actually
   **rendered** (a section that survived the budget):
   - a rendered knowledge item's `digest`, `file_digest`, or the uid of its record node id
     (`lesson:<uid>` gives `<uid>`);
   - a rendered input item's `digest` or `uid`, which the caller supplies per item in `inputs`
     and the pack records (never parsed from the text);
   - an entry in the pack's `memory` block (decision 11).

   Text is never a source: not `cites[].ref`, not a section body, not `summary`. Anything else
   refuses the whole report. An update with no `sources` is stored with `sources: []` and is
   reported as `unsourced`.

   Platform code that applies updates without a report (ADR-0035's fold) passes `sources=` and
   `unchecked=True` explicitly; the default of `apply_report` is the checked path. An unchecked
   record is marked `checked: false`, and the reverse index marks its edges as unchecked.
8. **An entry's label has a floor set by everything the model saw.** The pack gains labels: each
   rendered knowledge item and input item carries `tlp`, set by the assembler from the input's
   declared label (a record's or page's label; an input item's label from the caller), never from
   the text; an item with no label is `red`. The pack's label is the strictest of its rendered
   items. The store computes each record's `tlp` as the strictest of:
   - the pack's label (`red` for a report applied without its pack, and for platform writes
     unless the caller passes a label it computed by ADR-0033 decision 4);
   - the label of each source;
   - the entry's current label.

   This holds for every op. A label is never lowered except by a release transform (ADR-0033
   decision 7). Until packs carry labels, every pack is `red`, so all memory is `red`.

   Reads take the reader's ceiling from the `VerifiedProfile` (its attested `tlp_ceiling`, else
   the ceiling its `data_tier` gives), never from a caller argument. An entry above the ceiling
   is not returned, and its key is not returned either: keys are model-chosen slugs that can
   carry content. A read reports only `withheld: <count>` per scope. While all memory is `red`,
   a profile whose ceiling is below `red` reads its whole memory as withheld; that is the
   intended conservative state, and it is said here so it is not mistaken for a bug.
9. **A pack that rendered a source exposes its facts to it.** Every change record keeps, besides
   the sources it cites, the identifiers of everything its pack rendered (`exposed`). Citing is
   the model's claim; exposure is the platform's knowledge.
10. **Sources accumulate, and dependence is computed at write time.** An entry's **effective
    sources** are the union of the sources of every record since its last `add`: a `replace` or
    `verify` adds sources, never removes them. Each record stores its **base-source closure**: its
    effective sources, the closures of the `mem:` revisions it cites, and the aliases of each
    source (decision 13), capped at 256 identifiers (an update exceeding the cap is refused).
    `mem:` references name only revisions that already exist, so the memory graph has no cycles.
    Records carry no `derived_from` today (ADR-0033's consequences); when the records library
    exposes it, the closure includes it, cycles visited once.

### Memory citing memory (PR 3)

11. **A `mem:` source names a revision the pack showed.** When platform code renders memory
    entries into a pack, the pack gains a `memory` block of `{scope, key, rev, value_digest, tlp}`
    for each entry it carries. A `mem:` source is valid only when it names an entry in that block.
    Until something fills the block (ADR-0035's renderer), every `mem:` source is refused. A `mem:`
    source naming another owner is refused before any store lookup, with the same message whether
    or not the entry exists, so the check is no existence oracle. No update may cite any revision
    of its own key.

### Reverse index and retraction (PR 3)

12. **Retraction is an operator tool outside the agent's reach.** `dependents`, `retract`, `lift`
    and `purge` live on `MemoryAdmin(backend)`, a separate class the agent runtime never
    constructs; an import-graph test holds that line. Each takes an `OperatorPrincipal`, built only
    by the `hnx agent memory` command from the invoking operating-system user (or, later, from the
    broker's operator peers); passing a `VerifiedProfile` or a string raises. `MemoryBackend`
    gains `owners()`. None of these is a broker action: `hnx broker validate` refuses an action
    named `memory.retract`, `memory.lift`, `memory.purge` or `memory.dependents`. If it is ever
    exposed through the broker, it is an operator operation answered only to an operator peer, not
    affected by `approvers` or `allow_agent_approvers`, and never answered to a profile.
    `test_cross_agent_read_is_refused` passes unchanged.
13. **`retract` denies every name of a source, first.**
    - `dependents(source)` returns two sets across owners: **cited** (records whose closure
      reaches the source) and **exposed** (records written from a pack that rendered it without
      citing it). Unchecked edges are marked.
    - `retract(source, reason, by=)` resolves the source to its alias set (the uid, every content
      and file digest the store has seen for it, its graph id) and appends one deny record per
      alias **before** anything else, in its own transaction. Whether a uid retraction covers all
      its content revisions is the operator's choice (`revision: this | all`, default `all`).
    - It then retires every live entry in **cited**, owner by owner, each with a record `op:
      retire, reason: retracted:<source>`; with `include_exposed` it retires **exposed** too. The
      retirements are idempotent, so re-running `retract` completes one that crashed part-way.
    - It returns the affected owners, scopes and keys to the operator, and offers the same
      `dependents` output as a dry run first.
    - The deny list is an append-only log of `retract` and `lift` records, kept by the backend
      under a reserved key that no profile id can take. Retracting twice changes nothing the
      second time.
14. **A retraction sticks.**
    - Every `apply_*` re-checks the deny list inside its owner transaction, under the same lock,
      against each record's closure and its `exposed` set, so a report validated before a
      retraction cannot land after it.
    - A report whose pack **rendered** a denied source is refused, whatever it cites.
    - The pack assembler excludes denied sources at selection time (a knowledge exclusion with
      reason `retracted`, an input item listed as omitted), so no new run is shown one.
    - For a scope written only by platform code (ADR-0035's `fleet-ledger`), a denied update is
      dropped from its batch and reported; the rest applies, so a retraction cannot stall the
      fold.
    - `lift(source, reason, by=)` appends a lift record. It restores nothing: retired entries stay
      retired until a new report adds them.
    - `purge(owner, scope, key, rev, reason, by=)` replaces one record's `value` with nothing,
      keeps its `value_digest`, `sources` and `tlp`, and writes its own record. It is how a
      retracted poisoned value, or a secret the screen missed, leaves the log.

### Staleness (PR 4)

15. **A model can reassert a fact; only a verifier verifies it.** An entry gains `verified_at` and
    `reasserted_at`, both set at write time. `op: verify` takes no value, bumps `rev`, and must
    cite at least one non-`mem:` source the pack rendered; it sets `reasserted_at`, never
    `verified_at`. `verified_at` is set only by a `Verifier` implementation (a protocol is defined;
    none ships). `read(..., stale_after=)` reports entries whose `verified_at` is older than the
    budget as stale, with `reasserted_at` beside it.

### Evals (PR 5)

16. **Memory is judged by replay.** A fixture history of reports and packs, with timestamps,
    sources, labels and a retraction partway through, is replayed into a fresh store. Golden
    questions have exact expected answers: the value of key K as of T; the history of K; what
    `dependents(S)` returns, cited and exposed; what is retired after `retract(S)`, and that a
    later report citing or rendering S is refused; which entries are unsourced, unchecked or
    stale; and what a reader at a given ceiling sees withheld. It lives under `tests/agent/`, runs
    in `make check`, and judges later changes to the memory design the same way.

### What this changes in ADR-0035

17. **Amendments to ADR-0035** (it lists this ADR as amending it):
    - **Decision 4 (the fold):** the fold applies its updates with `unchecked=True`, its
      `sources=` and its computed label; a denied update is dropped, not fatal (decision 14).
    - **Decision 5 (value fields):** `tlp` inside a ledger value stays for the coordinator's own
      reading, but the store's `tlp` (decision 8) governs reads, and the two never disagree
      downward: the store's label is at least the value's.
    - **Decision 7 (pack fill order):** within a level, stale entries (decision 15) and withheld
      counts are reported; the renderer, not this ADR, decides their rank.
    - **Decision 8 (tiers):** "removes" an entry means retire plus, for `drop` and `count` entries
      beyond the cap, compaction of their records (decision 6); the tiers stay capped because the
      log is capped.
    - **Decision 10 (sole writer):** `MemoryAdmin.retract` and `purge` may also write
      `fleet-ledger`, as operator actions.
    - **Consequences ("the store's tiers are capped"):** true again only with decision 6.
18. **A report shown to another profile carries its `memory_updates` as a count only.** ADR-0035
    shows the coordinator other profiles' reports; their memory values, sources and `mem:` keys
    would otherwise be a cross-agent read through the report.

## Consequences

- **Easier:**
  - Every fact traces to what its profile was shown, and back: from a bad source to every fact
    that cited it or was written in its presence, at any depth.
  - A wrong source is withdrawn in one operator action, denied under every name it has, and kept
    out of new packs.
  - "What did this profile believe at T" has an exact answer for incident review.
  - Labels cannot be lowered by choosing what to cite, so memory does not move `amber` or `red`
    content into a lower context.
  - A secret cannot enter the log, and one that slips through can be purged.
  - The replay turns "is this memory design better" into a test.
- **Harder:**
  - Until packs carry labels, all memory is `red`, and profiles below `red` see only withheld
    counts. That is the price of not guessing labels.
  - Every write adds records, and `FileBackend` rewrites one file holding every owner, so the
    log's size raises the cost of every write fleet-wide, not only the writer's. The caps
    (decision 6) bound it; a per-owner file is a later backend change.
  - Retraction by exposure (`include_exposed`) can retire facts that never used the source; it is
    the operator's choice, shown in the dry run.
  - "A retraction sticks" holds for `MemoryStore` only. The broker's free-form `memory.write` lane
    (granted without approval in the example manifest) can still carry the same fact; routing or
    removing that lane is a precondition of relying on retraction fleet-wide.
  - `rev` never restarting means keys grow numbers over a long life; that is the cost of `@rev`
    being unambiguous.
- **Obliges us to maintain:**
  - the log, its all-or-nothing and fold-reproduces-entries tests on both backends, the migration,
    the caps and the head-digest event (PR 1);
  - the secret screen on values (PR 1);
  - `report_result` 1.2, per-item identities and labels in packs, the source check and the
    label computation (PR 2);
  - the pack `memory` block and the `mem:` rules (PR 3);
  - `MemoryAdmin`, `OperatorPrincipal`, `owners()`, the deny log, the import-graph test and the
    broker-validate refusal (PR 3);
  - `verify`, `reasserted_at`, `verified_at` and the `Verifier` protocol (PR 4);
  - the replay fixture and its golden answers (PR 5);
  - `docs/modules/egress.md`'s line on memory stores, once the withheld read ships.
- **Follow-ups** (named here, decided later, each by amending this ADR):
  1. **Two meanings of "as of".** `as_of(T)` shows what was believed at T. A second mode that
     applies today's retractions to that past state is what replaying a past decision needs.
  2. **Tamper-evident history.** A hash chain over the log, anchored by the head digests decision
     6 already emits.
  3. **Wider limits on history.** Compaction beyond `keep_last` (folding old revisions of any key
     into a snapshot that keeps their sources), and a per-owner log file.
  4. **Value scanning beyond secrets.** Personal data and other screen types on stored values.
  5. **Staleness by scope.** A default `stale_after` per scope (for example `ops` 7 days,
     `profile` 90 days), so callers do not each choose their own.
- **Open:**
  - The broker's free-form `memory.write` lane (still an open decision in docs/agent.md).
  - Whether `MemoryAdmin` is ever reachable through the broker's operator peers.

## Alternatives

- **Label by cited sources only.** It lets a model lower a label by citing the green item and not
  the red one. Rejected for the pack floor (decision 8).
- **Let the model state its sources freely, or accept a digest found in a cite's text.** A
  fabricated or planted identifier is indistinguishable from a real one. Rejected for structured
  identifiers the assembler wrote (decision 7).
- **Retract only what cited the source.** A misled model may cite nothing, or cite an innocent
  item; the fact would survive. Rejected for cited plus exposed (decisions 9 and 13).
- **Record only `pack_id` and retract everything a pack produced.** It retires every fact from
  every run, including ones the source never touched. Kept only as the operator's opt-in exposed
  set.
- **Keep history in a separate store or the lake.** A second store can disagree with the first,
  and a crash between the writes leaves an entry without history. Rejected for one transaction.
- **Expose retraction as a broker action with an approval.** Every broker action is submitted by
  a profile, so a profile would choose the source and see the result across owners. Rejected for
  `MemoryAdmin` (decision 12).
- **Retract without a deny list, or deny one name only.** The next report, or the same source
  under another digest or uid, puts the fact back. Rejected (decisions 13 and 14).
- **Defer the secret scan.** With an append-only log, a leaked credential would be permanent.
  Rejected (decision 4).
- **Treat a model's `verify` as verification.** A misled model would keep its own bad fact fresh
  forever. Rejected for `reasserted_at` (decision 15).
- **Return withheld entries by key.** Keys are model-chosen and can carry content. Rejected for a
  count (decision 8).
