---
summary: Every agent memory entry records its sources, TLP and revision history; an operator retracts a bad source and everything built on it.
summary_of: outline:sha256:6a503131303d6a02
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
- `MemoryBackend` has `load(owner)` and `transact(owner, fn)`, no way to list owners, and no
  transaction across two keys; `InMemoryBackend` has no lock.
- **Reads are owner-scoped.** A cross-agent read raises `MemoryAccessError`. ADR-0035 rests on
  that, and it stays.

The threat is concrete: a fact learned from a bad source keeps steering later runs, because
nothing can tell which facts came from it. The design has to hold when the model that wrote the
fact is the one that was misled, so provenance must come from what the platform knows the model
was shown, never from what the model says about its sources.

## Decision

### History (PR 1, may merge while this ADR is proposed)

1. **Every applied update appends a change record.** Per owner, the store keeps an append-only
   log. A record holds `at` (apply time, from the injected clock; not the report's `finished_at`),
   `scope`, `key`, `op`, the resulting `rev`, `value` (absent for `retire` and `verify`),
   `value_digest` (sha256 of the value), `pack_id`, `sources`, `checked`, `tlp`, the
   base-source closure (decision 10) and `reason` (only on records an operator causes). Until PR
   2, every record is written with `sources: []`, `checked: false` and `tlp: red`, so stored
   records keep one shape. The entry and its records are written in the **same backend
   transaction**: a batch that fails writes neither, on `InMemoryBackend` and `FileBackend`
   alike, and a test proves it for both.
2. **Entries are derived from the log.** Per owner, the stored value becomes `{entries, log}`; the
   entries are a cache of the log, and a test proves that folding the log reproduces them on both
   backends (ADR-0014's derived state). An entry gains `rev`, `updated_at` and `reasserted_at`.
   `rev` starts at 1 on a key's first `add`, rises by one on every record for that key, and
   **never restarts**, even after `retire` and a later `add`, so `@rev` names one value for the
   store's whole life. Existing entries migrate once to `rev: 1`, `checked: false`, `tlp: red`,
   `sources: []`.
3. **The clock is injected.** The store takes `now=` (a callable returning UTC). `_apply` reads no
   clock of its own.
4. **No secret enters the log.** Before the transaction, every `key` and `value` is run through
   the platform's secret screen (`homelabnext.agent.screen`, secret types) and the leak-scan
   shapes. A match refuses the whole batch; the refusal names the key's position and the type,
   never the value. An append-only log would otherwise make a leaked credential permanent
   (ADR-0033 decision 14).
5. **History is read through the owner's scope.** `history(profile, scope, key)` returns the key's
   records in order. `as_of(profile, scope, t)` returns the scope's live entries as they stood at
   `t`, rebuilt from the log; it shows what the profile believed at `t`, including facts retracted
   later (follow-up 1), and answers `compacted` for a key whose records at `t` were compacted
   (decision 6), never a wrong value. Both are owner-scoped like `read` (`owner=` naming another
   profile raises `MemoryAccessError`), both apply the reader's ceiling at the time of the read,
   and both report withheld records as a count only, as `read` does (decision 8). They are
   read-only: `MemoryStore`'s public API becomes `{apply_updates, apply_report, read, history,
   as_of}`, and `test_the_store_has_no_unvalidated_write_path` changes only by those two.
6. **The log is bounded per scope.** The profile gains an additive field, `memory_limits:
   {records: {<scope>: N}, keep_last: {<scope>: {<key pattern>: N}}}`, set in the compiled
   profile and never by a report.
   - Every scope has a record cap. Platform scopes (decision 7) have their own, which
     model-written scopes cannot consume.
   - At a cap, writes to that scope are refused and the operator is paged once per crossing
     (state-diffed), never silently dropped.
   - `keep_last` (platform scopes only) compacts a key's records beyond the last N.
   - A retired key in a platform scope may be compacted whole, to one tombstone record (below).
   - Compaction keeps each record's `rev`, `value_digest`, `sources`, closure, `tlp` and the
     `pack_id` that points at its exposure (decision 9), and drops only values.
   - A profile without `memory_limits` gets code-constant defaults: 10,000 records per scope and
     100,000 per platform scope.
   - A retired key's tombstone keeps the last `rev`, the union of the compacted records' sources
     and closures, and the list of their `pack_id`s.

   `platform_scopes` (decision 7) ships in this PR with `memory_limits`. This is what bounds
   ADR-0035's ledger, whose item keys are new every time.

### Sources and labels (PR 2, merges only after this ADR is accepted)

7. **An update names its sources, and only identifiers the platform wrote count.** A
   `memory_updates` item gains an optional `sources` list: at most 16 unique items, each matching
   exactly one of:
   - a content digest, `^sha256:[0-9a-f]{64}$`;
   - a canonical record uid (UUIDv7), never a legacy record code;
   - a memory revision, `mem:<profile id>/<scope>/<key>@<rev>`.

   Patterns are anchored as in `ids/common`. `report_result` becomes **1.2**, an additive minor
   that adds `sources` and adds `verify` to `op` (decision 15). It is a normal frozen minor
   (ADR-0001 decisions 3 and 4: a released major cannot be `x-draft`). Existing lists are not
   tightened in the schema, since that would not be additive. `validate_report` and
   `apply_updates` refuse more than 64 `memory_updates` or 128 `cites`.

   **A report is applied only with its pack**, and every source must equal an identifier the
   **pack assembler** wrote into the pack's structured records for something the pack actually
   **rendered** (a section that survived the budget):
   - a rendered knowledge item's `digest`, `file_digest`, or the uid of its record node id
     (`lesson:<uid>` gives `<uid>`);
   - a rendered input item's `digest` or `uid`, which the caller supplies per item in `inputs`
     and the pack records (never parsed from the text). The uid must be platform-issued: the caller resolves each input
     uid through the records or lake reader and passes the assembler a map of resolved uids (it
     stays a pure function with no I/O), and the assembler refuses an item whose uid is not in
     the map (decision 13);
   - an entry in the pack's `memory` block (decision 11).

   Text is never a source: not `cites[].ref`, not a section body, not `summary`. Anything else
   refuses the whole report. An update with no `sources` is stored with `sources: []` and reported
   as `unsourced`.

   **Platform scopes.** A compiled profile may list `platform_scopes` (for ADR-0035,
   `fleet-ledger`). Only `apply_updates(..., unchecked=True)` writes a platform scope, and it
   writes nothing else. A report's update naming a platform scope is refused. `apply_updates` without
   `unchecked=True` takes `pack=` and `pack_hash=` and checks sources exactly as `apply_report`
   does; without them it is refused. An unchecked record is `checked: false`, and the reverse index
   marks its edges as unchecked.
8. **An entry's label has a floor set by everything the model saw.** The pack gains labels.
   - Each rendered knowledge item and input item carries `tlp`, set by the assembler from the
     input's declared label (a record's or page's label; for an input item, the stored row's or record's
     `tlp` (ADR-0033 decision 5) or its source's declaration), never from the text. A label the
     caller supplies is clamped to be no looser than that, and an item with no label is `red`.
   - Pregate sections count as `red` (lab data, ADR-0033 decision 2). Static sections take the
     manifest's declared label, `red` when absent.
   - The pack's label is the strictest of all of these.

   The store computes each record's `tlp` as the strictest of:
   - the pack's label;
   - the label of each source;
   - the entry's current label.

   Unchecked platform writes are `red`; the store takes no label from a caller. This holds for
   every op. A label is never lowered except by a release transform (ADR-0033 decision 7). Until
   packs carry labels, every pack is `red`, so all memory is `red`.

   Reads take the reader's ceiling from the `VerifiedProfile` (its attested `tlp_ceiling`, else
   the ceiling its `data_tier` gives), never from a caller argument. An entry above the ceiling
   is not returned, and its key is not returned either: keys are model-chosen slugs that can carry
   content. A read reports only `withheld: <count>` per scope. While all memory is `red`, a
   profile whose ceiling is below `red` reads its whole memory as withheld. That is the intended
   conservative state, said here so it is not mistaken for a bug.
9. **A pack that rendered a source exposes its facts to it, through memory too.** For each pack
   whose report changed memory, the store keeps the pack's exposure once, keyed by `pack_id`, as
   `{rendered: [identifiers], memory: [mem:<owner>/<scope>/<key>@<rev>]}`: what the pack rendered,
   plus references to the memory revisions its `memory` block showed. It is never flattened.
   Exposure through memory is the walk over those references, which has no cycles because a pack
   references only revisions that already exist. `dependents` and `retract` do that walk at
   operator time. `retract` records each revision it reaches as `denied_reach: <deny id>` in a
   separate append-only index keyed by deny id and revision, never by editing the log; it walks
   until a pass finds nothing new, so a write that lands during the walk is caught, and a rerun
   does the same. A mark counts only while its deny id is not lifted, so a lift releases it
   without rewriting anything. The
   write-time deny check reads only the pack's own `rendered` identifiers and that mark on the
   revisions in its `memory` block, so it stays constant-cost however large memory grows. The cap
   (1,024 identifiers) applies to `rendered` only, and the caller checks it before assembly; a
   pack over it is refused. An exposure entry is dropped when no record points at it any longer.
   Citing is the model's claim; exposure is the platform's knowledge.
10. **Sources accumulate, and dependence is computed at write time.** An entry's **effective
    sources** are the union of the sources of every record since its last `add`: a `replace` or
    `verify` adds sources, never removes them. Each record stores its **base-source closure**: its
    effective sources, the closures of the `mem:` revisions it cites, and the aliases of each
    source (decision 13). The closure is capped at 256 identifiers. An update that would exceed
    the cap is refused, so such a key is retired and added again. `mem:` references name only
    revisions that already exist, so the memory graph has no cycles. Records carry no
    `derived_from` today (ADR-0033's consequences); when the records library exposes it, the
    closure includes it, cycles visited once.

### Memory citing memory (PR 3)

11. **A `mem:` source names a revision the pack showed.** When platform code renders memory
    entries into a pack, the pack gains a `memory` block of `{scope, key, rev, value_digest, tlp}`
    for each entry it carries. A `mem:` source is valid only when it names an entry in that block.
    Until something fills the block (ADR-0035's renderer), every `mem:` source is refused. A
    `mem:` source naming another owner is refused before any store lookup, with the same message
    whether or not the entry exists, so the check is no existence oracle. No update may cite any
    revision of its own key.

### Reverse index and retraction (PR 3)

12. **Retraction is an operator tool outside the agent's reach.** `dependents`, `retract`, `lift`
    and `purge` live on `MemoryAdmin(backend)`, a separate class.
    - An import-graph test holds that `homelabnext.agent`, `homelabnext.broker` and
      `homelabnext.orchestration` never import it.
    - Each method takes an `OperatorPrincipal`. It is built only by the `hnx agent memory` command
      from the invoking operating-system user, and it refuses the uids the agent runtime and the
      broker run as. It accepts only users in an operators list kept in reviewed configuration that
      the runtime's user cannot write, not in the state file. Passing a
      `VerifiedProfile` or a string raises.
    - None of these is a broker action: `hnx broker validate` refuses an action named
      `memory.retract`, `memory.lift`, `memory.purge` or `memory.dependents`. If it is ever
      exposed through the broker, it is an operator operation, answered only to an operator peer,
      not affected by `approvers` or `allow_agent_approvers`, and never answered to a profile.
    - `test_cross_agent_read_is_refused` keeps its assertions unchanged; only its setup passes a
      pack, as decision 7 requires of every checked write.
13. **`retract` denies every platform-issued name of a source, first.**
    - **Aliases come only from platform-issued pairings:**
      - a knowledge node's graph id, record uid and repository digests;
      - an input item's uid, which must be issued by the platform (a lake row's or record's
        uid), never taken from feed content.

      A pack in which an input item's uid is also a knowledge uid with a different digest is
      refused at assembly.
    - `dependents(source)` returns two sets across owners:
      - **cited:** records whose closure reaches the source;
      - **exposed:** records whose pack's exposure reaches it without citing it.

      Unchecked edges are marked. It doubles as the dry run: it lists the alias set and the
      affected owners, scopes and keys, and gives a digest of that list.
    - `retract(source, reason, by=, confirm=<dry-run digest>, revision=all|this,
      include_exposed=False)` refuses the call when `confirm` no longer matches what `dependents`
      returns (a rerun of a retraction whose deny records already exist skips `confirm` and
      completes it, keyed by the deny id), then appends one deny record per alias
      **before** anything else, in its own transaction.
      - With `revision=this`, it denies only that content digest. With `revision=all` (the
        default), it denies by uid. At check time, each pack's own
        pairing resolves a new digest to its uid, so later revisions of the same record are
        covered.
      - It then retires every live entry in **cited**, owner by owner, each with a record `op:
        retire, reason: retracted:<source>`. With `include_exposed=True`, it retires **exposed** too.
      - The retirements are idempotent, so re-running `retract` completes one that crashed
        part-way.
    - The deny list is an append-only log of `retract` and `lift` records, kept by the backend
      under a reserved key that no profile id can take. Retracting twice changes nothing the
      second time.
14. **A retraction sticks.**
    - **Writes re-check the deny list.**
      - `MemoryBackend` gains `owners()`.
      - `transact(owner, fn)` passes the deny log, read under the same lock: `FileBackend` uses
        `StateStore.rewrite`, and `InMemoryBackend` gains a lock.
      - Every apply re-checks each record's closure, its pack's `rendered` identifiers and the
        `denied_reach` marks in its `memory` block against the deny log
        inside its transaction, so a report validated before a retraction cannot land after it.
      - A report whose pack **rendered** a denied source is refused, whatever it cites.
      - A checked batch with a denied update is refused whole. An unchecked platform batch drops
        the denied update, reports it, and applies the rest, so a retraction cannot stall
        ADR-0035's fold.
    - **New packs leave denied sources out.** The caller passes the deny set (`retracted=`) to
      `select_knowledge`, which excludes those items with reason `retracted`, and to
      `assemble_pack`, which lists denied input items as omitted and leaves out of the `memory`
      block any entry whose closure reaches a denied source or that carries a `denied_reach`
      mark. Neither function reads
      the store.
    - **Lifting a retraction.** `lift(source, reason, by=)` appends a lift record. Its
      `denied_reach` marks stop counting at once. It restores nothing else: retired entries stay
      retired until a new report adds them.
    - **Purging a value.** `purge(owner | "*", value_digest | scope/key@rev, reason, by=)`
      (`"*"` with a digest finds every owner holding it):
      - retires the entry first if a purged revision is current;
      - blanks the value in every record with that digest and in the cached entry, keeping
        `value_digest`, `sources` and `tlp`;
      - writes its own record.

      `history` and `as_of` show `purged`. It is how a retracted poisoned value, or a secret the
      screen missed, leaves the store. Copies outside the store are not reached: backups,
      quarantined corrupt state files, and rendered packs kept in the activity detail tier.

### Staleness (PR 4)

15. **A model can reassert a fact; only a verifier verifies it.** `add`, `replace` and `verify`
    set `reasserted_at`.
    - `op: verify` takes no value, bumps `rev`, and must cite at least one non-`mem:` source the
      pack rendered.
    - `verified_at` is absent until a `Verifier` implementation sets it. A `Verifier` protocol is
      defined; none ships.
    - `read(..., stale_after=)` reports as stale an entry whose `verified_at` is absent or older
      than the budget, with `reasserted_at` beside it. So until a verifier ships, every entry is
      stale under any `stale_after`, by design.

### Evals (PR 5)

16. **Memory is judged by replay.** A fixture history of reports and packs, with timestamps,
    sources, labels, a write through memory and a retraction partway through, is replayed into a
    fresh store. Golden questions have exact expected answers:
    - the value of key K as of T;
    - the history of K;
    - what `dependents(S)` returns, cited and exposed, including one hop through memory;
    - what is retired after `retract(S)`, and that a later report citing or rendering S is
      refused;
    - which entries are unsourced, unchecked or stale;
    - what a reader at a given ceiling sees withheld.

    It lives under `tests/agent/`, runs in `make check`, and judges later changes to the memory
    design the same way.

### What this changes elsewhere (PR 3)

17. **Amendments to ADR-0035** (it lists this ADR as amending it):
    - **Decision 4 (the fold):** the fold writes `fleet-ledger`, a platform scope, with
      `unchecked=True` and its `sources=`. Its records are `red`, which is never below a ledger
      value's own `tlp` field. A denied update is dropped, not fatal (decision 14).
    - **Decision 5 (value fields):** `tlp` inside a ledger value stays for the coordinator's own
      reading. The renderer writes the store's label into what it renders, not the value's field.
    - **Decision 7 (pack fill order):** stale entries (decision 15) and withheld counts are
      reported. The renderer, not this ADR, decides their rank.
    - **Decision 8 (tiers):** "removes" an entry means retiring it and compacting the retired key
      whole (decision 6). The tiers stay capped because platform scopes have their own record cap
      and retired keys compact.
    - **Decision 10 (sole writer):** `MemoryAdmin.retract` and `purge` may also write
      `fleet-ledger`, as operator actions.
    - **Consequences ("the store's tiers are capped"):** true with decision 6.
18. **A report served to another profile carries its `memory_updates` as a count only.**
    Wherever a report is served to a profile other than its author, `memory_updates` is replaced
    by `{count: n}`: in ADR-0035's renderer, and in the context store's level reads by digest once
    the context store serves reports (still Open in ADR-0035). A test
    reads another profile's report by digest and finds no value, source or key. Otherwise the
    report would be a cross-agent read of memory.

## Consequences

- **Easier:**
  - Every fact traces to what its profile was shown, and back. From a bad source the trace
    reaches every fact that cited it, or was written in its presence, directly or through memory.
  - A wrong source is withdrawn in one operator action, after a dry run. It is denied under every
    platform-issued name it has, and kept out of new packs and new memory blocks.
  - "What did this profile believe at T" has an exact answer for incident review.
  - Labels cannot be lowered by choosing what to cite, no caller of the store sets one, and
    an input item's label is clamped to its stored label. So memory does
    not move `amber` or `red` content into a lower context.
  - A secret cannot enter the log, and one that slips through can be purged from the store.
  - The replay turns "is this memory design better" into a test.
- **Harder:**
  - Until packs carry labels, all memory is `red`, and profiles below `red` see only withheld
    counts. That is the price of not guessing labels.
  - Until a verifier ships, every entry is stale under any `stale_after`.
  - Every write adds records, and `FileBackend` rewrites one file holding every owner. So the log
    raises the cost of every write fleet-wide, not only the writer's. The per-scope caps bound
    it; a per-owner file is a later backend change.
  - Retraction by exposure (`include_exposed`) can retire facts that never used the source. But
    against a source that may have steered the model (poisoning), only `include_exposed` is
    complete: a misled model chooses what it cites. The dry run shows both sets so the operator
    chooses knowingly.
  - "A retraction sticks" holds for `MemoryStore` only. The broker's free-form `memory.write` lane
    (granted without approval in the example manifest) can still carry the same fact. Routing or
    removing that lane is a precondition of relying on retraction fleet-wide.
  - A key whose closure reaches 256 identifiers must be retired and added again.
  - Purge cannot reach copies outside the store.
- **Obliges us to maintain:**
  - **PR 1:**
    - the log and the migration;
    - the all-or-nothing and fold-reproduces-entries tests on both backends;
    - `memory_limits` and `platform_scopes` in the profile schema (an additive minor), the
      default caps, the per-scope caps, the once-per-crossing page and compaction;
    - the secret screen on keys and values.
  - **PR 2:**
    - `report_result` 1.2 and the list limits in `validate_report`;
    - per-item identities and labels in packs, including pregate and static labels;
    - the source check and the label computation.
  - **PR 3:**
    - the pack `memory` block and the `mem:` rules;
    - `MemoryAdmin` and `OperatorPrincipal` with its operators list;
    - `owners()` and the deny log passed into `transact`;
    - the `retracted=` arguments, the import-graph test and the broker-validate refusal;
    - decisions 17 and 18.
  - **PR 4:** `verify`, `reasserted_at`, `verified_at` and the `Verifier` protocol.
  - **PR 5:** the replay fixture and its golden answers.
  - **Docs:** `docs/modules/egress.md`'s line on memory stores, once the withheld read ships.
- **Follow-ups** (named here, decided later, each by amending this ADR):
  1. **Two meanings of "as of".** `as_of(T)` shows what was believed at T. A second mode that
     applies today's retractions to that past state is what replaying a past decision needs.
  2. **Tamper-evident history.** A hash chain over the log, with its head digest emitted to an
     outside anchor (a broker audit record or an event with its own schema), so the chain can be
     checked by someone who cannot edit the state file. Until then the log records what the
     platform wrote; it is not proof against someone who can edit the file.
  3. **Wider compaction.** Folding old revisions of model-written keys into a snapshot that keeps
     their sources, and a per-owner log file.
  4. **Value scanning beyond secrets.** Personal data and other screen types on stored values.
  5. **Staleness by scope.** A default `stale_after` per scope (for example `ops` 7 days,
     `profile` 90 days), so callers do not each choose their own.
- **Open:**
  - The broker's free-form `memory.write` lane (still an open decision in docs/agent.md).
  - Whether `MemoryAdmin` is ever reachable through the broker's operator peers.

## Alternatives

- **Label by cited sources only, or accept a caller's label.** Either lets a label be lowered: by
  citing the green item and not the red one, or by passing `clear`. Rejected for the pack floor
  and `red` platform writes (decision 8).
- **Let the model state its sources freely, or accept a digest found in a cite's text.** A
  fabricated or planted identifier is indistinguishable from a real one. Rejected for structured
  identifiers the assembler wrote (decision 7).
- **Retract only what cited the source.** A misled model may cite nothing, or cite an innocent
  item, and the fact would survive. So may a fact one hop away in memory. Rejected for cited plus
  exposed, propagated through memory (decisions 9 and 13).
- **Take aliases from whatever pairings a pack recorded.** A poisoned item could claim a good
  record's uid and get it retracted, or claim a fresh one and escape. Rejected for
  platform-issued pairings (decision 13).
- **Record only `pack_id` and retract everything a pack produced.** It retires every fact from
  every run, including ones the source never touched. Kept only as the operator's opt-in exposed
  set.
- **Keep history in a separate store or the lake.** A second store can disagree with the first,
  and a crash between the writes leaves an entry without history. Rejected for one transaction.
- **Expose retraction as a broker action with an approval.** Every broker action is submitted by
  a profile, so a profile would choose the source and see the result across owners. Rejected for
  `MemoryAdmin` (decision 12).
- **Retract without a deny list, or deny one name only.** The next report, or the same source
  under another name, puts the fact back. Rejected (decisions 13 and 14).
- **Defer the secret scan.** With an append-only log, a leaked credential would be permanent.
  Rejected (decision 4).
- **One record cap per owner.** A model-written scope could fill it and stall the platform's
  ledger. Rejected for per-scope caps (decision 6).
- **Bound `memory_updates` and `cites` in the 1.2 schema.** That tightens an existing list, which
  is not additive under ADR-0001. Rejected for limits in code (decision 7).
- **Treat a model's `verify` as verification.** A misled model would keep its own bad fact fresh
  forever. Rejected for `reasserted_at` (decision 15).
- **Return withheld entries by key.** Keys are model-chosen and can carry content. Rejected for a
  count (decision 8).
