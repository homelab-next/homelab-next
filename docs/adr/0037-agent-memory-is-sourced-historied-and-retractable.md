---
summary: Every agent memory entry records its sources, TLP and revision history; an operator retracts a bad source and everything built on it.
summary_of: outline:sha256:cc0b15786d3b8d62
---
# ADR-0037: Agent memory is sourced, historied and retractable

- **Status:** accepted (2026-11-05, by the operator; defects found on the first real deploy are
  fixed as they come)
- **Date:** 2026-11-05
- **Amended:** 2026-11-05 (decision 6: `keep_last` folds a key's older records into one range
  record, and tombstones in a platform scope age out past a budget, so platform scopes are
  bounded; see the amendment under it)
- **Amended:** 2026-11-06 (decision 6: a per-scope byte cap over records only and an owner-wide
  exposure budget, and range records capped at 256 value digests and pack ids; decision 7: a
  pack is bound to the profile it was assembled for, and input uids come only from a reader's
  sealed map; decision 10: an unchecked platform update past the closure cap is dropped, not
  fatal; follow-up 6: a path that takes a pack off `red`; see the amendments under each)
- **Amended:** 2026-11-06 (PR 3 review: decision 9, the exposure's `pairs`, the write-time check
  following cited lineage and truncated ranges; decision 12, operators trusted through root
  ownership and the uid, the deny state in its own file, the state file's owner kept; decision
  13, narrow alias closure, a `mem:` source's own revision, settings fixed on a rerun; decision
  14, input items matched by uid, quarantined sections, purge leaving no guessable digest; see
  the amendments under each)
- **Amended:** 2026-11-06 (PR 4: decision 15, how a verifier is asked and what clears
  `verified_at`; see the amendment under it)
- **Amended:** 2026-11-06 (review 2: decision 17 covers the ledger's decisions 3 and 7 as well,
  whose warm and cold tiers are now live keys, so decision 6 needs no opt-out; see the amendment
  under it)
- **Amended:** 2026-11-08 by ADR-0050, proposed (decisions 1, 2, 7, 12, 13, 15 and 16: records
  gain `rung`, `pending`, `live_only`, `expired`, `consolidation_reason` and `expect_rev`, a pack
  its `purpose`, one update per key per checked batch, `MemoryAdmin.review`, restoration on
  `retract`, and an offline consolidation pass as an author of revisions; the text is ADR-0050
  decision 9)
- **Related:** ADR-0001 (additive schemas), ADR-0014 (append-only events, derived state), ADR-0017
  and ADR-0030 (the broker), ADR-0032 (context in levels), [Agent profiles](../agent.md) ("Agent
  memory (M-09)"), `homelabnext/agent/memory.py`, `homelabnext/agent/pack.py`,
  `homelabnext/agent/knowledge.py`, `schemas/agent/report_result.schema.json`
- **Depends-on:** ADR-0033
- **Amends:** ADR-0035
- **Amended-by:** ADR-0050

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

### History (PR 1)

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
   A batch is stamped at the later of the clock and the log's newest record when the clock lags
   by at most five minutes; a larger lag refuses the batch and pages once, so the log's time never
   goes backwards. If the host clock was wrong forward and has been corrected, the log holds a
   future-stamped record and refuses writes until real time passes it; recovering sooner is an
   operator re-stamp in `MemoryAdmin` (PR 3).
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

   *Amendment (2026-11-05):* as first written, decision 6 did not bound a platform scope.
   `keep_last` kept every record and dropped only values, and every retired key left a tombstone
   for good, so ADR-0035's ledger (a cursor replaced on every fold, item keys new every time)
   would reach its record cap and stall. Decision 6 now reads, for platform scopes:
   - `keep_last` folds a key's records beyond its last N into **one range record** per key. The
     range record keeps the rev range (`rev_from` to `rev`), the value digests, the union of the
     sources, closures and `pack_id`s, the strictest `tlp`, when the range starts (`since`) and
     the state it leaves the entry in. It drops the values. A later fold merges into it, so a key
     holds at most N + 1 records. **The bound covers only keys a `keep_last` pattern matches.** A
     key replaced without end (ADR-0035's `cursor-*` keys) needs a pattern, or it reaches the
     record cap.
   - Whole-key tombstones in a platform scope **age out oldest first** once they exceed the
     scope's tombstone budget: `memory_limits.tombstones: {<scope>: N}` (profile schema 1.6,
     additive, below the scope's record cap), by default 10% of the record cap. Only a key whose
     last record is its tombstone (a retired key) ages out. A key retired and added again keeps
     its old tombstone as an earlier record, and it is live, so it stays. Aged-out tombstones fold
     into the
     scope's one `aged` record. It keeps the count, the time range they cover and the scope's
     **high-water `rev`** (the largest it aged). A key's next `rev` is one above the larger of
     its own last `rev` and that high-water `rev`, so `rev` is never restarted or reused. Once a key in a scope has aged out,
     every key first added there starts above the high-water `rev`, because the scope no longer
     knows which keys it has seen.
   - `as_of` answers `compacted` for a key whose state at `t` lies in a range record or
     tombstone. When `t` falls in the aged range, it says `aged_out: true`: the aged keys' names
     are gone, so any key it does not list must be read as compacted.

   *Amendment (2026-11-06, PR 2):* closures (up to 256 identifiers) and exposures (up to 1,024)
   make the record cap alone no bound on bytes. Measured in compact JSON: a typical record (a
   200-character value, three sources, a ten-identifier closure) is about 1 kB; the largest model
   record (2,000 characters, 16 sources, a full closure) 22.5 kB in ASCII and 26.5 kB in CJK
   text; a range record at its list caps about 95 kB; one exposure 1.5 kB at 20 rendered
   identifiers and 75.8 kB at 1,024.
   - **A per-scope byte cap** beside the record cap, `memory_limits.bytes: {<scope>: N}` (profile
     schema 1.7, additive), counts the scope's **records only**: by default 2,000 bytes per record
     of the record cap (20 MB for a 10,000-record scope), so ordinary memory meets its record cap
     first and the byte cap binds only once closures grow fat.
   - A model can reach a scope's byte cap on purpose: about 65 to 75 maximal reports (64
     updates each, every one a 2,000-character value with 16 sources, about 4.8 kB a record) fill
     the default 20 MB of a 10,000-record scope. That is a refusal the operator is paged for, not a loss: the cap holds
     and nothing already stored is touched.
   - **Exposures are charged once per owner**, against `memory_limits.exposure_bytes` (profile
     1.7, additive), by default 50,000,000 bytes: about 33,000 ordinary packs or 660 full ones.
     Only a batch that stores a new exposure can cross it. Past it, every checked write from a
     new pack is refused and paged; the profile keeps writing from packs it already holds. That
     self-lockout is intended (an unbounded exposure index is the alternative), and it ends when
     the operator raises the budget in the reviewed profile or purges (PR 3).
   - A cap's refusal says what actually frees it. For a model-written scope that is raising the
     cap in the reviewed profile or an operator purge (PR 3): such a scope never shrinks, so
     retiring keys frees nothing. For a platform scope it is retiring finished keys and a
     `keep_last` pattern, so the scope compacts. A byte refusal reports the cap, never the
     scope's byte total, which would count records the reader may not see.
   - **A range record keeps at most 256 value digests and 256 pack ids**, the newest, and is
     marked `truncated: true` past that, so a key replaced without end has a bounded range
     record. Its sources and closures stay whole, and they are bounded only for a key that is
     never re-added: each add starts a closure of up to 256 afresh, and the range unions them
     all. A retraction treats a truncated range
     conservatively: as exposed to everything its sources reach, since the packs it no longer
     lists cannot be checked one by one.
   - A range record also stores `effective`, the folded state's own effective sources (those
     since its last `add`), beside the union in `sources`. The fold reads `effective`;
     `dependents` reads the union. A range that spans a `retire` and a later `add` would
     otherwise hand the re-added key the retired value's sources.

### Sources and labels (PR 2)

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

   *Amendment (2026-11-06, PR 3 review):*
   - **An exposure is `{rendered, memory, pairs}`.** `pairs` holds each rendered item's
     platform-issued names, one group per item (indexes into `rendered`, a graph id as itself),
     the only place `retract` takes aliases from (decision 13). Pairs count toward
     `exposure_bytes` (decision 6, amended) like the rest of the exposure; as indexes they add
     about 10 bytes an item.
   - **The write-time check follows cited lineage.** Besides the pack's own `rendered` names and
     the marks on its memory block's revisions, a write is refused (or, unchecked, dropped) when
     any `mem:` revision in an update's closure carries an active mark, and the assembler leaves
     out of a memory block an entry whose closure cites a marked revision. So a fact two hops from
     a reached revision cannot be laundered through a replace.
   - **"Constant-cost" is per pack, not per write.** The check reads the pack's names, its block's
     marks (looked up per key) and each update's closure: its cost grows with the pack and the
     closures (both capped), and with the number of marks on the keys it looks at, never with the
     size of memory.
   - **Truncated ranges.** A range record exists only in a platform scope (decision 6), whose
     writes are unchecked and store no exposure. An unchecked record's `pack_id` is provenance
     (the pack the platform acted for), never exposure: the walk reads exposure only through
     checked records. So the pack ids a range record drops at 256 point at no exposure, and
     nothing is lost. A truncated record a retraction's sources reach is cited (its closure
     holds them) and `dependents` lists it once, under `cited`, flagged `truncated`.

   *Amendment to decisions 7 and 8 (2026-11-06, PR 2):*
   - **A pack is bound to its profile.** The assembler records the `VerifiedProfile` it was
     assembled for as `profile: {id, digest}`, and the store refuses a checked write whose pack
     names another profile, or none. The runner applies a report with the session's own pack,
     which it holds; it never looks a pack up by the report's `pack_id`, which the model wrote.
   - **Input uids come from a reader's sealed map.** `resolved_uids` is a `ResolvedUids`, built
     only by `resolve_input_uids` from the rows a records or lake reader stored (`{uid, digest,
     tlp}`, the label read as stored data, so a non-canonical label is `red`). An item whose
     digest is not the stored one is refused, and so is a digest paired with two uids.
   - **A section's label may rise from its text.** An input section's label is the strictest of
     its items' and of any TLP marker in its text. Text never lowers a label.
   - **A trimmed section counts as rendered.** A section the budget cut short, but did not drop,
     counts every item declared for it as rendered: the assembler cannot tell which item a cut
     fell in, so it errs toward retracting more.
   - **Reads are no oracle.** A write returns only what it touched, filtered by the writer's own
     ceiling; `history` of a key with no visible record answers `records: []` and the scope's
     withheld count, as for a key that does not exist; a write refusal names the update's
     position, never its key; `as_of` says `aged_out` only when the aged record is within the
     ceiling.
10. **Sources accumulate, and dependence is computed at write time.** An entry's **effective
    sources** are the union of the sources of every record since its last `add`: a `replace` or
    `verify` adds sources, never removes them. Each record stores its **base-source closure**: its
    effective sources, the closures of the `mem:` revisions it cites, and the aliases of each
    source (decision 13). The closure is capped at 256 identifiers. An update that would exceed
    the cap is refused, so such a key is retired and added again. `mem:` references name only
    revisions that already exist, so the memory graph has no cycles. Records carry no
    `derived_from` today (ADR-0033's consequences); when the records library exposes it, the
    closure includes it, cycles visited once.

    *Amendment (2026-11-06, PR 2):* in an **unchecked** platform batch, an update past the
    closure cap is dropped and reported (its position, in the result's `dropped`), and the rest
    of the batch applies, as a denied update is (decision 14): a key ADR-0035's fold replaces
    without end must not stall the fold. A checked batch with such an update is still refused
    whole. A drop pages the operator once per crossing (pair `AGENT_MEMORY_DROPPED`, keyed by a
    digest of owner and scope, naming the scope and the count, never a key), and recovers on the
    scope's next batch with no drop, so a key that stopped advancing is seen, not silent. The
    fold's `cursor-*` writes carry no `sources`: a cursor is position, not provenance, so a cursor
    replaced without end never reaches the cap.

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

    *Amendment (2026-11-06, PR 3 review):* **the boundary is the uid and file ownership, not the
    Python type.** A runtime that runs arbitrary Python can construct any object; it cannot
    change its uid or write root's files.
    - **The operators file** is `/etc/homelabnext/memory-operators.yml` (`--operators` names
      another only when the effective uid is 0), shaped `{operators: [users], agent_runtime:
      [{user}|{uid}], broker: [{user}|{uid}], broker_manifest?: path, deny_file: path}`. It is trusted only
      through root ownership: the file and every directory above it are owned by uid 0 and
      writable by no group or other. It
      is opened with `O_NOFOLLOW`, and the descriptor that is `fstat`-ed is the one parsed.
    - **Refused uids**, whatever `operators` says: `agent_runtime`, `broker`, the broker
      manifest's `callers`, `approval_relays`, 1.8 `operators` peers and Code Mode `runners` and
      `sandboxes`, and always the owner of the memory state file, which the runtime owns and the
      operators file cannot forge. **The runtime must not run as root**: a state file owned by
      uid 0 refuses every operator. The deployment runs `hnx agent memory` through `sudo`, so
      the principal's user is `root` (listed in `operators`), and `by` on every record reads
      `root`: **attribution comes from sudo's own log**. `SUDO_USER` is recorded as `by_sudo`,
      an environment value the invoker sets, advisory only.
    - **Every method re-checks the process**: `require_operator` compares `os.getuid()` and
      `os.geteuid()` with the principal's uids and the refused set, so a principal forged or
      carried into another process does not act. The seal on `OperatorPrincipal` guards against
      accidents, not attacks.
    - **The deny state lives in its own file**, not under reserved keys of the runtime's state
      file: the deny log and the `denied_reach` index in one JSON file beside a `.lock` file,
      owned by root (or the operator), mode 0644, in a directory the runtime cannot write.
      **One path serves both**: the operators file's required `deny_file`, which `hnx agent
      memory` uses and the runtime reads (`deny_path_from`); `FileBackend(path, deny_path=)`
      requires it (no default). The runtime only reads the file, under a shared `flock` taken
      inside its own `transact`; only `MemoryAdmin` appends, under the exclusive lock. Lock order:
      the deny file, then the state file. Every lock is taken without blocking and retried for a
      bounded time (5 s by default), so a process that holds one forever gets a refusal, not a
      hang. A deny file whose lock is missing is still read (fail closed). `hnx agent memory`
      refuses a deny file (or a directory above it) the runtime could write; the runtime refuses
      one it can write itself, and pages (`AGENT_MEMORY_DENY`). `InMemoryBackend` keeps the
      equivalent in process, under its own lock. Owners starting `@` stay refused.
    - **The operator stamps the state file.** After each append, `MemoryAdmin` writes the deny
      path and how many records it wrote into the runtime's state file (reserved key
      `@deny-stamp`); the runtime refuses writes, and pages, when its deny file is missing, is
      another path, or is shorter than the stamp, so a retraction cannot silently not apply.
    - **Root never touches a name the runtime controls.** Run as root, every state-file operation
      (load, rewrite, lock, quarantine, temporary files) runs with the effective uid and gid (and
      groups) of the state file's owner, restored afterwards, so a lock planted as a link to a
      root file, or a dangling link into a root directory, is opened as the runtime and refused.
      What the operator writes there is the runtime's by construction. The state file must be no
      link, and it and the directories above it must be owned only by root or the runtime and
      writable by no group or other. A corrupt state file is refused, never quarantined and
      recreated by an operator run.
    - **Second re-audit (2026-11-06).** Reads check what writes check: `load_deny` (what new
      packs read through `denied`) refuses, and pages, a deny file the runtime could write or
      one that does not match the stamp, so a runtime on the wrong path never reads an empty
      deny set. The runtime's writability check walks every directory above the deny file. The
      operator run waits for the state file's lock at most 5 s, then refuses (exit 2). It pins
      the state file's uid and gid when it starts and refuses if they change, refuses a state
      file with more than one hard link, and lets the runtime own only the state file and its
      own directory: every directory above is root's. Each id change is undone in reverse in a
      `finally` that covers the setup too, so a failure part-way never leaves root's ids changed.
    - The whole `memory.*` broker action namespace is refused, `memory.restamp` included, except
      the notes lane's `memory.write`; and no broker handler may name `homelabnext.memory_admin`
      (defence in depth only: the broker's uid is refused as an operator, which is the boundary).
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
      under a reserved key that no profile id can take (amended under decision 12: in its own
      deny file). Retracting twice changes nothing the second time.

    *Amendment (2026-11-06, PR 3 review):*
    - **Alias closure never crosses from a digest to another uid.** A graph id closes to its uid
      (`node_uid`), a uid to its own digests and graph ids, a digest to the one uid it is paired
      with. A digest paired with more than one uid anywhere in the store is listed under
      `ambiguous` in `dependents` and joins only with an explicit `include_alias <uid>` per
      foreign uid; a uid's digest that another uid shares is left out the same way. So an
      attacker row that once carried a good record's digest cannot pull that record in. A digest
      that resolves to no uid (a lone digest) is denied by name alone, with a warning. A node
      without a uid is denied by its graph id under `revision=all`.
    - **A `mem:` source reaches its own revision.** It seeds the reached set and the marks with
      that revision, and its key is retired when that revision is current; memory blocks then
      leave it out and a pack that shows it is refused.
    - **A rerun cannot widen a retraction.** Each deny record carries the retraction's
      `revision`, `include_exposed` and `include_alias`; a rerun with the same settings completes
      it without `confirm`, and one asking for others needs a fresh `confirm` (a `settings`
      record then holds them). A lift that lands during a retraction stops it: every step
      re-checks that the deny id is still active, inside its transaction.
    - **Retire records add no marks**: no memory block shows a retired revision, so a completed
      retraction's own retirements leave the index as it was.
    - **Admin retirements are not held to the caps**, and a platform key retired so compacts on
      its scope's next platform write.
14. **A retraction sticks.**
    - **Writes re-check the deny list.**
      - `MemoryBackend` gains `owners()`.
      - `transact(owner, fn)` passes the deny log, read under the same lock: `FileBackend` uses
        `StateStore.rewrite`, and `InMemoryBackend` gains a lock (amended under decision 12: the
        deny file's own shared lock, taken first).
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

    *Amendment (2026-11-06, PR 3 review):*
    - **Purge leaves no plaintext digest.** Every `value_digest`, range `value_digests` entry and
      the purge record's digest of the purged value becomes one random `purged:<hex>` token per
      purge (records of one value still share it), since an unsalted digest of a low-entropy
      value is a guess away from the value. Only the operator's dry run shows the digest. A rerun
      finds nothing and appends nothing.
    - **Input items are matched by uid.** An input item is denied by a denied uid, or by its
      digest only where a `revision=this` retraction denied that digest, so a feed item that
      merely carries a denied digest under another uid is not censored by it.
    - **A section declaring a denied item is left out whole**: the assembler cannot cut one item's
      text from a section. A required one is quarantined (listed in `omitted` and in the pack's
      `retracted.quarantined`, and paged by the caller with `quarantine_page`, pair
      `AGENT_PACK_QUARANTINED`), and the pack goes ahead without it. (As first built, the pack was
      deferred, with the reason in `deferred_reasons`.) No caller reads an empty `deferred`
      as "every required section is present": the agent CLI and the handoff look only at
      `status`, and a report that must cite the missing section fails `must_cite`. Callers
      should filter denied items before they render a section's text, so a whole section is not
      lost for one item.

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

    *Amendment (2026-11-06, PR 4):*
    - `verify` is a checked write only: an unchecked platform write has no pack, so it cannot
      cite a source the pack rendered. A verify of a key that is not live is refused, and so is
      one with a value. `validate_report` refuses the malformed ones too.
    - The store asks its `Verifier` (`MemoryStore(verifier=)`) about every `add`, `replace` and
      `verify` of a batch once the batch is accepted, inside the transaction; it is never asked
      about a refused batch, whose values must not leave the store (the record cap, the byte cap,
      with the bytes its stamps can add reserved, and the exposure budget are checked before it
      is asked; a write that fails after the verifier was asked (I/O) is not a refusal). The
      request carries the record's label, and a verifier must not send the value past that
      label's egress ceiling (ADR-0033). Only `True` stamps the record's `verified_at` (the
      record's own time). A `replace` the verifier does not confirm clears the entry's
      `verified_at`, since the value changed. A `verify` it answers `False` is a statement that the fact does not hold: the
      record is marked `refuted` and the entry's `verified_at` is cleared. A verifier that cannot
      answer (it raises, or returns anything but a bool) verifies nothing and refuses nothing,
      and a `verify` it cannot answer keeps the earlier stamp.
    - A `verified_at` later than the time staleness is judged at is stale: an operator restamp
      (decision 3) moves `at` back after a clock ran ahead but leaves `verified_at`, which must
      not then read as fresh for as long as the clock was wrong.
    - `as_of(..., stale_after=)` judges staleness at `t`, from the stamps as they stood then.
      `memory_block_input(..., stale_after=)` marks each entry `stale` with its stamps, and the
      pack's memory block records them; the renderer decides their rank (decision 17).
    - A range record keeps its folded state's `reasserted_at` and `verified_at`, so the fold
      reproduces both.

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
      value's own `tlp` field. A denied update is dropped, not fatal (decision 14). The ledger's
      profile gives its `cursor-*` keys a `keep_last` pattern (decision 6, amended); a key no
      pattern matches is not bounded by it. The fold's `cursor-*` writes carry no `sources`: a
      cursor is position, not provenance, so it never reaches the closure cap (decision 10,
      amended); an update dropped there pages (`AGENT_MEMORY_DROPPED`).
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

    *Amendment (2026-11-06, review 2):* as first written, this list left out ADR-0035's decisions
    3 and 7, which built the warm tier from retired keys. A retired key here keeps value digests,
    not values, and its tombstone ages out oldest first whatever its retention class, so those
    decisions could not be built on this store. ADR-0035 now defines every tier as live keys
    (`warm-*`, `rollup-*`, `exc-*`; its decisions 3, 7 and 8, amended), and its fold and renderer
    read no tombstone. So:
    - **Decision 3 (keys):** a closed item's history is its `warm-*` key, not its tombstone.
    - **Decision 7 (pack fill order):** levels 4 and 5 render live keys only.
    - **Decision 8 (tiers):** the line above holds for every key leaving a tier. Whole compaction
      and oldest-first age-out (decision 6) stay as built, with no per-scope opt-out, because no
      tier lives in a tombstone. The ledger's profile gives its replaced keys (`cursor-*`,
      `rollup-*`) `keep_last` patterns.
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
  - A retired key whose tombstone ages out of a platform scope (decision 6, amended) leaves
    `dependents` for good: its sources, closures and `pack_id`s go with it. It was already
    retired, so a retraction loses nothing live. Its time range stays visible as `aged_out` in
    `as_of`.
  - Until `MemoryAdmin` ships (PR 3), nothing can erase history: a report cannot write a platform
    scope, so it cannot cause compaction, and only platform code's own writes compact. The one
    exception is migration: a legacy key or value holding a secret is kept only as a `purged`
    marker, with no value and no digest, since an unsalted digest of a low-entropy secret
    confirms a guess.
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
  - **PR 4:** `verify`, `reasserted_at`, `verified_at` and the `Verifier` protocol (shipped:
    `MemoryStore(verifier=)`, `read`/`as_of(..., stale_after=)` and
    `memory_block_input(..., stale_after=)`; no `Verifier` implementation ships).
  - **PR 5:** the replay fixture and its golden answers (shipped: `tests/agent/replay/fixture.yml`
    and `golden.yml`, replayed on both backends by `tests/agent/test_agent_memory_replay.py`,
    which prints a diff per answer that differs; `make memory-replay` runs it alone).
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
  6. **A path off `red`.** Today no pack can be below `red`: `start_session`'s access and terms
     sections declare no label, records and pages carry none, and a knowledge node's label
     comes only from its graph node's attributes. The work, each a change of its own: give the
     access and terms static sections a declared label; add `tlp` to the record schemas (lesson,
     runbook and the rest, additive minors); and have the graph builder copy it into node
     attributes. Until then all memory is `red`, as decision 8 says.
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
