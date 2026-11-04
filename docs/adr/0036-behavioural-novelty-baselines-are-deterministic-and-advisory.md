---
summary: A deterministic analyzer learns per-entity first-seen baselines from the lake over a decaying window; its findings are heuristic and never escalate alone.
summary_of: outline:sha256:0365a5d172926402
---
# ADR-0036: Behavioural novelty baselines are deterministic, recomputed from the lake, and advisory

- **Status:** proposed
- **Date:** 2026-11-04
- **Related:** ADR-0006 (detections in a Sigma subset); ADR-0013 and ADR-0033 (the lake, TLP
  labels and reader ceilings); ADR-0030 (agents act only through the broker);
  [decide](../decide.md) (the decision cascade); [log pipeline](../log-pipeline.md);
  [lake README](../../homelabnext/lake/README.md)
- **Amends:** ADR-0033
- **Depends-on:** ADR-0033

## Context

The platform's detection is deterministic: Sigma rules with must-fire and must-not-fire fixtures
(ADR-0006) and a decision cascade with a deterministic floor ([decide](../decide.md)). It answers
"does this event match a known-bad shape?". It cannot answer "is this normal *for this entity*?":
a host that has never spoken to a destination, a user who has never logged in from a source, a
program that has never written a class of file. That question needs a learned baseline per
entity, and it is the question signature detection misses most often (living off the land,
novel infrastructure, a credential used from a new place).

Three shapes of evidence argue for how to build it:

- **An agent that recomputes baselines by judgement does not produce a baseline.** An analyst
  agent asked to "baseline the alert stream" each day computes something different on each run,
  skips days it judges unrepresentative, and leaves a gap that nobody notices for weeks. Its
  output cannot be replayed or tested, and it baselined alert *volume per rule*, never the
  behaviour of entities.
- **A baseline learned once and frozen is poisonable and goes stale.** A host agent that learns
  for a fixed period and then stops scores anything seen a handful of times during learning as
  normal forever, has no way to forget, and silently scores a whole class of activity it never
  saw during learning as unremarkable. Its baseline lives in one local file that a crash can lose
  and nobody can audit.
- **Most behavioural telemetry is already in the lake.** Network sessions, DNS, authentication
  and IDS records arrive from many sensors and are labelled (ADR-0033). Network, DNS and
  third-party sources do not belong to any one host, so a host agent cannot see them; a host's
  own kernel view (process lineage, file writes, privilege changes) is not in any log and needs
  a host agent.

## Decision

1. **A deterministic novelty analyzer** (`homelabnext/novelty/`) computes per-entity baselines
   from lake tables. It makes no model call and has no learned state of its own: every run
   recomputes the baseline from the lake for an injected `as_of` time, so the same lake contents,
   spec and `as_of` always give the same findings, and a past run can be replayed exactly.
2. **What is learned is declared, not inferred.** A novelty spec (`schemas/platform/
   novelty_spec.schema.json`, a draft until this ADR is accepted) lists *profiles*. A profile
   names one lake table, an `entity` column, one or more `value` columns (dotted paths into the
   table's own columns, validated against its schema), optional equality filters, the timestamp
   column its windows are taken on (`time` by default), and its parameters: `learn_days`,
   `half_life_days`, `score_hours`, `min_support`, `entity_min_samples`,
   `max_values_per_entity`, `emit_at`, `max_findings` and `min_history_days` (default
   `learn_days`, at most `learn_days`). A profile is the
   question "has *this entity* had *this value* before?" (host to destination port, client to DNS
   name, user to source address).
3. **The scoring rule** is fixed and documented, so a finding can be explained by arithmetic:
   - The scoring window is `[S, as_of)` with `S = as_of - score_hours`; the learning window is
     the `learn_days` days before it, `[S - learn_days, S)`. The scoring window is never learned
     from in the same run.
   - Support `s(e, v)` is the count of (entity, value) per UTC day, each day weighted
     `0.5 ** (age_days / half_life_days)`, where `age_days` is whole UTC days from the scoring
     window's start day (`date(S) - day`), so old behaviour fades and anything seen only during
     a past window ages out instead of staying normal forever.
   - The entity total `T(e)` is the sum of the entity's support over all its values.
   - For each (entity, value) in the scoring window: if `T(e) == 0` the pair is **unlearned**
     (reported with no score, never scored 0); otherwise surprise is `0` when `s >= min_support`
     and `1 - s / min_support` below it, confidence is `min(1, T(e) / entity_min_samples)`, and
     the score is their product. A pair is a finding when its score is at least `emit_at`.
   - An entity with more than `max_values_per_entity` distinct values in the learning window is
     reported once (when it appears in the scoring window) as **high-cardinality** and not
     scored, so one noisy entity cannot flood the output or the memory of a run. One with more
     than that many distinct values in the scoring window alone is reported once as **burst**,
     with its row count there and not scored; unlike a high-cardinality entity, a burst is new
     behaviour (a scan on the scoring day, by an entity learned or not), so it is a signal. A cardinality read of each window finds
     such entities first (one row each, however many values), and the per-value reads leave
     them out, so one port scan costs a few groups, never the profile. Their own per-entity
     reads are bounded too: at most 1,000 entities, each giving at most one group per UTC day
     and label, so a set-aside read is at most `entities x (learn_days + 1) x 5` groups and fails
     the profile, visibly, only when that passes the group limit; more than 1,000 noisy entities
     also fails the profile, visibly.
   - A profile emits at most `max_findings` rows per run: findings by score (highest first),
     then bursts, high-cardinality entities and unlearned pairs, each by entity and value; the number
     dropped, by status, is reported in the run summary. No cap is silent.
   - **Cold start.** A profile's history is `min(learn_days, date(S) - oldest day)`, where the
     oldest day is the oldest its table holds in `[midnight(date(S)) - 2 * learn_days, S)`, a
     day-aligned range longer than the learning window (as the analyzer's ceiling lets it see the
     table, without the profile's filters), and 0 when the range holds nothing. The longer range
     means a sparse table whose first row predates the window, or an `as_of` that is not
     midnight, still counts its history. While the history is below `min_history_days` the
     profile is **warming**: the run writes no findings for it and its summary reports `status:
     warming`, the days of history so far and the days remaining. The history depends only on
     the lake and `as_of`, so the same run warms the same way when replayed. A table entirely
     above the analyzer's ceiling reads as empty, so a profile over it is warming for good,
     which its summary shows.
   - A finding's `time` is `S`, the start of the behaviour window it describes (its `as_of` is
     the end), so a window that holds the behaviour holds the finding.
4. **It reads through its TLP ceiling.** The analyzer is a lake reader (`analyzer:novelty`) with
   a declared ceiling in `tlp_readers`, like any other (ADR-0033 decision 6; `analyzer:` is a
   reader kind beside `profile:`, `module:`, `user:` and `group:`). It reads with a new bounded
   aggregate on `CeilingReader`, `count_by`, which groups validated columns by UTC day and label
   within a time range (or by day and label alone, for the cold-start history), applies the
   ceiling's row filter, checks each group's label again, and returns only keys, counts and
   labels; more groups than its limit is an error, never a truncated count. Struct fields and
   the UTC day are not in the portable SQL subset, so each lake adapter declares its SQL
   dialect. It needs no raw SQL and so no red grant; a profile over a table above the
   analyzer's ceiling sees only the rows its ceiling allows.

   **It writes through a table-scoped insert grant (amending ADR-0033 decision 6).** ADR-0033
   lets only a `red` reader write, and every table. An `analyzer:` entry in `tlp_readers` may
   instead carry `writes: [<table>]`: `lake-access.json` then gives that engine user, before its
   `.*` rule, `SELECT` and `INSERT` on each named table only, never `DELETE` or `UPDATE`, with
   its own row filter; no other kind may have `writes`, nor an analyzer `writes` and `write:
   true` together; `writes` names only declared analyzer-output tables (`novelty_finding`), and
   the rule is pinned to the core's namespace. The residual risk is stated, not hidden: the
   query engine applies the row filter to an insert, so it refuses a row labelled above the
   analyzer's ceiling, but it cannot see a label set lower than the row's inputs, so a correct
   label is enforced in this code (decision 5), not by the engine. It is bounded: the grant is
   `INSERT` on one table, the analyzer never receives a row above its ceiling to copy, and a
   mislabelled row could only be one of its own findings. File-based access control checks a
   table procedure (`ALTER TABLE ... EXECUTE`) only on a table whose rule carries a row filter;
   the analyzer's own-table rule does, so it cannot run one, and `lake-access.json` grants no
   `CALL` procedure to anyone. The batch ledger (the batch id and the source's mark) is a second
   write: table properties set through the REST catalog by the lake's write path, as for every
   writer (`homelabnext/lake/trino_rest.py`). The catalog credential the analyzer's writer
   holds must be scoped to `novelty_finding`; where the catalog cannot scope a credential to a
   table, that credential can set any table's properties, and that is a residual risk of the
   deployment, not something this repository can check.
5. **Findings are labelled data.** A finding's TLP label is the strictest label among the rows
   that produced it, its learning-window support included: the pair's scoring-window rows and,
   for a scored or high-cardinality row, every learning-window row of its entity, since they
   make its total and so its confidence (derived data takes its strictest input, ADR-0033).
   Findings are written to their own lake table, `novelty_finding`, idempotently: the batch id
   is a digest of the profile, the spec and `as_of`, so a re-run of the same window writes
   nothing new. The run summary (oldest day, counts, what was dropped) is derived from what the
   analyzer read and is labelled at its ceiling. A label bounds what a finding says, and so what
   its absence says: a finding labelled `green` with support 0 means no row at or below the
   analyzer's ceiling had the pair, not that none existed, and a reader of `novelty_finding` can
   infer only that much (rows above the ceiling were never read, and say nothing).
6. **Findings are advisory and say so.** Every finding row carries `source_kind: heuristic`, the
   `source` that produced it (`lake-novelty` here), the profile, entity, value, score, confidence,
   support, entity total, the windows and `as_of`. No Sigma rule, decide floor or other
   deterministic gate takes a novelty finding as its sole basis to escalate. The one path from
   novelty to escalation is `corroborate`, which groups findings by entity (its `entity_kind`
   and value, never bare text) within a time window
   and returns only entities flagged by at least two **distinct sources** (for example a host
   agent and a network profile), as candidates for the decision cascade and the analyst agents.
   Two profiles of one source are one source. `finding`, `unlearned` and `burst` rows count as
   signals; a `high_cardinality` row (the entity was too noisy to baseline) does not. Distinct sources are
   meant to be distinct writers: the table's key is `(source, uid)`; `write_findings` refuses a
   batch with a row of any source but the writer's own, a mark that is not the source's, or a
   batch id that does not start with the mark; and the lake binds a batch id to its source: a
   write that names a source replays only a batch committed under exactly that source, and one
   committed under another source or under none raises (fail closed), so no writer can suppress
   the analyzer's batch by taking its id, with or without a source. A write that names no
   source is not judged and replays as before (the dual-write queue re-sends parked batches
   that way), so a source-less writer can only drop its own rows. That binding
   holds for cooperating writers only: the engine sees one `INSERT` grant, not which `source`
   value a row carries, so a writer with the grant that bypasses `write_findings` could write
   rows under another source's name. Like the label (decision 4), it is a residual risk,
   bounded by who holds the grant.
7. **Host agents report into the same table.** A host-kernel sensor that learns its own baseline
   (process lineage, file writes, privilege changes) is a second source, not a second design:
   its findings enter the lake in the `novelty_finding` shape with its own `source` value and
   `source_kind: heuristic`, so `corroborate` sees both. It names entities in the declared shared
   namespace, `entity_kind` (`ip`, `host`, `user`, `domain`, `process`, `other`), with the same
   text a lake profile would use for that kind (an address as written, a host by its name), so
   both sources can name one entity. Such an agent runs alert-only by default;
   any enforcement it has is off unless the site turns it on explicitly in its configuration.
8. **Agents interpret; they do not compute.** An analyst agent reads `novelty_finding`, explains
   and groups findings and routes the corroborated ones. It never computes or edits a baseline.
   Alert-volume tuning stays a separate, existing job.

## Consequences

- A novelty finding can be reproduced from the lake and explained from the spec; a baseline is
  never lost with a host, and backfilling is running the analyzer with an earlier `as_of`.
- The lake must keep at least `learn_days` of each profiled table; a shorter retention silently
  shortens the baseline, so the run summary reports the oldest day it found per profile.
- A fresh, empty lake gives each profile `min_history_days` (by default `learn_days`) of silence
  while it warms. That is by design, not a gap: a baseline learned from a day of data would
  score nearly everything as new. The summary says how many days remain, so the silence is
  visible rather than mistaken for a quiet lab.
- Recomputing per run costs five grouped queries per profile per run on the query engine (the
  history, a cardinality read of each window, the learning window, the scoring window), seven
  when the cardinality reads set entities aside (their per-entity counts in both windows). Profiles
  should be few and scoped; each read is bounded like `select`.
- Late data is not re-scored for a past `as_of`: a re-run of the same window has the same batch
  id and is replayed as written, whatever arrived since. Re-scoring a window means a new spec
  (a new digest) or a later `as_of`.
- Poisoning is limited, not removed: behaviour repeated `min_support` times inside the learning
  window is normal until it decays. Shorter half-lives forget faster and alert more.
- The `novelty_finding` table, the spec schema and `count_by` are new contracts that each adapter
  and the fake lake must implement and test.
- Escalation from heuristics needs two independent sources, so a single compromised or noisy
  source cannot page anyone on its own; a real event seen by only one source stays a finding for
  an analyst, not an alert.

## Alternatives

- **Let the analyst agent keep computing baselines.** Not reproducible or testable, and it skipped
  days; rejected.
- **A learned model (clustering, autoencoders).** Harder to explain and to test than counted
  first-seen support, for little gain at homelab volume; can be revisited behind the same finding
  contract.
- **Persist the baseline as incremental state.** Cheaper per run, but state drifts from the lake,
  cannot be replayed, and is one more thing to back up; rejected while recomputation fits.
- **Write novelty into `detection_finding`.** It would mix advisory heuristics with tested
  detections and invite a deterministic consumer to escalate on one; a separate table keeps the
  boundary structural.
- **Run only a host agent.** It cannot see network, DNS or third-party sources; both are needed.
- **Write findings as a separate `red` writer principal.** It would satisfy ADR-0033 as written,
  but a writer that may insert and delete in every table, and reads everything, is a far wider
  grant than an analyzer that reads below `red` needs; the table-scoped insert grant gives it
  only the one table it writes. Rejected.
