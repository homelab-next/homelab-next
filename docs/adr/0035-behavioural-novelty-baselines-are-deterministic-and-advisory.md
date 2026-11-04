---
summary: A deterministic analyzer learns per-entity first-seen baselines from the lake over a decaying window; its findings are heuristic and never escalate alone.
summary_of: outline:sha256:bb26e3bb40508401
---
# ADR-0035: Behavioural novelty baselines are deterministic, recomputed from the lake, and advisory

- **Status:** proposed
- **Date:** 2026-11-04
- **Related:** ADR-0006 (detections in a Sigma subset); ADR-0013 and ADR-0033 (the lake, TLP
  labels and reader ceilings); ADR-0030 (agents act only through the broker);
  [decide](../decide.md) (the decision cascade); [log pipeline](../log-pipeline.md);
  [lake README](../../homelabnext/lake/README.md)
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
     scored, so one noisy entity cannot flood the output or the memory of a run.
   - A profile emits at most `max_findings` rows per run: findings by score (highest first),
     then high-cardinality entities, then unlearned pairs, each by entity and value; the number
     dropped, by status, is reported in the run summary. No cap is silent.
   - **Cold start.** A profile's history is the number of UTC days from the oldest day its table
     holds within the learning window (as the analyzer's ceiling lets it see the table, without
     the profile's filters) to the scoring window's start day, `date(S) - oldest day`, and 0
     when the window holds nothing. While the history is below `min_history_days` the profile is
     **warming**: the run writes no findings for it and its summary reports `status: warming`,
     the days of history so far and the days remaining. The history depends only on the lake
     and `as_of`, so the same run warms the same way when replayed.
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
5. **Findings are labelled data.** A finding's TLP label is the strictest label among the rows
   that produced it, its learning-window support included: the pair's scoring-window rows and,
   for a scored or high-cardinality row, every learning-window row of its entity, since they
   make its total and so its confidence (derived data takes its strictest input, ADR-0033). Findings are written to their own lake table, `novelty_finding`, idempotently:
   the batch id is a digest of the profile, the spec and `as_of`, so a re-run of the same window
   writes nothing new.
6. **Findings are advisory and say so.** Every finding row carries `source_kind: heuristic`, the
   `source` that produced it (`lake-novelty` here), the profile, entity, value, score, confidence,
   support, entity total, the windows and `as_of`. No Sigma rule, decide floor or other
   deterministic gate takes a novelty finding as its sole basis to escalate. The one path from
   novelty to escalation is `corroborate`, which groups findings by entity within a time window
   and returns only entities flagged by at least two **distinct sources** (for example a host
   agent and a network profile), as candidates for the decision cascade and the analyst agents.
   Two profiles of one source are one source. `finding` and `unlearned` rows count as signals;
   a `high_cardinality` row (the entity cannot be baselined) does not.
7. **Host agents report into the same table.** A host-kernel sensor that learns its own baseline
   (process lineage, file writes, privilege changes) is a second source, not a second design:
   its findings enter the lake in the `novelty_finding` shape with its own `source` value and
   `source_kind: heuristic`, so `corroborate` sees both. Such an agent runs alert-only by default;
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
- Writing `novelty_finding` is a write to the lake: where the query engine's access rules
  (`lake-access.json`) give `INSERT` only to a writer declared `red`, the analyzer reads at its
  own ceiling and writes through the lake's write path under a writer identity of its own.
- Recomputing per run costs one grouped query per profile per run on the query engine. Profiles
  should be few and scoped; `count_by` is bounded like `select`.
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
