---
summary: 'The behavioural novelty analyzer: profiles in a spec, the scoring arithmetic, cold start, TLP labels, the novelty_finding table and corroboration.'
summary_of: outline:sha256:5137753838336993
---
# Behavioural novelty baselines

[ADR-0035](adr/0035-behavioural-novelty-baselines-are-deterministic-and-advisory.md) (proposed).
Detections ([detections](detections.md)) answer "does this event match a known-bad shape?".
The novelty analyzer (`homelabnext.novelty`) answers "has *this entity* had *this value*
before?": a host and a destination port, a user and a source address, a client and a DNS name.
It is deterministic, recomputes every baseline from the lake for an injected `as_of`, and its
findings are advisory: no gate escalates on one alone.

## The spec

A spec (`schemas/platform/novelty_spec.schema.json`, a draft; [example](../examples/novelty/spec.yml))
lists profiles. Each names one lake table, an `entity` column path and one or more `values`
column paths (a top-level column or a dotted path into a struct, such as `src_endpoint.ip`;
scalar, not a timestamp), optional `where` equality filters and `time_column` (default `time`),
and its parameters:

| Parameter | Meaning |
|---|---|
| `learn_days` | days of history before the scoring window that are learned from |
| `half_life_days` | the age at which a day's count weighs half |
| `score_hours` | the scoring window, `[as_of - score_hours, as_of)` |
| `min_support` | decayed support at or above which a value is normal for its entity |
| `entity_min_samples` | decayed entity total at which confidence reaches 1 |
| `max_values_per_entity` | above this many distinct learned values, the entity is high-cardinality |
| `emit_at` | the score at or above which a pair is a finding |
| `max_findings` | the most rows the profile emits per run |
| `min_history_days` | days of history before the profile scores at all (default `learn_days`) |

`hnx novelty run` checks the spec against the lake's table schemas before reading anything: an
unknown table, a path that is not a scalar column, an entity that is also a value, a duplicate
profile id or `min_history_days > learn_days` refuses the whole spec.

## The arithmetic

With `S = as_of - score_hours`:

1. The learning window is `[S - learn_days, S)`; the scoring window `[S, as_of)` is never
   learned from in the same run.
2. A UTC day's age is `date(S) - day` in whole days; its weight is
   `0.5 ** (age / half_life_days)`.
3. Support `s(e, v)` is the weighted count of (entity, value) in the learning window; the entity
   total `T(e)` is the sum of its support over all its values.
4. For each (entity, value) in the scoring window:
   - more than `max_values_per_entity` distinct learned values: one **high_cardinality** row for
     the entity, not scored;
   - `T(e) == 0`: **unlearned**, reported with no score (never scored 0);
   - otherwise `surprise = 0` when `s >= min_support`, else `1 - s / min_support`;
     `confidence = min(1, T(e) / entity_min_samples)`; `score = surprise * confidence`; a
     **finding** when `score >= emit_at`.
5. At most `max_findings` rows: findings by score, then high-cardinality, then unlearned; the
   rest are counted in the summary as dropped, by status.

A worked case: a host spoke to port 443 twice a day on each of the four learning days and never
to port 22, with `half_life_days: 2`. Its total is `2 * (0.25 + 0.354 + 0.5 + 0.707) = 3.62`;
port 22 has support 0, so surprise 1; with `entity_min_samples: 4` confidence is `0.905`, and the
score `0.905` is a finding at any `emit_at` up to that. The tests in `tests/novelty/` hold these
cases by hand.

## Cold start

A profile's history is `date(S) - oldest day` its table holds in the learning window (as the
analyzer's ceiling lets it see the table, without the profile's filters; 0 when it holds
nothing). Below `min_history_days` the profile is **warming**: the run writes nothing for it and
the summary reports `status: warming`, `history_days` and `days_remaining`. A fresh lake is
therefore `min_history_days` (by default `learn_days`) of silence per profile, by design: a
baseline learned from one day would call nearly everything new.

## Reading through the ceiling

The analyzer is the lake reader `analyzer:novelty`; the site declares its ceiling in
`tlp_readers` ([module selection](modules/selection.md)), and without a declaration it reads
nothing. It reads with `CeilingReader.count_by` ([lake README](../homelabnext/lake/README.md)):
three grouped queries per profile per run (the learning window, the scoring window, and the
table's per-day history), each with the ceiling's row filter in the query and every group's label
checked again. More groups than the limit fails that profile (`status: failed`), never a
truncated baseline; the other profiles still run.

## Findings

Rows go to the lake table `novelty_finding` (`schemas/ocsf/novelty_finding.v1.json`, a draft):
`source` (`lake-novelty`), `source_kind: heuristic`, `profile`, `entity`, `value`, `status`,
`score`, `confidence`, `support`, `entity_total`, `count`, the windows, `as_of`, the profile's
`spec_digest`, a `message` and `reasons` with the arithmetic. A row's `tlp` is the strictest label
among the rows that produced it: the pair's scoring rows and, for a scored or high-cardinality
row, every learning row of its entity. The `uid` is a digest of the source, the profile, `as_of`,
status, entity and value, and each profile's write is one batch whose id digests the profile, the
spec and `as_of`, so re-running a window writes nothing new and backfilling is running with an
earlier `as_of`.

A host-kernel sensor that learns its own baseline writes the same shape with its own `source`.

## Corroboration

`corroborate` is the one path from novelty to escalation: it groups `finding` and `unlearned`
rows by entity within a window and returns only the entities flagged by at least two distinct
sources, with the strictest label of the rows behind each. Two profiles of one source are one
source.

## Command line

```bash
hnx novelty run --spec examples/novelty/spec.yml --as-of 2026-03-29T00:00:00Z \
  --site lab/modules.yml --fixture rows.yml --dry-run --show-findings
hnx novelty corroborate --since 2026-03-28T00:00:00Z --until 2026-03-29T00:00:00Z \
  --site lab/modules.yml --domain example.internal --warehouse lab
```

`--fixture` loads a YAML or JSON mapping of table name to rows into the in-memory fake lake;
`--domain`, `--namespace` and `--warehouse` reach the lab's `lake-query` and `lake-catalog`
endpoints, signing in as `analyzer:novelty`. `--as-of` is required (there is no clock). The run
prints a JSON summary; exit 1 when a profile failed, 2 on a usage, spec, site or lake error.
