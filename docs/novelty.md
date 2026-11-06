---
summary: 'The behavioural novelty analyzer: profiles in a spec, the scoring arithmetic, cold start, TLP labels, the novelty_finding table and corroboration.'
summary_of: outline:sha256:4cbb20ef8744cc85
---
# Behavioural novelty baselines

[ADR-0036](adr/0036-behavioural-novelty-baselines-are-deterministic-and-advisory.md) (proposed).
Detections ([detections](detections.md)) answer "does this event match a known-bad shape?".
The novelty analyzer (`homelabnext.novelty`) answers "has *this entity* had *this value*
before?": a host and a destination port, a user and a source address, a client and a DNS name.
It is deterministic, recomputes every baseline from the lake for an injected `as_of`, and its
findings are advisory: no gate escalates on one alone.

## The spec

A spec (`schemas/platform/novelty_spec.schema.json`, a draft; [example](../examples/novelty/spec.yml))
lists profiles. Each names one lake table, the `entity_kind` its entity belongs to (`ip`, `host`,
`user`, `domain`, `process`, `other`), an `entity` column path and one or more `values`
column paths (a top-level column or a dotted path into a struct, such as `src_endpoint.ip`;
scalar, not a timestamp), optional `where` equality filters (each value of its column's type) and `time_column` (default `time`),
and its parameters:

| Parameter | Meaning |
|---|---|
| `learn_days` | days of history before the scoring window that are learned from |
| `half_life_days` | the age at which a day's count weighs half |
| `score_hours` | the scoring window, `[as_of - score_hours, as_of)` |
| `min_support` | decayed support at or above which a value is normal for its entity |
| `entity_min_samples` | decayed entity total at which confidence reaches 1 |
| `max_values_per_entity` | above this many distinct values, the entity is set aside: learned values make it high-cardinality, values in the scoring window alone a burst |
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
     the entity, not scored and not a signal;
   - more than `max_values_per_entity` distinct values in the scoring window alone: one
     **burst** row for the entity with its row count there, not scored, and a signal (a scan on
     the scoring day, by an entity learned or not);
   - `T(e) == 0`: **unlearned**, reported with no score (never scored 0);
   - otherwise `surprise = 0` when `s >= min_support`, else `1 - s / min_support`;
     `confidence = min(1, T(e) / entity_min_samples)`; `score = surprise * confidence`; a
     **finding** when `score >= emit_at`.
5. At most `max_findings` rows: findings by score, then bursts, high-cardinality, unlearned; the
   rest are counted in the summary as dropped, by status.

A burst or high-cardinality row stands in for all that entity's per-value rows: it names the
entity and counts its rows, not its values (that would be the flood the bound prevents). An
analyst looks the values up in the source table, for the entity and the scoring window.

A worked case: a host spoke to port 443 twice a day on each of the four learning days and never
to port 22, with `half_life_days: 2`. Its total is `2 * (0.25 + 0.354 + 0.5 + 0.707) = 3.62`;
port 22 has support 0, so surprise 1; with `entity_min_samples: 4` confidence is `0.905`, and the
score `0.905` is a finding at any `emit_at` up to that. The tests in `tests/novelty/` hold these
cases by hand.

## Cold start

A profile's history is `min(learn_days, date(S) - oldest day)`, where the oldest day is the oldest
its table holds in `[midnight(date(S)) - 2 * learn_days, S)` (as the analyzer's ceiling lets it
see the table, without the profile's filters; 0 when it holds nothing). The range is day-aligned
and longer than the learning window, so a sparse table whose first row predates the window, or an
`as_of` that is not midnight, still counts its whole history. Below `min_history_days` the
profile is **warming**: the run writes nothing for it and the summary reports `status: warming`,
`history_days` and `days_remaining`. A fresh lake is therefore `min_history_days` (by default
`learn_days`) of silence per profile, by design: a baseline learned from one day would call
nearly everything new. A table entirely above the analyzer's ceiling reads as empty, so a profile
over it warms for good, which its summary shows.

## Reading and writing through the ceiling

The analyzer is the lake reader `analyzer:novelty`; the site declares its ceiling in
`tlp_readers` ([module selection](modules/selection.md)), and without a declaration it reads
nothing. It reads with `CeilingReader.count_by` and `CeilingReader.cardinality`
([lake README](../homelabnext/lake/README.md)), five grouped queries per profile per run: the
table's per-day history, a cardinality read of each window naming the entities with more than
`max_values_per_entity` distinct values there (a scan on the scoring day as much as a noisy
learned entity), and the learning and scoring windows without those entities; when there are
such entities, two more read their per-entity counts in both windows (seven), so one port scan
costs a few groups rather than failing the profile. A set-aside entity is reported once, with
its count in the scoring window: `high_cardinality` when it was noisy while learning, `burst`
when only the scoring window was. The set-aside reads are bounded too:
more than 1,000 noisy entities, or set-aside counts past the group limit (at most `entities x
(learn_days + 1) x 5` groups: one per entity, UTC day and label), fail the profile visibly
rather than truncate it. Every read has the ceiling's row filter
in the query and checks every group's label again. More groups than the limit (`run`'s
`limit`, 100,000 groups by default, against `count_by`'s own default of 10,000) fails that
profile (`status: failed`), never a truncated baseline; the other profiles still run.

Writing needs the entry's `writes: [novelty_finding]` (ADR-0036 amends ADR-0033 decision 6):
`SELECT` and `INSERT` on that table only, in the core's namespace, at the analyzer's ceiling. The
engine applies the row filter to an insert, so it refuses a row labelled above the ceiling; it
cannot see a label set lower than the row's inputs, so this code sets it (below), and the analyzer
never reads a row above its ceiling. The analyzer's catalog credential, which records the batch
ledger as table properties, should be scoped to `novelty_finding`; where the catalog cannot scope
it, that is a residual risk of the deployment. A failed write fails that profile only. `examples/novelty/site.yml` declares it.

## Findings

Rows go to the lake table `novelty_finding` (`schemas/ocsf/novelty_finding.v1.json`, a draft):
`source` (`lake-novelty`), `source_kind: heuristic`, `profile`, `entity_kind` (the profile's:
`ip`, `host`, `user`, `domain`, `process` or `other`), `entity`, `value`, `status`, `score` and
`confidence` (findings only), `support`, `entity_total`, `count`, the windows, `as_of`, the
profile's `spec_digest`, a `message` and `reasons` with the arithmetic. A row's `time` is the
start of the scoring window, the behaviour it describes. Its `tlp` is the strictest label among
the rows that produced it: the pair's scoring rows and, for a scored, burst or high-cardinality row,
every learning row of its entity. The label also bounds what a row says: support 0 on a `green`
finding means no row at or below the analyzer's ceiling had the pair, not that none existed. The
run summary is labelled at the analyzer's ceiling (`tlp`).

The table's key is `(source, uid)`. The `uid` is a digest of the source, the profile, `as_of`,
status, entity kind, entity and value, and each profile's write is one batch whose id digests the
profile, the spec and `as_of`, so re-running a window writes nothing new (late data included:
re-scoring a window needs a new spec or a later `as_of`), and backfilling is running with an
earlier `as_of`. The batch id is `<source>/<profile>:<digest>`, its writer's source mark
followed by the digest. `write_findings` refuses a batch with a row of any source but the
writer's own, a foreign mark, or a batch id that does not start with the mark, and the lake
refuses a batch id another source committed, so cooperating writers are bound to their sources.
The engine cannot see which `source` an inserted row names, so a writer that bypasses
`write_findings` could still write under another name: distinct sources are distinct writers by
convention, which ADR-0036 states as a residual risk.

A host-kernel sensor that learns its own baseline writes the same shape with its own `source`,
naming entities in the same `entity_kind` namespace.

## Corroboration

`corroborate` is the one path from novelty to escalation: it groups `finding` and `unlearned`
rows by `(entity_kind, entity)` within a window and returns only the entities flagged by at least
two distinct sources, with the strictest label of the rows behind each. Two profiles of one
source are one source, and an address and a host of the same text are two entities.

## Command line

```bash
hnx novelty run --spec examples/novelty/spec.yml --site examples/novelty/site.yml \
  --fixture examples/novelty/lake.yml --as-of 2026-03-11T00:00:00Z --dry-run --show-findings
hnx novelty corroborate --since 2026-03-10T00:00:00Z --until 2026-03-11T00:00:00Z \
  --site lab/modules.yml --domain example.internal --warehouse lab
```

`--site` is the lab's module selection, or a file with its `tlp_readers` and `lake_catalog`, held
to the selection's schema and the access rules' own refusals. `--fixture` loads a YAML or JSON
mapping of table name to rows into the in-memory fake lake (`examples/novelty/lake.yml`: the first
command above finds a new port, a new host and a new sign-in source); `--domain`, `--namespace`
and `--warehouse` reach the lab's `lake-query` and `lake-catalog` endpoints, signing in as
`analyzer:novelty`. The analyzer's insert grant is pinned to the core's `ocsf` namespace, so with
any other `--namespace` its writes are refused by design (a dry run still reads). `--as-of` is
required (there is no clock). The run prints a JSON summary;
exit 1 when a profile failed, 2 on a usage, spec, site or lake error.
