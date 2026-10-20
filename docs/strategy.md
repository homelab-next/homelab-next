<!-- SPDX-License-Identifier: Apache-2.0 -->
# Strategy to task

A lab that runs itself needs to say what it is for, how it knows it is getting there, and what it
needs to know to decide. This layer writes that down as records, measures it from what the lab
already observes, and turns gaps into questions. It grew out of intelligence practice (the
commander's critical information requirements, the objective cascade, collection management) but
nothing in it is about intelligence: the same records serve an availability team, a security
team or a home lab of one. ADR-0015 records the decision; [the generated index](strategy/README.md)
([[strategy/README|strategy index]]) shows the example tree.

```
examples/strategy/
  strategy.md                  the one strategy record (mission, intent, end state, ...)
  doctrine.yml                 the measurement doctrine: which rules apply, how hard
  objectives/SO-001.md ...     the cascade: SO -> OO -> TO -> TT
  measures/MOE-001.md ...      MOPs and MOEs (readings: value events in MOE-001.events/)
  requirements/CCIR-001.md ... CCIR, FFIR, PIR
  rfis/RFI-001.md ...          requests for information
```

```
hnx strategy check [ROOT]                 validate: schemas, links, lifecycle, reviews, doctrine
hnx strategy links [ROOT] [--check]       regenerate / check the records' Links blocks
hnx strategy measure [ROOT] --results F --state F --records DIR [--now T] [--dry-run]
hnx strategy rollup [ROOT] [--now T]      the cascade, graded from the recorded readings
hnx strategy rfis [ROOT] [--today D]      open RFIs by triage, expiring soon, uncovered gaps
hnx strategy rfis [ROOT] --raise --records DIR --as profile:NAME     file RFIs for the gaps
hnx strategy rfis [ROOT] --sweep --records DIR --as human:NAME [--today D]   LTIOV expiry
hnx strategy decide [ROOT] RECORDS --as human:NAME [--dry-run]       apply the intents
hnx strategy index [ROOT] [--out docs/strategy/README.md] [--check]
hnx status serve --strategy examples/strategy                        the hub pages
```

`make strategy` (part of `make check`) runs `check`, `links --check` and `index --check` on the
example tree.

## The model

**Strategy.** One record, `strategy.md` (`type: strategy`): the **mission**, the **intent** and
the **end state** as prose sections; **priorities** of work (ranked; a priority is not a weight of
effort), **assumptions**, and **constraints**, each a `{rule, owner}` so a hard rule always has
someone who answers for it.

**Objectives.** The cascade below the strategy, one file per objective:

| level | is | parent |
|---|---|---|
| **SO** strategic objective | an enduring end state | none (it hangs from the strategy) |
| **OO** operational objective | a decomposition of an SO | an SO |
| **TO** tactical objective | a concrete, assignable piece of work | an OO |
| **TT** tactical task | a step of a TO | a TO |

Each has an `owner` and `measures`. `supplemental: true` marks an objective proposed beyond the
baseline cascade (it still states its parent; see the doctrine).

**Measures.** A **MOP** (measure of performance) asks *are we doing the work?*; a **MOE**
(measure of effectiveness) asks *is it working?* Every measure carries the seven doctrine fields:

| field | where |
|---|---|
| `id` | MOP-NNN / MOE-NNN |
| `objective` | the objective it measures (which lists it back under `measures`) |
| `definition` | the `## Definition` section: what is counted, over what population |
| `source` | a typed binding (below) |
| value + time | the readings: `value` events in the sidecar, never in the record |
| `target` | `{op: '>=' \| '<=' \| '==', green: N, amber: N}` |
| `confidence` + `thinness` | `high \| moderate \| low`, and `{min_sample, max_age_h}` |

plus `kind` (`activity`, `output`, `outcome`), `unit`, `measured_by` and `definition_version`.

**Requirements** is the parent category, and each record is exactly one of three types:

| type | what the lab needs to know | serves |
|---|---|---|
| **CCIR** | what the owner needs to know to decide | nothing |
| **FFIR** | what the rest of the lab needs to know about itself: readiness and posture | CCIRs |
| **PIR** | what we need to know about the environment or the adversary | CCIRs or FFIRs |

A requirement record holds the question (`## Question`), the decision it supports
(`## Decision supported`), the `consumer`, its `cadence` (an ISO 8601 duration, `continuous` or
`on-change`), its LTIOV (`ltiov`: the last time the information is of value, a date or
`standing`), the specific information requirements (`sirs`), `indicators`, collection `sources`,
`tasked_to`, the `## Acceptance` criteria and `## Guardrails`, and the objectives it `supports`.

**RFIs.** A request for information: a question raised by a gap (`raised_by` a measure or a
requirement), **triaged** into a **collection** requirement (CR: the answer needs data the lab
does not hold) or a **production** requirement (PR: the lab holds the data and owes the answer),
with an LTIOV. Closing it is an answer, an **expiry** (the LTIOV passed) or a **no-find**: a no-find
is a valid closed outcome, because the search and its window are the answer.

## Link rules (enforced)

| from | field | may name |
|---|---|---|
| CCIR, FFIR, PIR | `supports` (required, one or more) | SO, OO, TO |
| FFIR | `serves` | CCIR |
| PIR | `serves` | CCIR, FFIR |
| CCIR | `serves` | nothing |
| OO / TO / TT | `parent` | SO / OO / TO |
| measure | `objective` | the objective whose `measures` lists it |
| RFI | `raised_by` | a measure or a requirement |

Nothing else: a CCIR never links to a PIR, a requirement never supports a TT, the `serves` graph
has no cycle, every name exists (a tombstoned id is reported as retired), and an active record
never supports or hangs from a closed one. Link targets are allocated ids, never `XX-NEW`.

## Records, reviews and ids: the registers' machinery

Every record is one Markdown file exactly like a lesson ([registers](registers.md),
[[registers]]): front-matter fields, `## Heading` prose sections, a generated `## Links` block of
wiki-links (Parent, Objective, Measured by, Supports, Serves, Raised by), and a sidecar
`<ID>.events/` of append-only events (ADR-0014):

* `review` events, the shared review model: `examples/review-policy.yml` has an entry per kind
  and state (`strategy`, `objective`, `measure`, `requirement`, `rfi`). An active objective,
  measure or requirement needs an agent check and a challenge; the strategy and an achieved or
  retired objective also a human approve; an RFI needs nothing (a question is never blocked).
* `value` events, a measure's readings (below). A reading is not content: recording one never
  makes a review stale.
* `transition` events, written only by the decider: the status of a record changes by intent.

Ids are `SO-NEW`, `PIR-NEW`, `RFI-NEW` ... until `hnx ids resolve` allocates them at merge time;
the four directories are registers of `homelabnext.registers.ids`, so `check-dupes`, `check-lost`
and `check-placeholders` guard them like lessons. `hnx reviews digest FILE` prints the digest a
review must carry.

Lifecycles: an objective is `active` -> `achieved` | `retired`; a measure `active` -> `retired`; a
requirement `active` -> `answered` | `expired` | `retired`; an RFI `open` -> `answered` |
`expired` | `no-find`. A closed record keeps its file (its id is cited), carries the transition's
`resolution`, and is inactive to the graph and its queries.

## The doctrine policy

`doctrine.yml` (`schemas/strategy/doctrine.schema.json`) lists the rules a program can decide,
each with `enforce: error | warn | 'off'` (quote `'off'`: YAML 1.1 reads a bare `off` as false).
A rule the file omits takes its default; another discipline writes only what it changes. The
defaults follow a nine-rule MOE/MOP doctrine:

| rule | default | what it does |
|---|---|---|
| `trend_same_definition` | error | a trend is drawn only between readings of one definition digest; across a change it is a re-baseline |
| `no_silent_redefinition` | error | changing `definition`, `source` or `unit` without bumping `definition_version` fails (ids never renumber: `check-lost`) |
| `self_measured_moe_cap` | error, `cap: amber` | a MOE measured manually, not at all, or by its objective's owner is amber at best |
| `activity_never_moe` | error, `kinds: [activity]` | an activity count is a MOP, never a MOE |
| `moe_per_objective` | error, `min: 1`, all levels | every objective has a MOE (narrow `levels` to roll MOEs up at OO/SO only) |
| `measures_per_owner` | off (`max: 8`) | the retired per-owner ceiling, kept switchable |
| `cold_start_baseline` | error, `readings: 1` | the first reading on a definition is a baseline, not a grade |
| `not_measurable_is_finding` | error | `source: none` needs a `## Not measurable` section; a reading without a value carries a finding |
| `never_fabricate` | error | a not-measurable measure has no values; every reading names its evidence |
| `baseline_so` | error, `types: [PIR, FFIR]`, `exactly: 1` | each such requirement supports exactly one baseline (non-supplemental) SO, and no baseline SO is shared between two of them, so their measures roll up apart |
| `so_supported` | warn | an active SO that no active requirement supports is an orphan |

What needs judgment is listed under `judgment:` in the file for the reviewers (check, challenge,
approve): completeness measures windowed on write time with backfills reported apart; "print the
predicate" when a changed predicate claims a null effect; a supplemental objective being additive
rather than a re-labelled baseline; a MOE that is really an effect and not a disguised count.

## How measures bind

`source` names where a value comes from:

| binding | reads | value | time |
|---|---|---|---|
| `invariant:<id>` | the invariants results (`hnx invariants run --out`) | 1 pass, 0 fail (error, skip or missing: a finding) | `checked_at` |
| `status:<source>[/<item>]` | the status hub's state (`hnx status collect`) | the item's value (else 1 ok, 0 not); without an item the share of the source's items that are ok | `observed_at` |
| `records:<lane>[?type=<t>]` | a records tree (`homelabnext.records`) | the number of notes in the lane | now |
| `manual` | nothing: a person writes the `value` event, with `evidence` | | |
| `none` | not measurable: the `## Not measurable` section is the finding | | |

`hnx strategy measure` reads every bound measure and appends one `value` event per new reading
(`value` or `finding`, `observed_at`, `sample`, `definition_digest`, `definition_version`,
`evidence`); the same data under the same definition again adds nothing. Grades are computed
on read: green, amber or red against the target; `baseline` (cold start, or a reading under an
older definition); `unmeasured` (a finding); `pending` (never read). A reading is **thin** when
fewer than `min_sample` data points stand behind it or it is older than `max_age_h`, and its
confidence is then reported low. The **rollup** grades an objective as the worst of its MOEs and
its child objectives (its MOPs when none of those has a grade), so a red MOP shows where the work
is behind while the effect still says whether it works; a finding rolls up red.

## RFIs from gaps

```
red / not-measurable measure, unmet requirement      (hnx strategy rfis: the gaps)
        |  --raise: a strategy-rfi note in the records inbox, triage suggested
        v
hnx strategy decide  -> rfis/RFI-NEW-<slug>.md (open, triage, LTIOV)   [hnx ids resolve numbers it]
        |  answered / no-find: a strategy-transition note (reason = the answer or the search)
        |  expired: hnx strategy rfis --sweep (an intent per RFI past its LTIOV, decided at once)
        v
closed RFI (resolution recorded; history kept)
```

A finding (no data) is suggested as a **collection** requirement, a red grade (data, no answer)
as a **production** requirement; an agent may file a different triage. A requirement is unmet when
an objective it supports rolls up red or its dated LTIOV has passed. A gap already covered by an
open RFI or a pending intent is not raised twice. `strategy-rfi` and `strategy-transition` notes
(`schemas/records/note.schema.json` 1.3) are decided by `hnx strategy decide`, the registers'
decider over the strategy tree: `from` must be current, `to` reachable in the lifecycle, the
review tiers of the target met by current reviews of the prospective content (else the note waits
in the inbox), and an applied transition writes its event before the note moves, so a crash is
finished on the next run, never decided twice. The sweep's own identity is `profile:ltiov-sweep`;
the RFI default LTIOV is `rfi_default_ltiov_days` (30) after the intent.

## The graph and the hub

The knowledge graph ([[graph]]) has `strategy:`, `objective:`, `measure:`, `req:` and `rfi:`
nodes and the edges `supports`, `serves`, `child_of`, `measured_by`, `binds` (to `inv:` and
`status:` nodes), `raised_by` and `tasked_to` (to a profile or human the keyring defines). Closed
records are inactive in its queries.

The status hub ([[status]]) serves four pages with `hnx status serve --strategy DIR`, listed in
`examples/status/views.yml` as page panels: **Strategy** (mission, intent, priorities,
constraints), **Requirements** (a board of three columns, CCIR / FFIR / PIR, each card with what it
supports and serves, its cadence, LTIOV and state), **Objectives** (the SO -> OO -> TO -> TT tree
with each node's rollup and each MOP/MOE's grade, value and time) and **RFIs** (open by triage,
expiring soon, closed). They are server-rendered without script, escaped, under the hub's CSP, and
read only the record files: a page never runs a measurement.

## Where a lab keeps its real strategy

The public repository ships the model, the schemas, the doctrine defaults and a fictional example
(ADR-0011). A lab's real mission, objectives and requirements are private: keep them in a private
repository or vault directory with the same layout (`strategy.md`, `doctrine.yml` and the four
record directories), with its `review-policy.yml`, `invariants.yml` and `services.yml` in the same
directory or beside it, and point every command at it: `hnx strategy check ../lab-private/strategy`,
`hnx status serve --strategy ../lab-private/strategy`. The loader, the rules and the pages are
the same code; only the path differs.
