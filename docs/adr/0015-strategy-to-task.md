---
summary: 'A strategy, its objective cascade, measures and requirements are register records measured from what the lab observes.'
---
# ADR-0015: Strategy to task: a strategy, its objectives, measures and requirements as records

- **Status:** proposed
- **Date:** 2026-10-20
- **Amended:** 2026-10-21 by ADR-0019 (see the amendment at the end of Decision)
- **Related:** ADR-0010, ADR-0011, ADR-0013, ADR-0014, `docs/strategy.md`, `homelabnext/strategy/`,
  `schemas/strategy/`

## Context

The lab measures a great deal (invariants, status sources, the records lanes) but nothing says
what the measurements are for: which outcome a red invariant threatens, which decision a question
serves, or when a question stops being worth answering. Operators who run a lab like a staff work
from a strategy (mission, intent, priorities, constraints), an objective cascade measured by
measures of performance and effectiveness, and information requirements of three kinds (what the
owner, the lab and the analysts need to know), with requests for information that expire. Kept as
prose, that layer drifts: measures are redefined silently, activity counts pose as outcomes, an
objective has no measure of effect, and a question nobody can answer stays open forever.

## Decision

1. A strategy is **records**: one `strategy.md`, and one Markdown file per objective (SO, OO, TO,
   TT), measure (MOP, MOE), requirement (CCIR, FFIR, PIR) and RFI, in four directories. They use
   the registers' machinery unchanged in kind: front-matter and sections, a generated Links block,
   sidecar events (reviews, readings, transitions), `XX-NEW` ids allocated at merge and guarded by
   `check-lost`, review tiers from the review policy, and intents applied by a decider (ADR-0014).
2. **Requirements** is the parent category with exactly three types: CCIR, FFIR and PIR. Every
   requirement supports one or more SO, OO or TO; an FFIR may serve CCIRs; a PIR may serve CCIRs
   or FFIRs; nothing else links, and the serves graph has no cycle. Objective parents go one level
   up (OO -> SO, TO -> OO, TT -> TO); an SO hangs from the strategy.
3. A **measure binds** to where its value comes from (`invariant:`, `status:`, `records:`,
   `manual`, `none`). `hnx strategy measure` records each new reading as an append-only `value`
   event carrying the definition digest it was taken under, so trends exist and never cross a
   redefinition. Grades (green, amber, red, baseline, unmeasured, pending) and the rollup are
   computed on read.
4. The **doctrine is data**: `doctrine.yml` lists every rule a program can decide with
   `enforce: error | warn | off`, defaulting to a nine-rule MOE/MOP doctrine; rules that need
   judgment are listed for reviewers. Another discipline tunes the file, not the code.
5. **Gaps raise RFIs** through the records inbox (`strategy-rfi` intents), triaged into collection
   or production, with an LTIOV; closing one is a `strategy-transition` intent (answered,
   no-find) or the LTIOV sweep (expired). A no-find is a valid outcome.
6. The graph gains the records and their typed edges; the status hub gains four read-only pages
   (Strategy, Requirements, Objectives, RFIs) served from the record files.
7. The public repository ships the model, the schemas, the doctrine defaults and a fictional
   example; a lab's real strategy lives in a private repository and loads through the same code
   with a path (ADR-0011).

### Amendment (2026-10-21): ADR-0019 supersedes the numbering

Decision 1's "`XX-NEW` ids allocated at merge" and the consequence "link targets must be
allocated ids" are superseded by [ADR-0019](0019-record-uids-computed-numbers.md): every
strategy record is identified by a UUIDv7 created with it and lives in `<type-dir>/<uid>.md`;
nothing is allocated at merge, a new objective and a record citing it arrive in one pull
request, and the number a record is shown with (`OO 1.2`) is computed from its type, parent and
order. `check-lost` still guards the directories, keyed by uid. The rest of this ADR stands; the
text above is kept as it was decided.

## Consequences

- What a measurement is for is written down and checked: an MOE that is an activity count, an
  objective with no MOE, a silent redefinition or a blank "not measurable" fails `make check`.
- Measures reuse what already runs (invariants, the hub, the records); nothing new is collected.
- Readings accumulate as small event files; the pages and the rollup read them on every request.
- Link targets must be allocated ids, so a new objective and a record citing it arrive in two
  steps, or the maintainer allocates both before merging.
- The review policy gains five artefact kinds; a private policy must list them (fail closed).

## Alternatives

- **Prose documents** (one strategy page with tables): readable, but nothing checks the links,
  the doctrine or the measures, which is exactly where the drift happens.
- **A separate store** (a database of objectives and measures): queryable, but a second write path
  beside the registers', invisible to git review and to Obsidian, and another service to run.
- **Hard-coded doctrine**: simpler, but it makes the code about one discipline's rules; the
  maintainer's rules are the defaults, and another team changes a file, not the program.
