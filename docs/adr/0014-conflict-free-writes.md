---
summary: Machine state is append-only sidecar events and status changes are intents a decider applies, so writes never conflict.
---
# ADR-0014: Conflict-free writes: append-only events, derived state, intents and a decider

- **Status:** proposed
- **Date:** 2026-10-20
- **Amended:** 2026-10-21 by ADR-0019 (see the amendment at the end of Decision)
- **Related:** ADR-0010, `docs/registers.md`, `homelabnext/registers/events.py`,
  `homelabnext/registers/transitions.py`, `schemas/registers/register_event.schema.json`

## Context

One file per record removed most collisions between authors of lessons and runbooks, but the
state that machines mutate still lived inside the human-authored record: the `reviews:` list
several agents append to, the `recurrences` counter, verification stamps and lifecycle status
changes. Two agents, or an agent and a person editing the same file in an editor, could still
write one file at the same time; the result is a merge conflict at best and a silently dropped
review at worst. Agents are optional in this project, so the fix must not depend on a service
being up.

## Decision

1. Machine-mutated state is **append-only events, one file per event**, in a sidecar directory
   beside the record (`lessons/LL-005.events/`, `docs/systems/dns.events/`), named
   `<UTC stamp>-<event>-<actor>[-<n>].yml` and created exclusively (a hard link that fails when
   the name exists), so two writers never write the same file and nothing is overwritten.
   Kinds: `review`, `recurrence`, `verified`, `transition`; schema
   `schemas/registers/register_event.schema.json`.
2. **Derived fields are computed on load**, never edited: `reviews`, `recurrences`,
   `last_verified` and the current status (base status plus applied transitions).
   `load_register` returns the same document shape as before, so every consumer is unchanged.
   The record file keeps only prose and stable fields.
3. **Status changes are intents.** An agent files a `register-transition` note through the
   records library (the inbox is its only lane). A decider (`hnx registers decide`, a library
   too) applies it under a lock when the `from` status is still current and the review policy's
   tiers for the target are met by current reviews of the prospective content; otherwise it
   denies (stale `from`, invalid target) or leaves it waiting (missing reviews, for example a
   human approve). Only the decider writes `transition` events.
4. **One write path validates before writing**: `write_record`, `write_event`, `write_events`
   and `write_register` apply the build's fatal rules to the register as it will be, then write
   atomically (temp file and rename, or exclusive create). The build, the pre-commit hooks and
   CI keep validating.
5. Scratch output of a run goes to `runs/<run_id>/` (`homelabnext.runs.run_dir`) or `build/`;
   `tools/run_output_lint.py` holds the repository's scripts to it.

### Amendment (2026-10-21): sidecars are named for the record's uid

Since [ADR-0019](0019-record-uids-computed-numbers.md) a record is `<uid>.md` and its sidecar
`<uid>.events/` (decision 1's example `lessons/LL-005.events/` is now
`lessons/<uid>.events/`); intents name a record by its uid, and a legacy code resolves through
the tree's `aliases.yml` with a deprecation warning. The events, derived state, intents and the
decider are unchanged; the text above is kept as it was decided.

## Consequences

- Concurrent reviewers, agents recording recurrences and a person editing prose touch disjoint
  files; git merges them without conflicts.
- History is kept: who reviewed what digest, when a transition was applied and which intent asked
  for it.
- The loader reads more files; directories stay small (a handful of events per record).
- Writers must use the library or write a correct event file by hand; a malformed or misnamed
  event fails the build like a malformed record.
- `hnx registers events migrate` converts existing inline state losslessly (proved by deep
  equality of the loaded document).

## Alternatives

- **A required broker or database service** that serializes all writes: correct, but it makes
  every edit depend on a running service in a project where agents and services are optional,
  and it hides the state from git review and from a person with an editor.
- **File locks on the record**: do not survive git (two clones never share a lock) and do not
  help an editor that does not take them.
- **Keep inline lists and resolve merge conflicts**: the status quo; review entries were lost or
  hand-merged, and a counter cannot be merged by line.
