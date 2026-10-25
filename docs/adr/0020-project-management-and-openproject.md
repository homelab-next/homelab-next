---
summary: 'Project management is a capability with board rules as MUSTs; OpenProject mirrors strategy one way and the repo wins.'
---
# ADR-0020: Make project management a capability, with OpenProject as its first product

- **Status:** proposed
- **Date:** 2026-10-21
- **Related:** ADR-0005, ADR-0011, ADR-0014, ADR-0015, ADR-0019 (record uids, computed numbers),
  `docs/projects.md`, `conformance/protocols/projects.py`, `schemas/events/project.changed.schema.json`

## Context

Work in a lab is tracked on a board that is really project management: projects with an ordered
list of steps, step cards as the work queue, one-off tasks, and rules a generator enforces
(unique project ids, a step card must point at an open step, a project whose steps are all done
must close). That board is a file format plus a script, so nothing but the script can use it,
and the rules exist only there. Labs that outgrow it want a real project tool (OpenProject is
the first candidate), and they want projects to link to the strategy records of ADR-0015 (the
objective a step supports, the RFI a task answers) so that the strategy pages can show the work
behind an objective. OpenProject cannot be configured through its API (types, statuses and custom
fields are admin-UI only), its webhooks are lossy, and anything mirrored into it can be edited by
people who should not be the source of truth for strategy.

## Decision

1. Project management is a capability, `projects` (the sixteenth), with a contract
   (`conformance/protocols/projects.py`), a conformance suite whose MUSTs include the board rules,
   idempotent create by external key, optimistic concurrency, a complete change feed and link
   integrity, a built-in fake and mutants each caught by its check.
2. Items are identified by a UUIDv7 `uid`; display numbers are computed, never stored. Links
   name uids, never display numbers, both to other items and to strategy records; uids come from
   `homelabnext.identity`.
3. The reference implementation keeps one Markdown file per item and an append-only change
   journal, written under ADR-0014's rules (exclusive creates, version-checked atomic replaces, no
   lock file in the tree). It backs `hnx projects`, the hub's Projects page and
   `homelabnext.project.changed` events.
4. All rules live in one place (`ProjectStore`); a product binds by implementing a small backend
   (load, write with the versions read, changes since a cursor). The OpenProject backend passes
   the same suite.
5. The strategy repository is the source of truth for strategy records. The sync to OpenProject
   is one way, upserts by uid into a permission-isolated Strategy project, skips unchanged
   records by a content hash, writes back and reports edits made in OpenProject, and never closes
   or deletes a record on its own.
6. Strategy records are read through one seam (`strategy_records`, over the ADR-0019 loader),
   so a change in how records are stored changes one function.
7. The change feed from OpenProject treats the webhook as a trigger and an `updatedAt` poll as the
   guarantee; both derive the event id from `wp:<id>:v<lockVersion>`, so they converge on one
   event. A webhook without a valid signature is refused.
8. Work completion may feed MOP readings only, never a MOE (doctrine rule `activity_never_moe`),
   and never changes an objective's status.
9. What OpenProject cannot do by API is a written admin checklist plus `hnx projects doctor`,
   which checks every precondition by name and prints the missing step.

## Consequences

- The board's rules become checks any project tool must pass, and a lab can move from the
  Markdown files to OpenProject (or later to another tool) through the swap procedure.
- Projects and work items use the same identity as strategy records (ADR-0019): a uid, with
  numbers only on display, so nothing is allocated or renumbered when work is added or moved.
- The OpenProject adapter reads the whole work project per operation: simple and correct for a
  lab, not built for a large instance.
- Setup stays manual and can drift; `doctor` makes the drift visible but cannot fix it.
- Mirrored strategy prose lives in a second datastore; it must stay on the lab network with a
  small membership.

## Alternatives

- **Keep the board as a file plus generator.** Cheap, but its rules stay private to one script
  and no tool can replace it.
- **Make OpenProject the source of truth for strategy.** Its edits are not reviewed, it has no
  link rules, and a lab without it would lose its strategy; rejected.
- **Bidirectional sync of strategy records.** Merging edits from two places needs conflict
  rules nobody reviews; one-way plus revert-and-report keeps one owner.
- **Webhooks only.** At-most-once delivery after a five-minute window, no delete or relation
  events: a feed built on them alone silently misses changes.
- **An existing Python OpenProject client.** The maintained ones are stale; eight endpoints over
  the standard library cost less than a dependency.
