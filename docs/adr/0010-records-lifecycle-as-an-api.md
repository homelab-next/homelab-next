---
summary: The records lifecycle (propose, find, complete) is written only through the records library, not by moving files; broker handlers come later.
summary_of: outline:sha256:5cbd1fe67bd124f3
---
# ADR-0010: The records lifecycle and register edits are an API, not file moves

- **Status:** proposed
- **Date:** 2026-10-15
- **Related:** ADR-0003, ADR-0005, `schemas/records/`

## Context

A records store with a propose, approve, complete lifecycle is often implemented as files moved
between directories by a sync job plus a guard hook. The semantics live in the sync job; many
scripts write directly into the directories; edits to registers (boards, lessons, runbooks) are
proposed as prose. The governance layer's only contract is a frontmatter convention.

## Decision

1. The `records` library (ADR-0003) is the only way code writes a proposal, finding or
   completion request. Notes are validated against `schemas/records/note.schema.json`.
2. Lanes are `inbox/` (the only agent-writable lane) and `decided/{approved,denied,completed}`
   (operator-only). A `completion-request` note with a `related:` list moves its targets to
   `completed/` on approval.
3. The lifecycle can later be exposed as broker handlers (`records.propose`, `records.complete`,
   `register.update`) with digest-bound approvals; the file store, a forge or a project tracker
   is the adapter behind them.
4. Any guard hook remains defence in depth, not the mechanism.

## Consequences

- One write path and one audit record for the lab's own records, the same as for hosts.
- Approval consoles and sync jobs become thin clients of the library.

## Alternatives

Keep file moves and a guard hook: works for one operator; every new writer re-implements the
convention.
