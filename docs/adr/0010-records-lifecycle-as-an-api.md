---
summary: The records lifecycle (propose, find, complete) is written through the records library and the broker's records-inbox lane, never by moving files.
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

1. Code writes a proposal, finding or completion request through the `records` library
   (ADR-0003) or, for an agent, through the broker's `records-inbox` lane
   (`homelabnext/broker/lanes.py`), which validates, renders and names the note with the
   library's own functions (`validate_note`, `render_note`, `build_filename`) and writes it with
   the broker's lane rules (no-follow path walk, exclusive create, a keyed name tag). Notes are
   validated against `schemas/records/note.schema.json`. *Status note (2026-11):* the two write
   paths still differ in one rule: `Records` refuses a name that is already in `decided/*`, and
   the lane does not yet; one shared write function is the follow-up.
2. Lanes are `inbox/` (the only agent-writable lane) and `decided/{approved,denied,completed}`
   (operator-only). A `completion-request` note with a `related:` list moves its targets to
   `completed/` on approval.
3. The lifecycle is exposed through the broker: the `records-inbox` lane files notes today
   (`examples/broker/manifest.yml`, `proposal.file`); `records.complete` and `register.update`
   handlers with digest-bound approvals may follow. The file store, a forge or a project
   tracker is the adapter behind them.
4. Any guard hook remains defence in depth, not the mechanism.

## Consequences

- One write path and one audit record for the lab's own records, the same as for hosts.
- Approval consoles and sync jobs become thin clients of the library.

## Alternatives

Keep file moves and a guard hook: works for one operator; every new writer re-implements the
convention.
