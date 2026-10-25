---
summary: 'One shared client library per data seam; a private copy of a client fails CI.'
---
# ADR-0003: One shared client library per data seam; private copies are a CI failure

- **Status:** proposed
- **Date:** 2026-10-15
- **Related:** ADR-0001, ADR-0002, ADR-0010

## Context

Without shared libraries, every script grows its own query helper, notification helper and
state-file helper, and some write straight into the directories of a records store. Dozens of
byte-identical copies exist; every seam change is an N-file sweep and the copies diverge in
their error handling.

## Decision

1. One Python package per data seam, all under `homelabnext/`: `lake` (named and ad-hoc query,
   catalog, idempotent write with commit-then-checkpoint), `notify` (state-diffed, dedup-keyed
   send through a sender adapter), `state` (cursor and history with atomic writes) and
   `records` (propose, finding, completion request, note validation). Each resolves endpoints
   through the registry (ADR-0002) and raises when an endpoint is unset.
2. Product-specific code lives only inside these packages as adapters.
3. Every library ships an in-memory fake used by the conformance tests (ADR-0005).
4. Migration is per script family with byte-stable output tests; a library change may not merge
   without deleting the copies it replaces. CI fails on a private re-implementation outside the
   package (allow-list with a written reason only).

## Consequences

- Swapping the query engine, catalog, notification channel or records store becomes an adapter
  change in one package.
- One more thing to version; consumers vendor a pinned version so a library bug cannot take
  every script down at once.

## Alternatives

Shell out to one CLI instead of a library: simpler for scripts but loses typed results and makes
non-Python consumers second class. The two can coexist later; the library remains the source.
