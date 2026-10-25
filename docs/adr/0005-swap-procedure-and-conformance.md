---
summary: 'Every swap of a product follows one procedure, and every capability has a passing swap conformance test.'
---
# ADR-0005: Every product swap follows one procedure and every capability has a passing swap test

- **Status:** proposed
- **Date:** 2026-10-15
- **Related:** ADR-0001, ADR-0002, ADR-0003, `homelabnext/swap`, `homelabnext/conform`

## Context

A modular architecture promises that any product can be replaced, but without a runnable swap
test per capability the promise is untested. Past replacements each invented their own cutover
method, and each rediscovered the same failure modes (non-atomic checkpoints, dual-write gaps,
forgotten consumers).

## Decision

1. `conformance/<capability>/` holds the swap test for each capability (fourteen at first
   drop). CI runs each against its fake; the nightly job runs them against real containers; an
   exporter lists capabilities without a passing test.
2. The swap procedure is fixed: the swap test passes on staging; shadow or dual-run in
   production with idempotency keys; parity for a declared window; cutover by changing the
   registry `impl:` (or the DNS alias) and regenerating; affected canaries and invariants green;
   a rollback window with the old component stopped, not destroyed; decommission via the drift
   check; ADR update with a revisit trigger. `hnx swap` runs this checklist and writes a swap
   record.
3. A swap that edits anything other than the registry row, the adapter and generated artefacts
   at cutover is a defect to be recorded as a lesson.

## Consequences

- "Should we switch?" becomes a measurement.
- Fakes must be kept faithful; a fake that passes while the real product fails is a bug in the
  fake.

## Alternatives

Ad-hoc cutovers per product: the status quo, and the source of the repeated failure modes.
