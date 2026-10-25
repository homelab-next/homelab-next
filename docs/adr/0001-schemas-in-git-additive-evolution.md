---
summary: Contracts are JSON Schema files in git, vendor schemas are pinned, and schemas evolve additively only.
---
# ADR-0001: Contracts live in `schemas/` in git, vendor schemas are pinned, and evolution is additive-only

- **Status:** proposed
- **Date:** 2026-10-15
- **Related:** ADR-0003, ADR-0005, `docs/interfaces.md`

## Context

A swappable platform is only as swappable as its contracts are testable. In a typical grown
lab the contracts are implicit: each writer carries an inline table schema, no version of the
upstream event-schema standard is pinned, table names are hard-coded in dozens of scripts, and
per-agent table allow-lists are maintained by hand. Nothing can be validated, so nothing
protects a product swap.

## Decision

1. `schemas/` holds one JSON Schema per seam, grouped by directory: `ids`, `events`, `ocsf`,
   `agent`, `broker`, `records`, `registers`, `platform`. Vendor schemas (OCSF) are vendored as
   a pinned subset with the version recorded.
2. Writers, DDL, table scopes and named-query definitions are generated from these files. A
   hand-written table name outside `schemas/` is a lint failure.
3. Evolution is additive within a major version. A breaking change is a new versioned schema
   with a declared dual-write window and a backfill tool; consumers declare the version they
   read.
4. Every schema ships at least one valid example and at least one negative example; CI
   (`tools/schema_check.py`) enforces this and the additive-evolution rule.
5. Both-side contract tests: every publisher's sample validates, every consumer accepts the
   schema's examples.

## Consequences

- The first validation run produces a list of non-conforming payloads; that list is the real
  coupling inventory and is worked before any product swap.
- Schema authors carry the burden of writing negatives, which is the point: a contract that
  rejects nothing is not a contract.
- Breaking changes are slow by design.

## Alternatives

Keep schemas implicit in writer code and product configuration: cannot be tested, so cannot
protect a swap. Code-first models (generate schemas from classes): ties the contract to one
language; JSON Schema is readable by every consumer.
