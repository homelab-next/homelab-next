---
summary: 'Detections are authored once in Sigma and cited by logical id, not copied per product.'
summary_of: outline:sha256:0b473ec2dc9e7a63
---
# ADR-0006: Detections are authored in Sigma, compiled to the engine, and referenced by logical id

- **Status:** proposed
- **Date:** 2026-10-15
- **Related:** ADR-0001, ADR-0005, `detections/`

## Context

Detections written directly in one engine's native rule format inherit that engine's authoring
traps, and engine-specific rule numbers end up cited in agent instructions, dossiers and
decision specs. Changing the rule engine would then mean rewriting prose as well as rules.

## Decision

1. New detections are authored in Sigma with `must_fire`, `must_not_fire` and `evasion`
   fixtures, and compiled to an engine through a backend (a generic backend ships; the engine
   adapters are interfaces with a fake).
2. Every detection has a logical id (`det:<slug>`). Instructions, dossiers, ledgers and decision
   specs cite logical ids; a generated map resolves them to engine rule numbers. A raw rule
   number in prose or a spec is a lint failure.
3. Alert severity at the automation seam is the OCSF `severity_id`, not an engine-specific level.
4. A rule without fixtures fails the gate. Rules that cannot be expressed in Sigma stay native
   with a stated reason.

## Consequences

- Swapping the engine is a backend change plus a re-run of the fixture gate.
- Some engine-only constructs will not express in Sigma.

## Alternatives

Keep the engine's native format as the authoring format: cheapest today, and it maximises the
cost of the one swap that is hardest to make later.
