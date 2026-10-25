---
summary: 'Hypervisor, physical network and base storage are a fixed substrate, not a swappable seam; hardware moves are a re-render plus DNS flips.'
summary_of: outline:sha256:094d6d265d082d7d
---
# ADR-0012: The hypervisor layer is deliberately not a swappable seam

- **Status:** proposed
- **Date:** 2026-10-15
- **Related:** ADR-0002, ADR-0004, ADR-0005

## Context

Applying the swap discipline to every layer invites a conformance test and an adapter for the
hypervisor, networking and storage substrate. Those layers are chosen once per hardware
generation, are expensive to rehearse, and abstracting them would add a layer whose failure
modes exceed the flexibility it buys.

## Decision

1. The platform treats the hypervisor, physical network and base storage as a fixed substrate
   chosen per deployment, not as a capability with a swap test.
2. What the platform does demand of the substrate is expressed as inventory facts and registry
   rows (guest sizes, networks, backup membership), so a hardware move is a re-render and a
   sequence of DNS flips (ADR-0002), not a rewrite.
3. Substrate changes are recorded as ordinary ADRs with a revisit trigger, not run through
   `hnx swap`.
4. No hypervisor-specific code lives in `homelabnext/`; provisioning examples live under
   `examples/` and `ansible/` only.

## Consequences

- Scope stays bounded; effort goes where swaps actually happen (products above the substrate).
- Users on a different substrate adapt provisioning, not the contracts.

## Alternatives

Abstract the hypervisor behind a capability: rejected as over-engineering. Make provisioning a
core library: it would couple the contracts to one substrate.
