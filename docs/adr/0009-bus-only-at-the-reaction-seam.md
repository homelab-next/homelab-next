# ADR-0009: A bus only at the reaction seam; telemetry stays direct and control stays typed RPC

- **Status:** proposed
- **Date:** 2026-10-15
- **Related:** ADR-0001, ADR-0003, ADR-0005

## Context

Making everything event-driven would add a hop beneath the lake writers, whose checkpointing is
already the fragile step, and would blur which component owns which kind of work. At the same
time the reaction layer (alert in, workflow out) benefits from decoupling.

## Decision

1. A CloudEvents-style envelope on a bus is used for reactions only. Publishers POST the
   envelope to a forwarder and never speak the bus protocol, so the bus product is swappable
   (the initial pick is NATS JetStream, with a revisit trigger).
2. Telemetry (collector to lake) stays direct and buffered.
3. Control (approval-gated actions, job submission, tool calls) stays synchronous typed RPC.
4. Dead-letter depth, consumer lag and the forwarder's own liveness are invariants before any
   rule goes live.

## Consequences

- The reaction layer gets its decoupling without the data plane inheriting a new dependency.
- Some events (for example a table-freshness event) are emitted by checks, not by the data path.

## Alternatives

A bus everywhere: rejected for operational weight and data-plane risk.
