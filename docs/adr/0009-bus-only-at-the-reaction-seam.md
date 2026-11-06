---
summary: 'A bus for reaction triggers, per-item records and decision events, via a forwarder or an outbox relay; telemetry stays direct, control typed RPC.'
summary_of: outline:sha256:16a943a11ecd382a
---
# ADR-0009: A bus only at the reaction seam; telemetry stays direct and control stays typed RPC

- **Status:** proposed
- **Date:** 2026-10-15
- **Related:** ADR-0001, ADR-0003, ADR-0005, ADR-0017, ADR-0033
- **Amended:** 2026-11-01: the three event classes and the two sanctioned publish paths (the
  broker's outbox relay was built against the `EventBus` protocol, not a forwarder)

## Context

Making everything event-driven would add a hop beneath the lake writers, whose checkpointing is
already the fragile step, and would blur which component owns which kind of work. At the same
time the reaction layer (alert in, workflow out) benefits from decoupling.

## Decision

1. A CloudEvents-style envelope on a bus carries three classes of event, and nothing else:
   - **reaction triggers**: an occurrence something reacts to (an alert, a case, a queued task, a
     fired schedule, a deploy, a scope denial, a swap step, a failed job);
   - **per-item business records**: one low-volume event per item or item version (an agent
     activity summary, a finished job's usage record, a project change, a status observation),
     never a metrics or log stream;
   - **decision events**: the broker's and the approver's decisions (requested, returned, a
     proposal filed or decided).

   Every event type's class is listed in `docs/events.md` ("What goes on the bus"), and a test
   fails when a type under `schemas/events/` has no class there.
2. The swap boundary is the `EventBus` protocol (`conformance/protocols/events.py`: publish under
   a message id, durable consumers), not a bus product (the initial pick is NATS JetStream, with
   a revisit trigger). A publisher reaches the bus in one of two sanctioned ways:
   - **through a forwarder** (the default for every producer): it POSTs the envelope to a
     forwarder (`Publisher` in `homelabnext/events/publisher.py`, `HttpForwarder` in
     `homelabnext/events/forwarder.py`) and never
     speaks the bus protocol;
   - **through a transactional outbox relay**: a component that must never wait on the bus
     writes its events to an outbox, and a separate relay publishes them through an `EventBus`
     client. The one such relay is the broker's (`hnx broker relay`,
     `homelabnext/broker/relay.py`), so a bus outage delays a decision event and never blocks or
     fails a decision. An embedded broker handed an `EventBus` (a test or a single-process setup;
     `BrokerService`'s approvals part, `homelabnext/broker/approvals.py`) publishes through it
     directly.

   Both paths make the event id the idempotency key. The forwarder answers *duplicate* for an id
   it already stored; the protocol's `publish(..., msg_id=id)` returns the existing sequence for
   a repeated id (the JetStream adapter maps it to `Nats-Msg-Id` and the stream's duplicate
   window). No other module publishes through an `EventBus`, and a test fails when one does
   without being named here.
3. Telemetry (collector to lake) stays direct and buffered.
4. Control (approval-gated actions, job submission, tool calls) stays synchronous typed RPC.
5. Dead-letter depth, consumer lag and the forwarder's own liveness are invariants before any
   rule goes live.

## Consequences

- The reaction layer gets its decoupling without the data plane inheriting a new dependency.
- Some events (for example a table-freshness event) are emitted by checks, not by the data path.
- Two publish paths exist, with one idempotency key and different retry rules (the publisher's
  state file and backoff; the relay's outbox, delivered markers and attempt counts). A bus swap
  replaces the forwarder's backend and the `EventBus` adapter, and must keep the protocol's
  repeated-id answer, which the relay's crash recovery depends on.
- The envelope carries an optional TLP label (`tlp`, absent reads `red`) and `derivedfrom` since
  envelope 1.2 (ADR-0033), but no producer sets them and nothing filters on them, so the bus is an
  egress point that is "not yet" checked (`docs/modules.md`); a single publish path that runs the
  egress check is open work, not decided here.

## Alternatives

A bus everywhere: rejected for operational weight and data-plane risk.
