# ADR-0025: Record each agent job's usage on the bus and read per-turn records from the gateway

- **Status:** proposed
- **Date:** 2026-10-22
- **Related:** ADR-0009, ADR-0013, ADR-0022, `schemas/events/agent.job.finished.schema.json`,
  `docs/orchestration-telemetry.md`

## Context

Tuning the orchestration (budgets, prompt ordering, routing, admission) needs per-job and
per-turn facts. Only the controller sees a job whole: its input, its outcome, its delivered
answer and its usage file. Only the gateway sees every model call. The controller already has a
durable outbox that publishes `agent.job.failed` in the same transaction as the terminal
transition. ADR-0009 keeps telemetry off the bus; ADR-0013 put agent activity's summary tier on
it because it is a low-volume, per-item record other consumers follow.

## Decision

1. A new event type `homelabnext.agent.job.finished` 1.0, owned here, is the per-job usage record:
   one per terminal run, from `svc:llm-orchestrator`, through the outbox, id derived from the run
   id. It is a per-item business record like `agent.activity`, not a metrics stream, so it fits
   the bus under ADR-0009.
2. Its data is names, counts, sizes and times only; every object is closed, so no prompt, task
   text, tool input or output or model output can be carried.
3. Per-turn records stay direct (ADR-0009 point 2): the hub reads the gateway's spend-log API
   (`/spend/logs/v2`) with a read-only viewer key named by secret, never the master key and never
   a database grant, and keeps only an allow-list of fields.
4. A job and its turns join by `gateway_tag`, which the controller sends as the request tag on
   every model call of the job.
5. The status hub stores both (SQLite, idempotent by event id and by run id, purged by age) and
   shows them on an Orchestration page; the rollup it computes is the input of the later
   recommendation engine, whose output is broker proposals, never applied automatically.

## Consequences

- One more type on the controller's NATS publish grant (`homelabnext.agent.job.>` already is its
  alone) and one more durable consumer for the hub.
- The controller and homelab-next share a schema; field changes are additive minors with frozen
  baselines.
- Jobs not routed through LiteLLM have no per-turn data; the page says so instead of showing zeros.
- A viewer key must be created on the gateway by hand until the gateway generator learns it.

## Alternatives

- Extending `agent.job.failed`: rejected, it is a reaction trigger (A02 resubmits on it) and covers
  failures only.
- Reading `LiteLLM_SpendLogs` from Postgres: rejected, an unsupported internal schema whose table
  also holds prompts, answers and key hashes.
- Pushing per-turn records through the bus: rejected by ADR-0009 (telemetry stays direct) and
  needless, since the gateway already keeps them.
