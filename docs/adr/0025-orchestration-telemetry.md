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
   one per terminal run, from the orchestration controller's service id (configuration; the
   example lab's is `svc:llm-orchestrator`), through the outbox, id derived from the run id. It
   is a per-item business record like `agent.activity`, not a metrics stream, so it fits the bus
   under ADR-0009.
2. Its data is names, counts, sizes and times only; every object is closed, so no prompt, task
   text, tool input or output or model output can be carried.
3. Per-turn records stay direct (ADR-0009 point 2): the hub reads them from the gateway
   provider's own per-call log API through a turn-source adapter (the `inference` capability's
   `turn-records` feature, `TurnSource` in `conformance/protocols/inference.py`), with a read-only
   key named by secret, never an admin key and never a database grant, and keeps only the neutral
   turn record's allow-listed fields. The first adapter is LiteLLM's `/spend/logs/v2`.
4. A job and its turns join by `gateway_tag`, which the controller sends as the request tag on
   every model call of the job.
5. The status hub stores both (SQLite, idempotent by event id and by run id, purged by age) and
   shows them on an Orchestration page; the rollup it computes is the input of the later
   recommendation engine, whose output is broker proposals, never applied automatically.
6. Requires and prefers: the feature *requires* the events capability (the bus) and the
   orchestration controller emitting `agent.job.finished`; it *prefers* an inference gateway with
   a turn source (`turn-records`), and without one (`--turn-source none`, or a direct backend) it
   shows per-job data only, with "no gateway data" instead of zeros. A later module manifest
   transcribes this as `requires:` and `prefers:`.

## Consequences

- One more type on the controller's NATS publish grant (`homelabnext.agent.job.>` already is its
  alone) and one more durable consumer for the hub.
- The controller and homelab-next share a schema; field changes are additive minors with frozen
  baselines.
- Jobs not routed through a gateway whose adapter provides turn records have no per-turn data;
  the page says so instead of showing zeros. Swapping the gateway is a turn-source adapter plus
  the `turn-records` conformance checks, not a change in the hub.
- The store moves as neutral JSON lines (`hnx orchestration export` / `import`,
  `homelabnext.orchestration.export/1`), so history survives a host move or an upstream swap;
  a published schema for `rollup/1` follows at its first release.
- A viewer key must be created on the gateway by hand until the gateway generator learns it.

## Alternatives

- Extending `agent.job.failed`: rejected, it is a reaction trigger (A02 resubmits on it) and covers
  failures only.
- Reading `LiteLLM_SpendLogs` from Postgres: rejected, an unsupported internal schema whose table
  also holds prompts, answers and key hashes.
- Pushing per-turn records through the bus: rejected by ADR-0009 (telemetry stays direct) and
  needless, since the gateway already keeps them.
