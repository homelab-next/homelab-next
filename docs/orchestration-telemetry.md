<!-- SPDX-License-Identifier: Apache-2.0 -->
# Orchestration telemetry

What each agent job of the [LLM orchestrator](orchestration-controller.md)
([[orchestration-controller]]) cost and how it went, so orchestration can be tuned from real data:
token and turn budgets, prompt ordering for cache hits, model routing, admission. The decision is
[ADR-0025](adr/0025-orchestration-telemetry.md).

Two sources, joined by a tag:

| Source | Grain | How it reaches the hub |
|---|---|---|
| the controller (it sees the task input and the final answer) | one record per job | the event `homelabnext.agent.job.finished` on the bus |
| the [LLM gateway](llm-gateway.md) ([[llm-gateway]]), LiteLLM's spend log | one record per model call (turn) | read from the gateway's API, joined by `gateway_tag` |

Per-tool-call records from first-party MCP servers may come later as a third source.

## The contract: `homelabnext.agent.job.finished` 1.0

Schema: `schemas/events/agent.job.finished.schema.json` (frozen baseline under
`schemas/_frozen/1.0/events/`, examples and negatives beside it; the generated publisher and
consumer contract tests cover it like every type, [events](events.md) ([[events]])).

The controller emits it once per job reaching a terminal state, through its durable outbox, in
the same transaction as the terminal transition, with `source: svc:llm-orchestrator` and an `id`
derived from the run id (a re-send is a duplicate). `agent.job.failed` is still emitted for
failures; `finished` is the usage record of every outcome.

| Field | Type | Meaning |
|---|---|---|
| `run_id` | string | the controller's run id |
| `profile` | `profile:<id>` | `profile:` + the run's agent key |
| `profile_revision` | string or null | |
| `lane` | `real` \| `shadow` | a shadow run's answer is recorded, never delivered |
| `outcome` | `completed` \| `failed` \| `cancelled` \| `timeout` | `timeout` = a failure of class timeout, deadline or budget; a cancel is `cancelled` with class `cancelled`; everything else is `failed` |
| `failure_class` | string or null | the controller's failure class; null exactly when `completed` |
| `retry_of_run_id` | string or null | |
| `auto_retry_scheduled` | boolean | as `agent.job.failed` 1.1 |
| `local_attempts` | integer >= 0 | |
| `cloud_fallback_used` | boolean | |
| `backend` | string or null | the logical backend name as the controller emits it (1 to 64 of `A-Za-z0-9._-`; a leading dot or digit is fine); no `:` or `/`, so never a URL or host:port |
| `model` | string or null | opaque: the usage file's model, else the request's (a vLLM model path is possible); no control characters |
| `queued_at`, `finished_at` | date-time | |
| `started_at` | date-time or null | null for a job that never started |
| `queue_wait_s`, `wall_s` | number >= 0 or null | null for a job that never started |
| `input_bytes` | integer >= 0 | size of the task description plus the request body |
| `output_bytes` | integer >= 0 or null | size of the delivered result; null when empty |
| `usage` | object or null | the usage file's `input_tokens`, `output_tokens`, `reasoning_tokens`, `cache_read_tokens`, `api_calls` (integers) and `cost_usd`; each null = unknown, which is not 0. Null when there is no usage file |
| `turn_exit_reason` | string or null | from the usage file |
| `tools` | array, optional | `[{name, calls}]` when the controller has them; omitted otherwise |
| `gateway_tag` | string | an optional prefix (at most 64 of `A-Za-z0-9._:/-`, never a comma) followed by the run id |

Every field but `tools` is always present (null when unknown). Evolution is additive.

## The privacy rule: names and numbers, never text

Neither source may carry a prompt, task text, tool input or output or model output, the same rule
as `agent.activity`'s summary tier ([status](status.md) ([[status]]) section 6):

- the event schema closes every object (`additionalProperties: false`), so a text field cannot
  ride along; the negatives `carries-task-text`, `usage-carries-prompt` and `tool-carries-input`
  prove it;
- sizes are byte counts, never content;
- a gateway row is reduced to an allow-list before it is stored
  (`homelabnext.orchestration.gateway.turn_from_row`): request id, matched tag, start time,
  duration, time to first token, model group (the role asked for), model, call type, status,
  HTTP error code, token counts, cache-read tokens, cache hit, cost. `api_base`, `user`,
  `end_user`, the client address, the key hash, the rest of `metadata` and any message or response
  column are dropped, and a name that is not name-shaped is dropped rather than kept. The tests
  plant such values (all fictional) and check that neither the store file nor the page holds them.

## Data flow

```
controller ── outbox ──▶ bus: homelabnext.agent.job.finished
                              │  hnx orchestration consume   (durable pull, one pass per timer)
                              ▼
                     telemetry store (SQLite) ◀── hnx orchestration turns ── gateway /spend/logs/v2
                              │                    (jobs not yet settled, joined by gateway_tag)
                              ├──▶ hub page /orchestration      (hnx status serve --orchestration DB)
                              └──▶ hnx orchestration report     (rollup JSON: the engine's input)
```

- **Consume** (`homelabnext.orchestration.bus.drain`): a durable pull consumer
  (`hnx-orchestration-telemetry`) on the type's subject. Stored or a duplicate: `ack`. Poison (not
  JSON, invalid, another type, a source other than `svc:llm-orchestrator`, an id reused with
  another body, a second record for a run under another id, a record whose `gateway_tag` another
  run already holds (the tag must name one job, or two jobs' turns would merge), a timestamp the pattern accepts but
  the calendar does not, such as `2026-02-30`): `term`, so the bus's dead-letter stream is the
  quarantine; only the id and the reason are logged. A body nested so deep that it parses but
  cannot be re-encoded is poison too. Anything else (a store failure, SQLite or the disk, or the
  environment: `jsonschema` missing, a schema file half-written by a deploy, a `$ref` that
  resolves to nothing): `nack` and the pass stops, so an outage never dead-letters valid records.
  The event schemas are loaded and their `$ref`s resolved before the first fetch, so a broken
  environment fails `consume` up front (exit 2) with nothing fetched. The consumer's NATS user needs the same pull-consumer grant shape as the
  StackStorm bridge's, on `<prefix>.homelabnext.agent.job.finished`; publishing on
  `homelabnext.agent.job.>` stays the controller's alone.
- **Ingest** (`hnx orchestration ingest FILE|-`): the same consumer over a JSON-lines file, for a
  backfill or a replay of the outbox.
- **Turns** (`hnx orchestration turns`): for every job whose turns are not settled, read the
  spend log over windows covering the jobs (from queue time less two minutes to finish time plus
  two, merged when within an hour, but cut into windows of at most an hour so a week of replay
  or a backlog after an outage never becomes one window over all the gateway's traffic), oldest
  first; keep the rows whose `request_tags` hold a job's tag, and rewrite them by request id. A
  job is settled ten minutes after it finished (LiteLLM writes its spend log in batches), as soon
  as the last window it overlaps has been read; a failed read stops the pass but keeps what was
  read and settled before it, and the next pass starts from the jobs still unsettled.
- **Retention**: 90 days by default (`--retention-days`), by finish time and turn start time. A
  record that arrives already older than that (a late replay, an old backfill) is counted
  `expired` by `consume` and `ingest`: acknowledged and not stored, neither processed nor poison.

### The gateway read path: the spend-log API with a viewer key

`GET /spend/logs/v2` (LiteLLM's paginated spend-log API), with a LiteLLM virtual key whose user has
the `proxy_admin_viewer` role (sees all spend, cannot create keys, change settings or call models)
and `allowed_routes: ["/spend/logs/v2"]`, named by secret: `secret:llm-gateway/key-telemetry-reader`,
delivered as `HNX_SECRET_LLM_GATEWAY_KEY_TELEMETRY_READER`. The reader refuses the master key (by
the variable it is delivered in, so no other spelling of its name gets past), a literal value, credentials in the URL, plain http to anything but loopback (unless
`--allow-plaintext`), redirects and proxies.

Why not a read-only Postgres role on `LiteLLM_SpendLogs`:

1. The API is LiteLLM's supported interface; the table is its ORM's internals, migrated by
   releases on a fast-moving patch line ([LLM gateway](llm-gateway.md)).
2. The list endpoint leaves out `messages`, `response` and `proxy_server_request`; a `SELECT` on
   the table hands over prompts and answers whenever prompt storage is on, plus key hashes and
   client addresses. Least privilege is the API.
3. The schema belongs to the gateway's own role and is re-created by migrations, so a grant would
   have to be redone after each one; the database also needs no network path from the hub.

The key is not generated yet: `hnx gen gateway render` creates only model-calling keys, so the
operator creates this one on the running gateway (`/user/new` with `user_role:
proxy_admin_viewer`, then `/key/generate` for that user with the route restriction) and stores it
under the secret name. Generating it from the gateway spec is a follow-up.

### Enabling tagging on the gateway

- The controller sends every model request of a job with the header `x-litellm-tags: <gateway_tag>`
  (the job-scoped hermes home's model config sets it). LiteLLM records it in
  `LiteLLM_SpendLogs.request_tags` (LiteLLM's "request tags").
- Tag tracking needs virtual keys and the database, which the supported LiteLLM shape already
  requires ([LLM gateway](llm-gateway.md), "Running LiteLLM: the supported shape").
- `general_settings.reject_clientside_metadata_tags` must stay unset or false, or LiteLLM drops
  client tags; spend logs must stay on (`disable_spend_logs` unset). Prompt storage in the spend
  log is not needed and should stay off.
- Only jobs routed through a LiteLLM gateway have turns. A job on a direct vLLM backend or a cloud
  provider has none: the page shows **no gateway data**, never zeros, and the rollup's turn sums
  are null.

## The hub page

`hnx status serve --orchestration DB` adds the Orchestration page (menu entry `panel:
orchestration`, views schema 1.9):

- **By profile and backend** (and lane): jobs, outcomes, p50/p95 wall time and queue wait, tokens
  in/out, cache-read share, cost, retries and auto-retries, cloud fallbacks, input vs output size
  (p50), gateway turns (or "no gateway data"). An unknown count or cost is shown as `?` or "(n
  unknown)", never folded into a zero.
- **Trend by day**: per day and profile, jobs, completed, not completed, wall p50, tokens, cost.
- **Latest jobs**, each linking to `/orchestration/job?run=<run id>`: the job's record, its tool
  counts and its gateway turns (model group, model, status, tokens, cache read, time to first
  token, duration, cost), with the gateway's token sums beside the usage file's.

Filters (`profile`, `backend`, `lane`, `outcome`, `days` 1..90) narrow everything. The hub
opens the store read-only (SQLite `mode=ro`): it creates, migrates and purges nothing, and a path
that is not an existing store stops `hnx status serve` at start (exit 2) instead of serving an
empty page; `hnx orchestration` is the only writer.

## What the recommendation engine will consume

`hnx orchestration report --db DB [--days N]` prints the rollup (`homelabnext.orchestration.rollup/1`,
`homelabnext.orchestration.model`): per profile, backend and lane, the job counts by outcome and
failure class, distributions (p50, p95 and n) of wall time, queue wait, input and output tokens per
job, API calls per job and gateway turns per job, token sums, cache-read share, cost, retries,
fallbacks, sizes, and the per-turn latency figures; plus the per-day trend (by UTC day). Every sum
(tokens, cost, output size, the gateway turns' tokens and cost, each day's tokens and cost) is over
the known values only, carries its own count of the values left out (`jobs_unknown.<sum>`,
`turns_unknown.<sum>`), and is `null` when no value is known: unknown is never folded into 0. The
full shape is in `homelabnext.orchestration.model`'s docstring. Until the first release the shape
of `rollup/1` may still change in place (nothing consumes it yet); after it, it evolves additively
and an incompatible change takes `rollup/2`. The engine (`hnx orchestration recommend`, a later step) turns rules over that
input into broker proposals (`proposal.created`) with the evidence attached:

| Rule | Reads |
|---|---|
| per-profile token and turn budgets | `tokens_per_job.*.p95`, `api_calls_per_job.p95`, `turns.per_job.p95` |
| prompt prefix ordering for cache hits | `cache_read_share`, per-turn `cache_read_tokens` |
| model routing, checked against golden evals | outcomes and cost per backend and lane (shadow vs real) |
| admission prediction | `queue_wait_s`, `wall_s` per profile and backend |
| regression alarms | the `days` trend |

Shadow first: the engine records what it would propose; filing proposals is an explicit config
flip; nothing is ever applied automatically.
