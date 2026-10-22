<!-- SPDX-License-Identifier: Apache-2.0 -->
# Events: envelope, validation and the idempotent publisher

`homelabnext.events` is the client side of the event seam. Schemas: `schemas/events/` (a
CloudEvents 1.0 compatible envelope plus the reaction-seam types).

* **Publishers never speak the bus.** They hand the envelope to a *forwarder* over HTTP
  (`HttpForwarder`); what sits behind the forwarder (a broker, a queue, a file) is its business.
* **`build_event` / `validate_event`** check the envelope and, when one exists, the per-type schema
  (`homelabnext.task.queued` -> `schemas/events/task.queued.schema.json`). Unknown types are checked
  against the envelope only.
* **The `id` is the idempotency key.** `derive_event_id(type, source, dedupe_key)` makes it a pure
  function of the event's identity, so the same occurrence always has the same id.

## Publisher protocol

```python
pub = Publisher(HttpForwarder("https://events.example.invalid/ingest"), StateStore("events.json"))
result = pub.publish(build_event("homelabnext.task.queued", "svc:siem", data, dedupe_key="job-17"))
pub.flush()  # resend anything still pending (after an outage or a crash)
```

1. validate (an invalid event is refused before any I/O);
2. write the event to the state file as `pending` (write-ahead);
3. send; transient failures (network, 5xx, 429, timeout) back off exponentially, bounded by
   `RetryPolicy(max_attempts, base_s, factor, max_s)`; a permanent failure (other 4xx, id
   collision) marks the event `rejected` and is never retried;
4. only an acknowledgement moves it to `sent`.

If the process dies between "the forwarder stored it" and "the publisher recorded the ack", the
record is still `pending`; the next `publish` or `flush` sends the *same id* again, the forwarder
answers *duplicate*, and the publisher marks it sent. On the wire that is at-least-once; in effect
it is exactly-once. Re-publishing a `sent` id makes no call at all, and the same id with different
content is refused.

## Forwarder contract (what `HttpForwarder` expects)

`POST` with `Content-Type: application/cloudevents+json` and `Idempotency-Key: <id>`.
`200/201/202/204` accepted (`{"duplicate": true}` in the body when already held), `409` id
collision (permanent), `408/425/429/5xx` retry, other `4xx` permanent.

## Testing

`FakeForwarder` records what it accepted and can fail before storing (`fail_next`), store then lose
the acknowledgement (`lose_ack_next`) or refuse (`reject_next`). `FakeForwarderServer` puts the same
fake behind a loopback HTTP server so the HTTP adapter is exercised for real. Nothing needs a
network beyond loopback: `pytest tests/events`.

The `homelabnext.scope.denied` event (a writer tool was refused) is described in `docs/scope.md`.
The `homelabnext.status.observed` event (one status observation, published by status collectors
and consumed by the status hub) is described in `docs/status.md`, and so is
`homelabnext.agent.activity` (an agent activity event, summary tier only). The
`homelabnext.agent.job.finished` event (the per-job usage record of the orchestration controller,
consumed by the status hub) is described in `docs/orchestration-telemetry.md`.

## Consumers (`homelabnext.events.consumer`)

`decode_event(body, types=...)` is what a consumer runs on every received body: parse, validate the
envelope and the per-type schema, refuse types it does not handle. Unknown extension attributes are
kept and ignored (CloudEvents), so adding one never breaks a consumer. `Consumer({type: handler})`
dispatches by type and is idempotent by id, the mirror of the publisher: a redelivered id is a
`duplicate` and does not run the handler again, the same id with a different body is refused, and a
handler that raises leaves the id unrecorded so the redelivery is processed.

## Contract tests for every seam (checklist T-07, Q-05)

Every event type with a schema (`schemas/events/<type>.schema.json`) and every shared lake table with
a schema (`schemas/ocsf/<table>.v1.json`) gets a publisher and a consumer contract test without
anyone writing one: `tests/events/test_contracts.py` and `tests/lake/test_table_contracts.py` are
parametrized from those directories (`homelabnext.events.contract`).

| Seam | Publisher test | Consumer test |
|---|---|---|
| event type | each example is rebuilt through `build_event` and published over HTTP to the loopback forwarder | the received bytes decode and validate, dispatch once, redelivery is a duplicate, an unknown extension is tolerated; every negative and every missing required `data` field is refused |
| lake table | each example row satisfies the table's JSON Schema and is written through the lake writer; every negative is refused | rows read back through the query interface carry exactly the schema's columns and normalise to the rows written; a replayed batch adds nothing |

`make contracts` (`tools/contract_coverage.py`, also in CI) runs them and fails, by name, for any
type or table without a passing `test_publisher_contract[<name>]` and
`test_consumer_contract[<name>]`. A skip is not a pass.

## Enrichment: asset owner and criticality (checklist T-04)

`homelabnext.events.enrich` builds an `AssetInventory` from the service registry and the guest
model (`AssetInventory.from_models(registry, guests)`) and `enrich_event` adds three extension
attributes: `assetid`, `assetowner`, `assetcriticality`. The asset is the event's `subject` when that
is an asset id, else the first known `host` entity in `data.entities`, else -- only when the event
names no target at all -- its `source`. An event naming a target the inventory does not know stays
unenriched rather than being attributed to its emitter. Criticality comes from tags (highest wins:
`secrets`/`identity` critical; `core`/`prod`/`hypervisor`/`storage`/`database`/`bus` high; `data`,
`compute`, `edge`, `monitoring` and friends medium; otherwise low), with per-asset `overrides`; a host
takes the highest of its guest and its services, and its owner is the guest's `owners.primary`, else
the single owner of its services. Values a publisher already set are kept. Enrich before publishing:
it changes the body, and the id is the idempotency key.

`enrichment_coverage(events)` is the metric (share of events carrying owner and a known criticality,
missing counts per type; an empty stream is not ok). The live >= 95% target is measured on the server
over an exported stream: `hnx events enrich-coverage events.jsonl [--min 0.95]`
(exit 0 at or above, 1 below, 100 nothing to measure; `--registry`/`--guests` enrich first).

## Deploys emit a what-changed event (checklist F-15)

`homelabnext.events.deploy` builds `homelabnext.deploy.changed` (component, from/to version,
environment, commit, and `changes` read from the changelog section of the new version, Keep a
Changelog headings). A version without a section, or a section that lists nothing, refuses the event.
The id derives from the deploy id, so a retried deploy step is a duplicate. The release workflow runs
`hnx events deploy-changed --component pkg:homelabnext --to <tag> ... --out sbom/deploy-changed.json`
(as `python -m homelabnext.cli events ...`: its build job does not install the project) and
attaches the event to the GitHub release; a lab deploy publishes it with
`--forwarder URL --state FILE` (or `emit_deploy_changed(publisher, ...)` from Python).
