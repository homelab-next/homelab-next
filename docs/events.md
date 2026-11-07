---
summary: 'The event seam: what goes on the bus, the envelope, validation, the idempotent publisher, forwarder contract, consumers, contract tests, deploy events.'
summary_of: outline:sha256:5032ecc0072ea895
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Events: envelope, validation and the idempotent publisher

`homelabnext.events` is the client side of the event seam. Schemas: `schemas/events/` (a
CloudEvents 1.0 compatible envelope plus the reaction-seam types).

* **Publishers do not speak the bus.** They hand the envelope to a *forwarder* over HTTP
  (`HttpForwarder`); what sits behind the forwarder (a broker, a queue, a file) is its business.
  The one exception is a transactional outbox relay, which publishes through the `EventBus`
  protocol (`conformance/protocols/events.py`): the broker's `hnx broker relay`
  ([docs/broker.md](broker.md#publishing-events-the-outbox-relay)). ADR-0009 names both paths;
  the event id is the idempotency key on each.
* **`build_event` / `validate_event`** check the envelope and, when one exists, the per-type schema
  (`homelabnext.task.queued` -> `schemas/events/task.queued.schema.json`). Unknown types are checked
  against the envelope only.
* **The `id` is the idempotency key.** `derive_event_id(type, source, dedupe_key)` makes it a pure
  function of the event's identity, so the same occurrence always has the same id.

## What goes on the bus

ADR-0009 allows three classes of event on the bus: **reaction** triggers (something reacts to the
occurrence), per-item **record**s (one low-volume event per item or item version, never a metrics
or log stream) and **decision** events. Telemetry stays direct (collector to lake) and control
stays typed RPC. Every type under `schemas/events/` has its class here
(`tests/events/test_bus_publish_paths.py` fails on a type without one):

| Type | Class |
|---|---|
| `homelabnext.alert.created` | reaction |
| `homelabnext.case.opened` | reaction |
| `homelabnext.task.queued` | reaction |
| `homelabnext.schedule.fired` | reaction |
| `homelabnext.deploy.changed` | reaction |
| `homelabnext.scope.denied` | reaction |
| `homelabnext.swap.step` | reaction |
| `homelabnext.agent.job.failed` | reaction |
| `homelabnext.agent.activity` | record |
| `homelabnext.agent.job.finished` | record |
| `homelabnext.project.changed` | record |
| `homelabnext.status.observed` | record |
| `homelabnext.decision.requested` | decision |
| `homelabnext.decision.returned` | decision |
| `homelabnext.proposal.created` | decision |
| `homelabnext.proposal.decided` | decision |

Since envelope 1.2 an event may carry its TLP label (ADR-0033) in the optional `tlp` extension
attribute (one of the five canonical spellings) and the ids of its inputs in `derivedfrom`;
`build_event(..., label=, derived_from=)` writes them and `event_label` reads them, an absent or
unreadable label as `red`. No producer labels its events yet, so every event still reads `red` to
a TLP check, and the bus is an egress point whose content is not yet checked (`docs/modules.md`,
the egress table): a subscriber can now compute a ceiling from the event, but nothing filters on it.

## Publisher protocol

```python
pub = Publisher(HttpForwarder("https://events.example.invalid/ingest"), StateStore("events.json"))
result = pub.publish(build_event("homelabnext.task.queued", "svc:siem", data, dedupe_key="job-17"))
pub.flush()  # resend anything still pending (after an outage or a crash)
```

1. validate (an invalid event is refused before any I/O);
2. write the event to the state file as `pending` (write-ahead);
3. send; transient failures (network, 5xx, 429, timeout) back off exponentially, bounded by
   `RetryPolicy(max_attempts, base_s, factor, max_s)`; a forwarder answer that blames the
   configuration (401/403/404/421, or a 3xx, `MisconfiguredError`) stops the loop at once but
   leaves the event `pending`, so a rerun, `flush` or `hnx events flush` delivers it once the URL
   or credential is fixed; a permanent failure (other 4xx, id collision) marks the event `rejected`. A rejected
   record is kept for the retention (`--retain-hours`, then removed) and `hnx events requeue
   --state FILE` makes the rejected ones pending again;
4. only an acknowledgement moves it to `sent`.

If the process dies between "the forwarder stored it" and "the publisher recorded the ack", the
record is still `pending`; the next `publish` or `flush` sends the *same id* again, the forwarder
answers *duplicate*, and the publisher marks it sent. On the wire that is at-least-once; in effect
it is exactly-once. Re-publishing a `sent` id makes no call at all, and the same id with different
content is refused.

## Forwarder contract (what `HttpForwarder` expects)

`POST` with `Content-Type: application/cloudevents+json` and `Idempotency-Key: <id>`.
`200/201/202/204` accepted (`{"duplicate": true}` in the body when already held), `409` id
collision (permanent), `408/425/429/5xx` retry, `401/403/404/421` retry after a configuration fix
(the event stays pending), other `4xx` permanent. A `3xx` is a configuration fault too: the
event stays pending. No sender follows a redirect (`HttpForwarder` and the controller's sender
follow none, and a write through `homelabnext._http.safe_urlopen` follows none either), because
urllib would resend the POST as a GET with no body and a `2xx` to it would read as delivered.

The CLI sends a credential with `--auth secret:<name>` (value from `HNX_SECRET_<NAME>` or a file in
`--secrets-dir`; the value is the whole `Authorization` header value) on `deploy-changed` and
`flush`. The secret must hold the full `Authorization` value, scheme included (for example
`Bearer ...`); a value with a control character is refused without being printed, and the event
stays pending. `--auth` takes only a canonical secret reference (`secret:<name>`, lowercase
segments of letters, digits, `_` and `-` joined by `/`, as in `secret:events/broker`); a nested
name is a subdirectory of `--secrets-dir`, and a name that resolves outside it (absolute, `..`, or a
symlink pointing out) is not read. A secret file that cannot be read or is not UTF-8 is a
misconfiguration like a missing one: the event stays pending and only the error's class is
reported.

`requeue` works only within `--retain-hours` of the refusal (rejected records are then pruned, and
they hold the only stored copy of the event); `requeue` itself sends and prunes nothing, so it takes
no `--retain-hours`. Pending records are never pruned, so a forwarder
that stays misconfigured grows the state file by one record per deploy until it is fixed.

## Testing

`FakeForwarder` records what it accepted and can fail before storing (`fail_next`), store then lose
the acknowledgement (`lose_ack_next`) or refuse (`reject_next`). `FakeForwarderServer` puts the same
fake behind a loopback HTTP server so the HTTP adapter is exercised for real. Nothing needs a
network beyond loopback: `pytest tests/events`.

The `homelabnext.scope.denied` event (a writer tool was refused) is described in `docs/scope.md`.
The `homelabnext.status.observed` event (one status observation, consumed by the status hub) is
described in `docs/status.md`. Stage 2, library only: `StatusHub.ingest_event` accepts it, but
no `hnx` command, collector or service publishes or consumes it yet, so a `push-event` source
reads stale until that is wired (see the developer follow-up in `docs/status.md`).
`homelabnext.agent.activity` (an agent activity event, summary tier only) is described there too. The
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
the single owner of its services. Values a publisher already set are kept; a publisher-set
`assetid` names the asset, so the owner and criticality come from it (or stay unset when the
inventory does not know it), never from another asset. Enrich before publishing:
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
