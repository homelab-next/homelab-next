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
