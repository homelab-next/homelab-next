# schemas/events

A CloudEvents 1.0 compatible envelope plus the event types of the **reaction seam** (the chain from
detection to decision to swap). Other event families are added later as separate files.

| Schema | Type (`type` field) |
|---|---|
| `envelope.schema.json` | any event |
| `alert.created` | `homelabnext.alert.created` |
| `case.opened` | `homelabnext.case.opened` |
| `proposal.created` / `proposal.decided` | `homelabnext.proposal.created` / `.decided` |
| `task.queued` | `homelabnext.task.queued` |
| `decision.requested` / `decision.returned` | `homelabnext.decision.requested` / `.returned` |
| `scope.denied` | `homelabnext.scope.denied` (a writer tool was refused for an out-of-scope target; `docs/scope.md`) |
| `swap.step` (1.1) | `homelabnext.swap.step` (steps 1..9 of the swap procedure; 1.1 adds the nine step names of the swap record, `homelabnext.swap.events` builds them from a record) |

Envelope: `specversion` (`"1.0"`), `id` (idempotency key; redelivery of the same id is harmless),
`source` (a `svc:`/`cap:`/`profile:` logical id, never a URL), `type`, `time` (RFC 3339), optional
`subject`, `severity`, `datacontenttype`, `dataschema`, `correlationid`, and `data` (object).
Extension attribute names are lower-case alphanumeric (CloudEvents rule), so new ones are additive.

Each type schema is `allOf [envelope, {type: const, data: ...}]`: a publisher sample must satisfy both.
Detections are referenced by `det:` id, never by an engine rule number; evidence tables by `table:` id.
Evolution is additive within a major version (see `tools/schema_check.py`).
