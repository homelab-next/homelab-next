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
| `decision.requested` / `decision.returned` (1.1) | `homelabnext.decision.requested` / `.returned` (1.1 adds `tier_used: agent`, an approval by an agent approver the broker manifest admits) |
| `scope.denied` | `homelabnext.scope.denied` (a writer tool was refused for an out-of-scope target; `docs/scope.md`) |
| `deploy.changed` | `homelabnext.deploy.changed` (a component was released or deployed: versions and the changelog's changes; `homelabnext.events.deploy`, checklist F-15) |
| `status.observed` | `homelabnext.status.observed` (one status observation, `schemas/status/observation.schema.json`; collectors publish it, the status hub consumes it: `docs/status.md`, ADR-0013) |
| `agent.activity` | `homelabnext.agent.activity` (one agent activity event, summary tier only: `schemas/status/agent_activity.schema.json`; the detail tier never goes on the bus: `docs/status.md` section 6) |
| `project.changed` | `homelabnext.project.changed` (a project, step or task changed: one event per item version, id from `<uid>:v<n>` or `wp:<id>:v<lockVersion>`; `docs/projects.md`, ADR-0020) |
| `agent.job.failed` (1.1) | `homelabnext.agent.job.failed` (an agent job in the orchestration controller's queue failed for good: run id, agent key, failure `reason` (= the controller's `failure_class`), `resubmits` in its retry lineage; 1.1 adds `failure_class`, `retried_by_run_id` once retried, `auto_retry_scheduled` and `profile_revision_drift` only when true; source `svc:llm-orchestrator`; StackStorm's A02 resubmits it, bounded: `docs/stackstorm.md`) |
| `schedule.fired` | `homelabnext.schedule.fired` (a named schedule fired; a StackStorm CronTimer builds it, id from schedule and time; a scheduled workflow pack triggers on it: `docs/stackstorm.md`) |
| `swap.step` (1.1) | `homelabnext.swap.step` (steps 1..9 of the swap procedure; 1.1 adds the nine step names of the swap record, `homelabnext.swap.events` builds them from a record) |

Envelope: `specversion` (`"1.0"`), `id` (idempotency key; redelivery of the same id is harmless),
`source` (a `svc:`/`cap:`/`profile:` logical id, never a URL), `type`, `time` (RFC 3339), optional
`subject`, `severity`, `datacontenttype`, `dataschema`, `correlationid`, and `data` (object).
Extension attribute names are lower-case alphanumeric (CloudEvents rule), so new ones are additive.
Enrichment (`homelabnext.events.enrich`) sets three declared, optional extensions: `assetid`
(`svc:`/`guest:`/`host:` id), `assetowner` (team slug) and `assetcriticality`
(`low`|`medium`|`high`|`critical`).

Every type here gets a publisher and a consumer contract test automatically
(`tests/events/test_contracts.py`, parametrized from this directory); `tools/contract_coverage.py`
fails the build when a type has no passing pair, so a new type needs at least one example and one
negative to land.

Each type schema is `allOf [envelope, {type: const, data: ...}]`: a publisher sample must satisfy both.
Detections are referenced by `det:` id, never by an engine rule number; evidence tables by `table:` id.
Evolution is additive within a major version (see `tools/schema_check.py`).
