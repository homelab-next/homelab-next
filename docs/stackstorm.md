<!-- SPDX-License-Identifier: Apache-2.0 -->
# StackStorm: when workflow packs run

A [workflow pack](workflows.md) ([[workflows]]) says *what* happens when an event arrives. StackStorm
decides *when*: it takes events from the bus and ticks from its own clock, filters them with rule
criteria, holds a burst back, and starts one run per admitted event. Everything a run changes goes
through the [broker](broker.md) ([[broker]]). StackStorm holds no credential for any target.

Command: `hnx workflows st2 render | check`. Library: `homelabnext.workflows.st2` (the renderer
and its checks) and `homelabnext.workflows.st2_runtime` (what a run executes). Binding:
`workflows/stackstorm.yml` (`schemas/workflows/stackstorm`). Rendered pack, committed:
`workflows/stackstorm/`. `make workflows` fails when that tree drifts from its inputs.

## Who owns what

| Concern | Owner | Here |
|---|---|---|
| When a pack runs: events, schedules, burst control, shadow or live | **StackStorm** | rules and CronTimers rendered from the binding |
| What a run does: the steps, in order, with the offline runner's semantics | **workflow pack** | `workflows/packs/`, pinned by digest in `workflows/deploy.yml` |
| Every effect, every approval, every audit record | **broker** | the actions in `workflows/broker.manifest.json`, called over its Unix socket |
| Agent sessions: queue, admission against live load, leases, failover, in-run retries (`max_attempts`) | **orchestration controller** | reached only through the broker action `agent.job.submit` |

StackStorm never runs an agent and never calls the controller. To run agent work it asks the broker
for `agent.job.submit`, and the broker's handler puts one job on the controller's queue. A burst of
events therefore becomes queued jobs that the controller admits at its own pace (the LL-399 burst
risk), never a burst of agent processes.

## How a pack maps

`hnx workflows st2 render` reads the binding, the deploy pins and the packs. It writes this tree:

| File | From | What it is |
|---|---|---|
| `homelabnext/pack.yaml`, `config.schema.yaml`, `requirements.txt` | the binding | the StackStorm pack (`st2_pack`, `version`) |
| `homelabnext/actions/admit.{yaml,py}`, `step.{yaml,py}` | fixed | the only two Python actions: shims over `st2_runtime.admit` and `st2_runtime.step` |
| `homelabnext/actions/<pack>.yaml` | each bound pack | an `orquesta` action with one string input: `event` (the encoded webhook body) or `fired_at` |
| `homelabnext/actions/workflows/<pack>.yaml` | each bound pack | task `admit`, then one task per pack step, in order. A task names its pack and step id; it never carries a step document, a mode or event data in clear. |
| `homelabnext/pinned/<pack>.json` | each bound rule | what the actions run: the pack document and its digest, the rule's `mode`, each step's risk, the coalesce window and the schedule |
| `homelabnext/rules/on_<pack>.yaml` | each bound rule | the trigger and criteria below; the one parameter is the encoded body |
| `configs/homelabnext.yaml` | the binding | the pack config: `broker_socket`, plus any `config` entries |
| `bridge.json` | the bound event types | the bus subjects the event bridge relays to the webhook |
| `provenance.json` | everything | the binding digest and, per pack, the pinned digest and mode |

**Triggers.** An event-triggered pack becomes a `core.st2.webhook` rule on `url: <webhook>`. Its
criteria are the pack trigger:

| Pack trigger | Rule criterion |
|---|---|
| `event: homelabnext.x.y` | `trigger.body.type` `equals` `homelabnext.x.y` (always present) |
| `{ref: $event.data.a, equals: v}` | `trigger.body.data.a` `equals` `v` |
| `{ref: $event.data.a, in: [..]}` | `trigger.body.data.a` `inside` `[..]` |
| `{ref: $event.data.a, exists: true/false}` | `exists` / `nexists` |
| `$event.data.list.0.kind` | `trigger.body.data.list[0].kind` |

Every event-triggered pack pins its producer: its `where` has `{ref: $event.source, equals: <id>}`
(`st2-source`), so the rule fires, and `admit` admits, only events that name that source. A01 takes
`svc:broker`, A02 `svc:orchestration`. The source is what the producer writes, not proof of who
sent it: who may post to the webhook (the bridge's API key) and publish the subject on the bus are
the bounds that make it mean something.

**What crosses StackStorm is encoded.** StackStorm renders every action parameter that contains
`{{` or `{%` with an unsandboxed Jinja environment: a datastore read (`st2kv ... decrypt_kv`), and
code on the action runner. Events carry text their producers do not control in full (a proposal's
title is any agent's that may file one). So:

- the rule's only parameter is `event: '{{ trigger.body | to_json_string | urlencode }}'`
  (`to_json_string` is st2's filter, `urlencode` Jinja's own): `{`, `%` and `<` arrive as `%XX`,
  whatever the event says, and rendering the result again changes nothing;
- `admit` decodes it in Python and hands the admitted event on encoded the same way
  (`st2_runtime.encode`); each step returns its outputs and calls as one encoded `state`. A
  workflow task's input is a literal or one of `<% ctx(event) %>`, `<% ctx(state) %>`,
  `<% ctx(fired_at) %>`; no event field is ever an expression;
- the broker refuses a records-inbox note whose front matter holds `{{`, `{%`, `<%` or `%>`
  (`lane-content-invalid`), so a proposal title never carries one in the first place.

`st2-template` checks the rendered tree for both: a rule parameter other than the encoded body
(or the CronTimer's `fired_at`), and a task input that is any other expression.

The `admit` task checks the event against its schema and re-checks the same trigger with the
offline runner's code, so the rule and the pack cannot disagree about what fires. A pack triggered by
`homelabnext.schedule.fired` instead takes a `schedule: {id, cron}` in its rule and becomes a
`core.st2.CronTimer` rule (UTC; day of week rendered as names, because cron counts 0 = Sunday and
the timer's scheduler counts 0 = Monday). A schedule may not restrict both day of month and day of
week (`st2-cron`): cron fires when either matches, the CronTimer's scheduler only when both do;
bind two schedules instead. `admit` builds the event from the firing. Its id derives
from the schedule and the firing time, so a timer that fires twice for the same time makes one event.
The pack's `where` must pin `$event.data.schedule` to that id.

**Steps.** `st2_runtime.step` takes a pack name, a step id, the encoded event and the previous
state. It loads `pinned/<pack>.json` from the installed pack, re-checks its digest, looks the step
up there and re-checks the event against the pack's trigger. The mode is the one the rule was
rendered with and the risk the manifest's; neither is a parameter, so `st2 run homelabnext.step`
can run only a pinned step, only in the mode it was promoted to. It runs the step exactly as
`hnx workflows run` does. A step whose `when`
does not hold is skipped. `enrich` `pick` and `extract-iocs` are computed. An `action` step builds the
broker request with the runner's own `action_request`. `lookup`, `decide` and `prompt` steps do not
run on StackStorm yet, and the renderer refuses a pack that has one (`st2-step`). The two packs that
use them (`new-critical-alert` and `phishing-report`) stay unbound until the runtime can reach the
table and decision services.

**Actions and approvals.** In `live` mode a risky action goes to the broker as `submit`. Risky means
the manifest gives it tier `execute` or `privileged`, or sets `requires_approval`. The broker holds
the request and emits `homelabnext.decision.requested`, and the run ends `held`. Any other action is
a `call`, and the broker decides it as usual (`executed` or `denied`). The approval and its digest
binding are the broker's ([ADR-0017](adr/0017-broker-service.md)). StackStorm inquiries
(`core.ask`) are not used.

## The first two automations

| Id | Pack | Trigger | Does | Replaces |
|---|---|---|---|---|
| A01 | `proposal-validate` | `homelabnext.proposal.created`, which the broker emits when a note is filed through the records-inbox lane (`proposal.file`) | `agent.job.submit` of one `proposal-validator` job, the event id as idempotency key | the proposal-validator dispatch timer |
| A02 | `agent-job-retry` | `homelabnext.agent.job.failed` with `reason` in capacity, stall, timeout, backend-down and `resubmits` = 0 | `agent.job.submit` again, at priority 90, with `retry_of_run_id` | ad-hoc reruns of failed jobs |

`homelabnext.agent.job.failed` (`schemas/events/agent.job.failed.schema.json`) is the contract
proposed for the controller's `agent.job.*` events. `resubmits` counts the whole-job resubmits in a
run's `retry_of_run_id` lineage. The controller sets it from the parent run, so A02's trigger bounds
the chain: a resubmitted job that fails again has `resubmits: 1`, and A02 does not fire. Retries
inside one run stay the controller's (`max_attempts`). Failures the controller decided on purpose
(deadline, cancel, turn cap, budget) never match.

**Bounds the renderer enforces:**

- `st2-coalesce`: a rule whose pack dispatches agent work has a coalesce window.
- `st2-bound`: a pack that reacts to `agent.job.failed` by dispatching pins `$event.data.resubmits` to
  integers below 3, and carries `retry_of_run_id: $event.data.run_id`.

## Redeliveries

A StackStorm webhook starts one run for every POST and ignores an `Idempotency-Key` header, and the
event bridge delivers at least once (a POST that timed out after StackStorm took it is sent
again). So `admit` drops an event id it has already taken for the same pack: it remembers the id
in the datastore (`homelabnext.seen.<hash of pack and id>`) for a day, or for the coalesce window
when that is longer, and a second delivery ends its run `duplicate` before any step runs. A
CronTimer that fires twice for the same time builds the same event id, so it is one run too. The
bound that holds when two deliveries race inside the same instant is the same as for coalescing
(below): the controller's idempotency key.

## Coalescing bursts

`coalesce: {key, window_s}` on a rule. The first event of a key opens a window. That is a datastore
key `homelabnext.coalesce.<hash of pack and key>` with TTL `window_s`. Every later event of the key
inside the window ends its run `coalesced`, before any step runs, and records which event it was
folded into. A02 keys on `$event.data.agent_key` with a ten-minute window. When a backend goes down
and fails every running job of an agent at once, A02 makes one resubmit, not one per failure. A01
keys on `$event.data.proposal_id`, so a redelivered event is a no-op. The datastore key also
hashes the event's `source`, and an event from another producer is `not-triggered` before the
datastore is touched, so it opens no window.

A forged event that names the right source can still open a window and fold the genuine one into
it (an A02 resubmit lost for ten minutes). StackStorm cannot tell the two apart: it does not ask
the controller whether `run_id` failed. The bounds are outside it, and the controller must hold
them: the bridge's webhook-only API key and the bus's publish permissions decide who can inject an
event, and the controller must refuse a submit whose `retry_of_run_id` is not one of its own runs
that failed with `resubmits` 0, whatever the event said. Until it does, A02's cap is the trigger's
and is only as good as the event.

The StackStorm datastore has no compare-and-set, so two events in the same instant can both pass
the window. Two things still hold in that case:

- the controller's idempotency key (the event id), so a redelivered event cannot queue twice;
- the trigger's `resubmits` cap, so a race costs at most one extra queued job and never a loop.

This is leading-edge debounce. Batching (one job that carries every event of the window) needs the
controller's job input to take a list, and is not built yet.

## Shadow, then live

Every rule ships with `mode: shadow`. A shadow run does everything up to the broker: it admits,
coalesces, evaluates every step and builds each broker request. It then records the request with
result `shadow` (reason `st2-shadow`), together with its `request_id` and `request_digest`, and
**sends nothing**. Shadow mode never opens the broker socket. The id and digest are the ones `hnx
workflows run PACK` prints for the same event, so a shadow log can be compared line by line with
the offline fixtures and with what the timer it replaces actually did (the parity method of
[swap.md](swap.md), [[swap]]). The mode is in `pinned/<pack>.json`, rendered from the rule, so a
run started by hand is in the rule's mode too: no parameter turns a shadow rule live.

To promote a rule, change `mode: live` in `workflows/stackstorm.yml` and add:

```yaml
promotion: {shadow_from: "2026-01-01", live_from: "2026-01-08", evidence: docs/parity/a02.md}
```

`st2-live` requires a shadow window of at least 7 days and evidence that git tracks: the parity
comparison that justified the change. Re-render and commit the tree in the same change. Retire the
timer that the rule replaces only after the rule has run in shadow beside it and matched it.

## Secrets

The pack's actions talk only to the broker's Unix socket. The broker takes the caller from the
peer's credentials (the manifest maps the StackStorm runner's user to the binding's `actor`), so the
pack needs no token. A `config` entry is a literal (`{value: ...}`) or a datastore key
(`{st2kv: name}`). A datastore key is rendered as `{{ st2kv.system.<name> | decrypt_kv }}` and marked
`secret: true` in `config.schema.yaml`. `st2-secret` refuses a literal under a name that looks like a
secret. The event bridge's StackStorm API key appears only as a secret-store name
(`bridge_api_key: secret:stackstorm/webhook-key`). It belongs to a StackStorm user whose RBAC role
can only post webhooks.

**Who may run the pack's actions.** Turn StackStorm RBAC on (`[rbac] enable = True`, backend
`default`). Rules run their actions as the system user (`stanley` by default); give that user, and
only it, `action_execute` on the `homelabnext` pack's actions (a role with
`resource_uid: pack:homelabnext`, permission `action_execute`). Operators get `action_view` and
`execution_view` for the shadow logs, never `action_execute` there; the bridge's user gets
`webhook_send` and nothing else. Without RBAC every authenticated user can `st2 run
homelabnext.step` with an event of their own. The step still runs only pinned steps in their pinned
mode, and the broker still decides, but the event is theirs.

**Handlers.** Every broker action a bound pack calls has its handler in the tree, pinned
(`st2-handler`): `agent.job.submit` is `workflows/handlers/agent-job-submit.sh`, with
`agent-job-submit.handler.json` beside it naming its digest. It posts the validated params to the
controller's `POST /jobs`, whose URL the broker resolves by name like a secret
(`ORCHESTRATOR_JOBS_URL`), so no endpoint is in the tree.

No literal in a bound pack may contain `{{`, `{%` or `<%` (`st2-template`). StackStorm renders
those in criteria, parameters and Orquesta inputs, so a literal would become an expression. Event
data never reaches them in clear (above).

## Installing the rendered pack

On the StackStorm host (3.8 or later; the official production minimum is 16 GB and 4 cores):

```bash
git checkout <a commit on main whose CI passed>    # the same rule as docs/workflows.md
hnx workflows validate && hnx workflows st2 check
sudo cp -r workflows/stackstorm/homelabnext /opt/stackstorm/packs/
sudo cp workflows/stackstorm/configs/homelabnext.yaml /opt/stackstorm/configs/
sudo st2 run packs.setup_virtualenv packs=homelabnext   # creates the pack's virtualenv
sudo /opt/stackstorm/virtualenvs/homelabnext/bin/pip install '.[core]'   # this checkout, not PyPI
sudo st2ctl reload --register-all
st2 key set homelabnext.<name> <value> --encrypt         # only for config entries with st2kv
```

Install `homelabnext` into the pack's virtualenv from the same checkout, so the runtime and the
rendered steps come from one commit (`provenance.json` names the digests). Then run the event
bridge. It is a durable bus consumer per entry of `bridge.json` (subject `homelabnext.<type>` under
the stream prefix). It POSTs each envelope as `application/json` to the webhook with the
`St2-Api-Key` header, acks on 2xx, and naks on 5xx or 429. StackStorm's webhook does not take
`application/cloudevents+json`.

## Checks

`hnx workflows st2 check`, rule by rule (the module docstring has the full list):

| Rule | Fails when |
|---|---|
| `st2-binding` | the binding is not schema-valid |
| `st2-pin` | a bound pack is not pinned at the digest of the pack in the tree, or does not validate |
| `st2-duplicate` | a pack or a schedule id is bound twice |
| `st2-actor` | a bound pack's `actor` is not the binding's `actor` |
| `st2-step` | a step does not run on StackStorm (`lookup`, `decide`, `prompt`) |
| `st2-template` | a literal holds `{{`, `{%` or `<%`; a rendered rule passes anything but the encoded body (or `fired_at`); a task input is an expression other than the encoded `event`, `state` or `fired_at` |
| `st2-source` | an event-triggered pack does not pin `$event.source` to one producer |
| `st2-handler` | an action a bound pack calls has no handler file in the tree, or none whose `handler.json` digest matches |
| `st2-trigger`, `st2-cron` | a schedule does not match its pack's trigger, is not five valid fields, or sets both day of month and day of week |
| `st2-live` | a live rule has no promotion, too short a shadow window, or untracked evidence |
| `st2-coalesce`, `st2-bound` | agent dispatch without a window, or job-failed retries without a cap |
| `st2-secret` | a secret-like config key holds a literal |
| `st2-shape` | a rendered document lacks a field StackStorm requires, uses a task action that is not a shim, or a runner other than `python-script` or `orquesta` |
| `st2-criteria` | a webhook rule does not test `trigger.body.type` for one event type (it would match everything) |
| `st2-drift` | the committed tree differs from the rendered one |

The required fields are encoded from st2 3.8.1's `st2common` API models (pack, action, rule), its
trigger parameter schemas (webhook, CronTimer) and the Orquesta native spec. `st2common` itself is
not a dependency. `tests/workflows/test_workflows_st2.py` evaluates every rendered rule's criteria,
with a transcription of st2's rule filter and operators, against every event example and fixture in
the repository. A rule must fire for exactly the events its pack triggers on. The test also asserts
that a rule with its type criterion removed fires on all of them, which is the failure
`st2-criteria` exists for.

Not checked offline: that the Orquesta files pass `orquesta`'s own inspector, because that would add
a dependency. They pass it with orquesta 1.6.0, and its conductor runs the A02 workflow through both
the admitted and the coalesced path.
