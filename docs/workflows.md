---
summary: 'Workflows as code: the YAML workflow pack, what hnx workflows validate checks, and deploying only pinned digests from passing commits.'
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Workflows as code

A reaction workflow - "a critical alert arrives: find the owner, decide whether to page, open a
case" - is a **workflow pack**: one YAML file in git, validated offline in CI, deployed only by
digest from a passing commit. Contract: `schemas/workflows/` (`pack`, `deploy`). Library:
`homelabnext.workflows`. Command: `hnx workflows validate | run | digest`. Shipped packs:
`workflows/packs/`; the broker manifest they act through: `workflows/broker.manifest.json`; the
deploy pins: `workflows/deploy.yml`.

StackStorm runs the pinned packs on events and schedules: [stackstorm.md](stackstorm.md)
([[stackstorm]]), `hnx workflows st2 render | check`.

Checklist rows: R-01 (workflows are code), R-03 (deterministic steps first), R-04 (risky actions
need bound approval), R-07 (fixtures round-trip). R-02, R-05 and R-06 need the running
orchestrator (SERVER); the `orchestration` conformance suite covers the job-runner contract a real
adapter maps packs onto.

## The pack

```yaml
pack: new-critical-alert               # unique slug
version: 1
trigger:
  event: homelabnext.alert.created     # an event type with a schema in schemas/events/
  where: [{ref: $event.data.severity, equals: critical}]
actor: profile:workflow-soc            # the broker identity every action request is made as
broker_manifest: workflows/broker.manifest.json
steps:                                 # run in order; `when` skips a step (its output is null)
  - {id: hosts, kind: enrich, op: pick, from: $event.data.entities, match: {kind: host}, field: value}
  - {id: owner, kind: enrich, op: lookup, table: table:cmdb.asset_owners, key: $steps.hosts.first}
  - {id: classify, kind: decide, spec: critical-alert-page, input: {title: $event.data.title, owner_team: $steps.owner.row.team}}
  - {id: page, kind: action, action: notify.page, target: svc:notify,
     when: [{ref: $steps.classify.label, equals: accept}], params: {rota: $steps.owner.row.oncall_rota}}
fixtures: [...]
```

| Step kind | What it is | Output |
|---|---|---|
| `enrich` `pick` | field values of the objects in a list that match `match` | `{values, first, count}` |
| `enrich` `lookup` | one row of a `table:` by key (live: the table; offline: the fixture's `lookups`) | `{key, found, row}` |
| `enrich` `extract-iocs` | URLs, their host names, IPv4 addresses, sha256 hashes in text; defanged forms refanged; nothing invented | `{urls, domains, ipv4, sha256, count}` |
| `decide` | a decision spec (`homelabnext.decide`) tracked in git, by `id` | `{label, confidence}` |
| `prompt` | a prompt template (`homelabnext.agent.template`), every required slot bound | the template's JSON reply |
| `action` | one broker action: a request `{action, actor, target, params}` | executed / held / denied / shadow |

A string starting with `$` is a reference - `$event.<path>` or `$steps.<id>.<path>`, a number
indexes a list, a missing part is `null`; `$$` escapes a literal `$`. A step may only read
earlier steps.

A **fixture** is an event plus everything the outside world would have answered: `lookups`
(table -> key -> row), `model` (step id -> the model's output), `approvals` (broker approval
records), an optional `now`, and `expect` - whether the pack triggers and the exact action calls,
in order (`action`, `target`, `params`, `result`; `reason` and `step` when given).

## What `hnx workflows validate` checks

Every pack git tracks (outside `schemas/`, `negative/`, `_frozen/`), offline. The rules and their
names are in the module docstring of `homelabnext/workflows/validate.py`; in short:

- **R-01, references resolve.** Schema-valid; the trigger's event type has a schema; every
  decision spec, prompt template and broker action exists; the pack's actor holds a grant for
  each action at its tier; references name earlier steps; a *trusted* template slot is bound to a
  literal, never to event or step data (G-01). An untracked pack fails `in-git`.
- **R-03, deterministic steps first.** A pack with a `decide` or `prompt` step runs an
  unconditional `enrich` step before the first one (`deterministic-first`), and every model step
  reads some earlier enrich step's output (`model-input`). A risky action takes no parameter from
  a prompt step's free text (`risky-params`): what it acts on comes from the event or a
  deterministic step - the phishing pack blocks the domains `extract-iocs` found in the message,
  not the URLs the model echoed.
- **R-07, fixtures round-trip.** Each fixture event is valid for its type and runs through
  `run_fixture`: deterministic steps are computed, model steps return the fixture's output (a
  decide label must be one its spec can return), actions go through the broker. The calls must
  equal `expect` exactly. A model output for a step that never ran, a missing one, or an approval
  for a request the run never made is a stale fixture and fails.
- **R-04, risky actions need bound approval.** Risky = the broker manifest gives the action tier
  `execute`/`privileged` or `requires_approval`. Action steps execute through `BrokerExecutor`,
  which asks `homelabnext.broker.decide`; only an enforced `allow` runs the (fake) handler. Each
  risky step must execute under approval in at least one fixture (`risky-untested`); for each such
  fixture the validator re-runs it without the approval (must be `held`) and with the action's
  payload altered after approval (must not execute) - `approval-binding`. The table test in
  `tests/workflows/test_workflows_approval.py` also covers another request's approval, denial,
  unlisted approver, self-approval, expiry and replay, and three mutant executors that it and the
  validator both catch.

Fixture approvals carry the `request_id` and `request_digest` of the request they approve; `hnx
workflows run PACK [--fixture NAME]` prints both for every call. Copying a digest from that
output *is* the act of approving that payload; if the pack later changes what it sends, the
fixture fails until someone approves the new payload.

## Deploying: only pinned digests from passing commits

`pack_digest(pack)` is the sha256 of the canonical JSON of the whole pack, fixtures included
(comments and key order do not change it). `workflows/deploy.yml` (`schemas/workflows/deploy`)
pins each deployable pack to one digest. `hnx workflows validate` fails when the deploy manifest
is untracked, a pin names a missing pack or names one twice, a pin's digest differs from the pack
in the tree, or a pinned pack does not validate. To change a deployed pack: edit it, run
`hnx workflows digest workflows/packs`, update its pin in the same commit.

The deployer (SERVER; the orchestrator adapter) follows one rule that is not checkable offline:
it deploys from a commit on the protected main branch whose CI `schemas` job (which runs
`hnx workflows validate`) passed, re-runs `hnx workflows validate` itself on that checkout, and
loads only packs whose digest - recomputed from the file it loads - equals the pin. A pack that is
not pinned is not deployed, however valid. Nothing is deployed from a working tree, a branch or a
file that is not in git.
