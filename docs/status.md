<!-- SPDX-License-Identifier: Apache-2.0 -->
# Status hub: one read-only place for activity and status

The status hub (`homelabnext.status`, `hnx status`, [ADR-0013](adr/0013-status-hub.md)) is the
primary UI: a main page and a left-side menu of views over every registered source of status. It
**observes and never acts**: anything that changes something is a link to the broker or the
approval path. It does not need agents, the broker or an agent dashboard; each of those is an
optional source or an optional menu entry.

Stage 1 (this page) is everything that can be proven without a server: the registry format, the
menu, the observation and event shapes, the collector framework with built-in collectors for what
this repository already has, the state service, the views and the page. Stage 2 adds product
collectors (an uptime monitor, metrics queries, the orchestrator, an automation engine, a dataflow
tool, the agent dashboard) tested in the lab-in-a-box; each is a mapping or a collector, nothing
else changes.

## 1. Register a source (the menu)

A service declares what it can tell the hub (`schemas/platform/service.json` 2.1):

```yaml
services:
  metrics:
    # ...
    status_sources:
      - id: metrics-alerts           # unique; graph node status:metrics-alerts
        kind: poll-http-json         # poll-http-json | poll-file | push-event | poll-prometheus (stage 2)
        target: {path: /api/v1/alerts}   # service defaults to this one; never an address
        interval_s: 60
        timeout_s: 10                # < interval_s
        # stale_after_s: 180         # default 3 x interval_s, >= interval_s
        # on_error: unknown          # or fail: a failed poll IS the reading (liveness probes)
        mapping:
          items: $.data.alerts[*]
          item: labels.alertname
          state: state
          states: {firing: fail, pending: warn, inactive: ok}
          summary: annotations.summary
        what: Every alert rule the metrics service evaluates; firing is fail, pending is warn.
```

`hnx registry validate` refuses a raw address anywhere in a source, a target that is not a
registered http(s) service, `timeout_s >= interval_s`, `stale_after_s < interval_s`, a duplicate
id, a polled kind without a mapping, and a target the kind cannot use. `hnx status sources` lists
the menu; [`docs/status/sources.md`](status/sources.md) ([[status/sources|status sources]]) is
generated from it (`hnx status catalog generate`, checked by `hnx status catalog check` in
`make gates`).

| Kind | Reads | Target |
|---|---|---|
| `poll-http-json` | `GET` the service's capability alias + `path`, 2xx JSON | `service` (default: the declaring one), `path` |
| `poll-file` | a JSON or YAML file, or a records directory, under the status root (`--root`) | `file` (relative, no `..`) |
| `push-event` | `homelabnext.status.observed` events the source publishes itself | none: silence for `stale_after_s` reads stale |
| `poll-prometheus` | reserved for stage 2; reads `unknown` until its collector ships | `service`, `path` |

### Mappings

Declarative selectors are a small JSONPath-like path: optional `$`, keys joined by `.`, `[*]`
(or `*`) for every element or value, `[N]` for one element; `@key` is an item's key in a
mapping. `items` selects the items (absent: the whole payload is one item named after the
source); `item`, `state` and `summary` are relative to each item. The raw state (lower-cased text;
`true`/`false` for booleans) is looked up in `states`; a value that is already a state word passes
through; **anything else is `unknown`, never `ok`**.

Built-in mappers for sources this repository has:

| `builtin` | Payload | Items |
|---|---|---|
| `invariants-results` | the invariants runner's results document | one per criterion: pass ok, fail fail, error and skip unknown; link `inv:<id>` |
| `records-lanes` | a records root (`homelabnext.records`) | `inbox`, `approved-not-completed`: live-work counts with the oldest age, warn past `warn_after_s` |
| `broker-pending` | broker requests awaiting approval (a list or `{"requests": [...]}`), or a `PendingApprovals` store in process | `pending-approvals`: a live-work count with the oldest age |

## 2. Collect

`hnx status collect [--all | --source ID ...]` runs one pass over the due sources (or every, or the named ones) and writes the state file
(`--state`, default `build/status/state.json`, a `homelabnext.state.StateStore`). Each source runs
in its own thread under its own `timeout_s`: a pass takes at most the longest timeout, and a hung
or raising source is an error for itself only. A source whose previous poll is still running is
not started again (no thread pile-up). `--notify-topic T` pages transitions through the
registry's `notify` service.

The hub keeps the latest observation per `(source, module, item)` and a bounded history of state
transitions. An item a successful poll no longer lists is removed (a resolved alert disappears
rather than going stale). **Staleness is computed at read time** from `expires_at`
(`observed_at + stale_after_s`): a reading past it is `stale` whatever it said, and a source with
no successful read inside its window is `stale` itself (`unknown` if it has never been read).

Notifications use the shared state-diffed `Notifier` (checklist O-08): one key per item and per
source, `fail` and `stale` page, everything else reports ok, so each transition into or out of a
paging state sends exactly one message. A stale source pages once under its own key and its
items are held (no flood, no false recovery); a paged item that disappears sends its recovery.

Library use, offline (what the tests do):

```python
hub = StatusHub(specs, StateStore(path, clock=clock), clock=clock)
ctx = CollectContext(clock=clock, http=fake_http, endpoint=lambda svc: base_url, root=checkout)
for result in Scheduler().run(due(specs, hub.last_attempts(), clock()), ctx):
    hub.record(result)
hub.ingest_event(body)  # a pushed homelabnext.status.observed event
hub.notify(notifier)  # state-diffed, transitions only
hub.publish(publisher, observations, "svc:metrics")  # onto the bus (homelabnext.events)
```

## 3. Views (`examples/status/views.yml`)

```yaml
views_version: 1
shell: {title: Northwind status, main: overview}   # optional act_via: {service: ...}
menu:
  - {id: overview, title: Overview, panel: exceptions}
  - {id: modules, title: All modules, panel: grid}
  - {id: governance, title: Proposals and approvals, panel: grid, select: {sources: [proposals, approvals]}}
  - {id: sources, title: Sources, panel: sources}
  - {id: grafana, title: Grafana, external: {service: dashboards}}
  - {id: agentmetry, title: Agentmetry, external: {service: agentmetry, optional: true}}
```

Schema: `schemas/status/views.schema.json`; `hnx status views check` also checks the menu ids are
unique, `main` is a panel view, a `select` names registered sources and modules, and an external
entry names a registered service unless it is `optional` (then it is shown as unavailable). An
external link is built from the registry: the service's public hostname, else its capability
alias. Panels:

- **exceptions** (O-05): the green count, the live work (items with `work` and a non-zero
  `value`) and the attention items (everything not `ok`, worst first, plus sources not `ok` that
  have no items to show it). With everything healthy that is one green number and the live work.
- **grid** (O-02): one tile per module with its worst state, its counts, the items that are not
  ok, and links to its service page and, where one exists, its capability contract page.
- **sources**: the source table: state, kind, module, interval and staleness, last good read,
  error, what it reports.

## 4. The page and `status.json` (the contract)

`hnx status render --out DIR [--now TIME]` writes `index.html` (self-contained: inline CSS, no
script, no CDN; the menu switches views with `#view-<id>` anchors and CSS `:target`) and
`status.json`. The same input renders the same bytes. `hnx status serve` answers the same two
documents live (`/`, `/index.html`, `/status.json`), **GET and HEAD only** (every other method is
405), building each response from the state file only, so no source can stall it (O-07). It binds
loopback; another address needs `--allow-remote` and belongs behind the forward-auth proxy.

`status.json` is the API; the HTML is one rendering of it. Shape (`schema:
homelabnext.status/1`, additive evolution):

| Key | Shape |
|---|---|
| `schema`, `generated_at`, `title`, `main` | strings; `main` is the main view id |
| `act_via` | the link for changes (broker/approval path) or `null` |
| `summary` | `{total, ok, warn, fail, unknown, stale}`: item counts by effective state |
| `menu` | `[{id, title, kind: panel, panel, available}]` or `[{id, title, kind: external, service, href, available}]` |
| `views` | `{<view id>: panel payload}`: `exceptions` `{panel, ok, total, live, attention}`; `grid` `{panel, modules}`; `sources` `{panel, sources}` |
| `modules` | `[{module, state, counts, service, capability, sources, links, items}]`; `links` holds `svc:`/`cap:` ids and docs paths |
| `sources` | the menu entries with `state` (`ok`, `warn` erroring, `fail` erroring liveness probe, `stale`, `unknown`), `last_attempt`, `last_ok`, `error` |
| `observations` | every observation (`schemas/status/observation.schema.json`) with `state` effective, `reported_state` as recorded, and `history` (`[[time, state], ...]`) |

## 5. Events and the graph

`homelabnext.status.observed` (`schemas/events/status.observed.schema.json`) carries one
observation as `data`; its id derives from the item and `observed_at`, so a re-send is a duplicate
(see [events](events.md) ([[events]])). Each source is a knowledge-graph node `status:<id>`
with `observes` edges to its service and capability and `polls` to a polled service, so a tile
can link to the capability and runbook pages ([graph](graph.md) ([[graph]])).

## What needs a server (stage 2)

The checklist rows O-02 and O-07 are also measured against a real deployment: stopping a monitored
service turns its tile red within 5 minutes, and with one source blackholed the page still renders
in under 2 seconds. Stage 1 proves the mechanisms with fakes (`pytest tests/status`); stage 2 runs
the same assertions against the lab-in-a-box with real product collectors.
