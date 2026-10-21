<!-- SPDX-License-Identifier: Apache-2.0 -->
# Status hub: one read-only place for activity and status

The status hub (`homelabnext.status`, `hnx status`, [ADR-0013](adr/0013-status-hub.md)) is the
primary UI: a main page and a left-side menu of views over every registered source of status. It
**observes and never acts**: anything that changes something is a link to the broker or the
approval path. The one write is the broker [Approvals page](#the-approvals-page-broker-stage-2b),
which relays a person's approve or deny to the broker and changes nothing in the hub itself. It does not need agents, the broker or an agent dashboard; each of those is an
optional source or an optional menu entry.

Stage 1 is everything that can be proven without a server: the registry format, the menu, the
observation and event shapes, the collector framework with built-in collectors for what this
repository already has, the state service, the views and the page. Stage 2 adds the product
collectors (section 7): Prometheus, Uptime Kuma, StackStorm, NiFi, the LLM orchestrator and
Agentmetry, each a source kind or a built-in mapping; Prometheus and Uptime Kuma also run in the
lab-in-a-box, where the nightly smoke polls them through the real collectors.

## 1. Register a source (the menu)

A service declares what it can tell the hub (`schemas/platform/service.json` 2.1):

```yaml
services:
  metrics:
    # ...
    status_sources:
      - id: metrics-alerts           # unique; graph node status:metrics-alerts
        kind: poll-http-json         # or poll-file, push-event, agent-activity, a product kind (section 7)
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
| `push-event` | `homelabnext.status.observed` events the source publishes itself: the envelope `source` must be `svc:<the declaring service>` and the module the one the source reports; an `observed_at` in the future is clamped to now (kept as the source's `clock_skew_s`) and `expires_at` is capped at now + `stale_after_s` | none: silence for `stale_after_s` reads stale |
| `agent-activity` | drains agent activity into the activity store and reports stuck and errored sessions (section 6) | `file` for `agent-spool` and `agentmetry-jsonl`, none for `agent-push` |
| `poll-prometheus` | a Prometheus instant query, or its firing alerts (section 7) | `service`, `path` (`.../api/v1/query` or `.../api/v1/alerts`) |
| `poll-uptime-kuma` | an Uptime Kuma public status page and its heartbeats, no login (section 7) | `service`, `path` `.../api/status-page/<slug>` |
| `poll-stackstorm` | StackStorm executions: failures in a window, the running count (section 7) | `service`, `path` `.../executions` |
| `poll-nifi` | NiFi controller status and bulletin board (section 7) | `service`, `path` `.../flow/status` |

Every HTTP kind (`poll-http-json` and the product kinds) takes an optional **`auth`**: the
credential by secret-store name, `{secret: "secret:<name>", header: St2-Api-Key}` (no `header`:
`Authorization: Bearer <value>`). `hnx status collect` reads the value at run time from
`HNX_SECRET_<NAME>` or the file `<name>` under `--secrets-dir`, the same lookup as the agents
configuration. A reference that does not resolve is that source's error: it is never polled
without its credential, and the value never appears in an error, the state file or the page.

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
| `orchestrator-queue` | the LLM orchestrator's `GET /admin/queue-summary` (`poll-http-json`, section 7) | `queued`, `running` (live work), `history` |
| `agentmetry-audit` | Agentmetry's `GET /api/v1/audit/status` (`poll-http-json`, section 7) | `audit-trail`: warn when off, empty, or silent past `warn_after_s` |
| `prometheus-alerts` | Prometheus `GET /api/v1/alerts` (`poll-prometheus` only, section 7) | one per firing alert, by severity |

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
loopback; another address needs `--allow-remote` plus `--allowed-host NAME` (repeatable) and
belongs behind the forward-auth proxy.

**Security of the console.** Binding loopback alone does not stop DNS rebinding: a web page the
operator visits can re-point a hostname of its own at the loopback address and read `status.json`
as same origin. So `serve` answers `403` to any request without a `Host` header, whose `Host`
hostname is not a loopback name (the IPv4 and IPv6 loopback addresses, `localhost`) or an
`--allowed-host`, or that carries an `Origin` whose hostname is not in that same set
(`Origin: null` included). It sends no CORS headers. Every response carries
`X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer` and a Content-Security-Policy of `default-src 'none'`, `style-src`
pinned to the hash of the page's one inline stylesheet (the page has no script), `img-src 'self'
data:`, `frame-ancestors 'none'`, `base-uri 'none'` and `form-action 'none'`. The design follows
the AOS-1 monitor's `hostAllowed` (MIT).

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

## 6. Agent activity (stage 1b)

Agents are optional. When they run, the hub shows what every one of them is doing, whatever
runs it: Claude Code on a workstation or in a cloud session, Codex or another CLI with the same
hook shape, the orchestrator, the maintainer's own agent fleet, or anything that can POST JSON.
Without `--agents` none of this runs and the hub is unchanged. Code: `homelabnext.status.agents`;
decision: ADR-0013 "Stage 1b".

### Two tiers

| Tier | Schema | Holds | Where it goes |
|---|---|---|---|
| summary | `schemas/status/agent_activity.schema.json` | `event_id`, `session_id`, `parent_session_id`, `runtime`, `surface` (local, cloud), `host`, `project`, `model`, `agent`, `time`, `kind`, `tool` (name only), `outcome`, `tokens_in`, `tokens_out`, `cost_usd`, `has_detail` | the hub pages, `status.json` (`agents`), the bus (`homelabnext.agent.activity`), CSV/JSONL export |
| detail | `schemas/status/agent_activity_detail.schema.json` | `prompt`, `command`, `tool_input`, `tool_output`, `error`, `approval` (`decision`, `payload`), plus `truncated` and `redactions` set by the hub | the activity store and the private pages; never the bus, never `status.json` |

Both schemas are closed: a summary event that carries a detail field is refused everywhere
(ingest, spool, store, bus).

A **session** is every summary event with one `session_id`. Its state is derived at read time:
`done` (last event `session_end`), `errored` (last event an error or outcome `error`),
`waiting` (`stop`, a notification, or a pending approval: the agent handed back to the
operator), `stuck` (otherwise, no event for `stuck_after_s`; a model's threshold beats its
runtime's, which beats the default) or `working`.

### Configuration (`examples/status/agents.yml`)

`store` (SQLite), `retention_days`, `detail` (keep the private tier at all),
`redact_personal_data`, `caps` (per-field characters), `stuck_after_s` (`default`, `runtimes`,
`models`), `private` (the front door), `ingest` (the senders) and `approvals` (the broker
Approvals page; agents 1.1, `approvals.csrf_key` 1.2). Schema:
`schemas/status/agents.schema.json`. Secrets are secret-store references (`secret:a/b`), never
values; at run time `secret:a/b-token` is read from `HNX_SECRET_A_B_TOKEN` (or the file `a/b-token` under
`--secrets-dir`). A reference that does not resolve **disables** what it guards (the private
tier, or that one sender) with a warning; nothing falls back to open. Since every character
but a letter or digit becomes `_`, two different references that land in one variable
(`a/b-token`, `a/b_token`) are refused, by the registry and by the agents config, and so are two
senders with the same token (a token names its sender).

**What happens to every record, in order:** schema validation; **secret redaction** with the
shared screener (`homelabnext.agent.screen`: private keys, JWTs, vendor tokens, `Authorization:
Bearer` credentials, secret-key values; typed labels such as `[REDACTED:token:1]`; e-mail,
phone, card, national id and addresses too when `redact_personal_data` is on); the **cap** (after
redaction, so a cut never leaves half a secret the screener cannot see); validation again; the
write. A secret the screener recognises never reaches the disk. Rows older than
`retention_days` (by event time or by arrival) are deleted when the store opens and on every
write.

### Collecting: sources and the push ingest

Registered like every source (`status_sources`, kind `agent-activity`, registry 2.2):

| `builtin` | Reads | Notes |
|---|---|---|
| `agent-spool` | `target.file`: a spool directory of one-record files `{"summary": {...}, "detail": {...}}` | the Claude Code hook writes it; so may anything else (the generic file spool). Ingested files are deleted, invalid ones moved to `rejected/` |
| `agentmetry-jsonl` | `target.file`: an Agentmetry canonical JSONL trail, from the last offset (kept with the file's inode and a hash of its first bytes, so a rotated or rewritten trail is read from the start; a line over 8 MiB is skipped and counted once) | `action.type` maps to `kind` (`tool_called` and `tool_failed` to `tool_end`, `detection` to `notification`, `config_change` skipped); arguments are hashes there, so no detail tier |
| `agent-push` | nothing: the push ingest writes the store | reports the pushed sessions |

Each source reports the sessions it fed: an errored session is a `fail` item, a stuck one a
`warn` item (both on the main page's attention list), and `working` / `waiting` are live-work
counts. `hnx status collect --agents examples/status/agents.yml` runs them.

**Push ingest** (`hnx status ingest --agents FILE [--bind ... --allow-remote --allowed-host
NAME]`, default port 8098, loopback by default): `POST /ingest/agent-activity` with
`Authorization: Bearer <token>` and a JSON body `{"summary": [...], "detail": [...]}`. Answers:
403 foreign Host/Origin, 404 other path, 405 other method, 401 no or unknown token, 429 over the
sender's `rate_per_min`, 411 no length, 413 over `max_body_bytes` or `max_events`, 415 not JSON,
400 not the batch shape, 422 any invalid record or a detail whose event is neither in the batch
nor stored (all or nothing), 403 the sender does not own what it writes (a runtime outside the
sender's `runtimes`, a session another sender or a local source started, an event id already
stored for another session or sender: what is stored decides ownership), 409 a second, different
detail for an event (a detail is written once; the same one again is a retry), 200 `{added,
duplicates, details, detail_dropped}`. A sender with `detail: false` has its details dropped and
its summaries' `has_detail` cleared. With `--publish-to URL` (an events forwarder;
`--publish-state FILE`, default `STORE.publish.json`) each summary the store accepted -- its
redacted copy, never a duplicate -- is also published as a `homelabnext.agent.activity` event
(one attempt in the request; what fails stays pending and is flushed at the next start). It is a
separate listener: the console never accepts a write. Cloud sessions reach it through a separate edge site **without** forward auth (bearer
only).

### The Claude Code hook

`hooks/claude_code_activity.py` (standard library only; copy it anywhere) maps SessionStart,
SessionEnd, UserPromptSubmit, PreToolUse, PostToolUse (outcome from the tool response),
PermissionRequest, Notification, Stop and SubagentStop to both tiers. It prints nothing (some
hook events feed stdout back into the agent's context) and always exits 0. With `--spool` it
writes the detail only after redacting it with the shared screener, and drops the detail when
the screener is not importable. In `~/.claude/settings.json` (or a project's
`.claude/settings.json`):

```json
{
  "hooks": {
    "SessionStart":     [{"hooks": [{"type": "command", "command": "python3 /opt/hnx/hooks/claude_code_activity.py --post https://status-ingest.lab.example/ingest/agent-activity", "timeout": 5}]}],
    "SessionEnd":       [{"hooks": [{"type": "command", "command": "python3 /opt/hnx/hooks/claude_code_activity.py --post https://status-ingest.lab.example/ingest/agent-activity", "timeout": 5}]}],
    "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "python3 /opt/hnx/hooks/claude_code_activity.py --post https://status-ingest.lab.example/ingest/agent-activity", "timeout": 5}]}],
    "PreToolUse":       [{"matcher": "*", "hooks": [{"type": "command", "command": "python3 /opt/hnx/hooks/claude_code_activity.py --post https://status-ingest.lab.example/ingest/agent-activity", "timeout": 5}]}],
    "PostToolUse":      [{"matcher": "*", "hooks": [{"type": "command", "command": "python3 /opt/hnx/hooks/claude_code_activity.py --post https://status-ingest.lab.example/ingest/agent-activity", "timeout": 5}]}],
    "Notification":     [{"hooks": [{"type": "command", "command": "python3 /opt/hnx/hooks/claude_code_activity.py --post https://status-ingest.lab.example/ingest/agent-activity", "timeout": 5}]}],
    "Stop":             [{"hooks": [{"type": "command", "command": "python3 /opt/hnx/hooks/claude_code_activity.py --post https://status-ingest.lab.example/ingest/agent-activity", "timeout": 5}]}],
    "SubagentStop":     [{"hooks": [{"type": "command", "command": "python3 /opt/hnx/hooks/claude_code_activity.py --post https://status-ingest.lab.example/ingest/agent-activity", "timeout": 5}]}]
  }
}
```

The token comes from `HNX_STATUS_INGEST_TOKEN` (`--token-env` names another variable). On the
hub's own host use `--spool build/status/agent-spool` instead of `--post`. `--surface` overrides
the local/cloud guess (`CLAUDE_CODE_REMOTE=true` reads as cloud); `--runtime codex` reports a
CLI with the same hook shape; `--no-detail` never sends the private tier.

### Strategy pages

`hnx status serve --strategy DIR` adds four more live pages, menu entries `panel: strategy |
requirements | objectives | rfis`: the strategy, the requirements board (CCIR / FFIR / PIR), the
objective tree with each MOP/MOE's grade, value and time, and the RFIs by triage. They read the
strategy records only; see [strategy to task](strategy.md) ([[strategy]]).

### Baselines page

`hnx status serve --guests DIR --guests-site SITE` adds the Baselines page, menu entry `panel:
baselines` (views 1.3): one row per guest with its baselines (or `missing` / `exempt` and the
reason) and the controls it gets in each defense layer, then every control with its layer, its
role (or `not bound`), its verify observable and how many guests need it. It is the same report
as `hnx guests baselines --json` and reads the guest files only; see the
[compute model](compute-model.md#baselines-and-defense-layers).

### Generated maps: topology, dataflow, architecture, roadmap

Four pages in the `maps` menu group (views 1.5, `panel: topology | dataflow | architecture |
roadmap`), each **generated** from models already in the repository and never drawn by hand
([ADR-0018](adr/0018-generated-maps.md) ([[adr/0018-generated-maps|ADR-0018]])). Each is a pure
function model -> view-model -> page (`homelabnext/status/maps/`, goldens in
`tests/status/golden/maps/`): an inline SVG (no script, no `style` attribute, themed by the hub's
one stylesheet, so it reads in light and dark; `title` and `desc` for assistive technology) and
the same facts as tables below it. A map whose inputs are not given is listed as unavailable; a
source that cannot be read gives the page an error line instead of a half-drawn picture.

| Page | Input | Drawn from |
|---|---|---|
| `/topology` | `--guests DIR --guests-site SITE` (as the Baselines page) | the site model (zones, VLANs, subnets, gateways, internet egress), the zone-to-zone flows the network IR allows (first match wins), the guest model (node, zone, address, capability, baselines): nodes as rows, zones as columns, then the zone flow matrix |
| `/dataflow` | `--maps ROOT` (a checkout) | producer -> transport -> consumer, one row per flow, labelled: event types (`schemas/events`, their contract samples, an AST scan of the code for who builds and who decodes each type, workflow pack triggers), status sources (polled, or pushed on the bus), the OCSF lake tables and workflow lookups, object-store upstreams, broker actions and lanes |
| `/architecture` | `--maps ROOT` | capabilities -> fakes, real adapters, products -> registry services (the knowledge graph's registry, compose and capability readers: the [capabilities](capabilities/README.md) matrix), then the control plane: agents, bus, workflows, decision, broker, status hub, with an edge only where the repository declares one |
| `/roadmap` | `--maps ROOT [--invariants-results FILE]` | `docs/build-order.md` phases and steps; each phase's `Checklist` cell names its `docs/checklist.md` rows (a section letter for that section's rows of the phase's tag, an id, or a range); per criterion `pass`, `fail`, `error`, `skip` from the results file (`make invariants` writes `build/invariants/results.json`), else `untested`; a progress bar per phase and every row no phase names as unphased |

`hnx status serve ... --maps . --invariants-results build/invariants/results.json` serves them
live; `hnx status render --out DIR` with the same options writes each available map as
`<panel>.html` beside `index.html`, and the static menu links to it. The dataflow and
architecture are built once per process (they change only with the code); the topology and the
roadmap are read on each request. A test keeps `docs/build-order.md` naming every checklist row
and only real ones.

### Pages

Menu entries in `views.yml` (`panel: agents | activity | agent-analytics`, and `agent-detail`,
`agent-access-log` in `group: private`), served live by `hnx status serve --agents FILE`; the
static page lists them as live-only. No script anywhere: filters are links with query strings,
the stream refreshes with a meta refresh, the inspector is a second pane chosen by `?event=`.

| Path | Shows |
|---|---|
| `/agents` | sessions with state badges and counts; filters `?runtime=`, `?state=`, `?project=` |
| `/agents/session?id=` | one session's facts and timeline (a link to its private detail when authorized) |
| `/activity` | the event stream, newest 200; filters `runtime`, `outcome`, `kind`, `session`; `?event=` opens the inspector |
| `/activity.csv`, `/activity.jsonl` | the same selection exported, summary tier only (CSV cells that would run as a spreadsheet formula are quoted) |
| `/agent-analytics` | counts by outcome, runtime, model, tool and day |
| `/private/sessions`, `/private/session?id=`, `/private/event?id=`, `/private/access-log` | the detail tier and the access log: **private** |
| `/approvals`, `POST /approvals/decide` | broker requests awaiting an approver, recent decisions, approve and deny: **private**, with an approver group (below) |

### The private tier: Caddy + Authentik setup

The private pages and the `private` menu group exist only for a request that passes **all** of:

1. it comes **from a trusted proxy address**: the hosts of the registry's `edge-proxy`
   services (or `private.trusted_proxies`, registry host names); a local process on the hub's
   host is not one, so the loopback listener alone never serves the private tier;
2. it carries the **front-door header** with the shared secret. The registry declares it on the
   hub's service (`front_door: {header: X-Hnx-Front-Door, secret: "secret:status/front-door-secret"}`,
   needs `auth: idp` and a `public_hostname`), and the generated Caddy site adds it:
   ```caddyfile
   status.lab.example {
   	import hnx_forward_auth
   	reverse_proxy <the hub's capability alias and port> {
   		header_up X-Hnx-Front-Door {env.HNX_SECRET_STATUS_FRONT_DOOR_SECRET}
   	}
   }
   ```
   Give the edge and the hub the same value in `HNX_SECRET_STATUS_FRONT_DOOR_SECRET` from the secret
   store;
3. it carries the **identity** the forward-auth proxy sets (`X-Authentik-Username`, copied by
   the generated `hnx_forward_auth` snippet);
4. that identity is in the **viewer group** (`X-Authentik-Groups`, `|`-separated; create the
   group in Authentik and add the people who may read prompts and commands).

Anything missing, repeated or malformed is `403`. Run the hub with `hnx status serve --agents
examples/status/agents.yml --bind <address> --allow-remote --allowed-host status.lab.example`.
**Check your edge** once: a request to the site with a forged `X-Authentik-Username` and no
login must not reach the hub with that header (Caddy's `copy_headers` sets the header from the
auth response; verify on your version). Every private view is appended to the access log
(`private.access_log`, JSONL, mode 0600: `at`, `user`, `view`, `session`, `event`), which is
itself a private page. Detail content is rendered as escaped text only (never HTML or markdown)
and nothing in this code feeds it back into an agent's context.

### The Approvals page (broker stage 2b)

With an `approvals:` block in `agents.yml` (it needs `private:`), `hnx status serve --agents FILE`
adds `/approvals`: the broker requests awaiting an approver (action, actor, target, params,
created, digest, age) and the last 20 approvals and denials, with an approve/deny form on each
request. `?request=ID` shows one request (the broker's notification links there). Its menu
entry is `panel: approvals` in `group: private` (views 1.4): it is listed only when `approvals:`
is configured, only to a request through the front door in the viewer group, never on the
static page or in the served `status.json`. A person in only the approver group sees no private
menu group; they reach the page by its URL or the notification link. Code:
`homelabnext.status.approvals`; the broker side: [broker](broker.md#front-door-approvals)
([[broker]]).

```yaml
approvals:
  socket: /run/hnx-broker/broker.sock   # the broker's Unix socket (absolute)
  issuer: sso                           # the broker manifest's approval_relays[].issuer for the hub
  approver_group: hub-approvers         # required to decide; must differ from viewer_group
  csrf_key: "secret:status/approvals-csrf-secret"   # the form tokens' HMAC key (agents 1.2)
  # timeout_s: 10
```

**The form-token key.** `csrf_key` names, in the secret store, the HMAC key the forms' CSRF tokens
are signed with (delivered like every reference: `HNX_SECRET_STATUS_APPROVALS_CSRF_SECRET`, or the file
under `--secrets-dir`). With it a form survives a hub restart and verifies on every hub instance
given the same key. The key must be at least 32 characters and its own secret (not the front
door's): a shorter key, or the front door's reference, is refused when the config is loaded. With
`csrf_key` absent, or naming a secret that is not set, the hub draws a key when it starts and warns
once at startup (`approvals.csrf_key is not set: ...`, naming the setting, never a value): forms
then stop verifying on restart and between instances (reload the page). **Rotation:** there is one
key at a time; replacing it invalidates the forms already shown (at most 30 minutes of them), so
rotate when no one is mid-decision, or accept that they reload the page.

**Who.** The page is behind the same front door as the private tier, by the same code
(`homelabnext.status.agents.auth.authorize`: trusted proxy, front-door secret, identity header),
then a group. **Viewers** (`viewer_group`) may see the queue, read only: a pending request's
params are as sensitive as the private tier's details, and people who already read prompts and
commands can see what agents ask to do. **Deciding** needs the **approver group** (create it in
Authentik next to the viewer group; a person in only the approver group may also see the page).
The approver the hub sends to the broker is `issuer` from the config and `subject` = the
`X-Authentik-Username` the front door passed (lower-cased: the broker compares identities
case-folded), never a form field. The broker then applies its own approver rules (allowlist, no
self-approval, no agent approver).

**The hub's only write.** `POST /approvals/decide` (every other `POST` is still `405`) answers, in
order: `403` the front door or the approver group fails; `403` a foreign `Host`/`Origin` (the
console's DNS-rebinding guard), no `Origin` and no same-host `Referer`, or a `Sec-Fetch-Site` other
than `same-origin`; `415` not `application/x-www-form-urlencoded`; `411` no length; `413` over
8 KiB; `400` a field other than `request_id`, `digest`, `decision` (approve, deny), `token` and
`note` (at most 2000 characters), a repeated or malformed one; `403` a CSRF token that is not the
HMAC (under the `csrf_key` above, else a key drawn when the hub starts) of its issue time, the
request id, the digest shown and this approver, or older than 30 minutes; `409` the broker's current digest for the request is
not the one in the form (**the person approves exactly what they saw**) or the request no longer
awaits approval; `403` a broker refusal (with its reason); `502` the broker is unreachable; `200`
done. Re-submitting a decision the same person already made answers `200` "already" and files
nothing. Every attempt, refused or not, is a line in the access log (`view: approve | deny |
decide`, `request`, `outcome`, `reason`), shown on `/private/access-log`. The page has no script;
its CSP is the hub's with `form-action 'self'`, and it is served with `Referrer-Policy:
same-origin` (the rest of the hub sends `no-referrer`, under which a browser posts the form with
`Origin: null`, which is refused). "Already" means the decision still stands: a request whose
approval expired shows its form again, and one whose approval was consumed (it ran) is no longer
awaiting approval (`409`).

**The broker side.** Run the hub as its own system user (`hnx-hub`) in the broker socket's group
and list it in the broker manifest's `approval_relays` with the same `issuer`; add each person who
may approve to the manifest's `approvers` (`{issuer: sso, subject: <username>, kind: human}`).
**Caddy:** the generated site for the hub's service (the `caddy` generator, `caddy/sites.caddy`)
already puts every path and method of the hostname behind `import hnx_forward_auth` and the
front-door `header_up`; it has no path matcher, so `/approvals` and `POST /approvals/decide` are
covered with no change (a test pins this).

## 7. Product collectors (stage 2)

Each product is either a **kind** with its own collector (`homelabnext.status.products`: several
requests, product-specific options) or a **built-in mapping** over `poll-http-json` (one request
says it all). Every one goes through the same path as stage 1: the target by registry name, the
credential by secret name, a bounded read, its own timeout (`timeout_s` bounds the whole poll,
every request of it), staleness from expiry, and a response it cannot read is the source's error,
never an `ok`. The response shapes were checked against each product's source and, where it fits
the lab, against the running product; the tests (`tests/status/test_status_products.py`) replay
them from `tests/status/fixtures/`.

| Product | How | Verified against | Where it runs in CI |
|---|---|---|---|
| Prometheus | kind `poll-prometheus` | `web/api/v1/api.go` (`QueryData`, `Alert`); a real 2.54.1 | fixtures (recorded) + lab-in-a-box nightly |
| Uptime Kuma | kind `poll-uptime-kuma` | 1.23 `server/routers/status-page-router.js`, `model/{group,monitor,heartbeat,incident}.js`; a real 1.23.16 | fixtures (recorded) + lab-in-a-box nightly |
| StackStorm | kind `poll-stackstorm` | `st2common/openapi.yaml` (`/api/v1/executions`), `ActionExecutionAPI`, `constants/action.py` | fixtures only: it needs MongoDB, RabbitMQ and a dozen st2 services, far over the 4 GB lab's remaining 256 MB |
| Apache NiFi | kind `poll-nifi` | `FlowResource` (`/flow/status`, `/flow/bulletin-board`), `ControllerStatusDTO`, `BulletinBoardEntity`, `BulletinEntity`/`BulletinDTO` | fixtures only: its default JVM heap alone is 1 GB (`bootstrap.conf`), four times what the 4 GB lab has left |
| LLM orchestrator | builtin `orchestrator-queue` | `internal/api/server.go` (routes), `internal/store` `QueueSummary` | fixtures only (the maintainer's own service, not in the lab) |
| Agentmetry | builtin `agentmetry-audit` | `apps/orchestrator/api/routes/audit.py` (`/audit/status`), `core/auth.py` (`X-API-Key`) | fixtures only |

### Prometheus (`poll-prometheus`)

```yaml
- id: metrics-targets
  kind: poll-prometheus
  target: {path: /api/v1/query}
  interval_s: 60
  timeout_s: 10
  mapping:
    query: up                      # an instant vector or a scalar; matrix results are refused
    item: job                      # the label that names an item (default: the metric name)
    thresholds: {fail: 0, direction: below}   # warn/fail at or above (below: at or below)
    empty: fail                    # optional: an empty result is one item in this state
  what: Whether each scrape job's targets answer.
- id: metrics-alerts
  kind: poll-prometheus
  target: {path: /api/v1/alerts}
  interval_s: 60
  timeout_s: 10
  mapping: {builtin: prometheus-alerts, item: instance}
  what: Every firing alert, fail or warn by its severity label.
```

A **query** is sent URL-encoded as `?query=`; each series is an item named by `mapping.item`
(series that share a name are told apart by a stable digest of their labels), its value judged by
`thresholds` (required: a number alone is never read as healthy; NaN and native histograms read
`unknown`). A raw address in the query (`instance="..."`) is refused like anywhere else in a
source. An error document (`"status": "error"`) or a non-2xx answer is the source's error.
**`prometheus-alerts`** lists only **firing** alerts: pending ones (inside their `for:`) and
resolved ones are not reported, so a resolved alert's item disappears. The `severity` label picks
the state: `critical`, `error`, `page`, `high` fail; `warning`, `warn`, `medium`, `low`, `info`
warn; `none` (the always-firing-by-design convention of Watchdog and InfoInhibitor) ok; a missing
or any other severity fails (unmapped is never healthy). `states` overrides or extends that table
(`{ticket: warn}`); `item: <label>` appends that label's value to the alert name.

### Uptime Kuma (`poll-uptime-kuma`)

```yaml
- id: uptime-monitors
  kind: poll-uptime-kuma
  target: {path: /api/status-page/lab}   # the status page's slug
  interval_s: 60
  timeout_s: 10
  what: Every monitor on the public status page.
```

It reads the **public status page** API, which needs no login and no API key:
`GET /api/status-page/<slug>` (the monitors of the page's public groups) and
`GET /api/status-page/heartbeat/<slug>` (each monitor's last heartbeats and its 24-hour uptime).
Each monitor is an item named after it, from its newest heartbeat: up `ok`, down `fail`, pending
`warn`, maintenance `unknown`, no heartbeat yet `unknown`; the summary carries the 24-hour uptime,
the ping and the heartbeat's age. A pinned incident is one more item (`danger` fail, any other
style warn). `states` overrides the four words (`{maintenance: ok}`). Publish only the monitors
the hub should see on that page. Two things from the product itself: Kuma caches these answers
(the page 5 minutes, the heartbeats 1 minute), so a reading can be that old; and Kuma 1.23 does
not answer at all for an unknown slug, so a wrong slug reads as a timeout, not a 404.

### StackStorm (`poll-stackstorm`)

```yaml
- id: automation-executions
  kind: poll-stackstorm
  target: {path: /api/v1/executions}     # behind st2web's nginx; st2api itself serves /v1/executions
  interval_s: 120
  timeout_s: 15
  auth: {secret: "secret:stackstorm/status-token", header: St2-Api-Key}
  mapping: {window_s: 3600, limit: 100}
  what: Actions with failed or timed-out executions in the last hour, and the running ones.
```

Two requests, each with the API key: `?limit=<limit>&sort_desc=true&timestamp_gt=<now -
window_s>&exclude_attributes=result,trigger_instance` (the newest executions in the window,
without their potentially large results) and `?status=running&limit=100`. Every action
(`action.ref`) with an execution that is `failed`, `timeout` or `abandoned` in the window is a
`fail` item ("1 failed, 1 timeout in the last 1h 0m; latest ..."); `executions` counts what the
window held and `running` is live work. A canceled execution is an operator's choice and is not
reported; `states` changes that (`{canceled: warn}`, keys are StackStorm's execution statuses).
`limit` is at most 100, StackStorm's `api.max_page_size` for a non-admin key; a summary says when
the window held more than one page. Use a read-only API key (an RBAC role with
`action_execution_list`/`action_execution_view` only).

### Apache NiFi (`poll-nifi`)

```yaml
- id: dataflow-status
  kind: poll-nifi
  target: {path: /nifi-api/flow/status}
  interval_s: 60
  timeout_s: 10
  auth: {secret: "secret:nifi/status-token"}   # optional: Authorization: Bearer <token>
  mapping:
    thresholds: {warn: 10000, fail: 100000}  # on queued flowfiles; absent: the queue is only live work
  what: Queued flowfiles, invalid and stopped components, and error bulletins.
```

`GET /nifi-api/flow/status` gives `queued` (flowfiles, live work, judged by `thresholds`),
`running` (components and active threads, live work), and the counts `invalid` (`fail` when
non-zero), `stopped` (`warn`), `disabled` (`ok`, a deliberate state) and `sync-failure`
(versioned groups that failed to sync, `warn`; absent without registry clients).
`GET /nifi-api/flow/bulletin-board?limit=100` adds one item per component (`bulletin:<source
name>`) with ERROR (`fail`) or WARNING (`warn`) bulletins and its latest message; INFO and DEBUG
are not attention, and a bulletin the credential may not read is only counted (`bulletins`).
NiFi keeps bulletins for five minutes, so a component's bulletin item disappears once it stops
reporting. `states` overrides the item states (`invalid`, `stopped`, `disabled`, `sync-failure`)
and the bulletin levels (`error`, `warning`). The token is any bearer token NiFi accepts (for
example one issued to a read-only user with the "view the user interface" policy).

### The LLM orchestrator (`orchestrator-queue`)

The maintainer's Go controller exposes no health or metrics endpoint; its status is
`GET /admin/queue-summary` (`{"by_state": {...}, "active": [{agent_key, state, count}],
"oldest_queued_run_id", "oldest_queued_age_seconds"}`), so the example declares it with
`on_error: fail` (not answering is the reading):

```yaml
- id: orchestrator-queues
  kind: poll-http-json
  target: {path: /admin/queue-summary}
  interval_s: 60
  timeout_s: 5
  on_error: fail
  mapping: {builtin: orchestrator-queue, warn_after_s: 3600}
  what: Queued and running orchestrator jobs; the oldest queued job waiting over an hour is warn.
```

Items: `queued` (live work; `warn` when the oldest queued job has waited over `warn_after_s`),
`running` (live work, with the running count per agent) and `history` (the all-time
done/failed/cancelled totals, informational: they never reset, so they are not a window). The
controller binds loopback (`http_addr`), so poll it from its own host or through the edge.
`/admin/backend-status` returns an external probe script's output verbatim and is not mapped.

### Agentmetry (`agentmetry-audit`)

Agentmetry is already a source through its canonical JSONL trail (`agentmetry-jsonl`, section
6). Its orchestrator API also answers `GET /api/v1/audit/status`, the freshness behind its
dashboard badge, which tells whether that trail is being written at all:

```yaml
- id: agentmetry-audit
  kind: poll-http-json
  target: {path: /api/v1/audit/status}
  interval_s: 300
  timeout_s: 10
  auth: {secret: "secret:agentmetry/api-token", header: X-API-Key}   # keyless only from loopback
  mapping: {builtin: agentmetry-audit, module: agents, warn_after_s: 86400}
  what: Whether the agent dashboard's audit trail is being written.
```

`audit-trail` is `warn` when the export is disabled, has no event yet, or its last event is older
than `warn_after_s` (a silent hook failure), else `ok` with the per-source counts of the last 500
events. The export path the endpoint also returns is never shown. (`GET /api/v1/health`, no key,
is a declarative `{state: status, states: {up: ok}}` if only liveness is wanted.)

## What needs a server

The checklist rows O-02 and O-07 are also measured against a real deployment: stopping a monitored
service turns its tile red within 5 minutes, and with one source blackholed the page still renders
in under 2 seconds. Stage 1 proves the mechanisms with fakes (`pytest tests/status`). The
lab-in-a-box runs **Prometheus** (scraping itself, with a warning and a critical rule that always
fire) and **Uptime Kuma** (provisioned headlessly through its own socket.io API by
`config/uptime-kuma/provision.js`: an admin user, a monitor that answers and one that cannot, the
public status page `lab`), and the nightly smoke (`smoke_checks.py`, checks `metrics` and
`uptime`) polls both through the real `poll-prometheus` and `poll-uptime-kuma` collectors and
expects exactly warn + fail alerts, the self-scrape target `ok`, and the two monitors `ok` and
`fail`. StackStorm and NiFi do not fit the lab's 4 GB budget and are tested against their
fixtures only.
