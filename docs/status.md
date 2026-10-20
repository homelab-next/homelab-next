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
| `push-event` | `homelabnext.status.observed` events the source publishes itself: the envelope `source` must be `svc:<the declaring service>` and the module the one the source reports; an `observed_at` in the future is clamped to now (kept as the source's `clock_skew_s`) and `expires_at` is capped at now + `stale_after_s` | none: silence for `stale_after_s` reads stale |
| `poll-prometheus` | reserved for stage 2; reads `unknown` until its collector ships | `service`, `path` |
| `agent-activity` | drains agent activity into the activity store and reports stuck and errored sessions (section 6) | `file` for `agent-spool` and `agentmetry-jsonl`, none for `agent-push` |

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
`models`), `private` (the front door) and `ingest` (the senders). Schema:
`schemas/status/agents.schema.json`. Secrets are secret-store references (`secret:a/b`), never
values; at run time `secret:a/b-token` is read from `HNX_SECRET_A_B_TOKEN` (or the file `a/b-token` under
`--secrets-dir`). A reference that does not resolve **disables** what it guards (the private
tier, or that one sender) with a warning; nothing falls back to open.

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
| `agentmetry-jsonl` | `target.file`: an Agentmetry canonical JSONL trail, from the last offset | `action.type` maps to `kind` (`tool_called` and `tool_failed` to `tool_end`, `detection` to `notification`, `config_change` skipped); arguments are hashes there, so no detail tier |
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
sender's `runtimes`, a session another sender or a local source started), 200 `{added, duplicates, details, detail_dropped}`. A sender with
`detail: false` has its details dropped. It is a separate listener: the console never accepts a
write. Cloud sessions reach it through a separate edge site **without** forward auth (bearer
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

## What needs a server (stage 2)

The checklist rows O-02 and O-07 are also measured against a real deployment: stopping a monitored
service turns its tile red within 5 minutes, and with one source blackholed the page still renders
in under 2 seconds. Stage 1 proves the mechanisms with fakes (`pytest tests/status`); stage 2 runs
the same assertions against the lab-in-a-box with real product collectors.
