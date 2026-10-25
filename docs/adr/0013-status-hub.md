---
summary: One read-only status hub over status sources registered in the registry; views pick from that menu.
---
# ADR-0013: One read-only status hub over registered status sources

- **Status:** proposed
- **Date:** 2026-10-20
- **Related:** ADR-0002, ADR-0003, ADR-0009, ADR-0010, `schemas/status/`, `schemas/platform/service.json` (2.1), [status hub guide](../status.md)

## Context

Activity and status are scattered across many tools: an uptime monitor, a metrics stack and its
alert rules, an orchestrator's queues, an automation engine, a dataflow tool, the invariants
register, the proposal lanes, broker approvals, an agent dashboard. Each has its own page, its own
idea of "red" and its own way of going quiet; nobody can see the whole lab in one place, and a tool
that stops reporting looks the same as a tool that is fine. Wiring a console to those tools after
the fact produced one-off scrapers with addresses baked in, each failing differently. Agents are
optional in this project, so a console must not need agents, the broker or the agent dashboard to
work.

## Decision

1. **There is one status hub**, the primary UI: a main page plus a left-side menu of views. It is
   **read-only**: it observes. Anything that changes something is a link out to the broker or the
   approval path (`shell.act_via`), never a button in the hub.
2. **Every status source is registered**, as `status_sources:` of the service that offers it in
   the registry (additive, `service.json` 2.1): `id`, `kind` (`poll-http-json`, `poll-file`,
   `push-event`; `poll-prometheus` reserved for stage 2), the target **by registry name**
   (service + path, or a file under the status root), `interval_s`, `stale_after_s` (default
   3 x interval), `timeout_s`, `on_error`, a `mapping` (declarative selectors or a named built-in
   mapper) and a one-line `what`. Validation is fatal like the rest of the registry: no raw
   address, a target that is a registered http(s) service, `timeout_s < interval_s <=
   stale_after_s`, unique ids.
3. **The registered sources are the menu.** `hnx status sources` lists them and
   `docs/status/sources.md` is generated from them and checked in CI. Views
   (`examples/status/views.yml`, `schemas/status/views.schema.json`) pick from that menu: a
   built-in panel (exceptions-first summary, per-module grid, source table) over a selection, or an
   external link entry naming a registry service, optionally (an agent dashboard is one such
   optional entry, like any external app).
4. **One observation shape** (`schemas/status/observation.schema.json`): `source`, `module`,
   `item`, `state` (`ok|warn|fail|unknown|stale`), `summary`, optional `link` (a logical id or a
   relative path, never an address), `observed_at`, `expires_at`. Collectors may also publish each
   one as a `homelabnext.status.observed` event, so the bus is one place to read everything.
5. **Isolation and staleness are structural.** Each source runs in its own thread under its own
   timeout; a hung or raising source becomes an error for that source only (O-07). Staleness is
   computed from `expires_at` at read time, never stored, so a source that stops reporting reads
   `stale` within its `stale_after_s` without anything having to run (O-06). The page and
   `hnx status serve` read the state file only and never call a source.
6. **Exceptions first** (O-05): the main panel shows the green count, live work and the items that
   need attention, and nothing else when everything is healthy.
7. **Notifications reuse the state-diffed `Notifier`** (O-08): one key per item and per source,
   paging on transitions into and out of `fail`/`stale` only.
8. **The live console defends itself**: loopback by default, `403` for any `Host`/`Origin` outside loopback and the configured `--allowed-host` names (DNS rebinding), no CORS, a hash-pinned CSP.
9. **`status.json` is the contract** (documented in `docs/status.md`); the HTML is a plain,
   self-contained rendering of it and may evolve freely.

### Stage 1b: agent activity

Agents are optional; when they run, what they do is one more domain of the hub, from any
runtime (a coding CLI on a workstation or in a cloud session, an orchestrator, the maintainer's
own agent fleet, anything that can POST JSON).

1. **Two tiers, kept apart.** The *summary* tier (`schemas/status/agent_activity.schema.json`:
   ids, runtime, surface, host, project, model, agent, parent session, kind, tool *name*,
   outcome, tokens, cost) is public: hub pages, `status.json` (`agents`) and the bus event
   `homelabnext.agent.activity`. The *detail* tier (`agent_activity_detail.schema.json`: prompt,
   command, tool input and output, error, approval with its gated payload) is private: never on
   the bus, never in `status.json`, served only behind the trusted front door. Both schemas are
   closed (`additionalProperties: false`), so a detail field in a summary event is refused.
2. **Redact before storage, always.** Every detail field goes through the shared screener with the
   secret types on (personal data when configured), *then* is cut to its configured cap, then is
   stored. Retention is by age, purged on open and on every write.
3. **The private tier has a door, not a login.** A request must come from a trusted proxy address
   (the registry's edge hosts), carry the front door's shared-secret header (the registry's
   `front_door`, added by the generated Caddy site with `header_up` from the secret store), carry
   the forward-auth identity header and be in the viewer group. Anything missing is `403`; every
   private view is access-logged; content is rendered as escaped text.
4. **Collection reuses the framework.** A new status-source kind `agent-activity` (registry 2.2)
   with built-ins `agent-spool` (the stdlib Claude Code hook's spool, and the generic file spool),
   `agentmetry-jsonl` (an Agentmetry canonical trail) and `agent-push` (sessions from the separate
   push listener, `POST /ingest/agent-activity`, a bearer token per sender named by secret
   reference). Each reports its errored sessions (`fail`) and stuck ones (`warn`) as attention
   items and the working/waiting counts as live work, so the exceptions-first page needs no change.
5. **Pages, not a graph.** Sessions, a session timeline, an event stream with an inspector pane and
   CSV/JSONL export, and counts are server-rendered pages with query-string filters (no script).
   Runtimes are not graph nodes: they are values in events, not registry entities.

### Stage 2: product collectors

1. **A product with more than one request is a kind; one request is a built-in mapping.**
   `poll-prometheus` (no longer reserved: an instant query, or `builtin: prometheus-alerts`),
   `poll-uptime-kuma` (the public status page and its heartbeats), `poll-stackstorm` (executions
   in a window, the running ones) and `poll-nifi` (controller status, bulletin board) are
   entries of `COLLECTORS` (`homelabnext.status.products`, registry 2.3); the LLM orchestrator
   (`orchestrator-queue`) and Agentmetry (`agentmetry-audit`) are built-ins over
   `poll-http-json`. Each kind validates its own target path and mapping keys in the registry.
2. **Credentials by name.** Every HTTP kind takes `auth: {secret, header?}`: a secret-store
   reference, sent as that header or as a bearer token, resolved at run time like the agents
   configuration. An unresolved reference is the source's error; nothing is polled without it.
3. **Verified shapes, replayed.** Every mapping is a pure function tested against the product's
   response shape as its source defines it, recorded from the running product where it fits the
   lab (Prometheus, Uptime Kuma: also polled nightly through the real collectors in the
   lab-in-a-box). StackStorm and NiFi do not fit the 4 GB lab and are tested from fixtures only.
4. **Unmapped is never healthy, here too**: a value without thresholds, an alert without a
   severity, an unknown heartbeat code all read `unknown` or `fail`, never `ok`.

Alternatives considered: shipping the details on the bus (rejected: everything on the bus is
shared); a login in the hub (rejected: one identity provider, at the edge); a client-side
dashboard framework (rejected: CSP and the no-dependency page).

## Consequences

- Adding a tool to the console is a registry edit plus, at most, a mapping; it appears in the menu,
  the catalog page and the knowledge graph (`status:<id>`, linked to its service and capability).
- A tile always knows its age: an adapter that dies cannot leave its last green on the console.
- Stage 2 added the product collectors (Prometheus, Uptime Kuma, StackStorm, NiFi, the
  orchestrator, Agentmetry), each a built-in mapping over `poll-http-json` or an entry of
  `homelabnext.status.collectors.COLLECTORS`; the model, the views and the contract did not
  change.
- We maintain the mapping engine, the built-in mappers and the catalog generator, and every new
  source needs a `what` line someone can read.

## Alternatives

- **One dashboard per tool** (status as each product shows it): no common idea of stale, no single
  page, and every tool has to be visited to learn that nothing is wrong. Rejected: it is the
  scattered state this decision replaces.
- **A console that can act** (restart, approve, re-run from the status page): it would need
  credentials and a second approval path beside the broker, and a status page that can change
  things becomes a target. Rejected: the hub links to the broker/approval path instead.
- **Scraping each tool from the console at render time**: one slow tool stalls the page. Rejected
  for collection into a state file that the page reads.
