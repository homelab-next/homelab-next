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
8. **`status.json` is the contract** (documented in `docs/status.md`); the HTML is a plain,
   self-contained rendering of it and may evolve freely.

## Consequences

- Adding a tool to the console is a registry edit plus, at most, a mapping; it appears in the menu,
  the catalog page and the knowledge graph (`status:<id>`, linked to its service and capability).
- A tile always knows its age: an adapter that dies cannot leave its last green on the console.
- Stage 2 adds product collectors (Uptime Kuma, Prometheus queries, the agent dashboard,
  StackStorm, NiFi, the orchestrator) tested in the lab-in-a-box. Each is either a declarative
  mapping over `poll-http-json` or a new entry of `homelabnext.status.collectors.COLLECTORS` for
  a reserved kind; the model, the views and the contract do not change.
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
