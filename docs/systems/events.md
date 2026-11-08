---
title: events
type: system
summary: events provides the events capability (nats), owned by data-team.
summary_generated: true
service: events
capability: events
impl: nats
owner: data-team
host: bus-core
port: 4222
protocol: nats
health: tcp
backup_job: null
tags: [bus, data]
status: draft
author: unknown
---

# events

## What it does

<!-- hnx:gen:what -->
- Capability: `events`
- Contract: [events capability reference](../capabilities/events.md) ([[capabilities/events|events capability]]): operations, data shapes, conformance checks, adapters
- Implementation: `nats` 2.15.1
- Owner: data-team
- Tags: bus, data
<!-- /hnx:gen -->

<!-- hnx:todo:what -->
> TODO(human): one paragraph: the job, who needs it, what breaks without it.
<!-- /hnx:todo -->

## Inputs

<!-- hnx:gen:inputs -->
- Listens on `nats` port `4222` on host `bus-core` (zone `data`)
- TLS: `mtls`
- Allowed client zones: compute
<!-- /hnx:gen -->

<!-- hnx:todo:inputs -->
> TODO(human): what it consumes and in what format (schemas, queues, files, requests).
<!-- /hnx:todo -->

## Outputs

<!-- hnx:gen:outputs -->
- Metrics: `/metrics` on port 7777
- MCP: none
<!-- /hnx:gen -->

<!-- hnx:todo:outputs -->
> TODO(human): what it produces, each with its format and where it lands.
<!-- /hnx:todo -->

## How to use it

<!-- hnx:todo:use -->
> TODO(human): the everyday commands or clicks, with one worked example.
<!-- /hnx:todo -->

## How to verify it is healthy

<!-- hnx:gen:verify -->
- Registry health probe: TCP connect to port `4222`
<!-- /hnx:gen -->

<!-- hnx:todo:verify -->
> TODO(human): the observable that proves it works, beyond the probe.
<!-- /hnx:todo -->

## Failure modes

<!-- hnx:todo:failure -->
> TODO(human): symptom, likely cause, first check, fix: one row each.

- **The server refuses its configuration after an upgrade from 2.10.** Likely cause: since 2.11,
  a server, cluster or gateway name that contains a space is refused. Fix: rename it.
- **A stream refuses new consumers.** Likely cause: since 2.15 a stream allows 1,000 consumers by
  default. First check: the stream's consumer count. Fix: delete stale durables, or raise the
  limit on the stream.
- **A supervisor reads a clean stop as a failure, or the reverse.** Since 2.15 a graceful stop
  exits 0 (2.10 exited 1). Fix: update any unit or script that treated exit 1 as a normal stop.

<!-- /hnx:todo -->

## Depends on / depended on by

<!-- hnx:gen:deps -->
- Depends on: none declared
- Depended on by: [agent-runtime](agent-runtime.md) ([[systems/agent-runtime|agent-runtime]])
<!-- /hnx:gen -->

<!-- hnx:todo:deps -->
> TODO(human): anything the registry cannot know (data, humans, schedules).
<!-- /hnx:todo -->

## Credentials and access

<!-- hnx:gen:access -->
- Authentication: `none`
- Endpoint override variable: `HNX_ENDPOINT_EVENTS`
<!-- /hnx:gen -->

<!-- hnx:todo:access -->
> TODO(human): secret-store NAMES only (never values), who may use it.
<!-- /hnx:todo -->

## Source of truth

<!-- hnx:gen:source -->
- Registry row (Veritas, ADR-0028): `services.events`
- Backup: not in a backup job
<!-- /hnx:gen -->

<!-- hnx:todo:source -->
> TODO(human): where the config, runbook and decisions live.
<!-- /hnx:todo -->
