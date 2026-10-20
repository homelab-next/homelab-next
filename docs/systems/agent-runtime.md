---
title: agent-runtime
type: system
service: agent-runtime
capability: agent-runtime
impl: orchestrator
owner: ml-team
host: runtime-core
port: 8088
protocol: http
health: http
backup_job: null
tags: [agents, compute]
status: draft
author: unknown
---

# agent-runtime

## What it does

<!-- hnx:gen:what -->
- Capability: `agent-runtime`
- Contract: none (`agent-runtime` is not one of the conformance capabilities)
- Implementation: `orchestrator` 0.3.0
- Owner: ml-team
- Tags: agents, compute
<!-- /hnx:gen -->

<!-- hnx:todo:what -->
> TODO(human): one paragraph: the job, who needs it, what breaks without it.
<!-- /hnx:todo -->

## Inputs

<!-- hnx:gen:inputs -->
- Listens on `http` port `8088` on host `runtime-core` (zone `compute`)
- TLS: `none`
- Allowed client zones: not restricted in the registry
<!-- /hnx:gen -->

<!-- hnx:todo:inputs -->
> TODO(human): what it consumes and in what format (schemas, queues, files, requests).
<!-- /hnx:todo -->

## Outputs

<!-- hnx:gen:outputs -->
- Metrics: `/metrics`
- MCP tool server `agent_runtime` (sse, `/sse`)
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
- Registry health probe: HTTP GET `/healthz` expects status `200`
<!-- /hnx:gen -->

<!-- hnx:todo:verify -->
> TODO(human): the observable that proves it works, beyond the probe.
<!-- /hnx:todo -->

## Failure modes

<!-- hnx:todo:failure -->
> TODO(human): symptom, likely cause, first check, fix: one row each.
<!-- /hnx:todo -->

## Depends on / depended on by

<!-- hnx:gen:deps -->
- Depends on: [lake-query](lake-query.md) ([[systems/lake-query|lake-query]]), [inference](inference.md) ([[systems/inference|inference]]), [notify](notify.md) ([[systems/notify|notify]]), [events](events.md) ([[systems/events|events]]), [secrets](secrets.md) ([[systems/secrets|secrets]])
- Depended on by: none declared
<!-- /hnx:gen -->

<!-- hnx:todo:deps -->
> TODO(human): anything the registry cannot know (data, humans, schedules).
<!-- /hnx:todo -->

## Credentials and access

<!-- hnx:gen:access -->
- Authentication: `none`
- Endpoint override variable: `HNX_ENDPOINT_AGENT_RUNTIME`
<!-- /hnx:gen -->

<!-- hnx:todo:access -->
> TODO(human): secret-store NAMES only (never values), who may use it.
<!-- /hnx:todo -->

## Source of truth

<!-- hnx:gen:source -->
- Registry row: `services.agent-runtime`
- Backup: not in a backup job
<!-- /hnx:gen -->

<!-- hnx:todo:source -->
> TODO(human): where the config, runbook and decisions live.
<!-- /hnx:todo -->
