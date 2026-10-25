---
title: notify
type: system
summary: notify provides the notify capability (ntfy), owned by platform-team.
service: notify
capability: notify
impl: ntfy
owner: platform-team
host: mon-core
port: 8080
protocol: http
health: http
backup_job: null
tags: [notify, ops]
status: draft
author: unknown
---

# notify

## What it does

<!-- hnx:gen:what -->
- Capability: `notify`
- Contract: [notify capability reference](../capabilities/notify.md) ([[capabilities/notify|notify capability]]): operations, data shapes, conformance checks, adapters
- Implementation: `ntfy` 2.11
- Owner: platform-team
- Tags: notify, ops
<!-- /hnx:gen -->

<!-- hnx:todo:what -->
> TODO(human): one paragraph: the job, who needs it, what breaks without it.
<!-- /hnx:todo -->

## Inputs

<!-- hnx:gen:inputs -->
- Listens on `http` port `8080` on host `mon-core` (zone `mgmt`)
- TLS: `none`
- Allowed client zones: data, compute
<!-- /hnx:gen -->

<!-- hnx:todo:inputs -->
> TODO(human): what it consumes and in what format (schemas, queues, files, requests).
<!-- /hnx:todo -->

## Outputs

<!-- hnx:gen:outputs -->
- Metrics: none declared
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
- Registry health probe: HTTP GET `/v1/health` expects status `200`
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
- Depends on: none declared
- Depended on by: [agent-runtime](agent-runtime.md) ([[systems/agent-runtime|agent-runtime]]), [metrics](metrics.md) ([[systems/metrics|metrics]])
<!-- /hnx:gen -->

<!-- hnx:todo:deps -->
> TODO(human): anything the registry cannot know (data, humans, schedules).
<!-- /hnx:todo -->

## Credentials and access

<!-- hnx:gen:access -->
- Authentication: `none`
- Endpoint override variable: `HNX_ENDPOINT_NOTIFY`
<!-- /hnx:gen -->

<!-- hnx:todo:access -->
> TODO(human): secret-store NAMES only (never values), who may use it.
<!-- /hnx:todo -->

## Source of truth

<!-- hnx:gen:source -->
- Registry row (Veritas, ADR-0028): `services.notify`
- Backup: not in a backup job
<!-- /hnx:gen -->

<!-- hnx:todo:source -->
> TODO(human): where the config, runbook and decisions live.
<!-- /hnx:todo -->
