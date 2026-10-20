---
title: lake-query
type: system
service: lake-query
capability: lake-query
impl: trino
owner: data-team
host: lake-core
port: 8443
protocol: https
health: http
backup_job: null
tags: [data, query]
status: draft
author: unknown
---

# lake-query

## What it does

<!-- hnx:gen:what -->
- Capability: `lake-query`
- Contract: [lake-query capability reference](../capabilities/lake-query.md) ([[capabilities/lake-query|lake-query capability]]): operations, data shapes, conformance checks, adapters
- Implementation: `trino` 450.0
- Owner: data-team
- Tags: data, query
<!-- /hnx:gen -->

<!-- hnx:todo:what -->
> TODO(human): one paragraph: the job, who needs it, what breaks without it.
<!-- /hnx:todo -->

## Inputs

<!-- hnx:gen:inputs -->
- Listens on `https` port `8443` on host `lake-core` (zone `data`)
- TLS: `internal`
- Allowed client zones: not restricted in the registry
<!-- /hnx:gen -->

<!-- hnx:todo:inputs -->
> TODO(human): what it consumes and in what format (schemas, queues, files, requests).
<!-- /hnx:todo -->

## Outputs

<!-- hnx:gen:outputs -->
- Metrics: `/metrics` on port 9091
- MCP tool server `lake_query` (http, `/mcp`)
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
- Registry health probe: HTTP GET `/v1/info` expects status `200` every 30s
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
- Depends on: [lake-catalog](lake-catalog.md) ([[systems/lake-catalog|lake-catalog]]), [object-store](object-store.md) ([[systems/object-store|object-store]]), [idp](idp.md) ([[systems/idp|idp]])
- Depended on by: [agent-runtime](agent-runtime.md) ([[systems/agent-runtime|agent-runtime]])
<!-- /hnx:gen -->

<!-- hnx:todo:deps -->
> TODO(human): anything the registry cannot know (data, humans, schedules).
<!-- /hnx:todo -->

## Credentials and access

<!-- hnx:gen:access -->
- Authentication: `idp`
- Endpoint override variable: `HNX_ENDPOINT_LAKE_QUERY`
<!-- /hnx:gen -->

<!-- hnx:todo:access -->
> TODO(human): secret-store NAMES only (never values), who may use it.
<!-- /hnx:todo -->

## Source of truth

<!-- hnx:gen:source -->
- Registry row: `services.lake-query`
- Backup: not in a backup job
<!-- /hnx:gen -->

<!-- hnx:todo:source -->
> TODO(human): where the config, runbook and decisions live.
<!-- /hnx:todo -->
