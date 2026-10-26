---
title: lake-catalog
type: system
summary: lake-catalog provides the lake-catalog capability (lakekeeper), owned by
  data-team.
summary_generated: true
service: lake-catalog
capability: lake-catalog
impl: lakekeeper
owner: data-team
host: lake-core
port: 8181
protocol: https
health: http
backup_job: daily-core
tags: [catalog, data]
status: draft
author: unknown
---

# lake-catalog

## What it does

<!-- hnx:gen:what -->
- Capability: `lake-catalog`
- Contract: [lake-catalog capability reference](../capabilities/lake-catalog.md) ([[capabilities/lake-catalog|lake-catalog capability]]): operations, data shapes, conformance checks, adapters
- Implementation: `lakekeeper` 0.5.2
- Owner: data-team
- Tags: catalog, data
<!-- /hnx:gen -->

<!-- hnx:todo:what -->
> TODO(human): one paragraph: the job, who needs it, what breaks without it.
<!-- /hnx:todo -->

## Inputs

<!-- hnx:gen:inputs -->
- Listens on `https` port `8181` on host `lake-core` (zone `data`)
- TLS: `internal`
- Allowed client zones: not restricted in the registry
<!-- /hnx:gen -->

<!-- hnx:todo:inputs -->
> TODO(human): what it consumes and in what format (schemas, queues, files, requests).
<!-- /hnx:todo -->

## Outputs

<!-- hnx:gen:outputs -->
- Metrics: `/metrics`
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
- Registry health probe: HTTP GET `/health` expects status `200`
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
- Depends on: [object-store](object-store.md) ([[systems/object-store|object-store]]), [idp](idp.md) ([[systems/idp|idp]]), [records-db](records-db.md) ([[systems/records-db|records-db]])
- Depended on by: [lake-query](lake-query.md) ([[systems/lake-query|lake-query]])
<!-- /hnx:gen -->

<!-- hnx:todo:deps -->
> TODO(human): anything the registry cannot know (data, humans, schedules).
<!-- /hnx:todo -->

## Credentials and access

<!-- hnx:gen:access -->
- Authentication: `none`
- Endpoint override variable: `HNX_ENDPOINT_LAKE_CATALOG`
<!-- /hnx:gen -->

<!-- hnx:todo:access -->
> TODO(human): secret-store NAMES only (never values), who may use it.
<!-- /hnx:todo -->

## Source of truth

<!-- hnx:gen:source -->
- Registry row (Veritas, ADR-0028): `services.lake-catalog`
- Backup: job `daily-core`
<!-- /hnx:gen -->

<!-- hnx:todo:source -->
> TODO(human): where the config, runbook and decisions live.
<!-- /hnx:todo -->
