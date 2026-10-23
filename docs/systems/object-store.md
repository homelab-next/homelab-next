---
title: object-store
type: system
service: object-store
capability: object-store
impl: minio
owner: data-team
host: lake-core
port: 9000
protocol: https
health: http
backup_job: weekly-lake
tags: [data, storage]
status: draft
author: unknown
---

# object-store

## What it does

<!-- hnx:gen:what -->
- Capability: `object-store`
- Contract: [object-store capability reference](../capabilities/object-store.md) ([[capabilities/object-store|object-store capability]]): operations, data shapes, conformance checks, adapters
- Implementation: `minio` 2024.9
- Owner: data-team
- Tags: data, storage
<!-- /hnx:gen -->

<!-- hnx:todo:what -->
> TODO(human): one paragraph: the job, who needs it, what breaks without it.
<!-- /hnx:todo -->

## Inputs

<!-- hnx:gen:inputs -->
- Listens on `https` port `9000` on host `lake-core` (zone `data`)
- TLS: `internal`
- Allowed client zones: not restricted in the registry
<!-- /hnx:gen -->

<!-- hnx:todo:inputs -->
> TODO(human): what it consumes and in what format (schemas, queues, files, requests).
<!-- /hnx:todo -->

## Outputs

<!-- hnx:gen:outputs -->
- Metrics: `/minio/v2/metrics/cluster`
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
- Registry health probe: HTTP GET `/minio/health/live` expects status `200`
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
- Depends on: [secrets](secrets.md) ([[systems/secrets|secrets]])
- Depended on by: [lake-catalog](lake-catalog.md) ([[systems/lake-catalog|lake-catalog]]), [lake-query](lake-query.md) ([[systems/lake-query|lake-query]])
<!-- /hnx:gen -->

<!-- hnx:todo:deps -->
> TODO(human): anything the registry cannot know (data, humans, schedules).
<!-- /hnx:todo -->

## Credentials and access

<!-- hnx:gen:access -->
- Authentication: `none`
- Endpoint override variable: `HNX_ENDPOINT_OBJECT_STORE`
<!-- /hnx:gen -->

<!-- hnx:todo:access -->
> TODO(human): secret-store NAMES only (never values), who may use it.
<!-- /hnx:todo -->

## Source of truth

<!-- hnx:gen:source -->
- Registry row (Veritas, ADR-0028): `services.object-store`
- Backup: job `weekly-lake`
<!-- /hnx:gen -->

<!-- hnx:todo:source -->
> TODO(human): where the config, runbook and decisions live.
<!-- /hnx:todo -->
