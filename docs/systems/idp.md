---
title: idp
type: system
summary: idp provides the idp capability (authentik), owned by identity-team.
summary_generated: true
service: idp
capability: idp
impl: authentik
owner: identity-team
host: idp-core
port: 9443
protocol: https
health: http
backup_job: daily-core
tags: [core, identity]
status: draft
author: unknown
---

# idp

## What it does

<!-- hnx:gen:what -->
- Capability: `idp`
- Contract: [idp capability reference](../capabilities/idp.md) ([[capabilities/idp|idp capability]]): operations, data shapes, conformance checks, adapters
- Implementation: `authentik` 2024.8
- Owner: identity-team
- Tags: core, identity
<!-- /hnx:gen -->

<!-- hnx:todo:what -->
> TODO(human): one paragraph: the job, who needs it, what breaks without it.
<!-- /hnx:todo -->

## Inputs

<!-- hnx:gen:inputs -->
- Listens on `https` port `9443` on host `idp-core` (zone `mgmt`)
- TLS: `internal`
- Allowed client zones: edge, data, compute
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
- Registry health probe: HTTP GET `/-/health/live/` expects status `204`
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
- Depended on by: [dashboards](dashboards.md) ([[systems/dashboards|dashboards]]), [edge-proxy](edge-proxy.md) ([[systems/edge-proxy|edge-proxy]]), [lake-catalog](lake-catalog.md) ([[systems/lake-catalog|lake-catalog]]), [lake-query](lake-query.md) ([[systems/lake-query|lake-query]]), [status-hub](status-hub.md) ([[systems/status-hub|status-hub]])
<!-- /hnx:gen -->

<!-- hnx:todo:deps -->
> TODO(human): anything the registry cannot know (data, humans, schedules).
<!-- /hnx:todo -->

## Credentials and access

<!-- hnx:gen:access -->
- Authentication: `own`
- Public hostname: `login.lab.example`
- Endpoint override variable: `HNX_ENDPOINT_IDP`
<!-- /hnx:gen -->

<!-- hnx:todo:access -->
> TODO(human): secret-store NAMES only (never values), who may use it.
<!-- /hnx:todo -->

## Source of truth

<!-- hnx:gen:source -->
- Registry row (Veritas, ADR-0028): `services.idp`
- Backup: job `daily-core`
<!-- /hnx:gen -->

<!-- hnx:todo:source -->
> TODO(human): where the config, runbook and decisions live.
<!-- /hnx:todo -->
