---
title: dashboards
type: system
summary: dashboards provides the dashboards capability (grafana), owned by platform-team.
service: dashboards
capability: dashboards
impl: grafana
owner: platform-team
host: mon-core
port: 3000
protocol: http
health: http
backup_job: daily-core
tags: [ops, ui]
status: draft
author: unknown
---

# dashboards

## What it does

<!-- hnx:gen:what -->
- Capability: `dashboards`
- Contract: none (`dashboards` is not one of the conformance capabilities)
- Implementation: `grafana` 11.2.0
- Owner: platform-team
- Tags: ops, ui
<!-- /hnx:gen -->

<!-- hnx:todo:what -->
> TODO(human): one paragraph: the job, who needs it, what breaks without it.
<!-- /hnx:todo -->

## Inputs

<!-- hnx:gen:inputs -->
- Listens on `http` port `3000` on host `mon-core` (zone `mgmt`)
- TLS: `none`
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
- Registry health probe: HTTP GET `/api/health` expects status `200`
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
- Depends on: [metrics](metrics.md) ([[systems/metrics|metrics]]), [idp](idp.md) ([[systems/idp|idp]])
- Depended on by: [edge-proxy](edge-proxy.md) ([[systems/edge-proxy|edge-proxy]])
<!-- /hnx:gen -->

<!-- hnx:todo:deps -->
> TODO(human): anything the registry cannot know (data, humans, schedules).
<!-- /hnx:todo -->

## Credentials and access

<!-- hnx:gen:access -->
- Authentication: `idp`
- Public hostname: `dashboards.lab.example`
- Endpoint override variable: `HNX_ENDPOINT_DASHBOARDS`
<!-- /hnx:gen -->

<!-- hnx:todo:access -->
> TODO(human): secret-store NAMES only (never values), who may use it.
<!-- /hnx:todo -->

## Source of truth

<!-- hnx:gen:source -->
- Registry row (Veritas, ADR-0028): `services.dashboards`
- Backup: job `daily-core`
<!-- /hnx:gen -->

<!-- hnx:todo:source -->
> TODO(human): where the config, runbook and decisions live.
<!-- /hnx:todo -->
