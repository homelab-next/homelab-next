---
title: edge-proxy
type: system
service: edge-proxy
capability: edge-proxy
impl: caddy
owner: platform-team
host: edge-core
port: 443
protocol: https
health: tcp
backup_job: null
tags: [core, edge]
status: draft
---

# edge-proxy

## What it does

<!-- hnx:gen:what -->
- Capability: `edge-proxy`
- Contract: none (`edge-proxy` is not one of the conformance capabilities)
- Implementation: `caddy` 2.8.4
- Owner: platform-team
- Tags: core, edge
<!-- /hnx:gen -->

<!-- hnx:todo:what -->
> TODO(human): one paragraph: the job, who needs it, what breaks without it.
<!-- /hnx:todo -->

## Inputs

<!-- hnx:gen:inputs -->
- Listens on `https` port `443` on host `edge-core` (zone `edge`)
- TLS: `public`
- Allowed client zones: not restricted in the registry
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
- Registry health probe: TCP connect to port `443`
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
- Depends on: [dashboards](dashboards.md) ([[systems/dashboards|dashboards]]), [idp](idp.md) ([[systems/idp|idp]])
- Depended on by: none declared
<!-- /hnx:gen -->

<!-- hnx:todo:deps -->
> TODO(human): anything the registry cannot know (data, humans, schedules).
<!-- /hnx:todo -->

## Credentials and access

<!-- hnx:gen:access -->
- Authentication: `none`
- Endpoint override variable: `HNX_ENDPOINT_EDGE_PROXY`
<!-- /hnx:gen -->

<!-- hnx:todo:access -->
> TODO(human): secret-store NAMES only (never values), who may use it.
<!-- /hnx:todo -->

## Source of truth

<!-- hnx:gen:source -->
- Registry row: `services.edge-proxy`
- Backup: not in a backup job
<!-- /hnx:gen -->

<!-- hnx:todo:source -->
> TODO(human): where the config, runbook and decisions live.
<!-- /hnx:todo -->
