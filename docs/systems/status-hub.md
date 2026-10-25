---
title: status-hub
type: system
summary: status-hub provides the status-hub capability (homelabnext), owned by platform-team.
summary_generated: true
service: status-hub
capability: status-hub
impl: homelabnext
owner: platform-team
host: mon-core
port: 8099
protocol: http
health: http
backup_job: null
tags: [ops, ui]
status: draft
author: unknown
reviews: []
---

# status-hub

## What it does

<!-- hnx:gen:what -->
- Capability: `status-hub`
- Contract: none (`status-hub` is not one of the conformance capabilities)
- Implementation: `homelabnext` 0.1.0
- Owner: platform-team
- Tags: ops, ui
<!-- /hnx:gen -->

<!-- hnx:todo:what -->
> TODO(human): one paragraph: the job, who needs it, what breaks without it.
<!-- /hnx:todo -->

## Inputs

<!-- hnx:gen:inputs -->
- Listens on `http` port `8099` on host `mon-core` (zone `mgmt`)
- TLS: `none`
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
- Registry health probe: HTTP GET `/status.json` expects status `200`
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
- Depends on: [idp](idp.md) ([[systems/idp|idp]])
- Depended on by: [edge-proxy](edge-proxy.md) ([[systems/edge-proxy|edge-proxy]])
<!-- /hnx:gen -->

<!-- hnx:todo:deps -->
> TODO(human): anything the registry cannot know (data, humans, schedules).
<!-- /hnx:todo -->

## Credentials and access

<!-- hnx:gen:access -->
- Authentication: `idp`
- Public hostname: `status.lab.example`
- Endpoint override variable: `HNX_ENDPOINT_STATUS_HUB`
<!-- /hnx:gen -->

<!-- hnx:todo:access -->
> TODO(human): secret-store NAMES only (never values), who may use it.
<!-- /hnx:todo -->

## Source of truth

<!-- hnx:gen:source -->
- Registry row (Veritas, ADR-0028): `services.status-hub`
- Backup: not in a backup job
<!-- /hnx:gen -->

<!-- hnx:todo:source -->
> TODO(human): where the config, runbook and decisions live.
<!-- /hnx:todo -->
