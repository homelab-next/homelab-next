---
title: auth-proxy
type: system
summary: auth-proxy provides the auth-proxy capability (oauth2-proxy), owned by identity-team.
summary_generated: true
service: auth-proxy
capability: auth-proxy
impl: oauth2-proxy
owner: identity-team
host: edge-core
port: 4180
protocol: http
health: http
backup_job: null
tags: [core, edge, identity]
status: draft
author: unknown
---

# auth-proxy

## What it does

<!-- hnx:gen:what -->
- Capability: `auth-proxy`
- Contract: none (`auth-proxy` is not one of the conformance capabilities)
- Implementation: `oauth2-proxy` 7.15.5
- Owner: identity-team
- Tags: core, edge, identity
<!-- /hnx:gen -->

<!-- hnx:todo:what -->
> TODO(human): one paragraph: the job, who needs it, what breaks without it.
<!-- /hnx:todo -->

## Inputs

<!-- hnx:gen:inputs -->
- Listens on `http` port `4180` on host `edge-core` (zone `edge`)
- TLS: `none`
- Allowed client zones: edge
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
- Registry health probe: HTTP GET `/ping` expects status `200`
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
- Authentication: `own`
- Endpoint override variable: `HNX_ENDPOINT_AUTH_PROXY`
<!-- /hnx:gen -->

<!-- hnx:todo:access -->
> TODO(human): secret-store NAMES only (never values), who may use it.
<!-- /hnx:todo -->

## Source of truth

<!-- hnx:gen:source -->
- Registry row (Veritas, ADR-0028): `services.auth-proxy`
- Backup: not in a backup job
<!-- /hnx:gen -->

<!-- hnx:todo:source -->
> TODO(human): where the config, runbook and decisions live.
<!-- /hnx:todo -->
