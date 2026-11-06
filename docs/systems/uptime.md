---
title: uptime
type: system
summary: uptime provides the uptime capability (uptime-kuma), owned by platform-team.
summary_generated: true
service: uptime
capability: uptime
impl: uptime-kuma
owner: platform-team
host: mon-core
port: 3001
protocol: http
health: http
backup_job: null
tags: [monitoring, ops]
status: draft
author: unknown
---

# uptime

## What it does

<!-- hnx:gen:what -->
- Capability: `uptime`
- Contract: none (`uptime` is not one of the conformance capabilities)
- Implementation: `uptime-kuma` 2.5.6
- Owner: platform-team
- Tags: monitoring, ops
<!-- /hnx:gen -->

<!-- hnx:todo:what -->
> TODO(human): one paragraph: the job, who needs it, what breaks without it.
<!-- /hnx:todo -->

## Inputs

<!-- hnx:gen:inputs -->
- Listens on `http` port `3001` on host `mon-core` (zone `mgmt`)
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
- Registry health probe: HTTP GET `/api/entry-page` expects status `200`
<!-- /hnx:gen -->

<!-- hnx:todo:verify -->
> TODO(human): the observable that proves it works, beyond the probe.
<!-- /hnx:todo -->

## Failure modes

<!-- hnx:todo:failure -->
> TODO(human): symptom, likely cause, first check, fix: one row each.

- **Healthy probe, but no UI, no login and no status page (Uptime Kuma 2.x).** Likely cause: the
  data directory has neither `db-config.json` nor a 1.x `kuma.db`, so 2.x serves its first-run
  "setup database" page and holds the server, and that page also answers the registry probe
  (`/api/entry-page`, 200, `{"type": "setup-database"}`). First check: the probe's body, or
  `/setup-database-info`. Fix: set `UPTIME_KUMA_DB_TYPE` (`sqlite`, or `mariadb` with
  `UPTIME_KUMA_DB_HOSTNAME`, `..._PORT`, `..._NAME`, `..._USERNAME` and `..._PASSWORD`, each
  `_FILE`-able) or ship `db-config.json` in the data directory before the first start. This is
  a security requirement, not only an availability one: `/setup-database` takes no
  authentication, so whoever reaches a fresh 2.x first chooses its database (one they control
  included), a pre-auth takeover. The lab-in-a-box sets `UPTIME_KUMA_DB_TYPE: sqlite` and its
  health check requires `type: entryPage`.
- **A kept 1.x data volume does not start on the rootless image.** Likely cause: 1.x ran as root
  here, so the volume is root-owned and the 2.x `-rootless` image (uid 1000) cannot write it;
  2.x would also migrate it one way. Fix in the lab: `docker compose down -v`. Elsewhere: back
  up `data/`, then follow the upstream v1 to v2 migration guide.
<!-- /hnx:todo -->

## Depends on / depended on by

<!-- hnx:gen:deps -->
- Depends on: none declared
- Depended on by: [edge-proxy](edge-proxy.md) ([[systems/edge-proxy|edge-proxy]])
<!-- /hnx:gen -->

<!-- hnx:todo:deps -->
> TODO(human): anything the registry cannot know (data, humans, schedules).
<!-- /hnx:todo -->

## Credentials and access

<!-- hnx:gen:access -->
- Authentication: `idp`
- Public hostname: `uptime.lab.example`
- Endpoint override variable: `HNX_ENDPOINT_UPTIME`
<!-- /hnx:gen -->

<!-- hnx:todo:access -->
> TODO(human): secret-store NAMES only (never values), who may use it.
<!-- /hnx:todo -->

## Source of truth

<!-- hnx:gen:source -->
- Registry row (Veritas, ADR-0028): `services.uptime`
- Backup: not in a backup job
<!-- /hnx:gen -->

<!-- hnx:todo:source -->
> TODO(human): where the config, runbook and decisions live.
<!-- /hnx:todo -->
