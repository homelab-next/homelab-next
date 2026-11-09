---
title: secrets
type: system
summary: secrets provides the secrets capability (openbao), owned by identity-team.
summary_generated: true
service: secrets
capability: secrets
impl: openbao
owner: identity-team
host: secrets-core
port: 8200
protocol: https
health: http
backup_job: daily-core
tags: [core, secrets]
status: draft
author: unknown
---

# secrets

## What it does

<!-- hnx:gen:what -->
- Capability: `secrets`
- Contract: [secrets capability reference](../capabilities/secrets.md) ([[capabilities/secrets|secrets capability]]): operations, data shapes, conformance checks, adapters
- Implementation: `openbao` 2.7.1
- Owner: identity-team
- Tags: core, secrets
<!-- /hnx:gen -->

<!-- hnx:todo:what -->
> TODO(human): one paragraph: the job, who needs it, what breaks without it.
<!-- /hnx:todo -->

## Inputs

<!-- hnx:gen:inputs -->
- Listens on `https` port `8200` on host `secrets-core` (zone `mgmt`)
- TLS: `mtls`
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
- Registry health probe: HTTP GET `/v1/sys/health` expects status `200`
<!-- /hnx:gen -->

<!-- hnx:todo:verify -->
> TODO(human): the observable that proves it works, beyond the probe.
<!-- /hnx:todo -->

## Failure modes

<!-- hnx:todo:failure -->
> TODO(human): symptom, likely cause, first check, fix: one row each.

- **A production OpenBao upgraded from 2.1 to 2.7 does not start, or starts without its data or
  API.** Likely cause: what 2.2 to 2.7 removed. 2.2 dropped legacy barrier entries and direct
  Shamir keys from storage. 2.7 removed the `file` storage backend, and its release notes list
  seal, plugin and LDAP/Kerberos/RADIUS removals. 2.5.4 removed the legacy `sys/renew` and
  `sys/revoke*` lease endpoints. First check: the server's storage stanza, seal and enabled auth
  methods against the 2.7 release notes. Fix: move off the `file` backend (to raft, as
  [the private overlay](../private-overlay.md) installs it) and off any removed seal or auth
  method before the upgrade. In server mode the container now starts as the `openbao` user (2.6)
  and the image declares no `VOLUME` (2.7), so mount the data directory explicitly and give it to
  that user. Since 2.5 a listener refuses the unauthenticated `sys/rekey/*` endpoints, so rotate
  unseal keys with `bao operator rotate-keys`. The lab-in-a-box runs `server -dev` in memory and
  is unaffected.

<!-- /hnx:todo -->

## Depends on / depended on by

<!-- hnx:gen:deps -->
- Depends on: none declared
- Depended on by: [object-store](object-store.md) ([[systems/object-store|object-store]]), [orchestrator](orchestrator.md) ([[systems/orchestrator|orchestrator]])
<!-- /hnx:gen -->

<!-- hnx:todo:deps -->
> TODO(human): anything the registry cannot know (data, humans, schedules).
<!-- /hnx:todo -->

## Credentials and access

<!-- hnx:gen:access -->
- Authentication: `own`
- Endpoint override variable: `HNX_ENDPOINT_SECRETS`
<!-- /hnx:gen -->

<!-- hnx:todo:access -->
> TODO(human): secret-store NAMES only (never values), who may use it.
<!-- /hnx:todo -->

## Source of truth

<!-- hnx:gen:source -->
- Registry row (Veritas, ADR-0028): `services.secrets`
- Backup: job `daily-core`
<!-- /hnx:gen -->

<!-- hnx:todo:source -->
> TODO(human): where the config, runbook and decisions live.
<!-- /hnx:todo -->
