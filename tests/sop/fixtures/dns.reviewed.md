---
title: dns
type: system
service: dns
capability: dns
impl: technitium
owner: platform-team
host: dns-core
port: 53
protocol: dns
health: none
backup_job: null
tags: [core]
status: reviewed
author: unknown
reviews:
- {by: 'agent:example-checker', kind: agent, role: check, date: '2026-10-19', verdict: pass,
  digest: 'sha256:9ac56b5d5963', note: test fixture}
- {by: 'agent:example-auditor', kind: agent, role: audit, date: '2026-10-19',
  verdict: pass, digest: 'sha256:9ac56b5d5963', note: test fixture}
- {by: 'human:example-operator', kind: human, role: approve, date: '2026-10-19', verdict: pass,
  digest: 'sha256:9ac56b5d5963', note: test fixture}
---

# dns

## What it does

<!-- hnx:gen:what -->
- Capability: `dns`
- Contract: none (`dns` is not one of the conformance capabilities)
- Implementation: `technitium` 13.0
- Owner: platform-team
- Tags: core
<!-- /hnx:gen -->

<!-- hnx:todo:what -->
Resolves internal names for every zone of the example lab; without it nothing finds its upstreams.
<!-- /hnx:todo -->

## Inputs

<!-- hnx:gen:inputs -->
- Listens on `dns` port `53` on host `dns-core` (zone `mgmt`)
- TLS: `none`
- Allowed client zones: mgmt, data, compute, edge
<!-- /hnx:gen -->

<!-- hnx:todo:inputs -->
DNS queries over UDP and TCP port 53 from the allowed client zones.
<!-- /hnx:todo -->

## Outputs

<!-- hnx:gen:outputs -->
- Metrics: none declared
- MCP: none
<!-- /hnx:gen -->

<!-- hnx:todo:outputs -->
Answers for the lab zones and forwarded answers for everything else.
<!-- /hnx:todo -->

## How to use it

<!-- hnx:todo:use -->
Add a record in the server's zone editor, then query it: `dig @dns-core svc.lab.example`.
<!-- /hnx:todo -->

## How to verify it is healthy

<!-- hnx:gen:verify -->
- Registry health probe: no probe is defined in the registry (a gap: add one, or say why none is possible)
<!-- /hnx:gen -->

<!-- hnx:todo:verify -->
`dig @dns-core dns-core.lab.example +short` returns the server's own address.
<!-- /hnx:todo -->

## Failure modes

<!-- hnx:todo:failure -->
Clients time out: check the service is listening on port 53, then the zone ACLs.
<!-- /hnx:todo -->

## Depends on / depended on by

<!-- hnx:gen:deps -->
- Depends on: none declared
- Depended on by: none declared
<!-- /hnx:gen -->

<!-- hnx:todo:deps -->
None beyond its host; every other service depends on it.
<!-- /hnx:todo -->

## Credentials and access

<!-- hnx:gen:access -->
- Authentication: `none`
- Endpoint override variable: `HNX_ENDPOINT_DNS`
<!-- /hnx:gen -->

<!-- hnx:todo:access -->
Admin credential: secret-store name `dns-admin`; platform-team only.
<!-- /hnx:todo -->

## Source of truth

<!-- hnx:gen:source -->
- Registry row: `services.dns`
- Backup: not in a backup job
<!-- /hnx:gen -->

<!-- hnx:todo:source -->
Zone files in the configuration repository; this page and its runbook.
<!-- /hnx:todo -->
