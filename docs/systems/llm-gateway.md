---
title: llm-gateway
type: system
summary: llm-gateway provides the llm-gateway capability (example-llm-gateway), owned
  by ml-team.
summary_generated: true
service: llm-gateway
capability: llm-gateway
impl: example-llm-gateway
owner: ml-team
host: infer-core
port: 4000
protocol: http
health: http
backup_job: null
tags: [compute, inference]
status: draft
author: unknown
---

# llm-gateway

## What it does

<!-- hnx:gen:what -->
- Capability: `llm-gateway`
- Contract: none (`llm-gateway` is not one of the conformance capabilities)
- Implementation: `example-llm-gateway` 1.0.0
- Owner: ml-team
- Tags: compute, inference
<!-- /hnx:gen -->

<!-- hnx:todo:what -->
> TODO(human): one paragraph: the job, who needs it, what breaks without it.
<!-- /hnx:todo -->

## Inputs

<!-- hnx:gen:inputs -->
- Listens on `http` port `4000` on host `infer-core` (zone `compute`)
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
- Registry health probe: HTTP GET `/health/liveliness` expects status `200`
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
- Depends on: [inference](inference.md) ([[systems/inference|inference]])
- Depended on by: [orchestrator](orchestrator.md) ([[systems/orchestrator|orchestrator]])
<!-- /hnx:gen -->

<!-- hnx:todo:deps -->
> TODO(human): anything the registry cannot know (data, humans, schedules).
<!-- /hnx:todo -->

## Credentials and access

<!-- hnx:gen:access -->
- Authentication: `none`
- Endpoint override variable: `HNX_ENDPOINT_LLM_GATEWAY`
<!-- /hnx:gen -->

<!-- hnx:todo:access -->
> TODO(human): secret-store NAMES only (never values), who may use it.
<!-- /hnx:todo -->

## Source of truth

<!-- hnx:gen:source -->
- Registry row (Veritas, ADR-0028): `services.llm-gateway`
- Backup: not in a backup job
<!-- /hnx:gen -->

<!-- hnx:todo:source -->
> TODO(human): where the config, runbook and decisions live.
<!-- /hnx:todo -->
