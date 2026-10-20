---
id: CCIR-001
title: Is any core service down for more than 15 minutes?
status: active
date: 2026-10-20
author: human:example-planner
consumer: human:example-operator
cadence: PT15M
ltiov: standing
supports: [SO-001]
sirs:
  - 1.1 Which core service (DNS, proxy, secrets) has failed its health check for 15 minutes or more?
  - 1.2 Did the failure start with a change (a deploy, an approved proposal) in the hour before?
indicators:
  - an uptime monitor down for three consecutive checks
  - a firing alert on a core service's own health endpoint
sources:
  - status hub (uptime monitors, metrics alerts)
  - the records lanes (recent approved proposals)
tasked_to: [profile:responder]
---

## Question

Is any core service of the lab down for more than 15 minutes, and which one?

## Decision supported

Whether to invoke the outage runbook for that service and tell the lab's users, or to wait for an automatic recovery.

## Acceptance

A monitor that stays down for 15 minutes shows on the operator's status page within the next collection cycle, naming the service and the time it went down.

## Guardrails

Read only: answering the question never restarts or changes a service; recovery is a separate, approved action.

## Links

<!-- hnx:gen:links -->
- Supports: [[SO-001]]
<!-- /hnx:gen -->
