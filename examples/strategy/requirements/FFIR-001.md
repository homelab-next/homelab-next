---
id: FFIR-001
title: Is the monitoring that would show an outage healthy itself?
status: active
date: 2026-10-20
author: human:example-planner
consumer: human:example-operator
cadence: PT1H
ltiov: standing
supports: [SO-001, OO-001]
serves: [CCIR-001]
sirs:
  - 1.1 Is every status source the outage question reads collected within its staleness window?
  - 1.2 Does every core service have an uptime monitor?
indicators:
  - a status source stale or in error on the hub's Sources view
  - a core service with no monitor on the uptime status page
sources:
  - status hub (sources table)
  - service registry (status_sources)
tasked_to: [profile:responder]
---

## Question

Would the lab notice an outage right now: is every source the outage question depends on healthy and current?

## Decision supported

Whether the answer to CCIR-001 can be trusted, or the monitoring has to be fixed before anything else.

## Acceptance

A stale or failing status source that CCIR-001 reads is listed, with the source and since when, on the hub within one collection cycle.

## Guardrails

The lab's own posture stays internal: never published outside the lab.

## Links

<!-- hnx:gen:links -->
- Supports: [[SO-001]], [[OO-001]]
- Serves: [[CCIR-001]]
<!-- /hnx:gen -->
