---
summary: 'Consumers name model roles; only the LLM gateway maps a role to a backend model.'
summary_of: outline:sha256:35e9abb31394d520
---
# ADR-0007: Consumers name model roles; only the gateway maps roles to backends and model ids

- **Status:** proposed
- **Date:** 2026-10-15
- **Related:** ADR-0002, ADR-0005, `schemas/platform/model_roles.json`

## Context

Served model ids and inference endpoints leak into many files: generated tool configuration,
instructions, scripts. Models turn over within weeks, so every model change becomes a
repository-wide edit and a window where consumers disagree about what is being served.

## Decision

1. Consumers request a role: `main-reasoner`, `fast-classifier`, `embedder`, `redactor`,
   `summariser`. A gateway maps role to backend, model id and policy.
2. `inference.svc.example.internal` and `fast-classifier.svc.example.internal` are the only
   endpoints consumers see (ADR-0002).
3. No file outside the gateway configuration holds a model id or a backend address; generated
   tool configuration carries roles.
4. Runtime truth about which model is served comes from the gateway's `/v1/models`, compared
   against the declared mapping; a mismatch is flagged.
5. The swap test for serving is golden tasks per role, tool-call contract tests and a
   concurrency benchmark, run against a fake OpenAI-compatible server in CI.

## Consequences

- A serving-engine or model change is a gateway configuration change plus a golden-task run.
- The gateway is a tier-0 dependency for inference consumers; keep it small.

## Alternatives

Resolve model facts per consumer at deploy time: works until the first model change that does
not trigger a redeploy.
