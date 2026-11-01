---
summary: Consumers name model roles; only the LLM gateway maps a role to a backend model.
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
2. Consumers reach the gateway through one registry capability, `llm-gateway` (ADR-0002), and
   name the role in the request (`"model": "<role>"`). There is no per-role endpoint: a role is a
   model name at the gateway, not a DNS name. The serving engines behind it have their own
   capabilities, which consumers do not call.
3. No file outside the gateway configuration and the role table holds a model id or a backend
   address; generated tool configuration carries roles. The one exception is host-side
   verification of a binding: the K-14 serving probe and the golden runs that test one binding
   (`homelabnext.registry.models`, direct mode) resolve the backend from the role table and carry
   the backend's own key. Everything else (agents, the decision cascade, tools) goes through the
   gateway with its own key.
4. Runtime truth about which model is served comes from `/v1/models`, compared against the
   declared mapping; a mismatch is flagged. The K-14 probe asks each backend (it checks a
   binding's model id and loaded context, which the gateway does not expose); the conformance
   suite asks the gateway.
5. The swap test for serving is golden tasks per role and tool-call contract tests, run against a
   fake OpenAI-compatible server in CI. A concurrency benchmark is not part of it yet: the
   deterministic fake cannot measure one (ADR-0022, "Not measured").

## Consequences

- A serving-engine or model change is a gateway configuration change plus a golden-task run.
- The gateway is a tier-0 dependency for inference consumers; keep it small.

## Alternatives

Resolve model facts per consumer at deploy time: works until the first model change that does
not trigger a redeploy.
