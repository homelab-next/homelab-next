# ADR-0022: Run LiteLLM, the supported way, as the LLM gateway; keep Bifrost as the tested alternate

- **Status:** proposed
- **Date:** 2026-10-21
- **Related:** ADR-0005, ADR-0007, `schemas/platform/model_roles.json`, [LLM gateway](../llm-gateway.md)

## Context

ADR-0007 says consumers name model roles and only the gateway maps a role to a backend. It does not
say which product the gateway is. LiteLLM was dismissed once after real problems. A wrong key got
`No connected db` instead of a 401. Upstream releases change constantly, and one PyPI release was
compromised in March 2026. Most of those problems turned out to come from running it without
Postgres, unpinned, and with custom admission code in a callback. Bifrost (Go, Apache-2.0) is the
credible alternative, but almost all the published evidence about it comes from its vendor.

So the question was settled by running both, not by reading about them. Each gateway was put in
front of the project's fake OpenAI-compatible server, using config generated from
`model_roles.valid.json` and the example agent profiles. Then each was run through the `inference`
suite with three new `gateway` checks: a bad key gets a clean 401, a configured limit gets a 429,
and `/v1/models` lists exactly the role aliases. Docker was not used. LiteLLM 1.103.3 came from
PyPI, with distro Postgres 16 in a throwaway cluster. Bifrost 2.2.6 was the static binary taken
from the image `maximhq/bifrost:v2.2.6@sha256:d0b4708a…`; every layer was verified against its
digest, because GitHub release assets were not reachable. Both are versions at least 14 days old.

| Check (raw HTTP unless noted) | LiteLLM 1.103.3 + Postgres | LiteLLM 1.103.3, no Postgres | Bifrost 2.2.6 |
|---|---|---|---|
| `hnx conform run inference` (12 checks) | **12/12 pass** | 10/12: fails `gateway-rejects-bad-key` and `gateway-limit-throttles` | 9/12: fails three MUSTs (`models-lists-the-served-model`, `chat-echoes-requested-model`, `gateway-models-match-roles`) |
| wrong key | 401 `token_not_found_in_db` | **400 `No connected db.`** | 401 `access_not_found` |
| no key | 401 `auth_error` | 500 (pip install has no `prisma`) | 401 `virtual_key_required` |
| per-key limit, 3/min | 429 on call 4 (`throttling_error`) | no keys without a DB | 429 on call 4 (`request_limited`) |
| per-role limit, 3/min | 429 on call 4, `No deployments available` (type `internal_server_error`); needs `enable_pre_call_checks` | — | 429 on call 4 (`model_config` rate limit) |
| `/v1/models`, admin key | `[fast-classifier, main-reasoner]` = role table | same | `[hnx-inference-large/main-reasoner, hnx-inference-small/fast-classifier]` |
| `/v1/models`, one agent's key | that agent's roles only | — | that agent's roles, provider-prefixed |
| reply `model` for role `fast-classifier` | `fast-classifier` | same | `example-4b` (the backend id) |
| key asks for a role outside its scope | 403 `key_model_access_denied` | — | **200**: with a role-fallback routing rule, served by the fallback role (silent substitution); without one, 400 |
| unknown model | 400 | 400 | 400 |
| role fallback, primary backend down | 200 via fallback, header `x-litellm-attempted-fallbacks: 1` | — | 200 via fallback, `routing_info.is_fallback: true` |
| start-up, RSS | ~31 s (migrations), ~520–550 MB | ~12 s | ~1 s, ~135 MB |
| keys as code | no: keys live in Postgres, set through the admin API (`hnx gen gateway provision`) | — | yes: in `config.json` (sqlite state), but a value without the `sk-bf-` prefix is **silently replaced** with a generated key |
| offline start | starts | starts | **fatal** with default settings (datasheet download); starts with `file://` datasheets |
| release cadence | 14 stable releases in 14 days | | 5 releases in 19 days |

Two documentation and behaviour findings on Bifrost came up during the run. Its governance docs
write routing-rule CEL as `request.model`, but the engine only compiles `model`. And the npm
launcher downloads the binary without verifying a checksum.

## Decision

1. The LLM gateway is **LiteLLM, run the supported way**:
   - Postgres (the lab's own, schema `litellm`) and `LITELLM_SALT_KEY`;
   - the `litellm-database` image pinned by digest, following one stable patch line;
   - no custom callbacks and no admission logic in the gateway;
   - every upgrade must first pass the `inference` suite with the `gateway` feature.
2. Gateway config is generated from the role table, the agent profiles and a small spec
   (`hnx gen gateway render`), never written by hand. Every agent profile gets its own virtual key,
   scoped to its role and that role's fallback chain. Secrets appear only as `secret:` references.
3. A local-only role and everything in its fallback chain stay on local backends. An agent role's
   fallback chain never changes locality. The generator refuses any config that breaks this, and
   `make gateway-check` audits the rendered files for it.
4. `gateway-rejects-bad-key`, `gateway-limit-throttles` and `gateway-models-match-roles` are the
   gateway contract. Any target that declares the `gateway` feature must pass them.
5. Bifrost stays wired as the tested alternate: config is rendered from the same inputs, there is a
   `gateway-bifrost` lab profile, and it has a target file. It can be revisited when it passes the
   same suite unchanged.

## Consequences

- Swapping the gateway means changing a target file and passing a suite (ADR-0005). The ADR-0007
  decision 4 check (`/v1/models` against the declared mapping) now runs against the real gateway.
- LiteLLM brings Postgres and a key-provisioning step at deploy time, because keys cannot be in the
  config file. It also uses roughly 4× Bifrost's memory and takes ~30 s to start.
- Its release cadence makes the digest pin and the conformance gate mandatory, not optional.
- The 429 for a per-role limit carries a misleading error type. Callers must branch on the status
  code.
- The lab gains two optional profiles (1088 MB together). They are outside the 3584 MB default
  budget and not part of the nightly.
- Not measured: concurrency, latency, streaming under load, and behaviour with a GPU-backed engine.
  The run used the deterministic fake.

## Alternatives

- **Bifrost.** It is smaller, faster to start, and keeps keys in its config file. It fails three
  inference-contract MUST checks as configured here: `/v1/models` lists provider-prefixed ids, and
  replies name the backend model rather than the requested role. That is exactly the signal the
  `alias-swap` mutant uses to catch a silent model swap. Its role-fallback routing rule can also
  serve a key a model it did not ask for. It is kept as the alternate, not the choice.
- **LiteLLM without Postgres.** This is the configuration that failed before: a wrong key gets
  `400 No connected db.`, and there are no virtual keys or per-key limits.
  `gateway-rejects-bad-key` now fails it.
- **Envoy AI Gateway, TensorZero, Portkey, Kong.** Not run. Envoy AI Gateway depends on Kubernetes,
  and TensorZero routes only statically. Neither fits a single-host lab better than the two that
  were tested.
- **Admission and scheduling in the gateway.** Rejected. Request-level gateways cannot see agent
  sessions, and a past custom admission callback built into the gateway was itself a recurring
  source of faults.
