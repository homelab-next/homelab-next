---
summary: The lab's LLM gateway becomes its own Go binary that reads a product-neutral rendered config; LiteLLM stays deployed until that binary passes the gateway suite.
summary_of: outline:sha256:c8cb65aa8eb8766b
---
# ADR-0038: Make the LLM gateway our own, behind the same contract

- **Status:** proposed
- **Date:** 2026-11-07
- **Related:** ADR-0005, ADR-0007, ADR-0022, ADR-0033, [LLM gateway](../llm-gateway.md),
  [orchestration telemetry](../orchestration-telemetry.md), `conformance/protocols/inference.py`
- **Depends-on:** ADR-0033
- **Amends:** ADR-0022, ADR-0033

## Context

ADR-0022 made LiteLLM the only LLM gateway and named an exit if it had to go: a renderer beside
`render_litellm`, an audit of its files, a target file, and a pass of the `inference` suite with the
`gateway` feature. Three things now argue for taking that exit with a gateway of the lab's own
rather than another product:

- **What the lab uses is small.** The rendered config is the whole requirement. It holds the role
  aliases and their ordered deployments, role fallback chains, per-role and per-key request and
  token limits, per-key model lists (which is also how TLP key ceilings are enforced), and one
  read-only telemetry key. LiteLLM is a large Python application that needs Postgres, a salt key and
  a key-provisioning step at every deploy to serve that.
- **The cost of keeping it is high and recurring.** It is the fastest-moving pin in the lab
  (fourteen stable releases in fourteen days at the ADR-0022 evidence run). It has had two
  supply-chain compromises in 2026 (a PyPI release in March, and 1.107.0 in October on both PyPI
  and Docker Hub). Each upgrade waits out the release cooldown, then needs a suite run and a review.
- **It cannot do the one thing the lab still lacks.** The gateway cannot read a request's TLP
  label, because it runs no admission code. So the per-request rule (ADR-0033 decision 11,
  `model_tlp.admit`) has no call site. Key scope is the only enforcement, and a role raised to
  `green` is reachable only by `clear`-ceiling keys ([LLM gateway](../llm-gateway.md), "TLP labels
  on model requests").

The operator already runs a Go controller of their own in front of the same backends: the
orchestrator (`llm-orchestrator`). It does weighted local selection and failover, and owns session
admission. A request-level gateway beside it needs no new language, toolchain or deployment shape.

The orchestrator's repository is private, and this one is public. So the contract and its tests live
here, and the implementation is tested against them from the private side.

## Decision

1. **A product-neutral rendered config.** `hnx gen gateway render` also writes `gateway/gateway.json`
   to a new schema, `schemas/platform/gateway_config.json`. It is a draft until this ADR is
   accepted. The file holds:
   - the gateway's name;
   - the admin key's environment name;
   - each role's kind, context limit, TLP ceiling, whether it leaves the lab, its ordered
     deployments, its fallback chain and its limits. The ceiling and `leaves_lab` are the
     chain-inclusive values the TLP rules already compute (`role_ceiling`, `cloud_roles`), so a
     local role with a cloud fallback reads as leaving the lab;
   - each key's alias, environment name, owner, data tier, sending TLP ceiling, allowed roles and
     limits;
   - the telemetry reader key.

   Each deployment gives its protocol (`openai` or `anthropic`), base URL, backend model id,
   locality and the API key's environment name. Every value comes from the role table, the profiles
   and the gateway spec, exactly as the LiteLLM files do. Secret values never appear: only the
   environment names that `secret:` references map to. The same audit that reads `litellm/` for
   locality and key ceilings reads `gateway/gateway.json`, and also refuses a `local-only` key
   whose roles reach a role that leaves the lab. The renderer refuses its own output when that
   audit fails.
2. **The lab's implementation is the orchestrator's gateway binary.** It is a separate command in
   the orchestrator's Go module, `cmd/gateway`, run as its own process and unit, under its own user
   so agent processes cannot read its environment. It is not a listener inside the controller, for
   two reasons: it holds the provider API keys, and a controller restart must not drop in-flight
   model calls. It reads `gateway.json` and the key values from its environment. Each client key is
   held only as a SHA-256 digest and compared in constant time; provider keys are necessarily held
   as values. At start it refuses a client key shorter than 32 bytes and any two keys with the same
   value. It needs no database.
3. **What it serves.** The first version serves these routes, and refuses everything else with 404:
   - `GET /v1/models`: the role aliases the calling key may call. The admin key sees every alias.
   - `POST /v1/chat/completions`, including streaming.
   - `POST /v1/embeddings`.
   - `GET /v1/usage` (decision 6) and an unauthenticated `GET /healthz`.

   It translates OpenAI-compatible backends and the Anthropic Messages API. A deployment with any
   other protocol is refused by the renderer for this target. A reply's `model` is always the
   requested role alias, never the backend's model id (the ADR-0007 decision 4 signal that the
   `alias-swap` mutant relies on). The gateway decodes each request body, replaces only `model` and
   re-encodes it upstream; it forwards none of the caller's headers (its `Authorization`, any
   `X-HNX-*` header, cookies). It listens on loopback unless it is given a TLS certificate, or is
   told explicitly to accept plaintext on the lab network, which puts bearer tokens and prompts in
   the clear on that segment.
4. **The contract's errors.** These are what the `gateway` feature checks. The gateway evaluates a
   request in this order and stops at the first refusal, which consumes no limit:
   1. A missing or unknown key gets 401, whose reason names no store.
   2. A `model` that is not a role alias, byte for byte, gets 400, and so does a chat call to an
      embedding role or the reverse.
   3. A role outside the key's list gets 403. The gateway never substitutes another role.
   4. A TLP refusal (decision 5) gets 403.
   5. A request past the key's limit, then the role's, gets 429. A role's limit is one budget
      across all its deployments, not a per-deployment share. Limits are counted in memory, so a
      restart starts every window again. Token limits count streamed replies too: the gateway asks
      OpenAI-compatible backends for stream usage, and estimates it when a stream ends without any.

   Upstream failures (a connection error, a timeout, a 429 or a 5xx) move to the next deployment,
   then down the role's rendered fallback chain and nothing else. An upstream 401 or 403 is the
   gateway's own credentials failing, so the caller gets 502, never a 401 that reads as its own key
   failing. Any other upstream 4xx is returned with its status and the gateway's own error body,
   never the upstream body, which can name backend model ids. When every deployment and fallback
   has failed, the caller gets 502. The renderer refuses a chain that crosses locality for a
   local-only or agent role (ADR-0022 decision 3); a chain may still reach the cloud from another
   local role, which is why `leaves_lab` is chain-inclusive.
5. **Per-request TLP admission.** A request may carry its label in one `X-HNX-TLP` header field. The
   gateway applies the `admit` rule to it:
   - The header is read as data. No field reads as `red`, reason `unlabelled` if refused. One field
     is read with `tlp.read`: a value that is not an accepted spelling, including an empty one,
     reads as `red`, reason `above-ceiling` if refused. More than one field reads as `red`, reason
     `above-ceiling`.
   - For a role that leaves the lab, the request is judged at the higher of that label and the
     key's sending ceiling. For a role that stays in the lab, it is judged at its own label. The
     admin key's sending ceiling is always `red`, and a ceiling that is missing or not a label
     reads as `red`.
   - The judged label is checked against the requested role's ceiling. A refusal of the requested
     role is a 403 with the `Admission` reason at once: the gateway never falls back to another
     role because of a TLP refusal, which would be substitution. A fallback role reached after
     upstream failures is admitted the same way first, and skipped if refused.

   The orchestrator's Go module and this repository's Python implement the same rule. This
   repository holds the rule's test vectors (`conformance/fixtures/tlp_admit_vectors.json`), which
   its tests regenerate from `admit` itself, and both implementations must pass them. This is a
   check on data, not admission in ADR-0022's sense: the gateway still does no scheduling, queuing
   or session admission (ADR-0022 decision 1, final bullet), which stay with the serving engine and
   the orchestrator. The gateway becomes the backstop call site for `admit` that ADR-0033 decision
   11 lacked; the agent runtime still applies `admit` to the label it assembled before it sends,
   and sends that label in the header.
6. **Usage records.** The gateway writes one record for every admission decision past the key and
   `model` checks, allowed or refused, to an append-only JSON-lines file. A record uses the neutral
   turn-record names of orchestration telemetry (`turn_id`, `gateway_tag`, `model_role`, `model`,
   `call_type`, `status`, `error_code`, `input_tokens`, `output_tokens`, `cache_read_tokens`,
   `cache_hit`, `cost_usd`, `ttft_ms`, `duration_ms`), plus the key alias, owner, the deployment and
   role that served it, the fallback count, whether usage was estimated, and the admission's
   `record()` fields (`label`, `ceiling`, `leaves_lab`, `allowed`, `reason`). It never holds prompt
   or reply text. A caller may tag a request with one `X-HNX-Tag` header, which is recorded as
   `gateway_tag` and never sent upstream. The telemetry reader key and the admin key can read the
   records over `GET /v1/usage` for a time range and an optional tag. A `TurnSource` adapter for
   that route replaces the spend-log reader in orchestration telemetry for this gateway
   (`homelabnext.conform.adapters`, the `turn-records` feature). The file is not rotated in the
   first version.
7. **Acceptance, then cutover.**
   - The `inference` suite gains a `tlp-admit` feature. Its checks send `X-HNX-TLP` over HTTP: no
     header to a role that leaves the lab is a 403 `unlabelled`; a label within the ceiling is
     served; a label below the key's ceiling is still refused; an empty header field differs from
     no field; a refused fallback is skipped. It runs against a conformance gateway spec with a
     test-only role that leaves the lab, pointed at the fake inference server, which only a
     renderer test option allows.
   - The orchestrator's CI builds `cmd/gateway`, checks out this repository at a pinned commit,
     renders that spec, and runs the `inference` suite with the `streaming`, `embeddings`,
     `gateway`, `tlp-ceiling`, `tlp-admit` and `turn-records` features against the binary and the
     fake inference server.
   - Until that run is green on the orchestrator's main branch and the binary has served the lab
     beside LiteLLM, LiteLLM stays the deployed gateway.
   - Cutover also needs the agent runtime to send `X-HNX-TLP`. Until it does, every request reads
     as `red` and the gateway refuses every role that leaves the lab to every key, where LiteLLM
     today lets a `clear`-ceiling key reach one. Cutting over before that is allowed only if the
     operator records that the lab accepts losing cloud roles until the runtime sends labels.
   - Cutover is the operator's change of the overlay's gateway target. Removing LiteLLM's renderer,
     its Postgres role and its provisioning step is a later, dated amendment to this ADR, not part
     of it.
8. **ADR-0022 is amended.** LiteLLM is the deployed gateway until the cutover in decision 7, and its
   decision 1 rules hold for as long as it runs. The documented exit is this ADR, no longer Bifrost.
9. **ADR-0033 is amended.** Decision 11's statements that the gateway cannot read a request's label
   and that no component calls `admit` hold only for LiteLLM. With this gateway, the rule is
   enforced per request at the gateway as well as by key scope (decision 5).

## Consequences

- A gateway swap is still a target file plus a passing suite (ADR-0005). The swap is now to code the
  operator owns, and the contract it is tested against does not move.
- Once LiteLLM is removed, the lab loses Postgres's `litellm` schema, `LITELLM_SALT_KEY`, the
  key-provisioning step, about 520 MB of resident memory and about 30 s of startup.
- Keys become code. Adding or revoking a key is a spec change and a restart, not an admin API call.
  A key stays valid until the gateway restarts with the new config, so revocation is as fast as a
  deploy.
- The lab now maintains a gateway: roughly a thousand lines of Go plus two protocol translations,
  and their tests. It runs in the lab's path to every model, so a defect there stops every agent.
  The suite and the side-by-side period are the guard against that.
- Limits reset on restart, and a gateway's limits are per process. Two gateway instances would each
  allow the full budget. The lab runs one.
- Provider coverage shrinks to OpenAI-compatible endpoints and Anthropic. A role that needs another
  provider cannot use this gateway until a translation for it is added.
- The `X-HNX-TLP` header lets a caller narrow what it may send, never widen it: the judged label is
  never below the key's ceiling for a role that leaves the lab. A caller that mislabels below its
  real data is still bounded by its key's ceiling, as today.
- Docs that describe today's gateway as unable to read labels (`docs/llm-gateway.md`, the
  `model_tlp` and `conformance/protocols/inference.py` docstrings, `docs/modules/egress.md`) stay
  true for LiteLLM and are updated at cutover.
- The usage file grows without rotation until a later change adds it.

## Alternatives

- **Keep LiteLLM.** This is the status quo, and it stays the status quo until decision 7's cutover.
  Kept as the only gateway, it leaves the cost above and the missing per-request TLP call site in
  place.
- **Bifrost.** It is the evaluated exit in ADR-0022. It fails three MUST checks of the inference
  contract (provider-prefixed ids in `/v1/models`, backend ids in replies, silent role
  substitution), and it is another vendor's release stream to follow.
- **A listener inside the controller.** This means one binary and one unit. It was rejected because
  provider keys would sit in the process that runs agent subprocesses, and because a controller
  restart, which is frequent during profile work, would cut model calls in flight.
- **Write the gateway in this repository.** This repository is public and its code is Python with
  no long-running network server of this kind. The operator's Go controller already speaks to the
  same backends, has the failover code and runs in the lab. The contract, the schema and the tests
  stay here, so the implementation is replaceable.
