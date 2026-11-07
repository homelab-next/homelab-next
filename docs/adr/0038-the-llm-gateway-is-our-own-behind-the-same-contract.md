---
summary: The lab's LLM gateway becomes its own Go binary that reads a product-neutral rendered config; LiteLLM stays deployed until that binary passes the gateway suite.
summary_of: outline:sha256:c8cb65aa8eb8766b
---
# ADR-0038: Make the LLM gateway our own, behind the same contract

- **Status:** proposed
- **Date:** 2026-11-07
- **Related:** ADR-0005, ADR-0007, ADR-0022, ADR-0033, [LLM gateway](../llm-gateway.md),
  [orchestration telemetry](../orchestration-telemetry.md), `conformance/protocols/inference.py`
- **Amends:** ADR-0022

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
   to a new schema, `schemas/platform/gateway_config.schema.json`. It is a draft until this
   ADR is accepted. The file holds:
   - the gateway's name;
   - the admin key's environment name;
   - each role's kind, context limit, TLP ceiling, whether it leaves the lab, its ordered
     deployments, its fallback chain and its limits;
   - each key's alias, environment name, owner, data tier, sending TLP ceiling, allowed roles and
     limits;
   - the telemetry reader key.

   Each deployment gives its protocol (`openai` or `anthropic`), base URL, backend model id,
   locality and the API key's environment name. Every value comes from the role table, the profiles
   and the gateway spec, exactly as the LiteLLM files do. Secret values never appear: only the
   environment names that `secret:` references map to. The same audit that reads `litellm/` for
   locality and key ceilings reads `gateway/gateway.json`. The renderer refuses its own output
   when that audit fails.
2. **The lab's implementation is the orchestrator's gateway binary.** It is a separate command in
   the orchestrator's Go module, `cmd/gateway`, run as its own process and unit. It is not a
   listener inside the controller, for two reasons: it holds the provider API keys, and a
   controller restart must not drop in-flight model calls. It reads `gateway.json` and the key
   values from its environment. It holds each key only as a SHA-256 digest and compares in constant
   time. It needs no database.
3. **What it serves.** The first version serves these routes, and refuses everything else with 404:
   - `GET /v1/models`: the role aliases the calling key may call. The admin key sees every alias.
   - `POST /v1/chat/completions`, including streaming.
   - `POST /v1/embeddings`.

   It translates OpenAI-compatible backends and the Anthropic Messages API. A deployment with any
   other protocol is refused by the renderer for this target. A reply's `model` is always the
   requested role alias, never the backend's model id (the ADR-0007 decision 4 signal that the
   `alias-swap` mutant relies on).
4. **The contract's errors.** These are what the `gateway` feature checks:
   - A missing or unknown key gets 401, whose reason names no store.
   - A role outside the key's list gets 403. The gateway never substitutes another role.
   - A request past a key's or a role's limit gets 429.

   A role's limit is one budget across all its deployments, not a per-deployment share. Limits are
   counted in memory, so a restart starts every window again. Upstream failures follow the role's
   rendered fallback chain and nothing else. The chain never crosses locality, because the renderer
   refuses a chain that would (ADR-0022 decision 3).
5. **Per-request TLP admission.** A request may carry its label in an `X-HNX-TLP` header. The gateway
   applies the `admit` rule to it:
   - The header is read as data: a missing header, or a value that is not an accepted spelling,
     reads as `red`.
   - For a role that leaves the lab, the request is judged at the higher of that label and the
     key's sending ceiling. For a role that stays in the lab, it is judged at its own label.
   - The judged label is checked against the requested role's ceiling. Each role in its fallback
     chain is checked again before the call falls back to it.
   - A refusal is a 403 with the `Admission` reason (`above-ceiling`, `unlabelled`).

   The orchestrator's Go module and this repository's Python implement the same rule. This
   repository holds the rule's test vectors (`conformance/fixtures/tlp_admit_vectors.json`),
   and both implementations must pass them. This is a check on data, not admission in ADR-0022's
   sense: the gateway still does no scheduling, queuing or session admission (ADR-0022 decision 1,
   final bullet), which stay with the serving engine and the orchestrator.
6. **Usage records.** Every call the gateway answers writes one usage record to an append-only
   JSON-lines file. A record holds the time, key alias, owner, role, the deployment that served it,
   the status, the token counts and the latency. It never holds prompt or reply text. The telemetry
   reader key, and only that key, can read the records over `GET /v1/usage` for a time range. A
   `TurnSource` adapter for that route replaces the spend-log reader in orchestration telemetry for
   this gateway (`homelabnext.conform.adapters`, the `turn-records` feature).
7. **Acceptance, then cutover.** The orchestrator's CI builds `cmd/gateway`, checks out this
   repository at a pinned commit, renders the lab-in-a-box gateway spec, and runs the `inference`
   suite with the `streaming`, `embeddings`, `gateway` and `tlp-ceiling` features against the
   binary and this repository's fake inference server. Until that run is green on the
   orchestrator's main branch and the binary has served the lab beside LiteLLM, LiteLLM stays the
   deployed gateway. Cutover is the operator's change of the overlay's gateway target. Removing
   LiteLLM's renderer, its Postgres role and its provisioning step is a later, dated amendment to
   this ADR, not part of it.
8. **ADR-0022 is amended.** LiteLLM is the deployed gateway until the cutover in decision 7, and its
   decision 1 rules hold for as long as it runs. The documented exit is this ADR, no longer Bifrost.

## Consequences

- A gateway swap is still a target file plus a passing suite (ADR-0005). The swap is now to code the
  operator owns, and the contract it is tested against does not move.
- Once LiteLLM is removed, the lab loses Postgres's `litellm` schema, `LITELLM_SALT_KEY`, the
  key-provisioning step, about 520 MB of resident memory and about 30 s of startup.
- Keys become code. Adding or revoking a key is a spec change and a restart, not an admin API call.
  A key stays valid until the gateway restarts with the new config, so revocation is as fast as a
  deploy.
- The lab now maintains a gateway. That is about a thousand lines of Go plus two protocol
  translations, and its tests. It runs in the lab's path to every model, so a defect there stops
  every agent. The suite and the side-by-side period are the guard against that.
- Limits reset on restart, and a gateway's limits are per process. Two gateway instances would each
  allow the full budget. The lab runs one.
- Provider coverage shrinks to OpenAI-compatible endpoints and Anthropic. A role that needs another
  provider cannot use this gateway until a translation for it is added.
- The `X-HNX-TLP` header gives the agent runtime a place to send the label it assembled. The runtime
  is not changed by this ADR: until it sends the header, every request reads as `red`, which
  refuses cloud roles to everyone. That is the safe default and also a behaviour change from
  LiteLLM, where a `clear`-ceiling key could reach a cloud role with no label. It is called out in
  the cutover.

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
