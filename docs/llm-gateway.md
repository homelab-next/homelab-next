---
summary: 'The LLM gateway, where a role becomes a backend and model id: generated config, the locality rule, TLP labels on requests, lab-in-a-box, conformance, LiteLLM.'
summary_of: outline:sha256:0f06bc9ebbfefedc
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# LLM gateway

The gateway is the one place where a model role (ADR-0007) becomes a backend and a model id. Every
consumer (agents, the decision cascade, tools) calls the `llm-gateway` capability with a role name
as the model and its own key (the `inference` capability names a serving engine, which consumers do
not call). The gateway enforces that key's scope and limits and forwards the call to the
backend. The decision on which product does this is [ADR-0022](adr/0022-llm-gateway-litellm.md):
**LiteLLM, run the supported way**, and it is the only gateway: the Bifrost adapter was removed
on 2026-10-31 (ADR-0022, amendment). Bifrost stays the documented exit if LiteLLM must be
replaced, through the product-neutral gateway contract below (the spec, the locality rule and the
`gateway` conformance feature).

The gateway handles single requests. It does not schedule agent sessions, admit work against GPU
capacity, or choose cloud for an agent. Those belong to the orchestrator, and the gateway config
must not take them over (see the locality rule below). How the orchestrator's backends become
role aliases is in [orchestration-controller.md](orchestration-controller.md)
([[orchestration-controller]]).

## One source of truth, generated config

The gateway config is never written by hand. `hnx gen gateway render` builds it from three
inputs:

| Input | Gives |
|---|---|
| the role table (`schemas/platform/model_roles.json`) | roles, bindings in priority order, `fallback`, `limits`, context length, cost per 1k tokens |
| the agent profiles (`schemas/agent/profile.schema.json`) | one key per profile (`profile:reader` gets `agent-reader`, secret `secret:llm-gateway/key-reader`), the role it calls and its `data_tier` |
| a small gateway spec (YAML) | where each `svc:` backend is (`local`, or `cloud` with a provider), the secrets for the master key and the database, and any extra non-agent keys |
| optionally, a serving spec (`serving:`, [model-serving.md](model-serving.md)) | the store-served backends: each becomes `{locality: local, port}` from the serving plan, and every binding on it must resolve to a store entry its engine may serve; the plan's `exposure` must be `zone`, and a registry service for a backend must have the plan's port |

```bash
hnx gen gateway render SPEC OUT_DIR            # writes litellm/ and gateway/ under OUT_DIR
hnx gen gateway render SPEC OUT_DIR --check    # drift check and locality audit (make gateway-check)
hnx gen gateway provision OUT_DIR/litellm/keys.json   # create LiteLLM keys on a running proxy
hnx gen gateway homes --roles ROLES HOME...    # no HERMES_HOME names an IP or an engine model id (A-14)
```

A spec may declare the orchestration telemetry's spend-log reader (`telemetry_reader:`, its key's
secret): LiteLLM then gets a spend-viewer user and one key confined to `/spend/logs/v2`
([orchestration telemetry](orchestration-telemetry.md), "LiteLLM: the spend-log API with a viewer
key").

A spec may also name the orchestration controller in front of it (`controller:`, its config, the
gateway's `base_url` as the homes name it, and one `HERMES_HOME` per local backend). `--check` then
also fails when a controller backend is not a `svc:` of the spec, its home's `model.default` is not
a role bound to it alone, its `max_context` is not that role's `max_context_tokens`, its home's
`model.base_url` is not the gateway's, its home's `model.context_length` is set and not a whole
number of tokens up to the role's `max_context_tokens`, or that role has no `max_context_tokens`
([orchestration-controller.md](orchestration-controller.md), "Checks").

It writes:

- **`litellm/config.yaml`**. The `model_list` has one entry per binding, and `model_name` is the
  role. Binding priority becomes `order`. Role `limits` become per-deployment `rpm`/`tpm` (the
  per-minute share, rounded down) and `max_budget`. LiteLLM limits each deployment and its
  pre-call checks move an over-limit request onto the next one, so a role with `n` bindings gives
  each deployment `1/n` of the share and of the budget (rounded down): the sum is never above the
  declared figure, and a share that rounds to nothing is refused. LiteLLM counts only per minute, so a limit
  must have a window of whole minutes and at least one call a minute: `1` per `3600` s or `5` per
  `10` s is refused rather than rendered looser (`1` rpm, `30` rpm). Counts are whole numbers of
  at least 1; `max_requests: 0` is refused, never rendered as unlimited. Role fallbacks go in `router_settings`, with
  `enable_pre_call_checks: true` so the limits are enforced. `general_settings` holds the master
  key and the database only as `os.environ/HNX_SECRET_*` references.
- **`litellm/keys.json`**. These are the virtual keys. LiteLLM stores keys in Postgres, not in its
  config file, so `provision` finds each one by `key_alias` (`/key/list`) and creates it
  (`/key/generate`), updates it in place by its token when the value is unchanged (`/key/update`),
  or, when the secret was rotated, deletes the old key by its token first, so the old value stops
  working, and creates the new one. Each key names the environment variable that holds its value, never the value.
  The spec's `name` (a slug) is the gateway's identity: `keys.json` carries it as `managed_by` and
  every key as `metadata: {"hnx-managed": "<name>"}`. After the declared keys, `provision` lists
  every key on the proxy (all `/key/list` pages) and deletes each key tagged with **this** name
  whose alias the file no longer declares, so a profile removed from the spec does not leave a
  working key behind. Keys tagged by another gateway spec on the same proxy (another site, staging
  beside production) and keys without the tag are never touched. A file that declares no keys
  refuses to prune, one that does not parse is refused outright, and an unnamed spec tags its keys
  `true` and prunes nothing. `--dry-run` sends no write and prints what would change;
  `--keep-undeclared` skips the deletion; each line is printed as it happens.
  **One-time cleanup:** a key provisioned before the tag existed gets it on its next `provision`,
  but one whose profile was removed before then carries no tag and is never deleted by
  `provision`. Its alias is listed ("untagged key(s) ... left alone"): delete it by hand once
  (`/key/delete` with its token). `--check` fails a key whose tag is not the spec's name, a
  `managed_by` that differs from it, and an alias declared twice.
Secrets are always `secret:<name>` and are delivered in `HNX_SECRET_<NAME>` (the registry's
mapping). The renderer refuses a literal value.

## The neutral gateway config, `gateway/gateway.json`

Beside `litellm/`, `render` also writes `gateway/gateway.json`: the product-neutral config of
[ADR-0038](adr/0038-the-llm-gateway-is-our-own-behind-the-same-contract.md) that the lab's own
gateway reads (schema `schemas/platform/gateway_config.schema.json`, a draft until ADR-0038 is
accepted). It comes from the same spec as the LiteLLM files and says the same things in one file:

- each role's kind, context limit, TLP ceiling and `leaves_lab` (both chain-inclusive: the role
  table's `role_ceiling` and `cloud_roles` over the role and its whole fallback chain, exactly what
  `model_tlp.admit` reads), its deployments in binding order (`openai` protocol for a local
  backend, its base URL without `/v1`; a cloud one on `https://api.openai.com` or
  `https://api.anthropic.com`), its fallbacks (what LiteLLM's `fallbacks` gets) and its limits as
  declared, one budget per role in its own window (not LiteLLM's per-minute, per-deployment
  share);
- each key's alias, environment name, owner, data tier, sending ceiling, the roles it may call
  (its own and their fallback chains, what LiteLLM's `models` gets) and its limits;
- the admin key's environment name (the master key; its ceiling is always `red`) and the
  telemetry reader's (it may call `GET /v1/usage` only).

Only environment names appear, never a value. JSON carries no comment, and the contract allows no
extra key, so the generated-by line and the digest are in the sibling `gateway/.hnx-generated`,
which also records `gateway.json`'s sha256.

**Refusals.** The contract cannot express a cloud provider other than `openai` or `anthropic`, an
embedding role on an `anthropic` deployment, or a role `max_cost` without `cost_per_1k_tokens`. For
such a spec `render` still writes `litellm/` (LiteLLM stays the deployed gateway until the cutover,
ADR-0038 decision 7), writes no `gateway/`, and says why in a `# note:` line of
`litellm/config.yaml` and on stderr; a `gateway/gateway.json` left from an earlier render is
removed (`--check` reports it stale), with or without its marker, so the lab's gateway never
reads a config the spec no longer produces.

**The audit** (`--check`, and every render) reads `gateway.json` itself: it must be schema-valid;
no local-only or agent role may have a cloud deployment or fall back to a role with one (a
deployment is local only when it says `local`, speaks `openai` and is on a declared local host); a
cloud deployment's base URL is its provider's API; each role's `tlp_ceiling` and `leaves_lab` are
the spec's; every key is the spec's, with its data tier and ceiling (a missing or unknown label
reads as `red`) and no role beyond what the spec grants; no key reaches a role whose ceiling is
below its own, and no `local-only` key reaches a role with a cloud deployment or `leaves_lab`; every
key role is a role of the file, and a key that lists a role also lists that role's fallbacks (the
contract's own invariant); and no environment name serves two credentials (admin, reader, keys,
upstream keys). It also holds the file to the spec, field by field: the same roles (none added or
missing); each role's kind, context limit, fallbacks, limits and cost, and each deployment's id,
backend, locality, protocol, base URL, model and API key environment as its binding renders; each
key's environment name, owner, roles and limits; the admin and telemetry-reader environment names.
Counts are compared as JSON (`60.0` is not `60`: the gateway decodes them as integers). A file that
is consistent on its own but is not the spec's (a fallback added, two key environments swapped, a
local deployment moved to another declared host) is refused, even when its marker's sha256 was
rewritten to match. The marker only says the file is generated; the comparison is what proves it.

Packaged examples carry `gateway.json` but not its `.hnx-generated` marker: no dotfile goes into a
wheel (the sdist drops them, and the two wheels must be identical); `hnx` never reads the marker
from the package.

## The locality rule

A per-request fallback from a local model to a cloud one has two effects. It bypasses `local_only`
and the data rules. And if the caller is an agent, it swaps the model under a running session. The
generator refuses both cases before writing anything:

1. **Local-only roles stay local.** A role is local-only if a `data_tier: local-only` profile or
   key uses it, or if the spec lists it under `local_only`. Its bindings, and every role in its
   fallback chain, must be on `local` backends.
2. **Agent roles do not cross providers.** If any agent profile uses a role, its fallback chain
   must not change locality at all, even when the role is cloud-allowed. Sending an agent session
   to cloud is the orchestrator's decision, made per session.

Fallbacks between two local roles, and fallbacks for non-agent cloud-allowed roles, are rendered
as declared.

**`local` is checked, not taken on trust.** A backend is local only when it resolves through the
registry (`registry:` in the spec) to a service whose host is in a lab zone (not one named `cloud`,
not a publicly routable network), or when its host is under the lab's internal service domain
(`<svc_label>.<domain>`, `svc.example.internal` in the lab). `{locality: local, host:
api.example.com}` is refused, and the `--check` audit counts such a host as cloud even if the spec
was edited to let it through.

`--check` then audits the rendered files themselves. It decides locality from each file, not from
the spec:

- A LiteLLM deployment is local only if it is `openai/` on a declared local host that passes the
  rule above.

Anything else counts as cloud. So a hand-edited `fallbacks`, `context_window_fallbacks` or
`default_fallbacks` entry, a cloud routing-rule target, or a cloud provider on a local-only key
fails `make gateway-check`, even though the generator would never have written it
(`tests/generators/test_llm_gateway.py` covers both the refusal and the audit).

## TLP labels on model requests

Every model role has a TLP ceiling ([ADR-0033](adr/0033-data-carries-tlp-every-reader-has-a-ceiling.md)
decision 10; [Model-role ceilings](modules/tlp.md#model-role-ceilings-adr-0033-decision-10)): `red` for a
role that stays in the lab, `clear` for one whose prompts can leave it, `green` only with the
provider's terms in the role table, never `amber` or above. A request carries the label of
everything its caller assembled, and for a role that leaves the lab it is judged at the higher of
that label and the sending profile's own TLP ceiling, so a profile that may hold `amber` cannot send
to a cloud role whatever its request claims. A request above the role's ceiling is refused, and a
request with no label (or a `null` one) is `red`. So an unlabelled request to a role that stays in
the lab is allowed, with reason `within-ceiling` (`red` is at or below that role's `red` ceiling),
and the same request to a role that leaves the lab is refused as `unlabelled`.

The gateway is LiteLLM run the supported way, with **no admission code** (ADR-0022): it cannot read
a request's label. So the rule is split where it can be enforced:

- **At render time, by key scope.** Every key carries its sending ceiling: a profile's
  `tlp_ceiling`, a spec key's own `tlp_ceiling` (a canonical label that agrees with its
  `data_tier`), or what its `data_tier` allows (`cloud-allowed`: `clear`; anything else: `red`).
  A role leaves the lab when the role table says so (`leaves_lab` on the chain), and the table
  and the spec must agree: the generator refuses a binding the spec puts on a `cloud` backend
  that the table does not mark `leaves_lab: true`, and a `leaves_lab` binding on a local backend.
  So the ceiling the gateway scopes keys by is exactly the one `admit` reads; a quietly
  reconciled disagreement would let `admit` judge a cloud role as staying in the lab (`red`) and
  allow an `amber` request the gateway then sends out. The generator refuses a key scoped (directly or down a fallback chain) to a role whose ceiling
  is below the key's: every request from it would be refused. It also runs the role table's
  ceiling rules. Today this mostly coincides with the locality rule. A key whose ceiling is above
  `clear` must be `data_tier: local-only` (decision 12), and the locality rule keeps every
  local-only key off cloud roles, so key scope only ever lets a `clear`-ceiling key reach a role
  that leaves the lab. A role raised to `green` is therefore reachable at `green` only through
  per-request `admit` (a `cloud-allowed` sender whose request claims `green`), not by giving a
  `green`-ceiling key that role.
- **In `--check`, by audit.** `litellm/keys.json` gives each key's `metadata.tlp_ceiling`. The
  audit reads it as data (missing or edited: `red`) and refuses a key that reaches a model the
  rendered config deploys to the cloud whose ceiling is below it: a model it lists, an `aliases`
  target, or a fallback of either (`fallbacks`, `context_window_fallbacks`,
  `content_policy_fallbacks`, `default_fallbacks`), followed transitively. A role the spec reads as local
  but the file deploys out is held at `clear`.
- **Per request, by the caller.** `homelabnext.registry.model_tlp.admit(roles, role, claimed,
  sender=send_ceiling(...))` is the rule as a library function. It returns an `Admission` whose
  `reason` (`within-ceiling`, `above-ceiling`, `unlabelled`, `unknown-role`, `invalid-role-table`
  for a table with an entry that is not the schema's shape) and `record()` the
  caller logs, allowed or refused. The component that assembles a request's context (the agent
  runtime) is meant to apply it to each request; the gateway's key scope is the backstop that
  holds even when a caller does not. **No component in this repository calls `admit` yet**
  (ADR-0033, amendment to decision 11): until one does, key scope and the `--check` audit are the
  only enforcement, and a role raised to `green` is reached only by `clear`-ceiling keys.

What this does not do: the gateway does not see a request's claimed label, so a caller that
mislabels its context below its profile's ceiling is bounded only by that ceiling (decision 11's
higher-of rule), and one that skips `admit` entirely is bounded only by its key's scope. The
egress content checks of decision 13 on gateway requests are a later step.

## Lab-in-a-box

The lab's spec is `compose/lab-in-a-box/config/llm-gateway/gateway.yml`. It uses
`schemas/platform/examples/model_roles.valid.json`, the two example profiles, and one extra key,
`conformance-throttle`, limited to 3 requests a minute so the limit check has something to hit.
Both backends point at the fake inference server, which serves `example-4b` and `example-27b`
under the aliases `inference-small` and `inference-large`.

The gateway services are an optional compose profile. They are not part of `make lab-up` or the
nightly. CI's `lab-gateway` job runs the sequence below (its compose settings in `COMPOSE_*`
variables instead of `$lab`) on every pull request that can affect the
lab (the same `tools/lab_paths.py` decision as `lab-in-a-box`, summed up by the same `lab-ok`
check). It fails when the key provisioning exits non-zero, when the suite fails, or when any of
the three `gateway-*` checks below did not pass (skipped or missing included), and it tears
everything down whatever happened:

```bash
lab="--env-file compose/lab-in-a-box/.env.example -f compose/lab-in-a-box/docker-compose.yml"
# the gateway and what it depends on (postgres, the fake inference), then its keys one-shot:
# 1280 MB of mem_limit in all
docker compose $lab --profile gateway up -d --build --wait llm-gateway
# then the key provisioning one-shot in the foreground: its exit code is the provisioning's
# (`up --wait` returns while a one-shot still runs, so it is not a verdict on the keys)
docker compose $lab --profile gateway run --rm --build llm-gateway-keys
set -a; . compose/lab-in-a-box/.env.example; set +a
export HNX_ENDPOINT_LLM_GATEWAY=http://${LAB_BIND}:${LAB_PORT_GATEWAY}
export HNX_SECRET_LLM_GATEWAY_MASTER_KEY=$LAB_GATEWAY_MASTER_KEY
export HNX_SECRET_LLM_GATEWAY_KEY_CONFORMANCE_THROTTLE=$LAB_GATEWAY_KEY_THROTTLE
hnx conform run inference --target compose/lab-in-a-box/targets/inference-gateway.yml
```

| Profile | Services | mem_limit |
|---|---|---|
| `gateway` | `llm-gateway` (LiteLLM 1.106.2, `litellm-database` image, digest-pinned), on the lab's postgres as role `litellm`, which owns only schema `litellm` (created by `config/postgres/init/10-litellm.sh` when the volume is first initialised; password `LAB_GATEWAY_DB_PASSWORD`); `llm-gateway-keys` (one-shot `provision`) | 896 + 64 MB |

The default stack's 3584 MB budget does not include profile services, because `docker compose up`
does not start them. `tests/compose` counts the profile's 960 MB separately and checks it against
the total stated in the compose header. It allows only `llm-gateway*` services to use a profile,
and it fails if a gateway service is moved out of its profile. The whole default stack plus
`gateway` needs about 4.5 GB, more than the 4 GB nightly runner, so the profiles are not in the
nightly. Starting only the gateway services, as above, brings up just postgres and the fake
inference with them: 1280 MB of `mem_limit` in all, inside the 4 GB runner (`tests/compose` sums
that `depends_on` closure against the figure stated here).

## Conformance: the `gateway` feature

A target that declares the `gateway` feature adds three checks to the `inference` suite. Its
subject must implement `GatewayClient` (`conformance/protocols/inference.py`).

| Check | Fails when |
|---|---|
| `gateway-rejects-bad-key` | a chat call (`/v1/chat/completions`, with the model taken from the admin key) with a wrong key or no key gets anything but a 401, or gets a 401 whose reason points at a store or database (`No connected db`) |
| `gateway-limit-throttles` | on the throttled key (limit `n`), any of the first `n` calls is not served, call `n + 1` is not a 429, or a call fails with something other than 429 |
| `gateway-models-match-roles` | `/v1/models` differs from the role table's aliases (backend ids, provider prefixes, extra names) |

`gateway-limit-throttles` uses up the throttled key's window (60 s for the lab's
`conformance-throttle` key). A rerun inside that window starts on a key that is already used up,
so its first call is a 429 and the check fails. Wait out the window before running the suite
again against the same gateway.

The product adapter is `homelabnext.conform.adapters.llm_gateway:make`. It is stdlib-only, keeps
no state between calls, and is not tied to any product. It reads the endpoint from
`HNX_ENDPOINT_<CAPABILITY>` and the keys from `HNX_SECRET_*` on every call. The declared models
come from the role table, not from the gateway itself. The lab ships one target file,
`targets/inference-gateway.yml` (LiteLLM). Switching gateways means a renderer for the new
product, a target file, and passing this suite.
[ADR-0038](adr/0038-the-llm-gateway-is-our-own-behind-the-same-contract.md) (proposed) takes that
exit with the lab's own gateway, which reads a product-neutral `gateway/gateway.json`; LiteLLM
stays deployed until that gateway passes this suite.

A target that also declares `tlp-ceiling` (`TlpCeilingGateway`) adds
`gateway-refuses-role-above-key-ceiling`: on a key whose sending TLP ceiling is above a cloud
role's (`over_ceiling_key`, `over_ceiling_model`; and `over_ceiling_served`, a role it may call),
the call to the cloud role is a 401 or 403 from the chat itself and the call to the other role is
served. The lab's targets do not declare it: the lab-in-a-box gateway has no role that leaves the
lab.

## Running LiteLLM: the supported shape

These rules come from the evidence run in ADR-0022. Each one is enforced or generated, not just
recommended:

- **Postgres is required.** Without it, a wrong key gets `400 No connected db.` instead of a 401,
  and virtual keys and per-key limits do not exist. `gateway-rejects-bad-key` catches this.
- **The image is pinned by digest** (`litellm/litellm-database`), following one stable patch line
  and never `latest`. LiteLLM ships fast: 14 stable releases in the 14 days before the evidence
  run. Pinning also blocks a repeat of the March 2026 PyPI compromise and of 1.107.0 (October 2026, a credential stealer on PyPI and Docker Hub; `.github/dependabot.yml` ignores that version). Run the `inference` suite
  before every upgrade. A plain `pip install litellm[proxy]` does not include `prisma`, so a
  request with no key fails with a 500.
- **`LITELLM_SALT_KEY` is set** and must not change once keys are stored.
- **No custom callbacks and no admission logic in the gateway.** Request priority belongs to the
  serving engine. Session admission belongs to the orchestrator.
- **No fallbacks that cross locality on agent or local-only roles.** The generator refuses them
  (rule above).
- The deployment-level limit answers `429` with `type: internal_server_error` and
  `No deployments available for selected model`. This is LiteLLM's wording. Treat the status code
  as the signal, not the type.

## Not covered here

- Concurrency, latency and streaming under load. The evidence run used the deterministic fake, not
  a GPU-backed engine.
- The model-serving stack behind the gateway (one model store, vLLM units generated from it) is in
  [model-serving.md](model-serving.md) ([[model-serving]]), ADR-0023.
- SSO for LiteLLM's admin UI (it takes the master key).
- Postgres high availability.
- Spend reporting. The hub reads per-call usage from the spend-log API for orchestration jobs:
  [orchestration telemetry](orchestration-telemetry.md) ([[orchestration-telemetry]]).
