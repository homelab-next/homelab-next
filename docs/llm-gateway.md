<!-- SPDX-License-Identifier: Apache-2.0 -->
# LLM gateway

The gateway is the one place where a model role (ADR-0007) becomes a backend and a model id. Every
consumer (agents, the decision cascade, tools) calls the `inference` capability with a role name
and its own key. The gateway enforces that key's scope and limits and forwards the call to the
backend. The decision on which product does this is [ADR-0022](adr/0022-llm-gateway-litellm.md):
**LiteLLM, run the supported way**. Bifrost is the tested alternate.

The gateway handles single requests. It does not schedule agent sessions, admit work against GPU
capacity, or choose cloud for an agent. Those belong to the orchestrator, and the gateway config
must not take them over (see the locality rule below).

## One source of truth, generated config

The gateway config is never written by hand. `hnx gen gateway render` builds it from three
inputs:

| Input | Gives |
|---|---|
| the role table (`schemas/platform/model_roles.json`) | roles, bindings in priority order, `fallback`, `limits`, context length, cost per 1k tokens |
| the agent profiles (`schemas/agent/profile.schema.json`) | one key per profile (`profile:reader` gets `agent-reader`, secret `secret:llm-gateway/key-reader`), the role it calls and its `data_tier` |
| a small gateway spec (YAML) | where each `svc:` backend is (`local`, or `cloud` with a provider), the secrets for the master key and the database, and any extra non-agent keys |

```bash
hnx gen gateway render SPEC OUT_DIR            # writes litellm/ and bifrost/ under OUT_DIR
hnx gen gateway render SPEC OUT_DIR --check    # drift check and locality audit (make gateway-check)
hnx gen gateway provision OUT_DIR/litellm/keys.json   # create LiteLLM keys on a running proxy
```

It writes:

- **`litellm/config.yaml`**. The `model_list` has one entry per binding, and `model_name` is the
  role. Binding priority becomes `order`. Role `limits` become per-deployment `rpm`/`tpm` (the
  per-minute share, rounded down) and `max_budget`. LiteLLM counts only per minute, so a limit
  must have a window of whole minutes and at least one call a minute: `1` per `3600` s or `5` per
  `10` s is refused rather than rendered looser (`1` rpm, `30` rpm). Counts are whole numbers of
  at least 1; `max_requests: 0` is refused, never rendered as unlimited. Bifrost gets the
  declared count and window exactly. Role fallbacks go in `router_settings`, with
  `enable_pre_call_checks: true` so the limits are enforced. `general_settings` holds the master
  key and the database only as `os.environ/HNX_SECRET_*` references.
- **`litellm/keys.json`**. These are the virtual keys. LiteLLM stores keys in Postgres, not in its
  config file, so `provision` finds each one by `key_alias` (`/key/list`) and creates it
  (`/key/generate`), updates it in place by its token when the value is unchanged (`/key/update`),
  or, when the secret was rotated, deletes the old key by its token first, so the old value stops
  working, and creates the new one. Each key names the environment variable that holds its value, never the value.
- **`bifrost/config.json`**. There is one custom OpenAI-compatible provider per local backend
  (`hnx-<svc>`). Role → model id mappings are key `aliases`. The file also holds virtual keys
  (`env.HNX_SECRET_*`), per-role `model_configs` with rate limits and budgets, and routing rules
  (`model == '<role>'`) that list bindings in priority order and then the fallback chain.
  The admin API and UI need a login (`governance.auth_config`: user `admin`, or
  `bifrost.admin_user`, and the password from `bifrost.admin_password`, default
  `secret:llm-gateway/bifrost-admin-password`), and `source_of_truth: config.json` makes the file
  authoritative: at every start Bifrost overwrites `config.db` from it and prunes rows it does not
  declare, so a key or limit changed through the API does not survive a restart. `--check` fails
  if either is missing.
- **`bifrost/pricing.json`, `bifrost/model-parameters.json`**. These are empty local datasheets.
  At its default settings Bifrost will not start if it cannot download them. Because the datasheets are
  empty, Bifrost prices every call at zero: the role budgets are rendered but never trigger, and
  `cost_per_1k_tokens` is not carried over (LiteLLM's `model_info` does carry it).

Secrets are always `secret:<name>` and are delivered in `HNX_SECRET_<NAME>` (the registry's
mapping). The renderer refuses a literal value.

Two more shapes are refused because Bifrost cannot render them faithfully: two cloud backends of
the same provider (Bifrost has one provider per name, so one key would serve both), and a role
with two bindings on the same backend (a provider keeps one model id per role).

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

- In LiteLLM, a deployment is local only if it is `openai/` on a declared local host that passes
  the rule above.
- In Bifrost, a provider is local only if it is a custom OpenAI provider on such a host.

Anything else counts as cloud. So a hand-edited `fallbacks`, `context_window_fallbacks` or
`default_fallbacks` entry, a cloud routing-rule target, or a cloud provider on a local-only key
fails `make gateway-check`, even though the generator would never have written it
(`tests/generators/test_llm_gateway.py` covers both the refusal and the audit).

## Lab-in-a-box

The lab's spec is `compose/lab-in-a-box/config/llm-gateway/gateway.yml`. It uses
`schemas/platform/examples/model_roles.valid.json`, the two example profiles, and one extra key,
`conformance-throttle`, limited to 3 requests a minute so the limit check has something to hit.
Both backends point at the fake inference server, which serves `example-4b` and `example-27b`
under the aliases `inference-small` and `inference-large`.

The gateway services are optional compose profiles. They are not part of `make lab-up` or the
nightly:

```bash
lab="--env-file compose/lab-in-a-box/.env.example -f compose/lab-in-a-box/docker-compose.yml"
# just the gateway and what it depends on (postgres, the fake inference): well inside 4 GB
docker compose $lab --profile gateway up -d --build --wait llm-gateway llm-gateway-keys
set -a; . compose/lab-in-a-box/.env.example; set +a
export HNX_ENDPOINT_LLM_GATEWAY=http://${LAB_BIND}:${LAB_PORT_GATEWAY}
export HNX_SECRET_LLM_GATEWAY_MASTER_KEY=$LAB_GATEWAY_MASTER_KEY
export HNX_SECRET_LLM_GATEWAY_KEY_CONFORMANCE_THROTTLE=$LAB_GATEWAY_KEY_THROTTLE
hnx conform run inference --target compose/lab-in-a-box/targets/inference-gateway.yml
```

| Profile | Services | mem_limit |
|---|---|---|
| `gateway` | `llm-gateway` (LiteLLM 1.103.3, `litellm-database` image, digest-pinned), on the lab's postgres in schema `litellm`; `llm-gateway-keys` (one-shot `provision`) | 768 + 64 MB |
| `gateway-bifrost` | `llm-gateway-bifrost` (Bifrost 2.2.6, digest-pinned) on port `LAB_PORT_GATEWAY_BIFROST` | 256 MB |

The default stack's 3584 MB budget does not include profile services, because `docker compose up`
does not start them. `tests/compose` counts the profiles' 1088 MB separately and checks it against
the total stated in the compose header. It allows only `llm-gateway*` services to use a profile,
and it fails if a gateway service is moved out of its profile. The whole default stack plus
`gateway` needs about 4.6 GB, more than the 4 GB nightly runner, so the profiles are not in the
nightly. Starting only the gateway services, as above, brings up just postgres and the fake
inference with them.

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
come from the role table, not from the gateway itself. The lab ships two target files:
`targets/inference-gateway.yml` (LiteLLM) and `targets/inference-gateway-bifrost.yml`. Switching
gateways means changing the target file and passing this suite.

## Running LiteLLM: the supported shape

These rules come from the evidence run in ADR-0022. Each one is enforced or generated, not just
recommended:

- **Postgres is required.** Without it, a wrong key gets `400 No connected db.` instead of a 401,
  and virtual keys and per-key limits do not exist. `gateway-rejects-bad-key` catches this.
- **The image is pinned by digest** (`litellm/litellm-database`), following one stable patch line
  and never `latest`. LiteLLM ships fast: 14 stable releases in the 14 days before the evidence
  run. Pinning also blocks a repeat of the March 2026 PyPI compromise. Run the `inference` suite
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
- The model-serving stack behind the gateway (one model store, one serving engine). This is
  context for later work, not built here.
- SSO for either product's admin UI (Bifrost's gets a password login, LiteLLM's the master key).
- Postgres high availability.
- Spend reporting.
