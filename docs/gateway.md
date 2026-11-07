---
summary: 'The lab''s own LLM gateway, orchestrator/cmd/gateway (ADR-0038, ADR-0039): routes, flags, behaviour, limits, usage records, conformance in CI and cutover.'
summary_of: outline:sha256:5dcfa94e8e34c540
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# The lab's own LLM gateway (`orchestrator/cmd/gateway`)

`orchestrator/cmd/gateway` is the lab's own LLM gateway, decided in
[ADR-0038](adr/0038-the-llm-gateway-is-our-own-behind-the-same-contract.md) and built in this
repository's Go module `orchestrator/` ([ADR-0039](adr/0039-make-the-orchestrator-and-its-gateway-part-of-this-repository.md)).
It is a separate process from the orchestration controller: it holds the provider API keys, and a
controller restart must not drop model calls in flight. LiteLLM stays the deployed gateway until
this binary passes the `inference` conformance suite and has served the lab beside it (ADR-0038
decision 7). The contract it implements, the renderer that writes its config and the suite that
judges it are described in [LLM gateway](llm-gateway.md).

It reads `gateway/gateway.json`, rendered by `hnx gen gateway render`
(`schemas/platform/gateway_config.schema.json`), and serves:

| Route | Who | What |
| --- | --- | --- |
| `GET /healthz` | anyone | `{"status":"ok", "usage_records_dropped": n, "usage_lines_skipped": n, "replies_overloaded": n}` (status is always `ok` while it serves) |
| `GET /v1/models` | any key (telemetry: 403) | the role aliases the key may call (admin: all) |
| `POST /v1/chat/completions` | any key (telemetry: 403) | chat, `stream: true` included |
| `POST /v1/embeddings` | any key (telemetry: 403) | embeddings |
| `GET /v1/usage?start=&end=[&tag=]` | admin, telemetry | usage records in a time range |

Everything else is a 404. The code is `orchestrator/internal/gateway`, standard library only. It
follows ADR-0038 with the four departures its security review made, recorded as R15 to R18 in
ADR-0038's amendment: in-flight caps before the body is read (R15), token and cost limits reserved
at admission and settled after (R16), aggregated refusal records (R17) and grouped writes of the
usage file with counted drops (R18). Each is described where it applies below. The code's comments
cite the clauses of the gateway contract by the labels its security review gave them (R1 to R18);
R15 to R18 are ADR-0038's amendment, and the others restate ADR-0038's decisions 2 to 6.

## Running it

```sh
cd orchestrator && go build -o ../build/bin/gateway ./cmd/gateway
export HNX_SECRET_LLM_GATEWAY_MASTER_KEY=...   # every *_env the config names
build/bin/gateway -config /etc/llm-gateway/gateway.json -usage /var/lib/llm-gateway/usage.jsonl
```

Validate a rendered config and its environment before a deploy (exit 0, or 1 with every problem;
a problem names an environment variable, never a value):

```sh
build/bin/gateway -config gateway.json -check
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-config` | (required) | the rendered `gateway.json` |
| `-listen` | loopback, port 4100 | listen address |
| `-usage` | (required to serve) | usage JSON-lines file: created 0600, written off the reply path (see Usage records) |
| `-upstream-timeout` | `120s` | bound on one upstream attempt; for a stream, on each wait for the next event |
| `-write-timeout` | `60s` | bound on each write to the caller: a whole non-streamed reply, or one streamed event |
| `-max-inflight` | `256` | model calls in flight at once, in all |
| `-max-inflight-per-key` | `32` | model calls in flight at once per caller key |
| `-max-reply-bytes-inflight` | `512 MiB` (bytes) | bytes all non-streamed replies being read may hold at once; over it the caller gets 503 `overloaded` |
| `-max-reply-bytes-inflight-per-key` | a quarter of the above | one caller key's share of that budget; over it that key's callers get 503 `overloaded` while other keys are served |
| `-reserve-tokens` | `4096` | output tokens a call reserves on token and cost limits when neither its `max_tokens` nor the role's `max_context_tokens` bounds it |
| `-tls-cert`, `-tls-key` | none | serve TLS |
| `-allow-plaintext` | off | allow a non-loopback listen without TLS. Bearer tokens and prompts then cross that segment in clear: use it only behind the lab's TLS edge on a trusted segment |
| `-upstream-proxy` | none | an http(s) proxy for **cloud** deployments only |
| `-conformance` | off | serve a config rendered with `"conformance_only": true` (a test rendering); loopback listen only |
| `-check` | off | load config and environment, report, exit |

SIGTERM (or Ctrl-C) stops accepting connections and drains in-flight calls for up to the upstream
timeout plus 5 s. An example hardened systemd unit is
[`orchestrator/deploy/systemd/llm-gateway.service`](../orchestrator/deploy/systemd/llm-gateway.service):
an example only, wired into no deploy and naming no host. It runs the gateway as a dynamic user
that can write only its state directory, reads the key values from a root-only environment file
before dropping privileges, keeps `/proc/<pid>/environ` from other users
(`ProtectProc=invisible`), filters system calls and unsets the proxy variables. A lab's real unit,
with its paths and listen address, is the private overlay's (ADR-0039 decision 3).

## Behaviour worth knowing

- **Keys.** Every `*_env` value is read once at start; a missing or empty one refuses the start.
  Every caller key (`keys[]`, telemetry and the admin key) must be at least 32 bytes and every
  caller key distinct. The values stay in the process environment for its lifetime; in the example
  unit `DynamicUser=yes` and `ProtectProc=invisible` keep `/proc/<pid>/environ` from other users.
  Caller keys are kept only as SHA-256 digests and compared in constant time against all of them;
  provider keys are necessarily kept as values. Revoking a key is a config change and a restart.
- **Strict JSON.** The config loader refuses a key given twice at any level and any key that is
  not the exact field name (Go's decoder would keep the last duplicate and match names
  case-insensitively). A request body that gives a top-level key twice is a 400 `invalid_json`;
  one with a case variant of `model` or `stream` (`Model`, `STREAM`, a Unicode fold) is a 400
  `invalid_request`. A role with `leaves_lab: true` must have a `tlp_ceiling` of `green` or
  `clear`.
- **In flight.** Model calls running at once are capped in all and per key; a call over a cap gets
  429 `concurrency_limited` (`Retry-After: 1`) right after auth, before its body is read, and
  consumes no limit and writes no usage record (refusals are logged at most once a second).
- **Evaluation order** (ADR-0038 decision 4, with R15 and R16): auth (401), in-flight caps (429
  `concurrency_limited`), body and exact `model` match (400), key scope (403 `model_not_allowed`),
  TLP (403 `tlp_refused`), a reservation larger than a whole max (400
  `reservation_exceeds_limit`), key limit then role limit (429). A refused request
  consumes no limit. `model` is matched byte for byte, and a role outside the key is refused,
  never substituted.
- **TLP.** `X-HNX-TLP` is read exactly as `homelabnext.tlp.read`; no field is `red`
  (`unlabelled`), more than one field is `red`. A role that leaves the lab judges the request at the
  higher of its label and the key's sending ceiling (the admin key's is `red`). The package test
  runs every vector of this repository's `conformance/fixtures/tlp_admit_vectors.json`, read in
  place (no copy), which the Python tests regenerate from `homelabnext.model_tlp.admit`: the two
  implementations always judge the same vectors.
- **Limits** are sliding windows in memory, per key and per role (one budget across all the role's
  deployments), kept as running sums in one-second buckets: an event leaves the window `window_s`
  seconds after the start of its second. Requests count at admission, and a request is refused
  once the window's count reaches `max_requests`. Token and cost limits are **ceilings**: at
  admission a call reserves an estimate on the key's and the role's windows, its output
  (`max_completion_tokens` or `max_tokens`, the larger when both; else the role's
  `max_context_tokens`; else `-reserve-tokens`) times `n`, plus its input estimated as
  `ceil(body bytes / 4)` (an embedding call reserves its input only), and its cost at the role's
  `cost_per_1k_tokens`. `n`, `max_tokens` and `max_completion_tokens`, when given (not null),
  must be JSON integers (no fraction, no exponent), `n >= 1` and the others `>= 0`, else 400
  `invalid_request` naming the field. A call is refused (429) when a window's sum already reaches
  its max or when the reservation would take it past the max. **A reservation larger than a key's
  or a role's token or cost max by itself can never be admitted: it is a 400
  `reservation_exceeds_limit`** (naming whether the key's or the role's token or cost limit, and
  the call's own reservation), not a 429; send a smaller `max_tokens` (or `n`). After the reply the reservation is released
  and the real usage spent. An attempt whose upstream answered 2xx but whose reply the gateway
  threw away (malformed, over the 16 MiB cap, over the reply budget, a stream that broke before
  its first chunk) is charged its reservation estimate on the key and the attempted role, since
  the upstream may have generated it; an upstream error status (429, 5xx, 401/403) costs nothing. A fallback role reserves the same way. A restart starts every window
  again, and two gateway processes would each allow the full budget.
- **Routing.** Deployments in config order, no shuffle. A connection error, timeout, upstream 429,
  5xx or 401/403 moves to the next deployment; then the role's fallbacks in order, each checked
  again for TLP and its own limit (a refused fallback is skipped; a TLP refusal of the requested
  role never falls back). All failed: 502 `upstream_error`. `X-HNX-Attempted-Fallbacks: n` only
  on a success a fallback role served. Any other upstream 4xx is returned with its status and the
  gateway's own error envelope, never the upstream body. A deployment that cannot take the request
  at all (an Anthropic translation refusal, or a URL part for a local deployment) is skipped
  without being called; when no deployment was called, that refusal (400, usually
  `unsupported_parameter`) is the answer, recorded with `deployment` null.
- **URL parts never reach a local backend.** A request body with a key named `url` or `*_url` at
  any depth (a part's `image_url.url`, an `input_file`'s `file_url`, a top-level `messages`
  object, an extra top-level field alike; `data:` URLs included), or with a part of type
  `image_url`, `audio_url` or `video_url` anywhere, chat or embeddings, is not sent to a local
  OpenAI-compatible deployment, which would fetch it from inside the lab. No role can opt in yet (there is no field
  for it); cloud deployments are not affected.
- **Writes to the caller** each have a deadline (`-write-timeout`): a non-streamed reply's whole
  body, or one streamed event. A caller that stops reading has its reply ended. A non-streamed
  upstream reply is capped at 16 MiB (over it is a failed attempt), read into a buffer sized from
  its `Content-Length` that never grows past the cap, and held once: its top-level `model` is
  rewritten in place, not by decoding and re-encoding it. All replies being read share a budget
  (`-max-reply-bytes-inflight`), and each caller key may hold at most its share of it
  (`-max-reply-bytes-inflight-per-key`), so one key's stuck callers cannot starve the others. A
  reply that would take its key over its share, or the budget over its max, is answered 503
  `overloaded` (`Retry-After: 1`) and counted (`replies_overloaded` on `/healthz`).
- **Replies.** `model` is always the requested role alias, in JSON replies and every stream chunk.
  Upstream headers are not forwarded.
- **Upstream requests** are the caller's body decoded and re-encoded with `model` replaced by the
  backend id (and, for an OpenAI stream, `stream_options.include_usage: true`, whose extra chunk is
  dropped unless the caller asked for it). Only the gateway's own headers are sent.
- **No proxy from the environment, no redirects.** The upstream client never reads
  `HTTP(S)_PROXY`: local backends must never route through an egress proxy, and an inherited proxy
  variable would silently send prompts somewhere unconfigured. `-upstream-proxy` is the only way to
  set one, and it applies to cloud deployments only. Redirects are never followed (a 3xx is an
  eligible failure): following one would carry the provider key (`x-api-key` is not stripped by Go
  on a cross-host redirect) to wherever `Location` points.
- **Streaming failover** happens only before the first byte reaches the caller: the gateway reads
  the upstream stream until its first real chunk (OpenAI) or `message_start` (Anthropic) before it
  sends headers. After that, an upstream error or a chunk it cannot rewrite ends the stream; it is
  never spliced onto another deployment's answer. Before the first byte, an upstream that answers a
  stream request with a non-SSE 2xx, or whose first chunk carries `error` and no `choices`, is a
  failed attempt and the next deployment is tried. A reply or stream with no usage is counted as
  an estimate: input `ceil(request body bytes / 4)`, output `ceil(content bytes / 4)`,
  `usage_estimated: true`.
- **Anthropic translation.** System and developer messages become `system` (joined by a blank
  line); consecutive turns of one role are merged; `max_tokens` is the request's (or
  `max_completion_tokens`), else 1024; `temperature`, `top_p`, `stop` and `stream` carry over.
  Headers `x-api-key` and `anthropic-version: 2023-06-01`. Every upstream request carries
  `User-Agent: hnx-gateway`, `Content-Type`, `Accept` and the deployment's own auth, nothing else. Replies map `stop_reason` to
  `finish_reason` (`max_tokens`: `length`, `tool_use`: `tool_calls`, `refusal`: `content_filter`,
  else `stop`) and usage to `prompt_tokens` (input plus cache tokens) and `completion_tokens`.
  Streams are translated to OpenAI `chat.completion.chunk` events ending in `[DONE]`.
- **Usage records** (ADR-0038 decision 6): one line per admission decision past auth and model parsing, served or
  refused, with the turn-record field names (`turn_id`, `gateway_tag` from `X-HNX-Tag`,
  `model_role`, `served_role`, `deployment`, token counts, `cache_read_tokens`/`cache_hit` null
  when upstream reports none, `cost_usd` (null when the call did not succeed), `ttft_ms`,
  `duration_ms`, `fallbacks`, the TLP verdict, `count` and `aggregated_overflow`). Names and numbers only, never prompt
  or reply text. The admin and telemetry keys are recorded as `@admin` and `@telemetry`.
  - `count` is 1, except on a refusal at admission (scope, TLP, limits): identical refusals, those
    that agree on every field but `ts`, `turn_id`, `duration_ms` and `count` (so the key, tag,
    roles, status, error code and the whole TLP verdict), are merged into at most one record per
    second (a `/v1/usage` read writes the pending ones early), and `count` says how many refusals
    the record stands for (R17). A key holds at most 16 distinct refusal records at once; a
    further distinct refusal of that key (another tag, role, label ...) is counted into one
    catch-all record per (key, `error_code`) with `gateway_tag` null and
    **`aggregated_overflow: true`**: its `count` is per key and error code only, and its other
    fields are those of the first refusal folded into it. `aggregated_overflow` is `false` on
    every other record.
  - The reply never waits on the log: the response is flushed first, and records go through a
    bounded queue (4096 for served calls; refusal records have their own, 1024, so a refusal
    flood can never crowd out a served call's record) to one writer that fsyncs once per group of
    up to 256 records. When a queue is full the record is dropped; when the file cannot be written the group is lost.
    Either way **serving continues**: drops are counted and logged as an error (`usage records
    dropped`, with the count) at most once a second, and a write failure is logged with its
    error. A crash can lose the records still queued.
  - `/v1/usage` takes whole unix seconds (`end` inclusive), waits (up to 5 s) for queued records,
    and returns the **earliest** 10000 matching records by `ts`, in `ts` order, with
    `"truncated": true` when more matched. Page by time: ask again from the last record's second,
    and de-duplicate by `turn_id` where pages meet. A malformed or over-1-MiB line is skipped and
    logged, never an error; `usage_lines_skipped` on `/healthz` counts them (once per read).

## What it does not do

- No other provider protocols (Gemini, Bedrock, ...): the renderer refuses them for this target.
- No tool calls, images, `n > 1` or `response_format` through an Anthropic deployment (refused with
  400 `unsupported_parameter`, never silently dropped). OpenAI-compatible deployments pass the body
  through, so they support whatever the backend does.
- No `/v1/completions`, no admin API, no key provisioning: keys are config.
- No scheduling, queuing or session admission (that is the serving engine's and the controller's).
- `max_context_tokens` is carried but not enforced; the backend enforces its own context.
- No usage-file rotation in v1; rotate by stopping the gateway.
- No shared state between processes: run one gateway.

## Conformance in CI

CI's `gateway-conformance` job (`.github/workflows/ci.yml`, ADR-0038 decision 7 as ADR-0039
amends it) runs the `inference` suite against this binary on every pull request and every push to
`main`, and `go-ok` (the Go modules' one stable check) passes only when it passed. Its steps are
[`tools/gateway_conformance.sh`](../tools/gateway_conformance.sh):

1. build `orchestrator/cmd/gateway` with the Go version `orchestrator/go.mod` names
   (`GOTOOLCHAIN=local`, `GOFLAGS=-mod=readonly`, `GOWORK=off`, as the `go` job);
2. `deps`: a venv on Python 3.12 with pip from `constraints/bootstrap.txt` (`--require-hashes`),
   the `core` extra under the hashed `constraints/ci.txt`, then this checkout (editable,
   `--no-deps --no-build-isolation`), then a check that every installed distribution is named, and
   so hash-pinned, by the two constraint files (pip hashes only what the constraints list, so a new
   transitive dependency would otherwise install unhashed);
3. `run`: render `compose/lab-in-a-box/config/llm-gateway-conformance/gateway.yml` with
   `hnx gen gateway render --conformance --conformance-host <loopback>` into a scratch directory;
   give every `*_env` name in the rendered `gateway.json` a fresh random value (64 bytes, distinct,
   never printed); start the fake inference server (`conformance/fakes/openai_server.py`) on
   loopback port 8000 serving `conformance-chat`, `conformance-spare`, `example-embed-8d` and
   `example-cloud-chat` (the refused `spare` fallback's model is served on purpose, so a gateway
   that wrongly calls it is caught by the fallback check), and the gateway with `-conformance` on
   loopback port 4100; wait for `/healthz`; run `hnx conform run inference --target
   compose/lab-in-a-box/targets/inference-own-gateway.yml --strict -v` (features `streaming`,
   `embeddings`, `gateway`, `tlp-ceiling`, `tlp-admit`, `turn-records`).

The job fails on a non-zero exit and on any check that did not pass, skipped and untested ones
included (24 checks today). It always stops both processes, and on a failure prints the gateway's
and the fake's logs (neither logs a key value). There is no cross-repository pin any more: the
suite, the spec, the renderer and the binary are one commit.

Run it on a workstation the same way, from the repository root:

```sh
(cd orchestrator && go build -o ../build/bin/gateway ./cmd/gateway)
HNX_VENV=build/gateway-venv HNX_PYTHON=python3.12 tools/gateway_conformance.sh deps
HNX_VENV=build/gateway-venv GATEWAY_BIN="$PWD/build/bin/gateway" WORK_DIR="$(mktemp -d)" \
  tools/gateway_conformance.sh run
```

The spec's ports and the fake's models are fixed in the script: a change to either in the spec
needs the matching change there. A new `*_env` name in the spec needs none.

## Cutover note: the callers' headers

LiteLLM reads a request's tag from `x-litellm-tags`; this gateway reads `X-HNX-Tag` (one field)
and the TLP label from `X-HNX-TLP` (no field reads as red). Before the lab moves from LiteLLM to
this gateway, its callers must send both: the orchestration controller's gateway-tag header and the
agent runtime's per-request headers (the runner contract of ADR-0039 decision 5 carries them). This
binary does not change them; a caller that sends neither header is judged red and refused on any
role whose ceiling is below red.
