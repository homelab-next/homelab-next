<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `llamacpp`: the inference provider on llama-server

A provider module ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that fills
the `inference` slot with [llama.cpp](https://github.com/ggml-org/llama.cpp)'s `llama-server`, which
serves **one GGUF model on one GPU** through an OpenAI-compatible API. It is the engine the
[model serving plan](../../docs/model-serving.md) names for GGUF-only models (`engine:
llama-server`), and what the [model gateway](../../docs/llm-gateway.md) routes a role such as
`mdl:fast-classifier` to. It is a **service, not a machine**: the guest is the site's guest file,
and the selection places the one host role (`server`) on it. Nothing here names a real host,
address, VM id or secret value.

| | |
|---|---|
| Slot | `inference` (contract `conformance/protocols/inference.py`), stateless |
| Adapter | the shared `homelabnext.conform.adapters.inference_server:make`, feature `streaming` |
| Product | llama.cpp build b12033 (product version `0.12033.0`: `0.<build>.0`), `ghcr.io/ggml-org/llama.cpp` pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `server` (the site adds `model-runtime`), footprint 8 vCPU, 16 GiB, 20 GB and one exclusive GPU (VRAM is not counted: a guest record declares none yet) |
| Role | `llamacpp` (role interface v1), a wrapper of the core `compose_app` |
| Requires | the weights in the model store (role `model_store`), the container engine, the GPU passed through |
| Egress | none (the guest is a model runtime: default-deny, see below) |
| Public route | none; no web UI |

## What the role does

- **One container, one starter.** `compose_app` renders `docker-compose.yml` (never started by
  it: `compose_app_start: false`); the unit `hnx-llamacpp.service` runs `docker compose up` in the
  foreground and is the only thing that starts the container (`restart: "no"`, so docker never
  brings it back by itself). A crash, a restart and a reboot all go through the unit's
  `ExecStartPre`.
- **The power-cap rule (the operator's).** `hnx-llamacpp-precheck` refuses to start unless the
  card's power cap is at or under `llamacpp_power_cap_max_watts` (default **200 W**). On Intel
  (vulkan, sycl) it reads each hwmon attribute of `llamacpp_power_cap_attrs` (default
  `power1_cap`, microwatts) under `/sys/class/drm/<render node>/device/hwmon/hwmon*/`; **absent,
  unreadable or 0 refuses** (0 means no limit is set: an unlimited card is not within 200 W). On
  NVIDIA (cuda) it reads `nvidia-smi -i <index> --query-gpu=power.limit`. A cpu backend has no
  card and passes. The health hook runs the same rule (`--power-only`), so a cap raised after
  the start turns the service red. Setting the cap is not this module's job (the baseline or a
  udev rule does it); this module only refuses to load without it.
- **The bytes are checked, not trusted.** The same script checks, before every start, that the
  model store's listing (`manifests/listings/<store id>.sha256`) hashes to the pinned
  `llamacpp_model_digest` and that every file in it matches (`sha256sum --check --strict`), as
  `vllm_server` does for vLLM. Weights are fetched only by `model_store`, at a pinned revision
  and a pinned sha256 per file, never at container start; the container mounts the entry's
  directory read-only and runs `--offline`.
- **GPU passthrough into the container.** `compose_app` gained two optional service keys for it
  (`devices` and `group_add`; docs/role-interface.md): `vulkan` and `sycl` pass
  `/dev/dri/<render node>` (default `renderD128`) and add the **render node's group** by number
  (read from the node, or `llamacpp_render_gid`); `cuda` passes the CDI device
  `nvidia.com/gpu=<index>` (the container toolkit's CDI spec must exist on the guest). Nothing
  else is a device (a disk, `/dev/mem` and the card node are refused), the container is not
  privileged, has no capability and `no-new-privileges`, and runs as an id of its own
  (`llamacpp_uid`) in the **model store's group** (read from the model directory, or
  `llamacpp_models_gid`), which reads the weights and writes none. Its only writable path is
  `cache/` under the module's data root (the driver's compiled shaders).
- **No egress.** `--offline`, no model URL, no update check. The container is on a bridge network:
  the module-level `egress: none` is not enforced by the module apply path for containers (the
  loader warns), the guest's own forward chain is: a model runtime guest runs the
  `model-runtime` baseline with `policy_out: DROP`, which holds containers to the same allow list
  as the host. Because that guest cannot pull from a registry either, `llamacpp_image_archive`
  loads the pinned image from a local `docker save`.
- **Backend.** `llamacpp_backend` is `vulkan` (Mesa; the Intel Arc B60), `sycl` (Intel oneAPI),
  `cuda` (NVIDIA; the CMP pool on a GPU guest) or `cpu`. The image must be that backend's build:
  the role refuses a tag that is not `server-vulkan-b<N>`, `server-intel-b<N>`,
  `server-cuda-b<N>` or `server-b<N>` for the backend. Pinned at build b12033 (image created
  2026-11-02, over 14 days old when set):

  | Backend | Image |
  |---|---|
  | `vulkan` (default) | `ghcr.io/ggml-org/llama.cpp:server-vulkan-b12033@sha256:421137599beb2135a9e1d664fa8991a3f4f5f953440a9d7622c7a61b63185fe8` |
  | `sycl` | `ghcr.io/ggml-org/llama.cpp:server-intel-b12033@sha256:4c49bfe65647abc1b904170764ff9b818f66459ffd24b37659e7d813430f85c1` |
  | `cuda` | `ghcr.io/ggml-org/llama.cpp:server-cuda-b12033@sha256:0a9f6c7cfe5a6b90b6c048b7a86865bf55a88af34bada927482eab2ef5f25b4a` |
  | `cpu` | `ghcr.io/ggml-org/llama.cpp:server-b12033@sha256:0b0212befa4facc6fd1e34ee04e19f13b570d0b9ec87d26edf4c402dc0dd636f` |

  (Digests are of the multi-architecture index; the images are Ubuntu 26.04 builds, the Vulkan one
  with Mesa's `mesa-vulkan-drivers`.) `tools/pin_freshness.py` watches `llamacpp_image`; the other
  three are for an overlay that sets `llamacpp_backend`.
- **Model, context, slots, layers.** `llamacpp_model_repo` / `llamacpp_model_file` /
  `llamacpp_model_store_id` / `llamacpp_model_digest` name the store entry (default: the
  fast-classifier's `ggml-org/Clef-GGUF`, `Clef-Q4_K_M.gguf`, entry digest
  `sha256:e29796ca...`), `llamacpp_served_model_name` is the id `/v1/models` lists (the role
  table's model id for this backend), `llamacpp_context_size` is the context **each slot** gets
  (the server is started with `-c` = that times `llamacpp_parallel`, with `--no-kv-unified`, so
  a slot's share is fixed), `llamacpp_n_gpu_layers` is a count, `all` or `auto` (default 99).

## The contract the gateway needs

`GET /health` (public: 200 `{"status":"ok"}` once the model is loaded, 503 while it loads),
`GET /v1/models` (the served id, and `meta.n_ctx`, the context each slot has: the K-14 probe
reads it), `POST /v1/chat/completions` (streaming included), `GET /metrics` (Prometheus, the
registry row's `metrics:` path). The row is `capability: inference`, port 8001 (the serving
plan's example port for a llama-server backend), `auth: none`: the server holds no key of its
own, and the guest firewall admitting only the gateway and the metrics scraper is the control
(with `--api-key` set llama-server would also lock `/metrics`, `/props` and `/v1/models`, which the
scraper and the probe read; `/health` stays open either way).

## Decision mode (`llamacpp_mode: decision`)

Some GGUF models (Clef, llama.cpp PR #29831) are **decision models**: llama-server refuses
`POST /v1/chat/completions` for them **by design** (HTTP 501 "This model is a decision model
without text generation, use /v1/systemone"). They answer `POST /v1/systemone`:

```
request:  {"model": "clef", "state": "<text>",
           "questions": {"<id>": {"type": "noul", "instructions": "<a yes/no question>"}}}
response: {"answers": {"<id>": {"type": "noul", "noul": <probability 0..1>}}, "usage": {...}}
```

Set `llamacpp_mode: decision` (default `generate`) for such a model. The role then:

- starts the server with `-b` and `-ub` **equal to `llamacpp_context_size`** (the per-slot
  context). **LL-492:** in decision and embedding mode llama-server forces `n_batch = n_ubatch =
  512`, so a state of about 500 tokens or more returns HTTP 500 "input is too large to process"
  while a short probe works, which is how a smoke test with a one-line input passes and the real
  corpus fails. With both raised to the slot context, any state that fits a slot fits the batch.
- replaces the health hook's chat completion with a `/v1/systemone` probe: a fixed tiny state and
  one `noul` question must come back **HTTP 200 with a number in [0, 1]** under the question's id
  (a missing answer, an empty body, a boolean, a string, NaN, another `type` or any other status
  fails), and, when a slot holds at least 2048 tokens, a second probe with a state past 512 tokens
  proves the batch flags took (a server still capped at 512 answers 500, and health says LL-492).
  The status is asserted explicitly: a task's `failed_when` replaces the HTTP module's own status
  check, so a 200 requirement written only as `status_code: 200` would not hold.
- leaves `/health`, `/v1/models` (with `meta.n_ctx`) and `/metrics` as they are.

**Chat completions are refused by design in this mode**, so a client (and the model gateway)
must call `/v1/systemone`. The platform's model roles know the kinds `chat`, `completion` and
`embedding` only (`homelabnext/registry/models.py`, `KINDS`), so the registry row stays
`capability: inference` and the role table cannot yet declare a decision role: a consumer of a
decision instance addresses the server's `/v1/systemone` itself, not a gateway role. The
inference conformance suite (chat, streaming, determinism) does not apply to a decision instance.

## Health and readiness

`readiness` (preflight, before `main`): the container engine is ready, the weights file and the
store's listing exist, the render node exists. `health`: the unit is active; the power cap holds;
every container is running and healthy; `/health` says `ok`; `/v1/models` lists the served id
with `meta.n_ctx` equal to `llamacpp_context_size`; `/metrics` answers; **one token comes back**
from a real chat completion (mode `generate`; the one place the hook touches the service: it
leaves a short prompt in a slot's cache) or, in mode `decision`, a probability from
`/v1/systemone` (above).

## Conformance

`hnx conform run inference --target modules/llamacpp/conformance/target.yml` with
`HNX_ENDPOINT_INFERENCE` set to the server. **Run directly, one mandatory check fails by design:**
`unknown-model-rejected`. llama-server (b12033, measured) answers a request for any model id with
its own and never returns a 4xx for another; the role allow-list lives in the gateway, and the
suite passes through the gateway (docs/llm-gateway.md). The other checks (models listed, the
reply names the model, determinism at temperature 0, streaming, usage) hold. The module's test
pins both facts against a stand-in that behaves like this.

## Facts measured, and what only hardware can show

- On the Intel Arc B60 24 GB VM (Debian 13, kernel 7.2 from backports, Mesa ANV), by hand,
  llama.cpp b12430, Vulkan, `-ngl 99`: Clef 27B Q4_K_M (18.2 GiB) pp512 198 t/s, tg128 8.6 t/s.
  The pin here is the older b12033 (the newest image tag at least 14 days old).
- Checked on a CPU image of the same build (b12033), not on a GPU: the flags of the command line,
  `/health` public with and without a key, `/v1/models` carrying `meta.n_ctx` = the per-slot
  context, `/metrics`, the web UI off, a container running as an unprivileged id with the image's
  `curl` healthcheck, and any model id being answered.
- **Not provable here** (verify at the first deploy, in order): that the image's Mesa drives the
  Battlemage card (`vulkaninfo` or the first `/v1/models` after load), that the xe driver
  exposes `power1_cap` for the card on the guest (see `ls /sys/class/drm/renderD128/device/hwmon/*/power1_*`;
  if the cap is the sustained limit it may be `power1_max`: set `llamacpp_power_cap_attrs`), and
  the group the render node has on the guest.

## Overlay checklist

- `lab/modules.yml`: select `llamacpp` in the `inference` slot, `instance` = the registry row's
  name (for example `inference-small`), `placement: {server: <site host>}`; the host's guest has
  the GPU (`gpu` in the guest file, one resource mapping) and the `model-runtime` baseline.
- `lab/services.yml`: the row exactly as bound (host = the guest, `version: "0.12033.0"`), plus at most
  `standing`, `backup_job`, `scope`.
- Group variables for `mod_llamacpp_server`: `llamacpp_logical_id`, `llamacpp_served_model_name`
  (the role table's model id), `llamacpp_model_*` if not the default model, `llamacpp_context_size`,
  `llamacpp_parallel`, `llamacpp_n_gpu_layers`, `llamacpp_backend` and `llamacpp_image`,
  `llamacpp_power_cap_max_watts` only to tighten the 200 W default (above 200 is refused; the check's sysfs and device roots are fixed role variables, not settings).
- Model store: an entry in the model store manifest (`format: gguf`, `engines: [llama-server]`,
  the file's sha256 and size, a 40-hex revision) applied by `model_store` **before** this module;
  the guest's `outbound_allow` reaches the lab's mirror for that fetch (`model_store_require_mirror`).
- Firewall: inbound `llamacpp_port` from the model gateway's guest and from the metrics guest,
  nothing else; no `outbound_allow` to the internet; SSH as the baseline's.
