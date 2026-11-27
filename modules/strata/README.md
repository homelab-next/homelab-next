<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `strata`: the inference provider on the Strata engine

A provider module ([module manifest](../../docs/modules.md), draft) that fills the `inference` slot
with [Strata](https://github.com/Niko1221/Strata) (MIT, C++/CUDA with a Python server), which serves
**one mixture-of-experts GGUF model** (a split series and, optionally, a refusal-direction file) **on
one NVIDIA GA100 card** (the CMP 170HX: sm_80, 64 GiB after the in-guest driver unlock) through an
OpenAI-compatible API. It is a sibling of the [`llamacpp`](../llamacpp/README.md) module: the same
slot, the same shared conformance adapter, the same security posture, a different engine. A site
selects `provider: strata` (or `provider: llamacpp`) for an inference instance; the
[model gateway](../../docs/llm-gateway.md) routes a role to it either way. It is a **service, not a
machine**: the guest is the site's guest file, and the selection places the one host role
(`server`) on it. Nothing here names a real host, address, VM id or secret value.

| | |
|---|---|
| Slot | `inference` (contract `conformance/protocols/inference.py`), stateless |
| Adapter | the shared `homelabnext.conform.adapters.inference_server:make`, feature `streaming` |
| Product | Strata release v0.2.22 (2026-11-25), commit `b28ca95e3e6847f2d5e317994f253b66716deeaa`, product version `0.2.22` |
| Host role | `server`: kind `vm`, baseline `server` (the site adds `model-runtime`), footprint 8 vCPU, 16 GiB, 20 GB and one exclusive GPU resource (see "Footprint") |
| Role | `strata` (role interface v1), a wrapper of the core `compose_app` |
| Requires | the weights in the model store (role `model_store`), the container engine, the card passed through with the container toolkit's CDI spec (role `nvidia_container_toolkit`), the image below |
| Egress | none (the guest is a model runtime: default-deny, see below) |
| Public route | none |

## What the role does

- **One container, one starter.** `compose_app` renders `docker-compose.yml` (never started by it:
  `compose_app_start: false`); the unit `hnx-strata.service` runs `docker compose up` in the
  foreground and is the only thing that starts the container (`restart: "no"`). A crash, a restart
  and a reboot all go through the unit's `ExecStartPre`. The unit stops the container with a 120 s
  grace period: Strata asks for two minutes to unload a large model, and docker's default 10 s kills it.
- **The pre-start check** (`hnx-strata-precheck`, below) refuses to start unless the card's power cap
  is at or under `strata_power_cap_max_watts` (default **200 W**, never above), the guest lists
  exactly `strata_expected_gpus` cards, the CDI spec is fresh and every model file is the pinned bytes.
  The health hook runs the card rules again (`--power-only`), so a cap raised after the start turns
  the service red.
- **GPU passthrough.** One CDI device, `nvidia.com/gpu=<strata_gpu_index>` (the container sees that
  one card as its own index 0). Nothing else is a device, the container is not privileged, has no
  capability (`cap_drop: ALL`) and `no-new-privileges`, runs as an id of its own (`strata_uid`, 61001)
  in the **model store's group** (read from the model directory, or `strata_models_gid`), which reads
  the weights and writes none. Its only writable paths are `data/` under the module's data root
  (mounted at `/data`: the launcher's settings and log and the tokenizer it builds from the weights,
  all rebuilt on start) and a 2 GiB `/dev/shm`.
- **No egress.** Nothing is fetched at start: the model is mounted read-only from the store, the
  draft layer (a separate ~5 GB download) is off, the image sets `HF_HUB_OFFLINE=1` and its starter
  has no network step. As for `llamacpp`, the module-level `egress: none` is not enforced by the module
  apply path for containers (the loader warns); the guest's own forward chain is: a model runtime
  guest runs the `model-runtime` baseline with `policy_out: DROP`. Because that guest cannot pull or
  build either, `strata_image_archive` loads the lab-built image from a local archive whose sha256
  (`strata_image_archive_sha256`) is checked **before** anything is loaded.
- **No key, no public route.** The registry row is `auth: none`: the server holds no key of its own and
  the guest firewall admitting only the gateway and the metrics scraper is the control, exactly as for
  `llamacpp` (Strata starts with `--no-api-key`, which it prints a warning for and does not refuse).
  Strata has a web page (chat, monitor, settings) and `POST /load`, `/unload` and `/config`; they
  answer whoever the firewall lets in, so the allow list is the whole control, and the page is not
  switchable off.

## The settings

Every setting is a named variable in `roles/strata/meta/argument_specs.yml`, with its default in
`defaults/main.yml`. There is **no raw flag passthrough** (as in `llamacpp`): the role turns the
names into `HNX_STRATA_*` environment variables and the image's starter (`roles/strata/files/image/entrypoint.sh`) turns
those into the one `strata launch` command line. An unknown key, a flag-shaped key or a value of
the wrong type or range is refused before a file is written.

| Variable | Default | Launcher setting |
|---|---|---|
| `strata_model_files` | the IQ3_XXS pack's two shards | `--model-path <first shard>` (the others are found beside it); every file is pinned and read-only |
| `strata_direction_file` | none | `--control-vector-scaled <file>:<scale>`, `--control-vector-layer-range <a> <b>`, `--cvec-mode project`, `--cvec-dir per-layer` |
| `strata_direction_scale`, `strata_direction_layers` | `1.0`, `[4, 44]` | the projection's scale (above 0, at most 4) and first and last layer |
| `strata_context_size` | `131072` | `--context` (the model is trained to 262,144) |
| `strata_parallel` | `1` | `--parallel` (1 to 16 requests decoded together) |
| `strata_spec_depth` | `4` | `--set spec=N` (0 to 8; 0 leaves it to the engine) |
| `strata_kv_mode` | `k8v4` | `--kv` (`int8`, `q4_0`, `k8v4`, `fp16`) |
| `strata_drafting` | `off` | `--drafting` (`off`, `auto`, `mtp`) |
| `strata_extra_args.kv_streaming` | `off` | `--set kv-streaming=on\|off\|auto` |
| `strata_extra_args.mmap_experts` | `on` | `--set mmap-experts=on` (`off` leaves the engine's own copy in RAM; `auto` leaves the choice to the launcher) |
| `strata_extra_args.pcie_frac` | `0` | `--set pcie-frac=F` (0 to 0.95) |
| `strata_extra_args.threads` | engine's | `--set pool-workers=N` (1 to 256: the CPU threads that compute experts) |
| `strata_extra_args.vram_reserve_mib` | engine's | `--set vram-reserve-mib=N` (0 to 65536) |
| `strata_port` | `8001` | the published port (the registry row's); inside the container Strata listens on 8080 |

**The flags for a 64 GiB sm_80 card with every expert resident.** The IQ3_XXS pack's experts are about
43 GiB and the rest of the model about 6 GiB; with the KV cache at `k8v4` (about 10.6 KB a token, 1.4 GB
at 131,072 and 2.8 GB at 262,144) everything fits in the card's memory with room to spare. The defaults
say so:

- `--kv k8v4` and `kv-streaming off`: keys at 8 bits and values at 4, kept **in the card's memory**
  (KV streaming moves the cache to RAM to make room for experts, which is not needed here).
- `mmap-experts on`: the experts are read from the GGUF files in place and uploaded once, and the card
  holds them; the engine does not keep a second, pinned copy of ~43 GiB in the guest's RAM. The guest
  then needs far less RAM than the pack's size. If the guest has RAM to spare and the files'
  filesystem does not map well (the store is virtiofs), set `mmap_experts: off` and give the placement
  the RAM (see "Footprint").
- `pcie-frac 0`: no expert crosses the card's PCIe link, which on this card is narrow; with every
  expert on the card there is nothing to copy, and with one missing a CPU computes it. The load itself
  reads ~76 GB through that link, so the **first start takes minutes** (health waits up to
  `strata_load_timeout`, 3600 s).
- `--spec 4`, `--drafting off`: Strata's depth of speculative decoding with its suffix and
  prompt-lookup drafter (every drafted token is verified by the model). The model's own MTP draft
  layer is a separate ~5 GB download of the original checkpoint, which the model store does not hold,
  so it is off; `strata_drafting: auto|mtp` would try to fetch it and the offline guest could not.
- `--parallel 1`, `--context 131072`, expert cache and VRAM reserve at the engine's `auto`.
- `--vision off`, `--tune skip`, `--access lan --no-api-key`: fixed by the starter.

Strata also documents opt-in kernels measured on a CMP 170HX (`STRATA_GRAPH_PRIO`, `STRATA_MMVQ_IL_PF`,
`STRATA_PF_FUSED_NT`, `STRATA_PF_BATCH`, ...; DETAILS.md, "CUDA opt-in decode switches measured on a
CMP 170HX"). They are `STRATA_*` environment variables, not settings of this module: a measured gain
on the real card is the reason to add each one as a named key.

## The refusal-direction file

`strata_direction_file` names a GGUF control vector in the same store entry. Strata applies it as its
**refusal-direction projection** (the package's own description: with it the model declines far fewer
requests, so removing refusals removes a safety behaviour, shifts ordinary answers a little and costs
0.2 to 0.4 % a token). The file is pinned in the store listing and checked before every start like a
shard; the role refuses a name that is also a shard or is not a plain `.gguf` file name. Whether to
set it is the site's decision; unset, the model is the stock one.

## The pre-start check

`hnx-strata-precheck` is the unit's `ExecStartPre` and the health hook's card rule. It is
[`hnx-llamacpp-precheck`](../llamacpp/roles/llamacpp/files/hnx-llamacpp-precheck)'s NVIDIA branch and
byte check, plus the rules this module adds. It is a **copy, not a shared file**, on purpose: a role
installs its own files, no module names another module's path (a module can be removed alone), and the
repository has no symlinks; a rule changed in one is changed in the other by hand.

1. **The driver is already up** (`/proc/modules` lists `nvidia` and `/dev/nvidiactl` exists), else it
   refuses without calling `nvidia-smi`, which as root would load the module itself.
2. **The CDI spec is fresh**: every NVIDIA device node the spec records with a major number must exist
   under `/dev` with that same major (`nvidia-uvm`'s is assigned at module load, so a spec from before a
   reboot hands the container the wrong node, `cuInit` fails and the model silently runs on the CPU).
3. **Exactly the expected cards**: `nvidia-smi` must list exactly `strata_expected_gpus` (a card that
   fell off the bus, or one more than the site placed, refuses), the card `strata_gpu_index` must be one
   of them, and both its `power.limit` and `enforced.power.limit` must be numbers above 0 and at most
   `strata_power_cap_max_watts` (an unreadable cap refuses).
4. **The bytes are checked, not trusted**: the model store's listing hashes to the pinned
   `strata_model_digest`, and every file in it matches (`sha256sum --check --strict`). The served first
   shard, **every other shard** (the whole series must be listed) and the direction file must be listed
   (an unlisted file is never checked by that), and every listed file must resolve inside the entry's
   directory.

Weights are fetched only by `model_store`, at a pinned revision and a pinned sha256 per file, never at
container start; the container mounts the entry's directory read-only.

## The image

There is **no published image to pin**: the container runs an image the lab builds from a pinned
release, like the gateway's. `image/Dockerfile` builds Strata **v0.2.22** for **sm_80 only**
(`-DCMAKE_CUDA_ARCHITECTURES=80-real;80-virtual`, no Hy4 or Inkling shape engine, no picture reader),
from the upstream's own `tools/docker/Dockerfile.src` stages at that commit, on a pinned CUDA 13.0.0
`devel` base and a pinned `ubuntu:24.04` runtime (both by the digest of their multi-architecture
index). The first stage fetches the source from GitHub by tag and **stops unless the tag resolves to
the pinned commit** (`b28ca95e3e6847f2d5e317994f253b66716deeaa`). The runtime stage is the lab's own:
no model download, no key made on first start, a starter (`roles/strata/files/image/entrypoint.sh`) that holds the settings to the named
variables, a health probe (`healthcheck.py`) (`GET /health`: healthy only with the model loaded) and `USER 61001:61001`.
The build needs the network (GitHub, the Ubuntu archive, PyPI for the upstream's pinned wheels);
**running it does not**.

The recipe (the build context is the module's own directory, whose `image/Dockerfile.dockerignore` lets in only the role's `files/image/` starter and probe; `<commit12>` is the first 12 hex of
the commit, `SOURCE_DATE_EPOCH` the commit's time):

```bash
docker buildx create --name hnx-strata --driver docker-container   # once: the default driver cannot write an OCI archive
cd modules/strata
SOURCE_DATE_EPOCH=1795609947 docker buildx build --builder hnx-strata -f image/Dockerfile \
  --provenance=false --sbom=false --build-arg SOURCE_DATE_EPOCH=1795609947 \
  --output type=oci,dest=hnx-strata-0.2.22-b28ca95e3e68.oci.tar,name=localhost/hnx-strata:0.2.22-b28ca95e3e68,rewrite-timestamp=true,oci-mediatypes=true,compression=gzip \
  .
# the pin: the OCI manifest digest (index.json), and the archive's own sha256 (checked before every load)
tar -xOf hnx-strata-0.2.22-b28ca95e3e68.oci.tar index.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["manifests"][0]["digest"])'
sha256sum hnx-strata-0.2.22-b28ca95e3e68.oci.tar | tee hnx-strata-0.2.22-b28ca95e3e68.oci.tar.sha256
# on a machine that has the container engine, to try it before the deploy (the guest does this itself):
sha256sum -c hnx-strata-0.2.22-b28ca95e3e68.oci.tar.sha256 && docker load -i hnx-strata-0.2.22-b28ca95e3e68.oci.tar
docker image inspect --format '{{.Id}}' localhost/hnx-strata:0.2.22-b28ca95e3e68   # the same manifest digest, the containerd image store
# the image carries no layer that unpacks at load on the guest: for a registry (not used here) push with
#   --output type=image,name=<registry>/<name>,push=true,rewrite-timestamp=true,unpack=false
```

`--provenance=false --sbom=false` keep BuildKit's attestation manifests out of the index (so the index
holds the one image manifest and its digest is the image's), `SOURCE_DATE_EPOCH` with
`rewrite-timestamp=true` clamps every file timestamp in the layers to the commit's time, and
`unpack=false` (registry exports) leaves the layers unextracted on the builder. The reference the role
takes is

```
strata_image: localhost/hnx-strata:0.2.22-b28ca95e3e68@sha256:5fa487d5345b04ee7022b27d18f0f8c228d531c0b8c8fab21f1797b040e3be41
strata_image_archive: /var/lib/hnx-images/hnx-strata-0.2.22-b28ca95e3e68.oci.tar
strata_image_archive_sha256: ce803457cfbf4321613ee3beb345994def0106e548218d313c9e4c03e8dd865d
```

The role refuses an image of any other repository, a tag that is not `<release>-<commit12>` and a
placeholder digest; it checks the archive's sha256 **before** `docker load` and the digest after. **A
rebuild is not promised to give the same digest, and measured, it does not**: a `--no-cache` rebuild
of the same files minutes later (the Ubuntu archive, PyPI and the compiler answer with what they hold
and produce what they produce) changed three of the six layers (the runtime's apt layer, the Terminal and
the engine). The pin is therefore the digest the operator built and recorded, and the saved archive, not
a rebuild, is what is deployed. This build, made on 2026-11-26 (CUDA 13.0.0 `nvcc`, the engine package
`0.1.69-linux-x86_64-cuda-cuda13`, 595 MB), has manifest digest
`sha256:5fa487d5345b04ee7022b27d18f0f8c228d531c0b8c8fab21f1797b040e3be41` and archive sha256
`ce803457cfbf4321613ee3beb345994def0106e548218d313c9e4c03e8dd865d`. The container could not be
run with a card here (no GPU on the build machine): the image's checks that ran are that the engine
package verifies, every library resolves inside the image, `strata launch --help` lists every flag
the starter passes, the starter refuses with a clear message when no card is visible, and the
container starts as a non-root id.

`tools/pin_freshness.py` lists `strata_image` as a lab-built pin (`none`: compare with the project's
releases by hand). A bump is a new tag and digest together with `product.version` in `module.yml`,
the lab registry's version and the README's pins; the upgrade hook validates a newer `<release>-<commit12>`
of this repository and records it, then the converge moves.

## The contract the gateway needs

`GET /health` (200 `{"status":"ok","loaded":<bool>,...}` from the moment the API is up; **`loaded` is
true once the model is**), `GET /v1/models` (one model, with `meta.n_ctx` its context limit: the K-14
probe reads it), `POST /v1/chat/completions` (streaming included; Strata does not match the `model`
field against the loaded model), `GET /metrics` (the registry row's `metrics:` path). The row is
`capability: inference`, port 8001, `auth: none`.

**Metrics, and the tokens-per-second gap.** Strata has Prometheus metrics, three routes of them:

| Route | Names | What it is |
|---|---|---|
| `GET /metrics` with `Accept: text/plain` (what a scraper sends) or `?format=prometheus` | vLLM's (`vllm:num_requests_running`, `vllm:kv_cache_usage_perc`, token and request counters, time-to-first-token, inter-token and end-to-end histograms, `vllm:spec_decode_*`) and Strata's own under `strata:` (`strata:live_tok_s`, `strata:last_hit_rate`, `strata:gpu_util`, ...) | the registry row's path; without that header the same route answers JSON (the Monitor tab's data) |
| `GET /metrics/prometheus` | **llama-server's** (`llamacpp:tokens_predicted_total`, `llamacpp:tokens_predicted_seconds_total`, `llamacpp:prompt_tokens_total`, `llamacpp:requests_processing`, ...) and `strata:drafts_offered_total`, `strata:drafts_accepted_total`, `strata:model_loaded` | what the metrics module's existing `LlmDecodeCollapsed` rule reads with `prometheus_inference_metric_prefix: "llamacpp:"` (`rate(tokens_predicted_total) / rate(tokens_predicted_seconds_total)` under the threshold while generating) |

So the honest answer is: **the data exists and is compatible, the registry row cannot point at it.**
A registry row's `metrics.path` is a string in the module's own YAML, and the product-name lint
(ADR-0027 rule 1) refuses another product's name in a module's files, `/metrics/prometheus` included:
the row therefore names `/metrics`, which a scraper gets in vLLM's names, and the decode-rate rule
reads nothing from it. Two ways to close the gap, both outside this module: the site adds a scrape job
for `/metrics/prometheus` (site configuration may name products) and sets the prefix, or the metrics
module's rule learns the inter-token histogram (`1 / (rate(sum) / rate(count))` of vLLM's
inter-token latency is the same decode rate). Until one is done, **`LlmDecodeCollapsed` does not
watch this module**, and the module's own health hook (the one-token completion) is what notices a
server that stopped generating; it cannot notice one that generates slowly on the CPU. The decode
counters count generated tokens and the time spent decoding them, so the ratio is the decode rate
including speculative decoding's gain. Strata's route has the totals since the start (the rate
functions handle the reset at a restart) and no per-request latency.

## Health and readiness

`readiness` (preflight, before `main`): the container engine is ready, every shard, the direction
file and the store's listing exist as regular files, the CDI spec is written. `health`: the unit is
active; the card rules hold; the container is running and healthy; `/health` says `loaded`; `/v1/models`
lists one model whose `meta.n_ctx` is a positive number at most `strata_context_size`; the metrics
route answers in the text exposition format; **one token comes back** from a real chat completion
(`reasoning_effort: none`, the one place the hook touches the service: it leaves a short prompt in the
conversation cache).

## Conformance

`hnx conform run inference --target modules/strata/conformance/target.yml` with
`HNX_ENDPOINT_INFERENCE` set to the server. **Run directly, `unknown-model-rejected` fails**: Strata's
documentation says the `model` field is not matched against the loaded model (one server serves one
model), as llama-server answers any id; the role allow-list lives in the gateway, and the suite passes
through the gateway. The module's tests pin this against a stand-in that behaves like it. The checks
that hold are the rest of the suite (models listed, determinism at temperature 0, streaming, usage).

## Footprint

The manifest's `server` footprint (8 vCPU, 16 GiB, 20 GB) is the module's **minimum**, and by
default its slice (`hnx-strata-server.slice`, the container's cgroup parent). With the defaults
(`mmap_experts: on`, the card holding every expert) the guest's RAM is the page cache for the reads
and the engine's own buffers; a site that sets `mmap_experts: off` raises the placement's `memory_mb`
past the experts' size (about 64 GiB), beside the placement in the site's selection, never in this
module. Set `threads` to at most the placement's `cpu`.
The disk is the image (0.6 GB compressed, about 1.5 GB loaded) and the data directory (small).

## Not provable without the card, and the first deploy's checks

Nothing here ran on a GA100 card: the build machine has no GPU. CI proves the role against fakes and
the image against its own build. At the first deploy, in order:

1. `docker logs` shows `strata launch` choosing the engine (`0.1.69 ... cuda13`) and the card
   (driver 615.71.10 is above the image's 580.65 floor); the model's setup checks each shard's
   sha256 against the values Strata pins for the ISTA-DASLab release.
2. The store's files are the **same bytes Strata pins** (revision `ed59f92082b1e93c0e96d60a8b11aab089b52f09`,
   shard 1 `219ea929...d15`, shard 2 `316b46f3...e113`): the launcher's setup reports a file that does not match what it pins.
3. `mmap-experts` over the read-only virtiofs mount works; if the engine reports a mapping failure,
   set `mmap_experts: off` and raise the placement's memory.
4. The container's `RLIMIT_MEMLOCK`: Strata's own Docker guide passes `--ulimit memlock=-1:-1` so the
   engine can pin RAM. `compose_app` has no `ulimits` key (a reviewed addition, like `devices` and
   `group_add` were), so this module does not set it. With the experts on the card and mapped, the
   engine pins little; if it reports `[pinned-memory-exhausted]`, that key is the next change.
5. `/v1/models` `meta.n_ctx` equals the context asked for, then tighten the health check to equality.
6. The decode rate on the real card, against `LlmDecodeCollapsed`'s threshold, and whether the opt-in
   CMP 170HX kernels above are worth a named key.

## Overlay checklist

- `lab/modules.yml`: select `strata` in the `inference` slot, `instance` = the registry row's name
  (for example `inference-moe`), `placement: {server: <site host>}`; the host's guest has the GPU (`gpu`
  in the guest file, one resource mapping) and the `model-runtime` baseline.
- `lab/services.yml`: the row exactly as bound (host = the guest, `version: "0.2.22"`), plus at most
  `standing`, `backup_job`, `scope`.
- Group variables for `mod_strata_server`: `strata_logical_id`, `strata_model_digest` (**required**: the
  digest of the entry's listing, `hnx models store list`), `strata_served_model_name` (the role table's
  model id), `strata_direction_file` if used, `strata_context_size`, `strata_image`,
  `strata_image_archive` and `strata_image_archive_sha256`, `strata_power_cap_max_watts` only to tighten
  the 200 W default (above 200 is refused), `strata_expected_gpus` if the guest has more than one card.
- Model store: an entry in the model store manifest (`format: gguf`, the two shards and the direction
  file: sha256 and size each, a 40-hex revision) applied by `model_store` **before** this module; the
  guest's `outbound_allow` reaches the lab's mirror for that fetch (`model_store_require_mirror`).
- Metrics: see "Metrics, and the tokens-per-second gap" (a scrape job for the llama-server-named route and `prometheus_inference_metric_prefix: "llamacpp:"`, or a rule on the inter-token histogram).
- Firewall: inbound `strata_port` from the model gateway's guest and from the metrics guest, nothing
  else; no `outbound_allow` to the internet; SSH as the baseline's.
