---
summary: 'Model serving behind the gateway: one model store, the serving spec, the model_store, vllm_server and open_webui roles, adding a model and GPU notes.'
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Model serving: one store, few engines

Behind the [LLM gateway](llm-gateway.md) ([[llm-gateway]]) sit the engines that actually run
models. The decision on which engines, and where their weights live, is
[ADR-0023](adr/0023-model-serving-one-store-few-engines.md):

- **one model store**, `/srv/models/{hf,gguf,exports}`, holding each model once per
  (source, revision, quant), pinned by commit and sha256;
- **vLLM** serves production (agents, the decision cascade, chat) from `hf/` and promoted
  `exports/`;
- **llama-server** serves the GGUF-only fallback from `gguf/`, only when a model needs it;
- **Unsloth Studio** is the interactive GUI, test bench and trainer; it writes fine-tune exports
  into `exports/`;
- **Open WebUI** is the chat front end, and it talks to the gateway only;
- **Ollama and LM Studio are retired.** Ollama repacks every model into its own blob store (a
  second copy), and its auto-update has evicted another tool's model. LM Studio wraps llama.cpp
  and adds nothing on a headless host.

Callers never see any of this. They call `mdl:<role>` through the gateway
([ADR-0007](adr/0007-model-role-aliases.md)), and swapping an engine is a binding change plus the
`inference` suite and a golden run.

## Three files, one truth

| File | Says | Checked by |
|---|---|---|
| the store manifest (`schemas/platform/model_store.schema.json`) | every model on disk: format, quant, source repo and pinned commit, every file's sha256 and size, licence, which engines may serve it | `hnx models store validate` (shape and cross-entry rules), `hnx models store check` (the bytes on disk) |
| the role table (`schemas/platform/model_roles.json`) | which role calls which backend and model id, its context length, its pin (`version`, `digest`) | `hnx golden pins check`, the K-14 probe |
| the serving spec (`schemas/platform/model_serving.schema.json`) | per backend: the engine, its port, its GPUs, its engine flags | `hnx models serving check` |

`hnx models serving render SPEC OUT_DIR` joins the three. It finds, per backend, the one store entry
it serves, and writes `vllm_server/instances.yml`, the input of the `vllm_server` role. The gateway
generator reads the same serving spec (`serving:` in a gateway spec) to declare its local backends.
So the vLLM command line and the gateway's backend list are both generated, and both come from the
same role table. `examples/model-serving/` is the worked example: store, role table, serving spec,
gateway spec, and the generated `vllm_server/instances.yml` and `gateway/`. `make models-check`
fails on drift in any of them.

### The store

```
/srv/models/                         root (owner models, group models: engines read, never write)
  hf/hub/models--<org>--<name>/      HF_HOME=/srv/models/hf: the hub cache layout
     blobs/<sha256>                    one copy of each file (the hub client deduplicates by blob)
     snapshots/<revision>/<file>       symlinks into blobs/, one directory per pinned commit
  gguf/<org>/<name>/<file>.gguf      single-file GGUF (gguf-split --merge a sharded one first)
  exports/<run>/                     fine-tune exports (group model-trainers may write here)
  manifests/model_store.json         the manifest the role deployed
```

| `format` | Where | May be served by |
|---|---|---|
| `hf` (safetensors BF16/FP16/FP8/AWQ/GPTQ) | `hf/hub/.../snapshots/<revision>/` | `vllm`, `unsloth-studio` |
| `gguf` | `gguf/<org>/<name>/` | `llama-server`, `unsloth-studio` |
| `export`, `layout: safetensors` | `exports/<run>/` | `vllm`, `unsloth-studio` |
| `export`, `layout: gguf` | `exports/<run>/` | `llama-server`, `unsloth-studio` |

vLLM never serves GGUF. Its GGUF path is an out-of-tree, single-file plugin that its own docs call
highly experimental and under-optimized. The manifest refuses `vllm` on a GGUF entry.

Rules the manifest enforces (`homelabnext.models.store`; the schema carries what JSON Schema can):

- `source.revision` is a full 40-hex commit. `main`, a tag or a short hash is refused, because a
  floating revision names a different model tomorrow.
- No two entries share (source, revision, quant). Two quants of one GGUF repository are two
  entries; the same quant twice is refused.
- Every file is listed with its sha256 and size, relative to the entry's directory, with no `..`.
- An entry's **digest** is `sha256:` of its `sha256sum` listing (`<hex>  <path>` lines in path
  order). `sha256sum` reproduces it, and `hnx models store list` prints it. This is the value a
  role binding's `digest` pins, so G-11 names one set of bytes, not a file name.
- An export names its training run and the `base` entry it came from.

**Resolving a binding.** A binding resolves to the entries whose `served_model_name` is its
`model_id`, that its backend's engine may serve, narrowed by its `digest` when pinned. Exactly one
must remain. A pinned `version` that is a commit must be the entry's revision. `hnx models store
validate STORE --roles ROLES` checks every binding without the engine; the serving plan checks it
with the engine.

### The serving spec

```yaml
version: 1
store: model_store.json
roles: model_roles.json
exposure: zone                 # or loopback; required
backends:
  svc:inference-large:
    engine: vllm
    port: 8000
    gpus: [0, 1]               # PCI bus order (CUDA_DEVICE_ORDER=PCI_BUS_ID)
    tensor_parallel_size: 2
    args: {tool-call-parser: qwen3_xml, enable-auto-tool-choice: true}
  svc:inference-small:
    engine: llama-server
    port: 8001
```

What the plan sets on every vLLM instance, never `args`:

| Flag | From |
|---|---|
| the model path | the store entry's directory (a snapshot by commit, never a repo id) |
| `--served-model-name` | the binding's `model_id`, which the gateway sends and the K-14 probe expects |
| `--max-model-len` | the bound roles' `max_context_tokens`; they must declare one and agree |
| `--scheduling-policy priority` | always: request priority belongs to the engine (docs/llm-gateway.md) |
| `--host`, `--port` | the role's listen address (held to the spec's `exposure`), the spec's port |
| `--tensor-parallel-size`, `--pipeline-parallel-size` | the spec; their product must equal the number of GPUs |
| `--gpu-memory-utilization` | the spec (default 0.9) |

`exposure` states where the engines listen, never left to a default: `zone` (the host's zone
address; the gateway reaches each backend as `<name>.svc.<domain>`, and the host firewall admits
only the gateway) or `loopback` (the loopback address, this host alone, for bring-up). It is rendered into the
role's input as `vllm_server_exposure`, and the role refuses a `vllm_server_listen_address` that
disagrees (a loopback address under `zone`, a zone address under `loopback`, a wildcard under
either). The gateway generator refuses a `loopback` plan, whose backends it could never reach, and
a registry service whose port is not the plan's (the gateway would call one port while vLLM
listened on the other).

Refused: two backends on one port or one GPU; a vLLM backend whose bindings name two model ids (one
vLLM process serves one model); a backend no role binds; `engine: unsloth-studio` (Studio is the GUI,
not a gateway backend); any `args` flag outside the allowlist.

`args` is an allowlist (`homelabnext.models.serving.ALLOWED_ARGS`), not a denylist: exact vLLM flag
names (so no argparse abbreviation such as `hos` for `host`), each with a typed value (a whole
number or a fraction in range, one of a few choices, a short parser or quantization name, or a
boolean: `true` renders the bare flag, `false` nothing). No value may begin with `-`, so
`{enforce-eager: "--trust-remote-code"}` cannot become two flags. Flags that load a file, a URL,
a module or JSON (`config`, `chat-template`, `tokenizer`, `allowed-local-media-path`,
`middleware`, `tool-parser-plugin`, `worker-extension-cls`, `hf-overrides`,
`speculative-config`, `lora-modules`, ...) are never on it. The `vllm_server` role re-checks the
rendered argv against the same list: its `vars/main.yml` is generated from it
(`role_vars_text()`, held equal by a test), so a hand-edited instances file with `-tp=4` or an
unlisted flag fails before a unit is written. Moving `vllm_server_version` means checking every
allowlisted name still exists exactly in `vllm serve --help=all`.

## The roles

All three follow the [role interface](role-interface.md) ([[role-interface]]) and pass
`tools/role_lint.py`. Their tests (`tests/roles/test_serving_roles.py`) run them on localhost
against fakes.

### `model_store`

`model_store_manifest` (required) is the manifest. `main`:

1. validates it again (every hub entry pinned by a 40-hex commit, paths that stay in their entry),
   before anything runs;
2. creates the layout. Directories are `2750` `models:models`; `exports/` is `3770`
   `models:model-trainers` (sticky: a trainer may add a run, never rename or remove a promoted
   one);
3. fetches each `hf`/`gguf` entry whose files are missing or wrong, with
   `hf download <repo> <files...> --revision <commit>` into a staging directory,
   `<root>/.staging/<entry id>` (`--cache-dir` for `hf`, `--local-dir` for `gguf`), never into the
   live store. It always passes `--revision`, because the CLI's default is `main`. The hub token,
   if any, is `model_store_hf_token_ref` (`secret:<name>`, `no_log`), and a mirror is
   `model_store_hf_endpoint`;
4. checks every staged file against its sha256 and only then renames it into place
   (`files/promote_entry.py`: an `hf` blob into the repository's `blobs/`, its snapshot link
   replaced by a rename; a `gguf` file over its path). One bad file and nothing moves, so an
   interrupted or tampered download never reaches the store. The live entry is then verified by
   sha256 again, and a snapshot file that links out of its repository's `blobs/` fails;
5. verifies each promoted export (in the manifest, on disk) by sha256 and takes it out of the
   trainers' hands: owned `models:models`, `u=rwX,g=rX,o=`. Studio writes exports into a
   trainer-writable directory, so an export becomes served bytes only once it is store-owned;
6. writes each entry's `sha256sum` listing to `manifests/listings/<id>.sha256`, the file every vLLM
   unit checks before it starts.

Hooks: `health` checks the layout and every file's size (fast). `tasks_from: verify` is the sha256
pass. `backup` names `exports/` and `manifests/` only, because hub entries can be re-fetched byte
for byte. `restore` puts `exports/` back. `export` writes the manifest and each entry's `sha256sum`
listing.

**Read-only for engines.** Engines run as their own account in group `models`. They can read every
weight and write none. The `vllm_server` units also mount the store `ReadOnlyPaths=`. A remote
consumer (Studio on the workstation) mounts it read-only over NFS/SMB, with `exports/` as the only
writable export. That share is the file server's role, not this one.

### `vllm_server`

`vllm_server_instances` (required) is the rendered `vllm_server/instances.yml`. For each instance,
`main` writes `hnx-vllm-<name>.service`:

- `ExecStart=<venv>/bin/vllm serve <store path> --served-model-name ... --max-model-len ...
  --scheduling-policy priority ...` with the plan's flags;
- `CUDA_DEVICE_ORDER=PCI_BUS_ID`, `CUDA_VISIBLE_DEVICES=<gpus>`, `HF_HUB_OFFLINE=1`, telemetry off,
  and `NCCL_P2P_DISABLE=1` when `vllm_server_nccl_p2p_disable` is set;
- the `example_service` sandbox, loosened only for the GPU: `PrivateDevices=no` with
  `DevicePolicy=closed` and only the instance's own `/dev/nvidiaN` plus the control and UVM
  nodes, and no `MemoryDenyWriteExecute` (the CUDA
  and Triton JIT need writable, executable memory). The store is read-only, and only the
  instance's cache directory is writable;
- `ExecStartPre=hnx-model-verify <listing> <digest> <model dir>` (`files/hnx-model-verify`,
  installed at `vllm_server_verify_bin`): the store's listing must hash to the instance's pinned
  digest and every file must match it (`sha256sum --check --strict`). It runs before every start,
  `Restart=on-failure` included, so a unit never serves bytes that changed after `model_store`
  verified them. It reads every byte: minutes per hundred GB, inside `TimeoutStartSec=1800`;
- with `vllm_server_api_key_ref`, a `0600` environment file holding `VLLM_API_KEY`, so vLLM refuses
  callers without the gateway's backend key. In the gateway spec, declare that backend with the
  same `api_key` and port.

`main` refuses a vLLM that is not `vllm_server_version`, and an instance whose model is not in the
store. It also stops and removes every `hnx-vllm-*.service` the plan no longer lists, so the old
per-GPU units retire themselves. It restarts only instances whose unit changed.

`health` is K-14 on the host. Each instance must answer `/health`, and `/v1/models` must list the
role's model id with `max_model_len` equal to the role's `max_context_tokens`. The test holds its
verdict equal to `homelabnext.registry.models.probe`, the gateway-side K-14 probe, on the same
answers: a matching model passes; another context, an unreported context, or another model fails.

### `open_webui`

`open_webui` runs Open WebUI as a [compose_app](role-interface.md), pinned
`ghcr.io/open-webui/open-webui:v0.11.4@sha256:9591b13f…`:

- `OPENAI_API_BASE_URLS` is the gateway's registry URL plus `/v1` (`open_webui_gateway_id`,
  required). A backend id (`inference-*`, `vllm*`, `llama*`, `ollama*`) is refused, and the id is
  resolved through the registry: its service's `capability` must be `llm-gateway`
  (`open_webui_gateway_capability`), so an id such as `gpu-01` that points at a vLLM is refused
  whatever it is called. There is no way to point it at an engine.
- The key is this app's own gateway key, by secret name (`open_webui_gateway_key_ref`, default
  `secret:llm-gateway/key-chat-ui`, the `chat-ui` key in `examples/model-serving/gateway.yml`).
  The gateway scopes it to the roles chat may use and limits it. The key goes only into compose's
  `0600` env file, never into `docker-compose.yml`.
- Ollama, direct connections, sign-up, community sharing and the update check are off (fixed in
  `vars/`), and `ENABLE_PERSISTENT_CONFIG=false`: the environment is the configuration on every
  start, so a connection added in the admin UI does not outlive a restart. `open_webui_extra_env`
  may not name any `*_BASE_URL*`, `*API_BASE*`, `*API_KEY*` or `*ENDPOINT*` variable,
  `TOOL_SERVER_CONNECTIONS`, the web-search, RAG, image, audio and code-execution settings (each
  calls an endpoint of its own), or any fixed setting; names are upper-case only.
- Egress: the role cannot restrict the container's network (`compose_app` has no networks
  setting, and the gateway runs on another host, so an internal-only compose network would cut it
  off too). Restrict it on the host firewall instead: in nftables' `DOCKER-USER` path, let the
  Open WebUI bridge reach only the gateway's address and port (and the resolver), and drop the
  rest. `OFFLINE_MODE=true` keeps it from fetching models and updates; the firewall is what makes
  "only the gateway" hold if a setting slips. This is on the verify-on-hardware list.
- It is published on loopback. The front door, with the lab's sign-in, is the way in.

### Unsloth Studio: documented, not a role (yet)

Studio is the GUI: it chats, compares models side by side, trains, and exports (GGUF incl. imatrix,
16-bit safetensors, FP8). It runs on the workstation GPU, not the serving host. Use it this way:

1. Mount `/srv/models` read-only, with `exports/` writable. Point Studio's model directory at
   `hf/` and `gguf/`, and its export directory at `exports/<run-id>/`.
2. To compare against production, point Studio at the gateway (its OpenAI-compatible connection),
   with its own key. Do not point it at vLLM directly.
3. To serve an export, **promote** it: add a manifest entry (`format: export`, the run id, `base`,
   `layout`, every file's sha256, which `hnx models store list` and `sha256sum` give you). Then pin
   a binding to its digest, run `hnx models serving render`, and deploy `model_store` and
   `vllm_server`. Nothing is served from `exports/` without its hashes in git.

There is no `unsloth_studio` role. Studio is in beta, and how it is installed and started (the
package, its launcher, its flags, where it keeps state) is still changing between releases. None of
that could be verified here. A role written against it would pin behaviour no one has run. Once
one install is proven on the workstation, the role is small: a venv at a pinned version, a user
unit bound to loopback, the read-only mount, and a health check of its API.

## Adding a model

1. `hf download <repo> --revision <commit>` somewhere scratch, or read the hub's file list for that
   commit, and record each file's sha256 and size in a new manifest entry (pick `engines` by format).
2. Bind a role to its `served_model_name` in the role table, with `version` = the commit and
   `digest` = the entry's digest (`hnx models store list`). Set `max_context_tokens`.
3. If it gets its own backend, add it to the serving spec (engine, port, GPUs).
4. `make serving-render` (or the two render commands in the Makefile), then `make models-check`.
5. Deploy `model_store` (fetch + verify), then `vllm_server`. Then run its `health` hook, the
   `inference` suite through the gateway, and `hnx golden pins report` for the new pin.

## GPU notes: 4x CMP 170HX, verify on hardware

The serving host's cards are mining GA100s (sm_80, unlocked to 64 GB). Nothing below can be checked
without the hardware. Each item is a test to run before promising capacity:

- [ ] **Only two of the four cards are proven.** One reported Xid 79 and one never enumerated.
  Every GPU index in a serving spec must come from a card that has passed a burn-in on this host.
- [ ] **No P2P**, so set `vllm_server_nccl_p2p_disable: true`. Check that NCCL falls back to
  shared memory/PCIe, and that TP=2 still holds its throughput.
- [ ] **PCIe link.** At best Gen2 x16, and **Gen1 inside a VFIO guest** unless the host retrains
  the link. Read `nvidia-smi -q` (link gen/width) in the guest, and benchmark TP=2, TP=4, PP=2×TP=2
  and PP=4. With no P2P and cards split across two sockets, TP=4 may lose to PP.
- [ ] **FP32 units disabled.** Kernels that fall back to FP32 CUDA cores will crawl. Check that the
  FP8 W8A16 Marlin path and the attention backend (FlashAttention-2/FlashInfer) stay on tensor
  cores. Check every new-architecture kernel (DeltaNet, sparse attention) on sm_80 before
  adopting a model.
- [ ] **Unlocks under VFIO.** The patched driver and `cmpunlocker` are unproven in a guest. Check
  that the guest sees 64 GB per card, then set `gpu_memory_utilization` from what it really sees.
- [ ] **Device nodes.** Each unit allows, by path, only its GPUs' `/dev/nvidiaN` plus
  `/dev/nvidiactl`, `/dev/nvidia-uvm` and `/dev/nvidia-uvm-tools`, under `DevicePolicy=closed` (a
  `char-nvidia-frontend` rule would open every card, and `char-nvidiactl` is not a
  `/proc/devices` group, so systemd ignored it). Check that the unit starts; that `/dev/nvidiaN`
  is the card the plan's PCI-bus-order index names (`nvidia-smi -q` bus id against
  `/proc/driver/nvidia/gpus/*/information` minor numbers); that `nvidia-smi` inside the unit
  sees only its own cards; and whether this driver needs `/dev/nvidia-caps/*` (MIG only).
- [ ] **Training on these cards.** Unsloth/bitsandbytes optimizer paths may hit the disabled FP32
  units. Train on the workstation GPU first. A small LoRA here is an experiment, not a plan.
- [ ] **Open WebUI with `cap_drop: ALL`.** Check that the image starts with every capability
  dropped and the data directory owned by root. If it needs one (for example `CHOWN`), add only
  that one.
- [ ] **Open WebUI egress.** With the host firewall rule in place, check from inside the container
  that the gateway answers and that any other address (another lab host, a public one) does not.

## Not covered here

- llama-server units: the plan validates `llama-server` backends and the gateway routes to them,
  but no role renders them yet.
- The NFS/SMB export of the store to the workstation (the file server's role).
- vLLM Playground (a launch-settings GUI, test instance only) and benchmarking harnesses.
- A live run of any of this on a GPU host. CI proves the roles against fakes, and the K-14 probe
  against the fake inference server.
