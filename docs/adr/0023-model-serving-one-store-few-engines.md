---
summary: One model store, each model once, pinned by commit and sha256; vLLM serves production from it, a few engines elsewhere.
summary_of: outline:sha256:4020b828d8a1085d
---
# ADR-0023: Serve models from one pinned store with vLLM; Unsloth Studio is the GUI; retire Ollama and LM Studio

- **Status:** proposed
- **Date:** 2026-10-22
- **Related:** ADR-0007, ADR-0022, `schemas/platform/model_store.schema.json`,
  `schemas/platform/model_serving.schema.json`, [model serving](../model-serving.md),
  [LLM gateway](../llm-gateway.md)

## Context

A lab that grew one tool at a time ends up with several engines on several hosts: vLLM for the
agents, plus LM Studio, Ollama and a fine-tuning stack on the workstation, each with its own model
directory. The same model then sits on disk two or three times. Ollama repacks every import into
content-hashed blobs that no other tool can read, and an Ollama auto-update has evicted another
tool's model. Nobody can say which bytes a role served on a given day: the pins in the role table
(G-11) name a version and a digest, but no file says which files that digest covers.

Formats force some of the split. vLLM, SGLang and Unsloth read Hugging Face safetensors (incl. FP8,
AWQ, GPTQ). llama.cpp-family tools read GGUF. vLLM's GGUF support is an out-of-tree, single-file
plugin its docs call highly experimental. Ollama and LM Studio both wrap llama.cpp and add nothing
on a headless host. Unsloth Studio (beta) trains, exports, and runs both formats interactively, but
it is a single-user server, not a batching engine.

The serving host's GPUs are mining cards (GA100, sm_80) with disabled FP32 units, no P2P, a slow
PCIe link in a VFIO guest, and only two of four cards proven. So the hardware risk is real but
separate: it decides how many cards and which parallelism, not which engine.

## Decision

1. **One model store** at `/srv/models`: `hf/` (the hub cache layout, `HF_HOME=/srv/models/hf`),
   `gguf/` (single-file GGUF), `exports/` (fine-tune exports). Each model is kept once per
   (source, revision, quant), and the manifest (`model_store.schema.json`) refuses a second entry.
2. **Everything is pinned.** Each entry names a 40-hex source commit, never a branch, plus every
   file's sha256 and size. Its digest is `sha256:` of its `sha256sum` listing, and a role binding's
   `digest` pins exactly that. `hnx models store check` verifies the bytes; the `model_store` role
   fetches with `--revision <commit>` and refuses a mismatch.
3. **vLLM is the production engine**, one systemd unit per served model, generated from the store,
   the role table and a serving spec: `--served-model-name` = the binding's model id,
   `--max-model-len` = the role's `max_context_tokens`, `--scheduling-policy priority`, GPUs pinned
   in PCI bus order, the store read-only. vLLM never serves GGUF.
4. **llama-server** is the GGUF fallback, used only for a model vLLM cannot serve well.
5. **Unsloth Studio is the GUI and trainer.** It reads the store and writes into `exports/`. An
   export is served only after it is promoted into the manifest with its hashes. Studio is not a
   gateway backend.
6. **Open WebUI is the chat front end**, pointed at the LLM gateway with its own key, never at an
   engine.
7. **Ollama and LM Studio are retired.**
8. Every binding on a served backend must resolve to exactly one store entry its engine may serve.
   The serving plan and the gateway generator (`serving:`) both refuse one that does not.

## Consequences

- One copy per model: the disk holds what the manifest lists, and `check` finds anything else.
- A role's pin means something. The digest names the files, and the K-14 probe (on the host by the
  `vllm_server` health hook, and through the gateway) checks the model id and context length the
  engine really loaded.
- The vLLM command line and the gateway's backend list are generated from the same files, so they
  cannot disagree about a port, a model id or a context length.
- Adding a model is a manifest entry, a binding, a render and two role runs. Hand-starting an engine
  is no longer the shortcut.
- We now maintain the manifest by hand (hashes included) and keep three schemas in step.
- Studio and llama-server get documentation and validation, not roles, until a pinned install is
  proven. The CMP 170HX caveats stay "verify on hardware" items until benchmarks exist.

## Alternatives

- **Keep Ollama as the GGUF engine.** Rejected: it copies models into its own store (the duplication
  this ADR removes), and its auto-update has broken a neighbour.
- **Serve GGUF on vLLM to have one engine only.** Rejected: an experimental, single-file plugin in
  the production path.
- **GPUStack or a similar manager** owning placement and launch flags. Rejected for production: it
  overlaps the gateway, and it takes over the hand-tuned parser and context flags the role table now
  generates. It stays acceptable on a test instance.
- **SGLang.** Same formats as vLLM, with nothing it adds here. Kept as a swap candidate behind the
  same store and the `inference` suite.
- **Let each tool keep its own directory and symlink between them.** Rejected: there is still no
  manifest, no pin and no check, and Ollama cannot share a tree at all.
