<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `tts`: the operator's cloned voice, as a service

A provider module ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that fills the
provisional `tts` slot with a speech service which speaks in **the operator's own voice**: the XTTS-v2
model plus four reference recordings of the operator (`ref1.wav` to `ref4.wav`). It answers
`POST /synthesize` exactly as the old podcast service did, so the publishing pipeline switches over by
changing a URL and nothing else. It is a **service, not a machine**: the guest is the site's guest file,
and the selection places the one host role (`server`) on it. Nothing here names a real host, address,
VM id or secret value.

| | |
|---|---|
| Slot | `tts` (provisional: no contract yet; the contract is the one below), stateful (the voice) |
| Adapter | `homelabnext.conform.adapters.tts:make`, a read-only probe (health, readiness, one render when asked) |
| Product | `coqui-tts` 0.28.0 (the maintained engine library, MPL-2.0) on `transformers` 5.22 (the 4.x line has open advisories) running the XTTS-v2 model (product version `2.0.0` is the model's major) |
| Host role | `server`: kind `vm`, baseline `server`, 8 vCPU, 12 GiB, 20 GB; on `cuda` the card is handed over by its CDI device |
| Role | `tts` (role interface v1), a wrapper of the core `compose_app` |
| Requires | the voice model in the model store (role `model_store`), the container engine, the operator's recordings in the data root |
| Egress | none: nothing is fetched at start or at run time |
| Public route | none; no key (the guest firewall admits the publishing pipeline and the metrics scraper) |

## The `/synthesize` contract (unchanged from the old service)

Derived from the archived service (`service/app.py` of the old lab, an XTTS-v2 cloned-voice FastAPI
app) and its caller (the episode generator), and pinned by `tests/tts_service/test_tts_contract.py` and
`tests/tts_service/test_tts_service.py`:

* `POST /synthesize`, JSON body `{"text": str, "temperature": float|null, "top_p": float|null}`.
  `text` is required. `temperature` is in (0, 1.5] and `top_p` in (0, 1] when given; a field left out or
  `null` takes the settled defaults **0.6** and **0.85** (what the caller sends with every request).
  There is **no `speaker` field**: the voice is always the operator's own recordings. Unknown fields are
  ignored.
* **200**: the body is a WAV file (RIFF, **24000 Hz, mono, 16-bit PCM**), `Content-Type: audio/wav`. The
  caller's own loudness-normalise step turns it into the mp3 and is not touched.
* **400** `{"detail": "text must not be empty"}` for an empty or white-space text (checked before
  anything about the engine).
* **422** `{"detail": [{"type", "loc", "msg", "input"}, ...]}` for a body that is not a JSON object of
  that shape (the shape the old framework answered with). One deliberate difference: the old service
  coerced a numeric string for `temperature`; this one answers 422 (the caller sends numbers).
* **413** `{"detail": "text is longer than N characters"}` for a text over `tts_max_text_chars` (default 200000;
  new: the old service had no bound) and for a body over 4 MiB.
* **504** `{"detail": "synthesis exceeded N seconds"}` when one job runs past `tts_job_timeout_s` (default 7200, 0 =
  no limit; new). A running model call cannot be interrupted, so the job is abandoned, the lock is released and
  the next job loads a fresh engine (the stuck one frees its memory when it ends).
* **503** `{"detail": ...}` when the engine cannot take the job: before, "model not loaded yet"; now
  also a refused load (the power cap, the weights, the voice files), with the reason.
* `GET /health` is **200** `{"status": "ok", "model_loaded": bool, "refs": [path, ...]}`. New and extra:
  `GET /ready` (200 `{"ready": true, ...}` or 503 naming the failing gate; it loads nothing).
* One text rule belongs to the service: the literal upper-case token `US` is spoken as `U.S.` (the
  engine reads it as the pronoun otherwise). The old service's own tests are ported verbatim.
* Sampling is fixed at `language="en"`, `split_sentences=True` and the model's own sampler settings, as
  before. A client that stalls (sends nothing, or a body that never ends) is cut off after 60 s without holding a thread. A request is one job: jobs run one at a time (a second request waits for the first; the caller
  already allows 30 minutes).

## What the role does

- **One container, built from this repository.** There is no published image to pin: `image/Dockerfile`
  builds `homelabnext/tts_service` with the hashed dependency set `requirements-<backend>.txt` on a base
  pinned by digest (python 3.11.14, Debian 13 slim). Every wheel is hash-checked (`--require-hashes`,
  `--no-deps`, `--only-binary=:all:`; the one exception is `docopt`, a pure-python package published only as a
  source archive, so it is built from its hashed sdist). `compose_app` renders it with `cgroup_parent`, no capability, `no-new-privileges`, a user
  of its own (`tts_uid`), the model store's group for reading the weights, and the voice, the weights and
  the listing mounted **read-only**; its only writable paths are `state/` (the embeddings cache) and the
  scratch cache.
- **The model is pinned and checked, never downloaded.** The entry is the model store's (`model_store`,
  format `hf`, engine `tts-server`, pinned 40-hex revision, a sha256 per file; see "The model store
  entry"). `HF_HUB_OFFLINE`/`TRANSFORMERS_OFFLINE` are set in the image; the service hashes the store's
  listing against `tts_model_digest` and every file against the listing **before every load** (a file
  already hashed is not read again while its size and mtime are unchanged), and refuses a listing that
  does not name every file the engine loads.
- **Loaded per job, unloaded when idle.** The engine is loaded by the first job and unloaded after
  `tts_idle_unload_s` seconds without one (a job running is never unloaded under). On `cuda` the default
  is 120 s: the card's memory is free between jobs, as the operator asked. On `cpu` the default is
  never (the model stays in memory: a reload costs half a minute on a CPU).
- **The power-cap rule (the operator's).** Before **every** load on `cuda` the service reads the card's
  `power.limit` (`nvidia-smi` inside the container, CDI) and refuses unless it is a number above 0 and at
  most `tts_power_cap_max_watts` (default **200 W**; a setting can only tighten it, above 200 is refused
  by the role and by the service). Unreadable, unparseable, `nan`, infinite, 0 ("no limit set") or negative refuses: only a finite number above 0 and within the limit passes. The refusal is a
  503 with the reason, and `/ready` reports it, so a cap raised after the start turns the health hook red.
  The cap itself is the baseline's job (or a udev rule): this module only refuses to load without it.
- **Identical sound, faster.** The reference recordings are the same four files and the call is the same
  (`TTS(model_path, config_path).tts(text, speaker_wav=refs, language="en", temperature, top_p,
  split_sentences=True)`). The one addition: the conditioning latents of the recordings (the "speaker
  embedding") are computed once per (recordings, model) and kept in `state/` instead of once per
  sentence. Measured on the same seed: the waveform is bit-identical to the uncached path.
- **No egress.** The container is on a bridge network: the module-level `egress: none` is not enforced by
  the module apply path for containers (the loader warns), the guest's own forward chain is. The guest
  runs the default-deny `model-runtime` baseline (no `outbound_allow` for it), which also means it cannot
  pull the image: `tts_image_archive` loads it from a local `docker save`.

## The image

Built by the orchestrator from the commit the overlay pins, one image per backend:

```bash
cd <a checkout of this repository at the commit the overlay pins>
docker build -f modules/tts/image/Dockerfile --build-arg BACKEND=cpu -t localhost/hnx-tts:<version>-<commit12>-cpu .
docker image inspect --format '{{.Id}}' localhost/hnx-tts:<version>-<commit12>-cpu          # sha256:<digest>
docker save localhost/hnx-tts:<version>-<commit12>-cpu | zstd -o hnx-tts-<version>-<commit12>-cpu.tar.zst
sha256sum hnx-tts-<version>-<commit12>-cpu.tar.zst > hnx-tts-<version>-<commit12>-cpu.tar.zst.sha256
```

The reference the role takes is `tts_image: localhost/hnx-tts:<version>-<commit12>-<backend>@sha256:<digest>`:
a tag of this repository's own (it must end in the backend: a cpu image on a `cuda` setting, and the other
way, is refused) and the digest. The role loads `tts_image_archive` when the daemon lacks the digest and
refuses to go on if it is still missing. Verify the archive (`sha256sum -c`) before the deploy. A rebuild
of the same commit is not guaranteed to give the same digest; the pin is the digest the operator built and
recorded. To regenerate the dependency pins see the header of `image/requirements-cpu.in`
(`uv pip compile --generate-hashes --exclude-newer <date>`: nothing newer than the date is taken).

The CPU image is 2.5 GB; the CUDA 12.8 image (`BACKEND=cuda`, torch 2.11 `+cu128`) is larger and needs a
driver that supports CUDA 12.8 and the container toolkit's CDI spec on the guest.

## The model store entry

An entry applied by `model_store` **before** this module (the guest's `outbound_allow` reaches the lab's
mirror for that fetch, `model_store_require_mirror`). The entry as the module expects it is
`schemas/platform/examples/model_store.speech.json` (revision `6c2b0d75…`, digest
`sha256:41212ef7…`, the six files the engine loads and the licence text). It is format `hf` with the
engine `tts-server` (added to the store's engines for this module; the layout name `safetensors` is the
hub cache's, not a claim about the files, which are the model's own `.pth` checkpoints). The revision's
`config.json`, `vocab.json` and `hash.md5` are byte-identical to the ones archived from the old lab, so
this is the model the old voice was made with.

## The voice

The four recordings are the operator's data, not the repository's: `<data root>/voice/ref1.wav` to
`ref4.wav`, owned by the role's owner, group `tts_gid`, mode 0640. They come from the archive of the old
lab (read-only there: `voice-tts/refs/`) through the same door as any restore:

1. make an archive holding only `voice/ref1.wav` … `voice/ref4.wav` and a `listing.jsonl`
   (`{"key": "tts-data.tar.gz", "size": N, "sha256": "<hex of the archive>"}`) in one directory;
2. run the role's `restore` hook with `tts_restore_source=<that directory>`. It checks the archive's
   hash against the listing, refuses links, special files and anything but `voice/` and `state/`,
   refuses an archive that extracts to more than `tts_restore_max_bytes` (default 256 MiB), stages and verifies every recording (and the pinned bytes, below), stops the service, moves the
   live directories aside (never deleted) and moves the staged ones in.

`tts_voice_expected_sha256` pins each recording by sha256 (the archive's `MANIFEST.sha256` has them): when
set, start, health and restore refuse any other bytes, because a copy cut short or another take is a
different voice. Start refuses to go on without all four.

## Health and readiness

`readiness` (preflight, before `main`): the container engine is ready, the model's listing and weights are
in the store, the recordings are there. `health`: the recordings (and their pinned bytes), every container
running and healthy, `GET /health` in the old shape listing exactly the recordings, `GET /ready` ready on
the configured backend (recordings, listing, power cap), and **one real synthesis of a fixed sentence**
(`python -m tts_service check` inside the container: the answer must be `audio/wav`, 24000 Hz, mono, 16-bit
and last between `tts_check_min_seconds` and `tts_check_max_seconds`). That one may load the model: on a
CPU it takes tens of seconds (`tts_check_timeout_s`, 900).

## Backup, export, restore

`backup` names the data root (the recordings and the embeddings cache; not the weights, which are the model
store's, and not the scratch cache). `export` writes `export/tts-data.tar.gz` and `listing.jsonl` (sha256 and
size) without stopping the service; `export_first: true` takes it before a removal. `restore` is described
above.

## Licence: what the model's terms allow (plainly)

The software around the model (the engine library `coqui-tts`) is MPL-2.0. **The model itself is not open
source**: it is under the **Coqui Public Model License 1.0.0** (`LICENSE.txt` in the model's repository,
carried in the store entry), which allows **only non-commercial use of the model and of its output**:

- **Allowed**, for any non-commercial purpose: personal use for research, experiment and testing, personal
  study, private entertainment, **hobby projects and amateur pursuits**; testing, evaluation and
  non-commercial research by a company; charitable use. A free, personal podcast in your own voice is
  within that.
- **Not allowed**: anything where you receive **direct or indirect payment arising from the use of the
  model or its output**. Revenue-generating activity is not non-commercial, and neither is training another
  model for commercial use. So no paid or sponsored episodes, no advertising or subscription revenue on
  the feed, no use inside a product or service you charge for. If the podcast ever earns money, stop and
  re-decide; there is no commercial licence to buy (the licensor, Coqui, has wound down, as far as we know).
- **Notices**: anyone who gets a copy of the model, a modification of it or its output from you must also
  get the terms or their URL (`https://coqui.ai/cpml.txt`). Whether a published episode counts as "output"
  for that is the operator's call; a one-line mention in the show notes costs nothing.
- **No sublicensing or transferring** of the licence. Making a patent claim that the model infringes ends
  your licence. A violation can be cured within 30 days of written notice, otherwise the licences end.

This is a plain reading, not legal advice. The voice recordings are the operator's own.

## Facts measured, and what only hardware can show

- Built and run on a CPU workstation (16 cores) from this Dockerfile: image 2.5 GB; the first request
  after start takes 20-30 s (it hashes the 2.1 GB of weights and loads the model), later ones about 6 s for a
  3 s sentence; the container uses ~3.3 GiB. `GET /ready` before any job is 200 with the model not
  loaded; with `TTS_IDLE_UNLOAD_S=6` the model was unloaded after the idle period (health says
  `model_loaded: false`, memory fell) and the next job reloaded it. The embeddings cache is written by
  the first job (`state/latents-<hash>.pt`, ~130 KB). The cached and uncached paths gave the identical
  waveform for the same seed. The library rewrites an original-format checkpoint in place after loading it;
  the service switches `torch.save` off for the load, because the weights are read-only and pinned by
  sha256 and must never change.
- **Not provable here** (verify at the first deploy, in order): that `nvidia-smi` inside the container
  (CDI) reports the card's `power.limit` (otherwise the load is refused and `/ready` says why; the fix is
  the container toolkit's spec, not a looser rule); that the CUDA 12.8 build runs on the 64 GB-class CMP
  cards after the unlock (driver and compute capability); VRAM is freed on unload (`torch.cuda.empty_cache`
  after dropping the model); and how long a full episode takes on the guest's CPU (the old CPU service
  took hours for a long one; the caller's 30-minute timeout may need raising for the first long script).

## Using it in a site (overlay checklist)

- `lab/modules.yml`: select `tts` in the `tts` slot, `instance` = the registry row's name,
  `placement: {server: <site host>}` (the guest the site chose for it); no grants (no egress, no public
  route).
- `lab/services.yml`: the row exactly as bound (host = the guest, `version: "2.0.0"`), plus at most
  `standing`, `backup_job`, `scope`.
- Group variables for `mod_tts_server`: `tts_logical_id`, `tts_image` (the build's reference),
  `tts_image_archive` (its `docker save`), `tts_backend` (`cpu` now), `tts_voice_expected_sha256` (the four
  recordings' sha256), and for a GPU guest later `tts_backend: cuda`, `tts_gpu_index`,
  `tts_power_cap_max_watts` (only to tighten the 200 W), `tts_idle_unload_s`.
- Model store: the entry `xtts-v2` of `schemas/platform/examples/model_store.speech.json` in the site's
  manifest, applied by `model_store` before this module.
- The voice: restore the four recordings (above) before the first start.
- Firewall: inbound `tts_port` from the publishing pipeline's guest and from the metrics guest, nothing
  else; no `outbound_allow` to the internet; SSH as the baseline's.
- Callers: the pipeline's TTS URL becomes `http://<tts guest>:8091` (the path `/synthesize` is the
  caller's); grep the rendered pipeline config for the old workstation address before the cutover.
- A test render, to listen to once (from a host the firewall lets reach the port):
  `curl -sS -X POST http://<tts guest>:8091/synthesize -H 'Content-Type: application/json' -d '{"text":"This is a test of the narration voice.","temperature":0.6,"top_p":0.85}' -o tts-test.wav`
