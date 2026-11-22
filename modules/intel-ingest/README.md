<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `intel-ingest`: threat-intel indicators into the graph store

A feature module ([module manifest](../../docs/modules.md), draft). A daily job pulls the
threat-intel platform's **actionable indicators** (attributes flagged for detection) per type and
writes them as graph nodes tagged by their source, so the graph carries the platform's indicators.
It is the old lab's `misp-cortex-ingest`, ported with its walk unchanged.

| | |
|---|---|
| Needs | `cap:threat-intel` and `cap:graph-store` (both provisional slots), `cap:secrets` |
| Host role | `job`: kind `vm`, baseline `base`, 1 vCPU, 1 GB. Place it where both services answer (the guest that holds them is the natural one) |
| Role | `intel_ingest`: a stdlib script, a oneshot unit and a daily timer. No container, no runtime release |
| Config secrets | the dedicated platform key, the graph account's password, the lab CA (names in `module.yml`) |
| Egress | none declared: both services are slots the module requires |

## The walk (LL-504, kept as it was)

Per attribute type, newest first, page by page (1000 rows), each page written to the graph store in
chained batches of 100 and then **checkpointed atomically** (`tmp` + rename) before the next page.
The state is `{type: {watermark_id, in_progress: null | {page, newest_id}}}`: the watermark is the
highest attribute id fully ingested; `in_progress` is where a stopped walk resumes. A run stops
cleanly at the wall-clock cap (`intel_ingest_max_runtime_s`, exit 2, which the unit accepts as
progress) or on SIGTERM, and the next run resumes at the saved page. Re-ingesting a value is a
no-op in the graph (set semantics), so a crash between a write and its checkpoint only repeats a page.

The walk pages by offset, so a cold type is expensive (that is what the checkpoint and the cap are
for, and why this state is worth keeping). **Do not start a cold walk of the big types on a
guest that is also importing**: the platform's database is the shared bottleneck.

## TLS: ordinary verification, both services

Both services are verified with normal TLS verification, hostname checking on, against one CA bundle
the role writes from two secrets: the lab CA for the platform, and `intel_ingest_graph_ca_ref` for
the graph store. If the graph store's certificate is signed by the lab CA, give the lab CA. If it
keeps its own self-signed certificate (it makes one on first start, keeps it in its data, and a
restored graph brings it along), give **that exact certificate** (PEM): it becomes the trust anchor
for that one service, so any other certificate is rejected. The graph URL's host must be a name the
certificate carries (check its subject alternative names; connect by that name, resolved on the
guest). There is no pin and no unverified path: the script refuses to connect without a CA file.

## Variables

Required: `intel_ingest_logical_id`, `intel_ingest_threat_intel_url`, `intel_ingest_graph_url`.
Everything else has a default in `defaults/main.yml`; the graph store's account (name and password
reference) is the site's, ideally with only the permissions to add nodes and run queries.

## Cutover: carrying the state over (install, then run once)

1. **Stop the old job first** (the operator): the old job's timer and any running unit, on the old
   host, so exactly one walker writes the graph. The old state then stops changing.
2. Copy the old state file (read-only) to the new guest, for example
   `/var/lib/hnx-modules/<id>/import/state.json`, and set `intel_ingest_state_seed_file` to it.
3. Install. The state is **checked** (this module's form: known types, integer watermarks, pages of 1
   or more; empty or foreign shapes are refused) and installed **create-only**: a live state is never
   replaced by the seed. `restore` (with `intel_ingest_restore_source`) is the explicit way to
   replace it.
4. Prerequisite for the seed to mean anything: the new platform's attribute **ids are the old
   ones** (it was restored from the old database, ids preserved). Compare the counts and the highest
   id per type before the first run; if the ids differ, do not seed (a watermark above the new ids
   skips them): start cold, or re-derive the watermarks.
5. Run once by hand (`systemctl start hnx-<id>.service`) and read: the journal says `resuming at
   page N` for each in-progress type, the state's `in_progress.page` advances, new nodes appear.

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (the module's preflight) | systemd and python3, the inputs, and every secret in its form (a reference with no value is **named**) |
| `main` | validates, writes the script, the CA bundle, the environment (no secret), the root-only logins file and the units; seeds the state create-only; arms the timer |
| `health` | the script, the environment, the logins and the CA bundle exist, the timer is active, the live state is this module's form. Nothing is written and neither service is called |
| `export` / `backup` | the state under `export/<stamp>/state.json`, built beside and renamed into place |
| `restore` | checks the source, stops the timer, waits for a running job, **replaces** the state, arms the timer |
| `upgrade` | no pinned artefact: validates and refuses a live state of another shape; the converge is the install |

## Notes

- The unit's secrets are in a root-only environment file that systemd reads; the job runs as the
  module's own user with no capabilities and a strict filesystem sandbox (state directory writable).
- The script is stdlib only and the product names in it are the product names of the API it talks to:
  the product-names allowlist lists this file for those two products and no other.
