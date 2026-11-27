<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `assemblyline`: file analysis on AssemblyLine 4

A provider module ([module manifest](../../docs/modules.md), draft; [ADR-0052](../../docs/adr/0052-file-analysis-runs-in-a-contained-research-stage-on-assemblyline-4.md),
proposed). It fills the provisional `file-analysis` slot with [AssemblyLine 4](https://github.com/CybercentreCanada/assemblyline)
(MIT; the Canadian Centre for Cyber Security's file-triage platform) for lab-internal analysis and
research of files the lab already collects. **This is a scaffold**: nothing in it is deployed and
`assemblyline_start` is refused while it is incomplete.

| | |
|---|---|
| Needs | `cap:secrets` |
| Host role | `server`: kind `vm`, baseline `base`, 16 vCPU, 48 GiB, 600 GB (ADR-0052 decision 8). **A dedicated guest**: the product's scaler and updater hold the docker socket, so the VM is the trust boundary |
| Role | `assemblyline`: wraps `compose_app` |
| Slot | `file-analysis` (provisional), probe `homelabnext.conform.adapters.file_analysis` |
| Egress | none declared, and the site's guest firewall must be `policy_out DROP` with an empty outbound list |
| Registry row | `file-analysis`: https 443, `tls: internal`, `auth: own`, no public hostname |
| Release | 4.8.0.stable4 (the compose repository's pin on 2026-11-26); every product image by digest |

## Contents of this change (PR 1)

- The manifest, the registry row, the three lifecycle playbooks, the role's argument specs.
- Role hooks: `readiness` (engine, inputs, credentials, image archive), the main converge (renders the
  datastore, the broker, `expiry`, `workflow`, `heartbeat`, `statistics`, `plumber`, `dispatcher`,
  `ingester`, `service_server`, `ui` and `socketio`; every capability dropped, `no-new-privileges`),
  `health` (every container healthy; **only `scaler` and `updater` may be privileged or hold the docker
  socket**), `upgrade` (one release tag for the five product images, same repositories, never older).
- `backup`, `export` and `restore` **fail closed** (not implemented).
- The slot, the read-only probe and the pin-freshness entries.

## What PR 2 needs (exact)

1. **`compose_app` cannot express the appliance yet.** It has no named or `internal: true` networks, no
   `profiles`/`extends`, and refuses `privileged` and the docker socket unless `compose_app_allow_privileged`
   and `compose_app_allow_docker_socket` are set. Either extend `compose_app` (a `networks:` map with
   `internal`, a per-service network list) or render the project in this role. The appliance's networks
   are `core` (`internal: true`), `registration` (`internal: true`) and `external` (only the front, `ui`,
   `socketio`, `dispatcher` and `updater`); the scaler attaches the analysis-service containers to `core`
   through `AL_CORE_NETWORK`.
2. **`scaler` and `updater`** (the privileged pair): the upstream `privilege-core-image` build, the shared
   `service_config` volume, the docker socket, the two allow flags above, and a health hook that proves
   nothing else holds them (already written).
3. **The service key's delivery (a decision for review).** The product reads the key the analysis services use at the
   service server from an environment variable (`.env` in the compose repository) whose name matches the public
   repository's `secret-name` leak-scan rule, which no marker or exemption can waive. Options: render that one env
   file from the overlay (the site's repository, where the name is not scanned), or agree a rule change. This change
   validates the secret but does not render it into any container.
3b. **`config.yml` and `classification.yml`** rendered into `{{ assemblyline_dir }}/config/` from the secrets
   (datastore, object store, service key), with: `core.scaler.service_defaults` and `min_instances`,
   `datastore.hosts` and `filestore` (the object-store bucket URLs), `submission.file_sources` emptied
   (the appliance's default entry is MalwareBazaar), expiry from `assemblyline_submission_ttl_days`, and the
   alerter off.
4. **The object store and the TLS front.** The project's `cccs/minio` and `cccs/nginx-ssl-frontend` images
   publish only a `latest` tag, which `compose_app` refuses: choose a pinned MinIO release (AGPL-3.0) and
   an nginx release with the project's routing (`ui`, `socketio`, `frontend`) rendered by the role, and a
   certificate the deploy renders.
5. **Bootstrap**: the first administrator (the appliance's `bootstrap-compose.yaml` runs a script that
   creates it from `AL_ADMIN_USER` and `AL_ADMIN_PASSWORD`), then per-consumer API keys created through
   the API and written to the secret store create-only (`apikey-<consumer>` in the module's secret namespace).
6. **The offline service set**: read each candidate service's manifest and licence; install a reviewed
   allow list (not "Install All"); import the service images by archive or a lab registry and set
   `REGISTRY`; mirror each rule and signature source into a local path the updater reads; turn the
   per-service internet switch off and have `health` read it from the API.
7. **`export`/`backup`/`restore`**: an Elasticsearch snapshot (the `path.repo` for
   `export/datastore` is already bind-mounted) and a copy of the object store's buckets with a sha256
   listing (ADR-0008); restore refuses a target that has data unless told.
8. **Rehearse** in the staging guest with a harmless EICAR-class file before any research guest exists;
   replace the datastore healthcheck (a TCP connect today, because the product needs credentials for cluster health and none may sit on a command line) with an authenticated check reading a 0400 file mounted into the container; confirm the health probe path in the adapter against the running front (`/api/v4/user/whoami/` is
   assumed to answer 401 anonymously) and the container healthchecks (the `kill -0 1` and TCP-connect
   ones are placeholders where the images have no endpoint).
9. **Then** the result puller (`file-analysis-export`) and the lake table `soc.file_analysis` (PR 3).

## Licences

AL4's core is MIT. Elasticsearch 8.10.2 is under the Elastic licence (not OSI), MinIO is AGPL-3.0, Redis
is the 7.2 BSD line. Each analysis service carries its own licence in its manifest and is read before it
is installed; commercial antivirus and reputation services and any sandbox service are out of scope.
