<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `nifi`: the dataflow provider

A provider module ([module manifest](../../docs/modules.md)) that fills the `dataflow` slot with
[Apache NiFi](https://nifi.apache.org) 2.x, a single node (no cluster, no ZooKeeper). It is the lab's
batch, feed, file and API ETL into the lake, with provenance, a dead-letter path and completion
events; it sits on the lake's guest next to `garage`, `iceberg-rest` and `trino` and reaches them
through the registry. It builds no flow of its own beyond a smoke flow: the CTI and other business
flows are later work that ships as flow definitions in the flows repository. Nothing in this
directory names a real host, address, VM id or secret value.

| | |
|---|---|
| Slot | `dataflow` (provisional: no contract yet), stateful, export format `json` |
| Adapter | `homelabnext.conform.adapters.dataflow:make` (read-only probe: version, single-node cluster summary, controller status, bulletins) |
| Product | NiFi 2.12.0 (published 2026-09-14), `docker.io/apache/nifi` pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, 2 vCPU, 4 GB, 40 GB (the footprint is a floor: raise the heap with the flows) |
| Role | `nifi` (role interface v1), a wrapper of the core `compose_app` |
| Requires | `cap:secrets`, `cap:object-store`, `cap:lake-catalog`, `cap:lake-query`, `cap:events` |
| Egress | none by default; `internet` is a per-site option (`optional: true`, see "Egress") |
| Public route | none; HTTPS on the guest's own address, port 9443 (`trino` has 8443 on the same guest) |

## What the role does

- **One container** as the image's own user (1000:1000: its installation is readable by that id alone),
  every capability dropped, `no-new-privileges`, a memory limit (heap + at least 1 GB), joined to the
  module's role slice by `compose_app`. **Only HTTPS is published**, on `nifi_bind:nifi_port`; the
  site-to-site and cluster ports are not published. The heap is `nifi_heap` (default 2g).
- **Everything the service writes is under the data root** (`nifi_data_root`): `conf/`, `state/`, the
  `flowfile_`, `content_`, `database_` and `provenance_repository/`, `logs/` and `smoke/`, each a bind
  mount, each the container user's and 0700. Provenance is kept `nifi_provenance_max_age` (30 days) up
  to `nifi_provenance_max_size`.
- **TLS from the lab CA.** The certificate, key and CA are the secrets `nifi/tls-cert`, `nifi/tls-key` and `nifi/ca`. The web
  server wants PKCS12 stores, so the role builds a keystore and a truststore (the lab CA) in a throwaway
  container of the pinned image (`openssl`, `keytool`), the password on standard input
  (`secret:nifi/store-password`), and rebuilds them, and restarts the service, when the certificate, the
  key, the CA or the password change. The truststore is also what flows use to reach a lab HTTPS
  endpoint (parameters `HNX_TRUSTSTORE_PATH`, `HNX_TRUSTSTORE_PASSWORD`).
- **Configuration is the image's own**, taken into `conf/` in a throwaway container and then edited by
  the image's start-up script from the environment; it is taken afresh whenever the image, the sign-in,
  the first administrator or the provenance retention change (the start-up script's edits only match a
  pristine file, and a file from an older image may not be read by a newer one). The stored flow
  (`flow.json.gz`), `users.xml` and `authorizations.xml` are never touched.

## Sign-in

`nifi_auth` is one of two. **`single-user`** (the default): one user, `nifi_single_user_name`, with the
password `secret:nifi/single-user-password`; the role signs in with it for its own API calls, so every
hook can prove the flow state. **`oidc`**: OpenID Connect against the identity provider (Keycloak), with
`nifi_oidc_issuer_url` (`https://<idp>/realms/<realm>`), `nifi_oidc_client_id`,
`secret:nifi/oidc-client-secret` and `nifi_initial_admin` (the value of `nifi_oidc_claim`, default
`preferred_username`, of the first administrator); the role cannot sign in as a person, so its own API
calls use `secret:nifi/api-token`, a bearer token the service accepts (the role refuses oidc without it
rather than skip the authenticated checks).

**Which one the platform supports today:** the keycloak module renders a client only for a registry row
with `auth: idp` and a public hostname, whose redirect is the edge's; this row is `auth: own` and has no
public route, so **no client for it exists in the realm** and the single-user sign-in is the default
that works. Using oidc needs the overlay to add a confidential client (authorization code with PKCE,
redirect `https://<name>:<port>/nifi-api/access/oidc/callback`) and its secret `idp/clients/<id>` /
`nifi/oidc-client-secret`. The oidc path renders and its settings are tested, but it has not been run
against a live realm (see "Undecided").

## What flows get: parameters from secret references

The role keeps one **parameter provider** (`nifi_parameter_provider`) that reads the container's
environment and fills one **parameter context** (`nifi_parameter_context`, `hnx-lake`); a flow binds to
that context by name and reads `#{NAME}`. Nothing sensitive is ever in a flow definition: the sensitive
parameters come from `secret:` references through the 0600 env_file, the others are rendered from the
registry.

| Parameter | Sensitive | From |
|---|---|---|
| `HNX_LAKE_S3_ENDPOINT`, `HNX_LAKE_S3_REGION`, `HNX_LAKE_WAREHOUSE` | no | the object store's registry row, `nifi_region`, `nifi_warehouse` |
| `HNX_LAKE_CATALOG_URI`, `HNX_LAKE_QUERY_URL` | no | the lake-catalog and lake-query rows; the catalog's address followed by `nifi_catalog_path` (empty by default, `/catalog` for a catalog that serves its API there, with `nifi_warehouse` then the warehouse's name) |
| `HNX_EVENTS_URL` | no | the events row |
| `HNX_TRUSTSTORE_PATH` | no | the stores the role builds |
| `HNX_LAKE_S3_ACCESS_KEY`, `HNX_LAKE_S3_SECRET_KEY` | yes | `secret:nifi/s3-access-key`, `secret:nifi/s3-secret-key` |
| `HNX_EVENTS_TOKEN` | yes | `secret:nifi/events-token` (the whole Authorization header value) |
| `HNX_TRUSTSTORE_PASSWORD` | yes | `secret:nifi/store-password` |
| any `HNX_*` in `nifi_extra_parameters` | yes | its `secret:` reference |

The Iceberg writer in a flow uses the REST catalog service at `#{HNX_LAKE_CATALOG_URI}` with the S3
settings above. The lake key may be the object store's own (the same value as its access key) or a
key limited to the lake's writers; the secret names are this module's own either way.

## Flows as code

A **Git flow registry client** (`nifi_registry_name`) is created, updated or removed to match
`nifi_registry_url`, `nifi_registry_owner`, `nifi_registry_repo`, `nifi_registry_branch`,
`nifi_registry_path` and, for a private repository, `secret:nifi/registry-token`. **An empty
`nifi_registry_url` is allowed and means no client**: the repository (Gitea) comes later. The client
is the product's GitHub client, whose API URL setting names the host; whether a Gitea instance
answers that API well enough is undecided (README "Undecided"), and the module changes no flow
definition itself. Process groups are versioned through that client by the person or workflow that
builds them; `export` keeps a portable JSON copy of every top-level group in any case.

The **smoke flow** (`hnx-smoke`, `roles/nifi/files/hnx-smoke.json`) is imported when absent and kept
running: `GenerateFlowFile` (every minute) -> `UpdateAttribute` -> `PutFile` into `<data root>/smoke`
as `heartbeat.txt` (replace), with the failure relationship retried back into the processor so a
persistent failure shows as a queue and a bulletin. Health reads that file's age (a flow that stops, or
cannot write, fails health after `nifi_smoke_max_age_minutes`). `nifi_smoke_enabled: false` stops it.

## The events contract (what a flow emits)

**Events are off until an HTTP forwarder exists.** This section is a contract; no emitter flow ships
yet, and the `events` registry row is a bus that may listen only on its own host. So `nifi_events_url`
is empty by default: readiness then reports that events are off and does **not** wait for the bus, and
health never needs it. Set `nifi_events_url` to a forwarder's `scheme://host:port` to turn events on;
readiness then waits for it. The query engine is always checked.

NiFi publishes to the events forwarder by **HTTP**, the way every other publisher does, from an
`InvokeHTTP` at the end of a flow (no extra processor bundle, one place to authenticate and validate):

- `POST #{HNX_EVENTS_URL}`, `Content-Type: application/cloudevents+json`, header
  `Authorization: #{HNX_EVENTS_TOKEN}` (the whole value), header `Idempotency-Key: <event id>`; success is
  200, 201, 202 or 204, `409` is a permanent id collision, 408/425/429/5xx are retried
  ([docs/events.md](../../docs/events.md), "Forwarder contract").
- The repository's CloudEvents 1.0 envelope (`schemas/events/envelope.schema.json`, checked by the
  forwarder): `specversion` `1.0`; `id`, the idempotency key, `nifi-` and the SHA-256 (hex) of `type`,
  `source` and a stable per-occurrence `dedupe` key, so a re-run of a flow publishes the same id;
  `source` the service's logical id (`svc:<registry id of this row>`); `type`; `time` (UTC);
  `subject` (the process group, table or feed); `datacontenttype` `application/json`; `data`.
- **Types carry the platform's `homelabnext.` prefix** (the bus refuses any other): the flows' logical
  names (`nifi.flow.completed`, `nifi.flow.failed`, `cti.feed.batch`, and the later `nifi.dlq.record`,
  `cti.intel.new`, `lake.freshness.stale`) are sent as `homelabnext.nifi.flow.completed` and so on, and
  a subscriber matches the full type. `data` of `homelabnext.nifi.flow.completed`: `flow`, `version`,
  `records_in`, `records_out`, `records_invalid`, `run_started`, `run_finished`; of
  `homelabnext.nifi.flow.failed`: `flow`, `reason`, `relationship`; of `homelabnext.cti.feed.batch`
  (the feed flow): the new-item counts of one run. Producers set `type`, `subject` and `dedupe`;
  `data` and the header values must be JSON-safe (`:escapeJson()` in the flow).
- The connection to the `InvokeHTTP` is durable with back-pressure and a bounded retry, so an
  outage of the forwarder delays events and loses none; a flow that goes silent is the freshness
  flow's and the invariants' to find.

`tests/modules/test_dataflow_module.py` pins this envelope against the repository's own event validator.

## Egress

The module's own steps and the smoke flow need no internet, and **a site that grants nothing gets none**. The manifest
declares `egress: [{host: server, to: [internet], optional: true}]`: an `optional` entry (docs/modules/egress.md) is
allowed but never owed, so `hnx modules check` is clean without a grant, and a site whose flows pull a public feed opts in
with one overlay line, `grants.egress.nifi.server: [internet]`. The container's own network namespace is outside the host's
per-slice ruleset (docs/modules/egress.md, "What it does not cover"):
the grant is the policy, the guest's NIC firewall is the control, so scope the feed's hosts there.

## JDBC drivers

The image ships no JDBC driver. A flow that writes through the query engine as its own user (so the engine's access rules
govern it, instead of the lake's object-store key) needs the engine's driver. `nifi_jdbc_drivers` (default `[]`) lists
`{name: <file>.jar, url: https://..., sha256: <64 hex>}`; the role fetches each on the guest, **refuses it unless its sha256
matches**, and mounts the directory **read-only** at `<container home>/drivers/<name>` for a database connection pool's
"Database Driver Locations". The fetch needs https egress from the guest at deploy time (not from the container).

## Hooks

| Hook | What it does |
|---|---|
| `readiness` (also the module's preflight) | `docker_engine` readiness; every credential resolves in its form; the object store (200 or 403 unsigned) and the catalog (`/v1/config`) answer; the query engine and the bus accept a connection |
| `health` | the container healthy; the API **refuses an anonymous request** (verified against the lab CA) and, with the credential, reports the expected version, a single node (not clustered), no invalid component and no failed registry sync, the parameter context holding every parameter with the right sensitivity, the registry client present exactly when one is configured, the smoke flow running, and its file younger than `nifi_smoke_max_age_minutes`. Read-only |
| `backup` | the backup manifest names the same state the export keeps (the stored flow, users and policies, and the state and repositories), a crash-consistent copy which NiFi recovers from; `conf/nifi.properties`, `conf/login-identity-providers.xml` and the other seeded files (the sensitive-props key, the keystore passwords, the single-user hash), the `tls/` directory and the logs are left out and rebuilt |
| `export` | `flows/*.json` (every top-level group through the API, sensitive values blank), `state.tar.gz` (the stored flow, users and policies, state, flowfile, content and database repositories, and provenance when `nifi_export_provenance`) taken **with the service stopped** and started again whatever happened, and `listing.jsonl` (key, size, sha256). The seeded configuration files, which hold the container's passwords, are left out. The previous archive is kept as `state.tar.gz.prev` (one generation; the generation before it is replaced), each flow file is replaced atomically, and the listing is written last. The listing's hash detects corruption and half-written exports, not tampering: it is stored beside the archive |
| `restore` | `nifi_restore_source` (an export directory); mode `state` checks the archive's hash against the listing and its members (no link, no path outside the state's own), extracts beside the live data, then with the service stopped moves every replaced path aside under `<data root>/before-restore` (never deleted: move it away before the next restore, which refuses to go over it) and the staged ones in; mode `flows` imports the portable definitions by name where absent, then for every named flow binds the group to the provider's parameter context, enables its controller services (waiting for ENABLED) and starts it only when `nifi_flow_run` names it true (a second run changes nothing). The sensitive-props key must be the one the export was taken under |
| `upgrade` | refuses a target that is not pinned by tag and digest, is another repository, is older, or has the running tag at another digest (unless `nifi_allow_same_tag_rebuild`); records the bump; the playbook exports first, then converges (the configuration files are taken afresh from the new image; NiFi migrates its repositories forward on first start) |

## Overlay checklist

1. Select the module for the `dataflow` slot, place its `server` role on the lake guest (the same
   host as `garage`, `iceberg-rest` and `trino`); add the registry row `dataflow` as the module
   contributes it (port 9443, `health` expecting 401).
2. Secrets in the store, by name (how to generate each is in the pull request that added this module):
   `nifi/tls-cert`, `nifi/tls-key`, `nifi/ca`, `nifi/store-password`, `nifi/sensitive-props-key`,
   `nifi/single-user-password`, `nifi/s3-access-key`, `nifi/s3-secret-key`, `nifi/events-token`; with oidc
   `nifi/oidc-client-secret` and `nifi/api-token`; with a registry repository `nifi/registry-token`.
3. The certificate must be for the row's internal name (and the guest's address when hooks use it).
4. The guest's NIC firewall: 9443 from the operator zone and the status hub; nothing else inbound.
5. DNS record for the internal name; the status hub's `dataflow-status` source (kind `poll-nifi`,
   target `/nifi-api/flow/status`, a bearer token a read-only user holds: see "Undecided", the
   service's own tokens expire).
6. Group variables: `nifi_logical_id`, `nifi_warehouse` and `nifi_region` (required: the lake's fixed
   warehouse and S3 region, no default here), `nifi_heap`/`nifi_mem_limit` for the flows, and (when used)
   `nifi_registry_*`, `nifi_oidc_*`, `nifi_extra_parameters`.

## Undecided

- Whether a Gitea instance works with the product's GitHub flow registry client (its API URL is a
  setting, the API is a subset): decide before the flows repository is created.
- The oidc path against Keycloak needs a client in the realm that the generator does not render for an
  `auth: own` row, and the bearer-token route for the role's own calls is untested against a live realm.
- **The status hub's token.** The hub's `poll-nifi` source sends one stored bearer token, and the
  service's own sign-in tokens expire (about 12 hours; the single-user provider has no setting for it).
  Until the hub can refresh a token (or the oidc path gives it a long-lived one from the identity
  provider), that source needs a token renewed on a schedule; this module does not run that timer.
- The footprint (2 vCPU, 4 GB) is a floor; the guest's real size and the flows' needs decide the heap.
